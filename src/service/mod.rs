//! The protection service's core: the pipe server and what it does with each
//! request. `phalanx-service.exe` runs it under Windows' service manager;
//! tests and `phalanx-service --console` run it in-process, on a private
//! pipe name. See `docs/protection-service.md` for the design.

#[cfg(windows)]
pub mod manage;

use crate::ipc::{Caller, ClientMessage, Reply, Request, Status};
use serde_json::json;
use std::io;

/// The service's name in Windows' service manager.
pub const SERVICE_NAME: &str = "Phalanx";
pub const DISPLAY_NAME: &str = "Phalanx Protection";
pub const DESCRIPTION: &str = "Phalanx's real-time protection, web protection and scans. It keeps protecting the PC when nobody is signed in and cannot be stopped by programs running as a user.";

/// What the request handler needs to know about the running service.
struct Context {
    started: u64,
    /// Told when an administrator asks the service to stop.
    stop_requested: std::sync::mpsc::Sender<()>,
}

/// Answers one request from `caller`.
fn handle(ctx: &Context, caller: &Caller, message: ClientMessage) -> Reply {
    let id = message.id;
    if !caller.may(&message.request) {
        return Reply::needs_approval(id);
    }
    match message.request {
        Request::Ping => Reply::ok(id, json!("pong")),
        Request::Status => {
            let status = Status { version: env!("CARGO_PKG_VERSION").into(), pid: std::process::id(), started: ctx.started, caller: caller.clone() };
            match serde_json::to_value(status) {
                Ok(value) => Reply::ok(id, value),
                Err(e) => Reply::error(id, e.to_string()),
            }
        }
        Request::Stop => {
            let _ = ctx.stop_requested.send(());
            Reply::ok(id, json!("stopping"))
        }
    }
}

/// The service running in this process. Dropping it stops the pipe server.
pub struct Running {
    /// Held so that dropping `Running` stops the pipe server.
    #[cfg(windows)]
    _server: imp::Running,
    stop_requests: std::sync::mpsc::Receiver<()>,
}

impl Running {
    /// Waits up to `timeout` for an administrator to ask the service to
    /// stop; `true` if one did.
    pub fn stop_requested(&self, timeout: std::time::Duration) -> bool {
        self.stop_requests.recv_timeout(timeout).is_ok()
    }

    /// Stops answering and waits for the pipe server to end.
    pub fn stop(self) {
        drop(self);
    }
}

/// Starts the service on the pipe `pipe_name` ([`crate::ipc::PIPE_NAME`] for
/// the real service). Fails if another process already holds the name.
pub fn start(pipe_name: &str) -> io::Result<Running> {
    let (tx, rx) = std::sync::mpsc::channel();
    let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let ctx = Context { started, stop_requested: tx };
    #[cfg(windows)]
    {
        Ok(Running { _server: imp::start(pipe_name, ctx)?, stop_requests: rx })
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe_name, ctx, rx);
        Err(io::Error::new(io::ErrorKind::Unsupported, "the protection service is Windows only"))
    }
}

#[cfg(windows)]
mod imp {
    use super::{handle, Context};
    use crate::ipc::{ClientMessage, Connection, Reply, Server, ServerMessage};
    use std::io::{self, BufRead, BufReader, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    pub struct Running {
        name: String,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // Wake the accept loop with a connection of our own.
            let _ = crate::ipc::Client::connect_to(&self.name, false);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    pub fn start(name: &str, ctx: Context) -> io::Result<Running> {
        let server = Server::bind(name)?;
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(ctx);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new().name("service-pipe".into()).spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match server.accept() {
                    Ok(connection) if !thread_stop.load(Ordering::Relaxed) => {
                        let ctx = Arc::clone(&ctx);
                        let _ = std::thread::Builder::new().name("service-client".into()).spawn(move || serve(connection, &ctx));
                    }
                    Ok(_) => break,
                    // Out of handles or similar: try again shortly.
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(200)),
                }
            }
        })?;
        Ok(Running { name: name.to_string(), stop, thread: Some(thread) })
    }

    /// Answers one client until it disconnects.
    fn serve(connection: Connection, ctx: &Context) {
        let Ok(read) = connection.file.try_clone() else { return };
        let mut writer = &connection.file;
        let mut caller = None;
        for line in BufReader::new(read).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            // Who is asking, once: the client has written, so it can be read.
            if caller.is_none() {
                caller = connection.caller().ok();
            }
            let reply = match (serde_json::from_str::<ClientMessage>(&line), &caller) {
                (Err(e), _) => Reply::error(0, format!("not a request: {e}")),
                (Ok(message), None) => Reply::error(message.id, "could not tell who is asking"),
                (Ok(message), Some(caller)) => handle(ctx, caller, message),
            };
            let Ok(mut text) = serde_json::to_string(&ServerMessage::Reply(reply)) else { break };
            text.push('\n');
            if writer.write_all(text.as_bytes()).is_err() || writer.flush().is_err() {
                break;
            }
        }
    }
}
