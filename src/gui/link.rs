//! The app's side of the protection service: the event connection, requests
//! off the UI thread, and approvals.
//!
//! Protection runs in the service; the app shows what it reports and asks it
//! for changes. One connection stays subscribed to the service's events on
//! a thread of its own (and reconnects when the service restarts); the
//! notifications are shown from that thread, so the app hidden in the tray
//! still notifies. Requests run on short-lived threads and hand their result
//! back to the UI thread as a closure.

use crate::App;
use eframe::egui;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use threat_scanner::ipc::{self, Client, Event, Reply, Request, ServerMessage};

/// How long the service may be gone before the user is told: a crash
/// restarts it in seconds.
const DOWN_GRACE: Duration = Duration::from_secs(20);
/// At sign-in the app may start before Windows has started the service.
const STARTUP_GRACE: Duration = Duration::from_secs(90);

/// What the link hands to the UI thread.
pub enum LinkMsg {
    Connected,
    /// The connection to the service ended; why.
    Lost(String),
    Event(Box<Event>),
    /// A request finished: apply its result.
    Done(Box<dyn FnOnce(&mut App) + Send>),
}

/// How a change that may need approval ended.
pub enum Approval<T> {
    Done(T),
    /// The user said no to Windows' administrator prompt.
    Declined,
    Failed(String),
}

/// Which events the event connection turns into Windows notifications (the
/// settings can change while it runs).
#[derive(Default)]
pub struct NotifyPrefs {
    threats: AtomicBool,
    risky: AtomicBool,
}

impl NotifyPrefs {
    pub fn set(&self, threats: bool, risky: bool) {
        self.threats.store(threats, Ordering::Relaxed);
        self.risky.store(risky, Ordering::Relaxed);
    }

    pub fn threats(&self) -> bool {
        self.threats.load(Ordering::Relaxed)
    }

    pub fn risky(&self) -> bool {
        self.risky.load(Ordering::Relaxed)
    }
}

pub struct Link {
    tx: Sender<LinkMsg>,
    pub rx: Receiver<LinkMsg>,
    ctx: egui::Context,
}

impl Link {
    /// Starts the event connection; `notify` says which events become
    /// Windows notifications.
    pub fn start(ctx: &egui::Context, notify: Arc<NotifyPrefs>) -> Self {
        let (tx, rx) = mpsc::channel();
        let (events_tx, repaint) = (tx.clone(), ctx.clone());
        let _ = std::thread::Builder::new().name("service-events".into()).spawn(move || {
            // Reported once when the service is first found missing, and once
            // each time a connection ends; not every retry.
            let mut report_failure = true;
            // A Windows notification when protection has been down a while
            // (not for a quick restart, nor while Windows is still starting
            // the service at sign-in), and when it is back.
            let started = Instant::now();
            let mut down_since: Option<Instant> = None;
            let mut warned = false;
            loop {
                let subscribed = Client::connect().and_then(|mut client| {
                    client.call(Request::Subscribe)?;
                    Ok(client)
                });
                match subscribed {
                    Ok(mut client) => {
                        report_failure = false;
                        down_since = None;
                        if std::mem::take(&mut warned) && notify.threats() {
                            threat_scanner::system::notify("Phalanx protection is back", "The protection service is running again.");
                        }
                        if events_tx.send(LinkMsg::Connected).is_err() {
                            return;
                        }
                        repaint.request_repaint();
                        let reason = loop {
                            match client.next_message() {
                                Ok(ServerMessage::Event { event }) => {
                                    let Ok(event) = serde_json::from_value::<Event>(event) else { continue };
                                    crate::notify_event(&event, &notify);
                                    if events_tx.send(LinkMsg::Event(Box::new(event))).is_err() {
                                        return;
                                    }
                                    repaint.request_repaint();
                                }
                                Ok(_) => {}
                                Err(e) => break ipc::describe(&e),
                            }
                        };
                        if events_tx.send(LinkMsg::Lost(reason)).is_err() {
                            return;
                        }
                        repaint.request_repaint();
                    }
                    Err(e) => {
                        let since = *down_since.get_or_insert_with(Instant::now);
                        if !warned && since.elapsed() >= DOWN_GRACE && started.elapsed() >= STARTUP_GRACE && notify.threats() {
                            warned = true;
                            threat_scanner::system::notify(
                                "Phalanx protection is not running",
                                "The Phalanx protection service stopped, so this PC is not protected. Open Phalanx to see what to do.",
                            );
                        }
                        if report_failure {
                            report_failure = false;
                            if events_tx.send(LinkMsg::Lost(ipc::describe(&e))).is_err() {
                                return;
                            }
                            repaint.request_repaint();
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        });
        Self { tx, rx, ctx: ctx.clone() }
    }

    /// Draws again after `wait` (a [`Settle`] waiting).
    pub fn repaint_after(&self, wait: Duration) {
        self.ctx.request_repaint_after(wait);
    }

    /// Runs `work` on a thread of its own and `then` with its result on the
    /// UI thread.
    pub fn run<T: Send + 'static>(&self, work: impl FnOnce() -> T + Send + 'static, then: impl FnOnce(&mut App, T) + Send + 'static) {
        let (tx, ctx) = (self.tx.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let result = work();
            let _ = tx.send(LinkMsg::Done(Box::new(move |app: &mut App| then(app, result))));
            ctx.request_repaint();
        });
    }
}

/// Waits for a value edited on a page to stop changing before it is sent, so
/// a slider dragged or a field typed in asks the service (and maybe
/// Windows' prompt) once, not at every step.
pub struct Settle<T> {
    last: Option<(T, Instant)>,
}

impl<T> Default for Settle<T> {
    fn default() -> Self {
        Self { last: None }
    }
}

/// How long a value must stay the same.
pub const SETTLE: Duration = Duration::from_millis(700);

impl<T: PartialEq + Clone> Settle<T> {
    /// Whether `value` has stayed the same for [`SETTLE`].
    pub fn settled(&mut self, value: &T) -> bool {
        match &self.last {
            Some((last, since)) if last == value => since.elapsed() >= SETTLE,
            _ => {
                self.last = Some((value.clone(), Instant::now()));
                false
            }
        }
    }
}

/// Sends one request on a connection of its own (call it off the UI thread).
pub fn call(request: Request) -> Result<Reply, String> {
    Client::connect().and_then(|mut client| client.call(request)).map_err(|e| ipc::describe(&e))
}

/// Sends one request and returns its result.
pub fn read<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, String> {
    call(request)?.into_result().map_err(|e| e.to_string())
}

/// Sends `request` and returns its result; when it needs an administrator's
/// approval, runs `phalanx-cli` with `approve_args` elevated (Windows shows
/// its prompt) and returns `then_read`'s result after it.
pub fn with_approval<T: serde::de::DeserializeOwned>(request: Request, approve_args: &str, then_read: impl FnOnce() -> Result<T, String>) -> Approval<T> {
    let reply = match call(request) {
        Ok(reply) => reply,
        Err(e) => return Approval::Failed(e),
    };
    if reply.ok {
        return match reply.into_result() {
            Ok(value) => Approval::Done(value),
            Err(e) => Approval::Failed(e.to_string()),
        };
    }
    if !reply.needs_approval {
        return Approval::Failed(reply.error.unwrap_or_default());
    }
    let cli = match std::env::current_exe() {
        Ok(exe) => exe.with_file_name("phalanx-cli.exe"),
        Err(e) => return Approval::Failed(e.to_string()),
    };
    // The elevated copy starts with a fresh environment: pass on a
    // development pipe.
    let args = match std::env::var(ipc::PIPE_ENV) {
        Ok(pipe) if !pipe.trim().is_empty() => format!("--pipe \"{pipe}\" {approve_args}"),
        _ => approve_args.to_string(),
    };
    match threat_scanner::system::run_elevated(&cli, &args) {
        Ok(threat_scanner::system::Elevated::Exited(0)) => match then_read() {
            Ok(value) => Approval::Done(value),
            Err(e) => Approval::Failed(e),
        },
        Ok(threat_scanner::system::Elevated::Exited(_)) => Approval::Failed("the change could not be made".into()),
        Ok(threat_scanner::system::Elevated::Declined) => Approval::Declined,
        Err(e) => Approval::Failed(format!("{e:#}")),
    }
}

/// `value` as JSON, hex-encoded: how settings travel on `phalanx-cli`'s
/// command line (not in a file a program could change in the meantime).
pub fn hex_json<T: serde::Serialize>(value: &T) -> String {
    hex::encode(serde_json::to_vec(value).unwrap_or_default())
}
