//! The protection service's core: the pipe server and what it does with each
//! request. `phalanx-service.exe` runs it under Windows' service manager;
//! tests and `phalanx-service --console` run it in-process, on a private
//! pipe name. See `docs/protection-service.md` for the design.

pub mod data;
pub mod migrate;
pub mod protect;
pub mod settings;
pub mod updates;
pub mod web;
#[cfg(windows)]
pub mod manage;

use crate::ipc::{Caller, ClientMessage, Reply, Request, Status};
use crate::web::WebConfig;
use protect::{Hub, Protector};
use std::sync::atomic::{AtomicBool, Ordering};
use updates::Updater;
use web::WebGuard;
use std::sync::Arc;
use crate::quarantine::Quarantine;
use crate::scan;
use crate::store::Store;
use serde::Serialize;
use serde_json::json;
use settings::ProtectionSettings;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The service's name in Windows' service manager.
pub const SERVICE_NAME: &str = "Phalanx";
pub const DISPLAY_NAME: &str = "Phalanx Protection";
pub const DESCRIPTION: &str = "Phalanx's real-time protection, web protection and scans. It keeps protecting the PC when nobody is signed in and cannot be stopped by programs running as a user.";

/// What the request handler needs to know about the running service.
struct Context {
    started: u64,
    data_dir: PathBuf,
    /// One settings change (or migration) at a time.
    settings: Mutex<()>,
    /// Told when an administrator asks the service to stop.
    stop_requested: std::sync::mpsc::Sender<()>,
    hub: Arc<Hub>,
    protector: Arc<Protector>,
    web: Arc<WebGuard>,
    updater: Arc<Updater>,
}

impl Context {
    /// Applies web settings off the pipe's threads (the DNS filter may restart).
    fn reapply_web(&self, config: WebConfig) {
        let web = Arc::clone(&self.web);
        let _ = std::thread::Builder::new().name("apply-web".into()).spawn(move || web.apply(&config));
    }

    /// Starts protection again with `settings`, off the pipe's threads
    /// (loading signatures takes seconds).
    fn reapply(&self, settings: ProtectionSettings) {
        let protector = Arc::clone(&self.protector);
        let _ = std::thread::Builder::new().name("apply-settings".into()).spawn(move || protector.apply(&settings));
    }
}

/// One client's connection: its history database, opened when first needed.
#[derive(Default)]
struct Session {
    store: Option<Store>,
}

impl Session {
    fn store(&mut self, data_dir: &Path) -> anyhow::Result<&Store> {
        if self.store.is_none() {
            self.store = Some(scan::open_store(data_dir)?);
        }
        Ok(self.store.as_ref().expect("just opened"))
    }
}

fn reply<T: Serialize>(id: u64, result: anyhow::Result<T>) -> Reply {
    match result.and_then(|value| Ok(serde_json::to_value(value)?)) {
        Ok(value) => Reply::ok(id, value),
        Err(e) => Reply::error(id, format!("{e:#}")),
    }
}

/// Answers one request from `caller`.
fn handle(ctx: &Context, session: &mut Session, caller: &Caller, message: ClientMessage) -> Reply {
    let id = message.id;
    if !caller.may(&message.request) {
        return Reply::needs_approval(id);
    }
    let dir = ctx.data_dir.as_path();
    match message.request {
        Request::Ping => Reply::ok(id, json!("pong")),
        Request::Status => reply(
            id,
            Ok(Status {
                version: env!("CARGO_PKG_VERSION").into(),
                pid: std::process::id(),
                started: ctx.started,
                caller: caller.clone(),
                data_dir: ctx.data_dir.clone(),
            }),
        ),
        Request::Stop => {
            let _ = ctx.stop_requested.send(());
            Reply::ok(id, json!("stopping"))
        }
        Request::GetSettings => reply(id, ProtectionSettings::load(dir)),
        Request::SetSettings { settings } => {
            let _one_at_a_time = ctx.settings.lock().unwrap_or_else(|p| p.into_inner());
            let current = match ProtectionSettings::load(dir) {
                Ok(current) => current,
                Err(e) => return Reply::error(id, format!("{e:#}")),
            };
            let weaker = current.weakened_by(&settings);
            if !weaker.is_empty() && !caller.admin {
                return Reply::needs_approval_because(id, &weaker);
            }
            reply(
                id,
                settings.save(dir).map(|()| {
                    ctx.reapply(settings.clone());
                    ctx.hub.send(&crate::ipc::Event::SettingsChanged { settings: settings.clone() });
                    settings
                }),
            )
        }
        Request::RecentScans { limit, kind } => reply(id, session.store(dir).and_then(|s| s.recent_scans(limit, kind.as_deref()))),
        Request::ScanDetails { scan } => reply(
            id,
            session.store(dir).and_then(|s| Ok(json!({ "detections": s.scan_detections(scan)?, "errors": s.scan_errors(scan)? }))),
        ),
        Request::RecentDetections { limit } => reply(id, session.store(dir).and_then(|s| s.recent_detections(limit))),
        Request::MonthlySummary => reply(id, session.store(dir).and_then(|s| s.monthly_summary())),
        Request::Quarantine { include_restored } => reply(id, session.store(dir).and_then(|s| s.quarantine_items(include_restored))),
        Request::Restore { item, force } => reply(
            id,
            session.store(dir).and_then(|s| Quarantine::new(scan::quarantine_dir(dir), s)?.restore(&item, force)),
        ),
        Request::DeleteQuarantined { item } => {
            reply(id, session.store(dir).and_then(|s| Quarantine::new(scan::quarantine_dir(dir), s)?.delete(&item)))
        }
        Request::Migrate { from, auth_key } => {
            let _one_at_a_time = ctx.settings.lock().unwrap_or_else(|p| p.into_inner());
            // Reopened after the import, so this session sees it.
            session.store = None;
            let done = migrate::migrate(&from, dir).and_then(|done| {
                // The copied key is encrypted for the user: save it again as SYSTEM.
                if let Some(key) = auth_key.as_deref() {
                    updates::save_auth_key(dir, Some(key))?;
                }
                Ok(done)
            });
            if done.is_ok() {
                let (settings, web) = (ProtectionSettings::load(dir).unwrap_or_default(), WebConfig::load(dir).unwrap_or_default());
                ctx.hub.send(&crate::ipc::Event::SettingsChanged { settings: settings.clone() });
                ctx.hub.send(&crate::ipc::Event::WebSettingsChanged { settings: web.clone() });
                ctx.reapply(settings);
                ctx.reapply_web(web);
            }
            reply(id, done)
        }
        Request::UpdateSignatures { force } => reply(id, ctx.updater.start(force).map(|()| json!("started"))),
        Request::SetAuthKey { key } => reply(id, updates::save_auth_key(dir, key.as_deref())),
        Request::GetWebSettings => reply(id, WebConfig::load(dir)),
        Request::SetWebSettings { settings } => {
            let _one_at_a_time = ctx.settings.lock().unwrap_or_else(|p| p.into_inner());
            let current = match WebConfig::load(dir) {
                Ok(current) => current,
                Err(e) => return Reply::error(id, format!("{e:#}")),
            };
            let weaker = current.weakened_by(&settings);
            if !weaker.is_empty() && !caller.admin {
                return Reply::needs_approval_because(id, &weaker);
            }
            reply(
                id,
                settings.save(dir).map(|()| {
                    ctx.reapply_web(settings.clone());
                    ctx.hub.send(&crate::ipc::Event::WebSettingsChanged { settings: settings.clone() });
                    settings
                }),
            )
        }
        Request::ChangeSite { change, site } => {
            let _one_at_a_time = ctx.settings.lock().unwrap_or_else(|p| p.into_inner());
            if change.weakens() && !caller.admin {
                let what = if change == crate::web::SiteChange::Allow { "allows" } else { "stops blocking" };
                return Reply::needs_approval_because(id, &[format!("{what} {}", site.trim())]);
            }
            let mut config = match WebConfig::load(dir) {
                Ok(config) => config,
                Err(e) => return Reply::error(id, format!("{e:#}")),
            };
            match config.change_site(change, &site) {
                Err(e) => Reply::error(id, e.to_string()),
                Ok(host) => reply(
                    id,
                    config.save(dir).map(|()| {
                        ctx.reapply_web(config.clone());
                        ctx.hub.send(&crate::ipc::Event::WebSettingsChanged { settings: config.clone() });
                        json!({ "site": host, "settings": config })
                    }),
                ),
            }
        }
        Request::WebStatus => reply(id, Ok(ctx.web.status())),
        Request::QuarantineFile { path, threat } => reply(id, session.store(dir).and_then(|s| quarantine_any(s, dir, &plain(&path), &threat))),
        // Handled by the connection itself (see `imp::serve`).
        Request::Subscribe => Reply::ok(id, json!("subscribed")),
        Request::ProtectionStatus => reply(id, Ok(ctx.protector.status())),
        Request::RunBoxView => reply(id, Ok(crate::rtp::commands::run_box_view())),
        Request::Scan { paths, kind } => {
            let paths = paths.iter().map(|p| plain(p)).collect();
            reply(id, ProtectionSettings::load(dir).and_then(|settings| ctx.protector.scan(paths, &kind, &settings)).map(|job| json!({ "job": job })))
        }
        Request::CancelScan { job } => match ctx.protector.cancel(job) {
            true => Reply::ok(id, json!("cancelling")),
            false => Reply::error(id, format!("there is no scan {job} running")),
        },
        Request::QuarantineDetection { scan, path } => reply(id, session.store(dir).and_then(|s| quarantine_detection(s, dir, scan, &path))),
    }
}

/// Quarantines `path` as `threat`, whatever it is (an administrator asked).
fn quarantine_any(store: &Store, dir: &Path, path: &Path, threat: &str) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    drop(file);
    scan::quarantine_file(store, dir, path, &hex::encode(hasher.finalize()), threat)
}

/// One spelling per file in history: `\\?\C:\x` is `C:\x`, and
/// `\\?\UNC\server\share` is `\\server\share`.
fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// Quarantines a file that scan `scan` detected and recorded, if it is
/// unchanged since. Nothing else: a user may not have the service (as
/// SYSTEM) remove files of their choosing.
fn quarantine_detection(store: &Store, dir: &Path, scan: i64, path: &Path) -> anyhow::Result<String> {
    let path = plain(path);
    let mut shown = path.display().to_string();
    let mut record = store.detection_record(scan, &shown)?;
    // Recorded with the `\\?\` prefix (before paths were made plain).
    if record.is_none() {
        let verbatim = format!(r"\\?\{shown}");
        record = store.detection_record(scan, &verbatim)?;
        if record.is_some() {
            shown = verbatim;
        }
    }
    let Some((sha256, threat, action)) = record else {
        anyhow::bail!("scan {scan} reported no threat at {}", path.display());
    };
    if action.contains("quarantined (") {
        anyhow::bail!("{shown} is already quarantined");
    }
    let quarantined = scan::quarantine_file(store, dir, &path, &sha256, &threat)?;
    store.set_detection_action(scan, &shown, &format!("quarantined ({quarantined})"), true)?;
    Ok(quarantined)
}

/// The service running in this process. Dropping it stops the pipe server,
/// real-time protection and scans.
pub struct Running {
    /// Held so that dropping `Running` stops the pipe server.
    #[cfg(windows)]
    _server: imp::Running,
    stop_requests: std::sync::mpsc::Receiver<()>,
    protector: Arc<Protector>,
    web: Arc<WebGuard>,
    /// Stops the update schedule.
    schedule: Arc<AtomicBool>,
    /// Loading signatures and starting protection, at start.
    starting: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.schedule.store(true, Ordering::Relaxed);
        if let Some(starting) = self.starting.take() {
            let _ = starting.join();
        }
        self.protector.stop();
        self.web.stop();
    }
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
/// the real service), keeping its data in `data_dir` (for the real service,
/// [`data::machine_data_dir`] after [`data::prepare`]). Fails if another
/// process already holds the pipe name.
pub fn start(pipe_name: &str, data_dir: &Path) -> io::Result<Running> {
    std::fs::create_dir_all(data_dir)?;
    let (tx, rx) = std::sync::mpsc::channel();
    let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let hub = Arc::new(Hub::default());
    let protector = Protector::new(data_dir, Arc::clone(&hub));
    let web = WebGuard::new(data_dir, Arc::clone(&hub));
    // New signatures or web rules: reload the engine and the web rules.
    let (reload_engine, reload_web, settings_dir) = (Arc::clone(&protector), Arc::clone(&web), data_dir.to_path_buf());
    let updater = Updater::new(data_dir, Arc::clone(&hub), move || {
        reload_engine.reload_signatures(&ProtectionSettings::load(&settings_dir).unwrap_or_default());
        reload_web.reload();
    });
    let ctx = Context {
        started,
        data_dir: data_dir.to_path_buf(),
        settings: Mutex::new(()),
        stop_requested: tx,
        hub,
        protector: Arc::clone(&protector),
        web: Arc::clone(&web),
        updater: Arc::clone(&updater),
    };
    let schedule = Arc::new(AtomicBool::new(false));
    #[cfg(windows)]
    {
        let server = imp::start(pipe_name, ctx)?;
        let (starter, web_starter, dir) = (Arc::clone(&protector), Arc::clone(&web), data_dir.to_path_buf());
        let starting = std::thread::Builder::new().name("start-protection".into()).spawn(move || {
            starter.apply(&ProtectionSettings::load(&dir).unwrap_or_default());
            web_starter.reload();
        })?;
        updater.schedule(Arc::clone(&schedule));
        Ok(Running { _server: server, stop_requests: rx, protector, web, schedule, starting: Some(starting) })
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe_name, ctx, rx, protector, web, updater, schedule);
        Err(io::Error::new(io::ErrorKind::Unsupported, "the protection service is Windows only"))
    }
}

#[cfg(windows)]
mod imp {
    use super::{handle, Context};
    use crate::ipc::{ClientMessage, Connection, Reply, Request, Server, ServerMessage};
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

    /// Answers one client until it disconnects, or until it subscribes:
    /// from then on the connection only carries events, written by the
    /// hub, and is no longer read. (On a synchronous pipe a pending read
    /// would hold up every write, so one connection cannot do both.)
    fn serve(connection: Connection, ctx: &Context) {
        let Ok(read) = connection.file.try_clone() else { return };
        let mut writer = connection.file;
        let mut caller = None;
        let mut session = super::Session::default();
        for line in BufReader::new(read).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            // Who is asking, once: the client has written, so it can be read.
            if caller.is_none() {
                caller = connection_caller(&writer);
            }
            let message = serde_json::from_str::<ClientMessage>(&line);
            let subscribing = matches!(&message, Ok(m) if m.request == Request::Subscribe) && caller.is_some();
            let reply = match (message, &caller) {
                (Err(e), _) => Reply::error(0, format!("not a request: {e}")),
                (Ok(message), None) => Reply::error(message.id, "could not tell who is asking"),
                (Ok(message), Some(caller)) => handle(ctx, &mut session, caller, message),
            };
            let Ok(mut text) = serde_json::to_string(&ServerMessage::Reply(reply)) else { break };
            text.push('\n');
            if writer.write_all(text.as_bytes()).is_err() || writer.flush().is_err() {
                break;
            }
            if subscribing {
                ctx.hub.subscribe(Box::new(writer));
                return;
            }
        }
    }

    fn connection_caller(file: &std::fs::File) -> Option<crate::ipc::Caller> {
        Connection { file: file.try_clone().ok()? }.caller().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::plain;
    use std::path::{Path, PathBuf};

    #[test]
    fn paths_have_one_spelling() {
        assert_eq!(plain(Path::new(r"\\?\C:\Users\me\x.exe")), PathBuf::from(r"C:\Users\me\x.exe"));
        assert_eq!(plain(Path::new(r"\\?\UNC\server\share\x.exe")), PathBuf::from(r"\\server\share\x.exe"));
        assert_eq!(plain(Path::new(r"C:\Users\me\x.exe")), PathBuf::from(r"C:\Users\me\x.exe"));
    }
}
