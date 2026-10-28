//! The protection service's core: the pipe server and what it does with each
//! request. `phalanx-service.exe` runs it under Windows' service manager;
//! tests and `phalanx-service --console` run it in-process, on a private
//! pipe name. See `docs/protection-service.md` for the design.

pub mod data;
pub mod history;
pub mod migrate;
pub mod protect;
pub mod settings;
pub mod updates;
pub mod web;
#[cfg(windows)]
pub mod manage;

use crate::ipc::{replies, Caller, ClientMessage, Reply, Request, ScanDetails, Status};
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
    /// The service's parts, none of them started yet.
    fn new(data_dir: &Path, stop_requested: std::sync::mpsc::Sender<()>) -> Self {
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
        Context { started, data_dir: data_dir.to_path_buf(), settings: Mutex::new(()), stop_requested, hub, protector, web, updater }
    }

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
        Request::Ping => reply::<replies::Ping>(id, Ok("pong".into())),
        Request::Status => reply::<replies::Status>(
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
            reply::<replies::Stop>(id, Ok("stopping".into()))
        }
        Request::GetSettings => reply::<replies::GetSettings>(id, ProtectionSettings::load(dir)),
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
            reply::<replies::SetSettings>(
                id,
                settings.save(dir).map(|()| {
                    ctx.reapply(settings.clone());
                    ctx.hub.send(&crate::ipc::Event::SettingsChanged { settings: settings.clone() });
                    settings
                }),
            )
        }
        Request::HistoryInfo => reply::<replies::HistoryInfo>(id, history::info(dir)),
        Request::ReviewFinding { detection, verdict, note } => reply::<replies::ReviewFinding>(
            id,
            session.store(dir).and_then(|s| s.review(detection, verdict.map(|v| (v, note.as_str())), &caller.user)),
        ),
        Request::ExportHistory { query } => reply::<replies::ExportHistory>(id, session.store(dir).and_then(|s| s.export(&query))),
        Request::DeleteHistory { target } => {
            reply::<replies::DeleteHistory>(id, session.store(dir).and_then(|s| s.delete_history(&target)).map(|n| n as u64))
        }
        Request::History { query } => reply::<replies::History>(id, session.store(dir).and_then(|s| s.history(&query))),
        Request::RecentScans { limit, kind } => reply::<replies::RecentScans>(id, session.store(dir).and_then(|s| s.recent_scans(limit, kind.as_deref()))),
        Request::ScanDetails { scan } => reply::<replies::ScanDetails>(
            id,
            session.store(dir).and_then(|s| Ok(ScanDetails { detections: s.scan_detections(scan)?, errors: s.scan_errors(scan)? })),
        ),
        Request::RecentDetections { limit } => reply::<replies::RecentDetections>(id, session.store(dir).and_then(|s| s.recent_detections(limit))),
        Request::MonthlySummary => reply::<replies::MonthlySummary>(id, session.store(dir).and_then(|s| s.monthly_summary())),
        Request::Quarantine { include_restored } => reply::<replies::Quarantine>(id, session.store(dir).and_then(|s| s.quarantine_items(include_restored))),
        Request::Restore { item, force } => reply::<replies::Restore>(
            id,
            session.store(dir).and_then(|s| Quarantine::new(scan::quarantine_dir(dir), s)?.restore(&item, force)),
        ),
        Request::DeleteQuarantined { item } => {
            reply::<replies::DeleteQuarantined>(id, session.store(dir).and_then(|s| Quarantine::new(scan::quarantine_dir(dir), s)?.delete(&item)))
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
            reply::<replies::Migrate>(id, done)
        }
        Request::UpdateSignatures { force } => reply::<replies::UpdateSignatures>(id, ctx.updater.start(force).map(|()| "started".into())),
        Request::SetAuthKey { key } => reply::<replies::SetAuthKey>(id, updates::save_auth_key(dir, key.as_deref())),
        Request::GetWebSettings => reply::<replies::GetWebSettings>(id, WebConfig::load(dir)),
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
            reply::<replies::SetWebSettings>(
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
                Ok(host) => reply::<replies::ChangeSite>(
                    id,
                    config.save(dir).map(|()| {
                        ctx.reapply_web(config.clone());
                        ctx.hub.send(&crate::ipc::Event::WebSettingsChanged { settings: config.clone() });
                        replies::SiteChanged { site: host, settings: config }
                    }),
                ),
            }
        }
        Request::WebStatus => reply::<replies::WebStatus>(id, Ok(ctx.web.status())),
        Request::QuarantineFile { path, threat } => reply::<replies::QuarantineFile>(id, session.store(dir).and_then(|s| quarantine_any(s, dir, &plain(&path), &threat))),
        // Handled by the connection itself (see `imp::serve`).
        Request::Subscribe => reply::<replies::Subscribe>(id, Ok("subscribed".into())),
        Request::ProtectionStatus => reply::<replies::ProtectionStatus>(id, Ok(ctx.protector.status())),
        Request::RunBoxView => reply::<replies::RunBoxView>(id, Ok(crate::rtp::commands::run_box_view())),
        Request::Scan { paths, kind } => {
            let paths = paths.iter().map(|p| plain(p)).collect();
            reply::<replies::Scan>(id, ProtectionSettings::load(dir).and_then(|settings| ctx.protector.scan(paths, &kind, &settings)).map(|job| replies::ScanStarted { job }))
        }
        Request::CancelScan { job } => match ctx.protector.cancel(job) {
            true => reply::<replies::CancelScan>(id, Ok("cancelling".into())),
            false => Reply::error(id, format!("there is no scan {job} running")),
        },
        Request::QuarantineDetection { scan, path } => reply::<replies::QuarantineDetection>(id, session.store(dir).and_then(|s| quarantine_detection(s, dir, scan, &path))),
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
    let ctx = Context::new(data_dir, tx);
    let (protector, web, updater) = (Arc::clone(&ctx.protector), Arc::clone(&ctx.web), Arc::clone(&ctx.updater));
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
        history::schedule(data_dir, Arc::clone(&schedule));
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
    use super::{handle, plain, Context, Session};
    use crate::ipc::{replies, Caller, ClientMessage, Reply, Request};
    use crate::service::settings::ProtectionSettings;
    use crate::web::{SiteChange, WebConfig};
    use serde::de::DeserializeOwned;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    /// Every kind of request there is. A new one fails the contract test
    /// until it is sent there (and given a type in [`replies`]).
    const REQUEST_KINDS: usize = 31;

    /// Reads `reply` as its request's type in [`replies`], as clients do.
    /// The match has no catch-all, so a new request does not compile
    /// without one.
    fn contract(request: &Request, reply: Reply) -> Result<(), String> {
        fn read<T: DeserializeOwned>(reply: Reply) -> Result<(), String> {
            reply.into_result::<T>().map(drop).map_err(|e| e.to_string())
        }
        match request {
            Request::Ping => read::<replies::Ping>(reply),
            Request::Status => read::<replies::Status>(reply),
            Request::Stop => read::<replies::Stop>(reply),
            Request::GetSettings => read::<replies::GetSettings>(reply),
            Request::SetSettings { .. } => read::<replies::SetSettings>(reply),
            Request::RecentScans { .. } => read::<replies::RecentScans>(reply),
            Request::History { .. } => read::<replies::History>(reply),
            Request::HistoryInfo => read::<replies::HistoryInfo>(reply),
            Request::ReviewFinding { .. } => read::<replies::ReviewFinding>(reply),
            Request::DeleteHistory { .. } => read::<replies::DeleteHistory>(reply),
            Request::ExportHistory { .. } => read::<replies::ExportHistory>(reply),
            Request::ScanDetails { .. } => read::<replies::ScanDetails>(reply),
            Request::RecentDetections { .. } => read::<replies::RecentDetections>(reply),
            Request::MonthlySummary => read::<replies::MonthlySummary>(reply),
            Request::Quarantine { .. } => read::<replies::Quarantine>(reply),
            Request::Restore { .. } => read::<replies::Restore>(reply),
            Request::DeleteQuarantined { .. } => read::<replies::DeleteQuarantined>(reply),
            Request::Migrate { .. } => read::<replies::Migrate>(reply),
            Request::Subscribe => read::<replies::Subscribe>(reply),
            Request::ProtectionStatus => read::<replies::ProtectionStatus>(reply),
            Request::RunBoxView => read::<replies::RunBoxView>(reply),
            Request::Scan { .. } => read::<replies::Scan>(reply),
            Request::CancelScan { .. } => read::<replies::CancelScan>(reply),
            Request::QuarantineDetection { .. } => read::<replies::QuarantineDetection>(reply),
            Request::UpdateSignatures { .. } => read::<replies::UpdateSignatures>(reply),
            Request::SetAuthKey { .. } => read::<replies::SetAuthKey>(reply),
            Request::GetWebSettings => read::<replies::GetWebSettings>(reply),
            Request::SetWebSettings { .. } => read::<replies::SetWebSettings>(reply),
            Request::ChangeSite { .. } => read::<replies::ChangeSite>(reply),
            Request::WebStatus => read::<replies::WebStatus>(reply),
            Request::QuarantineFile { .. } => read::<replies::QuarantineFile>(reply),
        }
    }

    /// Sends requests the way the pipe delivers them, as an administrator
    /// (so the requests only administrators may make are checked too), and
    /// checks each reply against its contract.
    struct Service {
        ctx: Context,
        session: Session,
        admin: Caller,
        next_id: u64,
        checked: BTreeSet<String>,
    }

    impl Service {
        fn ask(&mut self, request: Request) -> Reply {
            let reply = self.send(request.clone());
            assert!(reply.ok, "{request:?} failed: {:?}", reply.error);
            self.check(&request, &reply);
            reply
        }

        /// Like `ask`, for a request that may fairly fail (`allowed` is part
        /// of its error); its type is checked when it succeeds.
        fn ask_or(&mut self, request: Request, allowed: &str) {
            let reply = self.send(request.clone());
            if reply.ok {
                self.check(&request, &reply);
            } else {
                assert!(reply.error.as_deref().is_some_and(|e| e.contains(allowed)), "{request:?} failed: {:?}", reply.error);
                self.checked.insert(kind(&request));
            }
        }

        fn send(&mut self, request: Request) -> Reply {
            self.next_id += 1;
            // Through JSON both ways, as on the pipe.
            let message: ClientMessage = serde_json::from_str(&serde_json::to_string(&ClientMessage { id: self.next_id, request }).unwrap()).unwrap();
            let reply = handle(&self.ctx, &mut self.session, &self.admin, message);
            serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap()
        }

        fn check(&mut self, request: &Request, reply: &Reply) {
            if let Err(e) = contract(request, reply.clone()) {
                panic!("the reply to {request:?} does not read as its type in `replies`: {e}\n{:?}", reply.result);
            }
            self.checked.insert(kind(request));
        }
    }

    /// The request's name on the wire.
    fn kind(request: &Request) -> String {
        serde_json::to_value(request).unwrap()["op"].as_str().unwrap().to_string()
    }

    fn read<T: DeserializeOwned>(reply: Reply) -> T {
        reply.into_result().unwrap()
    }

    /// The service's events as they are written to a subscriber.
    #[derive(Clone, Default)]
    struct Events(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Events {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Events {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    #[test]
    fn every_reply_reads_back_as_its_named_type() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("data");
        std::fs::create_dir_all(&dir).unwrap();
        // Protection, the DNS filter and web rules stay off: this checks
        // replies, not protection. Scans run at normal priority: in
        // background mode they can wait out a busy test run.
        let quiet = ProtectionSettings { watch_enabled: false, performance: crate::system::Performance::Fast, ..Default::default() };
        quiet.save(&dir).unwrap();
        let web_off = WebConfig { enabled: false, dns_filter: false, ..Default::default() };
        web_off.save(&dir).unwrap();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let ctx = Context::new(&dir, stop_tx);
        let events = Events::default();
        ctx.hub.subscribe(Box::new(events.clone()));
        // Loads the signatures, for the scans below.
        ctx.protector.apply(&quiet);
        let admin = Caller { user: r"TEST\admin".into(), sid: "S-1-5-21-0-0-0-500".into(), admin: true };
        let mut service = Service { ctx, session: Session::default(), admin, next_id: 0, checked: BTreeSet::new() };

        service.ask(Request::Ping);
        service.ask(Request::Status);
        service.ask(Request::GetSettings);
        service.ask(Request::SetSettings { settings: quiet.clone() });
        service.ask(Request::ProtectionStatus);
        service.ask(Request::RunBoxView);
        service.ask(Request::Subscribe);
        service.ask(Request::SetAuthKey { key: None });
        service.ask(Request::GetWebSettings);
        service.ask(Request::SetWebSettings { settings: web_off.clone() });
        let changed: replies::ChangeSite = read(service.ask(Request::ChangeSite { change: SiteChange::Block, site: "https://example.test/x".into() }));
        assert_eq!(changed.site, "example.test");
        service.ask(Request::WebStatus);

        // A scan that finds the test marker, for History and quarantine.
        let scanned = tmp.path().join("scanned");
        std::fs::create_dir_all(&scanned).unwrap();
        let bad = scanned.join("setup.txt");
        std::fs::write(&bad, format!("x {} y", "threat-scanner-test-marker-7f3a".to_ascii_uppercase())).unwrap();
        service.ask(Request::Scan { paths: vec![scanned.clone()], kind: "custom".into() });
        let deadline = Instant::now() + Duration::from_secs(30);
        let scan = loop {
            let scans: replies::RecentScans = read(service.ask(Request::RecentScans { limit: 10, kind: Some("custom".into()) }));
            if let Some(row) = scans.iter().find(|s| s.detections > 0 && s.finished_at.is_some()) {
                break row.id;
            }
            assert!(Instant::now() < deadline, "the scan did not finish: {scans:?}
events:
{}", events.text());
            std::thread::sleep(Duration::from_millis(100));
        };
        // A second scan, cancelled; it may finish first.
        let started: replies::Scan = read(service.ask(Request::Scan { paths: vec![scanned.clone()], kind: "custom".into() }));
        service.ask_or(Request::CancelScan { job: started.job }, "there is no scan");
        let page: replies::History = read(service.ask(Request::History {
            query: crate::store::HistoryQuery { limit: 10, threats_only: true, text: Some("setup.TXT".into()), ..Default::default() },
        }));
        assert_eq!(page.scans.iter().map(|s| s.id).collect::<Vec<_>>(), vec![scan], "{page:?}");
        let details: replies::ScanDetails = read(service.ask(Request::ScanDetails { scan }));
        assert_eq!(details.detections.len(), 1, "{details:?}");
        let finding = details.detections[0].id;
        let mark: replies::ReviewFinding = read(service.ask(Request::ReviewFinding {
            detection: finding,
            verdict: Some(crate::store::Verdict::FalsePositive),
            note: "a test file".into(),
        }));
        assert_eq!(mark.map(|m| m.by), Some(r"TEST\admin".to_string()), "who marked it is the caller, not the client's say");
        let again: replies::ScanDetails = read(service.ask(Request::ScanDetails { scan }));
        assert_eq!(again.detections[0].review.as_ref().map(|r| r.note.as_str()), Some("a test file"));
        let rows: replies::ExportHistory = read(service.ask(Request::ExportHistory { query: crate::store::HistoryQuery { threats_only: true, ..Default::default() } }));
        assert!(rows.iter().any(|r| r.finding == Some(finding) && r.review_note.as_deref() == Some("a test file")), "{rows:?}");
        service.ask(Request::RecentDetections { limit: 10 });
        let info: replies::HistoryInfo = read(service.ask(Request::HistoryInfo));
        assert!(info.scans >= 1 && info.bytes > 0, "{info:?}");
        service.ask(Request::MonthlySummary);

        // Quarantine: what the scan found, then put back; a file no scan
        // found, then deleted.
        let id: replies::QuarantineDetection = read(service.ask(Request::QuarantineDetection { scan, path: bad.clone() }));
        let listed: replies::Quarantine = read(service.ask(Request::Quarantine { include_restored: false }));
        assert!(listed.iter().any(|q| q.id == id), "{listed:?}");
        let back: replies::Restore = read(service.ask(Request::Restore { item: id, force: false }));
        assert!(back.ends_with("setup.txt") && bad.exists(), "{back:?}");
        let other = tmp.path().join("other.txt");
        std::fs::write(&other, "flagged by AI Inspect").unwrap();
        let id: replies::QuarantineFile = read(service.ask(Request::QuarantineFile { path: other.clone(), threat: "Test.Contract".into() }));
        service.ask(Request::DeleteQuarantined { item: id });

        // Deleting: nothing matches here, then the cancelled scan, if it left one.
        let none = crate::store::HistoryQuery { text: Some("nothing has this name".into()), ..Default::default() };
        let deleted: replies::DeleteHistory = read(service.ask(Request::DeleteHistory { target: crate::store::DeleteTarget::Matching { query: none } }));
        assert_eq!(deleted, 0);
        let cancelled = crate::store::HistoryQuery { kinds: vec!["custom".into()], ..Default::default() };
        let all: replies::History = read(service.ask(Request::History { query: crate::store::HistoryQuery { limit: 10, ..cancelled } }));
        let others: Vec<i64> = all.scans.iter().map(|s| s.id).filter(|id| *id != scan).collect();
        let deleted: replies::DeleteHistory = read(service.ask(Request::DeleteHistory { target: crate::store::DeleteTarget::Scans { ids: others.clone() } }));
        assert_eq!(deleted, others.len() as u64);

        // A 0.4 user's folder brought over (protection stays off there too).
        let old = tmp.path().join("old-user");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("gui-settings.json"), r#"{"watch_enabled": false}"#).unwrap();
        service.ask(Request::Migrate { from: old, auth_key: None });

        // Not sent: it would download every feed. Its reply is built with
        // `replies::UpdateSignatures`, which the compiler checks.
        service.checked.insert(kind(&Request::UpdateSignatures { force: false }));

        service.ask(Request::Stop);
        assert!(stop_rx.try_recv().is_ok(), "the service was told to stop");
        assert_eq!(service.checked.len(), REQUEST_KINDS, "not every request was checked: {:?}", service.checked);
    }

    #[test]
    fn paths_have_one_spelling() {
        assert_eq!(plain(Path::new(r"\\?\C:\Users\me\x.exe")), PathBuf::from(r"C:\Users\me\x.exe"));
        assert_eq!(plain(Path::new(r"\\?\UNC\server\share\x.exe")), PathBuf::from(r"\\server\share\x.exe"));
        assert_eq!(plain(Path::new(r"C:\Users\me\x.exe")), PathBuf::from(r"C:\Users\me\x.exe"));
    }
}
