//! What the service protects with: one engine, real-time protection set up
//! from the service's settings, scans on request, and the hub that sends
//! their events to every subscribed client (the app and the tray agent show
//! them; the service itself runs where no one can see a notification).

use super::settings::ProtectionSettings;
use crate::engine::{Engine, EngineConfig};
use crate::ipc::{Event, ProtectionStatus, ServerMessage};
use crate::rtp::{self, RtpConfig, RtpEvent, RtpHandle};
use crate::scan::{self, ScanEvent, ScanOptions};
use crate::{system, update, Category};
use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A subscribed client's end of the pipe, written by a thread of its own.
pub(crate) type Writer = Box<dyn Write + Send>;
/// Real-time protection's "still running" time, for catching up after a stop.
const CHECKPOINT: &str = "rtp-checkpoint";
const CHECKPOINT_EVERY: Duration = Duration::from_secs(60);
/// Scan progress is sent at most this often.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);
/// Events waiting for a subscriber; one that falls this far behind is
/// dropped rather than holding up protection.
const QUEUE: usize = 1024;

/// Sends events to every subscribed client. Each has a writer thread and a
/// bounded queue, so a client that stops reading (a full pipe) can never
/// block real-time protection or scans: it is dropped instead.
#[derive(Default)]
pub(crate) struct Hub {
    subscribers: Mutex<Vec<SyncSender<Arc<str>>>>,
}

impl Hub {
    pub fn subscribe(&self, mut writer: Writer) {
        let (tx, rx) = sync_channel::<Arc<str>>(QUEUE);
        let started = std::thread::Builder::new().name("event-writer".into()).spawn(move || {
            for line in rx {
                if writer.write_all(line.as_bytes()).and_then(|()| writer.flush()).is_err() {
                    break; // the client is gone
                }
            }
        });
        if started.is_ok() {
            self.subscribers.lock().unwrap_or_else(PoisonError::into_inner).push(tx);
        }
    }

    /// Queues `event` for everyone subscribed; a client that is gone or too
    /// far behind is dropped.
    pub fn send(&self, event: &Event) {
        let Ok(event) = serde_json::to_value(event) else { return };
        let Ok(mut line) = serde_json::to_string(&ServerMessage::Event { event }) else { return };
        line.push('\n');
        let line: Arc<str> = line.into();
        self.subscribers.lock().unwrap_or_else(PoisonError::into_inner).retain(|tx| tx.try_send(Arc::clone(&line)).is_ok());
    }
}

#[derive(Default)]
struct State {
    engine: Option<Arc<Engine>>,
    /// Whether `engine` was built with heuristics.
    heuristics: bool,
    rtp: Option<RtpHandle>,
    /// Set when real-time protection reports it has started watching.
    watching: Arc<AtomicBool>,
}

pub(crate) struct Protector {
    data_dir: PathBuf,
    hub: Arc<Hub>,
    state: Mutex<State>,
    jobs: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    next_job: AtomicU64,
}

impl Protector {
    pub fn new(data_dir: &Path, hub: Arc<Hub>) -> Arc<Self> {
        Arc::new(Self { data_dir: data_dir.to_path_buf(), hub, state: Mutex::default(), jobs: Mutex::default(), next_job: AtomicU64::new(1) })
    }

    pub fn status(&self) -> ProtectionStatus {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        ProtectionStatus {
            engine: state.engine.as_ref().map(|e| (e.rule_count(), e.hash_count())),
            watching: state.rtp.is_some() && state.watching.load(Ordering::Relaxed),
            scans: self.jobs.lock().unwrap_or_else(PoisonError::into_inner).len(),
        }
    }

    pub fn engine(&self) -> Option<Arc<Engine>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).engine.clone()
    }

    /// Loads signatures (again, if heuristics changed) and starts real-time
    /// protection as `settings` say, stopping what ran before. Takes seconds
    /// the first time: call it off the pipe's threads.
    pub fn apply(&self, settings: &ProtectionSettings) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(running) = state.rtp.take() {
            running.stop();
        }
        if state.engine.is_none() || state.heuristics != settings.heuristics {
            let config = EngineConfig { signature_dir: Some(update::signature_dir(&self.data_dir)), heuristics: settings.heuristics, ..Default::default() };
            match Engine::new(&config) {
                Ok(engine) => {
                    self.hub.send(&Event::EngineReady { rules: engine.rule_count(), hashes: engine.hash_count() });
                    state.engine = Some(Arc::new(engine));
                    state.heuristics = settings.heuristics;
                }
                Err(e) => {
                    self.hub.send(&Event::EngineFailed { error: format!("{e:#}") });
                    return;
                }
            }
        }
        if !settings.watch_enabled {
            self.hub.send(&Event::ProtectionOff);
            return;
        }
        let Some(engine) = state.engine.clone() else { return };
        let watching = Arc::new(AtomicBool::new(false));
        state.watching = Arc::clone(&watching);
        let hub = Arc::clone(&self.hub);
        let dir = self.data_dir.clone();
        let mut checkpoint_saved: Option<Instant> = None;
        let on_event = move |event: RtpEvent| {
            if matches!(event, RtpEvent::Started { .. }) {
                watching.store(true, Ordering::Relaxed);
            }
            if matches!(event, RtpEvent::Started { .. } | RtpEvent::Scanned { .. }) && checkpoint_saved.is_none_or(|t| t.elapsed() >= CHECKPOINT_EVERY) {
                save_checkpoint(&dir);
                checkpoint_saved = Some(Instant::now());
            }
            hub.send(&Event::from(event));
        };
        match rtp::start(engine, self.data_dir.clone(), rtp_config(&self.data_dir, settings), on_event) {
            Ok(running) => state.rtp = Some(running),
            Err(e) => self.hub.send(&Event::ProtectionError { message: format!("{e:#}") }),
        }
    }

    /// Loads the signatures again (an update installed new ones) and starts
    /// protection with them.
    pub fn reload_signatures(&self, settings: &ProtectionSettings) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).engine = None;
        self.apply(settings);
    }

    /// Stops real-time protection and every scan (the service is stopping).
    pub fn stop(&self) {
        for cancel in self.jobs.lock().unwrap_or_else(PoisonError::into_inner).values() {
            cancel.store(true, Ordering::Relaxed);
        }
        if let Some(running) = self.state.lock().unwrap_or_else(PoisonError::into_inner).rtp.take() {
            running.stop();
        }
    }

    /// Starts scanning `paths` on a thread of its own; returns the job number
    /// its events carry.
    pub fn scan(self: &Arc<Self>, paths: Vec<PathBuf>, kind: &str, settings: &ProtectionSettings) -> Result<u64> {
        let engine = self.engine().ok_or_else(|| anyhow!("the signatures are still loading; try again in a moment"))?;
        if paths.is_empty() {
            bail!("nothing to scan");
        }
        if let Some(missing) = paths.iter().find(|p| !p.exists()) {
            bail!("{} does not exist", missing.display());
        }
        let job = self.next_job.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(AtomicBool::new(false));
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner).insert(job, Arc::clone(&cancel));
        let mut options = ScanOptions::new(paths, kind);
        options.max_size_bytes = settings.max_size_mb.saturating_mul(1024 * 1024);
        options.quarantine_floor = settings.quarantine_floor();
        options.exclude = settings.exclusions.clone();
        options.threads = system::worker_threads(settings.performance);
        options.background = settings.performance.background();
        options.signatures = signatures_label(&self.data_dir);
        options.trust_signed = settings.trust_signed;
        options.archives = settings.scan_archives;
        let this = Arc::clone(self);
        std::thread::Builder::new().name(format!("scan-{job}")).spawn(move || {
            let outcome = scan::open_store(&this.data_dir).and_then(|store| {
                let mut last = Instant::now();
                scan::run(&engine, &store, &this.data_dir, &options, &cancel, &mut |event| match event {
                    ScanEvent::Progress { path, stats } if last.elapsed() >= PROGRESS_EVERY => {
                        last = Instant::now();
                        this.hub.send(&Event::ScanProgress {
                            job,
                            files: stats.files_scanned,
                            bytes: stats.bytes_scanned,
                            detections: stats.detections,
                            path: path.to_path_buf(),
                        });
                    }
                    ScanEvent::Progress { .. } => {}
                    ScanEvent::Detection(report) => this.hub.send(&Event::ScanDetection { job, report: report.clone() }),
                })
            });
            this.jobs.lock().unwrap_or_else(PoisonError::into_inner).remove(&job);
            match outcome {
                Ok(report) => this.hub.send(&Event::ScanFinished { job, report }),
                Err(e) => this.hub.send(&Event::ScanFailed { job, error: format!("{e:#}") }),
            }
        })?;
        Ok(job)
    }

    /// Asks a scan to stop; `false` if there is no such scan (it finished).
    pub fn cancel(&self, job: u64) -> bool {
        match self.jobs.lock().unwrap_or_else(PoisonError::into_inner).get(&job) {
            Some(cancel) => {
                cancel.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
}

/// Real-time protection's configuration from the service's settings.
fn rtp_config(data_dir: &Path, s: &ProtectionSettings) -> RtpConfig {
    let folders = if s.watch_folders.is_empty() { users_downloads() } else { s.watch_folders.clone() };
    let mut config = RtpConfig::new(folders);
    config.exclude = s.exclusions.clone();
    config.max_size_bytes = s.max_size_mb.saturating_mul(1024 * 1024);
    config.quarantine_floor = s.quarantine_floor();
    config.signatures = signatures_label(data_dir);
    config.catch_up_since = load_checkpoint(data_dir);
    config.process_protection = s.program_protection;
    config.stop_running_threats = s.stop_running_threats;
    config.command_rules = s.command_rules;
    config.run_box_all_users = true;
    config.trust_signed = s.trust_signed;
    config.scan_archives = s.scan_archives;
    config.scan_new_drives = s.scan_new_drives;
    config.defer_when_fullscreen = s.defer_when_fullscreen;
    config
}

/// When the signatures in use were last updated, for history.
fn signatures_label(data_dir: &Path) -> Option<String> {
    update::load_manifest(&update::signature_dir(data_dir)).last_success().map(str::to_string)
}

fn load_checkpoint(data_dir: &Path) -> Option<SystemTime> {
    let secs: u64 = std::fs::read_to_string(data_dir.join(CHECKPOINT)).ok()?.trim().parse().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

fn save_checkpoint(data_dir: &Path) {
    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let _ = std::fs::write(data_dir.join(CHECKPOINT), now.as_secs().to_string());
    }
}

/// Each local user profile's Downloads folder: what is watched when no
/// folders are set.
pub fn users_downloads() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let Ok(list) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") else {
            return Vec::new();
        };
        // S-1-5-21-…: people's accounts, not the system's own.
        list.enum_keys()
            .filter_map(Result::ok)
            .filter(|sid| sid.starts_with("S-1-5-21-"))
            .filter_map(|sid| list.open_subkey(&sid).ok()?.get_value::<String, _>("ProfileImagePath").ok())
            .map(|profile| PathBuf::from(profile).join("Downloads"))
            .filter(|downloads| downloads.is_dir())
            .collect()
    }
    #[cfg(not(windows))]
    Vec::new()
}

impl ProtectionSettings {
    /// The lowest category quarantined automatically, if any.
    pub fn quarantine_floor(&self) -> Option<Category> {
        if self.quarantine_suspicious {
            Some(Category::Suspicious)
        } else if self.auto_quarantine {
            Some(Category::Pup)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that never reads: every write blocks.
    struct Stuck;
    impl Write for Stuck {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_secs(3600));
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_client_that_stops_reading_never_holds_up_protection() {
        let hub = Hub::default();
        hub.subscribe(Box::new(Stuck));
        let began = Instant::now();
        for _ in 0..QUEUE + 10 {
            hub.send(&Event::ProtectionOff);
        }
        assert!(began.elapsed() < Duration::from_secs(2), "sending waited for the stuck client");
        assert!(hub.subscribers.lock().unwrap().is_empty(), "the stuck client was dropped");
    }
}
