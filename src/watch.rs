//! Watches folders and scans files as they arrive.
//!
//! Files are scanned once they have *settled*: no change events and an
//! unchanged size for `settle`, so a download is scanned when it finishes,
//! not while it is being written. Browser/partial download names are ignored
//! until they are renamed to their final name. Everything runs on one
//! background-priority thread.
//!
//! Higher-risk files (programs, scripts, disk images; see [`crate::risk`]) are
//! announced as soon as they land, before they settle, so the user is warned
//! before opening them; their scan result follows once they are scanned.

use crate::engine::Engine;
use crate::risk::{self, DownloadOrigin, RiskyFile};
use crate::scan::{self, FileReport, ScanEvent, ScanOptions, ScanReport};
use crate::{system, Category};
use anyhow::Result;
use notify::event::ModifyKind;
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

/// Partial-download and temporary names; their final name is scanned instead.
const IN_PROGRESS_EXTENSIONS: &[&str] = &[
    "crdownload", "part", "partial", "download", "opdownload", "tmp", "temp", "!ut", "crswap",
];
/// Files older than this at catch-up are left to manual scans.
const MAX_CATCH_UP_FILES: usize = 2000;
/// A file that never settles (e.g. a log being appended) is dropped after this.
const GIVE_UP_AFTER: Duration = Duration::from_secs(30 * 60);
/// Delay before announcing a risky file, so the browser has attached its
/// Mark of the Web (download origin) by the time it is read.
const ALERT_DELAY: Duration = Duration::from_millis(800);
/// Bound on remembered alerts; cleared when exceeded.
const MAX_ALERTED: usize = 5000;

#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub folders: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
    pub max_size_bytes: u64,
    pub quarantine_floor: Option<Category>,
    pub signatures: Option<String>,
    /// On start, also scan files modified after this time (catch-up for files
    /// that arrived while the watcher was not running).
    pub catch_up_since: Option<SystemTime>,
    pub settle: Duration,
    /// Announce programs and scripts as soon as they land.
    pub alert_risky: bool,
}

/// How the scan of an announced risky file ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskyOutcome {
    /// Scanned; no signature or heuristic matched.
    NoThreatFound,
    /// Detected; a [`WatchEvent::Detection`] carries the details.
    Threat(String),
    /// Not scanned (too large, unreadable or removed); the reason.
    NotScanned(String),
}

pub enum WatchEvent {
    /// Watching started; `failed` lists folders that could not be watched.
    Started { watching: usize, failed: Vec<(PathBuf, String)> },
    Detection(FileReport),
    /// A batch of settled files was scanned.
    Scanned(ScanReport),
    /// A program, script or similar file just landed; it is scanned once it settles.
    RiskyFile {
        path: PathBuf,
        risk: RiskyFile,
        origin: Option<DownloadOrigin>,
    },
    /// The scan of a file announced by `RiskyFile` finished.
    RiskyChecked { path: PathBuf, outcome: RiskyOutcome },
    Error(String),
}

pub struct WatchHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WatchHandle {
    /// Stops watching and waits for an in-progress scan to wind down.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn start(
    engine: Arc<Engine>,
    data_dir: PathBuf,
    config: WatchConfig,
    mut on_event: impl FnMut(WatchEvent) + Send + 'static,
) -> Result<WatchHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("folder-watcher".into())
        .spawn(move || {
            system::enter_background_mode();
            if let Err(e) = watch_loop(&engine, &data_dir, &config, &thread_stop, &mut on_event) {
                on_event(WatchEvent::Error(format!("watcher stopped: {e:#}")));
            }
        })?;
    Ok(WatchHandle {
        stop,
        thread: Some(thread),
    })
}

struct Pending {
    last_event: Instant,
    first_seen: Instant,
    size: Option<u64>,
}

fn watch_loop(
    engine: &Engine,
    data_dir: &Path,
    config: &WatchConfig,
    stop: &AtomicBool,
    on_event: &mut (impl FnMut(WatchEvent) + Send),
) -> Result<()> {
    let store = scan::open_store(data_dir)?;
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(tx)?;
    let mut failed = Vec::new();
    let mut watching = 0;
    for folder in &config.folders {
        match watcher.watch(folder, RecursiveMode::Recursive) {
            Ok(()) => watching += 1,
            Err(e) => failed.push((folder.clone(), e.to_string())),
        }
    }
    on_event(WatchEvent::Started { watching, failed });

    let mut pending: HashMap<PathBuf, Pending> = HashMap::new();
    // Risky files waiting to be announced, those announced and awaiting their
    // scan result, and every announced path (so each is announced once until
    // it is removed).
    let mut alerts: Vec<(PathBuf, Instant)> = Vec::new();
    let mut awaiting_result: HashSet<PathBuf> = HashSet::new();
    let mut alerted: HashSet<PathBuf> = HashSet::new();
    let excluded: Vec<PathBuf> = config.exclude.iter().filter_map(|p| std::fs::canonicalize(p).ok()).collect();
    if let Some(since) = config.catch_up_since {
        for path in changed_since(&config.folders, since) {
            let now = Instant::now();
            pending.insert(path, Pending { last_event: now - config.settle, first_seen: now, size: None });
        }
    }

    while !stop.load(Ordering::Relaxed) {
        let tick = if alerts.is_empty() { 500 } else { 200 };
        match rx.recv_timeout(Duration::from_millis(tick)) {
            Ok(Ok(event)) => {
                let relevant = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                let removed = matches!(event.kind, EventKind::Remove(_));
                // A new file, or a partial download renamed to its final name.
                let arrived = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(_)));
                for path in event.paths {
                    if removed {
                        pending.remove(&path);
                        alerted.remove(&path);
                    } else if relevant && !in_progress_name(&path) {
                        if arrived && config.alert_risky && !alerted.contains(&path) && risk::classify(&path).is_some() {
                            if alerted.len() >= MAX_ALERTED {
                                alerted.clear();
                            }
                            alerted.insert(path.clone());
                            alerts.push((path.clone(), Instant::now()));
                        }
                        let now = Instant::now();
                        pending
                            .entry(path)
                            .and_modify(|p| p.last_event = now)
                            .or_insert(Pending { last_event: now, first_seen: now, size: None });
                    }
                }
            }
            Ok(Err(e)) => on_event(WatchEvent::Error(format!("watch error: {e}"))),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        alerts.retain(|(path, at)| {
            if at.elapsed() < ALERT_DELAY {
                return true;
            }
            let is_file = std::fs::metadata(path).is_ok_and(|m| m.is_file());
            let is_excluded =
                std::fs::canonicalize(path).is_ok_and(|real| excluded.iter().any(|x| real.starts_with(x)));
            if let (true, false, Some(risk)) = (is_file, is_excluded, risk::classify(path)) {
                awaiting_result.insert(path.clone());
                on_event(WatchEvent::RiskyFile { path: path.clone(), risk, origin: risk::download_origin(path) });
            }
            false
        });

        let ready = take_settled(&mut pending, config.settle);
        if ready.is_empty() {
            continue;
        }
        let risky_ready: Vec<PathBuf> = ready.iter().filter(|p| awaiting_result.remove(*p)).cloned().collect();
        let mut options = ScanOptions::new(ready, "watch");
        options.exclude = config.exclude.clone();
        options.max_size_bytes = config.max_size_bytes;
        options.quarantine_floor = config.quarantine_floor;
        options.signatures = config.signatures.clone();
        options.threads = 1;
        options.background = true;
        let mut forward = |event: ScanEvent<'_>| {
            if let ScanEvent::Detection(report) = event {
                on_event(WatchEvent::Detection(report.clone()));
            }
        };
        match scan::run(engine, &store, data_dir, &options, stop, &mut forward) {
            Ok(report) => {
                for path in risky_ready {
                    let outcome = risky_outcome(&path, &report, config.max_size_bytes);
                    on_event(WatchEvent::RiskyChecked { path, outcome });
                }
                on_event(WatchEvent::Scanned(report));
            }
            Err(e) => on_event(WatchEvent::Error(format!("{e:#}"))),
        }
    }
    drop(watcher);
    Ok(())
}

/// How the scan of one announced file ended, from the batch report.
fn risky_outcome(path: &Path, report: &ScanReport, max_size_bytes: u64) -> RiskyOutcome {
    let shown = path.display().to_string();
    if let Some(found) = report.infected.iter().find(|r| r.path == shown) {
        return RiskyOutcome::Threat(found.worst().threat.clone());
    }
    if let Some(error) = report.errors.iter().find(|e| e.starts_with(&shown)) {
        return RiskyOutcome::NotScanned(error[shown.len()..].trim_start_matches(':').trim().to_string());
    }
    match std::fs::metadata(path) {
        Err(_) => RiskyOutcome::NotScanned("the file was removed before it could be scanned".into()),
        Ok(meta) if meta.len() > max_size_bytes => {
            RiskyOutcome::NotScanned("it is larger than the size limit in Settings".into())
        }
        Ok(_) if report.cancelled => RiskyOutcome::NotScanned("folder protection stopped first".into()),
        Ok(_) => RiskyOutcome::NoThreatFound,
    }
}

/// Removes and returns files that have been quiet for `settle` with a stable size.
fn take_settled(pending: &mut HashMap<PathBuf, Pending>, settle: Duration) -> Vec<PathBuf> {
    let mut ready = Vec::new();
    pending.retain(|path, p| {
        if p.first_seen.elapsed() > GIVE_UP_AFTER {
            return false;
        }
        if p.last_event.elapsed() < settle {
            return true;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            return false; // gone (deleted or renamed away)
        };
        if !meta.is_file() {
            return false;
        }
        if p.size != Some(meta.len()) {
            // Size changed since the last look: wait another settle period.
            p.size = Some(meta.len());
            p.last_event = Instant::now();
            return true;
        }
        if std::fs::File::open(path).is_err() {
            p.last_event = Instant::now(); // still locked by the writer
            return true;
        }
        ready.push(path.clone());
        false
    });
    ready.sort();
    ready
}

fn in_progress_name(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with("~$") || name.starts_with(".~") {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| IN_PROGRESS_EXTENSIONS.iter().any(|x| ext.eq_ignore_ascii_case(x)))
}

fn changed_since(folders: &[PathBuf], since: SystemTime) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for folder in folders {
        for entry in walkdir::WalkDir::new(folder).into_iter().filter_map(|e| e.ok()) {
            if found.len() >= MAX_CATCH_UP_FILES {
                return found;
            }
            let path = entry.path();
            if !entry.file_type().is_file() || in_progress_name(path) {
                continue;
            }
            if entry.metadata().ok().and_then(|m| m.modified().ok()).is_some_and(|m| m > since) {
                found.push(path.to_path_buf());
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;
    use std::fs;

    fn marker() -> String {
        "threat-scanner-test-marker-7f3a".to_ascii_uppercase()
    }

    fn config(folder: &Path) -> WatchConfig {
        WatchConfig {
            folders: vec![folder.to_path_buf()],
            exclude: Vec::new(),
            max_size_bytes: 1 << 20,
            quarantine_floor: None,
            signatures: None,
            catch_up_since: None,
            settle: Duration::from_millis(400),
            alert_risky: true,
        }
    }

    fn name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn partial_download_names_are_ignored() {
        assert!(in_progress_name(Path::new("C:/d/setup.exe.crdownload")));
        assert!(in_progress_name(Path::new("C:/d/movie.part")));
        assert!(in_progress_name(Path::new("C:/d/~$report.docx")));
        assert!(!in_progress_name(Path::new("C:/d/setup.exe")));
    }

    #[test]
    fn new_threat_in_watched_folder_is_detected_once_settled() {
        let tmp = tempfile::tempdir().unwrap();
        let watched = tmp.path().join("Downloads");
        fs::create_dir_all(&watched).unwrap();
        let data_dir = tmp.path().join("data");
        let engine = Arc::new(Engine::new(&EngineConfig::default()).unwrap());

        let (tx, rx) = mpsc::channel();
        let handle = start(engine, data_dir.clone(), config(&watched), move |e| {
            let _ = tx.send(match e {
                WatchEvent::Started { watching, .. } => format!("started {watching}"),
                WatchEvent::Detection(r) => format!("detected {}", r.worst().threat),
                WatchEvent::Scanned(r) => format!("scanned {}", r.stats.files_scanned),
                WatchEvent::RiskyFile { path, risk, .. } => {
                    format!("risky {} {}", name(&path), risk.disguise.is_some())
                }
                WatchEvent::RiskyChecked { path, outcome } => format!("checked {} {outcome:?}", name(&path)),
                WatchEvent::Error(e) => format!("error {e}"),
            });
        })
        .unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), "started 1");

        // Simulate a browser download: partial name first, then the rename.
        let partial = watched.join("invoice.pdf.exe.crdownload");
        fs::write(&partial, format!("MZ... {}", marker())).unwrap();
        fs::write(watched.join("notes.txt"), "harmless").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        fs::rename(&partial, watched.join("invoice.pdf.exe")).unwrap();

        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        // Until the announced file's result arrives (the text file may be scanned in an earlier batch).
        while Instant::now() < deadline && !seen.iter().any(|s: &String| s.starts_with("checked")) {
            if let Ok(msg) = rx.recv_timeout(Duration::from_millis(500)) {
                seen.push(msg);
            }
        }
        handle.stop();
        assert!(seen.contains(&"detected Test.ThreatScanner.Marker".to_string()), "{seen:?}");
        // The disguised program was announced once, under its final name only
        // (not the partial name, not the text file), and its result followed.
        let risky: Vec<&String> = seen.iter().filter(|s| s.starts_with("risky")).collect();
        assert_eq!(risky, ["risky invoice.pdf.exe true"], "{seen:?}");
        assert!(seen.iter().any(|s| s.starts_with("checked invoice.pdf.exe Threat")), "{seen:?}");
        let scanned: i64 = seen
            .iter()
            .filter_map(|s| s.strip_prefix("scanned ")?.parse::<i64>().ok())
            .sum();
        assert!(scanned >= 1, "{seen:?}");

        let store = scan::open_store(&data_dir).unwrap();
        let row = &store.recent_scans(5, Some("watch")).unwrap()[0];
        assert_eq!(row.threads, 1);
        // The partial name itself was never scanned.
        let detections = store.scan_detections(row.id).unwrap();
        assert!(detections.iter().all(|d| !d.path.ends_with(".crdownload")));
    }

    #[test]
    fn catch_up_scans_files_changed_while_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let watched = tmp.path().join("w");
        fs::create_dir_all(&watched).unwrap();
        let since = SystemTime::now() - Duration::from_secs(60);
        fs::write(watched.join("arrived-while-off.txt"), marker()).unwrap();

        let engine = Arc::new(Engine::new(&EngineConfig::default()).unwrap());
        let mut cfg = config(&watched);
        cfg.catch_up_since = Some(since);
        let (tx, rx) = mpsc::channel();
        let handle = start(engine, tmp.path().join("data"), cfg, move |e| {
            if let WatchEvent::Detection(r) = e {
                let _ = tx.send(r.path);
            }
        })
        .unwrap();
        let path = rx.recv_timeout(Duration::from_secs(20)).expect("catch-up detection");
        handle.stop();
        assert!(path.ends_with("arrived-while-off.txt"));
    }
}
