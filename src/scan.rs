//! The scan workflow shared by the CLI, the GUI and the folder watcher: walk
//! targets, run the engine on worker threads, record history and optionally
//! quarantine.
//!
//! Threads: one walker feeds a small bounded queue, `threads` workers scan
//! (each with its own YARA scanner), and the calling thread is the only one
//! that touches the database or quarantine. With `background` set, walker and
//! workers run at Windows background priority so the PC stays responsive.

use crate::engine::Engine;
use crate::engine::Verdict;
use crate::quarantine::Quarantine;
use crate::store::{ScanMeta, ScanStats, Store, MAX_STORED_ERRORS};
use crate::{system, Category, Finding};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Errors kept in memory for the report (all are counted).
const MAX_REPORTED_ERRORS: usize = 1000;

/// Default location of the history database and quarantine.
pub fn default_data_dir() -> PathBuf {
    match std::env::var_os("LOCALAPPDATA") {
        Some(base) => PathBuf::from(base).join("threat-scanner"),
        None => PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into()))
            .join(".threat-scanner"),
    }
}

pub fn open_store(data_dir: &Path) -> Result<Store> {
    fs::create_dir_all(data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
    Store::open(&data_dir.join("history.sqlite"))
}

pub fn quarantine_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("quarantine")
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub paths: Vec<PathBuf>,
    pub max_size_bytes: u64,
    /// Quarantine detections at or above this category; `None` only reports.
    pub quarantine_floor: Option<Category>,
    /// Files or folders never scanned: user exclusions, and the user's own
    /// signature files, which contain the very patterns they detect.
    pub exclude: Vec<PathBuf>,
    /// Recorded in history: `quick`, `custom`, `watch`, `cli`...
    pub kind: String,
    /// Scanning threads (at least 1).
    pub threads: usize,
    /// Run walker and workers at background priority.
    pub background: bool,
    /// When the signatures in use were last updated, recorded in history.
    pub signatures: Option<String>,
}

impl ScanOptions {
    pub fn new(paths: Vec<PathBuf>, kind: &str) -> Self {
        Self {
            paths,
            max_size_bytes: 100 * 1024 * 1024,
            quarantine_floor: None,
            exclude: Vec::new(),
            kind: kind.to_string(),
            threads: 1,
            background: true,
            signatures: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub sha256: String,
    pub findings: Vec<Finding>,
    pub action: String,
}

impl FileReport {
    pub fn worst(&self) -> &Finding {
        &self.findings[0]
    }
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scan_id: i64,
    pub elapsed_ms: u128,
    pub cancelled: bool,
    pub threads: usize,
    #[serde(flatten)]
    pub stats: ScanStats,
    pub infected: Vec<FileReport>,
    pub errors: Vec<String>,
}

pub enum ScanEvent<'a> {
    /// Just finished this file; `stats` includes it.
    Progress { path: &'a Path, stats: &'a ScanStats },
    Detection(&'a FileReport),
}

enum WorkerMsg {
    Skipped,
    Error(String, String),
    Scanned {
        path: PathBuf,
        bytes: u64,
        verdict: Verdict,
        /// Kept only for detections, for quarantine without a second read.
        data: Option<Vec<u8>>,
    },
}

pub fn run(
    engine: &Engine,
    store: &Store,
    data_dir: &Path,
    options: &ScanOptions,
    cancel: &AtomicBool,
    on_event: &mut dyn FnMut(ScanEvent<'_>),
) -> Result<ScanReport> {
    // A missing target must not look like a clean scan.
    for path in &options.paths {
        if !path.exists() {
            bail!(
                "scan target `{}` does not exist (in cmd.exe use %USERPROFILE%, in PowerShell $env:USERPROFILE)",
                path.display()
            );
        }
    }
    let started = Instant::now();
    let threads = options.threads.max(1);
    let quarantine = match options.quarantine_floor {
        Some(_) => Some(Quarantine::new(quarantine_dir(data_dir), store)?),
        None => None,
    };
    // Never scan our own data folder (quarantine, downloaded signatures) or
    // the caller's exclusions.
    let excluded: Vec<PathBuf> = std::iter::once(data_dir)
        .chain(options.exclude.iter().map(PathBuf::as_path))
        .filter_map(|p| fs::canonicalize(p).ok())
        .collect();

    let targets = options
        .paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join("; ");
    let scan_id = store.begin_scan(&ScanMeta {
        kind: &options.kind,
        targets: &targets,
        threads: threads as i64,
        signatures: options.signatures.as_deref(),
    })?;
    let mut stats = ScanStats::default();
    let mut infected = Vec::new();
    let mut errors = Vec::new();
    // Set if this function fails, so the walker and workers stop early.
    let abort = AtomicBool::new(false);
    let stopping = || cancel.load(Ordering::Relaxed) || abort.load(Ordering::Relaxed);

    let outcome = std::thread::scope(|scope| -> Result<()> {
        let (path_tx, path_rx) = mpsc::sync_channel::<PathBuf>(threads * 8);
        let path_rx = Arc::new(Mutex::new(path_rx));
        let (msg_tx, msg_rx) = mpsc::channel::<WorkerMsg>();

        let walker_tx = msg_tx.clone();
        let (excluded, stopping) = (&excluded, &stopping);
        scope.spawn(move || {
            if options.background {
                system::enter_background_mode();
            }
            'roots: for root in &options.paths {
                for entry in walkdir::WalkDir::new(root).follow_links(false) {
                    if stopping() {
                        break 'roots;
                    }
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            let path = e.path().map(|p| p.display().to_string()).unwrap_or_default();
                            let _ = walker_tx.send(WorkerMsg::Error(path, e.to_string()));
                            continue;
                        }
                    };
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    if let Ok(real) = fs::canonicalize(entry.path()) {
                        if excluded.iter().any(|x| real.starts_with(x)) {
                            continue;
                        }
                    }
                    if entry.metadata().map(|m| m.len()).unwrap_or(0) > options.max_size_bytes {
                        let _ = walker_tx.send(WorkerMsg::Skipped);
                        continue;
                    }
                    if path_tx.send(entry.into_path()).is_err() {
                        break 'roots;
                    }
                }
            }
            // Dropping `path_tx` here lets the workers finish.
        });

        for _ in 0..threads {
            let path_rx = Arc::clone(&path_rx);
            let msg_tx = msg_tx.clone();
            scope.spawn(move || {
                if options.background {
                    system::enter_background_mode();
                }
                let mut scanner = engine.scanner();
                loop {
                    let next = path_rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                    let Ok(path) = next else { break };
                    if stopping() {
                        continue; // drain the queue quickly
                    }
                    let msg = match fs::read(&path) {
                        Err(e) => WorkerMsg::Error(path.display().to_string(), e.to_string()),
                        Ok(data) => {
                            let verdict = scanner.scan(&data);
                            WorkerMsg::Scanned {
                                bytes: data.len() as u64,
                                data: (!verdict.findings.is_empty()).then_some(data),
                                path,
                                verdict,
                            }
                        }
                    };
                    if msg_tx.send(msg).is_err() {
                        break;
                    }
                }
            });
        }
        drop(msg_tx);

        let mut record_error = |stats: &mut ScanStats, path: &str, message: &str| -> Result<()> {
            if stats.errors < MAX_STORED_ERRORS {
                store.add_scan_error(scan_id, path, message)?;
            }
            stats.errors += 1;
            if errors.len() < MAX_REPORTED_ERRORS {
                errors.push(format!("{path}: {message}"));
            }
            Ok(())
        };
        let mut handle = |msg: WorkerMsg| -> Result<()> {
            match msg {
                WorkerMsg::Skipped => stats.files_skipped += 1,
                WorkerMsg::Error(path, message) => record_error(&mut stats, &path, &message)?,
                WorkerMsg::Scanned { path, bytes, verdict, data } => {
                    stats.files_scanned += 1;
                    stats.bytes_scanned += bytes as i64;
                    let path_text = path.display().to_string();
                    for warning in &verdict.warnings {
                        record_error(&mut stats, &path_text, warning)?;
                    }
                    on_event(ScanEvent::Progress { path: &path, stats: &stats });
                    let Some(worst) = verdict.findings.first() else {
                        return Ok(());
                    };
                    stats.detections += 1;
                    let action = match (&quarantine, options.quarantine_floor, &data) {
                        (Some(q), Some(floor), Some(data)) if worst.category >= floor => {
                            match q.isolate(&path, data, &verdict.sha256, &worst.threat) {
                                Ok(id) => {
                                    stats.quarantined += 1;
                                    format!("quarantined ({id})")
                                }
                                Err(e) => {
                                    let message = format!("quarantine failed: {e:#}");
                                    record_error(&mut stats, &path_text, &message)?;
                                    message
                                }
                            }
                        }
                        _ => "reported".to_string(),
                    };
                    let report = FileReport {
                        path: path_text,
                        sha256: verdict.sha256,
                        findings: verdict.findings,
                        action,
                    };
                    for finding in &report.findings {
                        store.add_detection(scan_id, &report.path, &report.sha256, finding, &report.action)?;
                    }
                    on_event(ScanEvent::Detection(&report));
                    infected.push(report);
                }
            }
            Ok(())
        };
        for msg in msg_rx {
            if let Err(e) = handle(msg) {
                abort.store(true, Ordering::Relaxed);
                return Err(e);
            }
        }
        Ok(())
    });
    let cancelled = cancel.load(Ordering::Relaxed);
    let elapsed_ms = started.elapsed().as_millis();
    store.finish_scan(scan_id, &stats, elapsed_ms as i64, cancelled || outcome.is_err())?;
    outcome?;

    Ok(ScanReport {
        scan_id,
        elapsed_ms,
        cancelled,
        threads,
        stats,
        infected,
        errors,
    })
}

/// Quarantines a file reported by an earlier scan, after checking it is still
/// the same file (its SHA-256 has not changed since detection).
pub fn quarantine_reported(store: &Store, data_dir: &Path, report: &FileReport) -> Result<String> {
    quarantine_file(store, data_dir, Path::new(&report.path), &report.sha256, &report.worst().threat)
}

/// Quarantines `path` under `threat` if its SHA-256 is still `sha256`, so a
/// file replaced since it was examined is never isolated by mistake.
pub fn quarantine_file(store: &Store, data_dir: &Path, path: &Path, sha256: &str, threat: &str) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if hex::encode(Sha256::digest(&data)) != sha256 {
        bail!("{} changed since it was examined; check it again", path.display());
    }
    let q = Quarantine::new(quarantine_dir(data_dir), store)?;
    q.isolate(path, &data, sha256, threat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineConfig;

    fn marker() -> String {
        "threat-scanner-test-marker-7f3a".to_ascii_uppercase()
    }

    fn engine() -> Engine {
        Engine::new(&EngineConfig::default()).unwrap()
    }

    #[test]
    fn scan_reports_then_quarantines_on_request() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(target.join("sub")).unwrap();
        fs::write(target.join("clean.txt"), "nothing here").unwrap();
        let bad = target.join("sub").join("bad.txt");
        fs::write(&bad, format!("x {} y", marker())).unwrap();

        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        let options = ScanOptions::new(vec![target.clone()], "custom");
        let mut progress = 0;
        let report = run(&engine(), &store, &data_dir, &options, &AtomicBool::new(false), &mut |e| {
            if let ScanEvent::Progress { .. } = e {
                progress += 1;
            }
        })
        .unwrap();

        assert_eq!(progress, 2);
        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(report.infected.len(), 1);
        assert_eq!(report.infected[0].action, "reported");
        assert!(bad.exists(), "report-only scans must not remove files");

        // The GUI's "Quarantine selected" path.
        quarantine_reported(&store, &data_dir, &report.infected[0]).unwrap();
        assert!(!bad.exists());
        assert_eq!(store.quarantine_items(false).unwrap().len(), 1);
    }

    #[test]
    fn parallel_scan_finds_everything_and_records_history() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("many");
        for dir in 0..10 {
            let d = target.join(format!("d{dir}"));
            fs::create_dir_all(&d).unwrap();
            for file in 0..30 {
                let body = if file == 7 { format!("x {}", marker()) } else { format!("clean {dir} {file}") };
                fs::write(d.join(format!("f{file}.txt")), body).unwrap();
            }
        }
        let skip = target.join("d3");
        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        let mut options = ScanOptions::new(vec![target.clone()], "custom");
        options.threads = 4;
        options.exclude = vec![skip];
        options.quarantine_floor = Some(Category::Pup);
        options.signatures = Some("2026-10-14T21:11:00+05:30".into());

        let report = run(&engine(), &store, &data_dir, &options, &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(report.stats.files_scanned, 9 * 30, "the excluded folder is skipped");
        assert_eq!(report.infected.len(), 9);
        assert_eq!(report.stats.quarantined, 9);
        assert!(report.infected.iter().all(|r| r.action.starts_with("quarantined")));

        let row = &store.recent_scans(1, None).unwrap()[0];
        assert_eq!((row.kind.as_str(), row.threads, row.quarantined), ("custom", 4, 9));
        assert_eq!(row.signatures.as_deref(), Some("2026-10-14T21:11:00+05:30"));
        assert!(row.elapsed_ms.is_some());
        assert_eq!(store.scan_detections(row.id).unwrap().len(), 9);
    }

    #[test]
    fn quarantine_refuses_a_file_changed_since_the_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        let bad = tmp.path().join("bad.txt");
        fs::write(&bad, marker()).unwrap();
        let options = ScanOptions::new(vec![bad.clone()], "custom");
        let report = run(&engine(), &store, &data_dir, &options, &AtomicBool::new(false), &mut |_| {}).unwrap();

        fs::write(&bad, "replaced with a different file").unwrap();
        assert!(quarantine_reported(&store, &data_dir, &report.infected[0]).is_err());
        assert!(bad.exists());
    }

    #[test]
    fn cancelled_and_missing_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        fs::write(tmp.path().join("a.txt"), "a").unwrap();

        let mut options = ScanOptions::new(vec![tmp.path().to_path_buf()], "custom");
        options.threads = 3;
        let report = run(&engine(), &store, &data_dir, &options, &AtomicBool::new(true), &mut |_| {}).unwrap();
        assert!(report.cancelled);
        assert_eq!(report.stats.files_scanned, 0);
        assert!(store.recent_scans(1, None).unwrap()[0].cancelled);

        options.paths = vec![tmp.path().join("missing")];
        assert!(run(&engine(), &store, &data_dir, &options, &AtomicBool::new(false), &mut |_| {}).is_err());
    }
}
