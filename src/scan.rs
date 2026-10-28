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
use crate::trust::{self, Trust};
use crate::{contents, system, Category, Finding, Source};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
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
    /// Drop rule and heuristic findings on files with a valid Authenticode
    /// signature (see [`crate::trust`]). Hash matches stand.
    pub trust_signed: bool,
    /// Keep the history entry of a scan that found nothing. Real-time
    /// protection turns this off for programs, which are checked constantly.
    pub keep_clean_history: bool,
    /// Look inside ZIP and 7z archives (see [`crate::contents`]).
    pub archives: bool,
    /// Skip developers' dependency, build and cache folders (`node_modules`,
    /// `.git`, `.next`, Python environments, Cargo's `target`…) and source
    /// maps: on for quick scans, where a project folder on the desktop can
    /// hold hundreds of thousands of library files that are not run as they
    /// are. Full and custom scans still look everywhere.
    pub skip_build_folders: bool,
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
            trust_signed: true,
            keep_clean_history: true,
            archives: true,
            skip_build_folders: kind == "quick",
        }
    }
}

/// Folders a quick scan skips: package managers' dependencies, version
/// control, build output and caches. Python environments (`pyvenv.cfg`) and
/// cache folders that mark themselves (`CACHEDIR.TAG`, as Cargo's `target`
/// does) are recognised whatever their name.
pub fn is_build_folder(dir: &Path) -> bool {
    const NAMES: &[&str] = &[
        "node_modules", "bower_components", "jspm_packages", ".pnpm-store", ".yarn", ".git", ".svn", ".hg", "__pycache__",
        ".venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", ".terraform", ".turbo", ".parcel-cache",
        ".svelte-kit", ".nuxt", ".angular", ".expo",
    ];
    let Some(name) = dir.file_name().map(|n| n.to_string_lossy().to_lowercase()) else { return false };
    NAMES.contains(&name.as_str()) || name.starts_with(".next") || dir.join("pyvenv.cfg").is_file() || dir.join("CACHEDIR.TAG").is_file()
}

/// Files a quick scan skips: source maps (JSON describing other code).
fn is_build_file(path: &Path) -> bool {
    path.extension().is_some_and(|x| x.eq_ignore_ascii_case("map"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: i64,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    pub threads: usize,
    #[serde(flatten)]
    pub stats: ScanStats,
    pub infected: Vec<FileReport>,
    /// Named apart from `stats.errors` (the count), which shares the object.
    #[serde(rename = "error_messages")]
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
        /// `None` for a padded program, which was not read whole.
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
                // Exclusions are canonical paths. Each entry's is the root's
                // plus the rest of its path, so no file is opened just to
                // compare it; excluded folders are not entered at all.
                let real_root = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
                let real = |path: &Path| path.strip_prefix(root).map_or_else(|_| path.to_path_buf(), |rest| real_root.join(rest));
                let is_excluded = |path: &Path| !excluded.is_empty() && excluded.iter().any(|x| real(path).starts_with(x));
                let walk = walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
                    !(e.depth() > 0
                        && e.file_type().is_dir()
                        && ((options.skip_build_folders && is_build_folder(e.path())) || is_excluded(e.path())))
                });
                for entry in walk {
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
                    if (options.skip_build_folders && is_build_file(entry.path())) || is_excluded(entry.path()) {
                        continue;
                    }
                    // A large program may be a small one padded past the
                    // limit; the worker checks.
                    if entry.metadata().map(|m| m.len()).unwrap_or(0) > options.max_size_bytes
                        && !contents::starts_like_program(entry.path())
                    {
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
                let look = contents::Options { max_size: options.max_size_bytes, archives: options.archives };
                loop {
                    let next = path_rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                    let Ok(path) = next else { break };
                    if stopping() {
                        continue; // drain the queue quickly
                    }
                    let msg = match contents::examine_file(&mut scanner, &path, &look) {
                        Err(e) => WorkerMsg::Error(path.display().to_string(), e.to_string()),
                        Ok(None) => WorkerMsg::Skipped,
                        Ok(Some(examined)) => {
                            let mut verdict = examined.verdict;
                            weigh_signature(&mut verdict, &path, options.trust_signed);
                            WorkerMsg::Scanned {
                                bytes: examined.bytes,
                                data: if verdict.findings.is_empty() { None } else { examined.data },
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
                    let action = match (&quarantine, options.quarantine_floor) {
                        (Some(q), Some(floor)) if worst.category >= floor => {
                            let isolated = match &data {
                                Some(data) => q.isolate(&path, data, &verdict.sha256, &worst.threat),
                                // Not read whole (a padded program): copied from disk.
                                None => q.isolate_file(&path, &verdict.sha256, &worst.threat),
                            };
                            match isolated {
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
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    store.finish_scan(scan_id, &stats, elapsed_ms as i64, cancelled || outcome.is_err())?;
    outcome?;
    if !options.keep_clean_history && stats.detections == 0 {
        store.delete_scan(scan_id)?;
    }

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

/// Threat name for a signed file changed after signing.
pub const TAMPERED_THREAT: &str = "Tampered.SignedFile";

/// Weighs the signature of a file that rules or heuristics flagged; files
/// without such findings are not checked.
///
/// With `trust_signed`, on a valid Authenticode signature only hash matches
/// stand: rules and heuristics match code that signed software shares with
/// malware (open-source libraries, installers, embedded scripts), and the
/// signature is the stronger evidence. Data appended to a signed program
/// voids its signature (catalog or embedded), so a payload cannot hide
/// behind one that way.
///
/// A publisher's signature that no longer matches the file means it was
/// changed after signing (cracked, patched or infected). Together with a
/// flag of its own, that is reported as malware.
fn weigh_signature(verdict: &mut Verdict, path: &Path, trust_signed: bool) {
    if !verdict.findings.iter().any(|f| f.source != Source::Hash) {
        return;
    }
    match trust::verify(path) {
        Trust::Signed { .. } if trust_signed => verdict.findings.retain(|f| f.source == Source::Hash),
        Trust::Tampered => {
            verdict.findings.insert(
                0,
                Finding {
                    threat: TAMPERED_THREAT.to_string(),
                    category: Category::Malware,
                    source: Source::Heuristic,
                    details: "changed after it was signed: the publisher's signature no longer matches".to_string(),
                },
            );
        }
        _ => {}
    }
}

/// Quarantines a file reported by an earlier scan, after checking it is still
/// the same file (its SHA-256 has not changed since detection).
pub fn quarantine_reported(store: &Store, data_dir: &Path, report: &FileReport) -> Result<String> {
    quarantine_file(store, data_dir, Path::new(&report.path), &report.sha256, &report.worst().threat)
}

/// Quarantines `path` under `threat` if its SHA-256 is still `sha256`, so a
/// file replaced since it was examined is never isolated by mistake.
pub fn quarantine_file(store: &Store, data_dir: &Path, path: &Path, sha256: &str, threat: &str) -> Result<String> {
    let q = Quarantine::new(quarantine_dir(data_dir), store)?;
    q.isolate_file(path, sha256, threat)
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
    fn quick_scans_skip_code_libraries_and_custom_scans_do_not() {
        let tmp = tempfile::tempdir().unwrap();
        let desktop = tmp.path().join("Desktop");
        let project = desktop.join("app");
        let bad = format!("x {} y", marker());
        for dir in ["node_modules/lib/dist", ".git/objects", ".next-build/static", "venv/Lib", "target/debug", "src"] {
            fs::create_dir_all(project.join(dir)).unwrap();
        }
        fs::write(project.join("venv/pyvenv.cfg"), "home = C:\\Python312").unwrap();
        fs::write(project.join("target/CACHEDIR.TAG"), "Signature: 8a477f597d28d172789f06886806bc55").unwrap();
        for file in ["node_modules/lib/dist/x.js", ".git/objects/ab", ".next-build/static/c.js", "venv/Lib/m.py", "target/debug/app.exe", "src/app.js.map"] {
            fs::write(project.join(file), &bad).unwrap();
        }
        fs::write(project.join("src/payload.js"), &bad).unwrap();
        // A folder that only sounds like one is still scanned.
        fs::create_dir_all(desktop.join("target practice")).unwrap();
        fs::write(desktop.join("target practice/notes.txt"), &bad).unwrap();

        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        let found = |kind: &str| {
            let options = ScanOptions::new(vec![desktop.clone()], kind);
            let report = run(&engine(), &store, &data_dir, &options, &AtomicBool::new(false), &mut |_| {}).unwrap();
            let mut names: Vec<String> = report.infected.iter().map(|r| Path::new(&r.path).file_name().unwrap().to_string_lossy().into_owned()).collect();
            names.sort();
            names
        };
        assert_eq!(found("quick"), ["notes.txt", "payload.js"]);
        assert_eq!(found("custom").len(), 8, "a custom scan looks everywhere");
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

    #[cfg(windows)]
    #[test]
    fn padded_programs_and_archives_are_scanned_and_quarantined() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("downloads");
        fs::create_dir_all(&target).unwrap();
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let program = fs::read(Path::new(&root).join(r"System32\PING.EXE")).unwrap();
        let mut padded = program.clone();
        padded.resize(program.len() + 12 * 1024 * 1024, 0);
        let setup = target.join("setup.exe");
        fs::write(&setup, &padded).unwrap();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file("docs/invoice.txt", zip::write::SimpleFileOptions::default()).unwrap();
        std::io::Write::write_all(&mut zip, format!("x {} y", marker()).as_bytes()).unwrap();
        fs::write(target.join("invoice.zip"), zip.finish().unwrap().into_inner()).unwrap();

        let hashes = tmp.path().join("hashes.txt");
        fs::write(&hashes, format!("{} malware Test.Padded\n", hex::encode(Sha256::digest(&program)))).unwrap();
        let engine = Engine::new(&EngineConfig { hash_files: vec![hashes.clone()], ..Default::default() }).unwrap();
        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        let mut options = ScanOptions::new(vec![target.clone()], "custom");
        options.max_size_bytes = 1 << 20;
        options.quarantine_floor = Some(Category::Pup);
        let report = run(&engine, &store, &data_dir, &options, &AtomicBool::new(false), &mut |_| {}).unwrap();

        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(report.stats.files_skipped, 0, "the padded program is scanned, not skipped");
        let threats: Vec<(&str, &str)> = report.infected.iter().map(|r| (r.path.rsplit('\\').next().unwrap(), r.worst().threat.as_str())).collect();
        assert!(threats.contains(&("setup.exe", "Test.Padded")), "{threats:?}");
        assert!(threats.contains(&("invoice.zip", "Test.ThreatScanner.Marker")), "{threats:?}");
        assert_eq!(report.stats.quarantined, 2);
        assert!(!setup.exists());

        // The padded file was quarantined whole, and comes back unchanged.
        let item = store.quarantine_items(false).unwrap().into_iter().find(|q| q.original_path.ends_with("setup.exe")).unwrap();
        assert_eq!(item.size as usize, padded.len());
        Quarantine::new(quarantine_dir(&data_dir), &store).unwrap().restore(&item.id, false).unwrap();
        assert_eq!(fs::read(&setup).unwrap(), padded);
    }

    #[cfg(windows)]
    #[test]
    fn signed_files_keep_only_hash_matches() {
        let finding = |source| Finding { threat: "T".into(), category: Category::Malware, source, details: String::new() };
        let verdict = || Verdict {
            sha256: String::new(),
            findings: vec![finding(Source::Hash), finding(Source::Yara), finding(Source::Heuristic)],
            warnings: Vec::new(),
        };
        let sources = |v: &Verdict| v.findings.iter().map(|f| f.source).collect::<Vec<_>>();

        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let mut signed = verdict();
        weigh_signature(&mut signed, &Path::new(&root).join(r"System32\notepad.exe"), true);
        assert_eq!(sources(&signed), [Source::Hash]);

        let tmp = tempfile::tempdir().unwrap();
        let unsigned_path = tmp.path().join("tool.exe");
        fs::write(&unsigned_path, b"MZ not really a program").unwrap();
        let mut unsigned = verdict();
        weigh_signature(&mut unsigned, &unsigned_path, true);
        assert_eq!(sources(&unsigned), [Source::Hash, Source::Yara, Source::Heuristic]);

        // A payload appended to a signed program voids the signature.
        let padded_path = tmp.path().join("padded.exe");
        let mut data = fs::read(Path::new(&root).join(r"System32\notepad.exe")).unwrap();
        data.extend_from_slice(b"appended payload");
        fs::write(&padded_path, data).unwrap();
        let mut padded = verdict();
        weigh_signature(&mut padded, &padded_path, true);
        assert_eq!(sources(&padded), [Source::Hash, Source::Yara, Source::Heuristic]);

        // With trust turned off a signed file keeps everything.
        let mut untrusted = verdict();
        weigh_signature(&mut untrusted, &Path::new(&root).join(r"System32\notepad.exe"), false);
        assert_eq!(sources(&untrusted), [Source::Hash, Source::Yara, Source::Heuristic]);
    }

    #[cfg(windows)]
    #[test]
    fn a_flagged_file_changed_after_signing_is_malware() {
        let tmp = tempfile::tempdir().unwrap();
        let Some(tampered) = trust::tampered_copy(tmp.path()) else {
            eprintln!("no program with an embedded signature in System32; skipped");
            return;
        };
        let flagged = || Verdict {
            sha256: String::new(),
            findings: vec![Finding {
                threat: "Suspicious.Heuristic.PE".into(),
                category: Category::Suspicious,
                source: Source::Heuristic,
                details: String::new(),
            }],
            warnings: Vec::new(),
        };
        for trust_signed in [true, false] {
            let mut verdict = flagged();
            weigh_signature(&mut verdict, &tampered, trust_signed);
            assert_eq!(verdict.findings.len(), 2);
            assert_eq!((verdict.findings[0].threat.as_str(), verdict.findings[0].category), (TAMPERED_THREAT, Category::Malware));
        }

        // Nothing flagged: the signature is not checked, nothing is added.
        let mut clean = Verdict { sha256: String::new(), findings: Vec::new(), warnings: Vec::new() };
        weigh_signature(&mut clean, &tampered, true);
        assert!(clean.findings.is_empty());
    }

    /// The scan workflow end to end: the test marker appended to a signed
    /// program is still reported.
    #[cfg(windows)]
    #[test]
    fn marker_appended_to_a_signed_program_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let mut data = fs::read(Path::new(&root).join(r"System32\PING.EXE")).unwrap();
        data.extend_from_slice(marker().as_bytes());
        fs::write(target.join("ping.exe"), data).unwrap();

        let data_dir = tmp.path().join("data");
        let store = open_store(&data_dir).unwrap();
        let options = ScanOptions::new(vec![target], "custom");
        assert!(options.trust_signed);
        let report = run(&engine(), &store, &data_dir, &options, &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(report.infected.len(), 1);
    }
}
