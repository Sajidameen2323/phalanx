//! Real-time protection: scans files as they arrive in watched folders and
//! programs as they start, and acts on what it finds.
//!
//! The design follows the classic on-access antivirus pipeline, in user mode:
//!
//! ```text
//!  folder monitor ──┐                      ┌─ urgent lane (programs starting,
//!  (ReadDirectory-  │   exclusions, then   │   new programs/scripts; normal
//!   ChangesW)       ├─▶ disposition cache ─┼─ bulk lane (other files, catch-up;
//!  program monitor ─┘   (skip if known)    │   background priority, waits
//!  (process list)                          │   while a game is full screen)
//!                                          └─ sweep lane (programs already
//!                                              running at start; background)
//!                         │
//!                         ▼  engine: hashes → YARA → heuristics, with
//!                            heuristic-only hits on signed files dropped
//!                         ▼
//!          verdict cached; threats reported, quarantined and, for a
//!          running program, the process stopped
//! ```
//!
//! Without a kernel driver nothing is intercepted *before* it runs: a program
//! is checked within about half a second of starting and stopped if it is
//! known malware, and very short-lived programs can finish before that.
//!
//! A supervisor restarts the whole pipeline if any part fails or panics,
//! with backoff, and catches up on files that changed while it was down.
//! Verdicts are cached for the lifetime of a [`RtpHandle`]; callers start a
//! new one when signatures or settings change, which also clears the cache.

mod cache;
mod dirwatch;
mod files;
pub mod process;

use self::cache::{Disposition, DispositionCache, FileKey};
use self::process::ProcessInfo;
use crate::engine::Engine;
use crate::risk::{DownloadOrigin, RiskyFile};
use crate::scan::{self, FileReport, ScanEvent, ScanOptions, ScanReport};
use crate::store::Store;
use crate::{system, Category};
use anyhow::{anyhow, bail, Result};
use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

/// Items a lane scans together (one history entry).
const MAX_BATCH: usize = 32;
/// How often the list of running programs is read.
const PROCESS_POLL: Duration = Duration::from_millis(500);
/// Consecutive failures to list programs before the monitor gives up (and is restarted).
const MAX_PROCESS_LIST_FAILURES: u32 = 10;
/// Longest the bulk lane waits for a full-screen game or presentation to end.
const MAX_DEFER: Duration = Duration::from_secs(10 * 60);
/// A known threat that keeps restarting is reported at most this often.
const BLOCK_NOTICE_EVERY: Duration = Duration::from_secs(60);
/// Restart backoff after a failure, doubling up to the maximum.
const MIN_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A run that lasted this long was healthy: the backoff starts over.
const HEALTHY_RUN: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone)]
pub struct RtpConfig {
    pub folders: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
    pub max_size_bytes: u64,
    pub quarantine_floor: Option<Category>,
    pub signatures: Option<String>,
    /// On start, also scan files changed after this time (catch-up for files
    /// that arrived while protection was not running).
    pub catch_up_since: Option<SystemTime>,
    pub settle: Duration,
    /// Announce programs and scripts as soon as they land.
    pub alert_risky: bool,
    /// Scan the program file of every process that starts (Windows).
    pub process_protection: bool,
    /// Stop a running program found to be malware. PUPs and hacking tools
    /// (often run on purpose) and heuristic findings are only reported.
    pub stop_running_threats: bool,
    /// Ignore heuristic-only findings on files with a valid signature.
    pub trust_signed: bool,
    /// Hold back non-urgent scans while a full-screen game or presentation runs.
    pub defer_when_fullscreen: bool,
}

impl RtpConfig {
    /// Defaults for watching `folders`; program protection off.
    pub fn new(folders: Vec<PathBuf>) -> Self {
        Self {
            folders,
            exclude: Vec::new(),
            max_size_bytes: 100 * 1024 * 1024,
            quarantine_floor: None,
            signatures: None,
            catch_up_since: None,
            settle: Duration::from_secs(3),
            alert_risky: true,
            process_protection: false,
            stop_running_threats: true,
            trust_signed: true,
            defer_when_fullscreen: true,
        }
    }
}

/// What produced a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Folder,
    Program,
}

/// How the scan of an announced risky file ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskyOutcome {
    /// Scanned; no signature or heuristic matched.
    NoThreatFound,
    /// Detected; a detection event carries the details.
    Threat(String),
    /// Not scanned (too large, unreadable or removed); the reason.
    NotScanned(String),
}

/// A running process of a detected program.
#[derive(Debug, Clone)]
pub struct ProcessHit {
    pub pid: u32,
    pub name: String,
    /// `None` when it was left running (stopping is off, or the finding is
    /// only suspicious); otherwise whether stopping it worked.
    pub stopped: Option<Result<(), String>>,
}

pub enum RtpEvent {
    /// Protection started; `failed` lists folders that could not be watched
    /// (they are retried and reported by `FolderRestored` when they work).
    Started { watching: usize, failed: Vec<(PathBuf, String)>, programs: bool },
    /// A folder can no longer be watched; it is retried every few seconds.
    FolderLost { folder: PathBuf, reason: String },
    /// A folder is watched again; recent files in it are being checked.
    FolderRestored { folder: PathBuf },
    /// Windows dropped change notifications; recent files are rescanned.
    FolderRescan { folder: PathBuf },
    /// A threat was found; `processes` are its running copies, for programs.
    Detection { report: FileReport, processes: Vec<ProcessHit> },
    /// A program already detected was started again and handled.
    Blocked { report: FileReport, processes: Vec<ProcessHit> },
    /// A batch was scanned.
    Scanned { origin: Origin, report: ScanReport },
    /// A program, script or similar file just landed; it is scanned once it settles.
    RiskyFile { path: PathBuf, risk: RiskyFile, origin: Option<DownloadOrigin> },
    /// The scan of a file announced by `RiskyFile` finished.
    RiskyChecked { path: PathBuf, outcome: RiskyOutcome },
    /// Part of protection failed; everything restarts after `retry_in`.
    Restarting { error: String, retry_in: Duration },
    Error(String),
}

pub struct RtpHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RtpHandle {
    /// Stops protection and waits for an in-progress scan to wind down.
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

impl Drop for RtpHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

type EventSink = Mutex<Box<dyn FnMut(RtpEvent) + Send>>;

/// Starts real-time protection. Fails only if the history database cannot
/// be opened; problems after that are reported as events and recovered from.
pub fn start(
    engine: Arc<Engine>,
    data_dir: PathBuf,
    config: RtpConfig,
    on_event: impl FnMut(RtpEvent) + Send + 'static,
) -> Result<RtpHandle> {
    scan::open_store(&data_dir)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new().name("rtp-supervisor".into()).spawn(move || {
        let events: EventSink = Mutex::new(Box::new(on_event));
        supervise(&engine, &data_dir, &config, &thread_stop, &events);
    })?;
    Ok(RtpHandle { stop, thread: Some(thread) })
}

/// What one run of the pipeline shares between its threads.
struct Ctx<'a> {
    engine: &'a Engine,
    data_dir: &'a Path,
    config: &'a RtpConfig,
    /// Set by [`RtpHandle::stop`].
    stop: &'a AtomicBool,
    /// Set when stopping or when any thread of this run ends.
    halt: AtomicBool,
    cache: &'a Mutex<DispositionCache>,
    /// Canonical paths never scanned.
    excluded: &'a [PathBuf],
    events: &'a EventSink,
}

enum Lookup {
    Gone,
    Cached(Disposition),
    Miss(FileKey),
}

impl Ctx<'_> {
    fn halted(&self) -> bool {
        if self.stop.load(Ordering::Relaxed) {
            self.halt.store(true, Ordering::Relaxed);
        }
        self.halt.load(Ordering::Relaxed)
    }

    fn emit(&self, event: RtpEvent) {
        (self.events.lock().unwrap_or_else(PoisonError::into_inner))(event);
    }

    fn is_excluded(&self, path: &Path) -> bool {
        std::fs::canonicalize(path).is_ok_and(|real| self.excluded.iter().any(|x| real.starts_with(x)))
    }

    fn programs_enabled(&self) -> bool {
        self.config.process_protection && process::SUPPORTED
    }

    fn lookup(&self, path: &Path) -> Lookup {
        let Some(key) = FileKey::of(path) else { return Lookup::Gone };
        match self.cache.lock().unwrap_or_else(PoisonError::into_inner).get(&key) {
            Some(disposition) => Lookup::Cached(disposition),
            None => Lookup::Miss(key),
        }
    }

    /// Sleeps up to `duration`, waking early when halted.
    fn pause(&self, duration: Duration) {
        let until = Instant::now() + duration;
        while !self.halted() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100).min(until.saturating_duration_since(Instant::now())));
        }
    }
}

enum Item {
    File { path: PathBuf, announced: bool },
    Program(ProcessInfo),
}

fn supervise(engine: &Engine, data_dir: &Path, config: &RtpConfig, stop: &AtomicBool, events: &EventSink) {
    let cache = Mutex::new(DispositionCache::default());
    let excluded: Vec<PathBuf> = config
        .exclude
        .iter()
        .cloned()
        .chain([data_dir.to_path_buf()])
        .chain(std::env::current_exe().ok())
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    let mut catch_up = config.catch_up_since;
    let mut backoff = MIN_BACKOFF;
    loop {
        let started = SystemTime::now();
        let began = Instant::now();
        let ctx = Ctx { engine, data_dir, config, stop, halt: AtomicBool::new(false), cache: &cache, excluded: &excluded, events };
        let outcome = run_once(&ctx, catch_up);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let error = outcome.err().unwrap_or_else(|| "protection stopped unexpectedly".into());
        let healthy = began.elapsed() >= HEALTHY_RUN;
        if healthy {
            backoff = MIN_BACKOFF;
        }
        ctx.emit(RtpEvent::Restarting { error, retry_in: backoff });
        ctx.pause(backoff);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
        // Catch up on what changed since this run began; a run that failed
        // quickly may not have finished its own catch-up, so keep that too.
        catch_up = Some(match catch_up {
            Some(earlier) if !healthy => earlier.min(started),
            _ => started,
        });
    }
}

/// Runs every part of the pipeline until one ends; returns the first error.
fn run_once(ctx: &Ctx<'_>, catch_up: Option<SystemTime>) -> Result<(), String> {
    let (urgent_tx, urgent_rx) = mpsc::channel();
    let (bulk_tx, bulk_rx) = mpsc::channel();
    let (sweep_tx, sweep_rx) = mpsc::channel();
    std::thread::scope(|s| {
        let mut threads = Vec::new();
        let mut failures = Vec::new();
        let mut add = |started: std::io::Result<_>, name: &str| match started {
            Ok(handle) => threads.push(handle),
            Err(e) => {
                ctx.halt.store(true, Ordering::Relaxed);
                failures.push(format!("could not start {name}: {e}"));
            }
        };
        add(spawn_part(s, ctx, "urgent-lane", false, move || lane(ctx, urgent_rx, false)), "urgent-lane");
        add(spawn_part(s, ctx, "bulk-lane", true, move || lane(ctx, bulk_rx, true)), "bulk-lane");
        if ctx.programs_enabled() {
            add(spawn_part(s, ctx, "sweep-lane", true, move || lane(ctx, sweep_rx, true)), "sweep-lane");
            let urgent = urgent_tx.clone();
            add(spawn_part(s, ctx, "program-monitor", false, move || programs(ctx, &urgent, &sweep_tx)), "program-monitor");
        } else {
            drop(sweep_rx);
        }
        add(
            spawn_part(s, ctx, "folder-monitor", true, move || files::run(ctx, &urgent_tx, &bulk_tx, catch_up)),
            "folder-monitor",
        );
        for thread in threads {
            if let Err(e) = thread.join().unwrap_or_else(|_| Err("a protection thread crashed".into())) {
                failures.push(e);
            }
        }
        failures.into_iter().next().map_or(Ok(()), Err)
    })
}

/// Starts one part of the pipeline. A part that ends for any reason (error,
/// panic, or finishing) halts the run, so it restarts whole.
fn spawn_part<'scope, 'env>(
    s: &'scope std::thread::Scope<'scope, 'env>,
    ctx: &'env Ctx<'env>,
    name: &'static str,
    background: bool,
    f: impl FnOnce() -> Result<()> + Send + 'scope,
) -> std::io::Result<std::thread::ScopedJoinHandle<'scope, Result<(), String>>> {
    std::thread::Builder::new().name(format!("rtp-{name}")).spawn_scoped(s, move || {
        if background {
            system::enter_background_mode();
        }
        let result = match catch_unwind(AssertUnwindSafe(f)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("{name}: {e:#}")),
            Err(panic) => Err(format!("{name} crashed: {}", panic_text(&panic))),
        };
        ctx.halt.store(true, Ordering::Relaxed);
        result
    })
}

fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into())
}

/// Watches for programs starting. Programs already running when protection
/// starts go to the sweep lane, so they never hold up new files; new ones go
/// to the urgent lane.
fn programs(ctx: &Ctx<'_>, urgent: &Sender<Item>, sweep: &Sender<Item>) -> Result<()> {
    let mut known: HashSet<process::ProcessId> = HashSet::new();
    let mut first = true;
    let mut failures = 0;
    while !ctx.halted() {
        match process::running() {
            Ok(list) => {
                failures = 0;
                let lane = if first { sweep } else { urgent };
                let mut current = HashSet::with_capacity(list.len());
                for info in list {
                    current.insert(info.id.clone());
                    if known.contains(&info.id) || ctx.is_excluded(&info.image) {
                        continue;
                    }
                    lane.send(Item::Program(info)).map_err(|_| anyhow!("the scan lane stopped"))?;
                }
                known = current;
                first = false;
            }
            Err(e) => {
                failures += 1;
                if failures >= MAX_PROCESS_LIST_FAILURES {
                    bail!("cannot list running programs: {e}");
                }
            }
        }
        ctx.pause(PROCESS_POLL);
    }
    Ok(())
}

/// Scans what arrives on `rx`, a batch at a time, until halted or every
/// sender is gone.
fn lane(ctx: &Ctx<'_>, rx: Receiver<Item>, bulk: bool) -> Result<()> {
    let store = scan::open_store(ctx.data_dir)?;
    let mut notices: HashMap<PathBuf, Instant> = HashMap::new();
    while !ctx.halted() {
        let first = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(item) => item,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(item) => batch.push(item),
                Err(_) => break,
            }
        }
        if bulk && ctx.config.defer_when_fullscreen {
            let since = Instant::now();
            while system::fullscreen_app_running() && since.elapsed() < MAX_DEFER && !ctx.halted() {
                ctx.pause(Duration::from_secs(2));
            }
        }
        let mut files = Vec::new();
        let mut programs = Vec::new();
        for item in batch {
            match item {
                Item::File { path, announced } => files.push((path, announced)),
                Item::Program(info) => programs.push(info),
            }
        }
        if !files.is_empty() {
            scan_files(ctx, &store, files, !bulk);
        }
        if !programs.is_empty() {
            scan_programs(ctx, &store, programs, !bulk, &mut notices);
        }
    }
    Ok(())
}

fn scan_files(ctx: &Ctx<'_>, store: &Store, items: Vec<(PathBuf, bool)>, urgent: bool) {
    let mut announced = HashSet::new();
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for (path, was_announced) in items {
        if was_announced {
            announced.insert(path.clone());
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        let outcome = match ctx.lookup(&path) {
            Lookup::Miss(key) => {
                targets.push((path, key));
                continue;
            }
            Lookup::Gone => RiskyOutcome::NotScanned("the file was removed before it could be scanned".into()),
            Lookup::Cached(Disposition::Clean) => RiskyOutcome::NoThreatFound,
            Lookup::Cached(Disposition::Threat(report)) => RiskyOutcome::Threat(report.worst().threat.clone()),
        };
        if announced.remove(&path) {
            ctx.emit(RtpEvent::RiskyChecked { path, outcome });
        }
    }
    let Some(report) = scan_batch(ctx, store, targets, "watch", ctx.config.quarantine_floor, true, urgent) else {
        for path in announced {
            let outcome = RiskyOutcome::NotScanned("the scan could not run".into());
            ctx.emit(RtpEvent::RiskyChecked { path, outcome });
        }
        return;
    };
    for found in &report.infected {
        ctx.emit(RtpEvent::Detection { report: found.clone(), processes: Vec::new() });
    }
    for path in announced {
        let outcome = risky_outcome(&path, &report, ctx.config.max_size_bytes);
        ctx.emit(RtpEvent::RiskyChecked { path, outcome });
    }
    ctx.emit(RtpEvent::Scanned { origin: Origin::Folder, report });
}

fn scan_programs(ctx: &Ctx<'_>, store: &Store, list: Vec<ProcessInfo>, urgent: bool, notices: &mut HashMap<PathBuf, Instant>) {
    // One scan per program file, however many copies are running.
    let mut by_image: HashMap<PathBuf, Vec<ProcessInfo>> = HashMap::new();
    for info in list {
        by_image.entry(info.image.clone()).or_default().push(info);
    }
    let mut targets = Vec::new();
    for (image, running) in &by_image {
        match ctx.lookup(image) {
            Lookup::Miss(key) => targets.push((image.clone(), key)),
            Lookup::Gone | Lookup::Cached(Disposition::Clean) => {}
            Lookup::Cached(Disposition::Threat(known)) => {
                let (processes, action) = respond(ctx, store, running, &known, false);
                let stopped = processes.iter().any(|p| matches!(p.stopped, Some(Ok(()))));
                let due = notices.get(image).is_none_or(|t| t.elapsed() >= BLOCK_NOTICE_EVERY);
                if stopped && due {
                    notices.insert(image.clone(), Instant::now());
                    let report = FileReport { action, ..(*known).clone() };
                    ctx.emit(RtpEvent::Blocked { report, processes });
                }
            }
        }
    }
    let Some(report) = scan_batch(ctx, store, targets, "process", None, false, urgent) else { return };
    for found in &report.infected {
        let running = by_image.get(Path::new(&found.path)).map(Vec::as_slice).unwrap_or_default();
        let (processes, action) = respond(ctx, store, running, found, true);
        let quarantined = action.contains("quarantined (");
        if let Err(e) = store.set_detection_action(report.scan_id, &found.path, &action, quarantined) {
            ctx.emit(RtpEvent::Error(format!("recording the action taken: {e:#}")));
        }
        ctx.emit(RtpEvent::Detection { report: FileReport { action, ..found.clone() }, processes });
    }
    ctx.emit(RtpEvent::Scanned { origin: Origin::Program, report });
}

/// Stops the running copies of a detected program (when allowed) and
/// quarantines its file (when allowed). Returns what was done to each
/// process and the action taken, for history.
fn respond(ctx: &Ctx<'_>, store: &Store, running: &[ProcessInfo], report: &FileReport, first_time: bool) -> (Vec<ProcessHit>, String) {
    let worst = report.worst();
    let stop = ctx.config.stop_running_threats && worst.category == Category::Malware;
    let processes: Vec<ProcessHit> = running
        .iter()
        .map(|p| ProcessHit { pid: p.id.pid, name: p.name.clone(), stopped: stop.then(|| process::terminate(&p.id)) })
        .collect();
    let stopped = processes.iter().filter(|p| matches!(p.stopped, Some(Ok(())))).count();
    let mut action = if stopped > 0 { "program stopped".to_string() } else { "reported".to_string() };
    // A file that stays locked by a copy still running cannot be quarantined;
    // after the first detection, only retry once something was stopped.
    let allowed = ctx.config.quarantine_floor.is_some_and(|floor| worst.category >= floor);
    if allowed && (first_time || stopped > 0) {
        let path = Path::new(&report.path);
        let mut attempt = 0;
        let result = loop {
            match scan::quarantine_file(store, ctx.data_dir, path, &report.sha256, &worst.threat) {
                Ok(id) => break Ok(id),
                // The image can stay locked for a moment after its process exits.
                Err(_) if stopped > 0 && attempt < 10 && path.exists() => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(300));
                }
                Err(e) => break Err(e),
            }
        };
        action = match result {
            Ok(id) if stopped > 0 => format!("{action}; quarantined ({id})"),
            Ok(id) => format!("quarantined ({id})"),
            Err(e) => format!("{action}; quarantine failed: {e:#}"),
        };
    }
    (processes, action)
}

/// Scans `targets`, records the batch in history (clean program batches are
/// not kept: they would flood it), and caches each verdict under the file
/// version that was scanned. `None` if nothing could be scanned.
fn scan_batch(
    ctx: &Ctx<'_>,
    store: &Store,
    targets: Vec<(PathBuf, FileKey)>,
    kind: &str,
    quarantine_floor: Option<Category>,
    keep_clean_history: bool,
    urgent: bool,
) -> Option<ScanReport> {
    let keys: HashMap<PathBuf, FileKey> = targets.into_iter().filter(|(p, _)| p.is_file()).collect();
    if keys.is_empty() {
        return None;
    }
    let mut paths: Vec<PathBuf> = keys.keys().cloned().collect();
    paths.sort();
    let mut options = ScanOptions::new(paths, kind);
    options.exclude = ctx.config.exclude.clone();
    options.max_size_bytes = ctx.config.max_size_bytes;
    options.quarantine_floor = quarantine_floor;
    options.signatures = ctx.config.signatures.clone();
    options.trust_signed = ctx.config.trust_signed;
    options.keep_clean_history = keep_clean_history;
    options.threads = 1;
    options.background = !urgent;
    let mut scanned = Vec::new();
    let mut on_event = |event: ScanEvent<'_>| {
        if let ScanEvent::Progress { path, .. } = event {
            scanned.push(path.to_path_buf());
        }
    };
    let report = match scan::run(ctx.engine, store, ctx.data_dir, &options, &ctx.halt, &mut on_event) {
        Ok(report) => report,
        Err(e) => {
            ctx.emit(RtpEvent::Error(format!("{e:#}")));
            return None;
        }
    };
    let mut cache = ctx.cache.lock().unwrap_or_else(PoisonError::into_inner);
    for path in scanned {
        let Some(key) = keys.get(&path) else { continue };
        let shown = path.display().to_string();
        let disposition = match report.infected.iter().find(|r| r.path == shown) {
            Some(found) => Disposition::Threat(Arc::new(found.clone())),
            None => Disposition::Clean,
        };
        cache.insert(key.clone(), disposition);
    }
    Some(report)
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
        Ok(_) if report.cancelled => RiskyOutcome::NotScanned("protection stopped first".into()),
        Ok(_) => RiskyOutcome::NoThreatFound,
    }
}

#[cfg(test)]
mod tests;
