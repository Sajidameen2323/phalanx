//! Folder protection: turns change notifications from the watched folders
//! into files to scan.
//!
//! Files are scanned once they have *settled*: no change events and an
//! unchanged size for `settle`, so a download is scanned when it finishes,
//! not while it is being written. Browser/partial download names are ignored
//! until they are renamed to their final name. A folder moved or extracted
//! into a watched folder has its files scanned too.
//!
//! Higher-risk files (programs, scripts, disk images; see [`crate::risk`]) are
//! announced as soon as they land, before they settle, so the user is warned
//! before opening them, and go to the urgent scan lane.
//!
//! Nothing is silently missed: when Windows drops changes (too many at once)
//! the folder is rescanned for recent files, and a folder that disappears is
//! reported and watched again, with a catch-up scan, once it is back.

use super::dirwatch::{self, DirEvent, DirWatch};
use super::{Ctx, Item, RtpEvent};
use crate::risk;
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant, SystemTime};

/// Partial-download and temporary names; their final name is scanned instead.
const IN_PROGRESS_EXTENSIONS: &[&str] = &[
    "crdownload", "part", "partial", "download", "opdownload", "tmp", "temp", "!ut", "crswap",
];
/// Bound on the files one catch-up, rescan or new folder adds.
pub(super) const MAX_CATCH_UP_FILES: usize = 2000;
/// A file that never settles (e.g. a log being appended) is dropped after this.
const GIVE_UP_AFTER: Duration = Duration::from_secs(30 * 60);
/// Delay before announcing a risky file, so the browser has attached its
/// Mark of the Web (download origin) by the time it is read.
const ALERT_DELAY: Duration = Duration::from_millis(800);
/// Bound on remembered alerts; cleared when exceeded.
const MAX_ALERTED: usize = 5000;
/// How often watched folders are checked for having gone or come back.
const HEALTH_EVERY: Duration = Duration::from_secs(5);
/// Rescans and catch-ups also cover this much time before the gap, for
/// changes that were in flight when it started.
const GAP_MARGIN: Duration = Duration::from_secs(60);
/// After Windows drops changes, files changed this recently are rescanned.
const RESCAN_WINDOW: Duration = Duration::from_secs(5 * 60);

struct Pending {
    last_event: Instant,
    first_seen: Instant,
    size: Option<u64>,
    /// Arrived as a folder (moved or extracted in): scan what it contains.
    expand: bool,
}

struct Folder {
    path: PathBuf,
    watch: Option<DirWatch>,
    /// When watching last stopped, for the catch-up once it resumes.
    lost_at: Option<SystemTime>,
}

pub(super) fn run(ctx: &Ctx<'_>, urgent: &Sender<Item>, bulk: &Sender<Item>, catch_up_since: Option<SystemTime>) -> Result<()> {
    let config = ctx.config;
    let (tx, rx) = mpsc::channel();
    let mut folders = Vec::new();
    let mut failed = Vec::new();
    for path in &config.folders {
        let watch = match dirwatch::watch(path, tx.clone()) {
            Ok(watch) => Some(watch),
            Err(e) => {
                failed.push((path.clone(), e.to_string()));
                None
            }
        };
        let lost_at = watch.is_none().then(SystemTime::now);
        folders.push(Folder { path: path.clone(), watch, lost_at });
    }
    let watching = folders.iter().filter(|f| f.watch.is_some()).count();
    ctx.emit(RtpEvent::Started { watching, failed, programs: ctx.programs_enabled() });

    let mut pending: HashMap<PathBuf, Pending> = HashMap::new();
    // Risky files waiting to be announced, those announced and awaiting their
    // scan result, and every announced path (so each is announced once until
    // it is removed).
    let mut alerts: Vec<(PathBuf, Instant)> = Vec::new();
    let mut awaiting_result: HashSet<PathBuf> = HashSet::new();
    let mut alerted: HashSet<PathBuf> = HashSet::new();
    let mut last_health = Instant::now();
    if let Some(since) = catch_up_since {
        let roots: Vec<PathBuf> = folders.iter().filter(|f| f.watch.is_some()).map(|f| f.path.clone()).collect();
        add_settled(&mut pending, changed_since(&roots, since), config.settle);
    }

    while !ctx.halted() {
        let tick = if alerts.is_empty() { 500 } else { 200 };
        let mut next = rx.recv_timeout(Duration::from_millis(tick)).ok();
        while let Some(event) = next.take() {
            match event {
                DirEvent::Arrived(path) | DirEvent::Modified(path) if in_progress_name(&path) => {}
                DirEvent::Arrived(path) => {
                    if config.alert_risky && !alerted.contains(&path) && risk::classify(&path).is_some() {
                        if alerted.len() >= MAX_ALERTED {
                            alerted.clear();
                        }
                        alerted.insert(path.clone());
                        alerts.push((path.clone(), Instant::now()));
                    }
                    touch(&mut pending, path, true);
                }
                DirEvent::Modified(path) => touch(&mut pending, path, false),
                DirEvent::Removed(path) => {
                    pending.remove(&path);
                    alerted.remove(&path);
                }
                DirEvent::Overflow(folder) => {
                    // Windows dropped changes: look for anything recent.
                    let since = SystemTime::now() - RESCAN_WINDOW;
                    ctx.emit(RtpEvent::FolderRescan { folder: folder.clone() });
                    add_settled(&mut pending, changed_since(&[folder], since), config.settle);
                }
                DirEvent::Lost { folder, reason } => {
                    if let Some(f) = folders.iter_mut().find(|f| f.path == folder && f.watch.is_some()) {
                        f.watch = None;
                        f.lost_at = Some(SystemTime::now());
                        ctx.emit(RtpEvent::FolderLost { folder, reason });
                    }
                }
            }
            // Drain what has queued up before doing anything slower.
            next = rx.try_recv().ok();
        }

        if last_health.elapsed() >= HEALTH_EVERY {
            last_health = Instant::now();
            for folder in &mut folders {
                check_health(ctx, folder, &tx, &mut pending);
            }
        }

        alerts.retain(|(path, at)| {
            if at.elapsed() < ALERT_DELAY {
                return true;
            }
            let is_file = std::fs::metadata(path).is_ok_and(|m| m.is_file());
            if let (true, false, Some(risk)) = (is_file, ctx.is_excluded(path), risk::classify(path)) {
                awaiting_result.insert(path.clone());
                ctx.emit(RtpEvent::RiskyFile { path: path.clone(), risk, origin: risk::download_origin(path) });
            }
            false
        });

        for (path, expand) in take_settled(&mut pending, config.settle) {
            let files = if expand && path.is_dir() { files_in(&path) } else { vec![path] };
            for path in files {
                if ctx.is_excluded(&path) {
                    awaiting_result.remove(&path);
                    continue;
                }
                let announced = awaiting_result.remove(&path);
                let lane = if announced || risk::classify(&path).is_some() { urgent } else { bulk };
                lane.send(Item::File { path, announced }).map_err(|_| anyhow!("the scan lane stopped"))?;
            }
        }
    }
    Ok(())
}

/// Re-watches a folder that has come back, and notices one that is gone
/// even if Windows did not say so.
fn check_health(ctx: &Ctx<'_>, folder: &mut Folder, tx: &Sender<DirEvent>, pending: &mut HashMap<PathBuf, Pending>) {
    let exists = folder.path.is_dir();
    if folder.watch.is_some() && !exists {
        folder.watch = None;
        folder.lost_at = Some(SystemTime::now());
        ctx.emit(RtpEvent::FolderLost { folder: folder.path.clone(), reason: "the folder no longer exists".into() });
    } else if folder.watch.is_none() && exists && let Ok(watch) = dirwatch::watch(&folder.path, tx.clone()) {
        folder.watch = Some(watch);
        let since = folder.lost_at.take().map_or(SystemTime::UNIX_EPOCH, |t| t - GAP_MARGIN);
        ctx.emit(RtpEvent::FolderRestored { folder: folder.path.clone() });
        add_settled(pending, changed_since(std::slice::from_ref(&folder.path), since), ctx.config.settle);
    }
}

fn touch(pending: &mut HashMap<PathBuf, Pending>, path: PathBuf, arrived: bool) {
    let now = Instant::now();
    pending
        .entry(path)
        .and_modify(|p| {
            p.last_event = now;
            p.expand |= arrived;
        })
        .or_insert(Pending { last_event: now, first_seen: now, size: None, expand: arrived });
}

/// Queues files found by a walk; they are scanned once their size is stable.
fn add_settled(pending: &mut HashMap<PathBuf, Pending>, paths: Vec<PathBuf>, settle: Duration) {
    let now = Instant::now();
    for path in paths {
        pending.entry(path).or_insert(Pending { last_event: now - settle, first_seen: now, size: None, expand: false });
    }
}

/// Removes and returns entries that have been quiet for `settle`: files with
/// a stable size that can be opened, and folders that arrived (`true`).
fn take_settled(pending: &mut HashMap<PathBuf, Pending>, settle: Duration) -> Vec<(PathBuf, bool)> {
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
        if meta.is_dir() {
            if p.expand {
                ready.push((path.clone(), true));
            }
            return false;
        }
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
        ready.push((path.clone(), false));
        false
    });
    ready.sort();
    ready
}

pub(super) fn in_progress_name(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with("~$") || name.starts_with(".~") {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| IN_PROGRESS_EXTENSIONS.iter().any(|x| ext.eq_ignore_ascii_case(x)))
}

fn walk(roots: &[PathBuf], mut keep: impl FnMut(&walkdir::DirEntry) -> bool) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in roots {
        for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if found.len() >= MAX_CATCH_UP_FILES {
                return found;
            }
            if entry.file_type().is_file() && !in_progress_name(entry.path()) && keep(&entry) {
                found.push(entry.into_path());
            }
        }
    }
    found
}

/// Files under `folder`, for a folder moved or extracted into a watched one.
fn files_in(folder: &Path) -> Vec<PathBuf> {
    walk(&[folder.to_path_buf()], |_| true)
}

pub(super) fn changed_since(folders: &[PathBuf], since: SystemTime) -> Vec<PathBuf> {
    walk(folders, |entry| {
        // A file copied in keeps its old modification time but gets a new
        // creation time, so either counts.
        entry.metadata().ok().is_some_and(|m| {
            m.modified().is_ok_and(|t| t > since) || m.created().is_ok_and(|t| t > since)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_download_names_are_ignored() {
        assert!(in_progress_name(Path::new("C:/d/setup.exe.crdownload")));
        assert!(in_progress_name(Path::new("C:/d/movie.part")));
        assert!(in_progress_name(Path::new("C:/d/~$report.docx")));
        assert!(!in_progress_name(Path::new("C:/d/setup.exe")));
    }

    #[test]
    fn only_folders_that_arrived_are_expanded() {
        let tmp = tempfile::tempdir().unwrap();
        let moved_in = tmp.path().join("moved");
        let touched = tmp.path().join("touched");
        for dir in [&moved_in, &touched] {
            std::fs::create_dir(dir).unwrap();
            std::fs::write(dir.join("a.txt"), "a").unwrap();
        }
        let mut pending = HashMap::new();
        touch(&mut pending, moved_in.clone(), true);
        touch(&mut pending, touched.clone(), false);
        std::thread::sleep(Duration::from_millis(30));
        let ready = take_settled(&mut pending, Duration::from_millis(10));
        assert_eq!(ready, vec![(moved_in.clone(), true)]);
        assert!(pending.is_empty());
        assert_eq!(files_in(&moved_in), vec![moved_in.join("a.txt")]);
    }

    #[test]
    fn copied_in_files_count_as_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("old.txt");
        std::fs::write(&file, "x").unwrap();
        // An old modification time, as a copy keeps; its creation time is new.
        let old = SystemTime::now() - Duration::from_secs(3600 * 24 * 30);
        std::fs::File::options().write(true).open(&file).unwrap().set_modified(old).unwrap();
        let since = SystemTime::now() - Duration::from_secs(60);
        if cfg!(windows) {
            assert_eq!(changed_since(&[tmp.path().to_path_buf()], since), vec![file]);
        }
    }
}
