//! Keeping the history database sound and to size. When the service starts
//! it checks the database before anything opens it, and a damaged one is
//! moved aside and replaced with the last backup ([`check_at_start`]). Once a
//! day it removes what the retention settings no longer keep (their totals
//! stay in the monthly figures) and, if the database passes a quick check,
//! backs it up; once a month it compacts the file so the space goes back to
//! Windows. When each last happened is kept in `history-upkeep.json`.
//!
//! A restored backup is up to a day old: quarantine records made since are
//! not in it (the quarantined files themselves stay in their folder).

use super::settings::ProtectionSettings;
use crate::scan;
use crate::store::Store;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const UPKEEP: &str = "history-upkeep.json";
const DB: &str = "history.sqlite";
const BACKUP: &str = "history.backup.sqlite";
/// Written first, then renamed over [`BACKUP`], so a backup interrupted
/// halfway never replaces a good one.
const BACKUP_PART: &str = "history.backup.sqlite.part";
const PRUNE_EVERY: u64 = 24 * 3600;
const COMPACT_EVERY: u64 = 30 * 24 * 3600;
/// After the service starts, the first upkeep waits this long, so it does not
/// compete with loading signatures and starting protection.
const FIRST_AFTER: Duration = Duration::from_secs(120);
/// How often the schedule looks whether upkeep is due.
const TICK: Duration = Duration::from_secs(3600);

/// When upkeep last ran (seconds since 1970) and what it removed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Upkeep {
    pruned_at: Option<u64>,
    compacted_at: Option<u64>,
    /// Scans removed by the last prune.
    pruned: u64,
    backed_up_at: Option<u64>,
    /// When the database was last checked as the service started.
    checked_at: Option<u64>,
    /// The last time a damaged database was replaced.
    recovered: Option<Recovered>,
}

/// A damaged history database found as the service started, and what was
/// done about it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Recovered {
    /// When (seconds since 1970).
    pub at: u64,
    /// What SQLite's check found.
    pub problem: String,
    /// The last backup took its place; otherwise history starts empty.
    pub from_backup: bool,
    /// Where the damaged file was moved, in the data folder.
    pub kept_as: String,
}

/// The reply to `HistoryInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryInfo {
    /// The database's size on disk, with its write-ahead log.
    pub bytes: u64,
    pub scans: i64,
    /// When the oldest scan kept started.
    pub oldest: Option<String>,
    /// When old history was last removed, and how many scans went.
    pub pruned_at: Option<String>,
    pub pruned: u64,
    /// When the file was last compacted.
    pub compacted_at: Option<String>,
    /// When it was last backed up.
    #[serde(default)]
    pub backed_up_at: Option<String>,
    /// Its layout ([`crate::store::SCHEMA_VERSION`]).
    #[serde(default)]
    pub schema_version: i64,
    /// When it was last checked as the service started.
    #[serde(default)]
    pub checked_at: Option<String>,
    /// The last time a damaged database was replaced, if ever.
    #[serde(default)]
    pub recovered: Option<Recovered>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn load(data_dir: &Path) -> Upkeep {
    std::fs::read(data_dir.join(UPKEEP)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(data_dir: &Path, upkeep: &Upkeep) {
    if let Ok(bytes) = serde_json::to_vec_pretty(upkeep) {
        let _ = std::fs::write(data_dir.join(UPKEEP), bytes);
    }
}

fn local_time(secs: u64) -> Option<String> {
    let at = chrono::DateTime::from_timestamp(secs as i64, 0)?;
    Some(at.with_timezone(&chrono::Local).to_rfc3339_opts(chrono::SecondsFormat::Secs, false))
}

/// The history database's size and what it holds.
pub fn info(data_dir: &Path) -> Result<HistoryInfo> {
    let store = scan::open_store(data_dir)?;
    let (scans, oldest) = store.extent()?;
    let db = data_dir.join(DB);
    let bytes = ["", "-wal"].iter().filter_map(|suffix| std::fs::metadata(format!("{}{suffix}", db.display())).ok()).map(|m| m.len()).sum();
    let upkeep = load(data_dir);
    Ok(HistoryInfo {
        bytes,
        scans,
        oldest,
        pruned_at: upkeep.pruned_at.and_then(local_time),
        pruned: upkeep.pruned,
        compacted_at: upkeep.compacted_at.and_then(local_time),
        backed_up_at: upkeep.backed_up_at.and_then(local_time),
        schema_version: store.schema_version()?,
        checked_at: upkeep.checked_at.and_then(local_time),
        recovered: upkeep.recovered,
    })
}

/// Checks the history database before anything opens it. A damaged one is
/// moved aside (never deleted: it may still be read) and the last backup
/// that passes the same check takes its place; without one, history starts
/// empty. Returns what was done, if anything.
pub fn check_at_start(data_dir: &Path) -> Option<Recovered> {
    let db = data_dir.join(DB);
    if !db.is_file() {
        return None;
    }
    let mut state = load(data_dir);
    state.checked_at = Some(now());
    let recovered = Store::check_file(&db).err().map(|problem| recover(data_dir, problem));
    if recovered.is_some() {
        state.recovered = recovered.clone();
    }
    save(data_dir, &state);
    recovered
}

fn recover(data_dir: &Path, problem: String) -> Recovered {
    let at = now();
    let kept_as = format!("history.damaged-{at}.sqlite");
    let db = data_dir.join(DB);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::rename(format!("{}{suffix}", db.display()), format!("{}{suffix}", data_dir.join(&kept_as).display()));
    }
    let backup = data_dir.join(BACKUP);
    let from_backup = backup.is_file() && Store::check_file(&backup).is_ok() && std::fs::copy(&backup, &db).is_ok();
    Recovered { at, problem, from_backup, kept_as }
}

/// Backs the database up if it passes a quick check, so a damaged database
/// never replaces the last good backup.
fn back_up(data_dir: &Path, store: &Store) -> Result<bool> {
    if !store.quick_check()? {
        return Ok(false);
    }
    let part = data_dir.join(BACKUP_PART);
    let _ = std::fs::remove_file(&part);
    store.back_up_to(&part)?;
    std::fs::rename(&part, data_dir.join(BACKUP))?;
    Ok(true)
}

/// Prunes and backs up once a day, and compacts once a month, when due. A
/// compaction that fails (another connection was writing) is tried at the
/// next look.
pub fn upkeep(data_dir: &Path) -> Result<()> {
    let mut state = load(data_dir);
    let due = |last: Option<u64>, every: u64| last.is_none_or(|t| now().saturating_sub(t) >= every);
    let (prune, compact) = (due(state.pruned_at, PRUNE_EVERY), due(state.compacted_at, COMPACT_EVERY));
    if !prune && !compact {
        return Ok(());
    }
    let store = scan::open_store(data_dir)?;
    if prune {
        let retention = ProtectionSettings::load(data_dir).unwrap_or_default().retention();
        state.pruned = store.prune(retention, chrono::Local::now())? as u64;
        state.pruned_at = Some(now());
        save(data_dir, &state);
        if back_up(data_dir, &store)? {
            state.backed_up_at = Some(now());
            save(data_dir, &state);
        }
    }
    if compact {
        store.compact()?;
        state.compacted_at = Some(now());
        save(data_dir, &state);
    }
    Ok(())
}

/// Runs [`upkeep`] in the background, a while after the start and then
/// whenever it is due, until `stop` is set.
pub fn schedule(data_dir: &Path, stop: Arc<AtomicBool>) {
    let dir = data_dir.to_path_buf();
    let _ = std::thread::Builder::new().name("history-upkeep".into()).spawn(move || {
        let mut wait = FIRST_AFTER;
        loop {
            // Sleep in short steps, so stopping the service is quick.
            let mut slept = Duration::ZERO;
            while slept < wait {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
                slept += Duration::from_secs(1);
            }
            crate::system::enter_background_mode();
            let _ = upkeep(&dir);
            wait = TICK;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data folder whose history holds `scans` scans.
    fn with_scans(dir: &Path, scans: usize) {
        let store = scan::open_store(dir).unwrap();
        for i in 0..scans {
            let id = store.begin_scan(&crate::store::ScanMeta { kind: "quick", targets: &format!("scan {i}"), threads: 1, signatures: None }).unwrap();
            store.finish_scan(id, &Default::default(), 1, false).unwrap();
        }
    }

    fn scan_count(dir: &Path) -> i64 {
        scan::open_store(dir).unwrap().extent().unwrap().0
    }

    /// Overwrites the start of the database file, as a failing disk might.
    fn damage(dir: &Path) {
        // Everything into the main file first, as a service stopping does.
        scan::open_store(dir).unwrap().compact().unwrap();
        let db = dir.join(DB);
        let mut bytes = std::fs::read(&db).unwrap();
        bytes[..100].fill(0xA5);
        std::fs::write(&db, bytes).unwrap();
    }

    #[test]
    fn a_damaged_database_is_replaced_by_the_last_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        with_scans(dir, 5);
        // A healthy database is left as it is.
        assert_eq!(check_at_start(dir), None);
        assert!(load(dir).checked_at.is_some());

        // The daily upkeep backs it up; a scan comes after the backup.
        upkeep(dir).unwrap();
        assert!(dir.join(BACKUP).is_file() && load(dir).backed_up_at.is_some());
        with_scans(dir, 1);
        assert_eq!(scan_count(dir), 6);

        damage(dir);
        assert!(Store::check_file(&dir.join(DB)).is_err());
        let recovered = check_at_start(dir).expect("the damage is found");
        assert!(recovered.from_backup, "{recovered:?}");
        assert!(dir.join(&recovered.kept_as).is_file(), "the damaged file is kept, not deleted");
        // History is the backup's: the scan after it is lost, the rest is there.
        assert_eq!(scan_count(dir), 5);
        assert_eq!(info(dir).unwrap().recovered, Some(recovered));
    }

    #[test]
    fn a_damaged_database_without_a_backup_starts_history_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        with_scans(dir, 3);
        damage(dir);
        let recovered = check_at_start(dir).expect("the damage is found");
        assert!(!recovered.from_backup && !recovered.problem.is_empty(), "{recovered:?}");
        assert!(dir.join(&recovered.kept_as).is_file());
        assert_eq!(scan_count(dir), 0);
        // And it works again.
        with_scans(dir, 1);
        assert_eq!(scan_count(dir), 1);
    }

    #[test]
    fn a_newer_database_keeps_its_schema_version() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        with_scans(dir, 1);
        assert_eq!(info(dir).unwrap().schema_version, crate::store::SCHEMA_VERSION);
        scan::open_store(dir).unwrap().conn_for_test().execute_batch("PRAGMA user_version = 99").unwrap();
        assert_eq!(scan::open_store(dir).unwrap().schema_version().unwrap(), 99);
    }

    #[test]
    fn upkeep_prunes_once_a_day_and_compacts_once_a_month() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        ProtectionSettings { clean_history_days: 1, ..Default::default() }.save(dir).unwrap();
        let store = scan::open_store(dir).unwrap();
        let id = store.begin_scan(&crate::store::ScanMeta { kind: "watch", targets: "old", threads: 1, signatures: None }).unwrap();
        store.finish_scan(id, &Default::default(), 1, false).unwrap();
        // Two days old, so the 1-day retention removes it.
        let old = (chrono::Local::now() - chrono::Duration::days(2)).to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
        store.set_started_at_for_test(id, &old).unwrap();
        drop(store);

        upkeep(dir).unwrap();
        let first = info(dir).unwrap();
        assert_eq!((first.scans, first.pruned), (0, 1), "{first:?}");
        assert!(first.pruned_at.is_some() && first.compacted_at.is_some(), "{first:?}");
        assert!(first.bytes > 0);

        // Not due again yet: nothing changes.
        upkeep(dir).unwrap();
        assert_eq!(info(dir).unwrap(), first);

        // A day later it prunes again, but does not compact for a month.
        let mut state = load(dir);
        let day_ago = state.pruned_at.unwrap() - PRUNE_EVERY;
        state.pruned_at = Some(day_ago);
        save(dir, &state);
        upkeep(dir).unwrap();
        let after = load(dir);
        assert!(after.pruned_at.unwrap() > day_ago, "{after:?}");
        assert_eq!(after.compacted_at, state.compacted_at);
    }
}
