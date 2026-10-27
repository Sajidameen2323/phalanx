//! Keeping the history database to size: once a day the service removes what
//! the retention settings no longer keep (their totals stay in the monthly
//! figures), and once a month it compacts the file so the space goes back to
//! Windows. When each last happened is kept in `history-upkeep.json`.

use super::settings::ProtectionSettings;
use crate::scan;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const UPKEEP: &str = "history-upkeep.json";
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
    let db = data_dir.join("history.sqlite");
    let bytes = ["", "-wal"].iter().filter_map(|suffix| std::fs::metadata(format!("{}{suffix}", db.display())).ok()).map(|m| m.len()).sum();
    let upkeep = load(data_dir);
    Ok(HistoryInfo {
        bytes,
        scans,
        oldest,
        pruned_at: upkeep.pruned_at.and_then(local_time),
        pruned: upkeep.pruned,
        compacted_at: upkeep.compacted_at.and_then(local_time),
    })
}

/// Prunes and compacts if due. A compaction that fails (another connection
/// was writing) is tried at the next look.
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
