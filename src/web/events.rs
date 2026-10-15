//! A small append-only log of web protection decisions (blocks, and matches
//! in report-only mode), written by the DNS filter and the browser connector
//! and shown by the desktop app and `phalanx-cli web events`.

use super::rules::Verdict;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

const FILE: &str = "web-events.jsonl";
/// When the log grows past this, its older half is dropped.
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebEvent {
    pub time: String,
    /// `browser` (extension) or `dns` (DNS filter).
    pub source: String,
    /// `blocked` or `reported` (report-only mode).
    pub action: String,
    /// The URL (browser) or name (DNS) that was checked.
    pub target: String,
    pub code: u8,
    pub list: String,
    pub category: String,
    pub threat: String,
    pub rule: String,
}

impl WebEvent {
    pub fn new(source: &str, blocked: bool, target: &str, verdict: &Verdict) -> Self {
        Self {
            time: crate::store::now(),
            source: source.into(),
            action: if blocked { "blocked" } else { "reported" }.into(),
            target: target.into(),
            code: verdict.code.number(),
            list: verdict.list.clone(),
            category: verdict.category.clone(),
            threat: verdict.threat.clone(),
            rule: verdict.rule.clone(),
        }
    }
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

/// Appends one event. Failures are ignored: logging must never break
/// browsing.
pub fn record(data_dir: &Path, event: &WebEvent) {
    let path = path(data_dir);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        trim(&path);
    }
    let Ok(line) = serde_json::to_string(event) else { return };
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{line}");
    }
}

fn trim(path: &Path) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    let lines: Vec<&str> = text.lines().collect();
    let keep = lines[lines.len() / 2..].join("\n") + "\n";
    let tmp = path.with_extension("jsonl.tmp");
    if std::fs::write(&tmp, keep).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// The newest `limit` events, newest first. Unreadable lines are skipped.
pub fn recent(data_dir: &Path, limit: usize) -> Vec<WebEvent> {
    let text = std::fs::read_to_string(path(data_dir)).unwrap_or_default();
    text.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::rules::{UserLists, WebRules};

    #[test]
    fn records_and_reads_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = WebRules::load(None, &UserLists::default()).unwrap();
        let v = rules.classify_domain("blocktest.phalanx.invalid");
        record(tmp.path(), &WebEvent::new("dns", true, "one.example", &v));
        record(tmp.path(), &WebEvent::new("browser", false, "two.example", &v));
        std::fs::OpenOptions::new().append(true).open(path(tmp.path())).unwrap().write_all(b"garbage\n").unwrap();
        let events = recent(tmp.path(), 10);
        assert_eq!(events.len(), 2);
        assert_eq!((events[0].target.as_str(), events[0].action.as_str()), ("two.example", "reported"));
        assert_eq!((events[1].code, events[1].threat.as_str()), (2, "Phalanx.TestBlock.Malware"));
    }
}
