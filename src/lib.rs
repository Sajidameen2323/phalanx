//! On-demand threat scanner: SHA-256 blocklist, YARA rules and PE heuristics,
//! with a local SQLite history and reversible quarantine.

pub mod ai;
pub mod audit;
pub mod engine;
pub mod heuristics;
pub mod posture;
pub mod quarantine;
pub mod risk;
pub mod scan;
#[cfg(windows)]
mod shortcut;
pub mod store;
pub mod system;
pub mod update;
pub mod watch;
pub mod web;

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

/// Threat classes, ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Suspicious,
    Pup,
    HackTool,
    Malware,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Suspicious => "suspicious",
            Category::Pup => "pup",
            Category::HackTool => "hacktool",
            Category::Malware => "malware",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Category {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "suspicious" => Ok(Category::Suspicious),
            "pup" => Ok(Category::Pup),
            "hacktool" => Ok(Category::HackTool),
            "malware" => Ok(Category::Malware),
            other => Err(format!("unknown category `{other}`")),
        }
    }
}

/// Which detection layer produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Hash,
    Yara,
    Heuristic,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Hash => "hash",
            Source::Yara => "yara",
            Source::Heuristic => "heuristic",
        }
    }
}

/// One detection on one file.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub threat: String,
    pub category: Category,
    pub source: Source,
    /// Rule name, matched hash, or heuristic indicators.
    pub details: String,
}
