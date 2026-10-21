//! Disposition cache: the verdict for each file version already scanned, so
//! a file that is opened, touched or launched again is not read again.
//!
//! A version is the path plus size, modification and creation times; any
//! write changes the modification time, so a changed file misses the cache.
//! The cache lives as long as one real-time protection session, and the
//! session is restarted whenever signatures or settings change, so verdicts
//! never outlive the signatures that produced them.

use crate::scan::FileReport;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

/// Entries kept before the cache is emptied and starts over.
const MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileKey {
    /// Lower-cased on Windows, where paths are case-insensitive.
    path: String,
    size: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
}

impl FileKey {
    /// `None` if the file is gone or not a regular file.
    pub fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok().filter(|m| m.is_file())?;
        let text = path.display().to_string();
        Some(Self {
            path: if cfg!(windows) { text.to_lowercase() } else { text },
            size: meta.len(),
            modified: meta.modified().ok(),
            created: meta.created().ok(),
        })
    }
}

#[derive(Debug, Clone)]
pub enum Disposition {
    /// Scanned with no detection, or only heuristics on a signed file.
    Clean,
    Threat(Arc<FileReport>),
}

#[derive(Default)]
pub struct DispositionCache {
    entries: HashMap<FileKey, Disposition>,
}

impl DispositionCache {
    pub fn get(&mut self, key: &FileKey) -> Option<Disposition> {
        self.entries.get(key).cloned()
    }

    pub fn insert(&mut self, key: FileKey, disposition: Disposition) {
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, disposition);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_file_misses_the_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a.txt");
        std::fs::write(&file, "one").unwrap();
        let mut cache = DispositionCache::default();
        let key = FileKey::of(&file).unwrap();
        cache.insert(key.clone(), Disposition::Clean);
        assert!(matches!(cache.get(&FileKey::of(&file).unwrap()), Some(Disposition::Clean)));

        std::fs::write(&file, "two, longer").unwrap();
        assert!(cache.get(&FileKey::of(&file).unwrap()).is_none());
        assert!(FileKey::of(tmp.path()).is_none(), "folders have no key");
    }
}
