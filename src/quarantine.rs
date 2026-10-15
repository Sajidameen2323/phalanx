//! Reversible quarantine.
//!
//! The file is copied into the quarantine folder in an encoded form (so it can
//! no longer run, and other scanners don't re-detect it), recorded in the
//! database, and only then removed from its original location.

use crate::store::{now, QuarantineRow, Store};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"TSQ1";
const KEY: u8 = 0xA5;

pub struct Quarantine<'a> {
    dir: PathBuf,
    store: &'a Store,
}

impl<'a> Quarantine<'a> {
    pub fn new(dir: PathBuf, store: &'a Store) -> Result<Self> {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir, store })
    }

    fn stored_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.qtn"))
    }

    /// Moves `path` (whose bytes are `data`) into quarantine and returns its id.
    pub fn isolate(&self, path: &Path, data: &[u8], sha256: &str, threat: &str) -> Result<String> {
        let id = format!(
            "{}-{}",
            chrono::Local::now().format("%Y%m%d%H%M%S%3f"),
            &sha256[..12]
        );
        let stored = self.stored_path(&id);
        let mut encoded = Vec::with_capacity(MAGIC.len() + data.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend(data.iter().map(|b| b ^ KEY));
        write_new(&stored, &encoded)?;

        let row = QuarantineRow {
            id: id.clone(),
            original_path: path.display().to_string(),
            quarantined_at: now(),
            sha256: sha256.to_string(),
            threat: threat.to_string(),
            size: data.len() as i64,
            restored_at: None,
        };
        if let Err(e) = self.store.add_quarantine(&row) {
            let _ = fs::remove_file(&stored);
            return Err(e);
        }
        if let Err(e) = fs::remove_file(path) {
            // Couldn't remove the original (in use, permissions): undo, keep it where it was.
            let _ = self.store.remove_quarantine(&id);
            let _ = fs::remove_file(&stored);
            return Err(e).with_context(|| format!("removing {}", path.display()));
        }
        Ok(id)
    }

    /// Writes the original bytes back. Refuses to overwrite unless `force`.
    pub fn restore(&self, id: &str, force: bool) -> Result<PathBuf> {
        let Some(row) = self.store.quarantine_item(id)? else {
            bail!("no quarantine item `{id}`");
        };
        if row.restored_at.is_some() {
            bail!("`{id}` was already restored");
        }
        let encoded = fs::read(self.stored_path(id))
            .with_context(|| format!("reading quarantined copy of `{id}`"))?;
        let Some(body) = encoded.strip_prefix(MAGIC) else {
            bail!("quarantined copy of `{id}` is not in the expected format");
        };
        let data: Vec<u8> = body.iter().map(|b| b ^ KEY).collect();
        if hex::encode(Sha256::digest(&data)) != row.sha256 {
            bail!("quarantined copy of `{id}` is corrupted (SHA-256 mismatch)");
        }

        let target = PathBuf::from(&row.original_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if force {
            fs::write(&target, &data).map_err(anyhow::Error::from)
        } else {
            write_new(&target, &data)
        }
        .with_context(|| format!("restoring to {}", target.display()))?;
        self.store.mark_restored(id)?;
        let _ = fs::remove_file(self.stored_path(id));
        Ok(target)
    }

    /// Permanently deletes a quarantined item.
    pub fn delete(&self, id: &str) -> Result<()> {
        if self.store.quarantine_item(id)?.is_none() {
            bail!("no quarantine item `{id}`");
        }
        let stored = self.stored_path(id);
        if stored.exists() {
            fs::remove_file(&stored).with_context(|| format!("deleting {}", stored.display()))?;
        }
        self.store.remove_quarantine(id)
    }
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {} (does it already exist?)", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolate_then_restore_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("db.sqlite")).unwrap();
        let q = Quarantine::new(tmp.path().join("q"), &store).unwrap();

        let victim = tmp.path().join("sample.bin");
        let data = b"pretend this is malware".to_vec();
        fs::write(&victim, &data).unwrap();
        let sha = hex::encode(Sha256::digest(&data));

        let id = q.isolate(&victim, &data, &sha, "Test.Threat").unwrap();
        assert!(!victim.exists());
        let stored = fs::read(q.stored_path(&id)).unwrap();
        assert!(!stored.windows(data.len()).any(|w| w == data.as_slice()));
        assert_eq!(store.quarantine_items(false).unwrap().len(), 1);

        assert_eq!(q.restore(&id, false).unwrap(), victim);
        assert_eq!(fs::read(&victim).unwrap(), data);
        assert!(store.quarantine_items(false).unwrap().is_empty());
        assert!(q.restore(&id, false).is_err(), "double restore must fail");
    }

    #[test]
    fn restore_refuses_to_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("db.sqlite")).unwrap();
        let q = Quarantine::new(tmp.path().join("q"), &store).unwrap();
        let victim = tmp.path().join("a.bin");
        fs::write(&victim, b"bad").unwrap();
        let sha = hex::encode(Sha256::digest(b"bad"));
        let id = q.isolate(&victim, b"bad", &sha, "T").unwrap();

        fs::write(&victim, b"new file in the same place").unwrap();
        assert!(q.restore(&id, false).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"new file in the same place");
        q.restore(&id, true).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"bad");
    }
}
