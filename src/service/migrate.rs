//! Bringing a user's data from before the service (`%LOCALAPPDATA%\
//! threat-scanner`) into the service's folder, once.
//!
//! Only an administrator may ask for it: it imports settings, and settings
//! can weaken protection. What comes over: the protection settings from the
//! app's settings file, the history and quarantine (records and files), the
//! web-protection lists and the saved Windows DNS settings, and the
//! downloaded signatures. The old folder is left as it was.

use super::data::{set_permissions, QUARANTINE};
use super::settings::ProtectionSettings;
use crate::scan;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Written when a migration has run; its presence stops another.
pub const MARKER: &str = "migrated.json";
/// The abuse.ch key is a secret: administrators only, unlike the rest.
const SECRET_FILES: &[&str] = &["signatures/abuse-ch-key"];
const SECRET_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Migrated {
    pub from: PathBuf,
    pub at: String,
    pub settings: bool,
    pub scans: i64,
    /// Quarantine records; `files` is the stored copies.
    pub quarantined: i64,
    pub files: usize,
    /// Other files copied: web lists, DNS backup, signatures.
    pub copied: usize,
}

/// Migrates `from` into the service's folder `to`.
pub fn migrate(from: &Path, to: &Path) -> Result<Migrated> {
    if let Ok(bytes) = std::fs::read(to.join(MARKER)) {
        let done: Migrated = serde_json::from_slice(&bytes)?;
        bail!("already migrated from {} on {}", done.from.display(), done.at);
    }
    if !from.is_dir() {
        bail!("{} is not a folder", from.display());
    }
    if std::fs::canonicalize(from).ok() == std::fs::canonicalize(to).ok() {
        bail!("that is the service's own folder");
    }
    std::fs::create_dir_all(to.join(QUARANTINE))?;

    let mut settings = false;
    if let Ok(bytes) = std::fs::read(from.join("gui-settings.json")) {
        let read: ProtectionSettings = serde_json::from_slice(&bytes).context("reading gui-settings.json")?;
        read.save(to)?;
        settings = true;
    }

    let (mut scans, mut quarantined) = (0, 0);
    let history = from.join("history.sqlite");
    if history.is_file() {
        (scans, quarantined) = scan::open_store(to)?.import(&history).context("importing the history")?;
    }

    let mut files = 0;
    if let Ok(entries) = std::fs::read_dir(from.join(QUARANTINE)) {
        for entry in entries.flatten() {
            let target = to.join(QUARANTINE).join(entry.file_name());
            if entry.path().is_file() && !target.exists() {
                std::fs::copy(entry.path(), &target).with_context(|| format!("copying {}", entry.path().display()))?;
                files += 1;
            }
        }
    }

    let mut copied = 0;
    for name in ["web-protection.json", "web", "signatures"] {
        copied += copy_tree(&from.join(name), &to.join(name))?;
    }
    for secret in SECRET_FILES {
        let path = to.join(secret);
        if path.is_file() {
            set_permissions(&path, SECRET_SDDL)?;
        }
    }

    let done = Migrated { from: from.to_path_buf(), at: crate::store::now(), settings, scans, quarantined, files, copied };
    std::fs::write(to.join(MARKER), serde_json::to_vec_pretty(&done)?)?;
    Ok(done)
}

/// Copies a file, or a folder and everything in it, without overwriting.
/// Returns the files copied.
fn copy_tree(from: &Path, to: &Path) -> Result<usize> {
    if from.is_file() {
        if to.exists() {
            return Ok(0);
        }
        std::fs::copy(from, to).with_context(|| format!("copying {}", from.display()))?;
        return Ok(1);
    }
    if !from.is_dir() {
        return Ok(0);
    }
    std::fs::create_dir_all(to)?;
    let mut copied = 0;
    for entry in std::fs::read_dir(from)?.flatten() {
        copied += copy_tree(&entry.path(), &to.join(entry.file_name()))?;
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ScanMeta;

    #[test]
    fn a_users_data_comes_over_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (old, new) = (tmp.path().join("threat-scanner"), tmp.path().join("Phalanx"));
        std::fs::create_dir_all(old.join(QUARANTINE)).unwrap();
        std::fs::create_dir_all(old.join("web")).unwrap();
        std::fs::create_dir_all(old.join("signatures")).unwrap();
        std::fs::write(old.join("gui-settings.json"), r#"{"appearance":"Dark","max_size_mb":42,"exclusions":["D:\\VMs"]}"#).unwrap();
        std::fs::write(old.join("web-protection.json"), "{}").unwrap();
        std::fs::write(old.join("web").join("windows-dns-backup.json"), "[]").unwrap();
        std::fs::write(old.join("signatures").join("abuse-ch-key"), "secret").unwrap();
        std::fs::write(old.join(QUARANTINE).join("x.qtn"), "TSQ1").unwrap();
        {
            let store = scan::open_store(&old).unwrap();
            let id = store.begin_scan(&ScanMeta { kind: "quick", targets: "C:\\", threads: 2, signatures: None }).unwrap();
            store.finish_scan(id, &Default::default(), 5, false).unwrap();
        }

        let done = migrate(&old, &new).unwrap();
        assert!(done.settings);
        assert_eq!((done.scans, done.quarantined, done.files, done.copied), (1, 0, 1, 3));
        let settings = ProtectionSettings::load(&new).unwrap();
        assert_eq!((settings.max_size_mb, settings.exclusions.clone()), (42, vec![PathBuf::from(r"D:\VMs")]));
        let scans = scan::open_store(&new).unwrap().recent_scans(10, None).unwrap();
        assert_eq!((scans.len(), scans[0].kind.as_str(), scans[0].threads), (1, "quick", 2));
        assert!(new.join("web").join("windows-dns-backup.json").is_file());
        assert!(new.join(QUARANTINE).join("x.qtn").is_file());
        #[cfg(windows)]
        assert!(!super::super::data::permissions(&new.join("signatures/abuse-ch-key")).unwrap().contains("BU"), "the key is not readable by users");
        assert!(old.join("history.sqlite").is_file(), "the old folder is left as it was");

        // Once only.
        let again = migrate(&old, &new).unwrap_err().to_string();
        assert!(again.starts_with("already migrated from"), "{again}");
        #[cfg(windows)]
        super::super::data::set_permissions(&new.join("signatures/abuse-ch-key"), "D:(A;;FA;;;WD)").unwrap();
    }

    #[test]
    fn nothing_is_taken_from_a_missing_folder_or_into_existing_history() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(migrate(&tmp.path().join("missing"), &tmp.path().join("to")).is_err());
        let (old, new) = (tmp.path().join("old"), tmp.path().join("new"));
        for dir in [&old, &new] {
            let store = scan::open_store(dir).unwrap();
            store.begin_scan(&ScanMeta { kind: "quick", targets: "C:\\", threads: 1, signatures: None }).unwrap();
        }
        let err = format!("{:#}", migrate(&old, &new).unwrap_err());
        assert!(err.contains("not empty"), "{err}");
    }
}
