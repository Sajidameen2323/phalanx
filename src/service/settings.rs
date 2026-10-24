//! Protection settings, kept by the service in `settings.json`, and the rule
//! for changing them: a change that weakens protection needs an
//! administrator; one that strengthens it does not.
//!
//! These are the machine-wide settings. Preferences that only affect how the
//! app looks or talks to its user (appearance, notifications, AI Inspect)
//! stay with the app. Field names match the app's settings file, so a
//! per-user `gui-settings.json` can be read as these settings when it is
//! migrated.

use crate::system::Performance;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const FILE: &str = "settings.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectionSettings {
    /// Real-time protection.
    pub watch_enabled: bool,
    pub watch_folders: Vec<PathBuf>,
    /// Scan every program as it starts.
    pub program_protection: bool,
    /// Stop a running program found to be malware.
    pub stop_running_threats: bool,
    /// Check command lines and the Run box (report only for now).
    pub command_rules: bool,
    /// Check drives as they appear.
    pub scan_new_drives: bool,
    /// Hold back non-urgent scans during full-screen games.
    pub defer_when_fullscreen: bool,
    // Scanning
    pub heuristics: bool,
    /// Ignore heuristic-only findings on validly signed files.
    pub trust_signed: bool,
    pub scan_archives: bool,
    pub max_size_mb: u64,
    pub exclusions: Vec<PathBuf>,
    pub performance: Performance,
    // Quarantine
    /// Quarantine malware, PUPs and hacking tools automatically.
    pub auto_quarantine: bool,
    /// Also quarantine suspicious (heuristic) findings.
    pub quarantine_suspicious: bool,
    // Signatures
    pub auto_update: bool,
    pub auto_update_hours: u32,
}

impl Default for ProtectionSettings {
    fn default() -> Self {
        Self {
            watch_enabled: true,
            watch_folders: Vec::new(),
            program_protection: true,
            stop_running_threats: true,
            command_rules: true,
            scan_new_drives: true,
            defer_when_fullscreen: true,
            heuristics: true,
            trust_signed: true,
            scan_archives: true,
            max_size_mb: 100,
            exclusions: Vec::new(),
            performance: Performance::default(),
            auto_quarantine: false,
            quarantine_suspicious: false,
            auto_update: true,
            auto_update_hours: 4,
        }
    }
}

impl ProtectionSettings {
    /// Reads `settings.json` in `dir`; defaults if there is none.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        match std::fs::read(dir.join(FILE)) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes `settings.json` in `dir`, through a temporary file so a crash
    /// never leaves half a file.
    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        let temporary = dir.join(format!("{FILE}.new"));
        std::fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&temporary, dir.join(FILE))?;
        Ok(())
    }

    /// How changing from `self` to `new` weakens protection, in plain words;
    /// empty when it does not (only strengthens, or changes nothing).
    pub fn weakened_by(&self, new: &Self) -> Vec<String> {
        let mut out = Vec::new();
        let mut off = |was: bool, now: bool, what: &str| {
            if was && !now {
                out.push(format!("turns off {what}"));
            }
        };
        off(self.watch_enabled, new.watch_enabled, "real-time protection");
        off(self.program_protection, new.program_protection, "scanning programs as they start");
        off(self.stop_running_threats, new.stop_running_threats, "stopping running malware");
        off(self.command_rules, new.command_rules, "command-line checks");
        off(self.scan_new_drives, new.scan_new_drives, "checking new drives");
        off(self.heuristics, new.heuristics, "PE heuristics");
        off(self.scan_archives, new.scan_archives, "scanning inside archives");
        off(self.auto_quarantine, new.auto_quarantine, "automatic quarantine");
        off(self.quarantine_suspicious, new.quarantine_suspicious, "quarantining suspicious files");
        off(self.auto_update, new.auto_update, "automatic signature updates");
        if !self.trust_signed && new.trust_signed {
            out.push("ignores heuristic findings on signed programs".into());
        }
        if !self.defer_when_fullscreen && new.defer_when_fullscreen {
            out.push("delays scans during games and presentations".into());
        }
        if new.max_size_mb < self.max_size_mb {
            out.push(format!("skips files over {} MiB instead of {} MiB", new.max_size_mb, self.max_size_mb));
        }
        if new.auto_update && self.auto_update && new.auto_update_hours > self.auto_update_hours {
            out.push(format!("checks for signatures every {} hours instead of {}", new.auto_update_hours, self.auto_update_hours));
        }
        for folder in self.watch_folders.iter().filter(|f| !contains(&new.watch_folders, f)) {
            out.push(format!("stops watching {}", folder.display()));
        }
        for path in new.exclusions.iter().filter(|p| !contains(&self.exclusions, p)) {
            out.push(format!("never scans {}", path.display()));
        }
        out
    }
}

/// Windows paths compare without regard to case or a trailing separator.
fn contains(list: &[PathBuf], path: &Path) -> bool {
    let norm = |p: &Path| p.display().to_string().replace('/', "\\").trim_end_matches('\\').to_lowercase();
    list.iter().any(|p| norm(p) == norm(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weakening_is_told_apart_from_strengthening() {
        let base = ProtectionSettings { watch_folders: vec![r"C:\Users\me\Downloads".into()], ..Default::default() };
        assert!(base.weakened_by(&base).is_empty());

        // Each of these weakens, and says how.
        let cases: Vec<(ProtectionSettings, &str)> = vec![
            (ProtectionSettings { watch_enabled: false, ..base.clone() }, "turns off real-time protection"),
            (ProtectionSettings { command_rules: false, ..base.clone() }, "turns off command-line checks"),
            (ProtectionSettings { scan_archives: false, ..base.clone() }, "turns off scanning inside archives"),
            (ProtectionSettings { max_size_mb: 10, ..base.clone() }, "skips files over 10 MiB instead of 100 MiB"),
            (ProtectionSettings { auto_update_hours: 48, ..base.clone() }, "checks for signatures every 48 hours instead of 4"),
            (ProtectionSettings { watch_folders: vec![], ..base.clone() }, r"stops watching C:\Users\me\Downloads"),
            (ProtectionSettings { exclusions: vec![r"C:\Temp".into()], ..base.clone() }, r"never scans C:\Temp"),
        ];
        for (new, why) in cases {
            assert_eq!(base.weakened_by(&new), [why]);
        }
        let trusting = ProtectionSettings { trust_signed: false, ..base.clone() };
        assert_eq!(trusting.weakened_by(&base), ["ignores heuristic findings on signed programs"]);

        // Strengthening asks nothing.
        let stronger = ProtectionSettings {
            auto_quarantine: true,
            max_size_mb: 500,
            watch_folders: vec![r"c:\users\me\downloads\".into(), r"D:\Shared".into()],
            auto_update_hours: 1,
            ..base.clone()
        };
        assert!(base.weakened_by(&stronger).is_empty(), "{:?}", base.weakened_by(&stronger));
        // Removing an exclusion strengthens.
        let excluded = ProtectionSettings { exclusions: vec![r"C:\Temp".into()], ..base.clone() };
        assert!(excluded.weakened_by(&base).is_empty());
    }

    #[test]
    fn saved_settings_load_back_and_the_apps_file_reads_as_them() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(ProtectionSettings::load(tmp.path()).unwrap(), ProtectionSettings::default());
        let changed = ProtectionSettings { max_size_mb: 250, exclusions: vec![r"D:\VMs".into()], ..Default::default() };
        changed.save(tmp.path()).unwrap();
        assert_eq!(ProtectionSettings::load(tmp.path()).unwrap(), changed);

        // The app's own settings file: its other preferences are ignored.
        let app = r#"{"appearance":"Dark","watch_enabled":false,"max_size_mb":50,"ai_enabled":true,"performance":"fast"}"#;
        let read: ProtectionSettings = serde_json::from_str(app).unwrap();
        assert_eq!((read.watch_enabled, read.max_size_mb, read.performance), (false, 50, Performance::Fast));
        assert!(read.program_protection, "missing fields take their defaults");
    }
}
