//! DLL side-loading: a validly signed program made to load a planted DLL.
//! Many current loaders ship a signed program (often Microsoft's or a
//! security vendor's) together with a malicious DLL named after one the
//! program imports, in a folder the user can write to; Windows looks next
//! to the program first, so the planted copy runs inside a trusted process.
//!
//! Flagged: an unsigned DLL, loaded from outside Windows' and Program Files'
//! folders (which only administrators can change), whose name is that of a
//! DLL in `System32`, by a program with a valid signature. Apps installed
//! per user ship plenty of unsigned DLLs of their own (`ffmpeg.dll` and the
//! like), but rarely an unsigned copy of a Windows DLL. Report-only, like
//! command-line rules; the DLL is also scanned.

use serde::{Deserialize, Serialize};
use super::cache::FileKey;
use super::{Ctx, Item, RtpEvent};
use crate::store::{ScanMeta, ScanStats, Store};
use crate::trust::{self, Trust};
use crate::{Category, Finding, Source};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

const ACTION: &str = "reported (side-loading checks do not stop programs yet)";

/// A signed program that loaded an unsigned copy of a Windows DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideLoadHit {
    pub pid: u32,
    /// The program's file name, e.g. `OneDriveUpdater.exe`.
    pub program: String,
    pub image: PathBuf,
    /// Who signed the program, when it could be read.
    pub signer: Option<String>,
    pub dll: PathBuf,
}

impl SideLoadHit {
    /// What happened, in plain words.
    pub fn headline(&self) -> String {
        let dll = self.dll.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let folder = self.dll.parent().map(|p| p.display().to_string()).unwrap_or_default();
        format!("{} loaded an unsigned {dll} from {folder}; Windows' own {dll} is in System32", self.program)
    }
}

/// An image load worth a closer look, for the checker thread.
pub(super) struct Candidate {
    pub pid: u32,
    pub image: PathBuf,
    pub dll: PathBuf,
}

/// The cheap checks, made for every image load on the program monitor's
/// thread: only paths are looked at.
pub(super) struct Filter {
    /// Folders only administrators can change, lowercase with a trailing `\`.
    protected: Vec<String>,
    system32: PathBuf,
    /// DLL names (lowercase) and whether `System32` has one.
    in_system32: HashMap<String, bool>,
}

impl Filter {
    pub fn new() -> Self {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let protected = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|v| std::env::var(v).ok());
        Self::with(PathBuf::from(&root).join("System32"), std::iter::once(root).chain(protected).collect())
    }

    fn with(system32: PathBuf, protected: Vec<String>) -> Self {
        let protected = protected.into_iter().map(|p| format!("{}\\", p.trim_end_matches('\\').to_lowercase())).collect();
        Self { protected, system32, in_system32: HashMap::new() }
    }

    /// Whether loading `dll` could be side-loading: a DLL outside the
    /// protected folders named after one in `System32`.
    pub fn candidate(&mut self, dll: &Path) -> bool {
        let Some(name) = dll.file_name().map(|n| n.to_string_lossy().to_lowercase()) else { return false };
        if !name.ends_with(".dll") {
            return false;
        }
        let lower = dll.to_string_lossy().to_lowercase();
        if self.protected.iter().any(|p| lower.starts_with(p.as_str())) {
            return false;
        }
        if self.in_system32.len() > 10_000 {
            self.in_system32.clear();
        }
        let system32 = &self.system32;
        *self.in_system32.entry(name).or_insert_with_key(|name| system32.join(name).is_file())
    }
}

/// Checks candidates' signatures, off the program monitor's thread (a check
/// reads the whole file), and reports what it finds. Each program and DLL
/// pair is judged once per run, until either file changes.
pub(super) fn run(ctx: &Ctx<'_>, store: &Store, rx: Receiver<Candidate>, urgent: &Sender<Item>) -> anyhow::Result<()> {
    let mut judged: HashSet<(FileKey, FileKey)> = HashSet::new();
    let mut signed: HashMap<FileKey, Trust> = HashMap::new();
    while !ctx.halted() {
        let candidate = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(candidate) => candidate,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let (Some(program_key), Some(dll_key)) = (FileKey::of(&candidate.image), FileKey::of(&candidate.dll)) else { continue };
        if !judged.insert((program_key.clone(), dll_key)) || ctx.is_excluded(&candidate.dll) {
            continue;
        }
        if judged.len() > 10_000 {
            judged.clear();
        }
        if trust::verify(&candidate.dll).is_signed() {
            continue;
        }
        if signed.len() > 1_000 {
            signed.clear();
        }
        let Trust::Signed { signer, .. } = signed.entry(program_key).or_insert_with(|| trust::verify(&candidate.image)).clone() else { continue };
        let program = candidate.image.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let hit = SideLoadHit { pid: candidate.pid, program, image: candidate.image, signer, dll: candidate.dll };
        if let Err(e) = record(ctx, store, &hit) {
            ctx.emit(RtpEvent::Error(format!("recording possible DLL side-loading: {e:#}")));
        }
        let _ = urgent.send(Item::File { path: hit.dll.clone(), announced: false });
        ctx.emit(RtpEvent::SideLoad(hit));
    }
    Ok(())
}

fn record(ctx: &Ctx<'_>, store: &Store, hit: &SideLoadHit) -> anyhow::Result<()> {
    let path = hit.dll.display().to_string();
    let signer = hit.signer.as_deref().map(|s| format!(", signed by {s}")).unwrap_or_default();
    let name = hit.dll.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let finding = Finding {
        threat: format!("SideLoad.{name}"),
        category: Category::Suspicious,
        source: Source::Heuristic,
        details: format!("{} · program: {} (pid {}{signer})", hit.headline(), hit.image.display(), hit.pid),
    };
    let scan_id = store.begin_scan(&ScanMeta { kind: "sideload", targets: &path, threads: 1, signatures: ctx.config.signatures.as_deref() })?;
    store.add_detection(scan_id, &path, "", &finding, ACTION)?;
    let stats = ScanStats { files_scanned: 1, detections: 1, ..Default::default() };
    store.finish_scan(scan_id, &stats, 0, false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_windows_dll_names_outside_protected_folders_are_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let system32 = tmp.path().join("System32");
        std::fs::create_dir_all(&system32).unwrap();
        std::fs::write(system32.join("version.dll"), "").unwrap();
        let mut filter = Filter::with(system32, vec![r"C:\Windows".into(), r"C:\Program Files\".into()]);

        assert!(filter.candidate(Path::new(r"C:\Users\u\AppData\Local\Temp\x\VERSION.DLL")));
        assert!(filter.candidate(Path::new(r"D:\tools\version.dll")));
        assert!(!filter.candidate(Path::new(r"C:\Users\u\AppData\Local\Discord\ffmpeg.dll")), "not a Windows DLL name");
        assert!(!filter.candidate(Path::new(r"C:\Program Files\App\version.dll")), "admin-only folder");
        assert!(!filter.candidate(Path::new(r"c:\windows\SysWOW64\version.dll")), "Windows' own folders");
        assert!(!filter.candidate(Path::new(r"C:\Users\u\version.exe")), "not a DLL");
        // A folder whose name starts like a protected one is not inside it.
        assert!(filter.candidate(Path::new(r"C:\Windows2\version.dll")));
    }

    #[test]
    fn the_headline_names_the_program_dll_and_folder() {
        let hit = SideLoadHit {
            pid: 7,
            program: "Updater.exe".into(),
            image: PathBuf::from(r"C:\Users\u\AppData\Local\Temp\x\Updater.exe"),
            signer: Some("Microsoft Corporation".into()),
            dll: PathBuf::from(r"C:\Users\u\AppData\Local\Temp\x\version.dll"),
        };
        assert_eq!(
            hit.headline(),
            r"Updater.exe loaded an unsigned version.dll from C:\Users\u\AppData\Local\Temp\x; Windows' own version.dll is in System32"
        );
    }
}
