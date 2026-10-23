//! Drives that appear while protection runs: a mounted disk image (an ISO
//! or VHD opened from a download) or a USB drive.
//!
//! Disk images are a common way to deliver malware: the files inside carry
//! no Mark of the Web, so Windows' download warnings stay quiet, and they
//! never land in a watched folder. When a drive appears, the files near its
//! top (where the program to open is) are scanned in the urgent lane.

use super::{Ctx, Item, RtpEvent};
use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

/// How often the list of drives is read.
const POLL: Duration = Duration::from_secs(2);
/// Folder levels below the drive's root that are scanned.
const DEPTH: usize = 2;
/// Most files scanned on one new drive.
const MAX_FILES: usize = 500;

pub(super) fn run(ctx: &Ctx<'_>, urgent: &Sender<Item>) -> Result<()> {
    let mut known = roots();
    while !ctx.halted() {
        ctx.pause(POLL);
        let now = roots();
        for root in now.difference(&known) {
            let files: Vec<PathBuf> = top_files(root, DEPTH, MAX_FILES).into_iter().filter(|p| !ctx.is_excluded(p)).collect();
            ctx.emit(RtpEvent::DriveAdded { root: root.clone(), files: files.len() });
            for path in files {
                urgent.send(Item::File { path, announced: false }).map_err(|_| anyhow!("the scan lane stopped"))?;
            }
        }
        known = now;
    }
    Ok(())
}

/// Files at most `depth` folders below `root`, up to `max`, top level first.
pub(super) fn top_files(root: &Path, depth: usize, max: usize) -> Vec<PathBuf> {
    // Bounded, so a drive with a huge tree near its top is not listed whole.
    let mut found: Vec<(usize, PathBuf)> = walkdir::WalkDir::new(root)
        .max_depth(depth + 1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .take(max.saturating_mul(20))
        .map(|e| (e.depth(), e.into_path()))
        .collect();
    found.sort_by_key(|(depth, _)| *depth);
    found.into_iter().take(max).map(|(_, path)| path).collect()
}

/// Roots of the local drives (removable, fixed, CD/DVD, RAM disks); network
/// drives are left out.
#[cfg(windows)]
fn roots() -> BTreeSet<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const REMOVABLE: u32 = 2;
    const FIXED: u32 = 3;
    const CDROM: u32 = 5;
    const RAMDISK: u32 = 6;
    // SAFETY: no arguments; returns a bit mask of drive letters.
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i) as char))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain([0]).collect();
            // SAFETY: `wide` is NUL-terminated.
            matches!(unsafe { GetDriveTypeW(wide.as_ptr()) }, REMOVABLE | FIXED | CDROM | RAMDISK)
        })
        .map(PathBuf::from)
        .collect()
}

#[cfg(not(windows))]
fn roots() -> BTreeSet<PathBuf> {
    BTreeSet::new()
}
