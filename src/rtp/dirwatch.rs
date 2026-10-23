//! Change notifications for one folder tree.
//!
//! On Windows this is ReadDirectoryChangesW on a thread of its own, with a
//! 64 KiB buffer, so that the two failure modes a general-purpose watcher
//! hides are reported instead: a burst of changes larger than the buffer
//! (an archive extracted into Downloads) arrives as [`DirEvent::Overflow`],
//! and a folder that can no longer be watched (deleted, renamed, drive
//! removed) as [`DirEvent::Lost`]. Elsewhere the `notify` crate is used.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirEvent {
    /// A file or folder was created, or renamed or moved to this name.
    Arrived(PathBuf),
    Modified(PathBuf),
    /// Deleted, or renamed or moved away from this name.
    Removed(PathBuf),
    /// Changes were lost (too many at once); the folder needs a rescan.
    Overflow(PathBuf),
    /// The folder is no longer watched.
    Lost { folder: PathBuf, reason: String },
}

/// Watching stops when this is dropped.
pub struct DirWatch {
    #[cfg(windows)]
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(windows)]
    thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(not(windows))]
    _watcher: notify::RecommendedWatcher,
}

#[cfg(windows)]
impl Drop for DirWatch {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts watching `folder` and its subfolders.
pub fn watch(folder: &Path, tx: Sender<DirEvent>) -> std::io::Result<DirWatch> {
    imp::watch(folder, tx)
}

#[cfg(windows)]
mod imp {
    use super::{DirEvent, DirWatch};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::Sender;
    use std::sync::Arc;
    use std::{io, ptr};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_IO_INCOMPLETE, ERROR_NOTIFY_ENUM_DIR, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED,
        FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
        FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
        FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};

    /// The largest buffer ReadDirectoryChangesW accepts for network folders.
    const BUFFER_BYTES: usize = 64 * 1024;
    /// How often the thread checks whether it should stop.
    const POLL_MS: u32 = 250;

    /// Handles owned by the watch thread.
    struct Handles {
        dir: HANDLE,
        event: HANDLE,
    }
    // SAFETY: the handles are used only by the thread that owns them.
    unsafe impl Send for Handles {}
    impl Drop for Handles {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.dir);
                CloseHandle(self.event);
            }
        }
    }

    pub fn watch(folder: &Path, tx: Sender<DirEvent>) -> io::Result<DirWatch> {
        if !folder.is_dir() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "the folder does not exist"));
        }
        let wide: Vec<u16> = folder.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: plain FFI; both handles are owned by `Handles` from here on.
        let handles = unsafe {
            let dir = CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY,
                // Sharing delete lets the user rename or remove the folder.
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            );
            if dir == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let event = CreateEventW(ptr::null(), 1, 0, ptr::null());
            if event.is_null() {
                let e = io::Error::last_os_error();
                CloseHandle(dir);
                return Err(e);
            }
            Handles { dir, event }
        };
        // The first request is made before returning, so no change made after
        // `watch` returns can be missed: Windows queues changes from then on.
        let mut request = Request { handles, buffer: vec![0u32; BUFFER_BYTES / 4], overlapped: Box::default(), pending: false };
        request.issue()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let root = folder.to_path_buf();
        let thread = std::thread::Builder::new()
            .name("rtp-dirwatch".into())
            .spawn(move || run(request, &root, &thread_stop, &tx))?;
        Ok(DirWatch { stop, thread: Some(thread) })
    }

    /// One outstanding ReadDirectoryChangesW request and what it writes to.
    struct Request {
        handles: Handles,
        /// DWORD-aligned, as Windows requires.
        buffer: Vec<u32>,
        /// Boxed so it never moves while Windows holds a pointer to it.
        overlapped: Box<OVERLAPPED>,
        pending: bool,
    }
    // SAFETY: the OVERLAPPED's event handle is owned by `handles`; the
    // request is used by one thread at a time.
    unsafe impl Send for Request {}

    impl Request {
        fn issue(&mut self) -> io::Result<()> {
            let filter = FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_CREATION;
            *self.overlapped = OVERLAPPED { hEvent: self.handles.event, ..Default::default() };
            // SAFETY: the buffer and the boxed OVERLAPPED live until the
            // request completes or `Drop` cancels it and waits.
            let ok = unsafe {
                ResetEvent(self.handles.event);
                ReadDirectoryChangesW(
                    self.handles.dir,
                    self.buffer.as_mut_ptr().cast(),
                    BUFFER_BYTES as u32,
                    1,
                    filter,
                    ptr::null_mut(),
                    &mut *self.overlapped,
                    None,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            self.pending = true;
            Ok(())
        }

        /// Waits up to `ms` for the request. `None` on timeout; otherwise the
        /// bytes written (0 when Windows dropped changes) or the error.
        fn wait(&mut self, ms: u32) -> Option<io::Result<usize>> {
            let mut bytes = 0u32;
            // SAFETY: waits on the request issued by `issue`.
            if unsafe { GetOverlappedResultEx(self.handles.dir, &*self.overlapped, &mut bytes, ms, 0) } != 0 {
                self.pending = false;
                return Some(Ok(bytes as usize));
            }
            match unsafe { GetLastError() } {
                WAIT_TIMEOUT | ERROR_IO_INCOMPLETE => None,
                ERROR_NOTIFY_ENUM_DIR => {
                    self.pending = false;
                    Some(Ok(0))
                }
                code => {
                    self.pending = false;
                    Some(Err(io::Error::from_raw_os_error(code as i32)))
                }
            }
        }

        fn bytes(&self, len: usize) -> &[u8] {
            // SAFETY: the buffer is BUFFER_BYTES long; Windows wrote `len` of them.
            unsafe { std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), len.min(BUFFER_BYTES)) }
        }
    }

    impl Drop for Request {
        fn drop(&mut self) {
            if self.pending {
                let mut bytes = 0u32;
                // SAFETY: cancels our own request and waits until Windows no
                // longer uses the buffer.
                unsafe {
                    CancelIoEx(self.handles.dir, &*self.overlapped);
                    GetOverlappedResult(self.handles.dir, &*self.overlapped, &mut bytes, 1);
                }
            }
        }
    }

    fn run(mut request: Request, root: &Path, stop: &AtomicBool, tx: &Sender<DirEvent>) {
        let lost = |reason: String| {
            let _ = tx.send(DirEvent::Lost { folder: root.to_path_buf(), reason });
        };
        while !stop.load(Ordering::Relaxed) {
            let len = match request.wait(POLL_MS) {
                None => continue,
                Some(Ok(len)) => len,
                Some(Err(e)) => return lost(e.to_string()),
            };
            let events = if len == 0 {
                // The buffer overflowed: Windows dropped the changes.
                vec![DirEvent::Overflow(root.to_path_buf())]
            } else {
                parse(request.bytes(len), root)
            };
            // Ask for the next changes before handing these on.
            if let Err(e) = request.issue() {
                for event in events {
                    let _ = tx.send(event);
                }
                return lost(e.to_string());
            }
            for event in events {
                if tx.send(event).is_err() {
                    return;
                }
            }
        }
    }

    /// Decodes a buffer of FILE_NOTIFY_INFORMATION records.
    fn parse(bytes: &[u8], root: &Path) -> Vec<DirEvent> {
        let u32_at = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
        let mut events = Vec::new();
        let mut offset = 0usize;
        while let (Some(next), Some(action), Some(name_len)) = (u32_at(offset), u32_at(offset + 4), u32_at(offset + 8)) {
            let start = offset + 12;
            let Some(name) = bytes.get(start..start + name_len as usize) else { break };
            let name: Vec<u16> = name.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let path: PathBuf = root.join(std::ffi::OsString::from_wide(&name));
            match action {
                FILE_ACTION_ADDED | FILE_ACTION_RENAMED_NEW_NAME => events.push(DirEvent::Arrived(path)),
                FILE_ACTION_MODIFIED => events.push(DirEvent::Modified(path)),
                FILE_ACTION_REMOVED | FILE_ACTION_RENAMED_OLD_NAME => events.push(DirEvent::Removed(path)),
                _ => {}
            }
            if next == 0 {
                break;
            }
            offset += next as usize;
        }
        events
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{DirEvent, DirWatch};
    use notify::event::ModifyKind;
    use notify::{EventKind, RecursiveMode, Watcher};
    use std::path::Path;
    use std::sync::mpsc::Sender;

    pub fn watch(folder: &Path, tx: Sender<DirEvent>) -> std::io::Result<DirWatch> {
        let root = folder.to_path_buf();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                if event.need_rescan() {
                    let _ = tx.send(DirEvent::Overflow(root.clone()));
                }
                for path in event.paths {
                    let mapped = match event.kind {
                        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(_)) => DirEvent::Arrived(path),
                        EventKind::Modify(_) => DirEvent::Modified(path),
                        EventKind::Remove(_) => DirEvent::Removed(path),
                        _ => continue,
                    };
                    let _ = tx.send(mapped);
                }
            }
            Err(e) => {
                let _ = tx.send(DirEvent::Lost { folder: root.clone(), reason: e.to_string() });
            }
        })
        .map_err(std::io::Error::other)?;
        watcher.watch(folder, RecursiveMode::Recursive).map_err(std::io::Error::other)?;
        Ok(DirWatch { _watcher: watcher })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn collect(rx: &mpsc::Receiver<DirEvent>, until: impl Fn(&[DirEvent]) -> bool) -> Vec<DirEvent> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !until(&seen) {
            if let Ok(e) = rx.recv_timeout(Duration::from_millis(100)) {
                seen.push(e);
            }
        }
        seen
    }

    #[test]
    fn reports_arrivals_renames_and_removals_in_subfolders() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (tx, rx) = mpsc::channel();
        let _watch = watch(&root, tx).unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub").join("a.part"), "x").unwrap();
        std::fs::rename(root.join("sub").join("a.part"), root.join("sub").join("a.exe")).unwrap();
        std::fs::remove_file(root.join("sub").join("a.exe")).unwrap();
        let target = root.join("sub").join("a.exe");
        let seen = collect(&rx, |s| s.contains(&DirEvent::Removed(target.clone())));
        assert!(seen.contains(&DirEvent::Arrived(root.join("sub"))), "{seen:?}");
        assert!(seen.contains(&DirEvent::Arrived(target.clone())), "{seen:?}");
        assert!(seen.contains(&DirEvent::Removed(target)), "{seen:?}");
    }

    #[test]
    fn a_missing_folder_cannot_be_watched() {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel();
        assert!(watch(&tmp.path().join("missing"), tx).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_deleted_folder_is_reported_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = std::fs::canonicalize(tmp.path()).unwrap().join("w");
        std::fs::create_dir(&folder).unwrap();
        let (tx, rx) = mpsc::channel();
        let _watch = watch(&folder, tx).unwrap();
        std::fs::remove_dir(&folder).unwrap();
        let seen = collect(&rx, |s| s.iter().any(|e| matches!(e, DirEvent::Lost { .. })));
        assert!(seen.iter().any(|e| matches!(e, DirEvent::Lost { .. })), "{seen:?}");
    }
}
