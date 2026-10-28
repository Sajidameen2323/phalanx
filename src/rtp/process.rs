//! Running processes: listing them, finding each one's program file, and
//! stopping one.
//!
//! A process is identified by its id *and* creation time, so a process id
//! that Windows reuses for a new process is never mistaken for the old one
//! (and the wrong process is never stopped).

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessId {
    pub pid: u32,
    /// Creation time (FILETIME ticks).
    pub created: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub id: ProcessId,
    /// The executable's name as listed (e.g. `setup.exe`).
    pub name: String,
    /// Full path of the program file.
    pub image: PathBuf,
    /// Id of the process that started it. It may have exited, and Windows
    /// may have reused the id since: compare creation times before trusting it.
    pub parent: u32,
}

/// A process as Windows' process snapshot lists it, without opening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub pid: u32,
    pub parent: u32,
    /// The executable's name (e.g. `setup.exe`).
    pub name: String,
}

/// Every running process whose program file could be found. Protected and
/// system processes Windows does not let us query are left out.
pub fn running() -> std::io::Result<Vec<ProcessInfo>> {
    Ok(listed()?.iter().filter_map(open).collect())
}

/// Every running process (but this one and the kernel's), from a snapshot:
/// cheap, since no process is opened. See [`open`] for the rest.
pub fn listed() -> std::io::Result<Vec<Listed>> {
    imp::listed()
}

/// The creation time and program file of a listed process; `None` if it
/// exited or Windows denies access.
pub fn open(listed: &Listed) -> Option<ProcessInfo> {
    let (created, image) = identify(listed.pid)?;
    Some(ProcessInfo { id: ProcessId { pid: listed.pid, created }, name: listed.name.clone(), image, parent: listed.parent })
}

/// Stops `id`, waiting up to a few seconds for it to exit. Refuses if the
/// process id now belongs to a different process.
pub fn terminate(id: &ProcessId) -> Result<(), String> {
    imp::terminate(id)
}

/// The command line `id` was started with. `None` if it exited, its id now
/// belongs to another process, or Windows denies access.
pub fn command_line(id: &ProcessId) -> Option<String> {
    imp::command_line(id)
}

/// The creation time and program file of process `pid`, as [`running`]
/// reads them. `None` if it exited or Windows denies access.
pub fn identify(pid: u32) -> Option<(u64, PathBuf)> {
    imp::identify(pid)
}

/// Now, in the FILETIME ticks process creation times are in.
pub fn now_ticks() -> u64 {
    // From 1601, where FILETIME counts, to 1970, in 100 ns ticks.
    const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    let since_1970 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    UNIX_EPOCH_TICKS + (since_1970.as_nanos() / 100) as u64
}

/// Whether process listing is supported here.
pub const SUPPORTED: bool = cfg!(windows);

#[cfg(windows)]
mod imp {
    use super::{Listed, ProcessId};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
        WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: u32, access: u32) -> Option<Handle> {
        let h = unsafe { OpenProcess(access, 0, pid) };
        (!h.is_null()).then_some(Handle(h))
    }

    fn created(process: &Handle) -> Option<u64> {
        let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        // SAFETY: valid process handle and out-pointers.
        (unsafe { GetProcessTimes(process.0, &mut c, &mut e, &mut k, &mut u) } != 0)
            .then_some((c.dwHighDateTime as u64) << 32 | c.dwLowDateTime as u64)
    }

    fn image(process: &Handle) -> Option<PathBuf> {
        // Most paths fit the small buffer; the long one is for the rest.
        for size in [1024, 32 * 1024] {
            let mut buf = vec![0u16; size];
            let mut len = buf.len() as u32;
            // SAFETY: `buf` holds `len` UTF-16 units.
            let ok = unsafe { QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
            if ok != 0 && len > 0 {
                return Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize])));
            }
        }
        None
    }

    pub fn identify(pid: u32) -> Option<(u64, PathBuf)> {
        let process = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        Some((created(&process)?, image(&process)?))
    }

    pub fn listed() -> std::io::Result<Vec<Listed>> {
        let own = unsafe { GetCurrentProcessId() };
        // SAFETY: the snapshot handle is closed by `Handle`.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let snapshot = Handle(snapshot);
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut found = Vec::new();
        let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        while more {
            let pid = entry.th32ProcessID;
            // 0 is the idle process and 4 the kernel; neither has a program file.
            if pid > 4 && pid != own {
                let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                found.push(Listed { pid, parent: entry.th32ParentProcessID, name });
            }
            more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        Ok(found)
    }

    pub fn command_line(id: &ProcessId) -> Option<String> {
        let process = open(id.pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        if created(&process) != Some(id.created) {
            return None;
        }
        // The result is a UNICODE_STRING followed by the text it points to;
        // u64s keep the buffer aligned for it.
        let mut buf = vec![0u64; 512];
        loop {
            let size = (buf.len() * 8) as u32;
            let mut needed = 0u32;
            // SAFETY: `buf` holds `size` writable bytes; `needed` is an out-pointer.
            let status = unsafe {
                NtQueryInformationProcess(process.0, ProcessCommandLineInformation, buf.as_mut_ptr().cast(), size, &mut needed)
            };
            const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
            if status == STATUS_INFO_LENGTH_MISMATCH && needed > size && needed <= 1 << 20 {
                buf = vec![0u64; (needed as usize).div_ceil(8)];
                continue;
            }
            if status < 0 {
                return None;
            }
            // SAFETY: on success the buffer starts with a UNICODE_STRING whose
            // `Buffer` points inside `buf`, `Length` bytes long.
            let text = unsafe {
                let s = &*(buf.as_ptr() as *const UNICODE_STRING);
                if s.Buffer.is_null() {
                    return Some(String::new());
                }
                std::slice::from_raw_parts(s.Buffer, s.Length as usize / 2)
            };
            return Some(String::from_utf16_lossy(text));
        }
    }

    pub fn terminate(id: &ProcessId) -> Result<(), String> {
        let Some(process) = open(id.pid, PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION) else {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(5) {
                "Windows denied access; it runs as administrator or is protected".into()
            } else if e.raw_os_error() == Some(87) {
                "it had already exited".into()
            } else {
                e.to_string()
            });
        };
        if created(&process) != Some(id.created) {
            return Err("it had already exited".into());
        }
        // SAFETY: valid handle opened with PROCESS_TERMINATE.
        if unsafe { TerminateProcess(process.0, 1) } == 0 {
            let e = std::io::Error::last_os_error();
            // Windows refuses to stop a process that is already exiting.
            if unsafe { WaitForSingleObject(process.0, 1000) } == WAIT_OBJECT_0 {
                return Err("it had already exited".into());
            }
            return Err(e.to_string());
        }
        // Wait so the program file is unlocked for quarantine.
        if unsafe { WaitForSingleObject(process.0, 5000) } != WAIT_OBJECT_0 {
            return Err("it did not exit after being stopped".into());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Listed, ProcessId};

    pub fn listed() -> std::io::Result<Vec<Listed>> {
        Ok(Vec::new())
    }

    pub fn identify(_pid: u32) -> Option<(u64, std::path::PathBuf)> {
        None
    }

    pub fn command_line(_id: &ProcessId) -> Option<String> {
        None
    }

    pub fn terminate(_id: &ProcessId) -> Result<(), String> {
        Err("stopping programs is only supported on Windows".into())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn now_is_after_this_process_started() {
        let (created, _) = identify(std::process::id()).unwrap();
        let now = now_ticks();
        assert!(created < now, "{created} {now}");
        assert!(now - created < 60 * 60 * 10_000_000, "within the hour");
    }

    #[test]
    fn lists_a_started_process_and_stops_it() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let ping = std::path::Path::new(&root).join(r"System32\PING.EXE");
        let mut child = std::process::Command::new(&ping)
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let info = running()
            .unwrap()
            .into_iter()
            .find(|p| p.id.pid == child.id())
            .expect("the child is listed");
        assert!(info.image.to_string_lossy().to_lowercase().ends_with("ping.exe"), "{info:?}");
        assert_eq!(info.parent, std::process::id());
        let command = command_line(&info.id).unwrap();
        assert!(command.ends_with("-n 60 127.0.0.1"), "{command}");

        // A wrong creation time (pid reuse) is refused.
        let stale = ProcessId { pid: info.id.pid, created: info.id.created + 1 };
        assert!(terminate(&stale).is_err());
        terminate(&info.id).unwrap();
        assert!(child.wait().unwrap().code() == Some(1));
        assert!(!running().unwrap().iter().any(|p| p.id == info.id));
    }
}
