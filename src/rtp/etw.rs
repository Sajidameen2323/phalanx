//! Process and image-load events from ETW, Windows' event tracing: a
//! real-time session on the Microsoft-Windows-Kernel-Process provider.
//!
//! Events arrive within about 100 ms of a process starting (the session's
//! flush timer), so programs that run only briefly are still seen, with their
//! exact parent. Starting a session needs administrator rights; without them
//! [`start`] fails and the program monitor lists processes instead.
//!
//! Event fields are read by name through TDH, so a field that a later Windows
//! version adds or moves does not matter. Paths arrive as NT paths
//! (`\Device\HarddiskVolume3\…`) and are turned into drive paths.

use super::process::{ProcessId, ProcessInfo};
use std::path::PathBuf;
use std::sync::mpsc::Sender;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A process started.
    Started(ProcessInfo),
    /// A process exited.
    Stopped(ProcessId),
    /// A process loaded an image: a DLL, or its own program file.
    ImageLoaded { pid: u32, image: PathBuf },
}

/// A running session. Dropping it stops the session; the sender passed to
/// [`start`] is dropped once the last event is delivered, so a receiver sees
/// the channel close. It also closes if Windows ends the session.
pub struct Session(#[allow(dead_code)] imp::Session);

/// Starts a session named `name`, replacing one of that name left behind (by
/// a crash, say). Image loads are reported only when `images` is set: they
/// are by far the most frequent event.
pub fn start(name: &str, images: bool, tx: Sender<Event>) -> std::io::Result<Session> {
    imp::Session::start(name, images, tx).map(Session)
}

/// The session name for this program: one per program file, so the service
/// and an elevated `phalanx-cli watch` do not replace each other's session.
pub fn session_name() -> String {
    let stem = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "phalanx".into());
    format!("Phalanx {stem}")
}

/// Turns an NT path into a drive or UNC path. `devices` maps device names
/// (`\Device\HarddiskVolume3`, `\SystemRoot`) to what they stand for
/// (`C:`, `C:\Windows`).
fn dos_path(nt: &str, devices: &[(String, String)]) -> Option<PathBuf> {
    if let Some(rest) = nt.strip_prefix(r"\??\") {
        return Some(PathBuf::from(rest));
    }
    let bytes = nt.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return Some(PathBuf::from(nt));
    }
    let after = |prefix: &str| {
        let head = nt.get(..prefix.len())?;
        let rest = &nt[prefix.len()..];
        (head.eq_ignore_ascii_case(prefix) && rest.starts_with('\\')).then_some(rest)
    };
    if let Some(rest) = after(r"\Device\Mup") {
        return Some(PathBuf::from(format!(r"\{rest}")));
    }
    devices.iter().find_map(|(device, target)| after(device).map(|rest| PathBuf::from(format!("{target}{rest}"))))
}

#[cfg(windows)]
mod imp {
    use super::{dos_path, Event, ProcessId, ProcessInfo};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::mpsc::Sender;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use std::{io, ptr};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, TdhGetProperty,
        TdhGetPropertySize, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
        EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
        PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR,
        TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
    };

    /// Microsoft-Windows-Kernel-Process.
    const PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
    const KEYWORD_PROCESS: u64 = 0x10;
    const KEYWORD_IMAGE: u64 = 0x40;
    const PROCESS_START: u16 = 1;
    const PROCESS_STOP: u16 = 2;
    const IMAGE_LOAD: u16 = 5;
    /// `FlushTimer` is in milliseconds (Windows 8 and later).
    const EVENT_TRACE_USE_MS_FLUSH_TIMER: u32 = 0x10;
    const FLUSH_MS: u32 = 100;
    const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;
    /// How often the drive-letter map may be read again for a path it lacks.
    const DEVICE_REFRESH: Duration = Duration::from_secs(1);

    /// `EVENT_TRACE_PROPERTIES` followed by the session name, as Windows wants it.
    #[repr(C)]
    struct Properties {
        props: EVENT_TRACE_PROPERTIES,
        name: [u16; 256],
    }

    impl Properties {
        fn new(name: &[u16]) -> Box<Self> {
            let mut p = Box::new(Properties { props: EVENT_TRACE_PROPERTIES::default(), name: [0; 256] });
            let len = name.len().min(255);
            p.name[..len].copy_from_slice(&name[..len]);
            p.props.Wnode.BufferSize = size_of::<Properties>() as u32;
            p.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            // Timestamps from the performance counter.
            p.props.Wnode.ClientContext = 1;
            p.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_USE_MS_FLUSH_TIMER;
            p.props.FlushTimer = FLUSH_MS;
            p.props.BufferSize = 64;
            p.props.MinimumBuffers = 4;
            p.props.MaximumBuffers = 64;
            p.props.LoggerNameOffset = std::mem::offset_of!(Properties, name) as u32;
            p
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn os_error(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    /// Stops the session named `name`, if one runs.
    fn stop_named(name: &[u16]) {
        let mut p = Properties::new(name);
        // SAFETY: `p` is a properly sized properties block; a missing session is an error we ignore.
        unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, name.as_ptr(), &mut p.props, EVENT_TRACE_CONTROL_STOP) };
    }

    /// What the event callback works with; owned by the consumer thread.
    struct Context {
        tx: Sender<Event>,
        devices: Vec<(String, String)>,
        refreshed: Instant,
        names: Names,
    }

    /// Event field names, as TDH wants them.
    struct Names {
        process_id: Vec<u16>,
        parent_id: Vec<u16>,
        create_time: Vec<u16>,
        image_name: Vec<u16>,
    }

    pub struct Session {
        name: Vec<u16>,
        control: CONTROLTRACE_HANDLE,
        trace: PROCESSTRACE_HANDLE,
        thread: Option<JoinHandle<()>>,
    }

    /// The context pointer, handed to the consumer thread.
    struct ContextPtr(*mut Context);
    // SAFETY: only the consumer thread uses the context, and it frees it.
    unsafe impl Send for ContextPtr {}

    impl Session {
        pub fn start(name: &str, images: bool, tx: Sender<Event>) -> io::Result<Self> {
            let name = wide(name);
            stop_named(&name);
            let mut p = Properties::new(&name);
            let mut control = CONTROLTRACE_HANDLE::default();
            // SAFETY: `p` holds the properties and the name at `LoggerNameOffset`.
            let status = unsafe { StartTraceW(&mut control, name.as_ptr(), &mut p.props) };
            if status != ERROR_SUCCESS {
                return Err(os_error(status));
            }
            let keywords = KEYWORD_PROCESS | if images { KEYWORD_IMAGE } else { 0 };
            // SAFETY: `control` is the session just started.
            let status = unsafe {
                EnableTraceEx2(
                    control,
                    &PROVIDER,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION as u8,
                    keywords,
                    0,
                    0,
                    ptr::null(),
                )
            };
            if status != ERROR_SUCCESS {
                stop_named(&name);
                return Err(os_error(status));
            }
            let context = Box::into_raw(Box::new(Context {
                tx,
                devices: devices(),
                refreshed: Instant::now(),
                names: Names {
                    process_id: wide("ProcessID"),
                    parent_id: wide("ParentProcessID"),
                    create_time: wide("CreateTime"),
                    image_name: wide("ImageName"),
                },
            }));
            let mut logfile = EVENT_TRACE_LOGFILEW { LoggerName: name.as_ptr() as *mut u16, Context: context.cast(), ..Default::default() };
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(on_event);
            // SAFETY: `logfile` names a real-time session and a valid callback.
            let trace = unsafe { OpenTraceW(&mut logfile) };
            if trace.Value == INVALID_PROCESSTRACE_HANDLE {
                let e = io::Error::last_os_error();
                stop_named(&name);
                // SAFETY: never handed to Windows for delivery.
                drop(unsafe { Box::from_raw(context) });
                return Err(e);
            }
            let ctx = ContextPtr(context);
            let thread = std::thread::Builder::new().name("rtp-etw".into()).spawn(move || {
                let ctx = ctx;
                // SAFETY: returns once the session stops or the trace is closed;
                // no callback runs after that, so the context can be freed.
                unsafe { ProcessTrace(&trace, 1, ptr::null(), ptr::null()) };
                drop(unsafe { Box::from_raw(ctx.0) });
            });
            match thread {
                Ok(thread) => Ok(Session { name, control, trace, thread: Some(thread) }),
                Err(e) => {
                    // The closure (and the context with it) was dropped without
                    // running; only the session is left to stop.
                    stop_named(&name);
                    unsafe { CloseTrace(trace) };
                    Err(e)
                }
            }
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // A session that already ended (replaced, or stopped by someone
            // else) is not stopped again: its handle may now name another.
            if self.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                let mut p = Properties::new(&self.name);
                // SAFETY: the handle from `start`; stopping makes `ProcessTrace` return.
                unsafe { ControlTraceW(self.control, ptr::null(), &mut p.props, EVENT_TRACE_CONTROL_STOP) };
            }
            // SAFETY: the trace handle from `start`, closed once.
            unsafe { CloseTrace(self.trace) };
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Drive letters and the system root, by device name.
    fn devices() -> Vec<(String, String)> {
        let mut found = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let mut buf = [0u16; 1024];
            // SAFETY: `buf` holds `buf.len()` UTF-16 units.
            let len = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
            if len == 0 {
                continue;
            }
            // A list of strings; the first is the current target.
            let end = buf[..len].iter().position(|&c| c == 0).unwrap_or(len);
            found.push((String::from_utf16_lossy(&buf[..end]), drive));
        }
        if let Ok(root) = std::env::var("SystemRoot") {
            found.push((r"\SystemRoot".into(), root));
        }
        found
    }

    unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
        // A panic must not cross into Windows; a bad event is skipped.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: Windows passes a valid record whose `UserContext` is the
            // context given to `OpenTraceW`; callbacks run one at a time.
            let record = unsafe { &*record };
            let ctx = unsafe { &mut *(record.UserContext as *mut Context) };
            if let Some(event) = parse(ctx, record) {
                let _ = ctx.tx.send(event);
            }
        }));
    }

    fn is_provider(id: &GUID) -> bool {
        (id.data1, id.data2, id.data3, id.data4) == (PROVIDER.data1, PROVIDER.data2, PROVIDER.data3, PROVIDER.data4)
    }

    fn parse(ctx: &mut Context, record: &EVENT_RECORD) -> Option<Event> {
        if !is_provider(&record.EventHeader.ProviderId) {
            return None;
        }
        let names = &ctx.names;
        match record.EventHeader.EventDescriptor.Id {
            PROCESS_START => {
                let pid = u32_field(record, &names.process_id)?;
                let parent = u32_field(record, &names.parent_id)?;
                let created = u64_field(record, &names.create_time)?;
                let nt = string_field(record, &names.image_name)?;
                let image = path(ctx, &nt)?;
                let name = image.file_name()?.to_string_lossy().into_owned();
                Some(Event::Started(ProcessInfo { id: ProcessId { pid, created }, name, image, parent }))
            }
            PROCESS_STOP => {
                let pid = u32_field(record, &names.process_id)?;
                let created = u64_field(record, &names.create_time)?;
                Some(Event::Stopped(ProcessId { pid, created }))
            }
            IMAGE_LOAD => {
                let pid = u32_field(record, &names.process_id)?;
                let nt = string_field(record, &names.image_name)?;
                Some(Event::ImageLoaded { pid, image: path(ctx, &nt)? })
            }
            _ => None,
        }
    }

    /// The drive path of `nt`, reading the drive letters again (at most once
    /// a second) for a volume not seen before.
    fn path(ctx: &mut Context, nt: &str) -> Option<std::path::PathBuf> {
        if let Some(found) = dos_path(nt, &ctx.devices) {
            return Some(found);
        }
        if ctx.refreshed.elapsed() < DEVICE_REFRESH {
            return None;
        }
        ctx.devices = devices();
        ctx.refreshed = Instant::now();
        dos_path(nt, &ctx.devices)
    }

    fn field(record: &EVENT_RECORD, name: &[u16]) -> Option<Vec<u8>> {
        let descriptor = PROPERTY_DATA_DESCRIPTOR { PropertyName: name.as_ptr() as u64, ArrayIndex: u32::MAX, Reserved: 0 };
        let mut size = 0u32;
        // SAFETY: a valid record and one descriptor naming a null-terminated field.
        if unsafe { TdhGetPropertySize(record, 0, ptr::null(), 1, &descriptor, &mut size) } != ERROR_SUCCESS || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` holds `size` bytes.
        let status = unsafe { TdhGetProperty(record, 0, ptr::null(), 1, &descriptor, size, buf.as_mut_ptr()) };
        (status == ERROR_SUCCESS).then_some(buf)
    }

    fn u32_field(record: &EVENT_RECORD, name: &[u16]) -> Option<u32> {
        Some(u32::from_le_bytes(field(record, name)?.get(..4)?.try_into().ok()?))
    }

    fn u64_field(record: &EVENT_RECORD, name: &[u16]) -> Option<u64> {
        Some(u64::from_le_bytes(field(record, name)?.get(..8)?.try_into().ok()?))
    }

    fn string_field(record: &EVENT_RECORD, name: &[u16]) -> Option<String> {
        let bytes = field(record, name)?;
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
        (!units.is_empty()).then(|| String::from_utf16_lossy(&units))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Event;
    use std::sync::mpsc::Sender;

    pub struct Session;

    impl Session {
        pub fn start(_name: &str, _images: bool, _tx: Sender<Event>) -> std::io::Result<Self> {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "ETW is only available on Windows"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn devices() -> Vec<(String, String)> {
        vec![
            (r"\Device\HarddiskVolume3".into(), "C:".into()),
            (r"\Device\HarddiskVolume12".into(), "E:".into()),
            (r"\SystemRoot".into(), r"C:\Windows".into()),
        ]
    }

    #[test]
    fn nt_paths_become_drive_and_unc_paths() {
        let d = devices();
        let cases = [
            (r"\Device\HarddiskVolume3\Windows\System32\cmd.exe", Some(r"C:\Windows\System32\cmd.exe")),
            (r"\device\harddiskvolume3\Temp\a.dll", Some(r"C:\Temp\a.dll")),
            // Volume 1 is not a prefix match for volume 12.
            (r"\Device\HarddiskVolume12\x.exe", Some(r"E:\x.exe")),
            (r"\Device\HarddiskVolume1\x.exe", None),
            (r"\SystemRoot\System32\ntdll.dll", Some(r"C:\Windows\System32\ntdll.dll")),
            (r"\??\D:\setup.exe", Some(r"D:\setup.exe")),
            (r"\Device\Mup\server\share\tool.exe", Some(r"\\server\share\tool.exe")),
            (r"C:\already\fine.exe", Some(r"C:\already\fine.exe")),
            (r"\Device\HarddiskVolume3", None),
            ("", None),
        ];
        for (nt, want) in cases {
            assert_eq!(dos_path(nt, &d).as_deref(), want.map(Path::new), "{nt}");
        }
    }

    #[test]
    fn session_names_name_the_program() {
        assert!(session_name().starts_with("Phalanx "));
    }

    /// Needs administrator rights; skipped (and says so) without them.
    #[cfg(windows)]
    #[test]
    fn reports_a_short_lived_process_with_its_parent_and_image() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let (tx, rx) = mpsc::channel();
        let session = match start("Phalanx test", true, tx) {
            Ok(session) => session,
            Err(e) if e.raw_os_error() == Some(5) => {
                eprintln!("skipped: an ETW session needs administrator rights");
                return;
            }
            Err(e) => panic!("starting the session: {e}"),
        };
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let cmd = Path::new(&root).join(r"System32\cmd.exe");
        let mut child = std::process::Command::new(&cmd).args(["/c", "exit"]).spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();

        let (mut started, mut stopped, mut loaded) = (None, false, false);
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until && !(started.is_some() && stopped && loaded) {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Event::Started(info)) if info.id.pid == pid => started = Some(info),
                Ok(Event::Stopped(id)) if id.pid == pid => stopped = true,
                Ok(Event::ImageLoaded { pid: p, image }) if p == pid => {
                    loaded |= image.to_string_lossy().to_ascii_lowercase().ends_with("ntdll.dll");
                }
                _ => {}
            }
        }
        let info = started.expect("the start was reported");
        assert_eq!(info.parent, std::process::id());
        assert!(info.name.eq_ignore_ascii_case("cmd.exe"), "{info:?}");
        assert!(info.image.to_string_lossy().eq_ignore_ascii_case(&cmd.to_string_lossy()), "{info:?}");
        assert!(stopped, "the exit was reported");
        assert!(loaded, "its DLL loads were reported");

        // A second session of the same name replaces the first, whose
        // channel then closes.
        let (tx2, _rx2) = mpsc::channel();
        let _second = start("Phalanx test", false, tx2).unwrap();
        let closed = Instant::now() + Duration::from_secs(5);
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                _ if Instant::now() > closed => panic!("the replaced session kept running"),
                _ => {}
            }
        }
        drop(session);
    }
}
