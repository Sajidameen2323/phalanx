//! Command-line rules in real-time protection: script hosts and Windows
//! tools as they start, and commands typed or pasted into the Run box.
//!
//! This is report-only for now: nothing is stopped, so false positives can
//! be found before any rule is trusted to act. High-confidence matches are
//! recorded in history; medium ones (common in admin tools and terminals)
//! are only shown in the activity log. The same command line is reported
//! once per [`REPEAT_WINDOW`]. Programs started by Phalanx (its own PowerShell
//! queries), whether by this copy or by another one from the same folder
//! (the app and `phalanx-cli`), are never checked.

use serde::{Deserialize, Serialize};
use super::process::{self, ProcessInfo};
use super::{Ctx, RtpEvent};
use crate::cmdline::{self, Confidence, Match};
use crate::store::{ScanMeta, ScanStats, Store};
use crate::{Category, Finding, Source};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;
use std::time::{Duration, Instant};

/// A command line already reported is not reported again for this long.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Command lines remembered at most; older ones are forgotten first.
const MAX_RECENT: usize = 1000;

/// Where a suspicious command was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommandSource {
    /// A program that started.
    Program,
    /// An entry added to the Run box's history.
    RunBox,
}

/// A command line that matched one or more rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandHit {
    pub source: CommandSource,
    pub pid: Option<u32>,
    /// The program as named on the command line or in the process list.
    pub program: String,
    pub image: Option<PathBuf>,
    /// The program that started it, when known.
    pub parent: Option<String>,
    pub command: String,
    /// The decoded `-EncodedCommand` script, if there was one.
    pub script: Option<String>,
    /// Most confident first.
    pub matches: Vec<Match>,
    /// Whose Run box it was, when the service watches every user's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl CommandHit {
    pub fn confidence(&self) -> Confidence {
        self.matches.iter().map(|m| m.confidence).max().unwrap_or(Confidence::Medium)
    }

    /// The most telling reason.
    pub fn headline(&self) -> &str {
        self.matches.first().map_or("", |m| m.reason.as_str())
    }

    /// Whether it is recorded in history; medium-confidence matches are
    /// only shown in the activity log.
    pub fn in_history(&self) -> bool {
        self.confidence() == Confidence::High
    }
}

/// When each command line was last reported.
#[derive(Default)]
pub struct Recent {
    reported: HashMap<(CommandSource, String), Instant>,
}

impl Recent {
    /// Whether `hit` should be reported now, i.e. its command line was not
    /// reported within [`REPEAT_WINDOW`]; remembers it if so.
    fn first_in_window(&mut self, hit: &CommandHit) -> bool {
        let now = Instant::now();
        let key = (hit.source, hit.command.trim().to_string());
        if self.reported.get(&key).is_some_and(|t| now.duration_since(*t) < REPEAT_WINDOW) {
            return false;
        }
        if self.reported.len() >= MAX_RECENT {
            self.reported.retain(|_, t| now.duration_since(*t) < REPEAT_WINDOW);
            if self.reported.len() >= MAX_RECENT
                && let Some(oldest) = self.reported.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone())
            {
                self.reported.remove(&oldest);
            }
        }
        self.reported.insert(key, now);
        true
    }
}

/// What the service's Run-box reader sees, for diagnosing it (the
/// service's `RunBoxView` request, administrators only: it shows every
/// user's Run-box history).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunBoxView {
    /// A fresh read of every hive under `HKEY_USERS`.
    pub hives: Vec<HiveView>,
    /// Errors enumerating `HKEY_USERS` itself.
    pub enum_errors: Vec<String>,
    /// What the running all-users watcher last saw.
    pub watcher: WatcherView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveView {
    pub name: String,
    /// Counted as a signed-in person's hive (and so watched).
    pub person: bool,
    /// The Run-box history read from it, or why it could not be opened.
    pub run_box: Result<std::collections::BTreeMap<String, String>, String>,
    /// For people's hives: what Windows reports about the key, and every
    /// value as enumerated (including errors the reader skips).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detail: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatcherView {
    /// Passes over every user's Run box since the watcher started.
    pub passes: u64,
    /// The hives it watched on its last pass.
    pub users: Vec<String>,
    /// Run-box entries it read on its last pass, all users together.
    pub entries: usize,
}

/// What history records for a match; nothing is done to the process yet.
pub const ACTION: &str = "reported (command-line rules are in report-only mode)";

/// Hosts a fake verification page tells the user to run from the Run box.
const CLICKFIX_HOSTS: &[&str] = &["powershell", "pwsh", "mshta", "cmd", "conhost"];

/// Checks a program that just started. `by_pid` holds the running processes,
/// for naming its parent.
pub(super) fn check_program(ctx: &Ctx<'_>, info: &ProcessInfo, by_pid: &HashMap<u32, ProcessInfo>) -> Option<CommandHit> {
    let host = cmdline::host(&info.name)?;
    let own_exe = std::env::current_exe().ok();
    if started_by_phalanx(info, by_pid, std::process::id(), own_exe.as_deref().and_then(Path::parent)) {
        return None;
    }
    let command = process::command_line(&info.id)?;
    let (_, args) = cmdline::split_command(&command);
    let (mut matches, script) = assess(ctx, host, args);
    if matches.is_empty() {
        return None;
    }
    // A parent started after the child is a reused process id, not its parent.
    let parent = by_pid.get(&info.parent).filter(|p| p.id.created <= info.id.created).map(|p| p.name.clone());
    if parent.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("explorer.exe")) && CLICKFIX_HOSTS.contains(&host) {
        matches.insert(
            0,
            Match::new(
                "clickfix.explorer",
                "it was started from the Run box or File Explorer, which is how fake verification pages (ClickFix) get it run",
                Confidence::High,
            ),
        );
    }
    Some(CommandHit {
        source: CommandSource::Program,
        pid: Some(info.id.pid),
        program: info.name.clone(),
        image: Some(info.image.clone()),
        parent,
        command,
        script,
        matches: sorted(matches),
        user: None,
    })
}

/// The programs Phalanx is made of; their own PowerShell queries are not checked.
const PHALANX_PROGRAMS: &[&str] = &["phalanx.exe", "phalanx-cli.exe"];

/// Whether `info` was started by this process, or by a Phalanx program in
/// `own_dir` (the folder this copy runs from). Only that folder counts, so
/// malware cannot hide by naming itself `phalanx.exe`.
fn started_by_phalanx(info: &ProcessInfo, by_pid: &HashMap<u32, ProcessInfo>, own_pid: u32, own_dir: Option<&Path>) -> bool {
    if info.parent == own_pid {
        return true;
    }
    let (Some(parent), Some(own_dir)) = (by_pid.get(&info.parent), own_dir) else { return false };
    // A parent started after the child is a reused process id, not its parent.
    if parent.id.created > info.id.created {
        return false;
    }
    let same_folder = parent.image.parent().is_some_and(|dir| same_path(dir, own_dir));
    let name = parent.image.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    same_folder && PHALANX_PROGRAMS.contains(&name.as_str())
}

/// Windows paths compare without regard to case or a trailing separator.
fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.display().to_string().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Checks a command added to the Run box's history.
pub(super) fn check_run_box(ctx: &Ctx<'_>, command: &str, user: Option<String>) -> Option<CommandHit> {
    let (program, args) = cmdline::split_command(command);
    let host = cmdline::host(program)?;
    let (mut matches, script) = assess(ctx, host, args);
    if matches.is_empty() {
        return None;
    }
    matches.insert(
        0,
        Match::new(
            "clickfix.run-box",
            "it was pasted or typed into the Windows Run box, which is how fake verification pages (ClickFix) get it run",
            Confidence::High,
        ),
    );
    Some(CommandHit {
        source: CommandSource::RunBox,
        pid: None,
        program: program.to_string(),
        image: None,
        parent: None,
        command: command.to_string(),
        script,
        user,
        matches: sorted(matches),
    })
}

/// The rules, plus the signatures run on a decoded `-EncodedCommand`.
fn assess(ctx: &Ctx<'_>, host: &str, args: &str) -> (Vec<Match>, Option<String>) {
    let mut matches = cmdline::analyze(host, args);
    let script = cmdline::encoded_command(host, args);
    if let Some(script) = &script {
        for f in ctx.engine.scanner().scan(script.as_bytes()).findings {
            matches.push(Match::new(
                &format!("signature.{}", f.threat),
                format!("the hidden script matches {} ({})", f.threat, f.category),
                Confidence::High,
            ));
        }
    }
    (matches, script)
}

fn sorted(mut matches: Vec<Match>) -> Vec<Match> {
    matches.sort_by_key(|m| std::cmp::Reverse(m.confidence));
    matches
}

/// Reports `hit` (recording it in history when [`CommandHit::in_history`]),
/// unless the same command line was reported recently.
pub(super) fn report(ctx: &Ctx<'_>, store: &Store, hit: CommandHit) {
    if !ctx.commands.lock().unwrap_or_else(PoisonError::into_inner).first_in_window(&hit) {
        return;
    }
    if hit.in_history() && let Err(e) = record(ctx, store, &hit) {
        ctx.emit(RtpEvent::Error(format!("recording a suspicious command: {e:#}")));
    }
    ctx.emit(RtpEvent::Command(hit));
}

fn record(ctx: &Ctx<'_>, store: &Store, hit: &CommandHit) -> anyhow::Result<()> {
    let path = match (&hit.image, hit.source) {
        (Some(image), _) => image.display().to_string(),
        (None, CommandSource::RunBox) => format!("Run box: {}", hit.program),
        (None, CommandSource::Program) => hit.program.clone(),
    };
    let reasons: Vec<&str> = hit.matches.iter().map(|m| m.reason.as_str()).collect();
    let mut details = format!("{} · command: {}", reasons.join("; "), shorten(&hit.command, 1000));
    if let Some(script) = &hit.script {
        details.push_str(&format!(" · decoded: {}", shorten(script, 1000)));
    }
    let finding = Finding {
        threat: format!("CommandLine.{}", hit.matches[0].rule),
        category: Category::Suspicious,
        source: Source::Heuristic,
        details,
    };
    let scan_id = store.begin_scan(&ScanMeta { kind: "command", targets: &path, threads: 1, signatures: ctx.config.signatures.as_deref() })?;
    store.add_detection(scan_id, &path, "", &finding, ACTION)?;
    let stats = ScanStats { files_scanned: 1, detections: 1, ..Default::default() };
    store.finish_scan(scan_id, &stats, 0, false)?;
    Ok(())
}

fn shorten(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text.to_string(),
    }
}

#[cfg(windows)]
pub(super) use run_box::{run as run_box, run_all_users as run_box_all_users};
#[cfg(windows)]
pub use run_box::view as run_box_view;

#[cfg(not(windows))]
pub fn run_box_view() -> RunBoxView {
    RunBoxView::default()
}
#[cfg(all(windows, test))]
pub(super) use run_box::is_user_hive;

/// Watches the Run box's history (`RunMRU`). ClickFix has the user paste a
/// command there; the entry is written as the command runs, so this catches
/// it even when the program exits before the process monitor looks.
#[cfg(windows)]
mod run_box {
    use super::super::Ctx;
    use crate::scan;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    const RUN_MRU: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
    /// Re-read even without a change notice, in case one was missed.
    const MAX_WAIT: Duration = Duration::from_secs(30);

    pub fn run(ctx: &Ctx<'_>) -> anyhow::Result<()> {
        let store = scan::open_store(ctx.data_dir)?;
        // Entries present when watching starts are not new; `None` until read.
        let mut seen: Option<HashMap<String, String>> = None;
        while !ctx.halted() {
            // Armed before reading, so a change in between is not missed.
            let notice = Notice::arm();
            let Some(entries) = entries() else {
                // The key appears the first time the Run box is used; all its
                // entries are new then.
                seen.get_or_insert_with(HashMap::new);
                ctx.pause(Duration::from_secs(5));
                continue;
            };
            if let Some(seen) = &seen {
                for (name, command) in &entries {
                    if seen.get(name) != Some(command) && let Some(hit) = super::check_run_box(ctx, command, None) {
                        super::report(ctx, &store, hit);
                    }
                }
            }
            seen = Some(entries);
            match notice {
                Some(notice) => notice.wait(ctx),
                None => ctx.pause(Duration::from_secs(1)),
            }
        }
        Ok(())
    }

    /// Every signed-in user's Run box, read from their registry hive under
    /// `HKEY_USERS` (the service's own `HKEY_CURRENT_USER` is SYSTEM's).
    /// Read once a second; a user's entries when they are first seen (they
    /// just signed in) are where they start, not new.
    pub fn run_all_users(ctx: &Ctx<'_>) -> anyhow::Result<()> {
        let store = scan::open_store(ctx.data_dir)?;
        let users = winreg::RegKey::predef(winreg::enums::HKEY_USERS);
        let mut seen: HashMap<String, HashMap<String, String>> = HashMap::new();
        while !ctx.halted() {
            let signed_in: Vec<String> = users.enum_keys().filter_map(Result::ok).filter(|sid| is_user_hive(sid)).collect();
            seen.retain(|sid, _| signed_in.contains(sid));
            let mut read_entries = 0;
            for sid in signed_in.clone() {
                let entries = users.open_subkey(format!(r"{sid}\{RUN_MRU}")).ok().map(|key| read(&key)).unwrap_or_default();
                read_entries += entries.len();
                match seen.get(&sid) {
                    None => {}
                    Some(before) => {
                        for (name, command) in &entries {
                            if before.get(name) != Some(command) && let Some(hit) = super::check_run_box(ctx, command, Some(account_name(&sid))) {
                                super::report(ctx, &store, hit);
                            }
                        }
                    }
                }
                seen.insert(sid, entries);
            }
            {
                let mut watcher = WATCHER.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                watcher.passes += 1;
                watcher.users = signed_in;
                watcher.entries = read_entries;
            }
            ctx.pause(Duration::from_secs(1));
        }
        Ok(())
    }

    /// What the running all-users watcher last saw.
    static WATCHER: std::sync::Mutex<super::WatcherView> = std::sync::Mutex::new(super::WatcherView { passes: 0, users: Vec::new(), entries: 0 });

    /// A fresh read of every hive's Run box, the way the watcher reads
    /// them, and what the watcher itself last saw.
    pub fn view() -> super::RunBoxView {
        let users = winreg::RegKey::predef(winreg::enums::HKEY_USERS);
        let mut view = super::RunBoxView::default();
        for name in users.enum_keys() {
            match name {
                Ok(name) => {
                    let key = users.open_subkey(format!(r"{name}\{RUN_MRU}"));
                    let person = is_user_hive(&name);
                    let mut detail = Vec::new();
                    if let (true, Ok(key)) = (person, &key) {
                        match key.query_info() {
                            Ok(info) => {
                                let t = info.get_last_write_time_system();
                                detail.push(format!(
                                    "Windows reports {} value(s), {} subkey(s), last written {}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                                    info.values, info.sub_keys, t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
                                ))
                            }
                            Err(e) => detail.push(format!("query_info failed: {e}")),
                        }
                        for (i, value) in key.enum_values().enumerate() {
                            detail.push(match value {
                                Ok((n, v)) => format!("value {i}: {n} ({:?}, {} bytes) = {:?}", v.vtype, v.bytes.len(), key.get_value::<String, _>(&n)),
                                Err(e) => format!("value {i}: error {e}"),
                            });
                        }
                    }
                    let run_box = key.map(|key| read(&key).into_iter().collect()).map_err(|e| e.to_string());
                    view.hives.push(super::HiveView { person, name, run_box, detail });
                }
                Err(e) => view.enum_errors.push(e.to_string()),
            }
        }
        view.watcher = WATCHER.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        view
    }

    /// A signed-in person's hive: `S-1-5-21-…`, not its `_Classes` part and
    /// not the system's own accounts.
    pub(crate) fn is_user_hive(name: &str) -> bool {
        name.starts_with("S-1-5-21-") && !name.ends_with("_Classes")
    }

    /// `DOMAIN\user` for a SID, or the SID itself.
    fn account_name(sid: &str) -> String {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
        let wide: Vec<u16> = sid.encode_utf16().chain([0]).collect();
        unsafe {
            let mut psid: PSID = std::ptr::null_mut();
            if ConvertStringSidToSidW(wide.as_ptr(), &mut psid) == 0 {
                return sid.to_string();
            }
            let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
            let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
            let mut kind: SID_NAME_USE = 0;
            let ok = LookupAccountSidW(std::ptr::null(), psid, name.as_mut_ptr(), &mut name_len, domain.as_mut_ptr(), &mut domain_len, &mut kind) != 0;
            LocalFree(psid as _);
            if !ok {
                return sid.to_string();
            }
            let name = String::from_utf16_lossy(&name[..name_len as usize]);
            let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
            if domain.is_empty() { name } else { format!("{domain}\\{name}") }
        }
    }

    /// The commands in the Run box's history, by value name (`a`, `b`…).
    fn entries() -> Option<HashMap<String, String>> {
        let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey(RUN_MRU).ok()?;
        Some(read(&key))
    }

    fn read(key: &winreg::RegKey) -> HashMap<String, String> {
        key.enum_values()
            .filter_map(Result::ok)
            .filter(|(name, _)| !name.eq_ignore_ascii_case("MRUList"))
            .filter_map(|(name, _)| {
                let data: String = key.get_value(&name).ok()?;
                // Explorer appends `\1` to each entry.
                Some((name, data.strip_suffix(r"\1").unwrap_or(&data).to_string()))
            })
            .collect()
    }

    /// A pending change notification on the RunMRU key.
    struct Notice {
        key: HKEY,
        event: HANDLE,
    }

    impl Notice {
        fn arm() -> Option<Self> {
            let path: Vec<u16> = RUN_MRU.encode_utf16().chain([0]).collect();
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: `path` is NUL-terminated; `key` is an out-pointer.
            if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_NOTIFY, &mut key) } != ERROR_SUCCESS {
                return None;
            }
            // SAFETY: an unnamed manual-reset event with default security.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                unsafe { RegCloseKey(key) };
                return None;
            }
            let notice = Self { key, event };
            // SAFETY: both handles are valid until `notice` is dropped, which
            // also cancels the notification.
            let armed = unsafe { RegNotifyChangeKeyValue(key, 0, REG_NOTIFY_CHANGE_LAST_SET, event, 1) } == ERROR_SUCCESS;
            armed.then_some(notice)
        }

        /// Returns when the key changed, protection stops, or `MAX_WAIT` passes.
        fn wait(&self, ctx: &Ctx<'_>) {
            let since = Instant::now();
            while !ctx.halted() && since.elapsed() < MAX_WAIT {
                if unsafe { WaitForSingleObject(self.event, 250) } == WAIT_OBJECT_0 {
                    return;
                }
            }
        }
    }

    impl Drop for Notice {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.key);
                CloseHandle(self.event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::process::ProcessId;

    fn proc(pid: u32, created: u64, image: &str, parent: u32) -> ProcessInfo {
        let image = PathBuf::from(image);
        let name = image.file_name().unwrap().to_string_lossy().into_owned();
        ProcessInfo { id: ProcessId { pid, created }, name, image, parent }
    }

    #[test]
    fn programs_started_by_phalanx_are_skipped_only_from_its_own_folder() {
        let own_dir = Path::new(r"C:\Program Files\Phalanx");
        let cli = proc(10, 100, r"C:\Program Files\Phalanx\phalanx-cli.exe", 1);
        let app = proc(11, 100, r"c:\program files\phalanx\PHALANX.EXE", 1);
        let impostor = proc(12, 100, r"C:\Users\u\Downloads\phalanx.exe", 1);
        let other = proc(13, 100, r"C:\Program Files\Phalanx\helper.exe", 1);
        let by_pid: HashMap<u32, ProcessInfo> = [cli, app, impostor, other].into_iter().map(|p| (p.id.pid, p)).collect();
        let child = |parent: u32, created: u64| proc(50, created, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", parent);

        assert!(started_by_phalanx(&child(99, 200), &by_pid, 99, Some(own_dir)), "this process");
        assert!(started_by_phalanx(&child(10, 200), &by_pid, 99, Some(own_dir)), "phalanx-cli from the same folder");
        assert!(started_by_phalanx(&child(11, 200), &by_pid, 99, Some(own_dir)), "the app, in any case");
        assert!(!started_by_phalanx(&child(12, 200), &by_pid, 99, Some(own_dir)), "a phalanx.exe elsewhere");
        assert!(!started_by_phalanx(&child(13, 200), &by_pid, 99, Some(own_dir)), "another program in the folder");
        assert!(!started_by_phalanx(&child(10, 50), &by_pid, 99, Some(own_dir)), "a reused process id");
        assert!(!started_by_phalanx(&child(77, 200), &by_pid, 99, Some(own_dir)), "an unknown parent");
        assert!(!started_by_phalanx(&child(10, 200), &by_pid, 99, None), "own folder unknown");
        assert!(same_path(Path::new(r"C:\A\b\"), Path::new("c:/a/B")));
    }
}
