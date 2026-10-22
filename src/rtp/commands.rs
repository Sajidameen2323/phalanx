//! Command-line rules in real-time protection: script hosts and Windows
//! tools as they start, and commands typed or pasted into the Run box.
//!
//! This is report-only for now: nothing is stopped, so false positives can
//! be found before any rule is trusted to act. High-confidence matches are
//! recorded in history; medium ones (common in admin tools and terminals)
//! are only shown in the activity log. The same command line is reported
//! once per [`REPEAT_WINDOW`]. Children of Phalanx itself (its own PowerShell
//! queries) are never checked.

use super::process::{self, ProcessInfo};
use super::{Ctx, RtpEvent};
use crate::cmdline::{self, Confidence, Match};
use crate::store::{ScanMeta, ScanStats, Store};
use crate::{Category, Finding, Source};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

/// A command line already reported is not reported again for this long.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Command lines remembered at most; older ones are forgotten first.
const MAX_RECENT: usize = 1000;

/// Where a suspicious command was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandSource {
    /// A program that started.
    Program,
    /// An entry added to the Run box's history.
    RunBox,
}

/// A command line that matched one or more rules.
#[derive(Debug, Clone)]
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
            if self.reported.len() >= MAX_RECENT {
                if let Some(oldest) = self.reported.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
                    self.reported.remove(&oldest);
                }
            }
        }
        self.reported.insert(key, now);
        true
    }
}

/// What history records for a match; nothing is done to the process yet.
pub const ACTION: &str = "reported (command-line rules are in report-only mode)";

/// Hosts a fake verification page tells the user to run from the Run box.
const CLICKFIX_HOSTS: &[&str] = &["powershell", "pwsh", "mshta", "cmd", "conhost"];

/// Checks a program that just started. `by_pid` is the same process list,
/// for naming its parent.
pub(super) fn check_program(ctx: &Ctx<'_>, info: &ProcessInfo, by_pid: &HashMap<u32, &ProcessInfo>) -> Option<CommandHit> {
    let host = cmdline::host(&info.name)?;
    if info.parent == std::process::id() {
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
    })
}

/// Checks a command added to the Run box's history.
pub(super) fn check_run_box(ctx: &Ctx<'_>, command: &str) -> Option<CommandHit> {
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
    matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    matches
}

/// Reports `hit` (recording it in history when [`CommandHit::in_history`]),
/// unless the same command line was reported recently.
pub(super) fn report(ctx: &Ctx<'_>, store: &Store, hit: CommandHit) {
    if !ctx.commands.lock().unwrap_or_else(PoisonError::into_inner).first_in_window(&hit) {
        return;
    }
    if hit.in_history() {
        if let Err(e) = record(ctx, store, &hit) {
            ctx.emit(RtpEvent::Error(format!("recording a suspicious command: {e:#}")));
        }
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
pub(super) use run_box::run as run_box;

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
                    if seen.get(name) != Some(command) {
                        if let Some(hit) = super::check_run_box(ctx, command) {
                            super::report(ctx, &store, hit);
                        }
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

    /// The commands in the Run box's history, by value name (`a`, `b`…).
    fn entries() -> Option<HashMap<String, String>> {
        let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey(RUN_MRU).ok()?;
        Some(
            key.enum_values()
                .filter_map(Result::ok)
                .filter(|(name, _)| !name.eq_ignore_ascii_case("MRUList"))
                .filter_map(|(name, _)| {
                    let data: String = key.get_value(&name).ok()?;
                    // Explorer appends `\1` to each entry.
                    Some((name, data.strip_suffix(r"\1").unwrap_or(&data).to_string()))
                })
                .collect(),
        )
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
