//! Browser data watch: programs other than the browser opening the files
//! where browsers keep saved passwords, sign-in cookies, cards and the key
//! that unlocks them, and browsers started to be remote-controlled with the
//! person's own profile. Both are how infostealers take over accounts: a
//! stolen session cookie skips the password and the second factor, so the
//! thief can read email (password-reset codes included) as if signed in.
//!
//! File opens come from an ETW session on Microsoft-Windows-Kernel-File
//! ([`etw::start_file_opens`]), filtered by name on the session's thread so
//! only the few opens of those files reach this module. Watching every file
//! open costs some CPU and a few MB of event buffers, which is why the watch
//! is a switch of its own (off by default). Needs administrator rights, so
//! in practice the service.
//!
//! Who opened the file decides what happens:
//!
//! * the browser itself, or another program signed by a browser maker or by
//!   Microsoft (Windows' search, Defender, backup): nothing;
//! * a script host or Windows tool stealers use (PowerShell, `esentutl`,
//!   `rundll32`, Python…), or an unsigned program: **high**, stopped at once
//!   when automatic stopping is on, and its file scanned;
//! * any other signed program (a backup tool, a password manager importing):
//!   reported for review, never stopped.
//!
//! A stealer has usually copied the file by the time the event arrives
//! (about 100 ms); stopping it then still keeps it from sending what it
//! took, which stealers do once they have collected everything. The alert
//! says so: sign out of other sessions and change passwords either way.

use super::process::{self, ProcessId, ProcessInfo};
use super::{etw, net, Ctx, Item, RtpEvent};
use crate::store::{ScanMeta, ScanStats, Store};
use crate::trust::{self, Trust};
use crate::{Category, Finding, Source};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

/// Without the event session, how often it is tried again.
const RETRY: Duration = Duration::from_secs(60);
/// Files the same program opens this soon after the first join its alert.
const GATHER: Duration = Duration::from_millis(400);
/// A signed program is reported at most this often per browser.
const REVIEW_EVERY: Duration = Duration::from_secs(60 * 60);
/// Kept judgements and signatures, at most.
const MAX_CACHED: usize = 2_000;

/// How sure the watch is that a program is stealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    /// A script host, Windows tool or unsigned program: stopped when
    /// automatic stopping is on.
    High,
    /// A signed program: reported only.
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardKind {
    /// A program opened a browser's password, cookie or key file.
    DataRead,
    /// A browser was started for remote control with an existing profile.
    RemoteControl,
}

/// The program that started a remote-controlled browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Controller {
    pub pid: u32,
    pub program: String,
    pub image: PathBuf,
    /// `None` when left running.
    pub stopped: Option<Result<(), String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHit {
    pub kind: GuardKind,
    pub level: Level,
    pub pid: u32,
    /// Creation time, so the process can be stopped later without
    /// mistaking a reused id; 0 when it exited before it was identified.
    pub created: u64,
    /// The program's file name, e.g. `update.exe`.
    pub program: String,
    /// Its full path; empty when it exited before it was identified.
    pub image: PathBuf,
    /// Who signed it, when it is signed.
    pub signer: Option<String>,
    /// `Chrome`, `Edge`, `Firefox`…
    pub browser: String,
    /// What it reached, in plain words ("saved passwords").
    pub data: Vec<String>,
    /// The files it opened (a data read).
    pub files: Vec<PathBuf>,
    /// The switches it was started with (remote control).
    pub switches: Vec<String>,
    /// Why it was judged so, in plain words.
    pub reason: String,
    /// Where it was connected when caught (outside this PC).
    pub connections: Vec<String>,
    /// `None` when left running; otherwise whether stopping it worked.
    pub stopped: Option<Result<(), String>>,
    /// Remote control: the program that started the browser.
    pub controller: Option<Controller>,
}

impl BrowserHit {
    /// What happened, in plain words.
    pub fn headline(&self) -> String {
        match self.kind {
            GuardKind::DataRead => format!("{} opened {}'s {}", self.program, self.browser, join(&self.data)),
            GuardKind::RemoteControl => match &self.controller {
                Some(c) => format!("{} started {} for remote control with your profile", c.program, self.browser),
                None => format!("{} was started for remote control with your profile", self.browser),
            },
        }
    }

    pub fn process(&self) -> Option<ProcessId> {
        (self.created != 0).then_some(ProcessId { pid: self.pid, created: self.created })
    }

    /// What was done about it, for history.
    pub fn action(&self) -> String {
        let mut action = match (&self.stopped, self.level) {
            (Some(Ok(())), _) => "program stopped".to_string(),
            (Some(Err(e)), _) => format!("could not stop it: {e}"),
            (None, Level::High) => "reported (automatic stopping is off)".into(),
            (None, Level::Review) => "reported (signed program; not stopped)".into(),
        };
        if let Some(Controller { program, stopped: Some(result), .. }) = &self.controller {
            match result {
                Ok(()) => action.push_str(&format!("; {program} stopped")),
                Err(e) => action.push_str(&format!("; could not stop {program}: {e}")),
            }
        }
        action
    }
}

fn join(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
}

/// A browser's data file: which browser, and what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secret {
    pub browser: &'static str,
    pub data: &'static str,
}

/// Browser data folders (as they appear in a path) and the browser's name.
const BROWSER_FOLDERS: &[(&str, Family, &str)] = &[
    (r"\google\chrome", Family::Chromium, "Chrome"),
    (r"\microsoft\edge", Family::Chromium, "Edge"),
    (r"\bravesoftware\", Family::Chromium, "Brave"),
    (r"\opera software\", Family::Chromium, "Opera"),
    (r"\vivaldi\", Family::Chromium, "Vivaldi"),
    (r"\yandex\yandexbrowser\", Family::Chromium, "Yandex Browser"),
    (r"\chromium\", Family::Chromium, "Chromium"),
    (r"\mozilla\firefox\", Family::Firefox, "Firefox"),
    (r"\waterfox\", Family::Firefox, "Waterfox"),
    (r"\librewolf\", Family::Firefox, "LibreWolf"),
    (r"\thunderbird\", Family::Firefox, "Thunderbird"),
];

/// Whether `path` (a drive or NT path, any case) is a browser's password,
/// cookie, card or key file. Called for every file opened on the PC, so the
/// file name is checked first and the rest only for the few that match.
pub fn secret(path: &str) -> Option<Secret> {
    let name = path.rsplit(['\\', '/']).next()?;
    let is = |n: &str| name.eq_ignore_ascii_case(n);
    let (family, data) = if is("Login Data") || is("Login Data For Account") {
        (Family::Chromium, "saved passwords")
    } else if is("Cookies") {
        (Family::Chromium, "sign-in cookies")
    } else if is("Web Data") {
        (Family::Chromium, "saved cards and addresses")
    } else if is("Local State") {
        (Family::Chromium, "key that unlocks saved passwords and cookies")
    } else if is("logins.json") {
        (Family::Firefox, "saved passwords")
    } else if is("key4.db") || is("key3.db") {
        (Family::Firefox, "key that unlocks saved passwords")
    } else if is("cookies.sqlite") {
        (Family::Firefox, "sign-in cookies")
    } else if leveldb_file(name) && contains(path, r"\Local Extension Settings\") {
        (Family::Chromium, "extension data, such as crypto wallets")
    } else {
        return None;
    };
    if !contains(path, r"\AppData\") {
        return None;
    }
    let browser = BROWSER_FOLDERS.iter().find(|(folder, f, _)| *f == family && contains(path, folder)).map(|(_, _, name)| *name);
    let browser = browser.or_else(|| (family == Family::Chromium && contains(path, r"\User Data\")).then_some("a Chromium-based browser"))?;
    Some(Secret { browser, data })
}

/// The file filter for the event session.
fn wanted(nt: &str) -> bool {
    secret(nt).is_some()
}

fn leveldb_file(name: &str) -> bool {
    let lower = |suffix: &str| name.len() > suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix);
    lower(".ldb") || lower(".log") || name.starts_with("MANIFEST-")
}

/// Case-insensitive (ASCII) substring test.
fn contains(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Script hosts and Windows tools: signed, but what they do is up to whoever
/// runs them, and stealers run them to read browser files.
const TOOLS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "esentutl.exe", "certutil.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe",
    "python.exe", "pythonw.exe", "py.exe", "node.exe", "autoit3.exe", "autohotkey.exe", "java.exe", "javaw.exe",
];

/// Signers whose programs may read browser data: browser makers (their
/// browsers, updaters and helpers) and Microsoft (Windows' search, Defender
/// and backup, Edge importing from Chrome). Matched as part of the name.
const BROWSER_MAKERS: &[&str] = &["Google", "Microsoft", "Brave Software", "Opera Norway", "Vivaldi Technologies", "Mozilla", "YANDEX"];

/// Chromium browsers' program names: the ones remote control is checked on.
const CHROMIUM_BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "chromium.exe"];

/// Whether `image` may read browser data and, if not, how sure it is to be
/// a stealer and why. `own_dir` is Phalanx's folder (its browser checks
/// read these files too); `allowed` the programs people allowed.
pub fn judge(image: &Path, trust: &Trust, allowed: &[PathBuf], own_dir: Option<&Path>) -> Option<(Level, String)> {
    let same = |a: &Path, b: &Path| a.as_os_str().eq_ignore_ascii_case(b.as_os_str());
    if allowed.iter().any(|a| same(a, image)) || own_dir.is_some_and(|dir| image.parent().is_some_and(|p| same(p, dir))) {
        return None;
    }
    let name = image.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if TOOLS.contains(&name.as_str()) {
        return Some((Level::High, "it is a script host or Windows tool, which stealers use to copy browser files".into()));
    }
    match trust {
        Trust::Signed { signer, .. } => {
            let signer = signer.as_deref().unwrap_or("an unnamed publisher");
            if BROWSER_MAKERS.iter().any(|maker| contains(signer, maker)) {
                return None;
            }
            Some((Level::Review, format!("it is signed by {signer}; a backup tool or password manager may do this, so it was only reported")))
        }
        Trust::Unsigned => Some((Level::High, "it is not digitally signed".into())),
        Trust::Tampered => Some((Level::High, "it was changed after it was signed".into())),
        Trust::Invalid(why) => Some((Level::High, format!("its signature does not verify ({why})"))),
        Trust::Unknown(why) => Some((Level::High, format!("its signature could not be checked ({why})"))),
    }
}

/// Whether a browser's command line starts it for remote control with an
/// existing profile, and how sure that is a hijack: high when it was also
/// hidden (headless or off screen). The browser's own child processes, and
/// automation with a fresh profile (how developers test), are left alone.
/// `existing_profile` says whether a profile folder already has data.
pub fn remote_control(command: &str, existing_profile: impl Fn(&Path) -> bool) -> Option<(Level, Vec<String>)> {
    if contains(command, "--type=") || !(contains(command, "--remote-debugging-port") || contains(command, "--remote-debugging-pipe")) {
        return None;
    }
    let profile = switch_value(command, "--user-data-dir");
    let real = match &profile {
        None => true,
        Some(dir) => {
            let dir = dir.trim_end_matches(['\\', '/']);
            let lower = dir.to_lowercase();
            lower.ends_with(r"\user data") || lower.ends_with(r"\opera stable") || existing_profile(Path::new(dir))
        }
    };
    if !real {
        return None;
    }
    let off_screen = switch_value(command, "--window-position")
        .is_some_and(|pos| pos.split(',').any(|n| n.trim().parse::<i64>().is_ok_and(|n| n <= -1000)));
    let hidden = contains(command, "--headless") || contains(command, "--no-startup-window") || off_screen;
    let switches = ["--remote-debugging-port", "--remote-debugging-pipe", "--remote-allow-origins", "--headless", "--no-startup-window", "--window-position", "--user-data-dir"]
        .iter()
        .filter(|s| contains(command, s))
        .map(|s| s.to_string())
        .collect();
    Some((if hidden { Level::High } else { Level::Review }, switches))
}

/// The value of `--name=value` in a command line, quoted or not.
fn switch_value(command: &str, name: &str) -> Option<String> {
    let lower = command.to_lowercase();
    let at = lower.find(&format!("{name}="))?;
    let rest = &command[at + name.len() + 1..];
    let quoted_switch = command[..at].ends_with('"');
    let value = if let Some(inner) = rest.strip_prefix('"') {
        inner.split('"').next()
    } else if quoted_switch {
        rest.split('"').next()
    } else {
        rest.split(char::is_whitespace).next()
    };
    value.map(str::to_string).filter(|v| !v.is_empty())
}

/// A profile folder with data in it: a browser has used it before.
fn profile_in_use(dir: &Path) -> bool {
    dir.join("Local State").is_file()
}

/// What the watch keeps while it runs.
struct Watch<'a, 'c> {
    ctx: &'a Ctx<'c>,
    store: &'a Store,
    urgent: &'a Sender<Item>,
    own_dir: Option<PathBuf>,
    /// Processes started since the session began, by id.
    live: HashMap<u32, ProcessInfo>,
    /// Each process is judged once, when it first opens a file.
    judged: HashMap<ProcessId, bool>,
    signatures: HashMap<PathBuf, Trust>,
    /// Signed programs reported, by program and browser.
    reviewed: HashMap<(PathBuf, String), Instant>,
    /// Alerts waiting for more files from the same program.
    pending: Vec<(BrowserHit, Instant)>,
}

/// Runs the watch until protection stops. Without the event session (no
/// administrator rights) it says why and tries again now and then.
pub(super) fn run(ctx: &Ctx<'_>, store: &Store, urgent: &Sender<Item>) -> anyhow::Result<()> {
    let own_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    let mut watch = Watch {
        ctx,
        store,
        urgent,
        own_dir,
        live: HashMap::new(),
        judged: HashMap::new(),
        signatures: HashMap::new(),
        reviewed: HashMap::new(),
        pending: Vec::new(),
    };
    let mut announced = None;
    while !ctx.halted() {
        let (tx, rx) = mpsc::channel();
        let session = match etw::start_file_opens(&format!("{} browser data", etw::session_name()), wanted, tx) {
            Ok(session) => session,
            Err(e) => {
                let reason = if e.raw_os_error() == Some(5) { "it needs administrator rights".to_string() } else { e.to_string() };
                if announced.as_ref() != Some(&Some(reason.clone())) {
                    ctx.emit(RtpEvent::BrowserGuard { active: false, reason: Some(reason.clone()) });
                    announced = Some(Some(reason));
                }
                ctx.pause(RETRY);
                continue;
            }
        };
        ctx.emit(RtpEvent::BrowserGuard { active: true, reason: None });
        announced = Some(None);
        while !ctx.halted() {
            let wait = watch.pending.iter().map(|(_, due)| due.saturating_duration_since(Instant::now())).min().unwrap_or(Duration::from_millis(500));
            match rx.recv_timeout(wait.min(Duration::from_millis(500))) {
                Ok(etw::Event::Started(info)) => {
                    watch.live.insert(info.id.pid, info.clone());
                    watch.started(&info);
                }
                Ok(etw::Event::Stopped { pid }) => {
                    watch.live.remove(&pid);
                    watch.judged.retain(|id, _| id.pid != pid);
                }
                Ok(etw::Event::FileOpened { pid, path }) => watch.opened(pid, path),
                Ok(etw::Event::ImageLoaded { .. }) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            watch.flush(false);
        }
        watch.flush(true);
        drop(session);
        if !ctx.halted() {
            ctx.emit(RtpEvent::BrowserGuard { active: false, reason: Some("the event session ended; trying again".into()) });
            announced = None;
            ctx.pause(Duration::from_secs(5));
        }
    }
    Ok(())
}

impl Watch<'_, '_> {
    fn trust(&mut self, image: &Path) -> Trust {
        if self.signatures.len() > MAX_CACHED {
            self.signatures.clear();
        }
        self.signatures.entry(image.to_path_buf()).or_insert_with(|| trust::verify(image)).clone()
    }

    fn info(&self, pid: u32) -> Option<ProcessInfo> {
        if let Some(info) = self.live.get(&pid) {
            return Some(info.clone());
        }
        let (created, image) = process::identify(pid)?;
        let name = image.file_name()?.to_string_lossy().into_owned();
        Some(ProcessInfo { id: ProcessId { pid, created }, name, image, parent: 0 })
    }

    fn opened(&mut self, pid: u32, path: PathBuf) {
        let Some(secret) = secret(&path.to_string_lossy()) else { return };
        // More files from a program already caught join its alert.
        if let Some((hit, _)) = self.pending.iter_mut().find(|(hit, _)| hit.pid == pid && hit.kind == GuardKind::DataRead) {
            if !hit.data.iter().any(|d| d == secret.data) {
                hit.data.push(secret.data.into());
            }
            if !hit.files.contains(&path) {
                hit.files.push(path);
            }
            return;
        }
        let info = self.info(pid);
        // A process that could not be identified is judged once too.
        let id = info.as_ref().map_or(ProcessId { pid, created: 0 }, |i| i.id.clone());
        if self.judged.contains_key(&id) {
            return;
        }
        if self.judged.len() > MAX_CACHED {
            self.judged.clear();
        }
        if info.is_none() {
            self.judged.insert(id, true);
        }
        let (level, reason, signer) = match &info {
            Some(info) => {
                let trust = self.trust(&info.image);
                let verdict = judge(&info.image, &trust, &self.ctx.config.browser_guard_allowed, self.own_dir.as_deref());
                self.judged.insert(info.id.clone(), verdict.is_some());
                let Some((level, reason)) = verdict else { return };
                let signer = match trust {
                    Trust::Signed { signer, .. } => signer,
                    _ => None,
                };
                (level, reason, signer)
            }
            None => (Level::High, "it exited before it could be identified".to_string(), None),
        };
        if level == Level::Review && let Some(info) = &info {
            let key = (info.image.clone(), secret.browser.to_string());
            if self.reviewed.get(&key).is_some_and(|t| t.elapsed() < REVIEW_EVERY) {
                return;
            }
            self.reviewed.insert(key, Instant::now());
        }
        // Where it is connected, read before it is stopped.
        let connections = net::connections(pid).iter().map(ToString::to_string).collect();
        let stop = level == Level::High && self.ctx.config.browser_guard_stop;
        let stopped = match &info {
            Some(info) if stop => Some(process::terminate(&info.id)),
            _ => None,
        };
        let hit = BrowserHit {
            kind: GuardKind::DataRead,
            level,
            pid,
            created: info.as_ref().map_or(0, |i| i.id.created),
            program: info.as_ref().map_or_else(|| format!("A program (pid {pid})"), |i| i.name.clone()),
            image: info.as_ref().map(|i| i.image.clone()).unwrap_or_default(),
            signer,
            browser: secret.browser.into(),
            data: vec![secret.data.into()],
            files: vec![path],
            switches: Vec::new(),
            reason,
            connections,
            stopped,
            controller: None,
        };
        self.pending.push((hit, Instant::now() + GATHER));
    }

    /// A process started: a Chromium browser started for remote control
    /// with an existing profile is reported, and stopped when hidden.
    fn started(&mut self, info: &ProcessInfo) {
        if !CHROMIUM_BROWSERS.contains(&info.name.to_lowercase().as_str()) {
            return;
        }
        let Some(command) = process::command_line(&info.id) else { return };
        let Some((level, switches)) = remote_control(&command, profile_in_use) else { return };
        let stop = level == Level::High && self.ctx.config.browser_guard_stop;
        // The program that started it, when it is not a browser itself.
        let parent = self.info(info.parent).filter(|p| !CHROMIUM_BROWSERS.contains(&p.name.to_lowercase().as_str()));
        let controller = parent.map(|p| {
            let trust = self.trust(&p.image);
            let suspect = judge(&p.image, &trust, &self.ctx.config.browser_guard_allowed, self.own_dir.as_deref()).is_some_and(|(l, _)| l == Level::High);
            let stopped = (stop && suspect).then(|| process::terminate(&p.id));
            if suspect {
                let _ = self.urgent.send(Item::File { path: p.image.clone(), announced: false });
            }
            Controller { pid: p.id.pid, program: p.name, image: p.image, stopped }
        });
        let reason = match level {
            Level::High => "it was hidden (headless or off screen), so whoever started it can read your signed-in sites, email included, without you seeing".to_string(),
            Level::Review => "remote debugging lets another program read and act on your signed-in sites; developers use it, but so do stealers".to_string(),
        };
        let browser = browser_name(&info.name);
        let trust = self.trust(&info.image);
        let hit = BrowserHit {
            kind: GuardKind::RemoteControl,
            level,
            pid: info.id.pid,
            created: info.id.created,
            program: info.name.clone(),
            image: info.image.clone(),
            signer: match trust {
                Trust::Signed { signer, .. } => signer,
                _ => None,
            },
            browser: browser.into(),
            data: vec!["signed-in sites".into()],
            files: Vec::new(),
            switches,
            reason,
            connections: Vec::new(),
            stopped: stop.then(|| process::terminate(&info.id)),
            controller,
        };
        self.report(hit);
    }

    /// Reports alerts whose time to gather more files is up (all, when `all`).
    fn flush(&mut self, all: bool) {
        let now = Instant::now();
        let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending).into_iter().partition(|(_, at)| all || *at <= now);
        self.pending = waiting;
        for (hit, _) in due {
            self.report(hit);
        }
    }

    fn report(&mut self, hit: BrowserHit) {
        if hit.level == Level::High && hit.kind == GuardKind::DataRead && !hit.image.as_os_str().is_empty() {
            // Known malware is quarantined as settings say.
            let _ = self.urgent.send(Item::File { path: hit.image.clone(), announced: false });
        }
        if let Err(e) = record(self.ctx, self.store, &hit) {
            self.ctx.emit(RtpEvent::Error(format!("recording a browser data alert: {e:#}")));
        }
        self.ctx.emit(RtpEvent::BrowserData(hit));
    }
}

fn browser_name(program: &str) -> &'static str {
    match program.to_lowercase().as_str() {
        "chrome.exe" => "Chrome",
        "msedge.exe" => "Edge",
        "brave.exe" => "Brave",
        "opera.exe" => "Opera",
        "vivaldi.exe" => "Vivaldi",
        "browser.exe" => "Yandex Browser",
        _ => "Chromium",
    }
}

fn record(ctx: &Ctx<'_>, store: &Store, hit: &BrowserHit) -> anyhow::Result<()> {
    let path = if hit.image.as_os_str().is_empty() { hit.program.clone() } else { hit.image.display().to_string() };
    let mut details = vec![hit.headline(), format!("why: {}", hit.reason)];
    if let Some(signer) = &hit.signer {
        details.push(format!("signed by {signer}"));
    }
    if !hit.files.is_empty() {
        details.push(format!("files: {}", hit.files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>().join(", ")));
    }
    if !hit.switches.is_empty() {
        details.push(format!("started with {}", hit.switches.join(" ")));
    }
    if !hit.connections.is_empty() {
        details.push(format!("connected to {}", hit.connections.join(", ")));
    }
    details.push(format!("pid {}", hit.pid));
    let finding = Finding {
        threat: match hit.kind {
            GuardKind::DataRead => "BrowserData.Read".into(),
            GuardKind::RemoteControl => "BrowserData.RemoteControl".into(),
        },
        category: Category::Suspicious,
        source: Source::Heuristic,
        details: details.join(" · "),
    };
    let scan_id = store.begin_scan(&ScanMeta { kind: "browser", targets: &path, threads: 1, signatures: ctx.config.signatures.as_deref() })?;
    store.add_detection(scan_id, &path, "", &finding, &hit.action())?;
    let stats = ScanStats { files_scanned: 1, detections: 1, ..Default::default() };
    store.finish_scan(scan_id, &stats, 0, false)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = r"C:\Users\me\AppData\Local\Google\Chrome\User Data";

    #[test]
    fn browser_secrets_are_recognised_by_name_and_folder() {
        let cases = [
            (format!(r"{CHROME}\Default\Login Data"), Some(("Chrome", "saved passwords"))),
            (format!(r"{CHROME}\Profile 2\Network\Cookies"), Some(("Chrome", "sign-in cookies"))),
            (format!(r"{CHROME}\Local State"), Some(("Chrome", "key that unlocks saved passwords and cookies"))),
            (format!(r"{CHROME}\Default\Web Data"), Some(("Chrome", "saved cards and addresses"))),
            (format!(r"{CHROME}\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log"), Some(("Chrome", "extension data, such as crypto wallets"))),
            (r"\Device\HarddiskVolume3\Users\me\AppData\Local\Microsoft\Edge\User Data\Default\login data".into(), Some(("Edge", "saved passwords"))),
            (r"C:\Users\me\AppData\Roaming\Opera Software\Opera Stable\Login Data".into(), Some(("Opera", "saved passwords"))),
            (r"C:\Users\me\AppData\Local\Unknown\Thing\User Data\Default\Cookies".into(), Some(("a Chromium-based browser", "sign-in cookies"))),
            (r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json".into(), Some(("Firefox", "saved passwords"))),
            (r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\key4.db".into(), Some(("Firefox", "key that unlocks saved passwords"))),
            // Journals, Electron apps' own cookies, files elsewhere: not secrets.
            (format!(r"{CHROME}\Default\Network\Cookies-journal"), None),
            (r"C:\Users\me\AppData\Roaming\discord\Network\Cookies".into(), None),
            (r"D:\Backup\Google\Chrome\User Data\Default\Login Data".into(), None),
            (format!(r"{CHROME}\Default\Local Storage\leveldb\000003.log"), None),
            (r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\x\Login Data".into(), None),
        ];
        for (path, want) in cases {
            assert_eq!(secret(&path).map(|s| (s.browser, s.data)), want, "{path}");
        }
    }

    fn signed(by: &str) -> Trust {
        Trust::Signed { signer: Some(by.into()), catalog: false }
    }

    #[test]
    fn who_opened_the_file_decides_what_happens() {
        let level = |image: &str, trust: Trust| judge(Path::new(image), &trust, &[], Some(Path::new(r"C:\Program Files\Phalanx"))).map(|(l, _)| l);
        assert_eq!(level(r"C:\Program Files\Google\Chrome\Application\chrome.exe", signed("Google LLC")), None);
        assert_eq!(level(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", signed("Microsoft Corporation")), None);
        assert_eq!(level(r"C:\Windows\System32\SearchProtocolHost.exe", signed("Microsoft Windows")), None);
        assert_eq!(level(r"C:\Program Files\Phalanx\phalanx.exe", Trust::Unsigned), None, "Phalanx's own browser checks");
        // Signed by Microsoft, but a tool that runs whatever it is given.
        assert_eq!(level(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", signed("Microsoft Windows")), Some(Level::High));
        assert_eq!(level(r"C:\Windows\System32\esentutl.exe", signed("Microsoft Windows")), Some(Level::High));
        assert_eq!(level(r"C:\Users\me\AppData\Local\Temp\x\update.exe", Trust::Unsigned), Some(Level::High));
        assert_eq!(level(r"C:\Users\me\Downloads\crack.exe", Trust::Tampered), Some(Level::High));
        assert_eq!(level(r"C:\Program Files\Backup\backup.exe", signed("Acme Backup Ltd")), Some(Level::Review));
        // A stealer named like a browser is still unsigned.
        assert_eq!(level(r"C:\Users\me\AppData\Roaming\chrome.exe", Trust::Unsigned), Some(Level::High));

        let allowed = [PathBuf::from(r"c:\tools\MYTOOL.exe")];
        assert_eq!(judge(Path::new(r"C:\Tools\mytool.exe"), &Trust::Unsigned, &allowed, None), None, "allowed by the person");
    }

    #[test]
    fn remote_control_of_an_existing_profile_is_caught() {
        let none = |_: &Path| false;
        let level = |cmd: &str| remote_control(cmd, none).map(|(l, _)| l);
        // The real profile, hidden: a hijack.
        assert_eq!(level(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --remote-debugging-port=9222"#), Some(Level::High));
        assert_eq!(level(&format!(r#"chrome.exe --remote-debugging-port=9222 "--user-data-dir={CHROME}" --window-position=-32000,-32000"#)), Some(Level::High));
        // The real profile, on screen: someone may be debugging on purpose.
        assert_eq!(level("msedge.exe --remote-debugging-port=9222"), Some(Level::Review));
        // A fresh automation profile, and the browser's own child processes.
        assert_eq!(level(r"chrome.exe --headless --remote-debugging-port=0 --user-data-dir=C:\Users\me\AppData\Local\Temp\puppeteer_dev_profile-x"), None);
        assert_eq!(level(r"chrome.exe --type=renderer --remote-debugging-port=9222"), None);
        assert_eq!(level("chrome.exe --profile-directory=Default"), None);
        // A copy of a used profile is as good as the real one.
        let copied = |dir: &Path| dir.ends_with("copy");
        let (got, switches) = remote_control(r#"chrome.exe --headless --remote-debugging-pipe --user-data-dir="C:\Temp\copy""#, copied).unwrap();
        assert_eq!(got, Level::High);
        assert_eq!(switches, ["--remote-debugging-pipe", "--headless", "--user-data-dir"]);
    }

    #[test]
    fn switch_values_are_read_quoted_or_not() {
        assert_eq!(switch_value(r#"x --user-data-dir="C:\A B" --y"#, "--user-data-dir").as_deref(), Some(r"C:\A B"));
        assert_eq!(switch_value(r#"x "--user-data-dir=C:\A B" --y"#, "--user-data-dir").as_deref(), Some(r"C:\A B"));
        assert_eq!(switch_value(r"x --User-Data-Dir=C:\A --y", "--user-data-dir").as_deref(), Some(r"C:\A"));
        assert_eq!(switch_value("x --window-position=-32000,-32000", "--window-position").as_deref(), Some("-32000,-32000"));
        assert_eq!(switch_value("x --headless", "--user-data-dir"), None);
    }

    #[test]
    fn headlines_and_actions_read_plainly() {
        let mut hit = BrowserHit {
            kind: GuardKind::DataRead,
            level: Level::High,
            pid: 7,
            created: 1,
            program: "update.exe".into(),
            image: PathBuf::from(r"C:\Temp\update.exe"),
            signer: None,
            browser: "Chrome".into(),
            data: vec!["saved passwords".into(), "sign-in cookies".into(), "key that unlocks saved passwords and cookies".into()],
            files: Vec::new(),
            switches: Vec::new(),
            reason: String::new(),
            connections: Vec::new(),
            stopped: Some(Ok(())),
            controller: None,
        };
        assert_eq!(hit.headline(), "update.exe opened Chrome's saved passwords, sign-in cookies and key that unlocks saved passwords and cookies");
        assert_eq!(hit.action(), "program stopped");
        hit.stopped = None;
        assert_eq!(hit.action(), "reported (automatic stopping is off)");
        hit.kind = GuardKind::RemoteControl;
        hit.controller = Some(Controller { pid: 8, program: "loader.exe".into(), image: PathBuf::new(), stopped: Some(Ok(())) });
        assert_eq!(hit.headline(), "loader.exe started Chrome for remote control with your profile");
        assert_eq!(hit.action(), "reported (automatic stopping is off); loader.exe stopped");
    }
}
