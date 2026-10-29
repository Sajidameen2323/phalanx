//! Browser data watch: programs other than the browser opening the files
//! where browsers keep saved passwords, sign-in cookies, cards and the key
//! that unlocks them (and where Discord, Telegram and crypto wallets keep
//! their sign-in data and keys), browsers started to be remote-controlled
//! or with a planted extension, unsigned code loaded into a browser, and
//! programs reading a browser's memory. These are how infostealers take
//! over accounts: a stolen session cookie skips the password and the second
//! factor, so the thief can read email (password-reset codes included) as if
//! signed in.
//!
//! Everything comes from one ETW session ([`etw::start_file_opens`]): file
//! opens from Microsoft-Windows-Kernel-File, filtered by name on the
//! session's thread so only the few opens of those files reach this module;
//! process starts; and, for the browsers running (the watched set), the DLLs
//! they load and every `OpenProcess` of them with rights to read or change
//! their memory. Watching every file open costs some CPU and a few MB of
//! event buffers, which is why the watch is a switch of its own (off by
//! default). Needs administrator rights, so in practice the service.
//!
//! Who opened a file decides what happens:
//!
//! * the browser or app itself, another program signed by a browser maker,
//!   or one of Windows' own readers (search, Defender, Explorer, backup):
//!   nothing;
//! * a script host or a Windows tool that copies or sends files
//!   (PowerShell, `curl`, `esentutl`, `robocopy`, Python…), or an unsigned
//!   program: **high**, stopped at once when automatic stopping is on, and
//!   its file scanned;
//! * any other signed program, Microsoft's other programs included (a backup
//!   tool, a password manager importing): reported for review, never
//!   stopped.
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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

/// Without the event session, how often it is tried again.
const RETRY: Duration = Duration::from_secs(60);
/// Files the same program opens this soon after the first join its alert.
const GATHER: Duration = Duration::from_millis(400);
/// How long a file alert for a program not yet known waits for its start.
const IDENTIFY_WAIT: Duration = Duration::from_secs(2);
/// A signed program is reported at most this often per browser.
const REVIEW_EVERY: Duration = Duration::from_secs(60 * 60);
/// How long an exited program is remembered. Windows can deliver a file
/// open after the exit of the program that made it.
const EXITED_KEEP: Duration = Duration::from_secs(60);
/// How often Windows is asked whether it dropped events.
const LOST_CHECK: Duration = Duration::from_secs(60);
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
    /// A program opened a browser's (or app's) password, cookie or key file.
    DataRead,
    /// A browser was started for remote control with an existing profile,
    /// or with an extension loaded from a folder users can write to.
    RemoteControl,
    /// An unsigned DLL was loaded into a browser.
    Injected,
    /// A program opened a browser with rights to read or change its memory.
    MemoryRead,
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
    /// The process concerned: the reader (a data or memory read), or the
    /// browser (remote control, injected code).
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
    /// `Chrome`, `Edge`, `Firefox`, `Discord`…
    pub browser: String,
    /// What it reached, in plain words ("saved passwords").
    pub data: Vec<String>,
    /// The files it opened (a data read), or the DLL loaded (injected code).
    pub files: Vec<PathBuf>,
    /// The switches it was started with (remote control).
    pub switches: Vec<String>,
    /// Why it was judged so, in plain words.
    pub reason: String,
    /// Where it was connected when caught (outside this PC).
    pub connections: Vec<String>,
    /// `None` when left running; otherwise whether stopping it worked.
    pub stopped: Option<Result<(), String>>,
    /// It had exited by the time it was caught, so there was nothing to stop.
    #[serde(default)]
    pub exited: bool,
    /// Remote control: the program that started the browser.
    pub controller: Option<Controller>,
}

impl BrowserHit {
    /// What happened, in plain words.
    pub fn headline(&self) -> String {
        match self.kind {
            GuardKind::DataRead => format!("{} opened {}'s {}", self.program, self.browser, join(&self.data)),
            GuardKind::RemoteControl if !self.switches.iter().any(|s| s.starts_with("--remote-debugging")) => {
                format!("{} was started with an extension loaded from a folder any program can write to", self.browser)
            }
            GuardKind::RemoteControl => match &self.controller {
                Some(c) => format!("{} started {} for remote control with your profile", c.program, self.browser),
                None => format!("{} was started for remote control with your profile", self.browser),
            },
            GuardKind::Injected => {
                let dll = self.files.first().and_then(|f| f.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                format!("An unsigned {dll} was loaded into {}", self.browser)
            }
            GuardKind::MemoryRead => format!("{} opened {} to read its memory, where signed-in sessions are kept", self.program, self.browser),
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
            (None, Level::High) if self.exited || self.created == 0 => "reported (it had already exited)".into(),
            (None, Level::High) => "reported (automatic stopping is off)".into(),
            (None, Level::Review) => "reported (not stopped)".into(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
}

/// Whose a data file is: a browser's, or an app's (whose own programs, by
/// name prefix or signer, may read it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Browser,
    App { programs: &'static [&'static str], signers: &'static [&'static str] },
}

/// A data file stealers take: whose it is, and what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secret {
    /// The browser's or app's name.
    pub browser: &'static str,
    pub data: &'static str,
    pub owner: Owner,
}

/// Browser data folders (lowercase, as they appear in a path) and the
/// browser's name.
const BROWSER_FOLDERS: &[(&str, Family, &str)] = &[
    (r"\google\chrome", Family::Chromium, "Chrome"),
    (r"\microsoft\edge", Family::Chromium, "Edge"),
    (r"\bravesoftware\", Family::Chromium, "Brave"),
    (r"\opera software\", Family::Chromium, "Opera"),
    (r"\vivaldi\", Family::Chromium, "Vivaldi"),
    (r"\yandex\yandexbrowser\", Family::Chromium, "Yandex Browser"),
    (r"\chromium\", Family::Chromium, "Chromium"),
    (r"\mozilla\firefox\", Family::Firefox, "Firefox"),
    (r"\firefoxportable\", Family::Firefox, "Firefox"),
    (r"\waterfox\", Family::Firefox, "Waterfox"),
    (r"\librewolf\", Family::Firefox, "LibreWolf"),
    (r"\thunderbird\", Family::Firefox, "Thunderbird"),
];

/// An app whose sign-in data or wallet keys stealers take: the folder (in
/// AppData, lowercase), the app, what it holds, and the app's own programs
/// (file-name prefixes) and signers.
type AppFolder = (&'static str, &'static str, &'static str, &'static [&'static str], &'static [&'static str]);

const APP_FOLDERS: &[AppFolder] = &[
    (r"\appdata\roaming\discord\local storage\leveldb\", "Discord", "sign-in token", &["discord"], &["Discord"]),
    (r"\appdata\roaming\discordcanary\local storage\leveldb\", "Discord", "sign-in token", &["discord"], &["Discord"]),
    (r"\appdata\roaming\discordptb\local storage\leveldb\", "Discord", "sign-in token", &["discord"], &["Discord"]),
    (r"\appdata\roaming\telegram desktop\tdata\", "Telegram", "sign-in session", &["telegram"], &["Telegram"]),
    (r"\appdata\roaming\exodus\exodus.wallet\", "Exodus", "crypto wallet", &["exodus"], &["Exodus"]),
    (r"\appdata\roaming\electrum\wallets\", "Electrum", "crypto wallet", &["electrum"], &["Electrum"]),
    (r"\appdata\roaming\atomic\local storage\leveldb\", "Atomic Wallet", "crypto wallet", &["atomic"], &["Atomic"]),
    (r"\appdata\roaming\ledger live\", "Ledger Live", "crypto wallet data", &["ledger"], &["Ledger"]),
    (r"\appdata\roaming\ethereum\keystore\", "Ethereum", "crypto wallet keys", &["geth"], &[]),
];

/// Whether `path` (a drive or NT path, any case) is a file stealers take.
/// Called for every file opened on the PC: the browser files are told by
/// name first, and the path is lowercased once for the few folder checks.
pub fn secret(path: &str) -> Option<Secret> {
    let name = path.rsplit(['\\', '/']).next()?;
    let is = |n: &str| name.eq_ignore_ascii_case(n);
    let browser_file = if is("Login Data") || is("Login Data For Account") {
        Some((Family::Chromium, "saved passwords"))
    } else if is("Cookies") {
        Some((Family::Chromium, "sign-in cookies"))
    } else if is("Web Data") {
        Some((Family::Chromium, "saved cards and addresses"))
    } else if is("Local State") {
        Some((Family::Chromium, "key that unlocks saved passwords and cookies"))
    } else if is("logins.json") {
        Some((Family::Firefox, "saved passwords"))
    } else if is("key4.db") || is("key3.db") {
        Some((Family::Firefox, "key that unlocks saved passwords"))
    } else if is("cookies.sqlite") {
        Some((Family::Firefox, "sign-in cookies"))
    } else {
        None
    };
    let lower = path.to_ascii_lowercase();
    if let Some((family, data)) = browser_file {
        let in_appdata = lower.contains(r"\appdata\");
        let browser = BROWSER_FOLDERS
            .iter()
            .find(|(folder, f, _)| *f == family && lower.contains(folder) && (in_appdata || folder.ends_with("portable\\")))
            .map(|(_, _, name)| *name)
            // A Chromium profile anywhere (portable browsers, profiles on
            // another drive) has a `User Data` folder.
            .or_else(|| (family == Family::Chromium && lower.contains(r"\user data\")).then_some("a Chromium-based browser"))?;
        return Some(Secret { browser, data, owner: Owner::Browser });
    }
    if !lower.contains(r"\appdata\") {
        return None;
    }
    if leveldb_file(name) && lower.contains(r"\local extension settings\") {
        let browser = BROWSER_FOLDERS.iter().find(|(folder, f, _)| *f == Family::Chromium && lower.contains(folder)).map_or("a Chromium-based browser", |(_, _, n)| *n);
        return Some(Secret { browser, data: "extension data, such as crypto wallets", owner: Owner::Browser });
    }
    if is("wallet.dat") {
        let wallets: &[&str] = &["bitcoin", "litecoin", "dogecoin", "dash"];
        return Some(Secret { browser: "a crypto wallet app", data: "crypto wallet", owner: Owner::App { programs: wallets, signers: &[] } });
    }
    APP_FOLDERS.iter().find(|(folder, ..)| lower.contains(folder)).map(|(_, app, data, programs, signers)| Secret {
        browser: app,
        data,
        owner: Owner::App { programs, signers },
    })
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

/// Script hosts, and Windows tools that copy, pack or send files: signed,
/// but what they do is up to whoever runs them, and stealers run them to
/// copy or upload browser files.
const TOOLS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "esentutl.exe", "certutil.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe",
    "curl.exe", "tar.exe", "robocopy.exe", "xcopy.exe", "expand.exe", "makecab.exe", "bitsadmin.exe", "ftp.exe", "scp.exe",
    "sftp.exe", "certreq.exe", "forfiles.exe", "conhost.exe", "msxsl.exe", "odbcconf.exe", "cmstp.exe", "diskshadow.exe",
    "python.exe", "pythonw.exe", "py.exe", "node.exe", "autoit3.exe", "autohotkey.exe", "java.exe", "javaw.exe",
];

/// Microsoft's programs with a reason to open browser data: Windows Search,
/// Defender, Explorer, backup and sync, and Edge's (Edge importing from
/// Chrome). Other Microsoft programs are reported for review.
const MICROSOFT_READERS: &[&str] = &[
    "explorer.exe", "searchprotocolhost.exe", "searchindexer.exe", "searchfilterhost.exe", "msmpeng.exe",
    "mpdefendercoreservice.exe", "nissrv.exe", "mpcmdrun.exe", "svchost.exe", "filehistory.exe", "wbengine.exe",
    "onedrive.exe", "dllhost.exe", "backgroundtaskhost.exe", "msedge.exe", "msedgewebview2.exe", "identity_helper.exe",
    "elevation_service.exe",
];

/// Signers of browsers other than Microsoft's, whose programs (browsers,
/// updaters, helpers) may read browser data.
const BROWSER_MAKERS: &[&str] = &["Google", "Brave Software", "Opera Norway", "Vivaldi Technologies", "Mozilla", "YANDEX"];

/// Chromium browsers' program names: the ones started for remote control.
const CHROMIUM_BROWSERS: &[&str] = &["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "chromium.exe"];
/// Every browser whose loaded DLLs and memory are watched.
const BROWSERS: &[&str] = &[
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "chromium.exe", "firefox.exe",
    "waterfox.exe", "librewolf.exe",
];

fn same_path(a: &Path, b: &Path) -> bool {
    a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
}

fn allowed_here(image: &Path, allowed: &[PathBuf], own_dir: Option<&Path>) -> bool {
    allowed.iter().any(|a| same_path(a, image)) || own_dir.is_some_and(|dir| image.parent().is_some_and(|p| same_path(p, dir)))
}

fn file_name(image: &Path) -> String {
    image.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default()
}

/// Why an unsigned program is high, or `None` when it is signed.
fn unsigned_reason(trust: &Trust) -> Option<String> {
    match trust {
        Trust::Signed { .. } => None,
        Trust::Unsigned => Some("it is not digitally signed".into()),
        Trust::Tampered => Some("it was changed after it was signed".into()),
        Trust::Invalid(why) => Some(format!("its signature does not verify ({why})")),
        Trust::Unknown(why) => Some(format!("its signature could not be checked ({why})")),
    }
}

/// Whether `image` may open `secret` and, if not, how sure it is to be a
/// stealer and why. `own_dir` is Phalanx's folder (its browser checks read
/// these files too); `allowed` the programs people allowed.
pub fn judge(image: &Path, trust: &Trust, secret: &Secret, allowed: &[PathBuf], own_dir: Option<&Path>) -> Option<(Level, String)> {
    if allowed_here(image, allowed, own_dir) {
        return None;
    }
    let name = file_name(image);
    if TOOLS.contains(&name.as_str()) {
        return Some((Level::High, "it is a script host or a Windows tool that copies or sends files, which stealers use".into()));
    }
    let signer = match trust {
        Trust::Signed { signer, .. } => Some(signer.as_deref().unwrap_or("an unnamed publisher")),
        _ => None,
    };
    if let Owner::App { programs, signers } = secret.owner {
        let named_like = programs.iter().any(|p| name.starts_with(p));
        if signer.is_some_and(|s| named_like || signers.iter().any(|x| contains(s, x))) {
            return None;
        }
        if named_like {
            return Some((Level::Review, format!("it is named like {}'s own program but is not signed, so it was only reported", secret.browser)));
        }
    }
    match signer {
        Some(s) if contains(s, "Microsoft") => {
            let lower = image.to_string_lossy().to_lowercase();
            if MICROSOFT_READERS.contains(&name.as_str()) || lower.contains(r"\microsoft\edge") {
                return None;
            }
            Some((Level::Review, format!("it is a Microsoft program ({name}) with no usual reason to open this, so it was only reported")))
        }
        Some(s) if secret.owner == Owner::Browser && BROWSER_MAKERS.iter().any(|m| contains(s, m)) => None,
        Some(s) => Some((Level::Review, format!("it is signed by {s}; a backup tool or password manager may do this, so it was only reported"))),
        None => unsigned_reason(trust).map(|why| (Level::High, why)),
    }
}

/// Whether `image` may open a browser with rights to read its memory.
/// Windows' own programs (crash reporting, Task Manager, Defender) and the
/// browsers themselves do; script hosts and unsigned programs should not.
/// Other signed programs (anti-cheat, game overlays, mouse and keyboard
/// software, screen recorders) open every window's process and are only
/// reported when they run from where downloads and droppers land.
pub fn judge_memory(image: &Path, trust: &Trust, allowed: &[PathBuf], own_dir: Option<&Path>) -> Option<(Level, String)> {
    if allowed_here(image, allowed, own_dir) {
        return None;
    }
    if TOOLS.contains(&file_name(image).as_str()) {
        return Some((Level::High, "it is a script host or Windows tool, which cookie-stealing tools run in".into()));
    }
    match trust {
        Trust::Signed { signer, .. } => {
            let s = signer.as_deref().unwrap_or("an unnamed publisher");
            if !dropped(image) {
                return None;
            }
            Some((Level::Review, format!("it is signed by {s} but runs from a folder where downloads and droppers land, so it was reported")))
        }
        _ => unsigned_reason(trust).map(|why| (Level::High, format!("{why}; reading a browser's memory gets its sign-in cookies without touching its files"))),
    }
}

/// Folders only administrators can change, lowercase with a trailing `\`
/// (Windows' own and Program Files). `C:\Windows\Temp` is not one.
fn protected_folders() -> Vec<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let program_files = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|v| std::env::var(v).ok());
    std::iter::once(root).chain(program_files).map(|p| format!("{}\\", p.trim_end_matches('\\').to_lowercase())).collect()
}

fn is_protected(path: &Path, protected: &[String]) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    protected.iter().any(|p| lower.starts_with(p.as_str())) && !lower.contains(r"\windows\temp\")
}

/// How serious an unsigned DLL loaded into a browser is: high from folders
/// where downloads and droppers land, review from anywhere else outside
/// the protected folders. `None` for a signed DLL.
pub fn judge_dll(dll: &Path, trust: &Trust) -> Option<(Level, String)> {
    let why = unsigned_reason(trust)?;
    Some(if dropped(dll) {
        (Level::High, format!("{why} and it came from a folder where downloads and droppers land; code inside the browser can take its sign-in cookies"))
    } else {
        (Level::Review, format!("{why}; code inside the browser can take its sign-in cookies, but some apps add plugins this way, so it was only reported"))
    })
}

/// Whether `path` is in a folder where downloads and droppers land.
fn dropped(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    [r"\temp\", r"\downloads\", r"\users\public\"].iter().any(|f| lower.contains(f))
}

/// A browser start worth an alert: what it was started with and how sure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub level: Level,
    pub switches: Vec<String>,
    /// Remote debugging on an existing profile.
    pub debugging: bool,
    /// An extension loaded from a folder users can write to.
    pub extension: Option<String>,
}

/// Whether a browser's command line starts it for remote control with an
/// existing profile, or loads an extension from a folder users can write
/// to, and how sure that is a hijack: high when it was also hidden
/// (headless or off screen). The browser's own child processes, and
/// automation with a fresh profile (how developers test), are left alone.
/// `existing_profile` says whether a profile folder already has data.
pub fn launch(command: &str, existing_profile: impl Fn(&Path) -> bool) -> Option<Launch> {
    if contains(command, "--type=") {
        return None;
    }
    let real_profile = || match switch_value(command, "--user-data-dir") {
        None => true,
        Some(dir) => {
            let dir = dir.trim_end_matches(['\\', '/']);
            let lower = dir.to_lowercase();
            lower.ends_with(r"\user data") || lower.ends_with(r"\opera stable") || existing_profile(Path::new(dir))
        }
    };
    let debugging = (contains(command, "--remote-debugging-port") || contains(command, "--remote-debugging-pipe")) && real_profile();
    let extension = switch_value(command, "--load-extension")
        .filter(|list| list.split(',').any(|p| !p.trim().to_lowercase().contains(r"\program files")));
    if !debugging && extension.is_none() {
        return None;
    }
    let off_screen = switch_value(command, "--window-position")
        .is_some_and(|pos| pos.split(',').any(|n| n.trim().parse::<i64>().is_ok_and(|n| n <= -1000)));
    let hidden = contains(command, "--headless") || contains(command, "--no-startup-window") || off_screen;
    let switches = [
        "--remote-debugging-port", "--remote-debugging-pipe", "--remote-allow-origins", "--load-extension", "--headless",
        "--no-startup-window", "--window-position", "--user-data-dir",
    ]
    .iter()
    .filter(|s| contains(command, s))
    .map(|s| s.to_string())
    .collect();
    Some(Launch { level: if hidden { Level::High } else { Level::Review }, switches, debugging, extension })
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
    protected: Vec<String>,
    /// Browsers running, by id: the session reports their DLL loads and
    /// who opens them.
    browsers: etw::Watched,
    /// Processes started since the session began, by id.
    live: HashMap<u32, ProcessInfo>,
    /// …and those of them that exited lately.
    exited: Exited,
    /// Each process is judged once, when it first opens a file.
    judged: HashMap<ProcessId, bool>,
    /// …and once when it first opens a browser's memory.
    judged_memory: HashSet<ProcessId>,
    /// DLLs already looked at, per browser process.
    dlls: HashSet<(u32, PathBuf)>,
    signatures: HashMap<PathBuf, Trust>,
    /// Alerts waiting for more files from the same program.
    pending: Vec<(BrowserHit, Instant)>,
}

/// Programs that exited lately, so an event that arrives after the exit can
/// still name the program (and judge it) instead of reporting an unknown one.
#[derive(Default)]
struct Exited(HashMap<u32, (ProcessInfo, Instant)>);

impl Exited {
    fn remember(&mut self, info: ProcessInfo) {
        let now = Instant::now();
        self.0.retain(|_, (_, at)| now.duration_since(*at) < EXITED_KEEP);
        if self.0.len() < MAX_CACHED {
            self.0.insert(info.id.pid, (info, now));
        }
    }

    /// The id was given to a new process.
    fn forget(&mut self, pid: u32) {
        self.0.remove(&pid);
    }

    fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.0.get(&pid).filter(|(_, at)| at.elapsed() < EXITED_KEEP).map(|(info, _)| info)
    }
}

/// Signed programs reported, by program and what they reached. Kept for the
/// whole service, not one watch: any settings change restarts protection, and
/// that must not report them all again.
static REVIEWED: LazyLock<Mutex<HashMap<(PathBuf, String), Instant>>> = LazyLock::new(Default::default);

/// A signed program already reported for this browser within the hour is
/// not reported again.
fn reviewed_lately(image: &Path, what: &str) -> bool {
    let mut reviewed = REVIEWED.lock().unwrap_or_else(PoisonError::into_inner);
    let key = (image.to_path_buf(), what.to_string());
    if reviewed.get(&key).is_some_and(|t| t.elapsed() < REVIEW_EVERY) {
        return true;
    }
    if reviewed.len() > MAX_CACHED {
        reviewed.retain(|_, t| t.elapsed() < REVIEW_EVERY);
    }
    reviewed.insert(key, Instant::now());
    false
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
        protected: protected_folders(),
        browsers: Arc::new(RwLock::new(HashSet::new())),
        live: HashMap::new(),
        exited: Exited::default(),
        judged: HashMap::new(),
        judged_memory: HashSet::new(),
        dlls: HashSet::new(),
        signatures: HashMap::new(),
        pending: Vec::new(),
    };
    let mut announced = None;
    while !ctx.halted() {
        let (tx, rx) = mpsc::channel();
        let name = format!("{} browser data", etw::session_name());
        let session = match etw::start_file_opens(&name, wanted, Arc::clone(&watch.browsers), tx) {
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
        // Browsers already running; those that start are added as they do.
        watch.seed_browsers();
        ctx.emit(RtpEvent::BrowserGuard { active: true, reason: None });
        announced = Some(None);
        let (mut lost, mut lost_checked) = (session.events_lost().unwrap_or(0), Instant::now());
        while !ctx.halted() {
            let wait = watch.pending.iter().map(|(_, due)| due.saturating_duration_since(Instant::now())).min().unwrap_or(Duration::from_millis(500));
            match rx.recv_timeout(wait.min(Duration::from_millis(500))) {
                Ok(etw::Event::Started(info)) => {
                    if BROWSERS.contains(&info.name.to_lowercase().as_str()) {
                        watch.browsers.write().unwrap_or_else(PoisonError::into_inner).insert(info.id.pid);
                    }
                    watch.exited.forget(info.id.pid);
                    watch.live.insert(info.id.pid, info.clone());
                    watch.started(&info);
                }
                Ok(etw::Event::Stopped { pid }) => {
                    watch.browsers.write().unwrap_or_else(PoisonError::into_inner).remove(&pid);
                    if let Some(info) = watch.live.remove(&pid) {
                        watch.exited.remember(info);
                    }
                    watch.judged.retain(|id, _| id.pid != pid);
                    watch.judged_memory.retain(|id| id.pid != pid);
                    watch.dlls.retain(|(p, _)| *p != pid);
                }
                Ok(etw::Event::FileOpened { pid, path }) => watch.opened(pid, path),
                Ok(etw::Event::ImageLoaded { pid, image }) => watch.loaded(pid, image),
                Ok(etw::Event::ProcessOpened { pid, target, .. }) => watch.memory_opened(pid, target),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            watch.flush(false);
            if lost_checked.elapsed() >= LOST_CHECK {
                lost_checked = Instant::now();
                if let Some(now) = session.events_lost() && now > lost {
                    ctx.emit(RtpEvent::Error(format!(
                        "the browser data watch missed {} events in the last minute: the disk was very busy and Windows' event buffers were full. Programs opening browser data then may have gone unseen.",
                        now - lost
                    )));
                    lost = now;
                }
            }
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

    /// Like [`Self::info`], but also a program that exited lately: `true` then.
    fn info_or_exited(&self, pid: u32) -> Option<(ProcessInfo, bool)> {
        match self.info(pid) {
            Some(info) => Some((info, false)),
            None => self.exited.get(pid).map(|info| (info.clone(), true)),
        }
    }

    fn seed_browsers(&mut self) {
        let Ok(listed) = process::listed() else { return };
        let mut browsers = self.browsers.write().unwrap_or_else(PoisonError::into_inner);
        browsers.clear();
        browsers.extend(listed.iter().filter(|p| BROWSERS.contains(&p.name.to_lowercase().as_str())).map(|p| p.pid));
    }

    fn is_browser(&self, pid: u32) -> bool {
        self.browsers.read().unwrap_or_else(PoisonError::into_inner).contains(&pid)
    }

    fn signer(trust: &Trust) -> Option<String> {
        match trust {
            Trust::Signed { signer, .. } => signer.clone(),
            _ => None,
        }
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
        let found = self.info_or_exited(pid);
        let gone = found.as_ref().is_some_and(|(_, gone)| *gone);
        let info = found.map(|(info, _)| info);
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
                let verdict = judge(&info.image, &trust, &secret, &self.ctx.config.browser_guard_allowed, self.own_dir.as_deref());
                self.judged.insert(info.id.clone(), verdict.is_some());
                let Some((level, reason)) = verdict else { return };
                (level, reason, Self::signer(&trust))
            }
            None => (Level::High, "it exited before it could be identified".to_string(), None),
        };
        if level == Level::Review && let Some(info) = &info && reviewed_lately(&info.image, secret.browser) {
            return;
        }
        // Where it is connected, read before it is stopped.
        let connections = net::connections(pid).iter().map(ToString::to_string).collect();
        let stop = level == Level::High && self.ctx.config.browser_guard_stop;
        let stopped = match &info {
            Some(info) if stop && !gone => Some(process::terminate(&info.id)),
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
            exited: gone || info.is_none(),
            controller: None,
        };
        // Windows can deliver a program's start after its file opens; one not
        // yet known is looked up again before it is reported.
        let wait = if info.is_none() { IDENTIFY_WAIT } else { GATHER };
        self.pending.push((hit, Instant::now() + wait));
    }

    /// A file alert held for a program that was not yet known: judged again
    /// now that its start may have arrived. `None` when it may open it.
    fn identify_late(&mut self, mut hit: BrowserHit) -> Option<BrowserHit> {
        if hit.kind != GuardKind::DataRead || !hit.image.as_os_str().is_empty() {
            return Some(hit);
        }
        let Some((info, gone)) = self.info_or_exited(hit.pid) else { return Some(hit) };
        let secret = secret(&hit.files.first()?.to_string_lossy())?;
        let trust = self.trust(&info.image);
        let verdict = judge(&info.image, &trust, &secret, &self.ctx.config.browser_guard_allowed, self.own_dir.as_deref());
        self.judged.insert(info.id.clone(), verdict.is_some());
        let (level, reason) = verdict?;
        if level == Level::Review && reviewed_lately(&info.image, secret.browser) {
            return None;
        }
        let stop = level == Level::High && self.ctx.config.browser_guard_stop && !gone;
        hit.level = level;
        hit.reason = reason;
        hit.created = info.id.created;
        hit.program = info.name.clone();
        hit.signer = Self::signer(&trust);
        hit.stopped = stop.then(|| process::terminate(&info.id));
        hit.exited = gone && hit.stopped.is_none();
        hit.image = info.image;
        Some(hit)
    }

    /// A DLL loaded into a browser: an unsigned one from outside the
    /// protected folders is reported, and the browser process it runs in
    /// stopped when it came from where downloads land.
    fn loaded(&mut self, pid: u32, dll: PathBuf) {
        if !self.is_browser(pid) || is_protected(&dll, &self.protected) || !self.dlls.insert((pid, dll.clone())) {
            return;
        }
        if self.dlls.len() > MAX_CACHED * 10 {
            self.dlls.clear();
        }
        let trust = self.trust(&dll);
        let Some((level, reason)) = judge_dll(&dll, &trust) else { return };
        let Some(info) = self.info(pid) else { return };
        if allowed_here(&dll, &self.ctx.config.browser_guard_allowed, None) {
            return;
        }
        if level == Level::Review && reviewed_lately(&dll, "injected") {
            return;
        }
        let stop = level == Level::High && self.ctx.config.browser_guard_stop;
        let _ = self.urgent.send(Item::File { path: dll.clone(), announced: false });
        let browser_trust = self.trust(&info.image);
        let hit = BrowserHit {
            kind: GuardKind::Injected,
            level,
            pid,
            created: info.id.created,
            program: info.name.clone(),
            image: info.image.clone(),
            signer: Self::signer(&browser_trust),
            browser: browser_name(&info.name).into(),
            data: vec!["signed-in sessions".into()],
            files: vec![dll],
            switches: Vec::new(),
            reason,
            connections: net::connections(pid).iter().map(ToString::to_string).collect(),
            stopped: stop.then(|| process::terminate(&info.id)),
            exited: false,
            controller: None,
        };
        self.report(hit);
    }

    /// A program opened a browser with rights to read its memory.
    fn memory_opened(&mut self, pid: u32, target: u32) {
        // Browsers open their own processes all the time.
        if self.is_browser(pid) {
            return;
        }
        let Some((reader, gone)) = self.info_or_exited(pid) else { return };
        if !self.judged_memory.insert(reader.id.clone()) {
            return;
        }
        if self.judged_memory.len() > MAX_CACHED {
            self.judged_memory.clear();
        }
        let trust = self.trust(&reader.image);
        let Some((level, reason)) = judge_memory(&reader.image, &trust, &self.ctx.config.browser_guard_allowed, self.own_dir.as_deref()) else { return };
        if level == Level::Review && reviewed_lately(&reader.image, "memory") {
            return;
        }
        let browser = self.info(target).map_or("a browser", |b| browser_name(&b.name));
        let connections = net::connections(pid).iter().map(ToString::to_string).collect();
        let stop = level == Level::High && self.ctx.config.browser_guard_stop;
        if level == Level::High {
            let _ = self.urgent.send(Item::File { path: reader.image.clone(), announced: false });
        }
        let hit = BrowserHit {
            kind: GuardKind::MemoryRead,
            level,
            pid,
            created: reader.id.created,
            program: reader.name.clone(),
            image: reader.image.clone(),
            signer: Self::signer(&trust),
            browser: browser.into(),
            data: vec!["signed-in sessions in its memory".into()],
            files: Vec::new(),
            switches: Vec::new(),
            reason,
            connections,
            stopped: (stop && !gone).then(|| process::terminate(&reader.id)),
            exited: gone,
            controller: None,
        };
        self.report(hit);
    }

    /// A process started: a Chromium browser started for remote control
    /// with an existing profile, or with an extension from a folder users
    /// can write to, is reported, and stopped when hidden.
    fn started(&mut self, info: &ProcessInfo) {
        if !CHROMIUM_BROWSERS.contains(&info.name.to_lowercase().as_str()) {
            return;
        }
        let Some(command) = process::command_line(&info.id) else { return };
        let Some(launch) = launch(&command, profile_in_use) else { return };
        let level = launch.level;
        let stop = level == Level::High && self.ctx.config.browser_guard_stop;
        // The program that started it, when it is not a browser itself.
        let parent = self.info(info.parent).filter(|p| !CHROMIUM_BROWSERS.contains(&p.name.to_lowercase().as_str()));
        let controller = parent.map(|p| {
            let trust = self.trust(&p.image);
            let any = Secret { browser: "", data: "", owner: Owner::Browser };
            let suspect = judge(&p.image, &trust, &any, &self.ctx.config.browser_guard_allowed, self.own_dir.as_deref()).is_some_and(|(l, _)| l == Level::High);
            let stopped = (stop && suspect).then(|| process::terminate(&p.id));
            if suspect {
                let _ = self.urgent.send(Item::File { path: p.image.clone(), announced: false });
            }
            Controller { pid: p.id.pid, program: p.name, image: p.image, stopped }
        });
        let reason = match (level, launch.debugging) {
            (Level::High, true) => "it was hidden (headless or off screen), so whoever started it can read your signed-in sites, email included, without you seeing".to_string(),
            (Level::Review, true) => "remote debugging lets another program read and act on your signed-in sites; developers use it, but so do stealers".to_string(),
            (Level::High, false) => format!("it was hidden and loaded an extension from {}; an extension can read every signed-in site", launch.extension.unwrap_or_default()),
            (Level::Review, false) => format!("it loaded an extension from {}; an extension can read every signed-in site, so check you added it", launch.extension.unwrap_or_default()),
        };
        let trust = self.trust(&info.image);
        let hit = BrowserHit {
            kind: GuardKind::RemoteControl,
            level,
            pid: info.id.pid,
            created: info.id.created,
            program: info.name.clone(),
            image: info.image.clone(),
            signer: Self::signer(&trust),
            browser: browser_name(&info.name).into(),
            data: vec!["signed-in sites".into()],
            files: Vec::new(),
            switches: launch.switches,
            reason,
            connections: Vec::new(),
            stopped: stop.then(|| process::terminate(&info.id)),
            exited: false,
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
            if let Some(hit) = self.identify_late(hit) {
                self.report(hit);
            }
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
        "firefox.exe" => "Firefox",
        "waterfox.exe" => "Waterfox",
        "librewolf.exe" => "LibreWolf",
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
            GuardKind::Injected => "BrowserData.InjectedCode".into(),
            GuardKind::MemoryRead => "BrowserData.MemoryRead".into(),
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
    fn browser_and_app_secrets_are_recognised_by_name_and_folder() {
        let cases = [
            (format!(r"{CHROME}\Default\Login Data"), Some(("Chrome", "saved passwords"))),
            (format!(r"{CHROME}\Profile 2\Network\Cookies"), Some(("Chrome", "sign-in cookies"))),
            (format!(r"{CHROME}\Local State"), Some(("Chrome", "key that unlocks saved passwords and cookies"))),
            (format!(r"{CHROME}\Default\Web Data"), Some(("Chrome", "saved cards and addresses"))),
            (format!(r"{CHROME}\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log"), Some(("Chrome", "extension data, such as crypto wallets"))),
            (r"\Device\HarddiskVolume3\Users\me\AppData\Local\Microsoft\Edge\User Data\Default\login data".into(), Some(("Edge", "saved passwords"))),
            // A shadow copy keeps its NT path; it is still Chrome's.
            (r"\Device\HarddiskVolumeShadowCopy3\Users\me\AppData\Local\Google\Chrome\User Data\Default\Login Data".into(), Some(("Chrome", "saved passwords"))),
            (r"C:\Users\me\AppData\Roaming\Opera Software\Opera Stable\Login Data".into(), Some(("Opera", "saved passwords"))),
            (r"C:\Users\me\AppData\Local\Unknown\Thing\User Data\Default\Cookies".into(), Some(("a Chromium-based browser", "sign-in cookies"))),
            // Profiles outside AppData: portable browsers, other drives.
            (r"D:\Apps\ChromePortable\Data\User Data\Default\Login Data".into(), Some(("a Chromium-based browser", "saved passwords"))),
            (r"E:\FirefoxPortable\Data\profile\logins.json".into(), Some(("Firefox", "saved passwords"))),
            (r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json".into(), Some(("Firefox", "saved passwords"))),
            (r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\key4.db".into(), Some(("Firefox", "key that unlocks saved passwords"))),
            // Apps stealers take sign-in data and wallets from.
            (r"C:\Users\me\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb".into(), Some(("Discord", "sign-in token"))),
            (r"C:\Users\me\AppData\Roaming\Telegram Desktop\tdata\key_datas".into(), Some(("Telegram", "sign-in session"))),
            (r"C:\Users\me\AppData\Roaming\Exodus\exodus.wallet\seed.seco".into(), Some(("Exodus", "crypto wallet"))),
            (r"C:\Users\me\AppData\Roaming\Bitcoin\wallets\main\wallet.dat".into(), Some(("a crypto wallet app", "crypto wallet"))),
            // Journals, Electron apps' own cookies, files elsewhere: not secrets.
            (format!(r"{CHROME}\Default\Network\Cookies-journal"), None),
            (r"C:\Users\me\AppData\Roaming\discord\Network\Cookies".into(), None),
            (format!(r"{CHROME}\Default\Local Storage\leveldb\000003.log"), None),
            (r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\x\Login Data".into(), None),
            (r"D:\Projects\app\Login Data".into(), None),
            (r"D:\Backup\Telegram Desktop\tdata\key_datas".into(), None),
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
        let chrome = secret(&format!(r"{CHROME}\Default\Login Data")).unwrap();
        let level = |image: &str, trust: Trust| judge(Path::new(image), &trust, &chrome, &[], Some(Path::new(r"C:\Program Files\Phalanx"))).map(|(l, _)| l);
        assert_eq!(level(r"C:\Program Files\Google\Chrome\Application\chrome.exe", signed("Google LLC")), None);
        assert_eq!(level(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", signed("Microsoft Corporation")), None);
        assert_eq!(level(r"C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\setup.exe", signed("Microsoft Corporation")), None);
        assert_eq!(level(r"C:\Windows\System32\SearchProtocolHost.exe", signed("Microsoft Windows")), None);
        assert_eq!(level(r"C:\Program Files\Phalanx\phalanx.exe", Trust::Unsigned), None, "Phalanx's own browser checks");
        // Signed by Microsoft, but tools that run, copy or send whatever they are given.
        assert_eq!(level(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", signed("Microsoft Windows")), Some(Level::High));
        assert_eq!(level(r"C:\Windows\System32\esentutl.exe", signed("Microsoft Windows")), Some(Level::High));
        assert_eq!(level(r"C:\Windows\System32\curl.exe", signed("Microsoft Windows")), Some(Level::High));
        assert_eq!(level(r"C:\Windows\System32\tar.exe", signed("Microsoft Windows")), Some(Level::High));
        // Other Microsoft programs: reported, not trusted blindly.
        assert_eq!(level(r"C:\Windows\System32\notepad.exe", signed("Microsoft Windows")), Some(Level::Review));
        assert_eq!(level(r"C:\Users\me\AppData\Local\Temp\x\update.exe", Trust::Unsigned), Some(Level::High));
        assert_eq!(level(r"C:\Users\me\Downloads\crack.exe", Trust::Tampered), Some(Level::High));
        assert_eq!(level(r"C:\Program Files\Backup\backup.exe", signed("Acme Backup Ltd")), Some(Level::Review));
        // A stealer named like a browser is still unsigned.
        assert_eq!(level(r"C:\Users\me\AppData\Roaming\chrome.exe", Trust::Unsigned), Some(Level::High));

        let allowed = [PathBuf::from(r"c:\tools\MYTOOL.exe")];
        assert_eq!(judge(Path::new(r"C:\Tools\mytool.exe"), &Trust::Unsigned, &chrome, &allowed, None), None, "allowed by the person");
    }

    #[test]
    fn an_apps_own_programs_may_open_its_data() {
        let discord = secret(r"C:\Users\me\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb").unwrap();
        let level = |image: &str, trust: Trust| judge(Path::new(image), &trust, &discord, &[], None).map(|(l, _)| l);
        assert_eq!(level(r"C:\Users\me\AppData\Local\Discord\app-1.0.9\Discord.exe", signed("Discord Inc.")), None);
        assert_eq!(level(r"C:\Users\me\AppData\Local\Discord\Update.exe", signed("Discord Inc.")), None);
        // Named like Discord but unsigned: reported, not stopped.
        assert_eq!(level(r"C:\Users\me\AppData\Local\Temp\discord.exe", Trust::Unsigned), Some(Level::Review));
        // Google's programs may read Chrome's data, not Discord's.
        assert_eq!(level(r"C:\Program Files\Google\Chrome\Application\chrome.exe", signed("Google LLC")), Some(Level::Review));
        assert_eq!(level(r"C:\Users\me\AppData\Roaming\x\grab.exe", Trust::Unsigned), Some(Level::High));
    }

    #[test]
    fn memory_reads_and_loaded_dlls_are_judged() {
        let memory = |image: &str, trust: Trust| judge_memory(Path::new(image), &trust, &[], None).map(|(l, _)| l);
        assert_eq!(memory(r"C:\Program Files (x86)\Steam\steam.exe", signed("Valve Corp.")), None, "signed and installed");
        assert_eq!(memory(r"C:\Riot Games\Riot Client\RiotClientServices.exe", signed("Riot Games, Inc.")), None, "signed anti-cheat");
        assert_eq!(memory(r"C:\Users\me\Downloads\tool.exe", signed("Valve Corp.")), Some(Level::Review), "signed but where droppers land");
        assert_eq!(memory(r"C:\Program Files (x86)\Steam\fake.exe", Trust::Unsigned), Some(Level::High), "unsigned is never let off");
        assert_eq!(memory(r"C:\Windows\System32\WerFault.exe", signed("Microsoft Windows")), None);
        assert_eq!(memory(r"C:\Program Files\Google\Chrome\Application\chrome.exe", signed("Google LLC")), None);
        assert_eq!(memory(r"C:\Users\me\AppData\Local\Temp\katz.exe", Trust::Unsigned), Some(Level::High));
        assert_eq!(memory(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", signed("Microsoft Windows")), Some(Level::High));
        assert_eq!(memory(r"C:\Program Files\Monitor\monitor.exe", signed("Acme")), None);

        let dll = |path: &str, trust: Trust| judge_dll(Path::new(path), &trust).map(|(l, _)| l);
        assert_eq!(dll(r"C:\Users\me\AppData\Local\Temp\x\chrome_elf_hook.dll", Trust::Unsigned), Some(Level::High));
        assert_eq!(dll(r"C:\Users\me\Downloads\inject.dll", Trust::Unsigned), Some(Level::High));
        assert_eq!(dll(r"C:\Users\me\AppData\Local\SomeApp\plugin.dll", Trust::Unsigned), Some(Level::Review));
        assert_eq!(dll(r"C:\Users\me\AppData\Local\Google\Chrome\Application\130.0\chrome.dll", signed("Google LLC")), None);

        let protected = vec![r"c:\windows\".to_string(), r"c:\program files\".to_string()];
        assert!(is_protected(Path::new(r"C:\Windows\System32\ntdll.dll"), &protected));
        assert!(!is_protected(Path::new(r"C:\Windows\Temp\x.dll"), &protected), "users can write there");
        assert!(!is_protected(Path::new(r"C:\Users\me\x.dll"), &protected));
    }

    #[test]
    fn remote_control_and_planted_extensions_are_caught() {
        let none = |_: &Path| false;
        let level = |cmd: &str| launch(cmd, none).map(|l| l.level);
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
        let got = launch(r#"chrome.exe --headless --remote-debugging-pipe --user-data-dir="C:\Temp\copy""#, copied).unwrap();
        assert_eq!((got.level, got.debugging), (Level::High, true));
        assert_eq!(got.switches, ["--remote-debugging-pipe", "--headless", "--user-data-dir"]);
        // An extension loaded from a folder users can write to.
        let ext = launch(r"msedge.exe --load-extension=C:\Users\me\AppData\Local\Temp\ext", none).unwrap();
        assert_eq!((ext.level, ext.debugging, ext.extension.as_deref()), (Level::Review, false, Some(r"C:\Users\me\AppData\Local\Temp\ext")));
        assert_eq!(level(r"brave.exe --headless --load-extension=C:\ProgramData\x"), Some(Level::High));
        assert_eq!(level(r#"chrome.exe "--load-extension=C:\Program Files\Vendor\ext""#), None, "installed by an administrator");
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
            exited: false,
            controller: None,
        };
        assert_eq!(hit.headline(), "update.exe opened Chrome's saved passwords, sign-in cookies and key that unlocks saved passwords and cookies");
        assert_eq!(hit.action(), "program stopped");
        hit.stopped = None;
        assert_eq!(hit.action(), "reported (automatic stopping is off)");
        // Gone before it was caught, named or not: there was nothing to stop.
        hit.exited = true;
        assert_eq!(hit.action(), "reported (it had already exited)");
        hit.exited = false;
        hit.created = 0;
        assert_eq!(hit.action(), "reported (it had already exited)");
        hit.created = 1;
        hit.kind = GuardKind::RemoteControl;
        hit.switches = vec!["--remote-debugging-port".into()];
        hit.controller = Some(Controller { pid: 8, program: "loader.exe".into(), image: PathBuf::new(), stopped: Some(Ok(())) });
        assert_eq!(hit.headline(), "loader.exe started Chrome for remote control with your profile");
        assert_eq!(hit.action(), "reported (automatic stopping is off); loader.exe stopped");
        hit.switches = vec!["--load-extension".into()];
        assert_eq!(hit.headline(), "Chrome was started with an extension loaded from a folder any program can write to");
        hit.kind = GuardKind::Injected;
        hit.files = vec![PathBuf::from(r"C:\Temp\hook.dll")];
        assert_eq!(hit.headline(), "An unsigned hook.dll was loaded into Chrome");
        hit.kind = GuardKind::MemoryRead;
        assert_eq!(hit.headline(), "update.exe opened Chrome to read its memory, where signed-in sessions are kept");
    }

    #[test]
    fn exited_programs_are_still_named_for_a_while() {
        let info = |pid: u32, name: &str| ProcessInfo {
            id: ProcessId { pid, created: 5 },
            name: name.into(),
            image: PathBuf::from(format!(r"C:\Program Files\Microsoft\Edge\Application\{name}")),
            parent: 0,
        };
        let mut exited = Exited::default();
        exited.remember(info(3172, "identity_helper.exe"));
        assert_eq!(exited.get(3172).map(|i| i.name.as_str()), Some("identity_helper.exe"));
        assert!(exited.get(3173).is_none());
        // The id went to a new process: the old one is not it.
        exited.forget(3172);
        assert!(exited.get(3172).is_none());
    }

    #[test]
    fn a_signed_program_is_reviewed_once_an_hour_across_restarts() {
        // Shared by every watch; a path no other test uses.
        let image = Path::new(r"C:\Program Files\Review Testgent.exe");
        assert!(!reviewed_lately(image, "memory"));
        assert!(reviewed_lately(image, "memory"), "within the hour");
        assert!(!reviewed_lately(image, "Chrome"), "another browser or kind of read");
    }
}
