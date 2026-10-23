//! The browser connector: a native-messaging host (stdio, 32-bit length +
//! JSON per message) that the Phalanx Browser Guard extension asks about
//! each page. Browsers start it themselves (`phalanx-cli` with the caller's
//! origin as its argument) once it is registered for the current user.
//!
//! Requests (each carries an `id` that the reply echoes):
//! * `{"type":"check","url":"…"}` → `{"type":"verdict","block":…, …}`
//! * `{"type":"status"}` → rule counts, mode and feed date
//! * `{"type":"exclude","site":"…"}` → adds a browser exclusion (verdict 6)
//! * `{"type":"check_many","urls":[…]}` → verdicts for search results (not logged)
//! * `{"type":"open_app"}` → starts the Phalanx app
//! * `{"type":"ads_domains","offset":n}` → one page of the ad and tracker
//!   names to block inside pages, in list order, with a `revision` that
//!   changes when they do (`active` is false while ad blocking is off)
//! * `{"type":"set_ads","on":…}` → switches ad blocking on or off
//! * `{"type":"threat_domains","offset":n}` → one page of the malicious
//!   names (after allow lists), with exceptions and a `revision`. The
//!   extension turns them into declarativeNetRequest block rules, which the
//!   browser applies *before* a request is sent; asking per page cannot,
//!   because the navigation is already under way while the reply travels.
//!
//! It reloads the settings and rules when their files change, so changes in
//! the desktop app apply without restarting the browser.

use super::config::{ads_file, Mode, WebConfig, FEED_FILE};
use super::events::{self, WebEvent};
use super::rules::WebRules;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Registered host name (what the extension passes to `connectNative`).
pub const HOST_NAME: &str = "com.phalanx.browser_guard";
/// The extension's ID in Chromium browsers (fixed by the key in its manifest).
pub const CHROMIUM_EXTENSION_ID: &str = "pbmiomloikaabmjoklgindgdhelghecp";
/// The extension's ID in Firefox.
pub const FIREFOX_EXTENSION_ID: &str = "browser-guard@phalanx.local";
/// Largest message accepted from the browser.
const MAX_MESSAGE: usize = 1024 * 1024;
/// Most addresses checked in one `check_many` request.
const MAX_BATCH: usize = 200;
/// Ad names per `ads_domains` reply (replies to the browser must stay under 1 MB).
const ADS_PAGE: usize = 20_000;
/// Threat names per `threat_domains` reply (replies must stay under 1 MB).
const THREAT_PAGE: usize = 20_000;
/// Most ad names handed to the browser; the first in list order are kept.
pub const MAX_AD_DOMAINS: usize = 150_000;

/// The extension's files, embedded so the app can write them out for
/// "Load unpacked".
pub const EXTENSION_FILES: &[(&str, &[u8])] = &[
    ("manifest.json", include_bytes!("../../browser-extension/manifest.json")),
    ("background.js", include_bytes!("../../browser-extension/background.js")),
    ("blocked.html", include_bytes!("../../browser-extension/blocked.html")),
    ("blocked.js", include_bytes!("../../browser-extension/blocked.js")),
    ("popup.html", include_bytes!("../../browser-extension/popup.html")),
    ("popup.js", include_bytes!("../../browser-extension/popup.js")),
    ("search.js", include_bytes!("../../browser-extension/search.js")),
    ("style.css", include_bytes!("../../browser-extension/style.css")),
    ("options.html", include_bytes!("../../browser-extension/options.html")),
    ("options.js", include_bytes!("../../browser-extension/options.js")),
    ("icon16.png", include_bytes!("../../browser-extension/icon16.png")),
    ("icon32.png", include_bytes!("../../browser-extension/icon32.png")),
    ("icon48.png", include_bytes!("../../browser-extension/icon48.png")),
    ("icon128.png", include_bytes!("../../browser-extension/icon128.png")),
];

/// Whether this process was started by a browser as the connector:
/// Chromium passes the caller's origin (`chrome-extension://…/`), Firefox
/// passes the manifest path and the extension ID.
pub fn is_host_invocation(args: &[String]) -> bool {
    match args {
        [first, ..] if first.starts_with("chrome-extension://") => true,
        [manifest, id, ..] => manifest.ends_with(".json") && id == FIREFOX_EXTENSION_ID,
        _ => false,
    }
}

struct HostState {
    data_dir: PathBuf,
    config: WebConfig,
    rules: WebRules,
    loaded_from: [Option<SystemTime>; 3],
    error: Option<String>,
    /// Ad names for the browser, in list order; built on first request.
    ad_domains: Option<Vec<String>>,
    /// Threat names for the browser's pre-request rules; built on first request.
    threat_domains: Option<Vec<String>>,
}

fn add(list: &mut Vec<String>, host: &str) {
    if !list.iter().any(|h| h == host) {
        list.push(host.to_string());
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl HostState {
    fn new(data_dir: &Path) -> Self {
        let mut state = Self {
            data_dir: data_dir.to_path_buf(),
            config: WebConfig::default(),
            rules: WebRules::default(),
            loaded_from: [None; 3],
            error: None,
            ad_domains: None,
            threat_domains: None,
        };
        state.reload();
        state
    }

    fn sources(&self) -> [Option<SystemTime>; 3] {
        [
            modified(&WebConfig::path(&self.data_dir)),
            modified(&crate::update::signature_dir(&self.data_dir).join(FEED_FILE)),
            modified(&ads_file(&self.data_dir)),
        ]
    }

    fn reload(&mut self) {
        self.loaded_from = self.sources();
        self.ad_domains = None;
        self.threat_domains = None;
        let loaded = WebConfig::load(&self.data_dir).and_then(|config| {
            let rules = config.load_rules(&self.data_dir)?;
            Ok((config, rules))
        });
        match loaded {
            Ok((config, rules)) => {
                self.config = config;
                self.rules = rules;
                self.error = None;
            }
            // Keep the previous rules rather than protecting with none.
            Err(e) => self.error = Some(format!("{e:#}")),
        }
        if self.rules.counts().blocking() == 0 && let Ok(builtin) = WebRules::load(None, &self.config.user_lists()) {
            self.rules = builtin;
        }
    }

    /// Picks up changes from the app or the command line at once (three file
    /// times per request), so the browser never acts on old lists.
    fn reload_if_changed(&mut self) {
        if self.sources() != self.loaded_from {
            self.reload();
        }
    }

    fn handle(&mut self, request: &Value) -> Value {
        self.reload_if_changed();
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let text = |key: &str| request.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        let mut reply = match request.get("type").and_then(Value::as_str) {
            Some("check") => self.check(&text("url")),
            Some("check_many") => {
                // Search-result marking: verdicts only, nothing is logged
                // (the user has not opened these pages).
                let urls: Vec<&str> = request
                    .get("urls")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).take(MAX_BATCH).collect())
                    .unwrap_or_default();
                let verdicts: Vec<Value> = urls
                    .iter()
                    .map(|url| {
                        let v = self.rules.classify_url(url);
                        json!({
                            "url": url,
                            "matched": v.blocks(),
                            "block": v.blocks() && self.config.enabled && self.config.mode == Mode::Block,
                            "code": v.code.number(),
                            "reason": v.code.label(),
                            "category": v.category,
                            "threat": v.threat,
                        })
                    })
                    .collect();
                json!({ "type": "verdicts", "verdicts": verdicts, "enabled": self.config.enabled })
            }
            Some("open_app") => match open_app() {
                Ok(()) => json!({ "type": "opened", "ok": true }),
                Err(e) => json!({ "type": "opened", "ok": false, "error": format!("{e:#}") }),
            },
            Some("status" | "ping") => {
                let counts = self.rules.counts();
                let manifest = crate::update::load_manifest(&crate::update::signature_dir(&self.data_dir));
                json!({
                    "type": "status",
                    "version": env!("CARGO_PKG_VERSION"),
                    "enabled": self.config.enabled,
                    "mode": mode_name(self.config.mode),
                    "rules": counts.blocking(),
                    "counts": counts,
                    "feeds_updated": manifest.last_success(),
                    "error": self.error,
                    "block_ads": self.config.block_ads,
                    "ads": counts.ads,
                    "ads_revision": self.ads_revision(),
                    "threats_revision": self.threats_revision(),
                })
            }
            Some("threat_domains") => {
                let offset = request.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let revision = self.threats_revision();
                let active = self.blocking();
                if active && self.threat_domains.is_none() {
                    self.threat_domains = Some(self.rules.threat_domains());
                }
                let domains: &[String] = if active { self.threat_domains.as_deref().unwrap_or_default() } else { &[] };
                let page: Vec<&String> = domains.iter().skip(offset).take(THREAT_PAGE).collect();
                let mut reply = json!({
                    "type": "threat_domains",
                    "active": active,
                    "revision": revision,
                    "total": domains.len(),
                    "offset": offset,
                    "domains": page,
                });
                if offset == 0 && active {
                    reply["excluded"] = json!(self.rules.threat_exclusions());
                }
                reply
            }
            Some("ads_domains") => {
                let offset = request.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let revision = self.ads_revision();
                let active = self.ads_active();
                let domains = if active { self.ad_domains() } else { &[] };
                let page: Vec<&String> = domains.iter().skip(offset).take(ADS_PAGE).collect();
                let mut reply = json!({
                    "type": "ads_domains",
                    "active": active,
                    "revision": revision,
                    "total": domains.len(),
                    "offset": offset,
                    "domains": page,
                });
                if offset == 0 && active {
                    reply["excluded"] = json!(self.rules.ad_exclusions());
                    // Pages on sites the user allowed show their ads.
                    reply["allowed_sites"] = json!(self.allowed_sites());
                }
                reply
            }
            // Cheap enough to ask on every page: whether the rules changed.
            Some("revisions") => json!({
                "type": "revisions",
                "threats_revision": self.threats_revision(),
                "ads_revision": self.ads_revision(),
            }),
            Some("set_ads") => {
                let on = request.get("on").and_then(Value::as_bool).unwrap_or(false);
                match WebConfig::update(&self.data_dir, |c| c.block_ads = on) {
                    Ok(_) => {
                        self.reload();
                        json!({ "type": "ads_set", "ok": true, "block_ads": self.config.block_ads, "ads_revision": self.ads_revision() })
                    }
                    Err(e) => json!({ "type": "ads_set", "ok": false, "error": format!("{e:#}") }),
                }
            }
            // Allow a site: no threat or ad blocking on it (verdict 6). It
            // leaves the user's block list, so the two never disagree.
            Some("exclude") => self.edit_site("excluded", &text("site"), |c, host| {
                c.unblock(host);
                add(&mut c.extension_exclusions, host);
                true
            }),
            // Block a site the rules do not know: the user's block list,
            // which known-good lists do not override. It stops being allowed.
            Some("block_site") => self.edit_site("site_blocked", &text("site"), |c, host| {
                c.unallow(host);
                add(&mut c.user_block, host);
                true
            }),
            // Removing covers the entry that applies: unblocking
            // www.example.com removes an `example.com` entry.
            Some("unblock_site") => self.edit_site("site_unblocked", &text("site"), |c, host| !c.unblock(host).is_empty()),
            Some("unallow_site") => self.edit_site("site_unallowed", &text("site"), |c, host| !c.unallow(host).is_empty()),
            Some("lists") => self.lists(),
            other => json!({ "type": "error", "error": format!("unknown request {other:?}") }),
        };
        reply["id"] = id;
        reply
    }

    /// Changes one site in the user's lists, saves and reloads. `kind` is the
    /// reply type; the reply carries the updated lists. The change applies to
    /// the settings file as it is now (the app may have changed it since this
    /// connector last read it); `change` returns false when the site was not
    /// on the list it should leave.
    fn edit_site(&mut self, kind: &str, site: &str, change: impl FnOnce(&mut WebConfig, &str) -> bool) -> Value {
        // Only websites: `chrome://settings` must not become a site called "settings".
        let lower = site.trim().to_ascii_lowercase();
        let web_scheme = !lower.contains("://") || lower.starts_with("http://") || lower.starts_with("https://");
        let Some(host) = super::rules::host_of(site).filter(|h| web_scheme && (h.contains('.') || h.parse::<std::net::IpAddr>().is_ok())) else {
            return json!({ "type": kind, "ok": false, "error": "not a web address" });
        };
        let mut config = match WebConfig::load(&self.data_dir) {
            Ok(c) => c,
            Err(e) => return json!({ "type": kind, "ok": false, "error": format!("{e:#}") }),
        };
        if !change(&mut config, &host) {
            self.reload(); // the lists shown may have been out of date
            let mut reply = self.lists();
            reply["type"] = json!(kind);
            reply["ok"] = json!(false);
            reply["error"] = json!(format!("{host} is not on that list (it may have been changed in the Phalanx app)"));
            return reply;
        }
        match config.save(&self.data_dir) {
            Ok(()) => {
                self.reload();
                let mut reply = self.lists();
                reply["type"] = json!(kind);
                reply["ok"] = json!(true);
                reply["site"] = json!(host);
                reply
            }
            Err(e) => json!({ "type": kind, "ok": false, "error": format!("{e:#}") }),
        }
    }

    /// Sites the user allowed, as plain host names (for browser rules).
    fn allowed_sites(&self) -> Vec<String> {
        let mut sites: Vec<String> = self
            .config
            .extension_exclusions
            .iter()
            .chain(&self.config.user_allow)
            .filter(|s| s.contains('.') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
            .map(|s| s.to_ascii_lowercase())
            .collect();
        sites.sort();
        sites.dedup();
        sites
    }

    /// The sites the user blocked and allowed, for the extension's settings.
    fn lists(&self) -> Value {
        let mut allowed: Vec<&String> = self.config.extension_exclusions.iter().chain(&self.config.user_allow).collect();
        allowed.sort();
        allowed.dedup();
        let mut blocked: Vec<&String> = self.config.user_block.iter().collect();
        blocked.sort();
        json!({ "type": "lists", "blocked": blocked, "allowed": allowed, "threats_revision": self.threats_revision() })
    }

    /// Web protection is on and blocking (not report-only).
    fn blocking(&self) -> bool {
        self.config.enabled && self.config.mode == Mode::Block
    }

    /// Ad blocking applies in the browser: switched on, protecting and blocking.
    fn ads_active(&self) -> bool {
        self.config.block_ads && self.blocking()
    }

    /// Changes whenever the threat names or their exceptions might have: the
    /// settings (allow lists, exclusions, mode) and the feed are among the
    /// watched files.
    fn threats_revision(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.blocking().hash(&mut h);
        self.loaded_from.hash(&mut h);
        self.rules.counts().domains.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    /// Changes whenever the ad names or their exclusions might have.
    fn ads_revision(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.ads_active().hash(&mut h);
        self.loaded_from.hash(&mut h);
        self.rules.counts().ads.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    /// The ad list's names in file order (most important first), without
    /// names an exclusion allows, capped at [`MAX_AD_DOMAINS`].
    fn ad_domains(&mut self) -> &[String] {
        if self.ad_domains.is_none() {
            let text = std::fs::read_to_string(ads_file(&self.data_dir)).unwrap_or_default();
            let domains = text
                .lines()
                .filter_map(|l| l.strip_prefix("domain "))
                .filter_map(|l| l.split_whitespace().next())
                .filter(|d| self.rules.classify_domain(d).blocks())
                .take(MAX_AD_DOMAINS)
                .map(str::to_string)
                .collect();
            self.ad_domains = Some(domains);
        }
        self.ad_domains.as_deref().unwrap_or_default()
    }

    fn check(&self, url: &str) -> Value {
        let verdict = self.rules.classify_url(url);
        let matched = verdict.blocks();
        let block = matched && self.config.enabled && self.config.mode == Mode::Block;
        // Ads are not logged: far too many, and not threats.
        if matched && self.config.enabled && verdict.category != "ads" {
            events::record(&self.data_dir, &WebEvent::new("browser", block, url, &verdict));
        }
        json!({
            "type": "verdict",
            "block": block,
            "matched": matched,
            "code": verdict.code.number(),
            "reason": verdict.code.label(),
            "trigger": verdict.trigger,
            "list": verdict.list,
            "category": verdict.category,
            "threat": verdict.threat,
            "rule": verdict.rule,
            "mode": mode_name(self.config.mode),
            "enabled": self.config.enabled,
        })
    }
}

/// Starts (or brings to the front) the Phalanx desktop app installed next
/// to the connector.
fn open_app() -> Result<()> {
    let exe = std::env::current_exe()?.with_file_name(if cfg!(windows) { "phalanx.exe" } else { "phalanx" });
    if !exe.is_file() {
        bail!("{} was not found", exe.display());
    }
    std::process::Command::new(exe).spawn()?;
    Ok(())
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Block => "block",
        Mode::ReportOnly => "report_only",
    }
}

/// Reads one message; `None` at a clean end of input.
fn read_message(input: &mut impl Read) -> Result<Option<Value>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_MESSAGE {
        bail!("message of {len} bytes is too large");
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body).context("message is not JSON")?))
}

fn write_message(output: &mut impl Write, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()?;
    Ok(())
}

/// Serves requests until the browser closes the pipe.
pub fn run_host(data_dir: &Path, mut input: impl Read, mut output: impl Write) -> Result<()> {
    let mut state = HostState::new(data_dir);
    // Which browser started us, so the app can say it is really protected.
    let caller = calling_browser();
    let mut last_contact: Option<Instant> = None;
    let mut note_contact = |force: bool| {
        if let Some(browser) = caller && (force || last_contact.is_none_or(|t| t.elapsed() >= CONTACT_EVERY)) {
            record_contact(data_dir, browser);
            last_contact = Some(Instant::now());
        }
    };
    note_contact(true);
    while let Some(request) = read_message(&mut input)? {
        let reply = state.handle(&request);
        write_message(&mut output, &reply)?;
        note_contact(false);
    }
    Ok(())
}

// ---------- contact tracking ----------

const CONTACT_FILE: &str = "contact.json";
/// While a browser stays connected, its contact time is refreshed this often.
const CONTACT_EVERY: Duration = Duration::from_secs(300);

/// Browser programs and the registration row they belong to.
const BROWSER_EXES: &[(&str, &str)] = &[
    ("chrome.exe", "Google Chrome"),
    ("msedge.exe", "Microsoft Edge"),
    ("brave.exe", "Brave"),
    ("vivaldi.exe", "Chromium and Vivaldi"),
    ("firefox.exe", "Firefox"),
];

/// The browser that started this process, found by walking up the parent
/// processes (Chromium starts hosts through `cmd.exe`).
fn calling_browser() -> Option<&'static str> {
    let processes = process_table();
    let mut pid = std::process::id();
    for _ in 0..4 {
        let parent = processes.iter().find(|p| p.0 == pid)?.1;
        let (_, _, exe) = processes.iter().find(|p| p.0 == parent)?;
        if let Some((_, row)) = BROWSER_EXES.iter().find(|(e, _)| exe.eq_ignore_ascii_case(e)) {
            return Some(row);
        }
        pid = parent;
    }
    None
}

/// (process id, parent id, program name) of every process.
fn process_table() -> Vec<(u32, u32, String)> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let len = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
            out.push((entry.th32ProcessID, entry.th32ParentProcessID, String::from_utf16_lossy(&entry.szExeFile[..len])));
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        out
    }
    #[cfg(not(windows))]
    Vec::new()
}

/// `2026-10-19T10:00:00+05:30` → `3 min ago`.
fn ago(rfc3339: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(rfc3339) else { return rfc3339.to_string() };
    let minutes = (chrono::Local::now().fixed_offset() - then).num_minutes().max(0);
    match minutes {
        0..=1 => "just now".into(),
        2..=119 => format!("{minutes} min ago"),
        120..=2879 => format!("{} h ago", minutes / 60),
        _ => format!("{} days ago", minutes / 1440),
    }
}

fn contact_path(data_dir: &Path) -> PathBuf {
    connector_dir(data_dir).join(CONTACT_FILE)
}

/// Last time each browser row reached the connector.
pub fn contacts(data_dir: &Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read_to_string(contact_path(data_dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn record_contact(data_dir: &Path, browser: &str) {
    let mut all = contacts(data_dir);
    all.insert(browser.to_string(), crate::store::now());
    let path = contact_path(data_dir);
    let _ = std::fs::create_dir_all(connector_dir(data_dir));
    if let Ok(text) = serde_json::to_string_pretty(&all) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

// ---------- registration ----------

/// Where each browser family looks for native-messaging hosts (per user).
pub const BROWSERS: &[(&str, &str, bool)] = &[
    ("Google Chrome", r"Software\Google\Chrome\NativeMessagingHosts", false),
    ("Microsoft Edge", r"Software\Microsoft\Edge\NativeMessagingHosts", false),
    ("Brave", r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts", false),
    ("Chromium and Vivaldi", r"Software\Chromium\NativeMessagingHosts", false),
    ("Firefox", r"Software\Mozilla\NativeMessagingHosts", true),
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct BrowserRegistration {
    pub browser: String,
    /// The manifest path registered, if any.
    pub manifest: Option<String>,
    /// Whether it points at this installation's manifest.
    pub current: bool,
    /// The browser has a profile on this PC.
    pub installed: bool,
    /// Profiles (display names) where the Browser Guard extension is added.
    pub extension_profiles: Vec<String>,
    /// Last time this browser's extension reached Phalanx (RFC 3339).
    pub last_contact: Option<String>,
}

/// What a browser row means for protection, most to least protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardState {
    /// The extension is added and has reached Phalanx.
    Protecting,
    /// The extension is added but has never reached Phalanx (restart the browser).
    Waiting,
    /// The connector is registered, but the extension is not added.
    ExtensionMissing,
    /// The registration points at another copy of Phalanx.
    OtherCopy,
    /// The browser is installed but the connector is not registered for it.
    NotConnected,
    NotInstalled,
}

impl BrowserRegistration {
    /// One line for the app and the command line.
    pub fn describe(&self) -> String {
        match self.state() {
            GuardState::Protecting => {
                let profiles = match self.extension_profiles.len() {
                    1 => format!("in {}", self.extension_profiles[0]),
                    n => format!("in {n} profiles"),
                };
                let ago = self.last_contact.as_deref().map(ago).unwrap_or_default();
                format!("protecting ({profiles}), last contact {ago}")
            }
            GuardState::Waiting => "extension added; waiting for it to reach Phalanx (restart the browser if this stays)".into(),
            GuardState::ExtensionMissing => "ready, but the extension is not added".into(),
            GuardState::OtherCopy => "linked to another copy of Phalanx; reconnect".into(),
            GuardState::NotConnected => "not connected".into(),
            GuardState::NotInstalled => "not installed".into(),
        }
    }

    pub fn state(&self) -> GuardState {
        if !self.installed && self.last_contact.is_none() {
            GuardState::NotInstalled
        } else if self.manifest.is_none() {
            GuardState::NotConnected
        } else if !self.current {
            GuardState::OtherCopy
        } else if self.extension_profiles.is_empty() {
            GuardState::ExtensionMissing
        } else if self.last_contact.is_none() {
            GuardState::Waiting
        } else {
            GuardState::Protecting
        }
    }
}

pub fn connector_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("browser-connector")
}

/// The extension for Chromium browsers (Chrome, Edge, Brave, Vivaldi).
pub fn extension_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("browser-extension")
}

/// The extension for Firefox, whose manifest differs.
pub fn firefox_extension_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("browser-extension-firefox")
}

/// The connector program: `phalanx-cli` next to the running program.
pub fn host_exe() -> Result<PathBuf> {
    let current = std::env::current_exe().context("finding this program")?;
    let name = if cfg!(windows) { "phalanx-cli.exe" } else { "phalanx-cli" };
    let sibling = current.with_file_name(name);
    if sibling.is_file() {
        Ok(sibling)
    } else {
        bail!("{} was not found next to {}", name, current.display())
    }
}

/// Writes both copies of the extension (replacing older ones).
pub fn write_extensions(data_dir: &Path) -> Result<()> {
    write_extension(&extension_dir(data_dir), false)?;
    write_extension(&firefox_extension_dir(data_dir), true)
}

/// Writes the extension's files to `dir`, with the manifest for Firefox or
/// for Chromium browsers.
fn write_extension(dir: &Path, firefox: bool) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // A file earlier versions wrote that this one no longer uses.
    let _ = std::fs::remove_file(dir.join("icon.png"));
    for (name, bytes) in EXTENSION_FILES {
        let path = dir.join(name);
        let manifest;
        let bytes = if *name == "manifest.json" {
            manifest = extension_manifest(firefox);
            manifest.as_slice()
        } else {
            *bytes
        };
        if std::fs::read(&path).ok().as_deref() != Some(bytes) {
            std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
        }
    }
    Ok(())
}

/// The bundled manifest is Chromium's, so the source folder loads as is.
/// Firefox runs background scripts instead of a service worker (Chromium
/// warns about `background.scripts`) and has no use for Chromium's `key`.
fn extension_manifest(firefox: bool) -> Vec<u8> {
    if !firefox {
        return EXTENSION_FILES[0].1.to_vec();
    }
    let mut manifest: Value = serde_json::from_slice(EXTENSION_FILES[0].1).expect("the bundled manifest is JSON");
    manifest["background"] = json!({ "scripts": ["background.js"] });
    manifest.as_object_mut().map(|m| m.remove("key"));
    serde_json::to_vec_pretty(&manifest).expect("JSON serializes")
}

fn manifest_json(exe: &Path, firefox: bool) -> Value {
    let mut manifest = json!({
        "name": HOST_NAME,
        "description": "Phalanx web protection connector",
        "path": exe.display().to_string(),
        "type": "stdio",
    });
    if firefox {
        manifest["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]);
    } else {
        manifest["allowed_origins"] = json!([format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")]);
    }
    manifest
}

fn manifest_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    let dir = connector_dir(data_dir);
    (dir.join("chromium.json"), dir.join("firefox.json"))
}

/// Registers the connector for the current user in every supported browser
/// (HKCU only; no administrator rights) and writes the extension's files.
pub fn install(data_dir: &Path, exe: &Path) -> Result<Vec<BrowserRegistration>> {
    let (chromium, firefox) = manifest_paths(data_dir);
    std::fs::create_dir_all(connector_dir(data_dir))?;
    std::fs::write(&chromium, serde_json::to_string_pretty(&manifest_json(exe, false))?)?;
    std::fs::write(&firefox, serde_json::to_string_pretty(&manifest_json(exe, true))?)?;
    write_extensions(data_dir)?;
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        for (browser, key, is_firefox) in BROWSERS {
            let manifest = if *is_firefox { &firefox } else { &chromium };
            let (k, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{key}\{HOST_NAME}"))
                .with_context(|| format!("registering for {browser}"))?;
            k.set_value("", &manifest.display().to_string()).with_context(|| format!("registering for {browser}"))?;
        }
    }
    Ok(status(data_dir))
}

/// Removes this connector's registrations.
pub fn uninstall() -> Result<()> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        for (browser, key, _) in BROWSERS {
            match RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(format!(r"{key}\{HOST_NAME}")) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("unregistering from {browser}"));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Which browsers have the connector registered.
pub fn status(data_dir: &Path) -> Vec<BrowserRegistration> {
    let (chromium, firefox) = manifest_paths(data_dir);
    let contacts = contacts(data_dir);
    let chromium_browsers = super::extensions::browsers();
    BROWSERS
        .iter()
        .map(|(browser, _key, is_firefox)| {
            #[cfg(windows)]
            let manifest: Option<String> = {
                use winreg::{enums::HKEY_CURRENT_USER, RegKey};
                RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(format!(r"{_key}\{HOST_NAME}"))
                    .and_then(|k| k.get_value::<String, _>(""))
                    .ok()
            };
            #[cfg(not(windows))]
            let manifest: Option<String> = None;
            let expected = if *is_firefox { &firefox } else { &chromium };
            let current = manifest.as_deref().is_some_and(|m| Path::new(m) == expected.as_path() && expected.is_file());
            let (installed, extension_profiles) = if *is_firefox {
                firefox_extension()
            } else {
                // The Chromium row covers Vivaldi and Chromium.
                let names: Vec<&str> = match *browser {
                    "Chromium and Vivaldi" => vec!["Vivaldi", "Chromium"],
                    other => vec![other],
                };
                let found: Vec<&super::extensions::Browser> = chromium_browsers.iter().filter(|b| names.contains(&b.name.as_str())).collect();
                let profiles = found
                    .iter()
                    .flat_map(|b| super::extensions::profiles_with_extension(&b.user_data, CHROMIUM_EXTENSION_ID))
                    .collect();
                (!found.is_empty(), profiles)
            };
            BrowserRegistration {
                browser: browser.to_string(),
                manifest,
                current,
                installed,
                extension_profiles,
                last_contact: contacts.get(*browser).cloned(),
            }
        })
        .collect()
}

/// Whether Firefox has a profile here, and the profiles with the extension
/// (temporary add-ons are listed while Firefox runs).
fn firefox_extension() -> (bool, Vec<String>) {
    let Some(root) = std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join(r"Mozilla\Firefox\Profiles")) else {
        return (false, Vec::new());
    };
    let Ok(entries) = std::fs::read_dir(&root) else { return (false, Vec::new()) };
    let profiles = entries
        .flatten()
        .filter(|e| {
            std::fs::read_to_string(e.path().join("extensions.json")).is_ok_and(|t| t.contains(FIREFOX_EXTENSION_ID))
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    (true, profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write_message(&mut out, value).unwrap();
        out
    }

    fn replies(output: &[u8]) -> Vec<Value> {
        let mut cursor = std::io::Cursor::new(output);
        std::iter::from_fn(|| read_message(&mut cursor).unwrap()).collect()
    }

    #[test]
    fn answers_checks_status_and_exclusions() {
        let tmp = tempfile::tempdir().unwrap();
        let mut input = Vec::new();
        input.extend(frame(&json!({"id": 1, "type": "check", "url": "https://blocktest.phalanx.invalid/x"})));
        input.extend(frame(&json!({"id": 2, "type": "check", "url": "https://example.org/"})));
        input.extend(frame(&json!({"id": 3, "type": "status"})));
        input.extend(frame(&json!({"id": 4, "type": "exclude", "site": "https://blocktest.phalanx.invalid/x"})));
        input.extend(frame(&json!({"id": 5, "type": "check", "url": "https://blocktest.phalanx.invalid/x"})));
        input.extend(frame(&json!({"id": 6, "type": "bogus"})));
        input.extend(frame(&json!({"id": 7, "type": "check_many", "urls": ["https://phishtest.phalanx.invalid/", "https://example.org/"]})));
        let mut output = Vec::new();
        run_host(tmp.path(), input.as_slice(), &mut output).unwrap();
        let r = replies(&output);
        assert_eq!(r.len(), 7);
        let batch = r[6]["verdicts"].as_array().unwrap();
        assert_eq!((batch[0]["block"].as_bool(), batch[0]["category"].as_str()), (Some(true), Some("phishing")));
        assert_eq!((batch[1]["block"].as_bool(), batch[1]["code"].as_u64()), (Some(false), Some(0)));
        assert_eq!((r[0]["id"].as_i64(), r[0]["block"].as_bool(), r[0]["code"].as_u64()), (Some(1), Some(true), Some(2)));
        assert_eq!(r[0]["threat"], "Phalanx.TestBlock.Malware");
        assert_eq!(r[1]["block"], false);
        assert_eq!((r[2]["type"].as_str(), r[2]["mode"].as_str()), (Some("status"), Some("block")));
        assert!(r[2]["rules"].as_u64().unwrap() >= 3);
        assert_eq!(r[3]["ok"], true);
        assert_eq!((r[4]["block"].as_bool(), r[4]["code"].as_u64()), (Some(false), Some(6)), "excluded by the extension");
        assert_eq!(r[5]["type"], "error");
        assert_eq!(WebConfig::load(tmp.path()).unwrap().extension_exclusions, ["blocktest.phalanx.invalid"]);
        assert_eq!(events::recent(tmp.path(), 10).len(), 1, "the block was logged");
    }

    #[test]
    fn report_only_and_disabled_never_block() {
        let tmp = tempfile::tempdir().unwrap();
        let config = WebConfig { mode: Mode::ReportOnly, ..Default::default() };
        config.save(tmp.path()).unwrap();
        let mut state = HostState::new(tmp.path());
        let reply = state.handle(&json!({"type": "check", "url": "http://blocktest.phalanx.invalid/"}));
        assert_eq!((reply["block"].as_bool(), reply["matched"].as_bool()), (Some(false), Some(true)));
        assert_eq!(events::recent(tmp.path(), 1)[0].action, "reported");
        state.config.enabled = false;
        assert_eq!(state.handle(&json!({"type": "check", "url": "http://blocktest.phalanx.invalid/"}))["block"], false);
    }

    #[test]
    fn sites_can_be_blocked_allowed_and_undone() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = HostState::new(tmp.path());
        let blocked = state.handle(&json!({"type": "block_site", "site": "https://shady.example/page"}));
        assert_eq!((blocked["ok"].as_bool(), blocked["site"].as_str()), (Some(true), Some("shady.example")));
        assert_eq!(blocked["blocked"], json!(["shady.example"]));
        let v = state.handle(&json!({"type": "check", "url": "https://www.shady.example/"}));
        assert_eq!((v["block"].as_bool(), v["list"].as_str()), (Some(true), Some("userBlockList")));
        let names = state.handle(&json!({"type": "threat_domains"}));
        assert!(names["domains"].as_array().unwrap().contains(&json!("shady.example")), "blocked before any request");

        // Allowing it takes it off the block list.
        let allowed = state.handle(&json!({"type": "exclude", "site": "https://shady.example/"}));
        assert_eq!((allowed["blocked"].as_array().unwrap().len(), allowed["allowed"].clone()), (0, json!(["shady.example"])));
        assert_eq!(state.handle(&json!({"type": "check", "url": "https://shady.example/"}))["block"], false);

        let undone = state.handle(&json!({"type": "unallow_site", "site": "shady.example"}));
        assert_eq!(undone["allowed"], json!([]));
        state.handle(&json!({"type": "block_site", "site": "shady.example"}));
        let unblocked = state.handle(&json!({"type": "unblock_site", "site": "shady.example"}));
        assert_eq!(unblocked["blocked"], json!([]));
        assert_eq!(state.handle(&json!({"type": "block_site", "site": "chrome://settings"}))["ok"], false);
        let config = WebConfig::load(tmp.path()).unwrap();
        assert!(config.user_block.is_empty() && config.extension_exclusions.is_empty());
    }

    #[test]
    fn hands_out_threat_names_for_pre_request_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = HostState::new(tmp.path());
        let first = state.handle(&json!({"type": "threat_domains", "offset": 0}));
        assert_eq!(first["active"], true);
        let domains = first["domains"].as_array().unwrap();
        assert!(domains.contains(&json!("blocktest.phalanx.invalid")), "{domains:?}");
        assert_eq!(first["total"].as_u64(), Some(domains.len() as u64));
        assert!(first["excluded"].is_array());

        // An exclusion changes the revision and drops the name.
        state.handle(&json!({"type": "exclude", "site": "https://blocktest.phalanx.invalid/"}));
        let after = state.handle(&json!({"type": "threat_domains", "offset": 0}));
        assert_ne!(after["revision"], first["revision"]);
        assert!(!after["domains"].as_array().unwrap().contains(&json!("blocktest.phalanx.invalid")));

        // Report-only mode hands out nothing to block.
        let mut config = WebConfig::load(tmp.path()).unwrap();
        config.mode = Mode::ReportOnly;
        config.save(tmp.path()).unwrap();
        state.reload();
        let report = state.handle(&json!({"type": "threat_domains"}));
        assert_eq!((report["active"].as_bool(), report["total"].as_u64()), (Some(false), Some(0)));
        assert_ne!(report["revision"], after["revision"]);
    }

    #[test]
    fn hands_out_ad_names_in_pages_and_switches_ads() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(crate::update::signature_dir(tmp.path())).unwrap();
        let mut list = String::from("# header\ndomain doubleclick.net ads StevenBlack.Ads\ndomain google.com ads StevenBlack.Ads\n");
        list.extend((0..ADS_PAGE).map(|i| format!("domain t{i}.example ads StevenBlack.Ads\n")));
        std::fs::write(ads_file(tmp.path()), list).unwrap();
        let mut state = HostState::new(tmp.path());
        let off = state.handle(&json!({"type": "ads_domains"}));
        assert_eq!((off["active"].as_bool(), off["total"].as_u64()), (Some(false), Some(0)), "off by default");
        assert!(!state.handle(&json!({"type": "check", "url": "https://doubleclick.net/"}))["block"].as_bool().unwrap());

        let set = state.handle(&json!({"type": "set_ads", "on": true}));
        assert_eq!((set["ok"].as_bool(), set["block_ads"].as_bool()), (Some(true), Some(true)));
        assert!(WebConfig::load(tmp.path()).unwrap().block_ads);
        assert_ne!(set["ads_revision"], off["revision"]);
        let first = state.handle(&json!({"type": "ads_domains", "offset": 0}));
        assert_eq!((first["active"].as_bool(), first["total"].as_u64()), (Some(true), Some(ADS_PAGE as u64 + 1)), "known-good google.com left out");
        assert_eq!(first["domains"][0], "doubleclick.net", "list order kept");
        assert_eq!(first["domains"].as_array().unwrap().len(), ADS_PAGE);
        assert!(first["excluded"].as_array().unwrap().contains(&json!("google.com")));
        assert_eq!(first["revision"], set["ads_revision"]);
        let second = state.handle(&json!({"type": "ads_domains", "offset": ADS_PAGE}));
        assert_eq!(second["domains"], json!([format!("t{}.example", ADS_PAGE - 1)]));
        let v = state.handle(&json!({"type": "check", "url": "https://ad.doubleclick.net/x"}));
        assert_eq!((v["block"].as_bool(), v["category"].as_str(), v["list"].as_str()), (Some(true), Some("ads"), Some("adsBlockList")));
        assert_eq!(state.handle(&json!({"type": "status"}))["ads"].as_u64(), Some(ADS_PAGE as u64 + 2));
    }

    #[test]
    fn app_and_browser_list_edits_stay_in_step() {
        let tmp = tempfile::tempdir().unwrap();
        let app = |change: &dyn Fn(&mut WebConfig)| {
            WebConfig::update(tmp.path(), |c| change(c)).unwrap();
            // File times can be coarse; make sure the edit is seen as new.
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let mut state = HostState::new(tmp.path());
        let blocked = |state: &mut HostState, url: &str| state.handle(&json!({"type": "check", "url": url}))["block"].as_bool().unwrap();
        let revision = |state: &mut HostState| state.handle(&json!({"type": "revisions"}))["threats_revision"].clone();

        // Blocked in the app: the browser sees it on its very next request.
        let before = revision(&mut state);
        app(&|c| drop(c.block("spicett.com")));
        assert_ne!(revision(&mut state), before, "revision changes at once");
        assert!(blocked(&mut state, "https://www.spicett.com/"));
        assert_eq!(state.handle(&json!({"type": "lists"}))["blocked"], json!(["spicett.com"]));

        // Removed in the app: no longer blocked in the browser.
        app(&|c| {
            c.forget("spicett.com");
        });
        assert!(!blocked(&mut state, "https://spicett.com/"));
        assert!(!state.handle(&json!({"type": "threat_domains"}))["domains"].as_array().unwrap().contains(&json!("spicett.com")));

        // Blocked in the browser while the app added another site: both kept.
        app(&|c| drop(c.block("other.example")));
        state.handle(&json!({"type": "block_site", "site": "https://spicett.com/"}));
        assert_eq!(WebConfig::load(tmp.path()).unwrap().user_block, ["other.example", "spicett.com"]);

        // Unblocking from a subdomain page removes the entry that applies.
        let r = state.handle(&json!({"type": "unblock_site", "site": "https://www.spicett.com/x"}));
        assert_eq!((r["ok"].as_bool(), r["blocked"].clone()), (Some(true), json!(["other.example"])));
        assert!(!blocked(&mut state, "https://www.spicett.com/"));
        // Removing what is no longer there says so, with the current lists.
        let gone = state.handle(&json!({"type": "unblock_site", "site": "spicett.com"}));
        assert_eq!((gone["ok"].as_bool(), gone["blocked"].clone()), (Some(false), json!(["other.example"])));

        // Allowed from the warning page, then blocked in the app: blocked.
        state.handle(&json!({"type": "exclude", "site": "https://blocktest.phalanx.invalid/"}));
        assert!(!blocked(&mut state, "https://blocktest.phalanx.invalid/"));
        app(&|c| drop(c.block("blocktest.phalanx.invalid")));
        assert!(blocked(&mut state, "https://blocktest.phalanx.invalid/"), "the app's block wins over the old exclusion");
        // And allowed again from the browser, then un-allowed: the feed rule applies.
        state.handle(&json!({"type": "exclude", "site": "https://blocktest.phalanx.invalid/"}));
        assert!(!blocked(&mut state, "https://blocktest.phalanx.invalid/"));
        assert_eq!(state.handle(&json!({"type": "unallow_site", "site": "blocktest.phalanx.invalid"}))["ok"], true);
        assert!(blocked(&mut state, "https://blocktest.phalanx.invalid/"));
    }

    #[test]
    fn guard_state_needs_registration_extension_and_contact() {
        let row = |manifest: bool, current: bool, installed: bool, ext: bool, contact: bool| BrowserRegistration {
            browser: "Google Chrome".into(),
            manifest: manifest.then(|| "m.json".into()),
            current,
            installed,
            extension_profiles: if ext { vec!["Person 1".into()] } else { Vec::new() },
            last_contact: contact.then(|| "2026-10-19T10:00:00+05:30".into()),
        };
        assert_eq!(row(true, true, false, false, false).state(), GuardState::NotInstalled);
        assert_eq!(row(false, false, true, false, false).state(), GuardState::NotConnected);
        assert_eq!(row(true, false, true, true, true).state(), GuardState::OtherCopy);
        assert_eq!(row(true, true, true, false, true).state(), GuardState::ExtensionMissing, "contact alone is not enough");
        assert_eq!(row(true, true, true, true, false).state(), GuardState::Waiting);
        assert_eq!(row(true, true, true, true, true).state(), GuardState::Protecting);

        let tmp = tempfile::tempdir().unwrap();
        record_contact(tmp.path(), "Brave");
        assert!(contacts(tmp.path()).contains_key("Brave"));
    }

    #[test]
    fn recognises_browser_launches() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_host_invocation(&args(&["chrome-extension://pbmiomloikaabmjoklgindgdhelghecp/", "--parent-window=0"])));
        assert!(is_host_invocation(&args(&[r"C:\x\firefox.json", FIREFOX_EXTENSION_ID])));
        assert!(!is_host_invocation(&args(&["scan", "C:\\"])));
        assert!(!is_host_invocation(&[]));
    }

    #[test]
    fn rejects_oversized_messages() {
        let mut input = Vec::new();
        input.extend_from_slice(&(MAX_MESSAGE as u32 + 1).to_ne_bytes());
        assert!(read_message(&mut input.as_slice()).is_err());
    }

    #[test]
    fn extension_key_gives_the_registered_id() {
        // Chromium derives the ID from SHA-256 of the public key: the first
        // 16 bytes in hex, with digits 0-f mapped to letters a-p.
        let manifest: Value = serde_json::from_slice(EXTENSION_FILES[0].1).unwrap();
        let key = manifest["key"].as_str().unwrap();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let (mut bits, mut acc, mut der) = (0u32, 0u32, Vec::new());
        for c in key.bytes().filter(|c| *c != b'=') {
            acc = (acc << 6) | alphabet.iter().position(|a| *a == c).unwrap() as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                der.push((acc >> bits) as u8);
            }
        }
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&der);
        let id: String = hex::encode(&digest[..16]).chars().map(|c| (b'a' + c.to_digit(16).unwrap() as u8) as char).collect();
        assert_eq!(id, CHROMIUM_EXTENSION_ID);
    }

    #[test]
    fn manifests_name_the_extension() {
        let exe = Path::new(r"C:\Phalanx\phalanx-cli.exe");
        assert_eq!(manifest_json(exe, false)["allowed_origins"][0], format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/"));
        assert_eq!(manifest_json(exe, true)["allowed_extensions"][0], FIREFOX_EXTENSION_ID);
        let manifest: Value = serde_json::from_slice(EXTENSION_FILES[0].1).unwrap();
        assert_eq!(manifest["browser_specific_settings"]["gecko"]["id"], FIREFOX_EXTENSION_ID);
    }

    #[test]
    fn each_browser_gets_its_own_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        write_extensions(tmp.path()).unwrap();
        let read = |dir: PathBuf| -> Value { serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap() };
        assert_eq!(std::fs::read(extension_dir(tmp.path()).join("manifest.json")).unwrap(), EXTENSION_FILES[0].1, "Chromium gets the source manifest");
        let chromium = read(extension_dir(tmp.path()));
        assert_eq!(chromium["background"], json!({ "service_worker": "background.js" }), "Chromium warns about background.scripts");
        assert!(chromium["key"].is_string(), "the key fixes the Chromium extension ID");
        let firefox = read(firefox_extension_dir(tmp.path()));
        assert_eq!(firefox["background"], json!({ "scripts": ["background.js"] }));
        assert!(firefox.get("key").is_none());
        assert_eq!(firefox["browser_specific_settings"]["gecko"]["id"], FIREFOX_EXTENSION_ID);
        assert_eq!(chromium["content_scripts"], firefox["content_scripts"]);
        let (a, b) = (extension_dir(tmp.path()).join("background.js"), firefox_extension_dir(tmp.path()).join("background.js"));
        assert_eq!(std::fs::read(a).unwrap(), std::fs::read(b).unwrap());
    }
}
