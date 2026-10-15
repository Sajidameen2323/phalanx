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
//!
//! It reloads the settings and rules when their files change, so changes in
//! the desktop app apply without restarting the browser.

use super::config::{Mode, WebConfig, FEED_FILE};
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
/// How often file changes are looked for.
const RELOAD_CHECK: Duration = Duration::from_secs(3);
/// Most addresses checked in one `check_many` request.
const MAX_BATCH: usize = 200;

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
    ("icon.png", include_bytes!("../../browser-extension/icon.png")),
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
    loaded_from: (Option<SystemTime>, Option<SystemTime>),
    last_check: Instant,
    error: Option<String>,
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
            loaded_from: (None, None),
            last_check: Instant::now(),
            error: None,
        };
        state.reload();
        state
    }

    fn sources(&self) -> (Option<SystemTime>, Option<SystemTime>) {
        (modified(&WebConfig::path(&self.data_dir)), modified(&crate::update::signature_dir(&self.data_dir).join(FEED_FILE)))
    }

    fn reload(&mut self) {
        self.loaded_from = self.sources();
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
        if self.rules.counts().blocking() == 0 {
            if let Ok(builtin) = WebRules::load(None, &self.config.user_lists()) {
                self.rules = builtin;
            }
        }
    }

    fn reload_if_changed(&mut self) {
        if self.last_check.elapsed() < RELOAD_CHECK {
            return;
        }
        self.last_check = Instant::now();
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
                })
            }
            Some("exclude") => {
                let mut config = self.config.clone();
                let site = text("site");
                match super::rules::host_of(&site) {
                    Some(host) => {
                        if !config.extension_exclusions.contains(&host) {
                            config.extension_exclusions.push(host.clone());
                        }
                        match config.save(&self.data_dir) {
                            Ok(()) => {
                                self.reload();
                                json!({ "type": "excluded", "ok": true, "site": host })
                            }
                            Err(e) => json!({ "type": "excluded", "ok": false, "error": format!("{e:#}") }),
                        }
                    }
                    None => json!({ "type": "excluded", "ok": false, "error": "not a web address" }),
                }
            }
            other => json!({ "type": "error", "error": format!("unknown request {other:?}") }),
        };
        reply["id"] = id;
        reply
    }

    fn check(&self, url: &str) -> Value {
        let verdict = self.rules.classify_url(url);
        let matched = verdict.blocks();
        let block = matched && self.config.enabled && self.config.mode == Mode::Block;
        if matched && self.config.enabled {
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
    while let Some(request) = read_message(&mut input)? {
        let reply = state.handle(&request);
        write_message(&mut output, &reply)?;
    }
    Ok(())
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
}

pub fn connector_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("browser-connector")
}

pub fn extension_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("browser-extension")
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

/// Writes the extension's files to `dir` (replacing older copies).
pub fn write_extension(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for (name, bytes) in EXTENSION_FILES {
        let path = dir.join(name);
        if std::fs::read(&path).ok().as_deref() != Some(*bytes) {
            std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
        }
    }
    Ok(())
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
    write_extension(&extension_dir(data_dir))?;
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
            BrowserRegistration { browser: browser.to_string(), manifest, current }
        })
        .collect()
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
        let mut config = WebConfig::default();
        config.mode = Mode::ReportOnly;
        config.save(tmp.path()).unwrap();
        let mut state = HostState::new(tmp.path());
        let reply = state.handle(&json!({"type": "check", "url": "http://blocktest.phalanx.invalid/"}));
        assert_eq!((reply["block"].as_bool(), reply["matched"].as_bool()), (Some(false), Some(true)));
        assert_eq!(events::recent(tmp.path(), 1)[0].action, "reported");
        state.config.enabled = false;
        assert_eq!(state.handle(&json!({"type": "check", "url": "http://blocktest.phalanx.invalid/"}))["block"], false);
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
}
