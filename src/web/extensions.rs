//! Browser extension remediation for Chromium browsers (Chrome, Edge, Brave,
//! Vivaldi, Chromium).
//!
//! Scanning reads each profile's `Preferences` and `Secure Preferences` and
//! every extension's `manifest.json`, then rates the extension: known-bad
//! IDs and extensions the browser itself flagged are threats; risky
//! permissions, settings overrides and unusual install sources add to a
//! risk score. Hijacked search engine, home page and start-up pages are
//! reported too, and checked against the web rules.
//!
//! Removal works only while the browser is closed. It backs up both
//! preference files (and the registry MAC Chromium keeps on Windows), moves
//! the extension's folder into the backup, and deletes the extension's
//! entries; [`restore_extension`] undoes it.

use super::rules::WebRules;
use super::url::WebAddress;
use crate::Category;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Built-in list of known-bad extension IDs (`<id> [category] [name]`).
pub const BUILTIN_BAD_EXTENSIONS: &str = include_str!("../../rules/extensions.txt");
/// Extra known-bad IDs the user can add, in the signature folder.
pub const USER_BAD_EXTENSIONS: &str = "bad-extensions.txt";
/// Risk score from which an extension is reported as suspicious.
pub const SUSPICIOUS_SCORE: u32 = 60;
/// Risk score from which an extension is worth reviewing.
pub const REVIEW_SCORE: u32 = 35;

/// A Chromium browser installed for this user.
#[derive(Debug, Clone, Serialize)]
pub struct Browser {
    pub name: String,
    pub user_data: PathBuf,
    /// Registry key (under HKCU) where it keeps preference MACs on Windows.
    #[serde(skip)]
    pub mac_key: Option<&'static str>,
}

/// Chromium browsers with a user-data folder for this user.
pub fn browsers() -> Vec<Browser> {
    let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else { return Vec::new() };
    let known: [(&str, &str, Option<&'static str>); 5] = [
        ("Google Chrome", r"Google\Chrome\User Data", Some(r"Software\Google\Chrome\PreferenceMACs")),
        ("Microsoft Edge", r"Microsoft\Edge\User Data", Some(r"Software\Microsoft\Edge\PreferenceMACs")),
        ("Brave", r"BraveSoftware\Brave-Browser\User Data", Some(r"Software\BraveSoftware\Brave-Browser\PreferenceMACs")),
        ("Vivaldi", r"Vivaldi\User Data", None),
        ("Chromium", r"Chromium\User Data", Some(r"Software\Chromium\PreferenceMACs")),
    ];
    known
        .iter()
        .map(|(name, dir, mac_key)| Browser { name: name.to_string(), user_data: local.join(dir), mac_key: *mac_key })
        .filter(|b| b.user_data.is_dir())
        .collect()
}

/// Profile folder names (`Default`, `Profile 1`…) with their display names.
pub fn profiles(user_data: &Path) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    if let Some(cache) = read_json(&user_data.join("Local State")).as_ref().and_then(|s| s.pointer("/profile/info_cache")).and_then(Value::as_object) {
        for (dir, info) in cache {
            if user_data.join(dir).join("Preferences").is_file() {
                let name = info.get("name").and_then(Value::as_str).unwrap_or(dir).to_string();
                found.push((dir.clone(), name));
            }
        }
    }
    if found.is_empty() {
        if let Ok(entries) = std::fs::read_dir(user_data) {
            for entry in entries.flatten() {
                let dir = entry.file_name().to_string_lossy().into_owned();
                if (dir == "Default" || dir.starts_with("Profile ")) && entry.path().join("Preferences").is_file() {
                    found.push((dir.clone(), dir));
                }
            }
        }
    }
    found.sort();
    found
}

/// Known-bad extension IDs with their category and threat name.
#[derive(Debug, Default, Clone)]
pub struct KnownBad {
    ids: HashMap<String, (Category, String)>,
}

impl KnownBad {
    /// The built-in list plus `<signature dir>/bad-extensions.txt`.
    pub fn load(signature_dir: Option<&Path>) -> Self {
        let mut list = Self::default();
        list.add_text(BUILTIN_BAD_EXTENSIONS);
        if let Some(text) = signature_dir.and_then(|d| std::fs::read_to_string(d.join(USER_BAD_EXTENSIONS)).ok()) {
            list.add_text(&text);
        }
        list
    }

    pub fn add_text(&mut self, text: &str) {
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let mut parts = line.split_whitespace();
            let Some(id) = parts.next().filter(|id| is_extension_id(id)) else { continue };
            let category = parts.next().and_then(|c| c.parse().ok()).unwrap_or(Category::Malware);
            let name = parts.collect::<Vec<_>>().join(" ");
            let name = if name.is_empty() { "BrowserExtension.KnownBad".to_string() } else { name };
            self.ids.insert(id.to_string(), (category, name));
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// Chromium extension IDs are 32 letters from `a` to `p`.
pub fn is_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtensionReport {
    pub browser: String,
    pub profile: String,
    pub profile_name: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub install_source: String,
    pub from_web_store: bool,
    pub permissions: Vec<String>,
    pub score: u32,
    pub reasons: Vec<String>,
    /// Set for threats: known-bad, flagged by the browser, or high risk.
    pub category: Option<Category>,
    pub threat: Option<String>,
    /// Installed folder (inside the profile, or the unpacked source).
    pub path: Option<PathBuf>,
}

impl ExtensionReport {
    /// What to tell the user in one word.
    pub fn rating(&self) -> &'static str {
        match self.category {
            Some(Category::Malware | Category::HackTool) => "malicious",
            Some(Category::Pup) => "unwanted",
            Some(Category::Suspicious) => "suspicious",
            None if self.score >= REVIEW_SCORE => "review",
            None => "ok",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingFinding {
    pub browser: String,
    pub profile: String,
    pub profile_name: String,
    /// `search engine`, `home page` or `start-up page`.
    pub setting: String,
    pub value: String,
    pub reason: String,
    /// Whether the web rules block the address (a threat, not just odd).
    pub blocked: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BrowserScan {
    pub browsers: Vec<String>,
    pub profiles: usize,
    pub extensions: Vec<ExtensionReport>,
    pub settings: Vec<SettingFinding>,
    pub errors: Vec<String>,
}

impl BrowserScan {
    /// Extensions rated as threats or worth reviewing.
    pub fn flagged(&self) -> impl Iterator<Item = &ExtensionReport> {
        self.extensions.iter().filter(|e| e.rating() != "ok")
    }
}

/// Scans every profile of every installed Chromium browser.
pub fn scan(rules: Option<&WebRules>, known_bad: &KnownBad) -> BrowserScan {
    let mut out = BrowserScan::default();
    for browser in browsers() {
        out.browsers.push(browser.name.clone());
        for (profile, profile_name) in profiles(&browser.user_data) {
            out.profiles += 1;
            match scan_profile(&browser.name, &browser.user_data.join(&profile), &profile, &profile_name, rules, known_bad) {
                Ok((extensions, settings)) => {
                    out.extensions.extend(extensions);
                    out.settings.extend(settings);
                }
                Err(e) => out.errors.push(format!("{} ({profile_name}): {e:#}", browser.name)),
            }
        }
    }
    out.extensions.sort_by(|a, b| b.category.cmp(&a.category).then(b.score.cmp(&a.score)).then(a.name.cmp(&b.name)));
    out
}

fn read_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

/// `extensions.settings`, merged from both preference files (the secure one
/// wins, as in the browser).
/// Display names of the profiles that have extension `id` installed.
pub fn profiles_with_extension(user_data: &Path, id: &str) -> Vec<String> {
    profiles(user_data)
        .into_iter()
        .filter(|(dir, _)| extension_settings(&user_data.join(dir)).is_ok_and(|s| s.contains_key(id)))
        .map(|(_, name)| name)
        .collect()
}

fn extension_settings(profile_dir: &Path) -> Result<Map<String, Value>> {
    let prefs = read_json(&profile_dir.join("Preferences")).with_context(|| format!("reading {}", profile_dir.join("Preferences").display()))?;
    let secure = read_json(&profile_dir.join("Secure Preferences")).unwrap_or(Value::Null);
    let mut merged = Map::new();
    for source in [&prefs, &secure] {
        if let Some(settings) = source.pointer("/extensions/settings").and_then(Value::as_object) {
            for (id, value) in settings {
                merged.insert(id.clone(), value.clone());
            }
        }
    }
    Ok(merged)
}

/// Scans one profile folder. Public for tests and for scanning a copied
/// profile.
pub fn scan_profile(
    browser: &str,
    profile_dir: &Path,
    profile: &str,
    profile_name: &str,
    rules: Option<&WebRules>,
    known_bad: &KnownBad,
) -> Result<(Vec<ExtensionReport>, Vec<SettingFinding>)> {
    let settings = extension_settings(profile_dir)?;
    let mut extensions = Vec::new();
    for (id, entry) in &settings {
        if id == super::native::CHROMIUM_EXTENSION_ID {
            continue; // Phalanx's own extension
        }
        let location = entry.get("location").and_then(Value::as_i64).unwrap_or(0);
        if matches!(location, 5 | 10) {
            continue; // part of the browser itself
        }
        let path = install_path(profile_dir, entry);
        let manifest = path.as_ref().and_then(|p| read_json(&p.join("manifest.json"))).or_else(|| entry.get("manifest").cloned());
        let Some(manifest) = manifest else { continue }; // stale entry, nothing installed
        let mut report = assess(id, entry, &manifest, path.as_deref(), known_bad);
        report.browser = browser.to_string();
        report.profile = profile.to_string();
        report.profile_name = profile_name.to_string();
        extensions.push(report);
    }
    let findings = setting_findings(browser, profile_dir, profile, profile_name, rules);
    Ok((extensions, findings))
}

fn install_path(profile_dir: &Path, entry: &Value) -> Option<PathBuf> {
    let path = entry.get("path").and_then(Value::as_str)?;
    let p = PathBuf::from(path);
    Some(if p.is_absolute() { p } else { profile_dir.join("Extensions").join(p) })
}

/// Resolves `__MSG_name__` placeholders from the default locale.
fn localized(manifest: &Value, dir: Option<&Path>, text: &str) -> String {
    let Some(key) = text.strip_prefix("__MSG_").and_then(|t| t.strip_suffix("__")) else { return text.to_string() };
    let locale = manifest.get("default_locale").and_then(Value::as_str).unwrap_or("en");
    let messages = dir.and_then(|d| read_json(&d.join("_locales").join(locale).join("messages.json")));
    messages
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)))
        .and_then(|(_, v)| v.get("message").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| text.to_string())
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn is_all_hosts(pattern: &str) -> bool {
    matches!(pattern, "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" | "*://*/" | "http://*/" | "https://*/")
}

/// Rates one extension.
fn assess(id: &str, entry: &Value, manifest: &Value, dir: Option<&Path>, known_bad: &KnownBad) -> ExtensionReport {
    let name = localized(manifest, dir, manifest.get("name").and_then(Value::as_str).unwrap_or(id));
    let version = manifest.get("version").and_then(Value::as_str).unwrap_or("").to_string();
    let location = entry.get("location").and_then(Value::as_i64).unwrap_or(0);
    let from_web_store = entry.get("from_webstore").and_then(Value::as_bool).unwrap_or(false);
    let disabled = entry.get("state").and_then(Value::as_i64) == Some(0)
        || entry.get("disable_reasons").is_some_and(|d| d.as_i64().is_some_and(|n| n != 0) || d.as_array().is_some_and(|a| !a.is_empty()));

    let mut permissions = strings(manifest.get("permissions"));
    permissions.extend(strings(manifest.get("host_permissions")));
    permissions.extend(strings(manifest.get("optional_host_permissions")).into_iter().filter(|p| is_all_hosts(p)));
    if let Some(scripts) = manifest.get("content_scripts").and_then(Value::as_array) {
        for s in scripts {
            permissions.extend(strings(s.get("matches")));
        }
    }
    permissions.sort();
    permissions.dedup();
    let has = |p: &str| permissions.iter().any(|x| x == p);
    let all_hosts = permissions.iter().any(|p| is_all_hosts(p));

    let mut score = 0;
    let mut reasons = Vec::new();
    let mut add = |points: u32, reason: &str| {
        score += points;
        reasons.push(reason.to_string());
    };
    let source = match location {
        1 => "web store or downloaded package",
        2 | 6 => "installed by another program",
        3 => "installed by another program (registry)",
        4 => "loaded unpacked (developer mode)",
        7 | 9 => "installed by policy",
        8 => "loaded from the command line",
        _ => "unknown",
    };
    match location {
        4 => add(25, "loaded unpacked, outside the web store's review"),
        8 => add(35, "loaded with --load-extension, a trick malware uses"),
        2 | 3 | 6 if !from_web_store => add(20, "installed by another program, not from the web store"),
        7 | 9 => add(15, "force-installed by policy (fine if your organisation manages this PC; malware also does this)"),
        1 if !from_web_store => add(15, "not installed from the web store"),
        _ => {}
    }
    if all_hosts {
        add(20, "can read and change all your data on every website");
    }
    for (perm, points, reason) in [
        ("debugger", 30, "can attach the debugger to your tabs"),
        ("proxy", 20, "can route your traffic through a proxy"),
        ("management", 20, "can manage (and disable) other extensions"),
        ("nativeMessaging", 10, "talks to programs on this PC"),
        ("webRequestBlocking", 15, "can intercept and alter web requests"),
        ("webRequest", 10, "can watch all web requests"),
        ("clipboardRead", 10, "can read your clipboard"),
        ("privacy", 10, "can change privacy settings"),
        ("contentSettings", 10, "can change site permissions"),
        ("desktopCapture", 10, "can capture your screen"),
        ("history", 5, "can read your browsing history"),
        ("downloads", 5, "can manage downloads"),
    ] {
        if has(perm) {
            add(points, reason);
        }
    }
    if has("cookies") && all_hosts {
        add(10, "can read cookies (sign-ins) for every site");
    }
    let overrides = manifest.get("chrome_settings_overrides");
    if overrides.and_then(|o| o.get("search_provider")).is_some() {
        add(25, "replaces your search engine");
    }
    if overrides.is_some_and(|o| o.get("homepage").is_some() || o.get("startup_pages").is_some()) {
        add(20, "replaces your home or start-up page");
    }
    if manifest.pointer("/chrome_url_overrides/newtab").is_some() {
        add(10, "replaces the new tab page");
    }
    let score = score.min(100);

    // The browser's own verdict (Safe Browsing blocklist).
    let flagged = ["blacklist_state", "blocklist_state"].iter().find_map(|k| entry.get(*k).and_then(Value::as_i64)).unwrap_or(0);
    let (category, threat) = if let Some((category, threat)) = known_bad.ids.get(id) {
        reasons.insert(0, "on the known-bad extension list".into());
        (Some(*category), Some(threat.clone()))
    } else if flagged > 0 {
        let (category, label) = match flagged {
            1 => (Category::Malware, "malware"),
            4 => (Category::Pup, "potentially unwanted"),
            2 => (Category::Suspicious, "a security vulnerability"),
            _ => (Category::Suspicious, "a policy violation"),
        };
        reasons.insert(0, format!("flagged by the browser for {label}"));
        (Some(category), Some(format!("BrowserExtension.Flagged.{}", capitalize_words(label))))
    } else if score >= SUSPICIOUS_SCORE && !from_web_store {
        // Store extensions are reviewed and many legitimate ones need broad
        // permissions; on permissions alone they are only worth reviewing.
        (Some(Category::Suspicious), Some("BrowserExtension.HighRisk".to_string()))
    } else {
        (None, None)
    };

    ExtensionReport {
        browser: String::new(),
        profile: String::new(),
        profile_name: String::new(),
        id: id.to_string(),
        name,
        version,
        enabled: !disabled,
        install_source: source.to_string(),
        from_web_store,
        permissions,
        score,
        reasons,
        category,
        threat,
        path: dir.map(Path::to_path_buf),
    }
}

fn capitalize_words(text: &str) -> String {
    text.split_whitespace()
        .filter(|w| *w != "a")
        .map(|w| {
            let mut c = w.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default()
        })
        .collect()
}

/// Well-known search engines; anything else as the default is reported.
const SEARCH_ENGINES: &[&str] = &[
    "google.", "bing.com", "duckduckgo.com", "yahoo.", "ecosia.org", "search.brave.com", "startpage.com", "yandex.",
    "baidu.com", "naver.com", "qwant.com", "seznam.cz", "sogou.com", "ask.com", "you.com", "perplexity.ai", "kagi.com",
    "mojeek.com", "swisscows.com", "presearch.com", "so.com", "daum.net", "coccoc.com",
];

fn known_search_engine(host: &str) -> bool {
    let host = host.strip_prefix("www.").unwrap_or(host);
    SEARCH_ENGINES.iter().any(|e| {
        if let Some(stem) = e.strip_suffix('.') {
            host.split('.').any(|label| label == stem)
        } else {
            host == *e || host.ends_with(&format!(".{e}"))
        }
    })
}

fn setting_findings(browser: &str, profile_dir: &Path, profile: &str, profile_name: &str, rules: Option<&WebRules>) -> Vec<SettingFinding> {
    let prefs = read_json(&profile_dir.join("Preferences")).unwrap_or(Value::Null);
    let secure = read_json(&profile_dir.join("Secure Preferences")).unwrap_or(Value::Null);
    let get = |pointer: &str| secure.pointer(pointer).or_else(|| prefs.pointer(pointer)).cloned();
    let mut out = Vec::new();
    let mut push = |setting: &str, value: String, reason: String, blocked: bool| {
        out.push(SettingFinding {
            browser: browser.into(),
            profile: profile.into(),
            profile_name: profile_name.into(),
            setting: setting.into(),
            value,
            reason,
            blocked,
        })
    };
    let blocked_by_rules = |url: &str| rules.map(|r| r.classify_url(url)).filter(|v| v.blocks());

    if let Some(url) = get("/default_search_provider_data/template_url_data/url").and_then(|v| v.as_str().map(str::to_string)) {
        let host = WebAddress::parse(&url.replace("{searchTerms}", "x")).map(|a| a.host).unwrap_or_default();
        if let Some(v) = blocked_by_rules(&url) {
            push("search engine", url.clone(), format!("points to a blocked site ({})", v.threat), true);
        } else if !host.is_empty() && !known_search_engine(&host) {
            push("search engine", url.clone(), format!("{host} is not a well-known search engine; check you chose it"), false);
        }
    }
    let homepage_is_ntp = get("/homepage_is_newtabpage").and_then(|v| v.as_bool()).unwrap_or(true);
    if let (false, Some(url)) = (homepage_is_ntp, get("/homepage").and_then(|v| v.as_str().map(str::to_string))) {
        if let Some(v) = blocked_by_rules(&url) {
            push("home page", url, format!("points to a blocked site ({})", v.threat), true);
        }
    }
    if get("/session/restore_on_startup").and_then(|v| v.as_i64()) == Some(4) {
        for url in strings(get("/session/startup_urls").as_ref()) {
            if let Some(v) = blocked_by_rules(&url) {
                push("start-up page", url, format!("points to a blocked site ({})", v.threat), true);
            }
        }
    }
    out
}

// ---------- removal ----------

/// Whether the browser using `user_data` is running (it holds `lockfile`
/// open exclusively while it runs).
pub fn browser_running(user_data: &Path) -> bool {
    let lock = user_data.join("lockfile");
    lock.exists() && std::fs::OpenOptions::new().read(true).write(true).open(&lock).is_err()
}

#[derive(Debug, Serialize, Deserialize)]
struct RestoreInfo {
    browser: String,
    user_data: PathBuf,
    profile: String,
    id: String,
    /// Where the extension folder was (moved into `extension/`).
    extension_dir: Option<PathBuf>,
    mac_key: Option<String>,
    mac_value: Option<String>,
    removed_at: String,
}

/// Removes extension `id` from a profile. Returns the backup folder.
pub fn remove_extension(browser: &Browser, profile: &str, id: &str, backup_root: &Path) -> Result<PathBuf> {
    if !is_extension_id(id) {
        bail!("`{id}` is not an extension ID");
    }
    if browser_running(&browser.user_data) {
        bail!("{} is running; close it completely (check the tray) and try again", browser.name);
    }
    let profile_dir = browser.user_data.join(profile);
    let settings = extension_settings(&profile_dir)?;
    if !settings.contains_key(id) {
        bail!("extension {id} is not installed in {} ({profile})", browser.name);
    }

    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let backup = backup_root.join(format!("{stamp}-{}-{}-{id}", slug(&browser.name), slug(profile)));
    std::fs::create_dir_all(&backup).with_context(|| format!("creating {}", backup.display()))?;
    for file in ["Preferences", "Secure Preferences"] {
        let src = profile_dir.join(file);
        if src.is_file() {
            std::fs::copy(&src, backup.join(file)).with_context(|| format!("backing up {}", src.display()))?;
        }
    }

    // Only folders inside the profile are moved; an unpacked extension's
    // source folder belongs to whoever put it there.
    let installed = profile_dir.join("Extensions").join(id);
    let extension_dir = installed.is_dir().then_some(installed);
    let mac_key = browser.mac_key.map(|k| format!(r"{k}\{profile}\extensions.settings"));
    let mac_value = mac_key.as_deref().and_then(|k| read_mac(k, id));
    let info = RestoreInfo {
        browser: browser.name.clone(),
        user_data: browser.user_data.clone(),
        profile: profile.to_string(),
        id: id.to_string(),
        extension_dir: extension_dir.clone(),
        mac_key: mac_key.clone(),
        mac_value,
        removed_at: crate::store::now(),
    };
    std::fs::write(backup.join("restore.json"), serde_json::to_string_pretty(&info)?)?;

    for file in ["Preferences", "Secure Preferences"] {
        let path = profile_dir.join(file);
        let Some(mut prefs) = read_json(&path) else { continue };
        if strip_extension(&mut prefs, id) {
            std::fs::write(&path, serde_json::to_vec(&prefs)?).with_context(|| format!("updating {}", path.display()))?;
        }
    }
    if let Some(dir) = &extension_dir {
        move_dir(dir, &backup.join("extension"))?;
    }
    if let Some(key) = &mac_key {
        delete_mac(key, id);
    }
    Ok(backup)
}

/// Undoes [`remove_extension`] from its backup folder. Preference changes
/// made since the removal are lost.
pub fn restore_extension(backup: &Path) -> Result<String> {
    let info: RestoreInfo = serde_json::from_str(&std::fs::read_to_string(backup.join("restore.json")).context("reading restore.json")?)?;
    if browser_running(&info.user_data) {
        bail!("{} is running; close it completely and try again", info.browser);
    }
    let profile_dir = info.user_data.join(&info.profile);
    for file in ["Preferences", "Secure Preferences"] {
        let saved = backup.join(file);
        if saved.is_file() {
            std::fs::copy(&saved, profile_dir.join(file)).with_context(|| format!("restoring {file}"))?;
        }
    }
    if let Some(dir) = &info.extension_dir {
        if backup.join("extension").is_dir() && !dir.exists() {
            move_dir(&backup.join("extension"), dir)?;
        }
    }
    if let (Some(key), Some(value)) = (&info.mac_key, &info.mac_value) {
        write_mac(key, &info.id, value);
    }
    Ok(format!("{} restored to {} ({})", info.id, info.browser, info.profile))
}

/// Deletes every trace of `id` from one preferences document. Returns
/// whether anything changed.
fn strip_extension(prefs: &mut Value, id: &str) -> bool {
    let mut changed = false;
    for pointer in ["/extensions/settings", "/protection/macs/extensions/settings"] {
        if let Some(map) = prefs.pointer_mut(pointer).and_then(Value::as_object_mut) {
            changed |= map.remove(id).is_some();
        }
    }
    for pointer in ["/extensions/pinned_extensions", "/extensions/toolbar"] {
        if let Some(list) = prefs.pointer_mut(pointer).and_then(Value::as_array_mut) {
            let before = list.len();
            list.retain(|v| v.as_str() != Some(id));
            changed |= list.len() != before;
        }
    }
    changed
}

fn move_dir(from: &Path, to: &Path) -> Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    copy_dir(from, to)?;
    std::fs::remove_dir_all(from).with_context(|| format!("removing {}", from.display()))
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target).with_context(|| format!("copying {}", entry.path().display()))?;
        }
    }
    Ok(())
}

fn slug(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect()
}

fn read_mac(key: &str, id: &str) -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        RegKey::predef(HKEY_CURRENT_USER).open_subkey(key).ok()?.get_value(id).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = (key, id);
        None
    }
}

fn delete_mac(key: &str, id: &str) {
    #[cfg(windows)]
    {
        use winreg::{enums::{HKEY_CURRENT_USER, KEY_SET_VALUE}, RegKey};
        if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(key, KEY_SET_VALUE) {
            let _ = k.delete_value(id);
        }
    }
    #[cfg(not(windows))]
    let _ = (key, id);
}

fn write_mac(key: &str, id: &str, value: &str) {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        if let Ok((k, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(key) {
            let _ = k.set_value(id, &value.to_string());
        }
    }
    #[cfg(not(windows))]
    let _ = (key, id, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::rules::{Origin, UserLists};
    use serde_json::json;

    const BAD: &str = "abcdefghijklmnopabcdefghijklmnop";
    const RISKY: &str = "ppppppppppppppppaaaaaaaaaaaaaaaa";
    const PLAIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A profile with three installed extensions and a hijacked search engine.
    fn profile(root: &Path) -> PathBuf {
        let dir = root.join("Default");
        let ext = |id: &str, manifest: Value| {
            let d = dir.join("Extensions").join(id).join("1.0_0");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("manifest.json"), manifest.to_string()).unwrap();
        };
        ext(BAD, json!({"name": "__MSG_appName__", "default_locale": "en", "version": "1.0", "permissions": ["tabs"]}));
        std::fs::create_dir_all(dir.join("Extensions").join(BAD).join("1.0_0/_locales/en")).unwrap();
        std::fs::write(dir.join("Extensions").join(BAD).join("1.0_0/_locales/en/messages.json"), r#"{"appname": {"message": "Free Coupons"}}"#).unwrap();
        ext(RISKY, json!({
            "name": "Super Search", "version": "2.0",
            "permissions": ["proxy", "management", "cookies", "webRequest"],
            "host_permissions": ["<all_urls>"],
            "chrome_settings_overrides": {"search_provider": {"search_url": "https://evil-search.example/?q={searchTerms}"}}
        }));
        ext(PLAIN, json!({"name": "Dark Reader-ish", "version": "3.0", "permissions": ["storage"]}));
        let settings = |id: &str, location: i64, webstore: bool| json!({"path": format!("{id}/1.0_0"), "location": location, "from_webstore": webstore});
        let prefs = json!({
            "extensions": {"settings": {BAD: settings(BAD, 1, true)}, "pinned_extensions": [BAD, PLAIN]},
            "default_search_provider_data": {"template_url_data": {"url": "https://evil-search.example/?q={searchTerms}"}},
            "homepage_is_newtabpage": false,
            "homepage": "http://blocktest.phalanx.invalid/",
        });
        let secure = json!({
            "extensions": {"settings": {RISKY: settings(RISKY, 8, false), PLAIN: settings(PLAIN, 1, true), "mhjfbmdgcfjbbpaeojofohoefgiehjai": {"location": 5}}},
            "protection": {"macs": {"extensions": {"settings": {BAD: "AA", RISKY: "BB", PLAIN: "CC"}}}},
        });
        std::fs::write(dir.join("Preferences"), prefs.to_string()).unwrap();
        std::fs::write(dir.join("Secure Preferences"), secure.to_string()).unwrap();
        dir
    }

    #[test]
    fn rates_extensions_and_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = profile(tmp.path());
        let mut known = KnownBad::default();
        known.add_text(&format!("# comment\n{BAD} pup Adware.FreeCoupons\nnot-an-id malware X\n"));
        assert_eq!(known.len(), 1);
        let mut rules = WebRules::load(None, &UserLists::default()).unwrap();
        rules.add_text("domain evil-search.example malware Hijacker", Origin::Feed, "t").unwrap();

        let (exts, settings) = scan_profile("Chrome", &dir, "Default", "Person 1", Some(&rules), &known).unwrap();
        assert_eq!(exts.len(), 3, "component extension skipped");
        let by_id = |id: &str| exts.iter().find(|e| e.id == id).unwrap();

        let bad = by_id(BAD);
        assert_eq!((bad.name.as_str(), bad.category, bad.threat.as_deref()), ("Free Coupons", Some(Category::Pup), Some("Adware.FreeCoupons")));
        assert_eq!(bad.rating(), "unwanted");

        let risky = by_id(RISKY);
        assert_eq!(risky.category, Some(Category::Suspicious));
        assert!(risky.score >= SUSPICIOUS_SCORE, "{}", risky.score);
        assert!(risky.reasons.iter().any(|r| r.contains("--load-extension")));
        assert!(risky.reasons.iter().any(|r| r.contains("search engine")));

        assert_eq!(by_id(PLAIN).rating(), "ok");

        let kinds: Vec<(&str, bool)> = settings.iter().map(|s| (s.setting.as_str(), s.blocked)).collect();
        assert_eq!(kinds, [("search engine", true), ("home page", true)]);
    }

    #[test]
    fn remove_and_restore_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let user_data = tmp.path().join("User Data");
        let dir = profile(&user_data);
        let browser = Browser { name: "Test Browser".into(), user_data: user_data.clone(), mac_key: None };
        let before_secure = std::fs::read(dir.join("Secure Preferences")).unwrap();

        let backup = remove_extension(&browser, "Default", RISKY, &tmp.path().join("backups")).unwrap();
        assert!(!dir.join("Extensions").join(RISKY).exists());
        assert!(backup.join("extension/1.0_0/manifest.json").is_file());
        let secure = read_json(&dir.join("Secure Preferences")).unwrap();
        assert!(secure.pointer(&format!("/extensions/settings/{RISKY}")).is_none());
        assert!(secure.pointer(&format!("/protection/macs/extensions/settings/{RISKY}")).is_none());
        assert!(secure.pointer(&format!("/extensions/settings/{PLAIN}")).is_some(), "others untouched");
        let (exts, _) = scan_profile("T", &dir, "Default", "P", None, &KnownBad::default()).unwrap();
        assert!(exts.iter().all(|e| e.id != RISKY));

        assert!(remove_extension(&browser, "Default", RISKY, &tmp.path().join("backups")).is_err(), "already gone");
        assert!(remove_extension(&browser, "Default", "nope", &tmp.path().join("backups")).is_err());

        restore_extension(&backup).unwrap();
        assert_eq!(std::fs::read(dir.join("Secure Preferences")).unwrap(), before_secure);
        assert!(dir.join("Extensions").join(RISKY).join("1.0_0/manifest.json").is_file());
    }

    #[test]
    fn store_extensions_are_only_reviewed_on_permissions() {
        let manifest = json!({"name": "Assistant", "permissions": ["debugger", "nativeMessaging", "history", "downloads"], "host_permissions": ["<all_urls>"]});
        let store = assess(PLAIN, &json!({"location": 1, "from_webstore": true}), &manifest, None, &KnownBad::default());
        assert!(store.score >= SUSPICIOUS_SCORE);
        assert_eq!((store.category, store.rating()), (None, "review"));
        let sideloaded = assess(PLAIN, &json!({"location": 4}), &manifest, None, &KnownBad::default());
        assert_eq!(sideloaded.category, Some(Category::Suspicious));
        let flagged = assess(PLAIN, &json!({"location": 1, "from_webstore": true, "blocklist_state": 1}), &manifest, None, &KnownBad::default());
        assert_eq!(flagged.category, Some(Category::Malware));
    }

    #[test]
    fn strips_pins_and_toolbar_entries() {
        let mut prefs = json!({"extensions": {"pinned_extensions": [BAD, PLAIN], "toolbar": [BAD]}});
        assert!(strip_extension(&mut prefs, BAD));
        assert_eq!(prefs["extensions"]["pinned_extensions"], json!([PLAIN]));
        assert!(!strip_extension(&mut prefs, BAD));
    }

    #[test]
    fn search_engines_and_ids() {
        assert!(known_search_engine("www.google.co.uk"));
        assert!(known_search_engine("duckduckgo.com"));
        assert!(!known_search_engine("google-search.example"));
        assert!(!known_search_engine("notbing.com"));
        assert!(is_extension_id(super::super::native::CHROMIUM_EXTENSION_ID));
        assert!(!is_extension_id("abc"));
    }
}
