//! Browser hardening check: read-only settings that decide how well each
//! Chromium browser profile resists the attacks that matter most here:
//! exploits through a just-opened page, and stealers copying saved data.
//!
//! * Version: an update downloaded but waiting for a restart (Chromium keeps
//!   `new_chrome.exe` / `new_msedge.exe` beside the old one until then), and
//!   whether a newer stable release exists (public version feeds; optional).
//! * Safe Browsing level (standard or enhanced) and the JavaScript optimizer
//!   setting (turning it off removes the code most browser exploits target).
//! * Secure DNS, which bypasses Phalanx's DNS filter (Browser Guard still
//!   blocks in the browser).
//! * Whether Phalanx Browser Guard is installed in the profile.
//! * How many passwords the profile stores: what stealers copy first. Only
//!   rows are counted; nothing is read or decrypted.

use super::extensions::{self, Browser};
use crate::posture::{Check, Link, Status};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    pub browser: String,
    /// The name the browser shows for the profile.
    pub profile: String,
    /// The profile's folder (`Default`, `Profile 1`), which opens its pages.
    pub profile_dir: String,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionReport {
    pub browser: String,
    pub installed: Option<String>,
    /// Newest stable release, when the version feed could be reached.
    pub latest: Option<String>,
    pub restart_pending: bool,
    pub check: Check,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HardeningReport {
    pub versions: Vec<VersionReport>,
    pub profiles: Vec<ProfileReport>,
}

/// Where each browser keeps its program files (per-machine, then per-user).
fn install_dirs(name: &str) -> Vec<PathBuf> {
    let env = |n: &str| std::env::var_os(n).map(PathBuf::from);
    let (pf, pf86, local) = (env("ProgramFiles"), env("ProgramFiles(x86)"), env("LOCALAPPDATA"));
    let rel = match name {
        "Google Chrome" => r"Google\Chrome\Application",
        "Microsoft Edge" => r"Microsoft\Edge\Application",
        "Brave" => r"BraveSoftware\Brave-Browser\Application",
        "Vivaldi" => r"Vivaldi\Application",
        "Chromium" => r"Chromium\Application",
        _ => return Vec::new(),
    };
    [pf, pf86, local].into_iter().flatten().map(|b| b.join(rel)).filter(|d| d.is_dir()).collect()
}

/// The browser's program file, without `.exe`.
fn exe_name(name: &str) -> &'static str {
    match name {
        "Google Chrome" | "Chromium" => "chrome",
        "Microsoft Edge" => "msedge",
        "Brave" => "brave",
        "Vivaldi" => "vivaldi",
        _ => "chrome",
    }
}

/// The name links use for the browser (`start:<program> <page>`).
fn program(name: &str) -> &'static str {
    match name {
        "Chromium" => "chromium",
        name => exe_name(name),
    }
}

const BROWSERS: [&str; 5] = ["Google Chrome", "Microsoft Edge", "Brave", "Vivaldi", "Chromium"];

/// Settings page for a browser, opened with the browser itself.
fn settings_link(name: &str) -> Link {
    match name {
        "Google Chrome" => Link { label: "Open Chrome security settings", target: "start:chrome chrome://settings/security" },
        "Microsoft Edge" => Link { label: "Open Edge privacy and security settings", target: "start:msedge edge://settings/privacy" },
        "Brave" => Link { label: "Open Brave security settings", target: "start:brave brave://settings/security" },
        // Vivaldi answers Chromium's own page addresses.
        "Vivaldi" => Link { label: "Open Vivaldi security settings", target: "start:vivaldi chrome://settings/security" },
        "Chromium" => Link { label: "Open Chromium security settings", target: "start:chromium chrome://settings/security" },
        _ => Link { label: "Open the browser's settings", target: "start:chrome chrome://settings/security" },
    }
}

/// Opens a browser's own page (`chrome://settings/security`) with that
/// browser, in the given profile folder when one is named. `program` is the
/// browser's program name (`chrome`, `msedge`, `brave`, `vivaldi`).
/// Chromium ignores internal pages given on its command line, so the page
/// goes through Browser Guard ([`crate::posture::browser_page_address`]).
pub fn open_browser_page(program_name: &str, page: &str, profile: Option<&str>) -> std::io::Result<()> {
    let address = crate::posture::browser_page_address(page);
    let installed = BROWSERS
        .into_iter()
        .filter(|name| program(name) == program_name)
        .flat_map(|name| install_dirs(name).into_iter().map(move |dir| dir.join(format!("{}.exe", exe_name(name)))))
        .find(|exe| exe.is_file());
    let Some(exe) = installed else {
        // Not in a usual folder: let Windows find it (App Paths). The profile
        // cannot be passed safely through `start`, so the last one used opens.
        let mut command = std::process::Command::new("cmd");
        command.args(["/c", "start", "", program_name, &address]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        return command.spawn().map(drop);
    };
    let mut command = std::process::Command::new(exe);
    // A running browser hands the request to the window of that profile.
    if let Some(profile) = profile.filter(|p| is_profile_folder(p)) {
        command.arg(format!("--profile-directory={profile}"));
    }
    command.arg(address).spawn().map(drop)
}

/// Profile folder names as Chromium makes them (`Default`, `Profile 3`,
/// `Guest Profile`): nothing that could act as another argument.
fn is_profile_folder(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && name.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_')
}

/// The browser's own password manager.
fn passwords_link(name: &str) -> Link {
    let label = "Open the browser's password manager";
    match name {
        "Microsoft Edge" => Link { label, target: "start:msedge edge://wallet/passwords" },
        "Brave" => Link { label, target: "start:brave brave://password-manager/passwords" },
        "Vivaldi" => Link { label: "Open Vivaldi settings (Privacy and security > Passwords)", target: "start:vivaldi chrome://settings/security" },
        "Chromium" => Link { label, target: "start:chromium chrome://password-manager/passwords" },
        _ => Link { label, target: "start:chrome chrome://password-manager/passwords" },
    }
}

/// Every browser page the checks link to, for tests.
pub fn browser_links() -> Vec<&'static str> {
    BROWSERS
        .iter()
        .flat_map(|name| [settings_link(name), update_link(name), passwords_link(name)])
        .map(|link| link.target)
        .collect()
}

fn update_link(name: &str) -> Link {
    match name {
        "Google Chrome" => Link { label: "Open About Chrome (updates and restarts)", target: "start:chrome chrome://settings/help" },
        "Microsoft Edge" => Link { label: "Open About Edge (updates and restarts)", target: "start:msedge edge://settings/help" },
        "Brave" => Link { label: "Open About Brave (updates and restarts)", target: "start:brave brave://settings/help" },
        "Vivaldi" => Link { label: "Open About Vivaldi (updates and restarts)", target: "start:vivaldi chrome://settings/help" },
        _ => settings_link(name),
    }
}

/// Version folders (`146.0.7680.80`) beside the browser program.
fn installed_version(dirs: &[PathBuf]) -> Option<String> {
    dirs.iter()
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| parse_version(n).is_some())
        .max_by_key(|n| parse_version(n))
}

pub fn parse_version(text: &str) -> Option<Vec<u32>> {
    let parts: Option<Vec<u32>> = text.trim().split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| p.len() == 4)
}

/// Newest stable versions from Google's and Microsoft's public version feeds.
/// Only the request is sent; nothing about this PC.
pub fn latest_versions(timeout: Duration) -> Vec<(&'static str, String)> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).build().into();
    let get = |url: &str| -> Option<Value> {
        let text = agent.get(url).call().ok()?.into_body().read_to_string().ok()?;
        serde_json::from_str(&text).ok()
    };
    let mut out = Vec::new();
    // Releases currently being served, with the share of users each is
    // offered to. A new version is listed at 0% before its rollout starts,
    // so the newest *offered* version is the highest one above 0%.
    if let Some(v) = get("https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions/all/releases?filter=endtime=none") {
        if let Some(version) = newest_offered(&v) {
            out.push(("Google Chrome", version));
        }
    }
    if let Some(v) = get("https://edgeupdates.microsoft.com/api/products") {
        let stable = v.as_array().into_iter().flatten().find(|p| p["Product"] == "Stable");
        let version = stable
            .and_then(|p| p["Releases"].as_array())
            .into_iter()
            .flatten()
            .filter(|r| r["Platform"] == "Windows" && r["Architecture"] == "x64")
            .filter_map(|r| r["ProductVersion"].as_str())
            .max_by_key(|v| parse_version(v));
        if let Some(version) = version {
            out.push(("Microsoft Edge", version.to_string()));
        }
    }
    out
}

/// The highest version in a VersionHistory `releases` reply that is offered
/// to some users (rollout fraction above 0).
fn newest_offered(releases: &Value) -> Option<String> {
    releases["releases"]
        .as_array()?
        .iter()
        .filter(|r| r["fraction"].as_f64().is_some_and(|f| f > 0.0))
        .filter_map(|r| r["version"].as_str())
        .max_by_key(|v| parse_version(v))
        .map(str::to_string)
}

/// The version check for one browser.
pub fn version_check(name: &str, installed: Option<&str>, latest: Option<&str>, restart_pending: bool) -> Check {
    let behind = match (installed.and_then(parse_version), latest.and_then(parse_version)) {
        (Some(i), Some(l)) => Some(i < l),
        _ => None,
    };
    let (status, detail) = match (restart_pending, behind) {
        (true, _) => (Status::Risk, format!("An update is downloaded but only applies after you restart {name}. Until then, its fixes for actively exploited bugs are not active.")),
        (false, Some(true)) => (
            Status::Attention,
            format!(
                "Version {} is installed; version {} is being rolled out. Open About to update (a gradual rollout may not offer it to you yet).",
                installed.unwrap_or("?"),
                latest.unwrap_or("?")
            ),
        ),
        (false, Some(false)) => (Status::Good, format!("Up to date ({})", installed.unwrap_or("?"))),
        (false, None) => (Status::Info, format!("Version {} (could not check for a newer one)", installed.unwrap_or("unknown"))),
    };
    Check {
        id: "browser_version",
        title: "Up to date",
        why: "Zero-click attacks use bugs the browser has already fixed; an update only protects you once the browser restarts.",
        status,
        detail,
        weight: 5,
        link: update_link(name),
        fix: None,
        toggle: None,
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Checks one profile from its preference files and password store.
pub fn profile_checks(browser: &Browser, dir: &str, local_state: Option<&Value>) -> Vec<Check> {
    let profile = browser.user_data.join(dir);
    let prefs = read_json(&profile.join("Preferences")).unwrap_or(Value::Null);
    let secure = read_json(&profile.join("Secure Preferences")).unwrap_or(Value::Null);
    build_profile_checks(&browser.name, &prefs, &secure, local_state, count_passwords(&profile))
}

pub fn build_profile_checks(name: &str, prefs: &Value, secure: &Value, local_state: Option<&Value>, passwords: Option<u64>) -> Vec<Check> {
    let link = settings_link(name);
    let mut checks = Vec::new();
    let edge = name == "Microsoft Edge";

    // Safe Browsing: missing keys are Chromium's default (standard, on).
    let sb = |key: &str| prefs.pointer(&format!("/safebrowsing/{key}")).and_then(Value::as_bool);
    let (status, detail) = if edge {
        (Status::Info, "Edge uses Microsoft Defender SmartScreen (see Protection)".to_string())
    } else {
        match (sb("enabled"), sb("enhanced")) {
            (Some(false), _) => (Status::Risk, "Off: no warnings for known malicious sites or downloads".to_string()),
            (_, Some(true)) => (Status::Good, "Enhanced protection".to_string()),
            _ => (Status::Attention, "Standard protection. Enhanced protection checks sites and downloads in real time".to_string()),
        }
    };
    checks.push(Check {
        id: "safe_browsing",
        title: "Safe Browsing",
        why: "The browser's own check of sites and downloads against Google's live threat lists.",
        status,
        detail,
        weight: 3,
        link,
        fix: None,
        toggle: None,
    });

    // JavaScript optimizer (V8 JIT): content setting 2 = blocked everywhere.
    let jit = prefs.pointer("/profile/default_content_setting_values/javascript_optimizer").and_then(Value::as_i64);
    let (status, detail) = match jit {
        Some(2) => (Status::Good, "Off for all sites".to_string()),
        _ if edge => (Status::Info, "Edge calls this \"Enhanced security for the web\" (set it to Strict)".to_string()),
        _ => (Status::Attention, "On. Turning it off makes some heavy sites slower but removes the part of the browser most exploits target".to_string()),
    };
    checks.push(Check {
        id: "js_optimizer",
        title: "JavaScript optimizer",
        why: "Most browser zero-days attack the JavaScript optimizer. Turning it off (Settings > Privacy and security > Security > Manage V8 security, or Edge's enhanced security) blocks many of them.",
        status,
        detail,
        weight: 2,
        link,
        fix: None,
        toggle: None,
    });

    // Secure DNS lives in Local State, for all profiles.
    let mode = local_state.and_then(|s| s.pointer("/dns_over_https/mode")).and_then(Value::as_str);
    let (status, detail) = match mode {
        Some("secure") => (Status::Info, "Always on: Phalanx's DNS filter does not see this browser's lookups (Browser Guard still blocks)".to_string()),
        Some("off") => (Status::Info, "Off: lookups go through Windows, so Phalanx's DNS filter applies".to_string()),
        _ => (Status::Info, "Automatic: used only when your DNS provider supports it".to_string()),
    };
    checks.push(Check {
        id: "secure_dns",
        title: "Secure DNS",
        why: "Encrypted DNS hides lookups from the network, but also from Phalanx's DNS filter.",
        status,
        detail,
        weight: 0,
        link,
        fix: None,
        toggle: None,
    });

    // Browser Guard: present in either preference file's extension settings.
    let installed = [prefs, secure].iter().any(|p| p.pointer(&format!("/extensions/settings/{}", super::native::CHROMIUM_EXTENSION_ID)).is_some());
    checks.push(Check {
        id: "browser_guard",
        title: "Phalanx Browser Guard",
        why: "Blocks malicious sites before the browser sends any request to them, and works even when secure DNS is on.",
        status: if installed { Status::Good } else { Status::Risk },
        detail: if installed { "Installed".to_string() } else { "Not installed in this profile: install it from the Web protection page".to_string() },
        weight: 4,
        link: Link { label: "Open the Web protection page in Phalanx", target: "" },
        fix: None,
        toggle: None,
    });

    let (status, detail) = match passwords {
        Some(0) => (Status::Good, "No passwords saved in the browser".to_string()),
        Some(n) => (
            Status::Attention,
            format!("{n} passwords are saved in this profile. A stealer running as you can copy all of them; a password manager with its own master password, or passkeys, is safer"),
        ),
        None => (Status::Unknown, "Could not read the password store".to_string()),
    };
    checks.push(Check {
        id: "saved_passwords",
        title: "Saved passwords",
        why: "Infostealers copy the browser's saved passwords and session cookies first. Passwords alone are not all they take: sign out of other sessions after an infection.",
        status,
        detail,
        weight: 2,
        link: passwords_link(name),
        fix: None,
        toggle: None,
    });
    checks
}

/// Rows in the profile's password databases. Reads a copy (the browser keeps
/// the file locked) and counts entries; nothing is read or decrypted.
fn count_passwords(profile: &Path) -> Option<u64> {
    let mut total = 0;
    let mut any = false;
    for file in ["Login Data", "Login Data For Account"] {
        let path = profile.join(file);
        if !path.is_file() {
            continue;
        }
        let tmp = std::env::temp_dir().join(format!("phalanx-logins-{}.db", std::process::id()));
        if std::fs::copy(&path, &tmp).is_err() {
            continue;
        }
        let count = rusqlite::Connection::open_with_flags(&tmp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .and_then(|db| db.query_row("SELECT COUNT(*) FROM logins WHERE blacklisted_by_user = 0", [], |r| r.get::<_, i64>(0)));
        let _ = std::fs::remove_file(&tmp);
        if let Ok(n) = count {
            total += n.max(0) as u64;
            any = true;
        }
    }
    any.then_some(total)
}

/// Checks every Chromium browser profile of this user. `online` also asks
/// the public version feeds for the newest stable versions.
pub fn check(online: bool) -> HardeningReport {
    let latest = if online { latest_versions(Duration::from_secs(8)) } else { Vec::new() };
    let mut report = HardeningReport::default();
    for browser in extensions::browsers() {
        let dirs = install_dirs(&browser.name);
        if !dirs.is_empty() {
            let installed = installed_version(&dirs);
            let pending = dirs.iter().any(|d| d.join(format!("new_{}.exe", exe_name(&browser.name))).is_file());
            let newest = latest.iter().find(|(n, _)| *n == browser.name).map(|(_, v)| v.clone());
            let check = version_check(&browser.name, installed.as_deref(), newest.as_deref(), pending);
            report.versions.push(VersionReport { browser: browser.name.clone(), installed, latest: newest, restart_pending: pending, check });
        }
        let local_state = read_json(&browser.user_data.join("Local State"));
        for (dir, display) in extensions::profiles(&browser.user_data) {
            report.profiles.push(ProfileReport {
                browser: browser.name.clone(),
                profile: display,
                checks: profile_checks(&browser, &dir, local_state.as_ref()),
                profile_dir: dir,
            });
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn find<'a>(checks: &'a [Check], id: &str) -> &'a Check {
        checks.iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn only_real_profile_folders_reach_the_command_line() {
        assert!(is_profile_folder("Default"));
        assert!(is_profile_folder("Profile 12"));
        assert!(is_profile_folder("Guest Profile"));
        assert!(!is_profile_folder("--disable-web-security"));
        assert!(!is_profile_folder("Profile 1\" --x"));
        assert!(!is_profile_folder(""));
        // Every browser opens its own pages, never another browser's.
        for name in BROWSERS {
            for link in [settings_link(name), update_link(name), passwords_link(name)] {
                assert!(link.target.starts_with(&format!("start:{} ", program(name))), "{name}: {}", link.target);
            }
        }
    }

    #[test]
    fn versions_compare_numerically_and_restarts_come_first() {
        assert!(parse_version("146.0.7680.80") < parse_version("146.0.7680.153"));
        assert!(parse_version("99.0.1.2") < parse_version("100.0.0.0"));
        assert_eq!(parse_version("146.0"), None);
        assert_eq!(version_check("Google Chrome", Some("146.0.1.1"), Some("146.0.1.1"), true).status, Status::Risk);
        assert_eq!(version_check("Google Chrome", Some("146.0.1.1"), Some("146.0.2.0"), false).status, Status::Attention);
        assert_eq!(version_check("Google Chrome", Some("146.0.2.0"), Some("146.0.2.0"), false).status, Status::Good);
        assert_eq!(version_check("Google Chrome", Some("146.0.2.0"), None, false).status, Status::Info);
    }

    #[test]
    fn versions_listed_before_their_rollout_are_ignored() {
        // Shape of Google's VersionHistory reply on 2026-10-19: 156 is listed
        // but offered to no one yet; 155.0.8059.85 is fully rolled out.
        let releases = json!({"releases": [
            {"version": "155.0.8059.80", "fraction": 0.5},
            {"version": "156.0.8078.35", "fraction": 0},
            {"version": "155.0.8059.85", "fraction": 1},
            {"version": "156.0.8078.36", "fraction": 0},
        ]});
        let offered = newest_offered(&releases);
        assert_eq!(offered.as_deref(), Some("155.0.8059.85"));
        assert_eq!(version_check("Google Chrome", Some("155.0.8059.85"), offered.as_deref(), false).status, Status::Good);
        assert_eq!(newest_offered(&json!({"releases": []})), None);
    }

    #[test]
    fn profile_settings_are_interpreted() {
        let prefs = json!({
            "safebrowsing": {"enabled": true, "enhanced": true},
            "profile": {"default_content_setting_values": {"javascript_optimizer": 2}},
        });
        let secure = json!({"extensions": {"settings": {super::super::native::CHROMIUM_EXTENSION_ID: {}}}});
        let local = json!({"dns_over_https": {"mode": "secure"}});
        let c = build_profile_checks("Google Chrome", &prefs, &secure, Some(&local), Some(0));
        assert_eq!(find(&c, "safe_browsing").status, Status::Good);
        assert_eq!(find(&c, "js_optimizer").status, Status::Good);
        assert!(find(&c, "secure_dns").detail.contains("does not see"));
        assert_eq!(find(&c, "browser_guard").status, Status::Good);
        assert_eq!(find(&c, "saved_passwords").status, Status::Good);

        let bare = build_profile_checks("Google Chrome", &json!({}), &json!({}), None, Some(42));
        assert_eq!(find(&bare, "safe_browsing").status, Status::Attention, "default is standard protection");
        assert_eq!(find(&bare, "js_optimizer").status, Status::Attention);
        assert_eq!(find(&bare, "browser_guard").status, Status::Risk);
        assert!(find(&bare, "saved_passwords").detail.starts_with("42 passwords"));

        let off = build_profile_checks("Google Chrome", &json!({"safebrowsing": {"enabled": false}}), &json!({}), None, None);
        assert_eq!(find(&off, "safe_browsing").status, Status::Risk);
        assert_eq!(find(&off, "saved_passwords").status, Status::Unknown);
    }

    #[test]
    fn password_rows_are_counted_without_reading_them() {
        let tmp = tempfile::tempdir().unwrap();
        let db = rusqlite::Connection::open(tmp.path().join("Login Data")).unwrap();
        db.execute_batch("CREATE TABLE logins (origin_url TEXT, password_value BLOB, blacklisted_by_user INTEGER); INSERT INTO logins VALUES ('a', x'00', 0), ('b', x'00', 0), ('never', NULL, 1);").unwrap();
        drop(db);
        assert_eq!(count_passwords(tmp.path()), Some(2), "never-save entries are not passwords");
        assert_eq!(count_passwords(&tmp.path().join("missing")), None);
    }
}
