//! Read-only checks of Windows security and privacy settings.
//!
//! Nothing here changes a setting. Each check reports what it read, or
//! `Unknown` with the reason when a value could not be read, and names the
//! Windows page where the user can change it themselves.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Protective / private.
    Good,
    /// Partly on, audit-only, or a weaker choice worth reviewing.
    Attention,
    /// Off, or sharing data.
    Risk,
    /// Shown for information; not scored (optional or not applicable).
    Info,
    /// Could not be read; not scored.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    /// Why it matters, in one sentence.
    pub why: &'static str,
    pub status: Status,
    /// What was read, e.g. "On" or "Off (set by your organisation)".
    pub detail: String,
    /// Relative importance in the score.
    pub weight: u32,
    pub link: Link,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Link {
    pub label: &'static str,
    /// A `windowsdefender:` or `ms-settings:` URI, or a program in System32.
    pub target: &'static str,
}

impl Link {
    /// Opens the Windows page. Targets are fixed constants, never user input.
    pub fn open(&self) -> std::io::Result<()> {
        if self.target.ends_with(".exe") {
            std::process::Command::new(self.target).spawn().map(drop)
        } else {
            std::process::Command::new("explorer.exe").arg(self.target).spawn().map(drop)
        }
    }
}

/// Weighted share of scored checks that are `Good` (`Attention` counts half).
/// Weight-0 checks are informational and never scored.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Score {
    pub percent: u32,
    pub scored: usize,
    pub unknown: usize,
}

pub fn score(checks: &[Check]) -> Option<Score> {
    let (mut got, mut total, mut scored, mut unknown) = (0, 0, 0, 0);
    for c in checks.iter().filter(|c| c.weight > 0) {
        match c.status {
            Status::Good => got += 2 * c.weight,
            Status::Attention => got += c.weight,
            Status::Risk => {}
            Status::Unknown => {
                unknown += 1;
                continue;
            }
            Status::Info => continue,
        }
        total += 2 * c.weight;
        scored += 1;
    }
    (total > 0).then(|| Score { percent: (got * 100 + total / 2) / total, scored, unknown })
}

pub fn level(percent: u32) -> &'static str {
    match percent {
        85.. => "Strong",
        60..85 => "Fair",
        _ => "Weak",
    }
}

// ---------------------------------------------------------------------------
// Values read from Windows
// ---------------------------------------------------------------------------

/// One registry value: present, absent, or unreadable.
#[derive(Debug, Clone, PartialEq)]
pub enum Reg<T> {
    Value(T),
    Missing,
    Error(String),
}

impl<T: Copy> Reg<T> {
    fn value(&self) -> Option<T> {
        match self {
            Reg::Value(v) => Some(*v),
            _ => None,
        }
    }
}

#[cfg(windows)]
mod reg {
    use super::Reg;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    pub enum Hive {
        User,
        Machine,
    }

    fn read<T: winreg::types::FromRegValue>(hive: Hive, path: &str, name: &str) -> Reg<T> {
        let root = RegKey::predef(match hive {
            Hive::User => HKEY_CURRENT_USER,
            Hive::Machine => HKEY_LOCAL_MACHINE,
        });
        match root.open_subkey(path).and_then(|k| k.get_value::<T, _>(name)) {
            Ok(v) => Reg::Value(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Reg::Missing,
            Err(e) => Reg::Error(e.to_string()),
        }
    }

    pub fn dword(hive: Hive, path: &str, name: &str) -> Reg<u32> {
        read(hive, path, name)
    }

    pub fn string(hive: Hive, path: &str, name: &str) -> Reg<String> {
        read(hive, path, name)
    }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// Microsoft Defender, Security Center and firewall state, read through
/// PowerShell (these have no stable registry form). Each part may be missing.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct DefenderState {
    pub mp: Option<MpStatus>,
    #[serde(rename = "mpError")]
    pub mp_error: Option<String>,
    pub pref: Option<MpPreference>,
    #[serde(rename = "prefError")]
    pub pref_error: Option<String>,
    pub av: Option<Vec<AvProduct>>,
    #[serde(rename = "avError")]
    pub av_error: Option<String>,
    pub fw: Option<Vec<FirewallProfile>>,
    #[serde(rename = "fwError")]
    pub fw_error: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct MpStatus {
    pub antivirus_enabled: Option<bool>,
    pub real_time_protection_enabled: Option<bool>,
    pub is_tamper_protected: Option<bool>,
    #[serde(rename = "AMRunningMode")]
    pub am_running_mode: Option<String>,
    pub antivirus_signature_age: Option<i64>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct MpPreference {
    #[serde(rename = "PUAProtection")]
    pub pua_protection: Option<i64>,
    pub enable_controlled_folder_access: Option<i64>,
    #[serde(rename = "MAPSReporting")]
    pub maps_reporting: Option<i64>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct AvProduct {
    pub name: String,
    pub state: i64,
}

impl AvProduct {
    /// Security Center `productState`: bits 12-15 are 1 when scanning is on.
    pub fn enabled(&self) -> bool {
        (self.state >> 12) & 0xF == 1
    }
    pub fn up_to_date(&self) -> bool {
        self.state & 0xF0 == 0
    }
    fn is_defender(&self) -> bool {
        let n = self.name.to_ascii_lowercase();
        n.contains("windows defender") || n.contains("microsoft defender")
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct FirewallProfile {
    pub name: String,
    /// `True`, `False` or `NotConfigured`.
    pub enabled: String,
}

/// Single quotes only, one statement per line: passed as one `-Command` argument.
const DEFENDER_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'; $r = @{}
try { $s = Get-MpComputerStatus; $r.mp = @{ AntivirusEnabled = $s.AntivirusEnabled; RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled; IsTamperProtected = $s.IsTamperProtected; AMRunningMode = [string]$s.AMRunningMode; AntivirusSignatureAge = [int64]$s.AntivirusSignatureAge } } catch { $r.mpError = $_.Exception.Message }
try { $p = Get-MpPreference; $r.pref = @{ PUAProtection = [int64]$p.PUAProtection; EnableControlledFolderAccess = [int64]$p.EnableControlledFolderAccess; MAPSReporting = [int64]$p.MAPSReporting } } catch { $r.prefError = $_.Exception.Message }
try { $r.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | ForEach-Object { @{ name = [string]$_.displayName; state = [int64]$_.productState } }) } catch { $r.avError = $_.Exception.Message }
try { $r.fw = @(Get-NetFirewallProfile | ForEach-Object { @{ name = [string]$_.Name; enabled = [string]$_.Enabled } }) } catch { $r.fwError = $_.Exception.Message }
$r | ConvertTo-Json -Depth 4 -Compress"#;

/// Runs the read-only PowerShell query (about 1 to 3 seconds).
pub fn read_defender_state() -> Result<DefenderState, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"])
            .arg(DEFENDER_SCRIPT.replace('\n', "; "))
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("could not run PowerShell: {e}"))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let json = text.trim().trim_start_matches('\u{feff}');
        if json.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("PowerShell returned nothing: {}", err.trim()));
        }
        parse_defender_state(json)
    }
    #[cfg(not(windows))]
    Err("only available on Windows".into())
}

pub fn parse_defender_state(json: &str) -> Result<DefenderState, String> {
    serde_json::from_str(json).map_err(|e| format!("unexpected PowerShell output: {e}"))
}

/// Security checks from the PowerShell state plus registry reads.
pub fn security_checks(defender: &Result<DefenderState, String>) -> Vec<Check> {
    #[cfg(windows)]
    let local = read_security_registry();
    #[cfg(not(windows))]
    let local = SecurityRegistry::unavailable();
    build_security_checks(defender, &local)
}

/// Registry values the security checks use.
#[derive(Debug, Clone)]
pub struct SecurityRegistry {
    pub smartscreen: Reg<String>,
    pub smartscreen_policy: Reg<u32>,
    pub smart_app_control: Reg<u32>,
    pub memory_integrity: Reg<u32>,
    pub uac_enabled: Reg<u32>,
    pub uac_admin_prompt: Reg<u32>,
    pub hide_file_ext: Reg<u32>,
}

fn off_windows<T>() -> Reg<T> {
    Reg::Error("only available on Windows".into())
}

impl SecurityRegistry {
    pub fn unavailable() -> Self {
        Self {
            smartscreen: off_windows(),
            smartscreen_policy: off_windows(),
            smart_app_control: off_windows(),
            memory_integrity: off_windows(),
            uac_enabled: off_windows(),
            uac_admin_prompt: off_windows(),
            hide_file_ext: off_windows(),
        }
    }
}

#[cfg(windows)]
fn read_security_registry() -> SecurityRegistry {
    use reg::{dword, string, Hive::*};
    SecurityRegistry {
        smartscreen: string(Machine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"),
        smartscreen_policy: dword(Machine, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
        smart_app_control: dword(Machine, r"SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState"),
        memory_integrity: dword(
            Machine,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled",
        ),
        uac_enabled: dword(Machine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
        uac_admin_prompt: dword(
            Machine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
        ),
        hide_file_ext: dword(User, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt"),
    }
}

const VIRUS_SETTINGS: Link = Link { label: "Open virus & threat protection settings", target: "windowsdefender://threatsettings" };
const APP_BROWSER: Link = Link { label: "Open app & browser control", target: "windowsdefender://appbrowser" };
const DEVICE_SECURITY: Link = Link { label: "Open device security", target: "windowsdefender://devicesecurity" };
const FIREWALL: Link = Link { label: "Open firewall & network protection", target: "windowsdefender://network" };
const RANSOMWARE: Link = Link { label: "Open virus & threat protection", target: "windowsdefender://threat" };
const UAC: Link = Link { label: "Open User Account Control settings", target: "UserAccountControlSettings.exe" };
const FILE_EXTENSIONS: Link = Link { label: "Open File Explorer settings", target: "ms-settings:developers" };

fn unknown(reason: impl Into<String>) -> (Status, String) {
    (Status::Unknown, format!("Could not read: {}", reason.into()))
}

fn reg_unknown<T>(r: &Reg<T>) -> (Status, String) {
    match r {
        Reg::Error(e) => unknown(e.clone()),
        _ => unknown("not set"),
    }
}

pub fn build_security_checks(defender: &Result<DefenderState, String>, reg: &SecurityRegistry) -> Vec<Check> {
    let state = defender.as_ref().ok();
    let ps_error = defender.as_ref().err().cloned();
    let mp = state.and_then(|s| s.mp.as_ref());
    let pref = state.and_then(|s| s.pref.as_ref());
    let others: Vec<&AvProduct> = state
        .and_then(|s| s.av.as_ref())
        .map(|av| av.iter().filter(|p| !p.is_defender()).collect())
        .unwrap_or_default();
    let other_on = others.iter().find(|p| p.enabled());
    let defender_rtp = mp.and_then(|m| m.real_time_protection_enabled);
    // Defender settings matter only while Defender is the active antivirus.
    let defender_active = defender_rtp == Some(true)
        || mp.and_then(|m| m.am_running_mode.as_deref()).is_some_and(|m| m.eq_ignore_ascii_case("Normal"));
    let replaced = other_on.is_some() && !defender_active;
    let mp_reason = || {
        state
            .and_then(|s| s.mp_error.clone())
            .or_else(|| ps_error.clone())
            .unwrap_or_else(|| "Defender did not report its status".into())
    };
    let pref_reason = || {
        state
            .and_then(|s| s.pref_error.clone())
            .or_else(|| ps_error.clone())
            .unwrap_or_else(|| "Defender did not report its settings".into())
    };

    let mut checks = Vec::new();

    let (status, detail) = match (defender_rtp, other_on) {
        (Some(true), _) => {
            let age = mp.and_then(|m| m.antivirus_signature_age);
            match age {
                Some(days) if days > 7 => (Status::Attention, format!("Microsoft Defender is on, but its definitions are {days} days old")),
                _ => (Status::Good, "Microsoft Defender real-time protection is on".to_string()),
            }
        }
        (_, Some(p)) if p.up_to_date() => (Status::Good, format!("Protected by {}", p.name)),
        (_, Some(p)) => (Status::Attention, format!("{} is on, but reports out-of-date definitions", p.name)),
        (Some(false), None) => (Status::Risk, "Off: no antivirus is scanning files as they are opened".to_string()),
        (None, None) => unknown(mp_reason()),
    };
    checks.push(Check {
        id: "realtime",
        title: "Real-time antivirus protection",
        why: "Scans files as they are opened and blocks known malware before it runs. Phalanx cannot block programs from running.",
        status,
        detail,
        weight: 5,
        link: VIRUS_SETTINGS,
    });

    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match mp.and_then(|m| m.is_tamper_protected) {
            Some(true) => (Status::Good, "On".to_string()),
            Some(false) => (Status::Risk, "Off: malware could switch Defender off".to_string()),
            None => unknown(mp_reason()),
        }
    };
    checks.push(Check {
        id: "tamper",
        title: "Tamper protection",
        why: "Stops malicious programs from turning off Microsoft Defender.",
        status,
        detail,
        weight: 3,
        link: VIRUS_SETTINGS,
    });

    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match pref.and_then(|p| p.maps_reporting) {
            Some(0) => (Status::Risk, "Off".to_string()),
            Some(_) => (Status::Good, "On".to_string()),
            None => unknown(pref_reason()),
        }
    };
    checks.push(Check {
        id: "cloud",
        title: "Cloud-delivered protection",
        why: "Lets Defender recognise brand-new threats within seconds instead of waiting for the next definition update.",
        status,
        detail,
        weight: 2,
        link: VIRUS_SETTINGS,
    });

    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match pref.and_then(|p| p.pua_protection) {
            Some(1) => (Status::Good, "Blocking".to_string()),
            Some(2) => (Status::Attention, "Audit only: unwanted apps are logged but not blocked".to_string()),
            Some(_) => (Status::Risk, "Off".to_string()),
            None => unknown(pref_reason()),
        }
    };
    checks.push(Check {
        id: "pua",
        title: "Potentially unwanted app blocking",
        why: "Blocks adware, bundled toolbars and similar unwanted software that bundles itself into installers.",
        status,
        detail,
        weight: 2,
        link: APP_BROWSER,
    });

    let (status, detail) = match (&reg.smartscreen_policy, &reg.smartscreen) {
        (Reg::Value(0), _) => (Status::Risk, "Off (set by policy)".to_string()),
        (Reg::Value(_), _) => (Status::Good, "On (set by policy)".to_string()),
        (_, Reg::Value(v)) if v.eq_ignore_ascii_case("off") => (Status::Risk, "Off".to_string()),
        (_, Reg::Value(v)) if v.eq_ignore_ascii_case("prompt") || v.eq_ignore_ascii_case("warn") => {
            (Status::Good, "On (warns)".to_string())
        }
        (_, Reg::Value(v)) if v.eq_ignore_ascii_case("requireadmin") => (Status::Good, "On (blocks)".to_string()),
        (_, Reg::Value(v)) => (Status::Unknown, format!("Unrecognised value `{v}`")),
        (_, Reg::Missing) => (Status::Good, "On (Windows default)".to_string()),
        (_, r) => reg_unknown(r),
    };
    checks.push(Check {
        id: "smartscreen",
        title: "Check apps and files (SmartScreen)",
        why: "Warns before you open unrecognised programs downloaded from the internet.",
        status,
        detail,
        weight: 3,
        link: APP_BROWSER,
    });

    let (status, detail) = match &reg.smart_app_control {
        Reg::Value(1) => (Status::Good, "On".to_string()),
        Reg::Value(2) => (Status::Info, "Evaluation: Windows is deciding whether it suits this PC".to_string()),
        Reg::Value(0) => (Status::Info, "Off. Once off it can only be turned on again by reinstalling Windows".to_string()),
        Reg::Value(v) => (Status::Unknown, format!("Unrecognised state {v}")),
        Reg::Missing => (Status::Info, "Not available on this version of Windows".to_string()),
        r => reg_unknown(r),
    };
    checks.push(Check {
        id: "smart_app_control",
        title: "Smart App Control",
        why: "Blocks untrusted and unsigned programs outright. Optional: it can get in the way of developer tools.",
        status,
        detail,
        weight: 0,
        link: APP_BROWSER,
    });

    let (status, detail) = match &reg.memory_integrity {
        Reg::Value(1) => (Status::Good, "On".to_string()),
        Reg::Value(_) | Reg::Missing => (Status::Attention, "Off".to_string()),
        r => reg_unknown(r),
    };
    checks.push(Check {
        id: "memory_integrity",
        title: "Memory integrity (core isolation)",
        why: "Stops malicious drivers and kernel-level code from loading.",
        status,
        detail,
        weight: 2,
        link: DEVICE_SECURITY,
    });

    let profiles = state.and_then(|s| s.fw.as_ref());
    let (status, detail) = match profiles {
        Some(list) if !list.is_empty() => {
            let off: Vec<&str> = list
                .iter()
                .filter(|p| !p.enabled.eq_ignore_ascii_case("true"))
                .map(|p| p.name.as_str())
                .collect();
            if off.is_empty() {
                (Status::Good, "On for all networks".to_string())
            } else if other_on.is_some() && off.len() == list.len() {
                (Status::Info, "Windows Firewall is off; your security product may provide its own".to_string())
            } else {
                (Status::Risk, format!("Off for: {}", off.join(", ")))
            }
        }
        _ => unknown(
            state
                .and_then(|s| s.fw_error.clone())
                .or_else(|| ps_error.clone())
                .unwrap_or_else(|| "no firewall profiles reported".into()),
        ),
    };
    checks.push(Check {
        id: "firewall",
        title: "Firewall",
        why: "Blocks unsolicited connections from the network to this PC.",
        status,
        detail,
        weight: 4,
        link: FIREWALL,
    });

    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match pref.and_then(|p| p.enable_controlled_folder_access) {
            Some(1) => (Status::Good, "On".to_string()),
            Some(2) => (Status::Info, "Audit only".to_string()),
            Some(_) => (Status::Info, "Off (optional)".to_string()),
            None => unknown(pref_reason()),
        }
    };
    checks.push(Check {
        id: "controlled_folders",
        title: "Ransomware protection (controlled folder access)",
        why: "Lets only trusted apps change files in Documents, Pictures and other protected folders. Optional: you may need to allow some apps.",
        status,
        detail,
        weight: 0,
        link: RANSOMWARE,
    });

    let (status, detail) = match (&reg.uac_enabled, &reg.uac_admin_prompt) {
        (Reg::Value(0), _) => (Status::Risk, "Off: programs get administrator rights without asking".to_string()),
        (_, Reg::Value(0)) => (Status::Risk, "Never notify: programs can elevate silently".to_string()),
        (Reg::Value(_) | Reg::Missing, Reg::Value(_) | Reg::Missing) => (Status::Good, "On".to_string()),
        (r @ Reg::Error(_), _) => reg_unknown(r),
        (_, r) => reg_unknown(r),
    };
    checks.push(Check {
        id: "uac",
        title: "User Account Control",
        why: "Asks before a program gets administrator rights, so malware cannot quietly take over the PC.",
        status,
        detail,
        weight: 3,
        link: UAC,
    });

    let (status, detail) = match &reg.hide_file_ext {
        Reg::Value(0) => (Status::Good, "Shown".to_string()),
        Reg::Value(_) | Reg::Missing => (Status::Attention, "Hidden: invoice.pdf.exe appears as invoice.pdf".to_string()),
        r => reg_unknown(r),
    };
    checks.push(Check {
        id: "file_extensions",
        title: "Show file extensions",
        why: "Makes disguised programs such as invoice.pdf.exe easy to spot in File Explorer.",
        status,
        detail,
        weight: 2,
        link: FILE_EXTENSIONS,
    });

    checks
}

// ---------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------

/// Registry values the privacy checks use.
#[derive(Debug, Clone)]
pub struct PrivacyRegistry {
    pub advertising_id: Reg<u32>,
    pub advertising_policy: Reg<u32>,
    pub tailored: Reg<u32>,
    pub telemetry: Reg<u32>,
    pub telemetry_policy: Reg<u32>,
    pub language_opt_out: Reg<u32>,
    pub track_launches: Reg<u32>,
    pub suggested: [Reg<u32>; 3],
    pub start_suggestions: Reg<u32>,
    pub online_speech: Reg<u32>,
    pub typing_collection: Reg<u32>,
    pub typing_improve: Reg<u32>,
    pub bing_search: Reg<u32>,
    pub search_box_policy: Reg<u32>,
    pub cloud_search: Reg<u32>,
    pub location: Reg<String>,
    pub camera: Reg<String>,
    pub microphone: Reg<String>,
    pub feedback_frequency: Reg<u32>,
}

pub fn privacy_checks() -> Vec<Check> {
    #[cfg(windows)]
    let reg = read_privacy_registry();
    #[cfg(not(windows))]
    let reg = PrivacyRegistry::unavailable();
    build_privacy_checks(&reg)
}

impl PrivacyRegistry {
    pub fn unavailable() -> Self {
        Self {
            advertising_id: off_windows(),
            advertising_policy: off_windows(),
            tailored: off_windows(),
            telemetry: off_windows(),
            telemetry_policy: off_windows(),
            language_opt_out: off_windows(),
            track_launches: off_windows(),
            suggested: [off_windows(), off_windows(), off_windows()],
            start_suggestions: off_windows(),
            online_speech: off_windows(),
            typing_collection: off_windows(),
            typing_improve: off_windows(),
            bing_search: off_windows(),
            search_box_policy: off_windows(),
            cloud_search: off_windows(),
            location: off_windows(),
            camera: off_windows(),
            microphone: off_windows(),
            feedback_frequency: off_windows(),
        }
    }
}

#[cfg(windows)]
fn read_privacy_registry() -> PrivacyRegistry {
    use reg::{dword, string, Hive::*};
    const CDM: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    const CONSENT: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
    // Device-wide switch first; when the device allows, the per-user switch decides.
    let access = |name: &str| {
        let path = format!(r"{CONSENT}\{name}");
        match string(Machine, &path, "Value") {
            Reg::Value(v) if v.eq_ignore_ascii_case("deny") => Reg::Value("DenyDevice".to_string()),
            _ => string(User, &path, "Value"),
        }
    };
    PrivacyRegistry {
        advertising_id: dword(User, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled"),
        advertising_policy: dword(Machine, r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy"),
        tailored: dword(User, r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled"),
        telemetry: dword(Machine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry"),
        telemetry_policy: dword(Machine, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry"),
        language_opt_out: dword(User, r"Control Panel\International\User Profile", "HttpAcceptLanguageOptOut"),
        track_launches: dword(User, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs"),
        suggested: [
            dword(User, CDM, "SubscribedContent-338393Enabled"),
            dword(User, CDM, "SubscribedContent-353694Enabled"),
            dword(User, CDM, "SubscribedContent-353696Enabled"),
        ],
        start_suggestions: dword(User, CDM, "SubscribedContent-338388Enabled"),
        online_speech: dword(User, r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted"),
        typing_collection: dword(User, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection"),
        typing_improve: dword(User, r"Software\Microsoft\Input\TIPC", "Enabled"),
        bing_search: dword(User, r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled"),
        search_box_policy: dword(User, r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions"),
        cloud_search: dword(User, r"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsMSACloudSearchEnabled"),
        location: access("location"),
        camera: access("webcam"),
        microphone: access("microphone"),
        feedback_frequency: dword(User, r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod"),
    }
}

const PRIVACY_GENERAL: Link = Link { label: "Open Privacy > General", target: "ms-settings:privacy-general" };
const DIAGNOSTICS: Link = Link { label: "Open Diagnostics & feedback", target: "ms-settings:privacy-feedback" };
const SPEECH: Link = Link { label: "Open Speech privacy", target: "ms-settings:privacy-speech" };
const TYPING: Link = Link { label: "Open Inking & typing personalization", target: "ms-settings:privacy-speechtyping" };
const SEARCH: Link = Link { label: "Open Search permissions", target: "ms-settings:search-permissions" };
const START: Link = Link { label: "Open Start settings", target: "ms-settings:personalization-start" };
const LOCATION: Link = Link { label: "Open Location privacy", target: "ms-settings:privacy-location" };
const CAMERA: Link = Link { label: "Open Camera privacy", target: "ms-settings:privacy-webcam" };
const MICROPHONE: Link = Link { label: "Open Microphone privacy", target: "ms-settings:privacy-microphone" };

/// `1` means sharing, `0` means private; `missing` is what Windows does by default.
fn switch(r: &Reg<u32>, missing_shares: bool, on: &str, off: &str) -> (Status, String) {
    match r {
        Reg::Value(0) => (Status::Good, off.to_string()),
        Reg::Value(_) => (Status::Risk, on.to_string()),
        Reg::Missing if missing_shares => (Status::Risk, format!("{on} (Windows default)")),
        Reg::Missing => (Status::Good, format!("{off} (Windows default)")),
        Reg::Error(e) => unknown(e.clone()),
    }
}

fn access_status(r: &Reg<String>, sensitive: bool) -> (Status, String) {
    let allowed = if sensitive { Status::Attention } else { Status::Info };
    match r {
        Reg::Value(v) if v == "DenyDevice" => (Status::Good, "Off for this device".to_string()),
        Reg::Value(v) if v.eq_ignore_ascii_case("deny") => (Status::Good, "Apps cannot use it".to_string()),
        Reg::Value(v) if v.eq_ignore_ascii_case("allow") => (allowed, "Apps may ask to use it: review which apps are allowed".to_string()),
        Reg::Value(v) => (Status::Unknown, format!("Unrecognised value `{v}`")),
        Reg::Missing => (allowed, "Apps may ask to use it (Windows default)".to_string()),
        Reg::Error(e) => unknown(e.clone()),
    }
}

pub fn build_privacy_checks(reg: &PrivacyRegistry) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut add = |id, title, why, (status, detail): (Status, String), weight, link| {
        checks.push(Check { id, title, why, status, detail, weight, link });
    };

    let ad = if reg.advertising_policy.value() == Some(1) {
        (Status::Good, "Off (set by policy)".to_string())
    } else {
        switch(&reg.advertising_id, true, "On", "Off")
    };
    add(
        "advertising_id",
        "Advertising ID",
        "Gives apps an ID that ad networks use to profile you across apps.",
        ad,
        3,
        PRIVACY_GENERAL,
    );

    // 0 = security only, 1 = required, 3 = optional (full) diagnostic data.
    let telemetry = match (&reg.telemetry_policy, &reg.telemetry) {
        (Reg::Value(v), _) if *v <= 1 => (Status::Good, "Required diagnostic data only (set by policy)".to_string()),
        (Reg::Value(_), _) => (Status::Risk, "Optional diagnostic data is sent (set by policy)".to_string()),
        (_, Reg::Value(v)) if *v <= 1 => (Status::Good, "Required diagnostic data only".to_string()),
        (_, Reg::Value(_)) => (Status::Risk, "Optional diagnostic data is sent".to_string()),
        (_, Reg::Missing) => (Status::Unknown, "Could not read: not set".to_string()),
        (_, Reg::Error(e)) => unknown(e.clone()),
    };
    add(
        "diagnostics",
        "Optional diagnostic data",
        "Optional data includes the websites you browse and how you use apps and features.",
        telemetry,
        3,
        DIAGNOSTICS,
    );

    add(
        "tailored",
        "Tailored experiences",
        "Lets Microsoft use your diagnostic data for personalised tips, ads and recommendations.",
        switch(&reg.tailored, true, "On", "Off"),
        2,
        DIAGNOSTICS,
    );

    // HttpAcceptLanguageOptOut: 1 = opted out (private).
    let language = match &reg.language_opt_out {
        Reg::Value(1) => (Status::Good, "Off".to_string()),
        Reg::Value(_) => (Status::Risk, "On".to_string()),
        Reg::Missing => (Status::Risk, "On (Windows default)".to_string()),
        Reg::Error(e) => unknown(e.clone()),
    };
    add(
        "language_list",
        "Websites can read your language list",
        "Your language list helps websites fingerprint and identify you.",
        language,
        1,
        PRIVACY_GENERAL,
    );

    add(
        "track_launches",
        "Track app launches",
        "Windows records which apps you start to personalise Start and search.",
        switch(&reg.track_launches, true, "On", "Off"),
        1,
        PRIVACY_GENERAL,
    );

    let suggested = {
        let on = reg.suggested.iter().filter(|r| !matches!(r, Reg::Value(0))).count();
        if reg.suggested.iter().all(|r| matches!(r, Reg::Error(_))) {
            reg_unknown(&reg.suggested[0])
        } else if on == 0 {
            (Status::Good, "Off".to_string())
        } else {
            (Status::Risk, "On".to_string())
        }
    };
    add(
        "suggested_content",
        "Suggested content in Settings",
        "Shows promotional suggestions based on how you use Windows.",
        suggested,
        1,
        PRIVACY_GENERAL,
    );

    add(
        "start_suggestions",
        "Suggestions and ads in Start",
        "Shows recommended apps and promotions in Start.",
        switch(&reg.start_suggestions, true, "On", "Off"),
        1,
        START,
    );

    add(
        "online_speech",
        "Online speech recognition",
        "Sends your voice to Microsoft's cloud to recognise speech.",
        switch(&reg.online_speech, false, "On", "Off"),
        2,
        SPEECH,
    );

    // RestrictImplicitTextCollection: 1 = not collected (private).
    let typing = match (&reg.typing_collection, &reg.typing_improve) {
        (Reg::Value(1), Reg::Value(0) | Reg::Missing) => (Status::Good, "Off".to_string()),
        (Reg::Value(1), Reg::Value(_)) => (Status::Attention, "Personal dictionary off, but typing data is sent to improve Windows".to_string()),
        (Reg::Value(_) | Reg::Missing, _) => (Status::Risk, "On: words you type and ink are collected".to_string()),
        (Reg::Error(e), _) => unknown(e.clone()),
    };
    add(
        "typing",
        "Inking and typing personalisation",
        "Builds a personal dictionary from what you type and write, and can send it to Microsoft.",
        typing,
        2,
        TYPING,
    );

    let bing = if reg.search_box_policy.value() == Some(1) {
        (Status::Good, "Off (set by policy)".to_string())
    } else {
        switch(&reg.bing_search, true, "On: what you type in Start search goes to Bing", "Off")
    };
    add(
        "web_search",
        "Web results in Start search",
        "Sends what you type in the Start menu search box to Bing.",
        bing,
        2,
        SEARCH,
    );

    add(
        "cloud_search",
        "Cloud content search",
        "Includes your Microsoft account content (OneDrive, Outlook, Bing) in Windows search.",
        switch(&reg.cloud_search, true, "On", "Off"),
        1,
        SEARCH,
    );

    add(
        "location",
        "Location access",
        "Apps that are allowed can see where you are.",
        access_status(&reg.location, true),
        2,
        LOCATION,
    );
    add(
        "camera",
        "Camera access",
        "Apps that are allowed can use the camera. Fine for video calls; review the list of apps.",
        access_status(&reg.camera, false),
        0,
        CAMERA,
    );
    add(
        "microphone",
        "Microphone access",
        "Apps that are allowed can listen through the microphone. Review the list of apps.",
        access_status(&reg.microphone, false),
        0,
        MICROPHONE,
    );

    let feedback = match &reg.feedback_frequency {
        Reg::Value(0) => (Status::Good, "Never asks".to_string()),
        Reg::Value(_) | Reg::Missing => (Status::Info, "Windows may ask for feedback".to_string()),
        Reg::Error(e) => unknown(e.clone()),
    };
    add(
        "feedback",
        "Feedback requests",
        "How often Windows asks you for feedback.",
        feedback,
        0,
        DIAGNOSTICS,
    );

    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_all_missing() -> SecurityRegistry {
        SecurityRegistry {
            smartscreen: Reg::Missing,
            smartscreen_policy: Reg::Missing,
            smart_app_control: Reg::Missing,
            memory_integrity: Reg::Missing,
            uac_enabled: Reg::Missing,
            uac_admin_prompt: Reg::Missing,
            hide_file_ext: Reg::Missing,
        }
    }

    fn find<'a>(checks: &'a [Check], id: &str) -> &'a Check {
        checks.iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn product_state_is_decoded() {
        let on = AvProduct { name: "X".into(), state: 0x061000 };
        let off = AvProduct { name: "X".into(), state: 0x060100 };
        let stale = AvProduct { name: "X".into(), state: 0x061010 };
        assert!(on.enabled() && on.up_to_date());
        assert!(!off.enabled());
        assert!(stale.enabled() && !stale.up_to_date());
    }

    #[test]
    fn defender_output_is_parsed_and_scored() {
        let json = r#"{"mp":{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"IsTamperProtected":false,"AMRunningMode":"Normal","AntivirusSignatureAge":0},
            "pref":{"PUAProtection":2,"EnableControlledFolderAccess":0,"MAPSReporting":2},
            "av":[{"name":"Windows Defender","state":397568}],
            "fw":[{"name":"Domain","enabled":"True"},{"name":"Private","enabled":"True"},{"name":"Public","enabled":"False"}]}"#;
        let state = parse_defender_state(json);
        let checks = build_security_checks(&state, &registry_all_missing());
        assert_eq!(find(&checks, "realtime").status, Status::Good);
        assert_eq!(find(&checks, "tamper").status, Status::Risk);
        assert_eq!(find(&checks, "pua").status, Status::Attention);
        assert_eq!(find(&checks, "firewall").status, Status::Risk);
        assert!(find(&checks, "firewall").detail.contains("Public"));
        assert_eq!(find(&checks, "smartscreen").status, Status::Good, "missing means the Windows default");
        assert_eq!(find(&checks, "file_extensions").status, Status::Attention);
        assert!(score(&checks).unwrap().percent < 100);
    }

    #[test]
    fn third_party_antivirus_makes_defender_settings_not_applicable() {
        let json = r#"{"mp":{"RealTimeProtectionEnabled":false,"AMRunningMode":"Passive Mode"},
            "av":[{"name":"Windows Defender","state":393472},{"name":"Other AV","state":266240}]}"#;
        let checks = build_security_checks(&parse_defender_state(json), &registry_all_missing());
        assert_eq!(find(&checks, "realtime").status, Status::Good);
        assert!(find(&checks, "realtime").detail.contains("Other AV"));
        assert_eq!(find(&checks, "tamper").status, Status::Info);
    }

    #[test]
    fn unreadable_values_are_unknown_not_off() {
        let checks = build_security_checks(&Err("PowerShell missing".into()), &SecurityRegistry::unavailable());
        assert_eq!(find(&checks, "realtime").status, Status::Unknown);
        assert!(find(&checks, "realtime").detail.contains("PowerShell missing"));
        assert!(checks.iter().all(|c| matches!(c.status, Status::Unknown | Status::Info)));
        assert!(score(&checks).is_none());

        let privacy = build_privacy_checks(&PrivacyRegistry::unavailable());
        assert!(privacy.iter().all(|c| c.status == Status::Unknown));
    }

    #[test]
    fn privacy_defaults_and_choices_are_interpreted() {
        let mut reg = PrivacyRegistry::unavailable();
        reg.advertising_id = Reg::Value(0);
        reg.advertising_policy = Reg::Missing;
        reg.bing_search = Reg::Missing;
        reg.search_box_policy = Reg::Missing;
        reg.language_opt_out = Reg::Value(1);
        reg.location = Reg::Value("DenyDevice".into());
        let checks = build_privacy_checks(&reg);
        assert_eq!(find(&checks, "advertising_id").status, Status::Good);
        assert_eq!(find(&checks, "web_search").status, Status::Risk);
        assert!(find(&checks, "web_search").detail.contains("Windows default"));
        assert_eq!(find(&checks, "language_list").status, Status::Good);
        assert_eq!(find(&checks, "location").status, Status::Good);
        let s = score(&checks).unwrap();
        assert_eq!(s.scored, 4);
        assert!(s.unknown > 0);
    }

    #[test]
    fn score_weights_and_levels() {
        let c = |status, weight| Check {
            id: "x",
            title: "x",
            why: "",
            status,
            detail: String::new(),
            weight,
            link: PRIVACY_GENERAL,
        };
        let s = score(&[c(Status::Good, 3), c(Status::Risk, 1), c(Status::Info, 5)]).unwrap();
        assert_eq!(s.percent, 75);
        assert_eq!(level(75), "Fair");
        assert_eq!(level(90), "Strong");
        assert_eq!(level(10), "Weak");
    }
}
