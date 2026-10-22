//! Checks of Windows security and privacy settings.
//!
//! Reading never changes a setting. Each check reports what it read, or
//! `Unknown` with the reason when a value could not be read, and names the
//! Windows page where the user can change it themselves. Where Phalanx can
//! change it directly, a check also offers a [`Toggle`] (a per-user setting,
//! written the way Windows Settings writes it) or a [`Fix`] (an administrator
//! command shown word for word and run only after Windows' prompt).
//!
//! Windows 10 and 11 keep some settings in different places; the checks read
//! and link to the right one for the running version.

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
    /// A one-step fix Phalanx can apply (as administrator, after the user
    /// confirms), when the setting is not already as it should be.
    pub fix: Option<Fix>,
    /// A per-user switch Phalanx can flip both ways without administrator
    /// rights. `Good` status means it is in its protective position.
    pub toggle: Option<Toggle>,
}

/// A fixed administrator command that switches one protection on. Shown to
/// the user word for word before it runs; never built from input.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Fix {
    /// Button text, e.g. "Turn on".
    pub label: &'static str,
    /// The PowerShell command, as shown and as run.
    pub command: &'static str,
    /// What changes, in one sentence.
    pub effect: &'static str,
}

impl Fix {
    /// Runs the command as administrator after Windows' consent prompt.
    pub fn apply(&self) -> anyhow::Result<crate::system::Elevated> {
        crate::system::run_elevated_powershell(&format!(
            "$ErrorActionPreference = 'Stop'; try {{ {}; exit 0 }} catch {{ exit 1 }}",
            self.command
        ))
    }
}

pub const FIX_NETWORK_PROTECTION: Fix = Fix {
    label: "Turn on",
    command: "Set-MpPreference -EnableNetworkProtection Enabled",
    effect: "Microsoft Defender blocks connections to malicious and scam sites for every program.",
};
pub const FIX_PUA: Fix = Fix {
    label: "Turn on",
    command: "Set-MpPreference -PUAProtection Enabled",
    effect: "Microsoft Defender blocks potentially unwanted apps instead of letting them install.",
};
pub const FIX_CLOUD: Fix = Fix {
    label: "Turn on",
    command: "Set-MpPreference -MAPSReporting Advanced",
    effect: "Microsoft Defender checks unknown files with Microsoft's cloud, catching brand-new threats.",
};

pub const FIX_FIREWALL: Fix = Fix {
    label: "Turn on",
    command: "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
    effect: "Windows Firewall blocks unsolicited connections on every kind of network (domain, private and public).",
};
pub const FIX_CONTROLLED_FOLDERS: Fix = Fix {
    label: "Turn on",
    command: "Set-MpPreference -EnableControlledFolderAccess Enabled",
    effect: "Only trusted apps can change files in Documents, Pictures and other protected folders. If an app you use is blocked, allow it under Windows Security > Ransomware protection.",
};
pub const FIX_DIAGNOSTICS: Fix = Fix {
    label: "Send required data only",
    command: r"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name AllowTelemetry -Value 1 -Type DWord",
    effect: "Windows sends only required diagnostic data, the same as turning off \"Send optional diagnostic data\" in Settings.",
};
pub const FIX_WEB_SEARCH: Fix = Fix {
    label: "Turn off",
    command: r"$k = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'; if (-not (Test-Path $k)) { New-Item -Path $k | Out-Null }; Set-ItemProperty -Path $k -Name DisableSearchBoxSuggestions -Value 1 -Type DWord",
    effect: "Start search stops sending what you type to Bing and shows only results from this PC. Windows Settings has no switch for this: it is the policy Windows reads, set for the account that approves the prompt (yours, if you are an administrator). It applies after you sign out and back in.",
};

/// Scans from outside Windows after a restart: reaches malware that hides
/// from scans while Windows runs. Not a check, so it has no status.
pub const OFFLINE_SCAN: Fix = Fix {
    label: "Run offline scan",
    command: "Start-MpWDOScan",
    effect: "Windows restarts within about a minute and Microsoft Defender scans the PC before Windows starts (about 15 minutes). Save your work first.",
};

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Link {
    /// Empty when there is no page to open.
    pub label: &'static str,
    /// A `windowsdefender:` or `ms-settings:` URI, a program in System32 with
    /// optional arguments (`control.exe folders`), an `https:` page,
    /// `start:<browser> <settings page>`, or empty for a page inside Phalanx.
    pub target: &'static str,
}

impl Link {
    /// Opens the page. Targets are fixed constants, never user input.
    pub fn open(&self) -> std::io::Result<()> {
        self.open_in_profile(None)
    }

    /// Like [`Link::open`]; a browser page opens in the given profile folder
    /// (`Default`, `Profile 1`) of that browser.
    pub fn open_in_profile(&self, profile: Option<&str>) -> std::io::Result<()> {
        if let Some(rest) = self.target.strip_prefix("start:") {
            let (browser, page) = rest.split_once(' ').unwrap_or((rest, ""));
            return crate::web::hardening::open_browser_page(browser, page, profile);
        }
        let mut command = match self.target.split_once(".exe ") {
            Some((program, args)) => {
                let mut c = std::process::Command::new(format!("{program}.exe"));
                c.args(args.split_whitespace());
                c
            }
            None if self.target.ends_with(".exe") => std::process::Command::new(self.target),
            None => {
                let mut c = std::process::Command::new("explorer.exe");
                c.arg(self.target);
                c
            }
        };
        command.spawn().map(drop)
    }
}

/// For checks with no Windows page to open (Phalanx changes them itself).
const NO_PAGE: Link = Link { label: "", target: "" };

/// A per-user Windows setting Phalanx switches directly, writing the same
/// values the Windows Settings page writes (under HKEY_CURRENT_USER: no
/// administrator rights, nothing system-wide).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Toggle {
    AdvertisingId,
    Tailored,
    LanguageList,
    TrackLaunches,
    SuggestedContent,
    /// Windows 10: "Show suggestions occasionally in Start".
    StartSuggestions,
    /// Windows 11: "Show recommendations for tips, shortcuts, new apps, and more".
    StartRecommendations,
    OnlineSpeech,
    Typing,
    CloudSearch,
    Location,
    Camera,
    Microphone,
    Feedback,
    FileExtensions,
}

impl Toggle {
    /// Button text: to the protective position, or back.
    pub fn label(self, protective: bool) -> &'static str {
        match (self, protective) {
            (Toggle::Location | Toggle::Camera | Toggle::Microphone, true) => "Block apps",
            (Toggle::Location | Toggle::Camera | Toggle::Microphone, false) => "Let apps ask",
            (Toggle::Feedback, true) => "Never ask",
            (Toggle::Feedback, false) => "Let Windows ask",
            (Toggle::FileExtensions, true) => "Show extensions",
            (Toggle::FileExtensions, false) => "Hide extensions",
            (_, true) => "Turn off",
            (_, false) => "Turn on",
        }
    }

    /// Switches the setting to its protective position, or back to Windows'
    /// usual one.
    pub fn apply(self, protective: bool) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            reg::apply_toggle(self, protective)
        }
        #[cfg(not(windows))]
        {
            let _ = protective;
            anyhow::bail!("only available on Windows")
        }
    }
}

/// Host Browser Guard watches for to open a browser page Phalanx linked to.
/// It never resolves (`.invalid`); the extension acts before any request.
pub const BROWSER_PAGE_HOST: &str = "open.phalanx.invalid";

/// The address to hand a browser for `page`. Chromium browsers drop
/// `chrome://`, `brave://` and `edge://` pages given on the command line (only
/// a new tab opens), so those go through Browser Guard, which opens them:
/// `brave://settings/security` → `http://open.phalanx.invalid/brave/settings/security`
/// (no `%` or `&`, which `cmd /c start` would mangle).
pub fn browser_page_address(page: &str) -> String {
    match page.split_once("://") {
        Some((scheme @ ("chrome" | "brave" | "edge"), path)) => format!("http://{BROWSER_PAGE_HOST}/{scheme}/{path}"),
        _ => page.to_string(),
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

    /// The Windows build number (22000 and later is Windows 11).
    pub fn build() -> Option<u32> {
        match string(Hive::Machine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") {
            Reg::Value(v) => v.trim().parse().ok(),
            _ => None,
        }
    }

    fn set_dword(path: &str, name: &str, value: u32) -> std::io::Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(path)?;
        key.set_value(name, &value)
    }

    fn set_string(path: &str, name: &str, value: &str) -> std::io::Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(path)?;
        key.set_value(name, &value.to_string())
    }

    fn delete(path: &str, name: &str) -> std::io::Result<()> {
        let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(path, winreg::enums::KEY_SET_VALUE) {
            Ok(key) => key,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        match key.delete_value(name) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Writes what Windows Settings writes for each switch (per user). `on`
    /// is the protective position.
    pub fn apply_toggle(toggle: super::Toggle, on: bool) -> anyhow::Result<()> {
        use super::Toggle::*;
        // Most switches are "enabled = 1"; protective means disabled.
        let enabled = u32::from(!on);
        let consent = |name: &str| set_string(&format!(r"{CONSENT}\{name}"), "Value", if on { "Deny" } else { "Allow" });
        match toggle {
            AdvertisingId => set_dword(r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", enabled)?,
            Tailored => set_dword(r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", enabled)?,
            LanguageList => set_dword(r"Control Panel\International\User Profile", "HttpAcceptLanguageOptOut", u32::from(on))?,
            TrackLaunches => set_dword(EXPLORER_ADVANCED, "Start_TrackProgs", enabled)?,
            SuggestedContent => {
                for name in SUGGESTED {
                    set_dword(CDM, name, enabled)?;
                }
            }
            StartSuggestions => set_dword(CDM, START_SUGGESTIONS, enabled)?,
            StartRecommendations => set_dword(EXPLORER_ADVANCED, "Start_IrisRecommendations", enabled)?,
            OnlineSpeech => set_dword(r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted", enabled)?,
            Typing => {
                set_dword(r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", u32::from(on))?;
                set_dword(r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", u32::from(on))?;
                set_dword(r"Software\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", enabled)?;
                set_dword(r"Software\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", enabled)?;
                // "Improve inking and typing" (Diagnostics & feedback) is only switched off.
                if on {
                    set_dword(r"Software\Microsoft\Input\TIPC", "Enabled", 0)?;
                }
            }
            CloudSearch => {
                set_dword(SEARCH_SETTINGS, "IsMSACloudSearchEnabled", enabled)?;
                set_dword(SEARCH_SETTINGS, "IsAADCloudSearchEnabled", enabled)?;
            }
            Location => consent("location")?,
            Camera => consent("webcam")?,
            Microphone => consent("microphone")?,
            Feedback => {
                // "Never" is zero requests per period; Windows' automatic
                // default has neither value.
                if on {
                    set_dword(SIUF, "NumberOfSIUFInPeriod", 0)?;
                } else {
                    delete(SIUF, "NumberOfSIUFInPeriod")?;
                }
                delete(SIUF, "PeriodInNanoSeconds")?;
            }
            FileExtensions => {
                set_dword(EXPLORER_ADVANCED, "HideFileExt", u32::from(!on))?;
                crate::system::refresh_explorer_settings();
            }
        }
        Ok(())
    }

    pub const CONSENT: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
    pub const CDM: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    pub const EXPLORER_ADVANCED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    pub const SEARCH_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\SearchSettings";
    pub const SIUF: &str = r"Software\Microsoft\Siuf\Rules";
    pub const SUGGESTED: [&str; 3] = ["SubscribedContent-338393Enabled", "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled"];
    pub const START_SUGGESTIONS: &str = "SubscribedContent-338388Enabled";
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
    pub enable_network_protection: Option<i64>,
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

/// Read-only; passed to PowerShell as `-EncodedCommand`.
const DEFENDER_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'; $r = @{}
try { $s = Get-MpComputerStatus; $r.mp = @{ AntivirusEnabled = $s.AntivirusEnabled; RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled; IsTamperProtected = $s.IsTamperProtected; AMRunningMode = [string]$s.AMRunningMode; AntivirusSignatureAge = [int64]$s.AntivirusSignatureAge } } catch { $r.mpError = $_.Exception.Message }
try { $p = Get-MpPreference; $r.pref = @{ PUAProtection = [int64]$p.PUAProtection; EnableControlledFolderAccess = [int64]$p.EnableControlledFolderAccess; MAPSReporting = [int64]$p.MAPSReporting; EnableNetworkProtection = [int64]$p.EnableNetworkProtection } } catch { $r.prefError = $_.Exception.Message }
try { $r.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | ForEach-Object { @{ name = [string]$_.displayName; state = [int64]$_.productState } }) } catch { $r.avError = $_.Exception.Message }
try { $r.fw = @(Get-NetFirewallProfile | ForEach-Object { @{ name = [string]$_.Name; enabled = [string]$_.Enabled } }) } catch { $r.fwError = $_.Exception.Message }
$r | ConvertTo-Json -Depth 4 -Compress"#;

/// Runs the read-only PowerShell query (about 1 to 3 seconds).
pub fn read_defender_state() -> Result<DefenderState, String> {
    if !cfg!(windows) {
        return Err("only available on Windows".into());
    }
    crate::system::powershell_json(DEFENDER_SCRIPT, std::time::Duration::from_secs(60))
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
    /// Windows 11 (build 22000 or later).
    pub windows11: bool,
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
            windows11: false,
        }
    }
}

#[cfg(windows)]
fn is_windows11() -> bool {
    reg::build().is_some_and(|b| b >= 22000)
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
        windows11: is_windows11(),
    }
}

const VIRUS_SETTINGS: Link = Link { label: "Open virus & threat protection settings", target: "windowsdefender://threatsettings" };
/// Windows 10 (2004 and later) and 11: Reputation-based protection settings are here.
const APP_BROWSER: Link = Link { label: "Open App & browser control (Reputation-based protection settings)", target: "windowsdefender://appbrowser" };
const DEVICE_SECURITY: Link = Link { label: "Open Device security (Core isolation details)", target: "windowsdefender://devicesecurity" };
const FIREWALL: Link = Link { label: "Open firewall & network protection", target: "windowsdefender://network" };
const RANSOMWARE: Link = Link { label: "Open Virus & threat protection (Manage ransomware protection)", target: "windowsdefender://threat" };
/// Windows Security has no switch for network protection on any version.
const NETWORK_PROTECTION: Link = Link {
    label: "About network protection (Windows Security has no switch for it)",
    target: "https://learn.microsoft.com/defender-endpoint/network-protection",
};
const UAC: Link = Link { label: "Open User Account Control settings", target: "UserAccountControlSettings.exe" };
/// Folder Options is the same on Windows 10 and 11 (Settings moved the switch between versions).
const FILE_EXTENSIONS: Link = Link { label: "Open Folder Options (View > Hide extensions for known file types)", target: "control.exe folders" };

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
        fix: None,
        toggle: None,
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
        fix: None,
        toggle: None,
    });

    // Tamper protection also guards cloud protection: commands cannot change it.
    let tamper_on = mp.and_then(|m| m.is_tamper_protected) == Some(true);
    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match pref.and_then(|p| p.maps_reporting) {
            Some(0) if tamper_on => (Status::Risk, "Off. Tamper protection stops Phalanx from changing it: turn it on in Windows Security".to_string()),
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
        fix: (status == Status::Risk && !tamper_on).then_some(FIX_CLOUD),
        toggle: None,
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
        fix: matches!(status, Status::Risk | Status::Attention).then_some(FIX_PUA),
        toggle: None,
    });

    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match pref.and_then(|p| p.enable_network_protection) {
            Some(1) => (Status::Good, "Blocking".to_string()),
            Some(2) => (Status::Attention, "Audit only: dangerous connections are logged but not blocked".to_string()),
            Some(_) => (Status::Risk, "Off".to_string()),
            None => unknown(pref_reason()),
        }
    };
    checks.push(Check {
        id: "network_protection",
        title: "Network protection",
        why: "Microsoft Defender blocks connections to malicious and scam sites for every program, inside Windows' network stack, before a page can load. Phalanx's browser and DNS blocking add to it.",
        status,
        detail,
        weight: 4,
        link: NETWORK_PROTECTION,
        fix: matches!(status, Status::Risk | Status::Attention).then_some(FIX_NETWORK_PROTECTION),
        toggle: None,
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
        fix: None,
        toggle: None,
    });

    let (status, detail) = match &reg.smart_app_control {
        Reg::Value(1) => (Status::Good, "On".to_string()),
        Reg::Value(2) => (Status::Info, "Evaluation: Windows is deciding whether it suits this PC".to_string()),
        Reg::Value(0) => (Status::Info, "Off. On most Windows 11 versions it can only be turned on again by resetting or reinstalling Windows".to_string()),
        Reg::Value(v) => (Status::Unknown, format!("Unrecognised state {v}")),
        Reg::Missing if reg.windows11 => (Status::Info, "Not available on this PC".to_string()),
        Reg::Missing => (Status::Info, "Windows 11 only".to_string()),
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
        fix: None,
        toggle: None,
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
        fix: None,
        toggle: None,
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
        fix: (status == Status::Risk).then_some(FIX_FIREWALL),
        toggle: None,
    });

    let folders = (!replaced).then(|| pref.and_then(|p| p.enable_controlled_folder_access)).flatten();
    let (status, detail) = if replaced {
        (Status::Info, "Not applicable: another antivirus is active".to_string())
    } else {
        match folders {
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
        fix: folders.filter(|&v| v != 1).map(|_| FIX_CONTROLLED_FOLDERS),
        toggle: None,
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
        fix: None,
        toggle: None,
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
        fix: None,
        toggle: (status != Status::Unknown).then_some(Toggle::FileExtensions),
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
    /// Windows 10: suggestions in Start.
    pub start_suggestions: Reg<u32>,
    /// Windows 11: recommendations in Start.
    pub start_recommendations: Reg<u32>,
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
    pub windows11: bool,
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
            start_recommendations: off_windows(),
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
            windows11: false,
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
        suggested: reg::SUGGESTED.map(|name| dword(User, CDM, name)),
        start_suggestions: dword(User, CDM, reg::START_SUGGESTIONS),
        start_recommendations: dword(User, reg::EXPLORER_ADVANCED, "Start_IrisRecommendations"),
        online_speech: dword(User, r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted"),
        typing_collection: dword(User, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection"),
        typing_improve: dword(User, r"Software\Microsoft\Input\TIPC", "Enabled"),
        bing_search: dword(User, r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled"),
        search_box_policy: dword(User, r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions"),
        cloud_search: dword(User, r"Software\Microsoft\Windows\CurrentVersion\SearchSettings", "IsMSACloudSearchEnabled"),
        location: access("location"),
        camera: access("webcam"),
        microphone: access("microphone"),
        feedback_frequency: dword(User, reg::SIUF, "NumberOfSIUFInPeriod"),
        windows11: is_windows11(),
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
    // A switch is offered once its value could be read; `None` where a
    // policy or a device-wide setting decides instead.
    let switch_for = |(status, _): &(Status, String), toggle| (*status != Status::Unknown).then_some(toggle);
    let mut add = |id, title, why, (status, detail): (Status, String), weight, link, toggle: Option<Toggle>, fix: Option<Fix>| {
        checks.push(Check { id, title, why, status, detail, weight, link, fix, toggle });
    };

    let by_policy = reg.advertising_policy.value() == Some(1);
    let ad = if by_policy { (Status::Good, "Off (set by policy)".to_string()) } else { switch(&reg.advertising_id, true, "On", "Off") };
    let toggle = if by_policy { None } else { switch_for(&ad, Toggle::AdvertisingId) };
    add(
        "advertising_id",
        "Advertising ID",
        "Gives apps an ID that ad networks use to profile you across apps.",
        ad,
        3,
        PRIVACY_GENERAL,
        toggle,
        None,
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
    // A system-wide setting (administrator); a policy decides it outright.
    let fix = (telemetry.0 == Status::Risk && !matches!(reg.telemetry_policy, Reg::Value(_))).then_some(FIX_DIAGNOSTICS);
    add(
        "diagnostics",
        "Optional diagnostic data",
        "Optional data includes the websites you browse and how you use apps and features.",
        telemetry,
        3,
        DIAGNOSTICS,
        None,
        fix,
    );

    let tailored = switch(&reg.tailored, true, "On", "Off");
    let toggle = switch_for(&tailored, Toggle::Tailored);
    add(
        "tailored",
        "Tailored experiences",
        "Lets Microsoft use your diagnostic data for personalised tips, ads and recommendations.",
        tailored,
        2,
        DIAGNOSTICS,
        toggle,
        None,
    );

    // HttpAcceptLanguageOptOut: 1 = opted out (private).
    let language = match &reg.language_opt_out {
        Reg::Value(1) => (Status::Good, "Off".to_string()),
        Reg::Value(_) => (Status::Risk, "On".to_string()),
        Reg::Missing => (Status::Risk, "On (Windows default)".to_string()),
        Reg::Error(e) => unknown(e.clone()),
    };
    let toggle = switch_for(&language, Toggle::LanguageList);
    add(
        "language_list",
        "Websites can read your language list",
        "Your language list helps websites fingerprint and identify you.",
        language,
        1,
        PRIVACY_GENERAL,
        toggle,
        None,
    );

    let launches = switch(&reg.track_launches, true, "On", "Off");
    let toggle = switch_for(&launches, Toggle::TrackLaunches);
    add(
        "track_launches",
        "Track app launches",
        "Windows records which apps you start to personalise Start and search.",
        launches,
        1,
        PRIVACY_GENERAL,
        toggle,
        None,
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
    let toggle = switch_for(&suggested, Toggle::SuggestedContent);
    add(
        "suggested_content",
        "Suggested content in Settings",
        "Shows promotional suggestions based on how you use Windows.",
        suggested,
        1,
        PRIVACY_GENERAL,
        toggle,
        None,
    );

    // Windows 11 replaced "suggestions" in Start with "recommendations".
    if reg.windows11 {
        let start = switch(&reg.start_recommendations, true, "On", "Off");
        let toggle = switch_for(&start, Toggle::StartRecommendations);
        add(
            "start_suggestions",
            "Recommendations in Start",
            "Shows tips, app promotions and recommended files in Start.",
            start,
            1,
            START,
            toggle,
            None,
        );
    } else {
        let start = switch(&reg.start_suggestions, true, "On", "Off");
        let toggle = switch_for(&start, Toggle::StartSuggestions);
        add(
            "start_suggestions",
            "Suggestions and ads in Start",
            "Shows recommended apps and promotions in Start.",
            start,
            1,
            START,
            toggle,
            None,
        );
    }

    let speech = switch(&reg.online_speech, false, "On", "Off");
    let toggle = switch_for(&speech, Toggle::OnlineSpeech);
    add(
        "online_speech",
        "Online speech recognition",
        "Sends your voice to Microsoft's cloud to recognise speech.",
        speech,
        2,
        SPEECH,
        toggle,
        None,
    );

    // RestrictImplicitTextCollection: 1 = not collected (private).
    let typing = match (&reg.typing_collection, &reg.typing_improve) {
        (Reg::Value(1), Reg::Value(0) | Reg::Missing) => (Status::Good, "Off".to_string()),
        (Reg::Value(1), Reg::Value(_)) => (Status::Attention, "Personal dictionary off, but typing data is sent to improve Windows (Diagnostics & feedback)".to_string()),
        (Reg::Value(_) | Reg::Missing, _) => (Status::Risk, "On: words you type and ink are collected".to_string()),
        (Reg::Error(e), _) => unknown(e.clone()),
    };
    let toggle = switch_for(&typing, Toggle::Typing);
    add(
        "typing",
        "Inking and typing personalisation",
        "Builds a personal dictionary from what you type and write, and can send it to Microsoft.",
        typing,
        2,
        TYPING,
        toggle,
        None,
    );

    // Windows Settings has no switch for web results in Start, and current
    // Windows 10 and 11 ignore the old per-user value: only the search box
    // policy reliably turns them off.
    let bing = match (reg.search_box_policy.value(), &reg.bing_search) {
        (Some(1), _) => (Status::Good, "Off (search box policy)".to_string()),
        (_, Reg::Value(0)) => (
            Status::Attention,
            "Turned off with the older setting, which current Windows versions ignore: what you type in Start search may still go to Bing".to_string(),
        ),
        (_, Reg::Error(e)) => unknown(e.clone()),
        _ => (Status::Risk, "On: what you type in Start search goes to Bing (Windows default)".to_string()),
    };
    let fix = matches!(bing.0, Status::Risk | Status::Attention).then_some(FIX_WEB_SEARCH);
    add(
        "web_search",
        "Web results in Start search",
        "Sends what you type in the Start menu search box to Bing. Windows Settings has no switch for it.",
        bing,
        2,
        NO_PAGE,
        None,
        fix,
    );

    let cloud = switch(&reg.cloud_search, true, "On", "Off");
    let toggle = switch_for(&cloud, Toggle::CloudSearch);
    add(
        "cloud_search",
        "Cloud content search",
        "Includes your Microsoft account content (OneDrive, Outlook, Bing) in Windows search.",
        cloud,
        1,
        SEARCH,
        toggle,
        None,
    );

    // A device-wide "off" (administrator) is final; per-user switches are offered otherwise.
    let per_user = |r: &Reg<String>, status: &(Status, String), toggle| match r {
        Reg::Value(v) if v == "DenyDevice" => None,
        _ => switch_for(status, toggle),
    };
    let location = access_status(&reg.location, true);
    let toggle = per_user(&reg.location, &location, Toggle::Location);
    add("location", "Location access", "Apps that are allowed can see where you are.", location, 2, LOCATION, toggle, None);
    let camera = access_status(&reg.camera, false);
    let toggle = per_user(&reg.camera, &camera, Toggle::Camera);
    add(
        "camera",
        "Camera access",
        "Apps that are allowed can use the camera. Fine for video calls; review the list of apps.",
        camera,
        0,
        CAMERA,
        toggle,
        None,
    );
    let microphone = access_status(&reg.microphone, false);
    let toggle = per_user(&reg.microphone, &microphone, Toggle::Microphone);
    add(
        "microphone",
        "Microphone access",
        "Apps that are allowed can listen through the microphone. Review the list of apps.",
        microphone,
        0,
        MICROPHONE,
        toggle,
        None,
    );

    let feedback = match &reg.feedback_frequency {
        Reg::Value(0) => (Status::Good, "Never asks".to_string()),
        Reg::Value(_) | Reg::Missing => (Status::Info, "Windows may ask for feedback".to_string()),
        Reg::Error(e) => unknown(e.clone()),
    };
    let toggle = switch_for(&feedback, Toggle::Feedback);
    add("feedback", "Feedback requests", "How often Windows asks you for feedback.", feedback, 0, DIAGNOSTICS, toggle, None);

    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_pages_go_through_browser_guard() {
        assert_eq!(browser_page_address("brave://settings/security"), "http://open.phalanx.invalid/brave/settings/security");
        assert_eq!(browser_page_address("edge://wallet/passwords"), "http://open.phalanx.invalid/edge/wallet/passwords");
        assert_eq!(browser_page_address("https://example.org/"), "https://example.org/");
        // Every browser page Phalanx links to is one Browser Guard will open.
        let pages = include_str!("../browser-extension/background.js");
        for target in crate::web::hardening::browser_links() {
            let (_, page) = target.strip_prefix("start:").and_then(|t| t.split_once(' ')).expect("start:<browser> <page>");
            let path = page.split_once("://").unwrap().1;
            assert!(pages.contains(&format!("\"{path}\"")), "{page} is not in Browser Guard's list of pages it opens");
        }
    }

    #[cfg(windows)]
    #[test]
    fn scripts_are_valid_powershell() {
        assert!(!crate::system::powershell_syntax_errors("if ($x { 1").is_empty(), "the checker reports errors");
        assert_eq!(crate::system::powershell_syntax_errors(DEFENDER_SCRIPT), Vec::<String>::new());
        for fix in [FIX_NETWORK_PROTECTION, FIX_PUA, FIX_CLOUD, FIX_FIREWALL, FIX_CONTROLLED_FOLDERS, FIX_DIAGNOSTICS, FIX_WEB_SEARCH, OFFLINE_SCAN] {
            assert_eq!(crate::system::powershell_syntax_errors(fix.command), Vec::<String>::new(), "{}", fix.command);
        }
    }

    fn registry_all_missing() -> SecurityRegistry {
        SecurityRegistry {
            smartscreen: Reg::Missing,
            smartscreen_policy: Reg::Missing,
            smart_app_control: Reg::Missing,
            memory_integrity: Reg::Missing,
            uac_enabled: Reg::Missing,
            uac_admin_prompt: Reg::Missing,
            hide_file_ext: Reg::Missing,
            windows11: true,
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
            "pref":{"PUAProtection":2,"EnableControlledFolderAccess":0,"MAPSReporting":2,"EnableNetworkProtection":0},
            "av":[{"name":"Windows Defender","state":397568}],
            "fw":[{"name":"Domain","enabled":"True"},{"name":"Private","enabled":"True"},{"name":"Public","enabled":"False"}]}"#;
        let state = parse_defender_state(json);
        let checks = build_security_checks(&state, &registry_all_missing());
        assert_eq!(find(&checks, "realtime").status, Status::Good);
        assert_eq!(find(&checks, "tamper").status, Status::Risk);
        assert_eq!(find(&checks, "pua").status, Status::Attention);
        assert_eq!(find(&checks, "pua").fix, Some(FIX_PUA));
        assert_eq!(find(&checks, "network_protection").status, Status::Risk);
        assert_eq!(find(&checks, "network_protection").fix, Some(FIX_NETWORK_PROTECTION));
        assert_eq!(find(&checks, "cloud").fix, None, "already on: nothing to fix");
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
    fn windows_10_and_11_read_their_own_start_setting() {
        let mut reg = PrivacyRegistry::unavailable();
        reg.start_suggestions = Reg::Value(1);
        reg.start_recommendations = Reg::Value(0);
        let win10 = build_privacy_checks(&reg);
        assert_eq!(find(&win10, "start_suggestions").status, Status::Risk);
        assert_eq!(find(&win10, "start_suggestions").toggle, Some(Toggle::StartSuggestions));
        reg.windows11 = true;
        let win11 = build_privacy_checks(&reg);
        assert_eq!(find(&win11, "start_suggestions").status, Status::Good);
        assert_eq!(find(&win11, "start_suggestions").toggle, Some(Toggle::StartRecommendations));
    }

    #[test]
    fn switches_are_offered_only_where_the_user_decides() {
        let mut reg = PrivacyRegistry::unavailable();
        // Unreadable: no switch.
        assert!(build_privacy_checks(&reg).iter().all(|c| c.toggle.is_none()));
        reg.advertising_id = Reg::Value(1);
        reg.location = Reg::Value("DenyDevice".into());
        reg.camera = Reg::Missing;
        reg.bing_search = Reg::Value(0);
        reg.search_box_policy = Reg::Missing;
        reg.telemetry = Reg::Value(3);
        reg.telemetry_policy = Reg::Missing;
        let checks = build_privacy_checks(&reg);
        assert_eq!(find(&checks, "advertising_id").toggle, Some(Toggle::AdvertisingId));
        assert_eq!(find(&checks, "location").toggle, None, "turned off for the whole device");
        assert_eq!(find(&checks, "camera").toggle, Some(Toggle::Camera));
        // The old Bing switch alone is not trusted; the policy fix is offered.
        assert_eq!(find(&checks, "web_search").status, Status::Attention);
        assert_eq!(find(&checks, "web_search").fix, Some(FIX_WEB_SEARCH));
        assert!(find(&checks, "web_search").link.label.is_empty(), "Settings has no page for it");
        assert_eq!(find(&checks, "diagnostics").fix, Some(FIX_DIAGNOSTICS));
        reg.advertising_policy = Reg::Value(1);
        reg.search_box_policy = Reg::Value(1);
        reg.telemetry_policy = Reg::Value(3);
        let managed = build_privacy_checks(&reg);
        assert_eq!(find(&managed, "advertising_id").toggle, None, "a policy decides");
        assert_eq!(find(&managed, "web_search").status, Status::Good);
        assert_eq!(find(&managed, "diagnostics").fix, None, "a policy decides");
    }

    #[test]
    fn security_fixes_respect_tamper_protection_and_versions() {
        let json = r#"{"mp":{"RealTimeProtectionEnabled":true,"IsTamperProtected":true,"AMRunningMode":"Normal"},
            "pref":{"PUAProtection":1,"EnableControlledFolderAccess":0,"MAPSReporting":0,"EnableNetworkProtection":1},
            "fw":[{"name":"Public","enabled":"False"}]}"#;
        let mut reg = registry_all_missing();
        let checks = build_security_checks(&parse_defender_state(json), &reg);
        assert_eq!(find(&checks, "cloud").fix, None, "tamper protection blocks the command");
        assert!(find(&checks, "cloud").detail.contains("Tamper protection"));
        assert_eq!(find(&checks, "firewall").fix, Some(FIX_FIREWALL));
        assert_eq!(find(&checks, "controlled_folders").fix, Some(FIX_CONTROLLED_FOLDERS));
        assert_eq!(find(&checks, "file_extensions").toggle, Some(Toggle::FileExtensions));
        assert_eq!(find(&checks, "smart_app_control").detail, "Not available on this PC");
        reg.windows11 = false;
        let win10 = build_security_checks(&parse_defender_state(json), &reg);
        assert_eq!(find(&win10, "smart_app_control").detail, "Windows 11 only");
    }

    #[test]
    fn toggle_labels_read_as_actions() {
        assert_eq!(Toggle::AdvertisingId.label(true), "Turn off");
        assert_eq!(Toggle::AdvertisingId.label(false), "Turn on");
        assert_eq!(Toggle::Camera.label(true), "Block apps");
        assert_eq!(Toggle::FileExtensions.label(true), "Show extensions");
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
            fix: None,
            toggle: None,
        };
        let s = score(&[c(Status::Good, 3), c(Status::Risk, 1), c(Status::Info, 5)]).unwrap();
        assert_eq!(s.percent, 75);
        assert_eq!(level(75), "Fair");
        assert_eq!(level(90), "Strong");
        assert_eq!(level(10), "Weak");
    }
}
