//! Operating-system integration: low-impact threads, desktop notifications,
//! starting with Windows and per-user secret storage.

use anyhow::Result;

/// Puts the calling thread into Windows "background mode": lower CPU, disk
/// and memory priority, so foreground apps stay responsive while it scans.
/// No-op elsewhere.
pub fn enter_background_mode() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
        };
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
}

/// Whether an exclusive full-screen game or presentation mode is running, so
/// non-urgent work can wait. "Busy" is not counted: Windows reports it for
/// many ordinary windows, which would hold work back for no reason.
pub fn fullscreen_app_running() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::{SHQueryUserNotificationState, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN};
        let mut state = 0;
        // SAFETY: plain FFI with a valid out-pointer.
        let ok = unsafe { SHQueryUserNotificationState(&mut state) } >= 0;
        ok && matches!(state, QUNS_RUNNING_D3D_FULL_SCREEN | QUNS_PRESENTATION_MODE)
    }
    #[cfg(not(windows))]
    false
}

/// Name shown in notifications, the Start menu and the window title.
pub const APP_NAME: &str = "Phalanx";
/// Identity Windows shows notifications under (System.AppUserModel.ID).
pub const APP_USER_MODEL_ID: &str = "Phalanx.Desktop";
#[cfg(windows)]
const AUMID_KEY: &str = r"Software\Classes\AppUserModelId\Phalanx.Desktop";
/// Registered by versions released as "Threat Scanner"; removed on upgrade.
#[cfg(windows)]
const LEGACY_AUMID_KEY: &str = r"Software\Classes\AppUserModelId\ThreatScanner.Desktop";

/// The per-user Start-menu shortcut that carries the notification identity.
pub fn start_menu_shortcut() -> Option<std::path::PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    Some(std::path::PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs").join(format!("{APP_NAME}.lnk")))
}

/// Registers this app's notification identity for the current user, so
/// toasts pop up as "Phalanx" with its icon instead of "Windows PowerShell".
///
/// Writes `HKCU\Software\Classes\AppUserModelId\Phalanx.Desktop` (name and
/// icon) and a Start-menu shortcut to `exe` carrying the same ID; Windows only
/// shows pop-up banners for an unpackaged app that has such a shortcut. No
/// administrator rights; only values that differ are written. Removes the
/// identity registered under the app's former name.
pub fn register_notification_identity(icon_png: &std::path::Path, icon_ico: &std::path::Path, exe: &std::path::Path) -> Result<()> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu.create_subkey(AUMID_KEY)?;
        let icon = icon_png.display().to_string();
        for (name, value) in [("DisplayName", APP_NAME), ("IconUri", icon.as_str()), ("IconBackgroundColor", "FF0E131F")] {
            if key.get_value::<String, _>(name).ok().as_deref() != Some(value) {
                key.set_value(name, &value.to_string())?;
            }
        }
        match hkcu.delete_subkey_all(LEGACY_AUMID_KEY) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let link = start_menu_shortcut().ok_or_else(|| anyhow::anyhow!("APPDATA is not set"))?;
        crate::shortcut::ensure(&link, exe, icon_ico, APP_USER_MODEL_ID, "Malware scanner and folder protection")
            .map_err(|e| anyhow::anyhow!("creating the Start-menu shortcut: {e}"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (icon_png, icon_ico, exe);
        Ok(())
    }
}

/// Whether toasts can use the app's own identity: both the registry entry and
/// the Start-menu shortcut exist. Without the shortcut Windows would file the
/// toasts silently, so callers fall back to PowerShell's identity.
pub fn notification_identity_registered() -> bool {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let registered = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(AUMID_KEY)
            .and_then(|k| k.get_value::<String, _>("DisplayName"))
            .is_ok();
        registered && start_menu_shortcut().is_some_and(|l| l.is_file())
    }
    #[cfg(not(windows))]
    false
}

/// Shows a desktop notification, under the app's own name once its identity
/// is registered (otherwise Windows attributes it to PowerShell). Failures
/// are ignored: a missing toast must never break scanning.
pub fn notify(summary: &str, body: &str) {
    let mut toast = notify_rust::Notification::new();
    toast.summary(summary).body(body).appname(APP_NAME);
    #[cfg(windows)]
    {
        if notification_identity_registered() {
            let mut own = toast.clone();
            if own.app_id(APP_USER_MODEL_ID).show().is_ok() {
                return;
            }
        }
    }
    let _ = toast.show();
}

/// Tells File Explorer that its view settings changed (such as showing file
/// extensions), so open windows update without signing out.
pub fn refresh_explorer_settings() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
        use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};
        let area: Vec<u16> = "ShellState".encode_utf16().chain(Some(0)).collect();
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, area.as_ptr() as isize, SMTO_ABORTIFHUNG, 1000, std::ptr::null_mut());
        SHChangeNotify(SHCNE_ASSOCCHANGED as i32, SHCNF_IDLIST, std::ptr::null(), std::ptr::null());
    }
}

/// Encrypts a secret for the current Windows user (DPAPI), hex-encoded for
/// storage in a settings file. Only this user on this PC can decrypt it.
pub fn protect_secret(secret: &str) -> Result<String> {
    #[cfg(windows)]
    {
        dpapi(secret.as_bytes(), true).map(hex::encode)
    }
    #[cfg(not(windows))]
    {
        let _ = secret;
        anyhow::bail!("storing secrets is only supported on Windows")
    }
}

/// Reverses [`protect_secret`].
pub fn unprotect_secret(stored: &str) -> Result<String> {
    #[cfg(windows)]
    {
        let bytes = hex::decode(stored.trim()).map_err(|e| anyhow::anyhow!("stored secret is damaged: {e}"))?;
        let plain = dpapi(&bytes, false)?;
        String::from_utf8(plain).map_err(|_| anyhow::anyhow!("stored secret is damaged"))
    }
    #[cfg(not(windows))]
    {
        let _ = stored;
        anyhow::bail!("storing secrets is only supported on Windows")
    }
}

#[cfg(windows)]
fn dpapi(input: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let data_in = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    let null = std::ptr::null();
    // SAFETY: `data_in` borrows `input` for the call; `out` is allocated by
    // Windows and freed with LocalFree below.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(&data_in, null as _, null as _, null, null as _, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&data_in, std::ptr::null_mut(), null as _, null, null as _, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        }
    };
    if ok == 0 || out.pbData.is_null() {
        anyhow::bail!(
            "Windows could not {} the secret: {}",
            if encrypt { "protect" } else { "unprotect" },
            std::io::Error::last_os_error()
        );
    }
    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe { LocalFree(out.pbData as _) };
    Ok(bytes)
}

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const RUN_VALUE: &str = "Phalanx";
/// Entry written by versions released as "Threat Scanner".
#[cfg(windows)]
const LEGACY_RUN_VALUE: &str = "ThreatScanner";

/// The command this user's "run at sign-in" entry starts, if there is one
/// (under the current or the former name).
pub fn autostart_command() -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey(RUN_KEY).ok()?;
        key.get_value::<String, _>(RUN_VALUE).or_else(|_| key.get_value::<String, _>(LEGACY_RUN_VALUE)).ok()
    }
    #[cfg(not(windows))]
    None
}

/// The command the machine-wide "run at sign-in" entry starts (written by
/// the installer, for every user), if there is one.
pub fn machine_autostart_command() -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(RUN_KEY).ok()?.get_value::<String, _>(RUN_VALUE).ok()
    }
    #[cfg(not(windows))]
    None
}

/// Whether this user's "run at sign-in" entry exists.
pub fn autostart_enabled() -> bool {
    autostart_command().is_some()
}

/// Adds or removes a per-user (HKCU) "run at sign-in" entry for `command`,
/// and removes any entry under the former name. No administrator rights are
/// needed and nothing system-wide changes.
pub fn set_autostart(enabled: bool, command: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
        let remove = |name: &str| match key.delete_value(name) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
        if enabled {
            key.set_value(RUN_VALUE, &command.to_string())?;
        } else {
            remove(RUN_VALUE)?;
        }
        remove(LEGACY_RUN_VALUE)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (enabled, command);
        anyhow::bail!("starting automatically is only supported on Windows")
    }
}

/// How an administrator command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elevated {
    /// It ran; the process exit code (0 is success).
    Exited(u32),
    /// The user said no to the administrator (UAC) prompt; nothing ran.
    Declined,
}

/// Runs a PowerShell script as administrator, after Windows' own consent
/// prompt, and waits for it. The script travels as `-EncodedCommand`, so no
/// quoting can change what runs. Callers pass fixed scripts, never input.
pub fn run_elevated_powershell(script: &str) -> Result<Elevated> {
    let encoded = encode_powershell(script);
    run_elevated(
        std::path::Path::new("powershell.exe"),
        &format!("-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded}"),
    )
}

/// Runs `program` with `parameters` as administrator, after Windows' own
/// consent prompt, without a window, and waits for it.
pub fn run_elevated(program: &std::path::Path, parameters: &str) -> Result<Elevated> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        // Windows' prompt comes up in front only for the window the user is
        // in; without one it may wait as a flashing taskbar button.
        let owner = unsafe {
            let window = GetForegroundWindow();
            let mut pid = 0u32;
            GetWindowThreadProcessId(window, &mut pid);
            if pid == GetCurrentProcessId() { window } else { std::ptr::null_mut() }
        };
        let params = wide(parameters);
        let (verb, file) = (wide("runas"), wide(&program.display().to_string()));
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            hwnd: owner,
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: params.as_ptr(),
            nShow: 0, // SW_HIDE
            ..Default::default()
        };
        // SAFETY: every pointer in `info` outlives the call; the process
        // handle it returns is closed below.
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            if unsafe { GetLastError() } == ERROR_CANCELLED {
                return Ok(Elevated::Declined);
            }
            anyhow::bail!("could not start {} as administrator: {}", program.display(), std::io::Error::last_os_error());
        }
        if info.hProcess.is_null() {
            anyhow::bail!("{} started without a process handle", program.display());
        }
        let mut code = 0u32;
        unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
        }
        Ok(Elevated::Exited(code))
    }
    #[cfg(not(windows))]
    {
        let _ = (program, parameters);
        anyhow::bail!("only supported on Windows")
    }
}

/// Runs a read-only PowerShell script (no window, no profile) and parses
/// what it prints as JSON. The script travels as `-EncodedCommand`.
pub fn powershell_json<T: serde::de::DeserializeOwned>(script: &str, timeout: std::time::Duration) -> std::result::Result<T, String> {
    let mut command = std::process::Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
        .arg(encode_powershell(script))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let child = command.spawn().map_err(|e| format!("could not run PowerShell: {e}"))?;
    // Waited for on a thread, so a hung script cannot block the caller forever.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = rx
        .recv_timeout(timeout)
        .map_err(|_| format!("PowerShell did not finish within {} s", timeout.as_secs()))?
        .map_err(|e| format!("PowerShell failed: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let json = text.trim().trim_start_matches('\u{feff}');
    if json.is_empty() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("PowerShell returned nothing: {}", err.trim()));
    }
    serde_json::from_str(json).map_err(|e| format!("unexpected PowerShell output: {e}"))
}

/// A script as PowerShell's `-EncodedCommand` expects: UTF-16LE, base64.
pub(crate) fn encode_powershell(script: &str) -> String {
    base64(&script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>())
}

/// Standard base64 (RFC 4648) with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Roots of the fixed (internal) drives, for a full scan. Removable, network
/// and optical drives are left out.
pub fn fixed_drives() -> Vec<std::path::PathBuf> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        const DRIVE_FIXED: u32 = 3;
        let mask = unsafe { GetLogicalDrives() };
        (0..26u8)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| format!("{}:\\", (b'A' + i) as char))
            .filter(|root| {
                let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
                unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_FIXED }
            })
            .map(std::path::PathBuf::from)
            .collect()
    }
    #[cfg(not(windows))]
    vec![std::path::PathBuf::from("/")]
}

/// Number of scanning threads for each performance level.
pub fn worker_threads(level: Performance) -> usize {
    let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
    match level {
        Performance::LowImpact => (cores / 4).clamp(1, 2),
        Performance::Balanced => (cores / 2).clamp(1, 8),
        Performance::Fast => cores.clamp(1, 16),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Performance {
    /// Few threads, background priority: the PC stays fully usable.
    #[default]
    LowImpact,
    /// Half the cores, background priority.
    Balanced,
    /// All cores, normal priority.
    Fast,
}

impl Performance {
    pub fn background(self) -> bool {
        self != Performance::Fast
    }
    pub fn label(self) -> &'static str {
        match self {
            Performance::LowImpact => "Low impact",
            Performance::Balanced => "Balanced",
            Performance::Fast => "Fast",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, expected) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }

    #[cfg(windows)]
    #[test]
    fn secrets_round_trip_through_dpapi() {
        let stored = protect_secret("AIza-test-key").unwrap();
        assert!(!stored.contains("AIza"));
        assert_eq!(unprotect_secret(&stored).unwrap(), "AIza-test-key");
        assert!(unprotect_secret("00ff").is_err());
    }
}

#[cfg(all(test, windows))]
mod drive_tests {
    #[test]
    fn the_system_drive_is_a_fixed_drive() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let drives = super::fixed_drives();
        assert!(drives.iter().any(|d| d.display().to_string().eq_ignore_ascii_case(&format!("{system}\\"))), "{drives:?}");
    }
}

/// PowerShell's own parser on a script, without running it: the syntax
/// errors it reports (empty when the script is valid). For tests.
#[cfg(all(test, windows))]
pub(crate) fn powershell_syntax_errors(script: &str) -> Vec<String> {
    let wrapper = format!(
        "$s = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}')); $t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($s, [ref]$t, [ref]$e); ConvertTo-Json -InputObject @($e | ForEach-Object {{ $_.Message + ' (line ' + $_.Extent.StartLineNumber + ')' }})",
        encode_powershell(script)
    );
    powershell_json::<Vec<String>>(&wrapper, std::time::Duration::from_secs(60)).expect("PowerShell runs")
}
