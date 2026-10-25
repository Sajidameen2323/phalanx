//! Pointing Windows at the DNS filter, and back.
//!
//! [`apply`] saves every connected adapter's DNS settings (static servers,
//! or "automatic" from the router) to a backup file *before* changing them,
//! then sets each adapter's DNS to the filter on 127.0.0.1 and `::1`, both
//! families, so IPv6 servers from the router cannot answer around it. With
//! `fallback`, the adapter's previous first IPv4 server stays as the second
//! choice: when Phalanx is not running, names still resolve (after a delay),
//! at the cost of lookups that time out on the filter going to it unchecked.
//! [`restore`] puts the saved settings back and removes the backup.
//!
//! Both run as administrator after Windows' consent prompt. Windows cannot
//! use a DNS server on another port, so the filter must listen on port 53.

use crate::system::{self, Elevated};
use anyhow::{bail, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub fn backup_path(data_dir: &Path) -> PathBuf {
    data_dir.join("web").join("windows-dns-backup.json")
}

/// Settings were changed by [`apply`] and can be restored.
pub fn has_backup(data_dir: &Path) -> bool {
    backup_path(data_dir).is_file()
}

/// Whether Windows uses the DNS filter configured in `data_dir` now. A
/// backup with no adapter pointing at the filter any more is stale:
/// restoring it could put back settings from another time.
pub fn filter_in_use(data_dir: &Path) -> bool {
    crate::web::WebConfig::load(data_dir)
        .ok()
        .and_then(|config| config.dns_listen_addr().ok())
        .is_some_and(|listen| crate::web::config::windows_uses_filter(&listen))
}

/// Whether Windows can be pointed at a filter listening on `listen`.
pub fn usable_listen(listen: &SocketAddr) -> Result<()> {
    if listen.port() != 53 {
        bail!("Windows only uses DNS servers on port 53; set the filter's listen address to 127.0.0.1:53");
    }
    if !listen.ip().is_loopback() {
        bail!("the filter must listen on 127.0.0.1:53 for Windows to use it");
    }
    Ok(())
}

fn ps_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

pub fn apply_script(backup: &Path, fallback: bool) -> String {
    format!(
        r#"$backupPath = {backup}
$adapters = @(Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }})
if (-not $adapters) {{ throw 'no connected network adapter' }}
$records = @(foreach ($a in $adapters) {{
  $guid = [string]$a.InterfaceGuid
  $v4 = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -ErrorAction SilentlyContinue
  $v6 = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -ErrorAction SilentlyContinue
  @{{ index = $a.ifIndex; name = [string]$a.Name; guid = $guid; v4 = [string]$v4.NameServer; v6 = [string]$v6.NameServer; current = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses) }}
}})
# The first backup is the one that restores the original settings; keep it.
if (-not (Test-Path -LiteralPath $backupPath)) {{ ConvertTo-Json -InputObject $records -Depth 4 | Set-Content -Encoding UTF8 -LiteralPath $backupPath }}
foreach ($r in $records) {{
  $servers = @('127.0.0.1')
  if (${fallback}) {{ $fb = @($r.current | Where-Object {{ $_ -and $_ -ne '127.0.0.1' }}) | Select-Object -First 1; if ($fb) {{ $servers += $fb }} }}
  $servers += '::1'
  Set-DnsClientServerAddress -InterfaceIndex $r.index -ServerAddresses $servers
}}
Clear-DnsClientCache"#,
        backup = ps_quote(backup),
        fallback = if fallback { "true" } else { "false" },
    )
}

pub fn restore_script(backup: &Path) -> String {
    format!(
        r#"$backupPath = {backup}
$records = @(Get-Content -Raw -Encoding UTF8 -LiteralPath $backupPath | ConvertFrom-Json)
foreach ($r in $records) {{
  $a = @(Get-NetAdapter | Where-Object {{ [string]$_.InterfaceGuid -eq $r.guid }}) | Select-Object -First 1
  if (-not $a) {{ continue }}
  Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
  $static = @((([string]$r.v4) + ' ' + ([string]$r.v6)) -split '[ ,]+' | Where-Object {{ $_ }})
  if ($static) {{ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $static }}
}}
Clear-DnsClientCache
Remove-Item -LiteralPath $backupPath"#,
        backup = ps_quote(backup),
    )
}

fn run(script: &str) -> Result<Elevated> {
    system::run_elevated_powershell(&format!("$ErrorActionPreference = 'Stop'; try {{\n{script}\nexit 0 }} catch {{ exit 1 }}"))
}

/// Points every connected adapter's DNS at the filter (administrator).
pub fn apply(data_dir: &Path, listen: &SocketAddr, fallback: bool) -> Result<Elevated> {
    usable_listen(listen)?;
    let backup = backup_path(data_dir);
    if let Some(dir) = backup.parent() {
        std::fs::create_dir_all(dir)?;
    }
    run(&apply_script(&backup, fallback))
}

/// Puts back the DNS settings saved by [`apply`] (administrator).
pub fn restore(data_dir: &Path) -> Result<Elevated> {
    let backup = backup_path(data_dir);
    if !backup.is_file() {
        bail!("there is no saved DNS configuration to restore");
    }
    run(&restore_script(&backup))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn administrator_scripts_are_valid_powershell() {
        let backup = Path::new(r"C:\x\windows-dns-backup.json");
        for script in [apply_script(backup, true), apply_script(backup, false), restore_script(backup)] {
            let wrapped = format!("$ErrorActionPreference = 'Stop'; try {{\n{script}\nexit 0 }} catch {{ exit 1 }}");
            assert_eq!(crate::system::powershell_syntax_errors(&wrapped), Vec::<String>::new(), "{wrapped}");
        }
    }

    #[test]
    fn only_port_53_on_loopback_can_be_used() {
        assert!(usable_listen(&"127.0.0.1:53".parse().unwrap()).is_ok());
        assert!(usable_listen(&"127.0.0.1:5454".parse().unwrap()).is_err());
        assert!(usable_listen(&"192.168.1.5:53".parse().unwrap()).is_err());
    }

    #[test]
    fn scripts_back_up_first_and_quote_paths() {
        let backup = Path::new(r"C:\Users\o'neil\AppData\Local\threat-scanner\web\windows-dns-backup.json");
        let apply = apply_script(backup, true);
        assert!(apply.contains(r"'C:\Users\o''neil\AppData"), "{apply}");
        let backed_up = apply.find("Set-Content").unwrap();
        let changed = apply.find("Set-DnsClientServerAddress").unwrap();
        assert!(backed_up < changed, "the backup is written before anything changes");
        assert!(apply.contains("if ($true)") && apply.contains("'::1'"));
        assert!(apply_script(backup, false).contains("if ($false)"));
        let restore = restore_script(backup);
        assert!(restore.contains("-ResetServerAddresses") && restore.contains("Remove-Item -LiteralPath $backupPath"));
        assert!(restore.find("-ResetServerAddresses").unwrap() < restore.find("Remove-Item").unwrap(), "the backup is removed last");
    }
}
