# Phalanx hardening plan (user mode only)

> Phases 1 to 3 are done (0.5). What comes next is in [next-plan.md](next-plan.md).

Phalanx has no kernel driver, so it cannot intercept anything before it runs. This
plan closes the largest gaps that user-mode code *can* close. Each phase is ordered
by how many real-world attacks it stops for the work involved. Phases 1 and 2 need
no administrator rights and fit the current app. Phase 3 is the foundation for the
admin-only pieces in Phase 4.

## Phase 1: Command-line rules on the current process monitor (about 1 week, highest priority)

**Status:** done, in report-only mode (`src/cmdline.rs`, `src/rtp/commands.rs`).
Stopping high-confidence matches waits for a few days of real use without false
positives.

**Why first:** ClickFix and attacks that misuse Windows' own tools are today's main
way infostealers get in. Right now Phalanx sees a Microsoft-signed `powershell.exe`
and marks it clean. This phase uses the existing twice-a-second process monitor, so
it needs no new design.

1. **A shared rule module.** Move `script_reasons` and `tokens` out of
   `src/audit.rs` into a new `src/cmdline.rs`, so the Stealer check and real-time
   protection use the same rules. Add these rules:
   - **PowerShell:** `-enc` or `-EncodedCommand`, `iex`/`Invoke-Expression`
     combined with `iwr`/`irm`/`Net.WebClient`, `-w hidden`, `FromBase64String`
     followed by running the result, and `Add-MpPreference -ExclusionPath`
     (malware adding a Defender exclusion).
   - **Built-in tools:** `mshta http…`, `mshta javascript:`, `rundll32 javascript:`,
     `regsvr32 /i:http…scrobj`, `certutil -urlcache`/`-decode`,
     `bitsadmin /transfer`.
   - **Downloaders:** `curl` or `wget` saving a file into `%TEMP%`/`%APPDATA%` and
     running it in the same command.
2. **Read command lines.** In `src/rtp/process.rs`, `PROCESSENTRY32W` already gives
   the parent process id. For each new process, also read its command line with
   `NtQueryInformationProcess(ProcessCommandLineInformation)`. That works with
   `PROCESS_QUERY_LIMITED_INFORMATION`, so no administrator rights are needed. Add
   `parent` and `command_line` to `ProcessInfo`.
3. **Detect the ClickFix pattern.** A strong signal is `explorer.exe` starting
   `powershell`/`mshta`/`cmd`/`curl` with any of the rules above. ClickFix also
   leaves the pasted command in
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`. Watch that key
   with `RegNotifyChangeKeyValue` and treat a new entry that matches a rule as a
   high-confidence detection. That catches it even if the process exits too quickly
   for the monitor.
4. **Scan the hidden payload.** Decode `-EncodedCommand` (Base64 of UTF-16LE text)
   and run the decoded script through YARA. That makes YARA Forge's script rules
   useful.
5. **Response.**
   - High-confidence matches: stop the whole process tree, children first, using
     the parent ids already collected, and show which rule matched.
   - Everything else: report only.
   - Ship in **report-only mode** for one release so false positives show up in
     History before anything gets stopped.

**Done when:** a harmless `powershell -w hidden -enc <Base64 of Write-Output 1>`
started from the Run box is reported with the rule name, and test cases in
`src/rtp/tests.rs` cover each rule.

## Phase 2: Close the scanner's blind spots (about 1 week)

**Status:** done on `feat/scan-blind-spots` (`src/contents.rs`, `src/rtp/drives.rs`).
ISO and VHD files are handled by checking each drive as it appears rather than by
parsing the image; RAR archives are not opened.

1. **Size padding.** Today, files over `max_size_bytes` are skipped (`src/scan.rs`,
   `src/rtp/mod.rs`). Instead, for a PE file, find where its sections end using
   `goblin`. If the extra data after that (the overlay) is mostly a single repeated
   byte or very low entropy, scan and hash the file without the padding, and flag
   "padded executable" as suspicious on its own. Use `yara_x::Scanner::scan_file`,
   which reads the file without loading it all into memory, rather than reading it
   into a `Vec`.
2. **Archives.** The `zip` crate is already a dependency. Unpack ZIP files, plus 7z
   with `sevenz-rust`, and scan what's inside. Set limits:
   - at most 3 levels of nested archives
   - at most 512 MB unpacked in total
   - at most 10,000 entries
   - stop if a file unpacks to more than 100× its compressed size, which signals a
     zip bomb

   Report a **password-protected archive that contains an executable or script** as
   suspicious. Phalanx can't open it, and attackers use exactly that to get past
   scanners.
3. **ISO and VHD files.** Don't parse them. When Windows mounts one, a new drive
   letter appears. Notice that (`WM_DEVICECHANGE`, or poll `GetLogicalDrives`) and
   run a quick scan of the new drive's root and first level.
4. **LNK targets.** For `.lnk` files arriving in watched folders, read the target
   and its arguments and run them through the `cmdline.rs` rules. Shortcuts that
   launch PowerShell are a common delivery method.

**Done when:** the `ThreatScanner_Test_Marker` file is detected inside a nested ZIP
and inside a file padded to 800 MB, and a zip bomb is reported as stopped by the
limit rather than freezing the scan.

## Phase 3: A Windows service and self-protection (2–3 weeks; the foundation for Phase 4)

1. **Split the app in two.**
   - A new `phalanx-svc` binary runs as LocalSystem. It owns the engine, real-time
     protection, the DNS filter, quarantine and the history database.
   - The GUI and `phalanx-cli` become clients that talk to it over a named pipe.
     The pipe's permissions let the signed-in user read status and send commands.
     Changing settings, allow lists or exclusions requires administrator rights or
     the user confirming through UAC.
2. **Protect data and settings.** Move signatures, `web-protection.json`,
   quarantine and the database to `%ProgramData%\Phalanx`, writable only by SYSTEM
   and Administrators. Malware running as the normal user can then no longer add
   its own domain to the allow list or delete the database.
3. **Keep the service running.**
   - Set the service's recovery options to restart on failure.
   - The tray app warns loudly if the service stops.
   - The service records its own state, and a clean shutdown is distinguishable
     from being killed.
   - The `Run`-key start-up entry stays for the tray only.
4. **The browser extension.** Publish it to the Chrome Web Store and Edge Add-ons,
   then let the service install it through `ExtensionInstallForcelist` in HKLM.
   Normal-user malware then can't disable it, and the "Developer mode" warning goes
   away. Windows Chrome only force-installs off-store extensions on managed PCs, so
   publishing to the stores is required.
5. **DNS filter.** Run it in the service so it keeps working when the GUI is
   closed. Optionally also set browser policies (`DnsOverHttpsMode`) so browsers use
   the filter instead of DNS over HTTPS.
6. **Installer.** Register the service in `installer/phalanx.iss` and migrate the
   existing per-user data.

**Be clear about the limit:** this stops malware running as the normal user. It
does **not** stop malware with administrator rights. Shielding the service from
administrators needs Protected Process Light, which means a boot-time anti-malware
driver and Microsoft Virus Initiative membership. The README and Protection page
should say that plainly.

## Phase 4: Real-time events (ETW) and AMSI (2–3 weeks; needs Phase 3)

### 4a. ETW process and image-load events

Use ETW, Windows' built-in event tracing, through the `ferrisetw` crate in the
service, with the Microsoft-Windows-Kernel-Process provider.

- **Process starts** replace the twice-a-second polling. Short-lived processes are
  no longer missed, and the parent and child are linked exactly. Set a short flush
  interval; the default of about 1 s would cancel most of the gain.
- **Image (DLL) loads:** flag an unsigned DLL loaded by a signed program from a
  folder any user can write to. That's DLL side-loading, which many current loaders
  use.
- Keep the polling monitor as a fallback if the ETW session fails.
- This still reacts *after* a process starts. It just reacts in milliseconds
  instead of up to half a second.

### 4b. AMSI provider

AMSI is the one place user-mode code can **block before code runs**. It scans
PowerShell, Windows Script Host scripts, VBA macros and in-memory .NET assembly
loads after they have been decoded.

- **The DLL:** a small COM DLL (`windows` crate,
  `#[implement(IAntimalwareProvider)]`), registered under
  `HKLM\SOFTWARE\Microsoft\AMSI\Providers`. It does nothing except send the script
  to the service over the pipe with a **200 ms timeout, and fails open**. A crash or
  hang in this DLL would break PowerShell on the whole PC, so it must stay trivial
  and get thorough testing.
- **In the service:** run YARA script rules on the content. Add rules for:
  - AMSI-bypass attempts (`amsiInitFailed`, `AmsiUtils`, patching
    `AmsiScanBuffer`)
  - download-and-run commands
  - adding Defender exclusions
  - known ClickFix loader patterns

  Return `AMSI_RESULT_DETECTED` to block.
- **Code signing:** Windows can require AMSI providers to be signed
  (`FeatureBits`), so get the DLL Authenticode-signed before release.

**Done when:** running `'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'`
in PowerShell is blocked by Phalanx, and Defender's own detection is either turned
off for the test or noted.

## Later (not part of this plan)

- Scanning the memory of suspicious processes, triggered by ETW events: run YARA on
  regions that are private and executable.
- A ransomware canary: decoy files in Documents, watched by the service, which
  stops whoever changes them. Controlled Folder Access already does this better, so
  keep recommending it on the Protection page.

## Summary

| # | Work | Threats it closes | Admin needed | Effort |
|---|---|---|---|---|
| 1 | Command-line rules + RunMRU + decoding encoded commands | ClickFix, misused Windows tools | No | ~1 wk |
| 2 | Padding, archives, ISO, LNK | Payloads that slip past the scanner | No | ~1 wk |
| 3 | Service + locked-down settings + store extension | Phalanx being turned off by normal-user malware | Install only | 2–3 wk |
| 4 | ETW + AMSI | Short-lived processes, side-loading, blocking scripts before they run | Yes | 2–3 wk |

With all four done, Phalanx becomes a solid second layer next to Microsoft
Defender. Its only remaining blind spot is malware that already has administrator
rights, which no user-mode product can defend against.
