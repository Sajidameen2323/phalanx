# Phalanx: the next plan (after 0.5)

Phases 1 to 3 of [hardening-plan.md](hardening-plan.md) are done: command-line
rules, the scanner's blind spots (archives, padding, shortcuts, new drives), and the
protection service with approvals for weakening changes. This plan covers what
comes next, in the order that gives the most protection for the work.

## Where Phalanx stands

| Area | Today | Main gap |
| --- | --- | --- |
| Scanner | Hashes, YARA Forge core rules, PE heuristics, archives, padding, shortcuts | Small signature set; nothing for new or repacked malware; detection rate never measured |
| Real-time protection | New files, programs as they start, new drives, command lines (report-only) | Polls processes twice a second; reacts after a program starts; cannot block scripts |
| Web protection | About 700,000 rules, Browser Guard before any request, DNS filter, extension checks | Newest phishing domains; extension loaded unpacked; no live reputation |
| Hardening | Windows protections, privacy, browser hardening, stealer check | Few gaps |
| Self-protection | Service as SYSTEM, approvals for weakening changes | None against malware with administrator rights (out of reach for user mode) |
| History | Every scan and finding, filters by manual or real-time | Only the latest 300 shown; no search, delete, retention or export; grows forever |
| Notifications | A toast per threat or risky file, two on/off preferences | Clicking does nothing; no grouping; activity log lost on restart |
| AI Inspect | One file at a time through Gemini, with a review of what is sent | No retries; results not kept; accuracy never measured |

The single biggest unknown is **how well it detects**. Nothing has been measured
against real samples or for false positives on real software, so the first step is
a test lab that measures it, and every later step is judged by those numbers.

The second is **how dependable the app is day to day**: what happened, what it
did about it, and why. Steps 7 to 9 make History, notifications and AI Inspect
something people can rely on. They need no lab (except AI Inspect's accuracy
check) and can run alongside steps 0 to 6.

## Step 0: A test lab and measurements (about 1 week, first)

A Windows virtual machine where Claude can build, install, uninstall and test
Phalanx freely, answer its own administrator prompts, and scan real malware
without risking the PC. Setup is described in [The test lab](#the-test-lab) below.

Then build three measurements, each a script in `tools/lab/` that writes a report
to `target/lab/`:

1. **Detection rate.** Download recent samples (for example 300 from MalwareBazaar,
   across families and file types: exe, dll, scripts, documents, archives,
   shortcuts), scan them with `phalanx-cli scan --json` (never run them), and report
   the share detected per family and file type, and by which layer (hash, YARA,
   heuristics, contents). Repeat monthly, with fresh samples, to see the trend.
2. **False positives.** Scan a clean set: a fresh Windows install, `Program Files`
   after installing about 30 popular programs (browsers, Office, 7-Zip, VS Code,
   Steam, Python, Git, drivers), and their installers. Any finding is a false
   positive to fix. Also run the program monitor for a working day of normal use
   and count command-line reports.
3. **Cost.** Full-scan time and files per second on each performance setting; the
   service's CPU and memory when idle and during a burst of new files.

**Done when:** a lab run produces the three reports, and the README states the
detection and false-positive numbers honestly.

## Step 1: Releases people can trust (about 1 week)

- **Code signing.** Sign `phalanx.exe`, `phalanx-cli.exe`, `phalanx-service.exe`
  and setup. Microsoft's Artifact (Trusted) Signing is the cheapest route for an
  individual; an OV certificate also works. This removes SmartScreen's warning and
  is required for AMSI (step 3).
- **Release builds in CI.** A GitHub Actions workflow on tags: test, build release,
  build the installer, sign, attach to the release.
- **App updates.** The app checks GitHub releases (like it checks signature feeds)
  and offers to download and run the new setup. Today only signatures update.

## Step 2: Real-time process events with ETW (done in 0.6.0)

*Done:* see [etw-events.md](etw-events.md). Programs are seen within about 100 ms
(installed, 20 of 20 programs living under 110 ms were reported), side-loading of a
Windows DLL is flagged, and the idle service was brought down to about 0.5% of a
core. The plan as it was:

Phase 4a of the hardening plan. In the service, an ETW session on the
Microsoft-Windows-Kernel-Process provider (the `ferrisetw` crate):

- Process starts arrive within milliseconds, with exact parent and child, so
  short-lived processes are no longer missed. Keep the polling monitor as a
  fallback if the session cannot start.
- Image loads: flag an unsigned DLL loaded by a signed program from a folder any
  user can write to (DLL side-loading).

**Done when:** a process that lives for 50 ms is reported every time in the lab,
and the side-loading test (a signed program with a planted unsigned DLL next to it)
is flagged.

## Step 3: Block scripts before they run, with AMSI (about 2 weeks, needs step 1)

Phase 4b of the hardening plan: a tiny COM DLL registered as an AMSI provider that
passes PowerShell, Windows Script Host, macro and in-memory .NET content to the
service with a 200 ms timeout, and fails open. The service runs script rules
(AMSI bypasses, download-and-run, Defender exclusions, ClickFix loaders) and can
block. The DLL must be signed and very well tested: a hang in it would stall
PowerShell on the whole PC.

**Done when:** the AMSI test string is blocked by Phalanx in the lab, and the
lab's clean set runs with no blocks.

## Step 4: Browser Guard in the stores (mostly waiting on review)

Publish to the Chrome Web Store and Edge Add-ons (Firefox add-ons too). The service
then installs it for every user through `ExtensionInstallForcelist`, so it needs no
developer mode, cannot be removed by malware running as the user, and updates
itself. This is a policy, so browsers show "Managed by your organization": make it
a choice in setup, on by default, and say why.

## Step 5: Turn on blocking for command lines (about 3 days, after step 0)

The command-line rules still only report. With a working day of lab data and the
false-positive scan, let high-confidence matches stop the process (as detected
programs are stopped now), keep medium ones report-only, and add a setting.

## Step 6: More and better detection content (ongoing)

Driven by the detection report from step 0:

- YARA Forge's larger sets (extended), checked against the clean set first.
- Script and document rules for the families the lab misses most.
- Phishing: flag lookalikes of well-known brand domains (typosquats, Unicode
  look-alikes) in Browser Guard, and add a newly-registered-domains feed.

## Step 7: History people can manage (about 1 week)

*In progress:* see [history.md](history.md) for the milestones and progress.

History is the record of what Phalanx saw and did. Today the app loads the latest
300 entries, nothing can be found, removed or exported, and every real-time batch
adds a row, so the database only grows.

- **Paging and search.** The service answers in pages (`RecentScans` with a
  cursor) instead of a fixed 300; search by file, threat name and date; filter
  chips for threats only, commands, side-loading and web blocks.
- **Retention.** Keep detections and manual scans for a year and clean real-time
  batches for 30 days (a setting); prune once a day in the service and compact the
  database (`VACUUM`) monthly. Settings shows the database's size.
- **Review and delete.** Mark a finding as reviewed or as a false positive, with a
  note; false positives feed step 0's report and step 6's fixes. Deleting entries,
  one or by filter, needs an administrator, like other weakening changes: malware
  would like its traces gone.
- **Export.** CSV and JSON of the current view, from the page and from
  `phalanx-cli service history --export`.
- **Integrity.** A schema version with migrations, and `PRAGMA integrity_check`
  when the service starts, restoring a backup copy if it fails.
- **Contract tests.** In tests, every request the app makes is answered through the
  pipe and read back as the app's own type. History's "Show details" was broken
  through 0.5.x because the service sent an object and the app read a pair; that
  kind of bug should fail a test, not reach users.

**Done when:** 100,000 entries (a year of heavy use) page and search in under
200 ms, retention keeps the database under 50 MB, and every ipc reply has a
round-trip test.

## Step 8: Notifications and an activity log that last (about 1 week)

- **Clicking opens the right place.** A toast opens the app on that finding in
  History (it carries a launch argument such as `phalanx://scan/42`), with
  buttons where they help: **Show**, and **Quarantine** for a detected file (with
  approval).
- **No floods.** Bursts are grouped ("5 threats found in Downloads"), with at most
  one toast per program or command every few minutes. While a game or
  presentation runs full screen, or Windows' Do Not Disturb is on, only threats
  that were *not* handled automatically interrupt; the rest wait in the activity
  log.
- **Choice by kind.** Separate preferences for threats, risky files, suspicious
  commands, side-loading, web blocks, the service being down, and failed updates,
  instead of today's two switches.
- **An activity log that survives.** The service keeps it (30 days, in its
  database), so the app shows what happened while it was closed, with an unread
  count on the tray icon. Today it lives in the app's memory, 100 entries, and is
  lost on restart.
- **Delivery checks.** Settings shows whether notifications can reach the user
  (notification identity registered, Windows notifications on for Phalanx) and
  offers **Send a test notification**.

**Done when:** a burst of 50 detections gives at most three toasts and all 50 log
entries, clicking a toast opens that finding, and after a restart the log shows
everything since the last one.

## Step 9: AI Inspect that is dependable and measured (1 to 2 weeks)

- **Calls that hold up.** Retries with backoff on rate limits (429), server errors
  and timeouts; a Cancel button; Gemini's structured output (a response schema)
  so the answer is always valid JSON. Plain messages for a wrong key, a used-up
  quota and no network.
- **Results kept.** Each report is saved in the database, keyed by the file's
  SHA-256, the model and what was sent. A file inspected before shows its verdict
  at once, with **Inspect again**; History and Quarantine show the AI verdict next
  to the local one.
- **Inspect from where findings are.** History detections, Quarantine items,
  suspicious commands (the command line and decoded script) and side-loading
  reports (the program and the DLL together), not only files.
- **More than one provider.** A provider trait, with Anthropic's Claude beside
  Gemini, each with its own key (encrypted with DPAPI), model list and
  what-is-sent review.
- **Less sent.** The user name, other people's paths, e-mail addresses and tokens
  are removed from text before it is sent, and the review shows what was removed.
- **Accuracy, measured.** An evaluation set in the lab: step 0's clean and
  malicious scripts, plus files that try to talk the model into "safe". It reports
  how often the verdict is right and how often the model is fooled, and runs
  whenever the prompt or the default model changes.
- **Guardrails stay.** A local detection always outranks an AI "likely safe", and
  an AI verdict never quarantines or restores anything by itself.

**Done when:** the evaluation runs from `tools/lab/` and its numbers are in the
README, a connection dropped mid-inspection recovers or says why, and an inspected
file shows its saved verdict without a new call.

## Later

- Scanning the memory of suspicious processes (YARA on private, executable
  regions), triggered by ETW.
- An optional cloud reputation check for files and sites, only with the user's
  consent.

## Order and effort

| Step | Work | Effort | Needs |
| --- | --- | --- | --- |
| 0 | Test lab, detection / false-positive / cost reports | ~1 wk | a VM |
| 1 | Code signing, CI releases, app updates | ~1 wk | a signing account |
| 2 | ETW process and image-load events | done (0.6.0) | |
| 3 | AMSI provider | ~2 wk | step 1 |
| 4 | Browser Guard in the stores, force-installed | days, plus review | developer accounts |
| 5 | Command-line blocking | ~3 days | step 0 data |
| 6 | Detection content | ongoing | step 0 reports |
| 7 | History: paging, search, retention, review, export, contract tests | ~1 wk | |
| 8 | Notifications: click-through, grouping, preferences, a lasting activity log | ~1 wk | |
| 9 | AI Inspect: retries, saved results, more sources and providers, accuracy | 1–2 wk | step 0's lab, for the accuracy check |

Steps 7 and 8 need nothing else and make the app more dependable straight away, so
they suit the time while the lab (step 0) or a signing account (step 1) is being
set up. Step 7's contract tests come first: they guard every change after them.

---

## The test lab

### What it is for

Claude works inside the VM, not on your PC. There it can install and uninstall
Phalanx, run its own administrator prompts, change Windows settings, and scan real
malware, and the VM goes back to a clean snapshot afterwards. Your PC, accounts and
files are never involved.

### 1. A hypervisor

This PC runs Windows 11 Home, which has no Hyper-V or Windows Sandbox. Use one of:

- **VMware Workstation Pro** (free for personal use): the smoothest for Windows 11.
- **VirtualBox 7.x** (free): also works; turn on its TPM 2.0 and Secure Boot options
  for Windows 11.

Give the VM 4 cores, 8 GB of memory and an 80 GB disk.

### 2. Windows in the VM

Download the **Windows 11 Enterprise evaluation** (free for 90 days) from
Microsoft's Evaluation Center and install it. Use a local account (no Microsoft
account), for example `labadmin`, an administrator. Then:

- Install Windows updates once, then pause them, so runs are comparable.
- Create a second, standard account, `labuser`, for testing approvals the way a
  normal user meets them.
- Name the VM `phalanx-lab` and keep nothing personal in it: no email, browser
  sign-ins, passwords or files of yours.

### 3. Tools

In the VM, as `labadmin`:

```powershell
winget install Git.Git Rustlang.Rustup JRSoftware.InnoSetup Python.Python.3.12 Google.Chrome
rustup default stable-x86_64-pc-windows-gnu   # the toolchain Phalanx builds with
irm https://claude.ai/install.ps1 | iex       # Claude Code
git clone https://github.com/Sajidameen2323/phalanx C:\lab\phalanx
```

The installer reads its version from the built `phalanx.exe`, which `build.rs`
embeds with `windres`: install MSYS2's MinGW binutils (`winget install
MSYS2.MSYS2`, then `pacman -S mingw-w64-x86_64-binutils` and add
`C:\msys64\mingw64\bin` to `PATH`), or build setup with `/DAppVersion=x.y.z`.

Sign in to Claude Code there (`claude`, then follow the sign-in link). Run Claude
from a normal terminal in `C:\lab\phalanx`. A sandbox around its shell, as on this
PC, gives it a different registry view and breaks installer tests, so in the lab
VM let it run without one.

### 4. Let Claude answer administrator prompts

Windows' prompt is on a secure desktop that no program can click, by design. In the
lab VM only, let `labadmin` elevate without being asked:

```powershell
# Lab VM only. Never on a real PC.
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ConsentPromptBehaviorAdmin 0
```

Elevation stays separate (programs still start unelevated), so Phalanx's approval
logic is unchanged: a weakening change from the app still needs an elevated copy,
which now starts without a prompt. The "declined" path is tested by hand as
`labuser`, who has to type an administrator's password.

### 5. Snapshots

Take a snapshot named **clean** once the tools are installed and Claude is signed
in. Revert to it after every malware run and before every installer test, so each
run starts from the same state. A second snapshot with Phalanx 0.4.1 installed
(**old-version**) makes upgrade tests one click.

### 6. Rules for malware runs

Scanning a file does not run it, and the lab only ever scans:

- Download samples as MalwareBazaar's password-protected zips into `C:\samples`,
  and unpack them only there. Never double-click, run or open a sample.
- Defender in the VM deletes samples as they arrive: add an exclusion for
  `C:\samples` (in the VM), or turn real-time protection off there (Tamper
  Protection first, in Windows Security).
- No shared folders, shared clipboard or drag-and-drop between the VM and this PC
  during malware runs. Copy reports out only after the samples are gone.
- Keep the network on NAT (Claude Code needs the internet), and revert to the
  **clean** snapshot as soon as the run ends.
- Running samples to test real-time protection, if ever, happens in a separate VM
  with its network cut, without Claude, and is out of scope for now.

### 7. How a session in the lab goes

1. Revert to **clean** (or **old-version**), start the VM, open a terminal in
   `C:\lab\phalanx`, `git pull`, run `claude`.
2. Ask for the task: "Build, install setup, run the lab detection report", "Test
   the upgrade from 0.4.1", "Fix the false positives in the last report".
3. Claude builds, installs, drives the app (screenshots and clicks), runs the
   scripts, and commits fixes to a branch, which you review and merge as now.
4. Revert the snapshot.
