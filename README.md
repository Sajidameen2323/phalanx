# Phalanx

<img src="assets/phalanx.png" width="96" alt="Phalanx emblem">

**Phalanx is one place to protect a Windows PC.** It finds and removes malware,
watches for new threats as they arrive, blocks dangerous websites in your browsers
and for the whole PC, looks for what infostealers leave behind, and checks that
Windows' own protections are switched on. Everything runs on your PC, needs no
account, and shows you exactly what it found and why.

| Area | What Phalanx does |
| --- | --- |
| **Scanning** | Quick, full and custom scans with hash signatures, YARA rules and Windows-program heuristics, plus a reversible quarantine and a complete history. It also looks inside ZIP and 7z archives, scans programs padded past the size limit, and checks what shortcuts run. |
| **Real-time protection** | Scans new downloads, every program that starts (Windows reports each one within milliseconds, so even very short-lived programs are seen), and the files on a disk image or USB drive as soon as it appears, and stops running malware. It also reads the command lines of PowerShell and other Windows tools, and the commands pasted into the Run box, to catch attacks that never drop a file, such as fake CAPTCHA (ClickFix) pages, and spots a trusted program made to load a planted DLL (side-loading). These two only report for now. |
| **Web protection** | Browser Guard blocks malware and phishing sites before your browser sends them a single request, marks dangerous search results, and can block ads and trackers. A DNS filter extends the blocking to every program on the PC. It also finds malicious browser extensions and checks each browser's security settings. |
| **Stealer check** | Looks for the start-up entries, scheduled tasks, browser switches, policies, proxies and hosts-file changes that infostealers use. |
| **Windows protection and privacy** | Checks Microsoft Defender, SmartScreen, the firewall, memory integrity and more, and can switch on what is off. A privacy checklist does the same for Windows privacy settings. |
| **AI Inspect** | Asks Google Gemini for a second opinion on a file (optional, needs your own API key). |
| **Signature updates** | Pulls fresh malware hashes, YARA rules and malicious web addresses from public threat-intelligence feeds (abuse.ch, YARA Forge, URLhaus, HaGeZi, CERT Polska). |

Protection runs in a Windows service, so it keeps going with the app closed and
nobody signed in, and anything that weakens it needs an administrator's approval.
Phalanx works in user mode, without a kernel driver, so it is designed to run
**alongside Microsoft Defender**, not instead of it. It adds the web blocking,
stealer checks, command-line checks and clear explanations on top. See
[docs/hardening-plan.md](docs/hardening-plan.md) for what is planned next.

It is written in Rust and is an original implementation; it contains no
Malwarebytes code or signatures. The app is `phalanx.exe`; `phalanx-cli.exe` offers
the same features on the command line.

## How scanning works

Detection layers, in order:

1. **Hash blocklist**: exact SHA-256 matches (`rules/hashes.txt` plus `--hashes FILE`).
2. **YARA rules**: pattern rules run by [YARA-X](https://github.com/VirusTotal/yara-x)
   (`rules/default.yar` plus `--rules PATH`).
3. **PE heuristics**: scores Windows executables for packing (section entropy, packer
   section names), writable+executable code, injection/hollowing/keylogging API
   combinations and runtime API resolution. A score of 60 or more is reported as
   `suspicious`. Heuristics never report `malware`.
4. **What the file holds** (`src/contents.rs`), the usual ways past a scanner:
   * **Archives.** ZIP and 7z files are opened and every file inside goes through the
     layers above, up to 3 archives deep. A finding names where it was found
     (`… · inside invoice.zip > docs/setup.exe`) and is reported on the archive,
     which is what gets quarantined. Limits keep decompression bombs harmless: at
     most 512 MB unpacked and 10,000 files per archive, and a file that unpacks to
     over 100 times its packed size is not unpacked. A **password-protected archive
     holding a program, script, shortcut or disk image** is reported as
     `Suspicious.LockedArchive`: no scanner can look inside, which is why attackers
     use them. The PE heuristics are not applied inside archives, where a
     publisher signature cannot be checked. Turn this off under Settings >
     Scanning > Scan inside archives (`--no-archives`). RAR is not opened.
   * **Padded programs.** Stealers are often padded with hundreds of megabytes of
     zeros to exceed scanners' size limits. A Windows program larger than the limit
     is no longer skipped: if what follows its last section is padding (one
     repeated byte or a short repeated pattern), the program itself is read and
     scanned, so signatures and hash lists that know the original sample still
     match, and the file is reported as `Suspicious.PaddedExecutable`. Large
     installers with real compressed payloads are still skipped. A padded file is
     quarantined whole, streamed from disk rather than read into memory.
   * **Shortcuts.** A `.lnk` file's target and arguments are read and checked with
     the command-line rules, so a shortcut named like a document that starts
     PowerShell to download something is reported (`Suspicious.Shortcut.<rule>`),
     as is one whose arguments are pushed out of view with spaces.

Results are recorded in a local SQLite history. Detections can be moved into a
reversible quarantine.

## Build

```
cargo build --release
```

This produces `target\release\phalanx.exe` (the app) and `phalanx-cli.exe`. With the
GNU toolchain, `build.rs` embeds the Phalanx icon and version information using
`windres` (set `WINDRES` to use another one); without it the build still succeeds,
without the icon.

The icon assets in `assets/` come from the Phalanx logo:

* `phalanx-logo.png` and `phalanx-wordmark.png` are transparent, for dark
  backgrounds; their `-dark` versions are for light backgrounds.
* `phalanx-emblem.svg` is the vector emblem, with no background. It is the source
  of every icon. A dark outline and dark visor keep the helmet readable on light
  taskbars too.
* `phalanx-emblem-small.svg` is a heavier version for 16–32 px.
* Rendered from these: `phalanx-emblem.png` (512 px), the app icon `phalanx.ico`
  (16–256 px, small sizes from the heavier version), `phalanx.png`,
  `phalanx-128.rgba`, and the extension's `icon16/32/48/128.png`.

The first build takes several minutes, mostly compiling YARA-X's WebAssembly JIT.

### Protection service

Protection runs in a Windows service, `phalanx-service.exe`, as LocalSystem: it
keeps protecting when the app is closed and nobody is signed in, and programs
running as a user cannot switch it off. It runs real-time protection, scans,
signature updates, quarantine, and the DNS filter and block page, with its data in
`%ProgramData%\Phalanx` (administrators can change it; users can read it, except
the quarantine). The app, the browser connector and the CLI talk to it on the
named pipe `\.\pipe\Phalanx`, and the app shows its notifications. Anything that
weakens protection needs an administrator: the app then runs `phalanx-cli`
elevated, after Windows' own prompt, which malware running as the user cannot
answer. Malware that already has administrator rights is out of reach of any
user-mode tool; see [docs/protection-service.md](docs/protection-service.md).

```
phalanx-cli service install     # as administrator: install and start it (setup does this)
phalanx-cli service status      # any user: is it running, and who am I to it
phalanx-cli service stop | start | uninstall
phalanx-cli service migrate     # as administrator, once: bring a 0.4 user's data over
phalanx-cli service scan D:\    # scan in the service, with progress
phalanx-cli service events      # watch what the service reports
phalanx-cli service settings
phalanx-cli service history --search invoice --threats-only --days 7   # also --kind, --before, --findings
phalanx-cli service history --threats-only --export threats.csv        # or .json; every matching scan
phalanx-cli service review 42 --false-positive --note "our build tool"  # or --reviewed, --clear
phalanx-cli service delete-history --scan 300   # or --all-matching with history's filters (administrator)
phalanx-cli service protection  # watching? programs through process events?
phalanx-cli service update      # download signatures in the service, with progress
phalanx-cli service web         # web settings and whether the DNS filter runs
phalanx-cli service site block example.test   # allow / unblock need administrator
phalanx-cli service ads on|off  # off needs administrator
phalanx-cli service auth-key --from-app       # as administrator: the app's abuse.ch key
```

For development, run the service in a terminal on a pipe of its own and point the
app and CLI at it:

```
phalanx-service --console --pipe \.\pipe\phalanx-dev --data-dir D:\dev-data
set PHALANX_PIPE=\.\pipe\phalanx-dev
```

### Installer

```
cargo build --release
"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\phalanx.iss
```

This needs [Inno Setup](https://jrsoftware.org/isinfo.php) 6.7 or later and produces
`target\installer\Phalanx-Setup-<version>.exe`, with the version read from the built
`phalanx.exe` (so it always matches `Cargo.toml`). Setup asks for administrator
rights once and installs for the whole PC into `Program Files\Phalanx`: it installs
and starts the protection service, and starts the app in the tray at every user's
sign-in (`HKLM\...\Run`). It ships a short user guide (`installer\README.txt`)
rather than this file. A running Phalanx is asked to quit, and the service is
stopped, before files are replaced.

Setup upgrades a 0.4.x install (per user, in `%LOCALAPPDATA%\Programs\Phalanx`):
the installing user's settings, history, quarantine, web lists and abuse.ch key are
brought into the service's folder, the old copy is removed, and its data folder is
kept. If Windows' DNS was pointed at the DNS filter, it stays that way: the
service answers on the same address. The uninstaller puts Windows' DNS settings
back if Windows uses the DNS filter (`phalanx-cli web restore-dns`), removes the
service, and asks before deleting the data. The setup program is not code-signed,
so SmartScreen warns about it until it is.

## Desktop app

```
target\release\phalanx.exe            # open the app
target\release\phalanx.exe D:\folder  # open and scan immediately
target\release\phalanx.exe --quit     # quit the running copy (also from the tray)
```

The app has these pages:

* **Dashboard**: status (including threats that real-time protection found but did
  not remove), signature updates, monthly totals, and scan buttons. You can drop files
  onto the window to scan them.
* **Scan**: choose a **quick scan** (Downloads, Desktop, Documents, temp), a **full
  scan** (every file on the internal drives) or a **custom scan** (folders or
  files you pick); then live progress with a cancel button, and the detections.
  Select detections and quarantine them.
* **Protection**: a **Windows protection status** card (see below), and
  **real-time protection**: new files in watched folders (for example Downloads) and
  every program that starts are scanned automatically, threats that are running are
  stopped, and you get a Windows notification for each threat.
* **Web protection**: block malware and phishing sites in your browsers (Browser
  Guard) and for the whole PC (DNS filter), check a site, manage allowed and
  blocked sites, and find dangerous browser extensions (see below).
* **AI Inspect**: ask Google Gemini whether a file looks safe (see below).
* **Privacy**: a privacy checklist with a score; Phalanx can switch most items for
  you (see below).
* **Quarantine**: restore or permanently delete isolated files.
* **History**: every scan with its type, duration, files, data, threads, skipped
  and unreadable files, quarantined files and signature date. Expand a scan to see
  its detections and errors. Search by file, folder or threat name; filter by
  threats found, manual scans, real-time protection, suspicious commands or DLL
  side-loading, and by the last day, week or month. Pages of 50 load as you ask
  for more. History is kept a year, and real-time checks that found nothing for
  30 days (Settings > General > History; keeping less needs an administrator).
  The service removes what is older once a day, adding it to the monthly totals
  first, and compacts the database monthly; a year of heavy use takes about
  1 MB. Quarantine records are never removed.
  Each finding can be marked **Reviewed** or **Not a threat**, with a note; the
  service records who marked it. Entries can be deleted one at a time or all
  that match the current filter (an administrator's approval is needed: it
  removes evidence); deleted entries leave the monthly totals too, and
  quarantined files are not touched. **Export…** saves everything the current
  filter matches, one row per finding with its mark, as CSV (for spreadsheets;
  a cell that starts like a formula is kept as text) or JSON.
  The service checks the history database each time it starts and backs it up
  daily (only if it passes a check). A damaged database is moved aside, never
  deleted, and the last backup takes its place; the app says so in its
  activity log and in Settings. Quarantined files are never affected.
* **Settings**, in tabs: **General** (startup, tray, notifications, data folder),
  **Scanning** (performance, detection, quarantine), **Exclusions**, **Signatures**
  and **AI inspection**.

Layouts adapt to the window size: tiles reflow, button rows wrap, and long paths
show the file name first.

### Real-time protection

Real-time protection (`src/rtp/`) follows the usual on-access antivirus pipeline,
in user mode:

```
folder monitor ──┐                        ┌─ urgent lane: programs starting, new
program monitor ─┴─▶ exclusions, then the ─┼─ bulk lane: other files, catch-up
                     disposition cache     │  (background priority)
                                           └─ sweep lane: programs already running
                                              at start (background priority)
        ──▶ engine (hashes, YARA, heuristics; rule and heuristic hits on
            signed files dropped) ──▶ verdict cached ──▶ report, quarantine, stop
```

* **Watched folders.** Each folder has its own `ReadDirectoryChangesW` watch with a
  64 KiB buffer. When Windows drops changes because too many happened at once (an
  archive extracted into Downloads), the folder is rescanned for files changed in
  the last 5 minutes instead of silently missing them. A folder moved or extracted
  into a watched folder has its files scanned too.
* **Scans finished downloads only.** A file is scanned once it has *settled*: no
  changes and an unchanged size for 3 seconds. Partial downloads (`.crdownload`,
  `.part`, `.tmp`…) are ignored until they are renamed to their final name.
* **Programs as they start.** The service learns of every process that starts from
  Windows' own process events (ETW, the Microsoft-Windows-Kernel-Process provider,
  `src/rtp/etw.rs`), within about 100 ms, with its exact parent, so a program that
  runs for only a moment is still seen. The list of running programs is still read
  every 5 seconds, for anything the event session lost. Without administrator
  rights (a `phalanx-cli watch` in a normal terminal) the list is read twice a
  second instead, as before 0.6; the Protection page shows which ("Programs seen").
  The program file of each new process is scanned in the urgent lane. A program
  found to be malware is stopped (the process is identified
  by id *and* creation time, so a reused process id is never mistaken for it) and,
  with automatic quarantine on, quarantined once it has exited. A known threat that
  is started again is stopped at once without rescanning. Only **malware** is
  stopped: PUPs and hacking tools (often run on purpose) and suspicious (heuristic)
  findings are reported and left running. Programs already running when protection
  starts are checked in a lane of their own, in the background, so they never hold up
  new files. Turn this off, or turn off stopping, on the
  Protection page; clean program checks are not written to History.
* **Command lines are checked (report only).** Most infostealers now arrive without a
  file: a fake CAPTCHA page has you paste a command into the Run box (ClickFix), or a
  shortcut starts PowerShell with the payload on its command line. With program
  protection on, the command line of each PowerShell, `cmd`, `conhost`, `mshta`,
  `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wscript` and `cscript` that starts
  is read and checked against rules for downloading and running code, encoded and
  hidden commands, Defender exclusions, AMSI bypasses and ClickFix's fake verification
  comments (`src/cmdline.rs`, shared with the Stealer check). An `-EncodedCommand` is
  decoded and its script also goes through the signatures. New entries in the Run
  box's history (`RunMRU`) are checked the same way, which catches a pasted command
  even when it exits too quickly for the program monitor. Windows keeps that history
  only while "Track app launches" is on (Privacy page, `Start_TrackProgs`); with it
  off, the program monitor still catches what the command starts, and a command
  started by Explorer is reported as coming from the Run box. Every match is shown in the
  activity log. High-confidence ones are also recorded in History (kind `COMMAND`,
  category suspicious) and notify; medium-confidence ones (encoded commands, hidden
  windows, `Invoke-Expression` alone, all common in admin tools and terminals) are
  not kept. The same command line is reported once every 10 minutes, however often
  it runs. **Nothing is stopped yet**: this release only
  reports, so false positives surface before any rule acts. Programs that Phalanx
  itself starts are not checked. A program that exits before its start event is
  handled (about 100 ms) is still scanned, but its command line is gone by then.
* **DLL side-loading is flagged (report only).** Many current loaders bring a
  validly signed program (often Microsoft's or a security vendor's) together with a
  planted DLL named after one it imports; Windows looks next to the program first,
  so the planted copy runs inside a trusted process. With process events, every
  DLL a program loads is seen (`src/rtp/sideload.rs`). Phalanx reports a signed
  program loading an **unsigned DLL named after one in `System32`**, from outside
  Windows' and Program Files' folders (which only administrators can change). Apps
  installed per user load unsigned DLLs of their own all the time (`ffmpeg.dll`
  and the like), but rarely an unsigned copy of a Windows DLL, so this stays quiet
  on normal software. A finding is shown in the activity log, notifies, is recorded
  in History (kind `SIDELOAD`, category suspicious), and the DLL is scanned. Nothing
  is stopped yet. Needs administrator rights, so it runs in the service.
* **Disk images and USB drives are checked as they appear.** Opening an ISO or VHD
  adds a drive letter, and the files inside carry no Mark of the Web, so Windows'
  download warnings stay quiet. When a local drive appears (a mounted image or a USB
  drive), the files on it up to two folders deep (at most 500, top level first) are
  scanned in the urgent lane, and the activity log notes the new drive. Network drives
  are left out. Turn this off on the Protection page (`--no-new-drives`).
* **Signed software is trusted.** YARA and heuristic findings on a file with a
  valid Authenticode signature, embedded or through a Windows security catalog
  (how most of Windows is signed), are dropped: public rules match open-source
  libraries, installers and embedded scripts that signed programs share with
  malware. Revocation is not checked and nothing is fetched from the network.
  Known-malware hash matches are always reported. This also applies to manual
  scans (Settings > Scanning > Trust signed software). The other way round, a
  flagged file whose embedded signature no longer matches it (changed after
  signing: cracked, patched or infected) is also reported as
  `Tampered.SignedFile`, malware, whatever this setting says.
* **Disposition cache.** Each file version (path, size, modification and creation
  time) is scanned once; opening, renaming back or relaunching it costs nothing.
  The cache is cleared whenever signatures or settings change.
* **Recovers by itself.** If any part fails or crashes, the whole pipeline restarts
  after 2 s (doubling to at most 60 s while it keeps failing) and catches up on
  files changed meanwhile. A watched folder that disappears (an unplugged drive) is
  reported and watched again, with a catch-up scan, as soon as it is back; one that
  is missing at start is retried the same way.
* **Light on resources.** One file is scanned at a time per lane; everything but new
  programs runs at Windows *background priority*. While a full-screen game or
  presentation runs, the bulk lane waits (at most 10 minutes).
* **Catches up.** Files that arrived while the service was stopped are scanned the
  next time it starts. A copied-in file counts as new even if it keeps an old
  modification time.
* **Runs without the app.** Real-time protection runs in the protection service, so
  closing or quitting the app does not stop it. The app keeps running in the tray
  to show notifications, and warns when the service has been down for a while.
* **Start with Windows.** Setup adds a machine-wide sign-in entry
  (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`) that starts the app
  hidden in the tray for every user: the window never appears or takes the focus
  until you open it from the tray. Each user can turn it off for themselves in
  Windows' Settings > Apps > Startup. Without setup's entry, the app's own setting
  adds a per-user one (`HKCU`); a per-user entry left by 0.4 is removed when the
  machine-wide one exists.
* **One copy at a time.** Launching it again brings the running window to the
  front. A second start-up entry (`--background`) never does.
* **Warns about programs and scripts before you open them.** When an `.exe`, `.msi`,
  `.ps1`, `.py`, `.bat`, `.js`, `.lnk`, `.iso` or similar file lands in a watched
  folder, a notification appears within about a second, before the file has
  settled, naming the download site (from the Mark of the Web) when known.
  Disguised names such as `invoice.pdf.exe`, right-to-left-override tricks and
  space-padded extensions are called out. A second notification reports the scan
  result: no known threats, a detection, or why it was not scanned. Turn this off
  under Settings > General > Notifications.
* **Notifications pop up as Phalanx.** On start, the app registers a per-user
  notification identity: `HKCU\Software\Classes\AppUserModelId\Phalanx.Desktop`
  (name and icon) and a Start-menu shortcut, `Phalanx.lnk`, carrying the same ID.
  Windows only shows pop-up banners for a desktop app that has such a shortcut;
  without it, notifications land silently in the notification centre. No
  administrator rights are needed, and nothing is rewritten unless it changed.
  Delete the key and the shortcut to undo it. Use **Send a test** in Settings >
  General to check. If the identity cannot be registered, notifications fall back to
  PowerShell's name.

### Web protection

Web protection has three parts that share one set of rules and one settings file
(`web-protection.json` in the data folder).

**Rules and verdicts.** Rules block by domain (with its subdomains), exact URL,
IP address or CIDR range, and TCP port. They come from `rules/web.txt` (built in),
the downloaded feeds (`signatures/feed-web.txt`) and your own block list. Each
check gives a verdict code that says *why*:

| Code | Meaning | Result |
| --- | --- | --- |
| 0 | no rule matched | allow |
| 1 | bad IP address, range or port | **block** |
| 2 | bad domain or URL | **block** |
| 3 | DNS alias (CNAME) of a bad domain | **block** |
| 4 | you allowed the site | allow |
| 5 | false-positive reduction entry | allow |
| 6 | allowed from the browser's warning page | allow |
| 7 | known-good site (big platforms that host user content) | allow |

Exact-URL rules still apply on known-good hosts. For example, a single malware
download link on github.com is blocked, but github.com itself is not. Your own block
list overrides the known-good list. Loopback, local-network and multicast addresses
are never blocked. Set the mode to **Block**, **Report only** (matches are only
logged) or **Off**.

**Browser Guard (browser extension).** Choose **Connect browsers**. This registers a
native-messaging connector (`phalanx-cli`) for Chrome, Edge, Brave, Chromium/Vivaldi
and Firefox, per user under `HKCU`, so no administrator rights are needed. It also
writes the extension to `<data folder>\browser-extension`. Load that folder once per
Chromium browser with **Load unpacked** (Developer mode). Firefox gets its own copy in
`<data folder>\browser-extension-firefox` (its manifest runs the background page as a
script, where Chromium wants a service worker): load its `manifest.json` under
**about:debugging > This Firefox > Load Temporary Add-on**.

Malicious sites are blocked **before the browser sends any request** to them. The
connector hands the malicious names (after allow lists) to the extension, which
installs them as `declarativeNetRequest` block rules, 1,000 names to a rule, for
every resource type: the page itself and anything a legitimate page loads from a
malicious name. The browser applies these rules itself, synchronously, so a blocked
site receives no request, not even for a moment, and no page content loads. The
rules persist across browser restarts and keep protecting while the connector is
unavailable; they are refreshed when the rules or your allow lists change, retried
within 15 seconds when a sync fails. (This was verified in Edge with a test server:
the blocked host logged no request at all.) Asking Phalanx per page remains as a
second layer for rules a browser rule cannot express (exact URLs, IP ranges); that
check runs alongside the navigation, which is why it is not the first line.

A blocked page is replaced by a warning page with **Go back to safety**. Under **Details and options** you can also **Continue this time**
(only in that tab, until it leaves the site or closes; a session rule lets that tab
through while the site stays blocked everywhere else) or **Always allow this site**
(verdict 6). This works for `https://` sites too,
without intercepting TLS or installing a certificate. If Phalanx is unreachable, the
extension never blocks; its icon shows `!` instead.

The extension also **marks search results** on Google (common country domains),
Bing, DuckDuckGo, Yahoo and Brave Search:

* A green check means the address is on none of Phalanx's threat lists. That is not
  a guarantee that the site is safe.
* A red **Dangerous** label means opening it would be blocked.

It unwraps the engines' redirect links (Google `/url?q=`, Bing `/ck/a`, DuckDuckGo
`/l/`, Yahoo `RU=`) to check the real address. All checks happen in Phalanx on this
PC, and search-result checks are not logged. Turn marking off in the extension's
settings.

The popup shows whether protection is on, the verdict for the current site, when the
threat lists were last updated, and a button that opens Phalanx.

The popup shows, for the current page, how many ads and trackers were blocked, how
many ad pop-ups were closed and how many requests to dangerous sites the page made
(counted afresh for each new page; the toolbar icon shows the same total), plus
today's blocked sites and ads. **Block this site** adds it to your blocked sites
(blocked before loading, even if Phalanx otherwise trusts it); **Allow this site**
stops Phalanx blocking it and its ads, while dangerous third-party requests from it
stay blocked. Both can be undone from the popup or the extension's **Settings**
page, which also holds ad blocking, closing ad pop-ups, the icon count, search-result
marking, and your blocked and allowed sites (shared with the app and every connected
browser).

**Ad and tracker blocking (optional, off by default).** Turn on **Block ads and
trackers** on the Web protection page, in the extension's popup, or with
`phalanx-cli web ads on`. Phalanx then also blocks the names on the
[StevenBlack hosts](https://github.com/StevenBlack/hosts) list (about 74,000 ad,
tracking and adware names, saved as `signatures/feed-ads.txt`). They match with
their subdomains, like other domain rules, and report category `ads` from the list
`adsBlockList` with verdict code 2. Threat rules are checked first, so a name on
both lists still reports as malware. Known-good sites, your allowed sites,
false-positive entries and the extension's exclusions still win.

* **In the browser**, Browser Guard turns the names into `declarativeNetRequest`
  rules, so scripts, images, frames and other requests *inside* pages are blocked,
  not just pages you open. The connector hands the names out in list order, and the
  extension packs them 1,000 to a rule within the browser's dynamic-rule limit. If
  the browser refuses that many, the first half of the list is kept and the rest
  dropped. Allowed and excluded names are left out of the rules. The rules are
  rebuilt only when the list or your settings change. An ad address opened as a
  whole page gets no warning: a tab a page opened for it (pop-ups, pop-unders) is
  closed, and a tab that was showing a page goes back to it. Only an ad address
  you type into a blank tab shows the warning page ("Ad or tracker blocked"). The
  popup counts blocked ad requests today and in total. This count is read from the
  browser at most once a minute, so it is approximate.
* **In the DNS filter**, ad names get the sinkhole answer, and the block-page
  server answers their `http://` requests with an empty `204` instead of a warning
  page. Ad blocks are not written to the event log and never notify. The app shows
  how many the filter blocked since it started.

Ad blocking only blocks in **Block** mode. In report-only mode or with web
protection off, ads load normally and nothing is logged.

**Pausing ad blocking on one site.** If a site breaks or asks you to turn off your
ad blocker, open the extension's popup on that site and choose one of:

* **Pause 1 hour**
* **Until I close the browser**
* **Always on this site**

**Resume ad blocking** turns it back on. The extension's settings page lists every
paused site with a **Resume** button.

A pause covers the site and its subdomains, in that browser only. It is one
`allowAllRequests` rule for the site's pages and frames:

* **Always on this site:** a dynamic rule, kept until you resume.
* **The other two:** a session rule, which the browser drops when it closes.

The rule lets that site's ads and trackers load and keeps ad pop-ups from that site
open. Threat rules rank above it, so dangerous sites and dangerous requests on the
page are still blocked. A 1-hour pause ends at the first navigation after the hour
is up. The DNS filter, if you use it, still blocks ad names for the whole PC: it
cannot tell which site a lookup is for.

**DNS filter (whole PC).** When it is on and the app is running, a resolver runs on
`127.0.0.1:53` and forwards lookups to the PC's own resolvers. It checks the name
before forwarding and the answers afterwards, so a CNAME to a bad domain or an answer
inside a bad IP range is also caught. A blocked name resolves to the loopback
sinkhole `127.66.0.1`. A small server there answers `http://` requests with
`303 See Other` to its own block page. The redirection cache (1,000 entries, oldest
dropped first) records why each name was blocked. Blocked `https://` sites just fail
to load. The filter also answers on the IPv6 loopback `[::1]:53`.

To use it, choose **Set up…** under **Use the filter for Windows DNS** (administrator,
after a confirmation that says exactly what changes). It first saves every connected
adapter's DNS settings to `web\windows-dns-backup.json`, then points each adapter's
IPv4 *and* IPv6 DNS at the filter. Both matter: many routers also hand out IPv6 DNS
servers, which Windows would otherwise ask directly. **Keep a fallback DNS server**
(on by default) leaves the adapter's previous first server second in line, so the
internet still works when Phalanx is closed; turning it off means nothing resolves
without Phalanx, but no lookup can slip past it. **Restore previous DNS…** puts back
exactly what was saved (automatic from the router, or the servers you had). It is
offered only while Windows uses the filter: a backup from an earlier setup that
Windows no longer uses is stale and discarded rather than restored
(`phalanx-cli web restore-dns --check` says which; the uninstaller asks only then).
A browser whose "secure DNS" (DNS over HTTPS) is set to a provider of its own
bypasses the filter, but Browser Guard still covers it. Chrome's and Edge's default,
"automatic", does not: it only switches to a provider the DNS server offers. While
Windows uses the filter, browser hardening (below) flags a browser that bypasses it.
Phalanx does not force this with browser policies, which would show "Managed by
your organization" and turn encrypted DNS off for everyone.

**Browser hardening.** The Web protection page also checks each Chromium browser
and profile, read-only: whether an update is downloaded but waiting for a restart
(the browser keeps `new_chrome.exe` until then) and whether a newer stable release
exists (from Google's and Microsoft's public version feeds; nothing about the PC is
sent), Safe Browsing (standard or enhanced), the JavaScript optimizer (turning it off
removes the part of the browser most zero-day exploits target), secure DNS, whether
Browser Guard is installed, and how many passwords the profile stores (rows are
counted from a copy of the database; nothing is read or decrypted). Each item opens
the browser's own setting in that browser and in that profile (`--profile-directory`),
so a profile's settings never open in another profile or browser.
`phalanx-cli browsers` prints the same.

**Browser extensions.** **Check browsers** reads every Chrome, Edge, Brave and
Vivaldi profile. It reports an extension as:

* **malicious or unwanted** when it is on the known-bad list (`rules/extensions.txt`
  plus `signatures\bad-extensions.txt`) or the browser flagged it.
* **suspicious** when it was installed outside the web store and has a high risk
  score. The score counts risky permissions (all sites, debugger, proxy, managing
  other extensions…), settings overrides, and loading by command line or another
  program.
* **review** for web-store extensions with broad permissions.

It also reports a default search engine that is not a well-known one, and a search
engine, home page or start-up page that points to a blocked site. **Remove** works
while the browser is closed. It backs up both preference files (and the registry MAC
Chromium keeps), moves the extension's folder into `browser-backups`, and deletes
its entries. Undo it with `phalanx-cli web restore-extension <backup folder>`.

### Stealer check

The **Stealer check** page (and `phalanx-cli audit`) looks for what infostealers and
the loaders that install them leave behind. It is read-only and takes about 20
seconds:

* start-up entries (Run keys, Startup folders), scheduled tasks (outside
  `\Microsoft\`) and services, with each program's digital signature. Flagged:
  unsigned programs in folders any program can write to, signatures that do not
  verify, programs started from temporary folders, missing programs, and script
  hosts (PowerShell, `mshta`, `wscript`…) running encoded, hidden or downloaded code.
* browser shortcuts and launch commands with `--remote-debugging-port`,
  `--remote-debugging-pipe` or `--load-extension`, which let another program read the
  browser's cookies.
* browser policies that force-install extensions (`ExtensionInstallForcelist`).
* a proxy or proxy script, and hosts-file entries that redirect or block account and
  security sites.
* Microsoft Defender's exclusions, on request (they can only be read as
  administrator; malware often adds them).

Programs that are not validly signed are also scanned with the local engine. Each
finding shows where it is, with **Open folder**, **Scan file** and **Inspect with
AI**. Nothing is removed: after a real infection, the safe order is an offline scan,
then signing out of every session and changing passwords from another device, and
resetting Windows if malware is confirmed.

### Windows protection status

The Protection page checks: real-time antivirus (Microsoft Defender or another
registered product), tamper protection, cloud-delivered protection, potentially
unwanted app blocking, SmartScreen (Check apps and files), Smart App Control
(Windows 11 only), memory integrity, firewall profiles, controlled folder access,
User Account Control and whether file extensions are shown. Each check says what it
read and links to the Windows Security or Settings page where you can change it; the
pages are the ones that exist on both Windows 10 and Windows 11 (for example Folder
Options for file extensions, which Settings moved between versions). **Network
protection** (Microsoft Defender blocking connections to malicious sites for every
program, inside Windows' network stack) is checked too; Windows Security has no
switch for it, so it links to Microsoft's documentation.

Phalanx can change some of these itself:

* **Show extensions** switches file extensions on (or back off) for your account
  directly, no administrator rights needed, and refreshes open File Explorer windows.
* Network protection, potentially unwanted app blocking, cloud-delivered protection,
  the firewall and controlled folder access have a **Turn on** button when they are
  off. It shows the exact PowerShell command and runs it as administrator only after
  you confirm and approve Windows' prompt, then reads the setting again (some
  editions or policies accept the command without the setting changing; the page
  says so). Cloud-delivered protection has no button while tamper protection is on,
  because tamper protection blocks the command; use Windows Security for it. **Run offline scan** starts a
Microsoft Defender Offline scan, which restarts the PC and scans before Windows
starts. Values that cannot be read are shown as *Unknown*, never as off.
Defender settings are marked not applicable when another antivirus is active.
Reading Defender's state runs a short PowerShell query in the background (a few
seconds).

### Privacy checklist

The Privacy page scores Windows settings that decide how much the PC shares:
advertising ID, optional diagnostic data, tailored experiences, the language list
websites can read, app-launch tracking, suggested content and Start suggestions,
online speech recognition, inking and typing personalisation, web results and cloud
content in search, and location, camera and microphone access. More important
settings weigh more; camera, microphone and feedback frequency are shown for
information only. Windows 11 reads "Recommendations in Start" where Windows 10 reads
"Suggestions in Start".

Each item links to its Settings page, and most also have a button (**Turn off**,
**Block apps**, **Never ask**, and the matching button to undo it) that switches the
setting directly. These are per-user settings: Phalanx writes the same values the
Settings page writes, under your account, with no administrator rights. A switch is
not offered where a policy or a device-wide setting decides instead. Two items need
an administrator: optional diagnostic data (a system-wide setting) and **web results
in Start search**, for which Windows Settings has no switch and current Windows
versions ignore the old per-user value; Phalanx sets the search box policy Windows
reads, after showing the command and Windows' prompt (it takes effect after you sign
out and back in).

### AI inspection (Google Gemini)

Pick a file on the **AI Inspect** page (or drop one onto it, or use **Inspect with
AI** on a scan result or folder-protection alert). The file is first examined on
this PC, and the page lists exactly what will be sent before you press **Inspect
with Gemini**:

* **Scripts and other text files**: their text, up to a limit (256 KB by default),
  plus name, size, type, SHA-256, download origin and the local scan result.
* **Programs and other binaries are never uploaded.** Only facts extracted locally
  are sent: PE sections, imports, signature presence and heuristic score, ZIP entry
  names, and readable strings.

Gemini returns a verdict (likely safe, suspicious, likely malicious or could not
tell), a confidence, the behaviours it found with the evidence for each, and what to
do. The file is treated as untrusted: the prompt tells the model to ignore
instructions inside it, and to flag text that tries to influence the verdict.
Treat the result as advice: AI can be wrong or misled, and a local detection
always outranks a "likely safe" verdict. You can quarantine the file from the
result.

Set it up under **Settings > AI inspection**: turn it on, paste a free API key from
[Google AI Studio](https://aistudio.google.com/apikey), and optionally use **Test
connection** to list the models your key can use (default `gemini-flash-latest`).
The key is stored encrypted with Windows DPAPI, so only your account on this PC can
read it; the `GEMINI_API_KEY` environment variable is used when no key is saved.
On Gemini's free tier Google may use what you send to improve its products, so do
not inspect files that contain personal or confidential information.

### Scan performance

| Setting | Threads (8-core PC) | Priority | 468 MB test folder, 5,151 rules |
| --- | --- | --- | --- |
| Low impact (default) | 2 | background | 24.5 s |
| Balanced | 4 | background | 11.5 s |
| Fast | 8 | normal | 6.9 s |

The single-threaded version took 37.8 s on the same folder. Total CPU work is
about the same at every level (46 to 52 s); higher levels finish sooner by using
more cores at once. Peak memory was 300 to 380 MB.

## Command line

The command-line tool is `phalanx-cli.exe`.

```
phalanx-cli scan C:\Users\me\Downloads               # report only
phalanx-cli scan C:\Users\me\Downloads --quarantine  # isolate malware/pup/hacktool
phalanx-cli scan D:\stuff --quarantine-suspicious    # also isolate heuristic hits
phalanx-cli scan . --json                            # machine-readable report
phalanx-cli scan . --rules my-rules\ --hashes bad.txt
phalanx-cli scan D:\ --performance low-impact --exclude D:\VMs
phalanx-cli watch %USERPROFILE%\Downloads --notify   # watch until Ctrl+C
phalanx-cli watch %USERPROFILE%\Downloads --programs # also scan programs as they start
phalanx-cli watch --programs --report-only           # programs only; never stop them

phalanx-cli history [--kind watch]   # recent scans with full details (kinds: watch, process, ...)
phalanx-cli detections       # recent detections
phalanx-cli summary          # per-month totals
phalanx-cli quarantine list
phalanx-cli quarantine restore <ID> [--force]
phalanx-cli quarantine delete <ID>
phalanx-cli update [--check|--force]  # download feeds that changed
phalanx-cli info             # rule/hash counts, last update, data folder
phalanx-cli status [--json]  # Windows protection status and privacy checklist
phalanx-cli audit [--exclusions]       # stealer and persistence check (read-only)
phalanx-cli browsers [--offline]       # browser updates and hardening (read-only)
phalanx-cli inspect FILE --dry-run   # show what AI inspection would send
phalanx-cli inspect FILE             # ask Gemini (needs GEMINI_API_KEY)

phalanx-cli web check example.com https://x.example/a.exe [--resolve]
phalanx-cli web status               # mode, rule counts, connected browsers, DNS filter
phalanx-cli web mode block|report-only|off
phalanx-cli web ads on|off           # ad and tracker blocking (off by default)
phalanx-cli web allow SITE | block SITE | forget SITE
phalanx-cli web events               # recent blocks
phalanx-cli web connect              # register Browser Guard's connector, write the extension
phalanx-cli web disconnect
phalanx-cli web serve [--listen 127.0.0.1:53] [--upstream 9.9.9.9] [--report-only]
phalanx-cli web extensions [--all]   # risky or malicious browser extensions
phalanx-cli web remove-extension --browser "Google Chrome" --profile Default ID
phalanx-cli web restore-extension BACKUP_FOLDER
```

Use `blocktest.phalanx.invalid` (malware) and `phishtest.phalanx.invalid` (phishing)
to test web protection. These names never exist on the internet.

Exit codes: `0` clean, `1` detections found, `2` error. For `inspect`, `1` means
any verdict other than likely safe. For `update`, `2` means at
least one source failed and kept its previous version.

Data lives in `%LOCALAPPDATA%\threat-scanner` (the name it had before it became Phalanx): the history database, quarantine and
downloaded signatures. Use `--data-dir` to change it. Scans skip this folder.

## Updating signatures

**Updates are automatic.** By default the app checks the feeds every 4 hours (set
1, 4, 12 or 24 hours, or turn it off, under Settings > Signatures). It also checks
while it is hidden in the tray. A check is a few small `HEAD` requests that ask each
feed whether it changed since the copy you have (`ETag` / `Last-Modified`). Only
feeds that changed are downloaded. Then the engine is recompiled and web protection
reloads its rules: Browser Guard and the DNS filter pick up new malicious sites
without a restart. You can also click **Update now** (Dashboard or Settings), or
**Check now** in Settings, or run:

```
phalanx-cli update            # download feeds that changed
phalanx-cli update --check    # only report which feeds have new data
phalanx-cli update --force    # download everything again
phalanx-cli update --set-key <KEY>   # save your abuse.ch Auth-Key (`none` removes it)
```

The feeds are:

| Source | What | Licence | Needs |
| --- | --- | --- | --- |
| [YARA Forge](https://github.com/YARAHQ/yara-forge) core package | about 5,100 curated YARA rules | varies per rule (see each rule's `license_url`) | nothing |
| [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) URLhaus host list | malware-distribution hosts from URLhaus, republished twice a day (web protection) | CC0 | nothing |
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) base list | ad, tracker and adware names (used only when ad blocking is on) | MIT | nothing |
| [MalwareBazaar](https://bazaar.abuse.ch/) recent samples | SHA-256 hashes with malware family names | CC0 | abuse.ch Auth-Key |
| [ThreatFox](https://threatfox.abuse.ch/) indicators of the last 7 days | SHA-256 hashes; malware domains, URLs and command-and-control addresses (addresses only at confidence 75 or more) | CC0 | abuse.ch Auth-Key |
| [URLhaus](https://urlhaus.abuse.ch/) URLs of the last 30 days | malware download links (web protection) | CC0 | abuse.ch Auth-Key |
| [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (medium) | about 620,000 malware, phishing and scam domains merged from many feeds (web protection) | GPL-3.0 | nothing |
| [malware-filter](https://gitlab.com/malware-filter/phishing-filter) phishing host list | phishing hosts from OpenPhish, PhishTank and IPThreat (web protection) | CC0 | nothing |
| [CERT Polska](https://cert.pl/en/warning-list/) warning list | phishing and scam domains checked by CERT Polska's analysts (web protection) | free to use | nothing |

**abuse.ch Auth-Key.** Since mid-2025 abuse.ch (MalwareBazaar, ThreatFox, URLhaus)
only serves its data to callers with a free personal Auth-Key; requests without
one fail with HTTP 401. Get a key at [auth.abuse.ch](https://auth.abuse.ch/)
(sign in with a GitHub, Google or Microsoft account) and paste it under
Settings > Signatures, or run `phalanx-cli update --set-key <KEY>`. It is stored
encrypted for your Windows account (DPAPI), never in plain text. The
`ABUSE_CH_AUTH_KEY` environment variable is used when no key is saved. Without a
key, those three feeds are shown as **skipped** (not failed), and the other feeds
still update; the known-bad hash list then only grows once a key is added.

How updates work:

* **Validated before use.** Each download is checked first: rules must compile, and
  a hash feed must contain hashes. Only then does it atomically replace the local
  copy. A source that fails keeps its previous version, so an update never leaves
  you worse off.
* **ThreatFox is asked through its API** (no `HEAD` check is possible), at most
  every 6 hours during automatic checks.
* **Hash feeds accumulate.** abuse.ch publishes a rolling window of recent samples,
  so each update merges new hashes into `signatures/feed-hashes.txt`. The list is
  capped at 750,000 entries, oldest dropped first. Update regularly to build up
  coverage.
* **Domain lists replace their own names.** The HaGeZi, phishing and CERT Polska
  lists are full snapshots, so each changed download replaces the names that list
  added to `signatures/feed-web.txt`; names it dropped (often fixed false positives)
  stop being blocked. A download with fewer than 1,000 names is treated as broken,
  and the previous names are kept. The merged web feed is capped at 1,000,000
  rules, oldest dropped first.
* **The ad list is replaced, not merged.** Names its maintainers drop are usually
  false positives, so each changed download replaces `signatures/feed-ads.txt`. A
  download with fewer than 1,000 names is treated as broken, and the previous list
  is kept. The ad list is downloaded even while ad blocking is off (about 2 MB, and
  only when it changed), so turning it on works straight away. The scanner never
  reads it as a hash list.
* **Downloaded rules are stored encoded** (`*.rules`). Plaintext signature
  collections are flagged by other antivirus products. Windows Defender reported a
  plaintext compiled copy as `Trojan:JS/Webshell`.
* **Categories for public rules.** These rules carry no `category` meta, so it is
  derived from the rule name (`HKTL_` → hacktool, `PUA_` → pup, `SUSP_` →
  suspicious). Otherwise a YARA Forge `score` of 75 or more → malware, and anything
  else is suspicious.

Compiling about 5,000 rules takes about 2 to 3 seconds. The desktop app does this
once in the background and reuses the result for every scan. Each CLI command pays
this cost at startup. Use `--no-feeds` to skip downloaded signatures.

## Testing safely

The rules include a harmless marker for end-to-end tests. Use a file containing the
uppercase text `threat-scanner-test-marker-7f3a`. The industry-standard EICAR test
file is also detected, but your installed antivirus will probably remove it first.

## Adding your own signatures (command line only)

The app only uses the bundled and downloaded signatures. For your own, pass them to
`phalanx-cli` scans with `--rules <file or folder>` and `--hashes <file>`:

* Hash lists use `<sha256> [<category>] [<threat name>]`, one per line. Plain
  one-hash-per-line exports work too; the category defaults to `malware`.
  Categories are `malware`, `pup`, `hacktool` and `suspicious`.
* YARA rules can set `meta: threat = "..."` and `category = "..."`. Without them,
  the category is derived as described above.
* Keep your own rule folder and hash file outside the scanned folders (or exclude
  them): they contain the patterns they detect. The built-in rules use hex and
  `\xHH` escapes for the same reason.

## Limitations

* Real-time protection runs in user mode, without a kernel driver, so nothing is
  intercepted *before* it happens. Files are scanned after they land in watched
  folders (not on every open elsewhere on the disk). Programs are checked as soon
  as Windows reports them started and stopped if they are known malware, but a
  program can act before that, and one that exits within moments is only scanned
  afterwards. DLLs are checked for side-loading only, not scanned as they load;
  scripts run in memory (AMSI) and process memory are not scanned. The service
  cannot be stopped by malware running as the user, but malware with administrator
  rights can stop it.
* Without administrator rights, programs running as administrator cannot be
  stopped; the detection still reports them.
* Coverage is only as good as the feeds. YARA Forge core is tuned for low false
  positives rather than maximum coverage, and hash feeds only catch exact copies of
  known samples.
* Archives are not unpacked. Files larger than `--max-size-mb` (default 100) are skipped.
* Launching the app again while it runs only brings it to the front; paths passed
  to that second launch are not scanned.
* Clicking a notification does not open the app.
* AI inspection sees a binary only through extracted facts, so packed or
  obfuscated programs often get "could not tell".
* Web protection has no network driver. Programs that do not use Windows' resolver,
  or that connect straight to an IP address, are only caught by Browser Guard (in
  the browser). The DNS filter runs only while the app is open, and only after you
  point Windows' DNS at it.
* Browser Guard is loaded unpacked (Developer mode). Firefox removes temporary
  add-ons when it restarts. The connector uses the default data folder, whatever
  `--data-dir` says.
* Web protection only blocks names and addresses on a list. New phishing and
  fake-download sites are often unlisted for their first days.
