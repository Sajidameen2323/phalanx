# Phalanx

<img src="assets/phalanx.png" width="96" alt="Phalanx emblem">

An on-demand malware scanner written in Rust. It is an original implementation; it
contains no Malwarebytes code or signatures.

Detection layers, in order:

1. **Hash blocklist**: exact SHA-256 matches (`rules/hashes.txt` plus `--hashes FILE`).
2. **YARA rules**: pattern rules run by [YARA-X](https://github.com/VirusTotal/yara-x)
   (`rules/default.yar` plus `--rules PATH`).
3. **PE heuristics**: scores Windows executables for packing (section entropy, packer
   section names), writable+executable code, injection/hollowing/keylogging API
   combinations and runtime API resolution. A score of 60 or more is reported as
   `suspicious`. Heuristics never report `malware`.

Results are recorded in a local SQLite history. Detections can be moved into a
reversible quarantine.

## Build

```
cargo build --release
```

This produces `target\release\phalanx.exe` (the app) and `phalanx-cli.exe`. With the
GNU toolchain, `build.rs` embeds the Phalanx icon and version information using
`windres` (set `WINDRES` to use another one); without it the build still succeeds,
without the icon. The icon assets in `assets/` come from the Phalanx logo: `phalanx-logo.png`
and `phalanx-wordmark.png` (transparent, for dark backgrounds), their `-dark`
versions (for light backgrounds), `phalanx-emblem.png` (the shield alone), and the
app icon `phalanx.ico` / `phalanx.png` with the emblem on a dark tile so it stays
readable on light taskbars and toolbars.

The first build takes several minutes, mostly compiling YARA-X's WebAssembly JIT.

## Desktop app

```
target\release\phalanx.exe            # open the app
target\release\phalanx.exe D:\folder  # open and scan immediately
```

The app has these pages:

* **Dashboard**: status (including threats that folder protection found but did not
  remove), signature updates, monthly totals, and scan buttons. You can drop files
  onto the window to scan them.
* **Scan**: choose a **quick scan** (Downloads, Desktop, Documents, temp), a **full
  scan** (every file on the internal drives) or a **custom scan** (folders or
  files you pick); then live progress with a cancel button, and the detections.
  Select detections and quarantine them.
* **Protection**: a read-only **Windows protection status** card (see below), and
  folder watching. New files in watched folders (for example Downloads) are scanned
  automatically and you get a Windows notification for each threat.
* **Web protection**: block malware and phishing sites in your browsers (Browser
  Guard) and for the whole PC (DNS filter), check a site, manage allowed and
  blocked sites, and find dangerous browser extensions (see below).
* **AI Inspect**: ask Google Gemini whether a file looks safe (see below).
* **Privacy**: a read-only privacy checklist with a score (see below).
* **Quarantine**: restore or permanently delete isolated files.
* **History**: every scan with its type, duration, files, data, threads, skipped
  and unreadable files, quarantined files and signature date. Expand a scan to see
  its detections and errors. You can filter by manual scans or folder protection.
* **Settings**, in tabs: **General** (startup, tray, notifications, data folder),
  **Scanning** (performance, detection, quarantine), **Exclusions**, **Signatures**
  and **AI inspection**.

Layouts adapt to the window size: tiles reflow, button rows wrap, and long paths
show the file name first.

### Folder protection

* **Scans finished downloads only.** A file is scanned once it has *settled*: no
  changes and an unchanged size for 3 seconds. Partial downloads (`.crdownload`,
  `.part`, `.tmp`…) are ignored until they are renamed to their final name.
* **Light on resources.** It runs on one thread at Windows *background priority*
  (lower CPU, disk and memory priority), so the PC stays responsive.
* **Catches up.** Files that arrived while the app was closed are scanned the next
  time it starts.
* **Keeps running when closed.** Closing the window keeps it running in the tray.
  Right-click the tray icon and choose **Quit** to stop it.
* **Start with Windows.** This setting adds a per-user sign-in entry
  (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, no administrator rights
  needed). It starts the app hidden in
  the tray with protection on.
* **One copy at a time.** Launching it again brings the running window to the front.
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
browser with **Load unpacked** (Developer mode).

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
exactly what was saved (automatic from the router, or the servers you had).
Browsers with "secure DNS" (DNS over HTTPS) turned on bypass the filter, but Browser
Guard still covers them.

**Browser hardening.** The Web protection page also checks each Chromium browser
and profile, read-only: whether an update is downloaded but waiting for a restart
(the browser keeps `new_chrome.exe` until then) and whether a newer stable release
exists (from Google's and Microsoft's public version feeds; nothing about the PC is
sent), Safe Browsing (standard or enhanced), the JavaScript optimizer (turning it off
removes the part of the browser most zero-day exploits target), secure DNS, whether
Browser Guard is installed, and how many passwords the profile stores (rows are
counted from a copy of the database; nothing is read or decrypted). Each item links
to the browser's own setting. `phalanx-cli browsers` prints the same.

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

The Protection page checks, without changing anything: real-time antivirus
(Microsoft Defender or another registered product), tamper protection,
cloud-delivered protection, potentially unwanted app blocking, SmartScreen (Check
apps and files), Smart App Control, memory integrity, firewall profiles, controlled
folder access, User Account Control and whether file extensions are shown. Each
check says what it read and links to the Windows Security or Settings page where you
can change it. **Network protection** (Microsoft Defender blocking connections to
malicious sites for every program, inside Windows' network stack) is checked too.
Network protection, potentially unwanted app blocking and cloud-delivered protection
have a **Turn on** button when they are off: it shows the exact `Set-MpPreference`
command and runs it as administrator only after you confirm and approve Windows'
prompt, then reads the setting again (some Windows editions accept the command
without the setting changing; the page says so). **Run offline scan** starts a
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
information only. It only reads the registry, and links each item to its Settings
page.

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

phalanx-cli history [--kind watch]   # recent scans with full details
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
```

The feeds are:

| Source | What | Licence |
| --- | --- | --- |
| [YARA Forge](https://github.com/YARAHQ/yara-forge) core package | about 5,100 curated YARA rules | varies per rule (see each rule's `license_url`) |
| [MalwareBazaar](https://bazaar.abuse.ch/) recent samples | SHA-256 hashes with malware family names | CC0 |
| [ThreatFox](https://threatfox.abuse.ch/) recent SHA-256 IOCs | SHA-256 hashes with malware family names | CC0 |
| [URLhaus](https://urlhaus.abuse.ch/) host file and online URLs | malware-distribution hosts and download links (web protection) | CC0 |
| [ThreatFox](https://threatfox.abuse.ch/) recent domains, URLs and C2 addresses | malware sites and command-and-control servers (web protection; addresses only at confidence 75 or more) | CC0 |
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) base list | ad, tracker and adware names (used only when ad blocking is on) | MIT |

How updates work:

* **Validated before use.** Each download is checked first: rules must compile, and
  a hash feed must contain hashes. Only then does it atomically replace the local
  copy. A source that fails keeps its previous version, so an update never leaves
  you worse off.
* **Hash feeds accumulate.** abuse.ch publishes a rolling window of recent samples,
  so each update merges new hashes into `signatures/feed-hashes.txt`. The list is
  capped at 750,000 entries, oldest dropped first. Update regularly to build up
  coverage.
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

## Adding your own signatures

* Hash lists use `<sha256> [<category>] [<threat name>]`, one per line. Plain
  one-hash-per-line exports work too; the category defaults to `malware`.
  Categories are `malware`, `pup`, `hacktool` and `suspicious`.
* YARA rules can set `meta: threat = "..."` and `category = "..."`. Without them,
  the category is derived as described above.
* Your own rule folder and hash file are never scanned, because they contain the
  patterns they detect. The built-in rules use hex and `\xHH` escapes for the same
  reason.

## Limitations

* Folder protection is not antivirus real-time protection. It scans files *after*
  they land in watched folders and cannot block a program from running. There is
  no kernel driver and no memory scanning.
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
* Phishing coverage depends on the feeds. The bundled ones (URLhaus, ThreatFox) are
  mostly malware distribution and command-and-control.
