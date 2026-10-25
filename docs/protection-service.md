# Phase 3 design: the Phalanx protection service

Status: agreed; being built on `feat/protection-service`, milestone by milestone.

## The problem

Everything that protects the PC runs inside `phalanx.exe`, the app the user
signs in with: the engine, real-time protection, the DNS filter and block page,
signature updates, settings, history and quarantine. Its data lives in
`%LOCALAPPDATA%\threat-scanner`, which the user, and therefore any program
running as the user, can change. Malware that runs as the user can today:

- end `phalanx.exe` (it is the user's own process), which stops all protection;
- delete the `HKCU\…\Run` entry, so Phalanx does not start at the next sign-in;
- add its own domains to the allowed sites in `web-protection.json`, or add an
  exclusion, or turn real-time protection off in `gui-settings.json`;
- edit or delete the history and the quarantine.

Phase 3 moves protection into a Windows service that runs as LocalSystem, with
its data where only administrators can change it. Changes that weaken
protection then need an administrator's approval (a UAC prompt), which a
program running as the user cannot give itself.

What this does **not** do: protect against malware that already has
administrator rights. That needs Protected Process Light, which requires an
early-launch anti-malware driver and Microsoft Virus Initiative membership.
The README and Protection page will say so.

## Shape

```
 ┌────────────── LocalSystem ──────────────┐        ┌──── each signed-in user ────┐
 │ phalanx-service.exe                     │        │ phalanx.exe (app + tray)    │
 │  engine (signatures, YARA, heuristics)  │  pipe  │  status, scans, history,    │
 │  real-time protection (all users)       │◀──────▶│  settings, notifications    │
 │  DNS filter + block page                │ \\.\pipe│  AI Inspect, Stealer check, │
 │  signature updates (scheduled)          │ \Phalanx│  browser checks (per user)  │
 │  settings, history, quarantine          │        ├─────────────────────────────┤
 │  %ProgramData%\Phalanx (admins only)    │◀──────▶│ phalanx-cli.exe (browser    │
 └─────────────────────────────────────────┘        │  connector, command line)   │
                                                    └─────────────────────────────┘
```

### Runs in the service

| Part | Notes |
| --- | --- |
| Engine and signature updates | One engine for everyone; updates on a schedule, no user needed. |
| Real-time protection | Folders, programs, command lines, new drives. Programs and command lines are already machine-wide; folders are the configured list, by default each signed-in user's Downloads. The Run-box watcher reads each signed-in user's `HKEY_USERS\<SID>\…\RunMRU`. |
| DNS filter and block page | Runs without anyone signed in, so Windows' DNS never points at a filter that is not there. |
| Scans | Manual scans are asked of the service, which streams progress back. The service can then quarantine anything the user can read. |
| Settings, history, quarantine | The service owns them; the app reads and changes them through the pipe. |

### Stays in the app (per user)

AI Inspect (the Gemini key is encrypted for the user), the Stealer check and
the browser checks and extension removal (they read the user's own registry
and browser profiles), privacy settings, and showing notifications (only a
program in the user's session can). With the app closed, the tray agent (the
same `phalanx.exe --background`, started at every sign-in for every user)
shows them.

### The pipe

A named pipe, `\\.\pipe\Phalanx`, carrying one JSON message per line:
requests from the app or CLI, replies, and events (detections, scan progress,
protection status) to every connected client. Its security descriptor lets
SYSTEM and administrators in fully and interactive users connect.

Every request is authorised by **who asks**, read from the caller's token
(`ImpersonateNamedPipeClient`):

| Request | Who may |
| --- | --- |
| Status, history, events, scan, quarantine a threat, block a site, turn protection on, update signatures | any signed-in user |
| Turn protection or parts of it off, add an exclusion or an allowed site, restore or delete a quarantined file, change web-protection mode, stop the service | an elevated administrator only |

When a user asks for something in the second row, the app runs
`phalanx-cli.exe service approve <request>` with `runas`: Windows shows its
UAC prompt, and the elevated CLI sends the same request as an administrator.
Malware running as the user can ask, but cannot answer the prompt.

The browser connector works the same way: it reads rules from
`%ProgramData%\Phalanx` (users may read it) and sends "block this site" to the
pipe. "Always allow this site" from the warning page becomes a request that
needs approval, or stays a per-tab "Continue this time".

### Data and its permissions

`%ProgramData%\Phalanx`: SYSTEM and Administrators full control; Users read
only (the connector needs the rules); `quarantine\` not readable by Users.

### Self-protection

- Users cannot stop or reconfigure a service (Windows' default service
  permissions); recovery options restart it 3 times after a crash.
- The tray agent warns at once if the service stops or the pipe goes away.
- The service records a clean shutdown; a stop without one is reported as
  protection having been ended.

## Install and upgrade

A service can only be installed by an administrator, so setup becomes a
per-machine install in `Program Files\Phalanx` that asks for administrator
rights once. It:

- installs and starts the service, and sets its recovery options;
- registers the tray agent for every user (`HKLM\…\Run`);
- removes a per-user install of an earlier version;
- moves the installing user's data from `%LOCALAPPDATA%\threat-scanner` to
  `%ProgramData%\Phalanx` on the service's first start (settings, history,
  quarantine, web lists, the DNS backup), leaving the old folder in place;
- on uninstall: restores DNS, stops and deletes the service, and asks about
  the data folder.

## Milestones

Each one ends with the app working and the tests passing.

1. **Service skeleton.** `phalanx-service.exe` on `windows-service`; install,
   start, stop and remove through `phalanx-cli service …`; the pipe with its
   security descriptor and caller check; `status` and `ping`. The app shows
   whether the service is running. *Built (`src/ipc/`, `src/service/`,
   `src/service_main.rs`).* The pipe refuses to share its name; users can
   connect but not add pipe instances; clients only trust a server in
   session 0 and allow it identification, not impersonation.
Everything that writes Phalanx's data (real-time protection, scans,
quarantine, signature updates, web protection, the browser connector) must
move together: once the data is in `%ProgramData%\Phalanx`, only the service
can write it. So the service side is built first, milestone by milestone,
while the app keeps working as before; the app then switches to the service
in one step.

2. **Data and settings, service side.** `%ProgramData%\Phalanx` with its
   permissions; protection settings with the approval rule (weaker needs an
   administrator); history and quarantine through the pipe (restore and
   delete need an administrator); migration from the per-user folder
   (`phalanx-cli service migrate`, administrator). The service does not
   quarantine on request: a user could otherwise have it (as SYSTEM) remove
   files the user cannot. It quarantines what it detects itself, from
   milestone 3. *Built (`src/service/data.rs`, `settings.rs`, `migrate.rs`;
   `phalanx-cli service migrate | history | settings`).* The abuse.ch key
   is migrated readable by administrators only.
3. **Real-time protection, scans and quarantine in the service.** Events
   stream to the app and tray agent, which shows notifications; RunMRU for
   every signed-in user. *Built (`src/service/protect.rs`).* With no folders
   set, every user profile's Downloads is watched. A connection that
   subscribes only carries events from then on (on a synchronous pipe a
   pending read holds up writes), and each subscriber has its own writer
   thread and bounded queue: one that stops reading is dropped, never
   holding up protection. `ProtectionStatus` tells a client that connects
   late where protection is. Quarantine through the pipe moves only what a
   service scan detected and recorded, unchanged since.

   Tested installed. A command typed into Win+R (`cmd /c rem verify you are
   human`) was reported at high confidence by the program monitor, started
   by Explorer. The Run-box watcher saw nothing new because Windows wrote
   nothing: it keeps the Run-box history only while "Track app launches"
   (`Start_TrackProgs`) is on, and Phalanx's own Privacy page recommends
   turning that off. That item now says so. With tracking off, the program
   monitor is what catches these commands; the watcher only adds commands
   that exit before the program monitor looks. `phalanx-cli service run-box`
   (`RunBoxView`, administrators) shows what the watcher reads, as SYSTEM.
   Processes started from a Claude Code session see a different registry
   view than the service, so Run-box tests written from there never reach it.
4. **Signature updates, DNS filter, block page and web settings in the
   service**, and the browser connector through the pipe. *Built
   (`src/service/web.rs`, `updates.rs`).* Web settings follow the same rule
   as protection settings (`WebConfig::weakened_by`): turning checks or the
   DNS filter off, reporting only, allowing or unblocking a site, dropping
   the feeds or ad blocking, and changing where the DNS filter listens or
   forwards need an administrator. The DNS filter keeps serving across
   settings changes and is restarted only when what it listens with
   changes. Updates run on the settings' schedule and reload the engine
   and web rules when anything new arrives. The abuse.ch key is saved by
   the service, encrypted for SYSTEM and readable only by administrators;
   migration passes it decrypted, since the user's copy is encrypted for
   the user. With the service running, the browser connector reads the
   service's folder and sends changes through the pipe; a change that
   needs approval is made by `phalanx-cli` run elevated, after Windows'
   prompt, with only the host name on its command line.
5. **The switch:** the app uses the service for everything above, and asks
   for approval (UAC) for weakening changes. Plan:
   - **The app needs the service.** It runs no protection of its own any
     more (no real-time protection, engine, DNS filter or updates). With the
     service missing or stopped, it says so on every protection page and
     shows what to do; the Stealer check, browser checks, privacy and AI
     Inspect, which are per-user, keep working. This lands together with
     milestone 6 (the installer installs the service): `main` must not get
     an app that needs a service its installer does not install.
   - **Events instead of threads.** The app keeps one subscribed connection
     on a thread of its own; detections, scan progress, updates and web
     blocks arrive there, and notifications are shown from it, so the tray
     agent (the same app, hidden) notifies with no window open.
   - **Settings.** The app's settings file keeps only its own preferences
     (appearance, notifications, tray, AI Inspect). Protection and web
     settings are read from the service at start and whenever it reports
     a change (new `SettingsChanged` and `WebSettingsChanged` events, so a
     change from the CLI or the browser shows at once). The pages still
     edit them in place; a change is sent to the service, and if it needs
     approval the app runs `phalanx-cli service set-settings` (or
     `set-web-settings`) elevated with the settings on its command line, not
     in a file a program could change before the elevated copy reads it.
     Declined: the page shows the service's settings again.
   - **Approval for the rest.** Restoring and deleting quarantined files,
     allowing and unblocking sites, the abuse.ch key and quarantining a file
     that only AI Inspect flagged (new `QuarantineFile`, administrators) run
     the matching `phalanx-cli service …` command elevated. While Windows'
     prompt is up, the page says it is waiting for approval.
   - **Scans, history, quarantine** through the pipe; "Quarantine selected"
     is `QuarantineDetection` for the scan's own detections.
   - **AI Inspect** keeps a read-only engine, loaded from the service's
     signatures when first needed, for its local findings.
   - **Web page:** status, events and rule counts come from the service's
     folder and `WebStatus`; "Use the filter for Windows DNS" keeps its
     backup in the service's folder, where the uninstaller finds it.
   - **Development:** `PHALANX_PIPE` points the app and CLI at a
     `phalanx-service --console` run instead (and lifts the session-0
     check, which only a real service passes).

   *Built (`src/gui/link.rs`; the app's own protection, engine scans,
   updates and DNS filter are gone).* Edits on the pages are sent once
   they have stayed the same for 0.7 s, so a dragged slider or a typed
   field asks (and maybe prompts) once; the DNS listen address gets an
   Apply button for the same reason. The abuse.ch key is saved for the
   user first, then the elevated `phalanx-cli service auth-key --from-app`
   reads it there, so it never goes on a command line. Development pipes
   reach the elevated copy as `--pipe`, since it does not inherit the
   environment. Found while testing against a console service: the
   service held its protection lock while loading signatures, so status
   requests waited (now only applying is serialised); `ScanReport` could
   not be read back from an event (a `u128` field and two `errors` keys),
   so a finished scan never reached the app; `ProtectionStatus` now
   carries the watched-folder count for an app that connects late.
   Pages that show history and quarantine read them again when opened,
   since real-time protection, the command line or another user change
   them too. Tried with Windows' prompt: a weakening change approved
   (saved) and declined (the page shows the service's setting again),
   restoring a quarantined file, and saving the Auth-Key. Windows may
   show the prompt as a flashing taskbar button instead of on top.
6. **Installer** (per machine), upgrade from 0.4.x, tray warning when the
   service is down, README and Protection page. Plan:
   - **Setup asks for administrator rights once** and installs to
     `Program Files\Phalanx`: the app, the CLI and `phalanx-service.exe`.
     It stops the service before replacing files and runs `phalanx-cli
     service install` after (which updates an existing service), with
     its Start-menu shortcut for all users and an `HKLM\…\Run` entry
     that starts the tray agent at every sign-in.
   - **Upgrade from 0.4.x** (a per-user install of the same AppId): the
     installing user's data is migrated (`service migrate`, which also
     carries the abuse.ch key), then the old copy's uninstaller runs
     silently. Its DNS backup is set aside first, so the old uninstaller
     does not undo "Use the filter for Windows DNS": the service's filter
     answers on the same address, and its folder has the backup. The old
     data folder is kept. Browsers are connected again for that user.
   - **Uninstall:** restores Windows' DNS from the service's backup,
     removes the service, disconnects the browsers, and asks about
     `%ProgramData%\Phalanx`.
   - **App:** a Windows notification when the service has been down for a
     while (and when it is back), not for a quick restart; "Start with
     Windows" shows the machine-wide entry instead of a per-user toggle;
     the Data card shows the service's folder; Windows' prompt is given
     the app's window, so it comes up in front. `web restore-dns` looks
     in the service's folder first.
   - **README, setup's README.txt and the Protection page** describe the
     service, approvals and what it does not protect against (malware
     that already has administrator rights).
   - Version 0.5.0.

   *Built (`installer/phalanx.iss`).* Tested by upgrading a real 0.4.1
   install: the data and abuse.ch key came over (the first update in the
   service used the key), the old copy was removed, and the uninstaller
   removed the service and kept the data. Two fixes came from it: a
   browser keeps the old copy's connector running, which held its folder,
   so setup closes it first (Browser Guard starts the new one at its next
   lookup); and Setup named its entry "Phalanx (All users)" because the
   per-user one still existed, so it is renamed once that is gone. Start
   setup from Explorer, not from a sandboxed shell: the "as you" steps
   (connecting browsers, opening the app) run in the shell's session.

   *0.5.1.* The test also showed the uninstaller offering to restore a
   DNS backup Windows no longer used (restoring it would have put back
   settings from an earlier setup). DNS is now restored only while an
   adapter still points at the filter; a stale backup is discarded
   (`web restore-dns --check`). Browsers are not forced off DNS over
   HTTPS by policy (the "Managed by your organization" banner and no
   encrypted DNS for anyone were judged too costly); instead, while
   Windows uses the filter, browser hardening flags a browser whose
   secure DNS uses a provider of its own and so goes around it.

## Testing

- Unit tests for the pipe protocol, request authorisation and migration.
- End-to-end tests that start the service in-process (not installed) on a
  private pipe name, so they run without administrator rights.
- An installed-service test, as administrator, run by hand before release:
  install, kill the app (protection continues), try to stop the service as a
  standard user (refused), change an allowed site without approval (refused),
  upgrade from 0.4.1, uninstall.

## Decisions

1. **Service only.** There is no per-user mode without the service: one way of
   running to build, test and explain. Installing needs administrator rights.
2. **Anything that weakens protection needs approval**, including turning off
   individual checks (command-line rules, checking new drives, scanning inside
   archives), not only the main switches. Strengthening never asks.
3. **Browser Guard's "Always allow this site" asks for approval**, and once
   approved the site is allowed everywhere (all browsers and the DNS filter).
   "Continue this time" for one tab needs no approval.
