# Phase 4a design: process and image-load events from ETW

Step 2 of [next-plan.md](next-plan.md), Phase 4a of
[hardening-plan.md](hardening-plan.md). This file is also the progress log:
each milestone says what is built, where, and what is left, so the work can be
picked up from here.

## Why

The program monitor lists running processes twice a second
(`src/rtp/mod.rs`, `programs`). A program that starts and exits between two
lists is never seen, and one that is seen is checked up to half a second late.
Windows reports every process start and every image (DLL) load through ETW, its
event tracing, within milliseconds. A real-time ETW session needs administrator
rights, which the service (SYSTEM) has.

## Design

- **No new crate.** The plan named `ferrisetw`; it pulls in the `windows`
  crate, while Phalanx uses `windows-sys` everywhere. The session is about
  200 lines over `StartTraceW`, `EnableTraceEx2`, `OpenTraceW` and
  `ProcessTrace`, with event fields read by name through TDH
  (`TdhGetProperty`), so changes to an event's layout between Windows
  versions do not matter.
- **Provider:** Microsoft-Windows-Kernel-Process
  (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`), keywords `PROCESS` (0x10) and,
  when side-loading checks are on, `IMAGE` (0x40). Events 1 (process start:
  `ProcessID`, `ParentProcessID`, `CreateTime`, `ImageName`), 2 (process
  stop) and 5 (image load: `ProcessID`, `ImageName`).
- **Flushing:** the session uses a 100 ms flush timer
  (`EVENT_TRACE_USE_MS_FLUSH_TIMER`); the default of a second would undo most
  of the gain.
- **Session name:** one per program (`Phalanx <exe stem>`), so the service and
  an elevated `phalanx-cli watch` do not take each other's session. A session
  of the same name left by a crash is stopped and replaced at start (Windows
  allows only 64 sessions in all, so they must not leak).
- **Paths:** ETW gives NT paths (`\Device\HarddiskVolume3\…`). They are turned
  into drive paths with `QueryDosDeviceW`, refreshed when a volume is not
  found (a new drive); `\Device\Mup\…` becomes a UNC path.
- **Program monitor:** a process-start event becomes a `ProcessInfo` and goes
  to the urgent lane at once (command-line rules first, as now). The process
  list is still read, every 5 s instead of every 0.5 s, to catch anything the
  session lost; a `ProcessId` (pid + creation time) seen either way is checked
  once. If the session cannot start (no administrator rights, or the 64
  sessions are taken), the monitor polls every 0.5 s as before, and says so.
- **Side-loading (milestone 3):** an image load is flagged when the DLL is in a
  folder any user can write to (under a user profile, `ProgramData`, `Temp`,
  `Users\Public`, the root of a drive), is not signed, and the program loading
  it is signed. The DLL also goes to the urgent lane to be scanned. Verdicts are
  cached by `FileKey`, as scans are, since image loads are frequent.
  Report-only at first, like command-line rules.

## Milestones

Each one ends with the tests passing.

1. **The ETW session** (`src/rtp/etw.rs`): start and stop, process start and
   stop events, image loads, NT path conversion. Tests: path conversion
   (everywhere); a live test that a 50 ms process is reported with its parent
   and image (needs administrator rights, skipped otherwise).
2. **The program monitor uses it**, with the 5 s reconcile and the 0.5 s
   fallback. `RtpEvent::Started` and `ProtectionStatus` say whether programs
   are watched through events or polling; the app's Protection page shows it.
3. **Side-loading check**: rule, cache, `RtpEvent` and history entry,
   notification, and the DLL scanned. Test with a signed program next to a
   planted unsigned DLL in a temporary folder.
4. **Release**: README, Protection page and setup's README.txt; version 0.6.0;
   installed test (or lab, see next-plan.md): a 50 ms process is reported
   every time, the side-loading test is flagged, idle CPU of the service is
   measured before and after.

## Progress

- **Milestone 1: built, not yet run live** (`src/rtp/etw.rs`). Start, stop,
  replace-by-name, the three events through TDH, NT path conversion (unit
  tested). The live test (`reports_a_short_lived_process_with_its_parent_and_image`)
  skips without administrator rights, and the dev shell is not elevated: it
  still has to be run elevated once
  (`cargo test --lib rtp::etw -- --nocapture` from an administrator
  terminal; it prints "skipped" if it did not really run). A session left
  over from a crash is stopped by name at start; `Drop` does not stop a
  session that has already ended, since its handle may name another by then.
- **Milestone 2: built, ETW path not yet run live.** `programs`
  (`src/rtp/mod.rs`) starts the session before its first process list,
  takes `etw::Event::Started` to the urgent lane (command-line check first),
  drops `Stopped` processes from its tables, and still reads the list every
  5 s (`PROCESS_RECONCILE`). Without a session it reads the list every 0.5 s
  and tries the session again every 60 s (`EVENTS_RETRY`), quietly. If the
  session ends, it falls back and says so. `RtpConfig::process_events`
  (default on) turns events off. New `RtpEvent::ProgramWatch { events,
  reason }` → `ipc::Event::ProgramWatch`; `ProtectionStatus::program_events`
  (`serde(default)`); the app's Protection page shows "Programs seen: As they
  start (Windows events) / Twice a second (process list)" and logs why when
  it falls back; `phalanx-cli watch --programs` prints it.
  `check_program` now takes `&HashMap<u32, ProcessInfo>` (the monitor's live
  table, which also holds processes known only from events). The rtp tests
  pass here on the polling path; with administrator rights they would take
  the event path.
- **First elevated run (2026-10-25):** the ETW session test passed for real.
  `a_detected_program_is_stopped_and_quarantined` failed on the event path:
  detected and quarantined, but `stopped=0`. The event's `CreateTime` did not
  match what `GetProcessTimes` reads, so `terminate` took the process for
  a reused id and refused. Fixed: a start event now takes the creation time
  from the process itself (`process::identify`) when it is still the same
  program file, and only falls back to the event's; `Stopped` carries only
  the pid (events arrive in order). The ETW test now also checks that a
  running process's id from an event equals its id in the process list and
  can be stopped. **Needs one more elevated run to confirm.** The same run
  showed `a_suspicious_command_line_is_reported_and_left_running` hiding the
  terminal (`start /b` + `-w hidden`); it now uses `start /min`.
- **Known limit:** the Kernel-Process start event has no command line, so it
  is still read from the process; a program that exits before its event
  arrives (about 100 ms) is scanned but its command line is not checked. If
  that matters, the system process provider (Windows 11) carries the command
  line in the event.
- **To verify before milestone 3** (administrator terminal):
  `cargo test --lib rtp:: -- --nocapture`, then
  `phalanx-service --console` with `PHALANX_PIPE` (or `phalanx-cli watch
  --programs`) and check it says programs are seen through process events;
  start `cmd /c exit` repeatedly and see each one checked.
- **Next:** milestone 3, side-loading. `etw::start(…, images: true, …)`
  already delivers `ImageLoaded`; `programs` ignores it for now.
