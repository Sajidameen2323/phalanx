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
- **Next:** milestone 2, in `programs` (`src/rtp/mod.rs`).
