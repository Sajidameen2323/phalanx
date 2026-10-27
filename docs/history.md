# Step 7 design: History people can manage

Step 7 of [next-plan.md](next-plan.md). This file is also the progress log:
each milestone says what is built, where, and what is left, so the work can be
picked up from here.

## Why

History is the record of what Phalanx saw and did. The app loads only the
latest 300 entries, nothing can be found, removed or exported, every real-time
batch adds a row, so the database only grows, and History's "Show details" was
broken through 0.5.x because the service and the app disagreed on a reply's
shape.

## Milestones

Each one ends with the tests passing.

1. **Contract tests.** Every reply's type is named once, the service builds
   with it, clients read with it, and a test checks each one through its wire
   form.
2. **Paging and search.** `RecentScans` takes a cursor and a filter (text in
   the file or threat, kind, date range, threats only); the History page loads
   pages as it scrolls; new filter chips for threats only, commands,
   side-loading and web blocks.
3. **Retention.** Detections and manual scans kept a year, clean real-time
   batches 30 days (settings, changeable; shortening needs an administrator);
   the service prunes daily and compacts (`VACUUM`) monthly; Settings shows
   the database's size.
4. **Review and delete.** A finding can be marked reviewed or a false positive,
   with a note; deleting entries, one or by filter, needs an administrator.
5. **Export.** CSV and JSON of the current view, from the page and from
   `phalanx-cli service history --export`.
6. **Integrity.** A schema version with migrations; `PRAGMA integrity_check`
   when the service starts, with a backup copy restored if it fails.

**Done when** (from the plan): 100,000 entries page and search in under
200 ms, retention keeps the database under 50 MB, and every ipc reply has a
round-trip test.

## Progress

- **Milestone 1: done (2026-10-28).**
  - `ipc::replies` names the reply type of every request (26), with two new
    structs for replies that were untyped JSON: `ScanStarted { job }` (`Scan`)
    and `SiteChanged { site, settings }` (`ChangeSite`).
  - The service builds every reply as `reply::<replies::X>(…)`, so it cannot
    send another type without a compile error; no untyped `json!` replies are
    left. The app, `phalanx-cli` and the browser connector read through the
    same names wherever they use a reply's data.
  - `service::tests::every_reply_reads_back_as_its_named_type` sends every
    request through `handle` as an administrator (so admin-only requests are
    covered without elevation), through JSON both ways as on the pipe, and
    reads each reply as its type. `contract` has no catch-all, so a new
    request does not compile without a contract, and `REQUEST_KINDS` (26)
    fails the test until the new request is sent. `UpdateSignatures` is not
    sent (it would download every feed); its type is checked by the compiler.
    Checked by breaking a reply on purpose (`#[serde(skip_serializing)]` on
    `ScanStarted::job`): the test fails with "missing field `job`".
  - `Context::new` builds the service's parts without the pipe, for
    `service::start` and the test.
  - **Bug found by the test, fixed:** opening the history database from
    several threads at once while it was being created failed straight away
    with "database is locked" (5 of 8 threads), in spite of the 15 s busy
    timeout: switching a new database to WAL takes it over, and SQLite refuses
    rather than waits. The service's real-time threads do exactly that on a
    fresh install. `Store::open` now retries its setup for up to the busy
    timeout (also when two connections add the same new column).
    `store::tests::a_new_database_opens_from_many_threads_at_once`.
  - The contract test scans at normal priority: in background mode a scan can
    wait out a busy parallel test run.
- **Next:** milestone 2, paging and search (`Store::recent_scans`,
  `Request::RecentScans`, the History page in `src/gui/pages.rs`).
