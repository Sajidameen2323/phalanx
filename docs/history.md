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
- **Milestone 2: built (2026-10-28); the page itself not yet tried by hand.**
  - `Store::history(&HistoryQuery) -> HistoryPage`: newest first, below a
    cursor (`before`, a scan id), with kinds, threats only, `since` and text.
    Text is matched, ignoring case, in what was scanned and in each finding's
    path and threat name; `%`, `_` and `\` match only themselves. One fixed
    statement (`prepare_cached`) serves every query: each filter switches
    itself off when its parameter is empty. `MAX_HISTORY_PAGE` is 500.
  - `Request::History { query }` → `replies::History`; in the contract test
    (now 27 requests). `RecentScans` stays for older callers.
  - `phalanx-cli service history` takes `--search`, `--kind` (repeatable),
    `--threats-only`, `--days`, `--before` and says how to get the next page.
  - App: the History page has filter chips (All, Threats found, Manual scans,
    Real-time protection, Suspicious commands, DLL side-loading), a time range
    (any, 24 hours, 7 days, 30 days) and a search box that runs 0.4 s after
    typing stops (or on Enter); 50 rows a page with **Load more**. A reply to
    an older query is dropped (`HistoryView::generation`). `refresh()` after
    a scan reloads as many rows as are shown, so a long list stays long, and
    keeps open details open. The dashboard's two uses of the old 300-scan list
    have queries of their own: the last week's threats and the last manual
    scan.
  - Measured (`a_hundred_thousand_entries_page_and_search_quickly`, release):
    first page 0.3 ms, a deep page 10 ms, threats only 0.5 ms, one kind
    0.2 ms, text search 52–58 ms over 100,000 scans. The plan's 200 ms is met.
    Debug builds only print the times.
  - Tried end to end with `phalanx-service --console` on a private pipe and
    300 test scans: paging, search (with `_`), kind, days and "No scans
    match" all as expected from the CLI. Start the console service from
    PowerShell: Git Bash rewrites `\\.\pipe\…` to `\.\pipe\…`.
- **Page seen in the app (2026-10-28)** against the console service: filter
  and time-range chips, badges and Show details render as intended. The
  search box sits a little shorter than the chips beside it (cosmetic).
- **Milestone 3: built (2026-10-28); the Settings card not yet seen in the
  app, and the daily upkeep not yet seen running in the installed service.**
  - Settings: `ProtectionSettings::history_days` (365) and
    `clean_history_days` (30), 0 for good. Keeping either for less time
    weakens protection (`weakened_by`: "keeps history for 90 days instead of
    365 days"), so it needs an administrator; longer or "Always" does not.
  - `Store::prune(Retention, now)`: in one transaction, everything older
    than `history_days`, and `watch`/`process` scans that found nothing older
    than `clean_days` (`CLEAN_KINDS`), are first added per month to the new
    `PrunedTotals` table, then removed with their detections and errors.
    `monthly_summary` adds `PrunedTotals` back, so no month's figures change.
    Quarantine records are never removed. `Store::compact` runs `VACUUM` and
    truncates the write-ahead log.
  - `service/history.rs`: `upkeep` prunes when a day has passed and compacts
    when a month has (stamps in `history-upkeep.json`); `schedule` runs it
    2 minutes after the service starts, then checks hourly, in background
    mode. A failed compaction (a writer in the way) is tried at the next
    check. `Request::HistoryInfo` → `replies::HistoryInfo` (size on disk with
    the WAL, scans, oldest, last prune and how many it removed, last
    compaction); in the contract test (now 28 requests).
  - App: Settings > General has a **History** card above Data: "Keep
    history" (90 days, 1 year, 2 years, Always), "Keep routine checks" (7,
    30, 90 days, Always), and the size, entries, oldest and last tidy-up,
    read with `refresh()`.
  - Tests: `retention_keeps_what_it_should_and_the_monthly_totals` (410 days
    of 200 clean checks plus a finding, a manual scan and a command a day:
    83,230 scans down to exactly 7,095; every month's totals identical; no
    orphaned detections; quarantine untouched; a second prune removes
    nothing; compacted, **1.0 MB**, against the plan's 50 MB);
    `upkeep_prunes_once_a_day_and_compacts_once_a_month`; the settings test
    covers both shortenings and that lengthening asks nothing.
- **Milestone 4: built (2026-10-28); the page's new controls and the app's
  elevated delete not yet tried by hand.**
  - Reviews: a `Reviews` table, one row per finding (verdict `reviewed` or
    `false_positive`, note, when, by whom); `DetectionRow::review` (from
    `scan_detections` and `recent_detections`). `Store::review` marks,
    replaces or (with `None`) clears, and refuses an unknown finding.
    `Request::ReviewFinding` (anyone: a label changes no protection) records
    `by` as the caller the pipe identified, never a name the client sends.
  - Delete: `Store::delete_history(DeleteTarget)`, either chosen scans or
    everything a `HistoryQuery` matches on every page; the scans go with their
    findings, reviews and errors, and (unlike retention) leave the monthly
    totals; quarantine stays. `Request::DeleteHistory` is administrators
    only. `remove_marked` is shared with `prune`, which now also removes
    reviews with their findings (the foreign key would refuse otherwise).
  - `HistoryPage::matching` counts every scan the query matches; the
    filter is one `HISTORY_FILTER` string shared by paging, counting and
    deleting.
  - CLI: `service history --findings` lists findings with their numbers and
    marks; `service review N --false-positive|--reviewed|--clear --note`;
    `service delete-history --scan N…` or `--all-matching` with history's
    filters, and a hidden `--json` (hex) the app uses, so search text is
    never misread on the elevated command line.
  - App: each finding in Show details has **Mark reviewed**, **Not a
    threat** (a note, then Save) and **Clear mark**, and shows its mark
    (NOT A THREAT / REVIEWED, note, who, when). Each entry has **Delete…**;
    above the list, "N entries" and **Delete these…** for everything the
    current filter matches. Both ask first (a dialog naming what goes), then
    Windows' prompt.
  - Tests: `findings_are_marked_changed_and_cleared`,
    `history_is_deleted_by_choice_or_by_filter`,
    `pruning_takes_reviews_with_their_findings`; the contract test marks a
    finding and checks the reviewer is the caller, and deletes by filter and
    by choice (now 30 requests); deleting is administrators only and marking
    is not (`weakening_needs_an_administrator`).
  - Tried through a console service: findings listed, marked (as
    `DESKTOP-8Q8S8UH\Sajid`), shown, cleared; a normal user's delete refused
    for approval. The refusal says "this weakens protection", the generic
    approval text.
- **Milestone 5: built (2026-10-28); the app's Export… not yet tried by hand.**
  - `Store::export(&HistoryQuery) -> Vec<ExportRow>`: every scan the filter
    matches on all pages (at most `MAX_EXPORT`, 100,000), newest first, one
    row per finding with its mark; a scan that found nothing is one row with
    the finding columns empty.
  - `export_csv` and `export_json` format the rows, the same for the app and
    the CLI. CSV has a header, CRLF lines, quoting for commas, quotes and
    new lines, and a leading `'` on a cell that starts like a spreadsheet
    formula (`=`, `+`, `-`, `@`, tab, CR): file and threat names come from
    what was scanned, so they must not run in Excel.
  - `Request::ExportHistory { query }` → `replies::ExportHistory` (anyone,
    like reading history; in the contract test, now 31 requests). The
    service only sends rows: it runs as SYSTEM and writes no file a client
    names. The app and `phalanx-cli` write the file as the user.
  - CLI: `service history --export FILE` with history's filters (CSV, or JSON
    for a `.json` name). App: **Export…** beside the entry count opens a save
    dialog (CSV or JSON, named `phalanx-history-<date>`) for what the current
    filter and search match. `App::history_filter` is shared with **Delete
    these…**.
  - Test `export_has_a_row_per_finding_with_its_mark` (rows, marks, filters,
    the formula guard, quoting, JSON back as sent). Tried through a console
    service: 20 threat rows to CSV with a mark and its reviewer, 38
    side-loading rows to JSON.
- **Milestone 6: done (2026-10-28).**
  - Schema version in `PRAGMA user_version` (`store::SCHEMA_VERSION`, 2:
    0 the first release, 1 Scans' later columns, 2 `Reviews` and
    `PrunedTotals`). Opening any older database brings it up to date and
    sets the number; a database a newer Phalanx wrote keeps its number.
  - `Store::check_file`: SQLite's full `integrity_check` of a file opened
    read-only. `service::history::check_at_start` runs it in
    `service::start` before anything opens the database; a damaged one is
    renamed `history.damaged-<time>.sqlite` (with its `-wal` and `-shm`),
    never deleted, and `history.backup.sqlite` takes its place if it passes
    the same check; otherwise history starts empty. What happened is kept in
    `history-upkeep.json` and reported in `HistoryInfo::recovered`.
  - Daily backup with the prune: `quick_check` first (a damaged database
    never replaces a good backup), then `VACUUM INTO` a `.part` file renamed
    over the backup, so an interrupted backup never replaces a good one.
  - App: Settings' History card adds "checked … · backed up …" and, after a
    recovery, an amber note saying what happened and where the damaged file
    is; a recovery in the last week is also put in the activity log once.
  - Limit: a restored backup is up to a day old, so quarantine records from
    that day are missing (the files stay in the quarantine folder).
  - Tests: `a_damaged_database_is_replaced_by_the_last_backup` (the scan
    after the backup is gone, the rest is there, the damaged file is kept),
    `a_damaged_database_without_a_backup_starts_history_empty`,
    `a_newer_database_keeps_its_schema_version`,
    `the_file_check_finds_a_damaged_page` (the header intact, a data page
    overwritten; an early page can be an empty table's root with nothing to
    find, so the test damages the last page), and the upgrade test checks
    the version.
  - Tried with a console service: the first upkeep made the backup; with
    the live database's first 100 bytes overwritten and the service started
    again, it reported "file is not a database", kept the damaged file,
    restored the backup, and history answered with all its entries.

## Step 7 is done

All six milestones are built and tested; the plan's "done when" holds:
100,000 entries page and search in under 60 ms (200 ms allowed), a year
of heavy use takes about 1 MB after retention (50 MB allowed), and every
ipc reply (31 requests) has a round-trip contract test. Seen in the app:
paging, filters, details, deleting an entry. Not yet seen by hand: the
Settings History card, marking findings, Export…, and the daily upkeep in
an installed service.
