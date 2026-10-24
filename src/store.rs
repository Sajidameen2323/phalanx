//! Local SQLite history: scans, detections and quarantine records.

use crate::Finding;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS Scans (
    Id            INTEGER PRIMARY KEY,
    StartedAt     TEXT NOT NULL,
    FinishedAt    TEXT,
    Targets       TEXT NOT NULL,
    FilesScanned  INTEGER NOT NULL DEFAULT 0,
    BytesScanned  INTEGER NOT NULL DEFAULT 0,
    FilesSkipped  INTEGER NOT NULL DEFAULT 0,
    Errors        INTEGER NOT NULL DEFAULT 0,
    Detections    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS Detections (
    Id          INTEGER PRIMARY KEY,
    ScanId      INTEGER NOT NULL REFERENCES Scans(Id),
    DetectedAt  TEXT NOT NULL,
    Path        TEXT NOT NULL,
    Sha256      TEXT NOT NULL,
    Threat      TEXT NOT NULL,
    Category    TEXT NOT NULL,
    Source      TEXT NOT NULL,
    Details     TEXT NOT NULL,
    Action      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS DetectionsByScan ON Detections(ScanId);
CREATE TABLE IF NOT EXISTS Quarantine (
    Id             TEXT PRIMARY KEY,
    OriginalPath   TEXT NOT NULL,
    QuarantinedAt  TEXT NOT NULL,
    Sha256         TEXT NOT NULL,
    Threat         TEXT NOT NULL,
    Size           INTEGER NOT NULL,
    RestoredAt     TEXT
);
CREATE TABLE IF NOT EXISTS ScanErrors (
    Id       INTEGER PRIMARY KEY,
    ScanId   INTEGER NOT NULL REFERENCES Scans(Id),
    Path     TEXT NOT NULL,
    Message  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ScanErrorsByScan ON ScanErrors(ScanId);
";

/// Columns added after the first release; added to existing databases on open.
const SCAN_COLUMNS: &[(&str, &str)] = &[
    ("Kind", "TEXT NOT NULL DEFAULT 'manual'"),
    ("Threads", "INTEGER NOT NULL DEFAULT 1"),
    ("Cancelled", "INTEGER NOT NULL DEFAULT 0"),
    ("Quarantined", "INTEGER NOT NULL DEFAULT 0"),
    ("ElapsedMs", "INTEGER"),
    ("Signatures", "TEXT"),
];

/// Errors kept per scan; the total is still counted in `Scans.Errors`.
pub const MAX_STORED_ERRORS: i64 = 200;

/// What a scan was, recorded when it starts.
#[derive(Debug, Clone)]
pub struct ScanMeta<'a> {
    pub kind: &'a str,
    pub targets: &'a str,
    pub threads: i64,
    /// When the signatures in use were last updated, if known.
    pub signatures: Option<&'a str>,
}

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: i64,
    pub bytes_scanned: i64,
    pub files_skipped: i64,
    pub errors: i64,
    pub detections: i64,
    pub quarantined: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRow {
    pub id: i64,
    pub kind: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub elapsed_ms: Option<i64>,
    pub targets: String,
    pub files_scanned: i64,
    pub bytes_scanned: i64,
    pub files_skipped: i64,
    pub errors: i64,
    pub detections: i64,
    pub quarantined: i64,
    pub threads: i64,
    pub cancelled: bool,
    pub signatures: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanErrorRow {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRow {
    pub id: i64,
    pub scan_id: i64,
    pub detected_at: String,
    pub path: String,
    pub threat: String,
    pub category: String,
    pub source: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRow {
    pub id: String,
    pub original_path: String,
    pub quarantined_at: String,
    pub sha256: String,
    pub threat: String,
    pub size: i64,
    pub restored_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthRow {
    pub month: String,
    pub scans: i64,
    pub files_scanned: i64,
    pub detections: i64,
    pub quarantined: i64,
}

pub fn now() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        // The GUI, a scan and the folder watcher may each hold a connection.
        conn.busy_timeout(std::time::Duration::from_secs(15))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        conn.execute_batch(SCHEMA)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Copies every scan, detection, scan error and quarantine record from
    /// the history database at `other` into this one, which must be empty
    /// (ids are kept). Columns are matched by name, so an older database
    /// with fewer columns imports too. Returns the scans and quarantine
    /// records imported.
    pub fn import(&self, other: &Path) -> Result<(i64, i64)> {
        let count = |table: &str| -> Result<i64> { Ok(self.conn.query_row(&format!("SELECT COUNT(*) FROM main.{table}"), [], |r| r.get(0))?) };
        if count("Scans")? + count("Quarantine")? > 0 {
            anyhow::bail!("the history here is not empty");
        }
        self.conn.execute("ATTACH DATABASE ?1 AS old", [other.display().to_string()])?;
        let imported = (|| -> Result<(i64, i64)> {
            let tx = self.conn.unchecked_transaction()?;
            // Parents before children (foreign keys).
            for table in ["Scans", "Detections", "ScanErrors", "Quarantine"] {
                let columns = |schema: &str| -> Result<Vec<String>> {
                    Ok(self
                        .conn
                        .prepare(&format!("SELECT name FROM pragma_table_info('{table}', '{schema}')"))?
                        .query_map([], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?)
                };
                let here = columns("main")?;
                let shared: Vec<String> = columns("old")?.into_iter().filter(|c| here.iter().any(|h| h.eq_ignore_ascii_case(c))).collect();
                if shared.is_empty() {
                    continue;
                }
                let list = shared.join(", ");
                tx.execute(&format!("INSERT INTO main.{table} ({list}) SELECT {list} FROM old.{table}"), [])?;
            }
            tx.commit()?;
            Ok((count("Scans")?, count("Quarantine")?))
        })();
        self.conn.execute("DETACH DATABASE old", [])?;
        imported
    }

    fn migrate(&self) -> Result<()> {
        let existing: Vec<String> = self
            .conn
            .prepare("SELECT name FROM pragma_table_info('Scans')")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for (name, definition) in SCAN_COLUMNS {
            if !existing.iter().any(|c| c.eq_ignore_ascii_case(name)) {
                self.conn
                    .execute_batch(&format!("ALTER TABLE Scans ADD COLUMN {name} {definition}"))?;
            }
        }
        Ok(())
    }

    pub fn begin_scan(&self, meta: &ScanMeta<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO Scans (StartedAt, Targets, Kind, Threads, Signatures)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now(), meta.targets, meta.kind, meta.threads, meta.signatures],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_scan(&self, id: i64, stats: &ScanStats, elapsed_ms: i64, cancelled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE Scans SET FinishedAt = ?2, FilesScanned = ?3, BytesScanned = ?4,
                 FilesSkipped = ?5, Errors = ?6, Detections = ?7, Quarantined = ?8,
                 ElapsedMs = ?9, Cancelled = ?10
             WHERE Id = ?1",
            params![
                id,
                now(),
                stats.files_scanned,
                stats.bytes_scanned,
                stats.files_skipped,
                stats.errors,
                stats.detections,
                stats.quarantined,
                elapsed_ms,
                cancelled
            ],
        )?;
        Ok(())
    }

    pub fn add_scan_error(&self, scan_id: i64, path: &str, message: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ScanErrors (ScanId, Path, Message) VALUES (?1, ?2, ?3)",
            params![scan_id, path, message],
        )?;
        Ok(())
    }

    pub fn scan_errors(&self, scan_id: i64) -> Result<Vec<ScanErrorRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT Path, Message FROM ScanErrors WHERE ScanId = ?1 ORDER BY Id")?;
        let rows = stmt.query_map([scan_id], |r| {
            Ok(ScanErrorRow {
                path: r.get(0)?,
                message: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn scan_detections(&self, scan_id: i64) -> Result<Vec<DetectionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT Id, ScanId, DetectedAt, Path, Threat, Category, Source, Action
             FROM Detections WHERE ScanId = ?1 ORDER BY Id",
        )?;
        let rows = stmt.query_map([scan_id], detection_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }


    pub fn add_detection(
        &self,
        scan_id: i64,
        path: &str,
        sha256: &str,
        finding: &Finding,
        action: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO Detections
                 (ScanId, DetectedAt, Path, Sha256, Threat, Category, Source, Details, Action)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                scan_id,
                now(),
                path,
                sha256,
                finding.threat,
                finding.category.as_str(),
                finding.source.as_str(),
                finding.details,
                action
            ],
        )?;
        Ok(())
    }

    /// A detection's SHA-256, worst threat and action, if scan `scan_id`
    /// recorded one at `path`.
    pub fn detection_record(&self, scan_id: i64, path: &str) -> Result<Option<(String, String, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT Sha256, Threat, Action FROM Detections WHERE ScanId = ?1 AND Path = ?2 ORDER BY Id LIMIT 1",
                params![scan_id, path],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Records the action taken on a detection after its scan finished (a
    /// running program stopped, then quarantined); counts it as quarantined
    /// in the scan when `quarantined`.
    pub fn set_detection_action(&self, scan_id: i64, path: &str, action: &str, quarantined: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE Detections SET Action = ?3 WHERE ScanId = ?1 AND Path = ?2",
            params![scan_id, path, action],
        )?;
        if quarantined {
            self.conn.execute("UPDATE Scans SET Quarantined = Quarantined + 1 WHERE Id = ?1", [scan_id])?;
        }
        Ok(())
    }

    /// Removes a scan and everything recorded with it.
    pub fn delete_scan(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM Detections WHERE ScanId = ?1", [id])?;
        self.conn.execute("DELETE FROM ScanErrors WHERE ScanId = ?1", [id])?;
        self.conn.execute("DELETE FROM Scans WHERE Id = ?1", [id])?;
        Ok(())
    }

    /// Newest first; `kind` limits the result to one scan kind.
    pub fn recent_scans(&self, limit: u32, kind: Option<&str>) -> Result<Vec<ScanRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT Id, Kind, StartedAt, FinishedAt, ElapsedMs, Targets, FilesScanned,
                    BytesScanned, FilesSkipped, Errors, Detections, Quarantined, Threads,
                    Cancelled, Signatures
             FROM Scans WHERE ?2 IS NULL OR Kind = ?2 ORDER BY Id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit, kind], |r| {
            Ok(ScanRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                started_at: r.get(2)?,
                finished_at: r.get(3)?,
                elapsed_ms: r.get(4)?,
                targets: r.get(5)?,
                files_scanned: r.get(6)?,
                bytes_scanned: r.get(7)?,
                files_skipped: r.get(8)?,
                errors: r.get(9)?,
                detections: r.get(10)?,
                quarantined: r.get(11)?,
                threads: r.get(12)?,
                cancelled: r.get(13)?,
                signatures: r.get(14)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn recent_detections(&self, limit: u32) -> Result<Vec<DetectionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT Id, ScanId, DetectedAt, Path, Threat, Category, Source, Action
             FROM Detections ORDER BY Id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], detection_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Per-month totals, newest first (the equivalent of a monthly report).
    pub fn monthly_summary(&self) -> Result<Vec<MonthRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.Month,
                    (SELECT COUNT(*) FROM Scans s WHERE substr(s.StartedAt, 1, 7) = m.Month),
                    (SELECT COALESCE(SUM(FilesScanned), 0) FROM Scans s
                         WHERE substr(s.StartedAt, 1, 7) = m.Month),
                    (SELECT COUNT(DISTINCT ScanId || char(0) || Path) FROM Detections d
                         WHERE substr(d.DetectedAt, 1, 7) = m.Month),
                    (SELECT COUNT(*) FROM Quarantine q
                         WHERE substr(q.QuarantinedAt, 1, 7) = m.Month)
             FROM (SELECT substr(StartedAt, 1, 7) AS Month FROM Scans
                   UNION SELECT substr(QuarantinedAt, 1, 7) FROM Quarantine) m
             ORDER BY m.Month DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(MonthRow {
                month: r.get(0)?,
                scans: r.get(1)?,
                files_scanned: r.get(2)?,
                detections: r.get(3)?,
                quarantined: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn add_quarantine(&self, row: &QuarantineRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO Quarantine (Id, OriginalPath, QuarantinedAt, Sha256, Threat, Size)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.id,
                row.original_path,
                row.quarantined_at,
                row.sha256,
                row.threat,
                row.size
            ],
        )?;
        Ok(())
    }

    pub fn quarantine_items(&self, include_restored: bool) -> Result<Vec<QuarantineRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT Id, OriginalPath, QuarantinedAt, Sha256, Threat, Size, RestoredAt
             FROM Quarantine WHERE ?1 OR RestoredAt IS NULL ORDER BY QuarantinedAt DESC",
        )?;
        let rows = stmt.query_map([include_restored], quarantine_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn quarantine_item(&self, id: &str) -> Result<Option<QuarantineRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT Id, OriginalPath, QuarantinedAt, Sha256, Threat, Size, RestoredAt
                 FROM Quarantine WHERE Id = ?1",
                [id],
                quarantine_row,
            )
            .optional()?)
    }

    pub fn mark_restored(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE Quarantine SET RestoredAt = ?2 WHERE Id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn remove_quarantine(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM Quarantine WHERE Id = ?1", [id])?;
        Ok(())
    }
}

fn detection_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DetectionRow> {
    Ok(DetectionRow {
        id: r.get(0)?,
        scan_id: r.get(1)?,
        detected_at: r.get(2)?,
        path: r.get(3)?,
        threat: r.get(4)?,
        category: r.get(5)?,
        source: r.get(6)?,
        action: r.get(7)?,
    })
}

fn quarantine_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineRow> {
    Ok(QuarantineRow {
        id: r.get(0)?,
        original_path: r.get(1)?,
        quarantined_at: r.get(2)?,
        sha256: r.get(3)?,
        threat: r.get(4)?,
        size: r.get(5)?,
        restored_at: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_a_first_release_database() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("history.sqlite");
        {
            // The original Scans table, before Kind/Threads/... existed.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE Scans (Id INTEGER PRIMARY KEY, StartedAt TEXT NOT NULL, FinishedAt TEXT,
                     Targets TEXT NOT NULL, FilesScanned INTEGER NOT NULL DEFAULT 0,
                     BytesScanned INTEGER NOT NULL DEFAULT 0, FilesSkipped INTEGER NOT NULL DEFAULT 0,
                     Errors INTEGER NOT NULL DEFAULT 0, Detections INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO Scans (StartedAt, Targets, FilesScanned) VALUES ('2026-10-14T10:00:00+05:30', 'C:old', 7);",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let old = &store.recent_scans(10, None).unwrap()[0];
        assert_eq!((old.kind.as_str(), old.files_scanned, old.threads), ("manual", 7, 1));

        let id = store
            .begin_scan(&ScanMeta { kind: "watch", targets: "C:
ew", threads: 2, signatures: Some("x") })
            .unwrap();
        store.add_scan_error(id, "C:
ewa", "denied").unwrap();
        let stats = ScanStats { files_scanned: 3, quarantined: 1, ..Default::default() };
        store.finish_scan(id, &stats, 1234, true).unwrap();
        let rows = store.recent_scans(10, Some("watch")).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].elapsed_ms, rows[0].cancelled, rows[0].quarantined), (Some(1234), true, 1));
        assert_eq!(store.scan_errors(id).unwrap()[0].message, "denied");

        // Opening again must not try to add the columns twice.
        drop(store);
        Store::open(&path).unwrap();
    }
}
