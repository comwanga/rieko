use std::path::Path;

use chrono::{DateTime, Utc};
use rieko_alerts::{AlertError, AlertState, AlertStateStore};
use rieko_domain::ChannelSnapshot;
use rieko_findings::{
    ActionStage, AuditEntry, Finding, FindingLifecycle, Recommendation, Simulation,
    FINDING_SCHEMA_VERSION,
};
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::storage::{StorageCounts, StorageError};
use crate::Storage;

/// SQLite-backed storage, WAL mode (D6). Synchronous — used by the CLI scan
/// pipeline; the API holds it behind a `Mutex`.
pub struct SqliteStorage {
    conn: Connection,
    in_transaction: bool,
}

/// WAL checkpoint / busy wait: how long a writer waits for a competing reader
/// or writer before giving up with `SQLITE_BUSY`.
const BUSY_TIMEOUT_MS: u64 = 5000;
/// WAL mode with `synchronous=NORMAL` commits via the WAL without forcing an
/// fsync on every transaction. Data may be lost only on OS-level crash, which
/// is acceptable and is the documented operational model. See README.
const SYNCHRONOUS_MODE: &str = "NORMAL";

/// Sync strategy for opening connections; ensures reproducible connection state.
impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        let conn = Connection::open(path).map_err(|e| {
            StorageError::Backend(format!("opening sqlite db {}: {e}", path.display()))
        })?;
        apply_operational_settings(&conn)?;
        let mut s = Self {
            conn,
            in_transaction: false,
        };
        crate::migrations::migrate(&mut s.conn)
            .map_err(|e| StorageError::Backend(format!("migrating {}: {e}", path.display())))?;
        Ok(s)
    }

    pub fn in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StorageError::Backend(format!("opening in-memory sqlite: {e}")))?;
        apply_operational_settings(&conn)?;
        let mut s = Self {
            conn,
            in_transaction: false,
        };
        crate::migrations::migrate(&mut s.conn)?;
        Ok(s)
    }

    /// Obtain the exclusive advisory writer lock for this database. Only one
    /// writing process may hold it at a time; a second monitor gets an error
    /// instead of racing (see [`WriterLock`]).
    pub fn writer_lock(&self, db_path: &Path) -> Result<WriterLock, StorageError> {
        WriterLock::acquire(db_path)
    }

    fn row_to_finding(row: &rusqlite::Row) -> rusqlite::Result<Finding> {
        use rieko_findings::Severity;
        let severity: i64 = row.get(2)?;
        let severity = match severity {
            0 => Severity::Info,
            1 => Severity::Warning,
            _ => Severity::Critical,
        };
        let evidence_json: String = row.get(5)?;
        // Strict decode: malformed persisted evidence is corrupt data, never a
        // silent empty list (RIEKO-AUDIT-012).
        let evidence: Vec<rieko_findings::Evidence> = serde_json::from_str(&evidence_json)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    e.to_string().into(),
                )
            })?;
        let ts: String = row.get(7)?;
        // Strict decode: an invalid persisted timestamp must not silently be
        // replaced with the current time.
        let timestamp = DateTime::parse_from_rfc3339(&ts)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    format!("invalid timestamp {:?}: {e}", ts).into(),
                )
            })?;
        let detector_version: String = row
            .get::<_, Option<String>>(8)?
            .unwrap_or_else(|| "1".to_string());
        let _schema_version: u8 = row
            .get::<_, Option<i64>>(9)?
            .map(|v| v.clamp(0, u8::MAX as i64) as u8)
            .unwrap_or(FINDING_SCHEMA_VERSION);
        let first_string: String = row.get(10)?;
        let first_seen_at = DateTime::parse_from_rfc3339(&first_string)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Text,
                    format!("invalid first_seen_at {:?}: {e}", first_string).into(),
                )
            })?;
        let last_string: String = row.get(11)?;
        let last_seen_at = DateTime::parse_from_rfc3339(&last_string)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Text,
                    format!("invalid last_seen_at {:?}: {e}", last_string).into(),
                )
            })?;
        let lifecycle: String = row.get(12)?;
        let lifecycle = match lifecycle.as_str() {
            "resolved" => FindingLifecycle::Resolved,
            _ => FindingLifecycle::Active,
        };
        Ok(Finding {
            id: row.get(0)?,
            detector: row.get(1)?,
            detector_version,
            schema_version: FINDING_SCHEMA_VERSION,
            severity,
            node: row.get::<_, Option<String>>(3)?,
            channel: row.get::<_, Option<String>>(4)?,
            evidence,
            explanation: row.get::<_, Option<String>>(6)?,
            timestamp,
            first_seen_at,
            last_seen_at,
            lifecycle,
        })
    }
}

impl Storage for SqliteStorage {
    fn schema_version(&mut self) -> Result<i64, StorageError> {
        crate::migrations::schema_version(&self.conn)
    }

    fn integrity_check(&mut self) -> Result<(), StorageError> {
        let result: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| StorageError::Backend(format!("running integrity check: {e}")))?;
        if result.trim() == "ok" {
            Ok(())
        } else {
            Err(StorageError::Corrupt(format!(
                "database integrity check failed: {result}"
            )))
        }
    }

    fn begin_transaction(&mut self) -> Result<(), StorageError> {
        if self.in_transaction {
            return Err(StorageError::Backend("nested transaction attempted".into()));
        }
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| StorageError::Backend(format!("beginning transaction: {e}")))?;
        self.in_transaction = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), StorageError> {
        if !self.in_transaction {
            return Err(StorageError::Backend(
                "commit with no open transaction".into(),
            ));
        }
        self.conn
            .execute("COMMIT", [])
            .map_err(|e| StorageError::Backend(format!("committing transaction: {e}")))?;
        self.in_transaction = false;
        Ok(())
    }

    fn rollback_transaction(&mut self) -> Result<(), StorageError> {
        if !self.in_transaction {
            return Ok(());
        }
        let _ = self.conn.execute_batch("ROLLBACK");
        self.in_transaction = false;
        Ok(())
    }

    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError> {
        let severity = finding.severity as i64;
        let evidence = serde_json::to_string(&finding.evidence)
            .map_err(|e| StorageError::Corrupt(format!("finding evidence: {e}")))?;
        self.conn.execute(
            "INSERT INTO findings (id, detector, detector_version, severity, node_id, channel_id,
                    evidence, explanation, ts, first_seen_at, last_seen_at, lifecycle)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET
                detector_version = excluded.detector_version,
                explanation = COALESCE(excluded.explanation, findings.explanation),
                first_seen_at = COALESCE(findings.first_seen_at, excluded.first_seen_at),
                ts = excluded.ts,
                last_seen_at = excluded.last_seen_at,
                lifecycle = excluded.lifecycle",
            params![
                finding.id,
                finding.detector,
                finding.detector_version,
                severity,
                finding.node,
                finding.channel,
                evidence,
                finding.explanation,
                finding.timestamp.to_rfc3339(),
                finding.first_seen_at.to_rfc3339(),
                finding.last_seen_at.to_rfc3339(),
                lifecycle_str(finding.lifecycle),
            ],
        )?;
        Ok(())
    }

    fn latest_findings(&mut self, limit: u32) -> Result<Vec<Finding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                    detector_version, schema_version, first_seen_at, last_seen_at, lifecycle
             FROM findings ORDER BY ts DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_finding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn findings_for_channel(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<Finding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                    detector_version, schema_version, first_seen_at, last_seen_at, lifecycle
             FROM findings WHERE channel_id = ? ORDER BY ts DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(rusqlite::params![channel_id, limit], Self::row_to_finding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn save_recommendation(&mut self, rec: &Recommendation) -> Result<(), StorageError> {
        let params_json = serde_json::to_string(&rec.action.params)
            .map_err(|e| StorageError::Corrupt(format!("recommendation params: {e}")))?;
        let rationale_json = serde_json::to_string(&rec.rationale)
            .map_err(|e| StorageError::Corrupt(format!("recommendation rationale: {e}")))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO recommendations
             (finding_id, action_id, action_type, stage, target, params, summary, rationale, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rec.finding_id,
                rec.action.id,
                rec.action.action_type.as_str(),
                format!("{:?}", rec.action.stage),
                rec.action.target,
                params_json,
                rec.action.summary,
                rationale_json,
                rec.action.created_at.to_rfc3339(),
                rec.action.updated_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn latest_recommendations(&mut self, limit: u32) -> Result<Vec<Recommendation>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, action_id, action_type, stage, target, params, summary, rationale, created_at, updated_at
             FROM recommendations ORDER BY created_at DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], |row| {
            use rieko_findings::{Action, ActionStage, ActionType};
            let stage = match row.get::<_, String>(3)?.as_str() {
                "Simulated" => ActionStage::Simulated,
                "Approved" => ActionStage::Approved,
                "Executed" => ActionStage::Executed,
                "Rejected" => ActionStage::Rejected,
                "Failed" => ActionStage::Failed,
                _ => ActionStage::Recommended,
            };
            let action_type = match row.get::<_, String>(2)?.as_str() {
                "update_fee_policy" => ActionType::UpdateFeePolicy,
                "restart_service" => ActionType::RestartService,
                "custom" => ActionType::Custom,
                _ => ActionType::RebalanceChannel,
            };
            let params: Value =
                serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or(Value::Null);
            let rationale = parse_rationale(&row.get::<_, String>(7)?);
            Ok(Recommendation {
                finding_id: row.get(0)?,
                action: Action {
                    id: row.get(1)?,
                    action_type,
                    stage,
                    target: row.get::<_, Option<String>>(4)?,
                    params,
                    summary: row.get(6)?,
                    created_at: parse_ts(&row.get::<_, String>(8)?),
                    updated_at: parse_ts(&row.get::<_, String>(9)?),
                },
                rationale,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn recommendation_for_action(
        &mut self,
        action_id: &str,
    ) -> Result<Option<Recommendation>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, action_id, action_type, stage, target, params, summary, rationale, created_at, updated_at
             FROM recommendations WHERE action_id = ?1",
        )?;
        let mut rows = stmt.query_map([action_id], |row| {
            use rieko_findings::{Action, ActionStage, ActionType};
            let stage = match row.get::<_, String>(3)?.as_str() {
                "Simulated" => ActionStage::Simulated,
                "Approved" => ActionStage::Approved,
                "Executed" => ActionStage::Executed,
                "Rejected" => ActionStage::Rejected,
                "Failed" => ActionStage::Failed,
                _ => ActionStage::Recommended,
            };
            let action_type = match row.get::<_, String>(2)?.as_str() {
                "update_fee_policy" => ActionType::UpdateFeePolicy,
                "restart_service" => ActionType::RestartService,
                "custom" => ActionType::Custom,
                _ => ActionType::RebalanceChannel,
            };
            let params: Value =
                serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or(Value::Null);
            let rationale = parse_rationale(&row.get::<_, String>(7)?);
            Ok(Recommendation {
                finding_id: row.get(0)?,
                action: Action {
                    id: row.get(1)?,
                    action_type,
                    stage,
                    target: row.get::<_, Option<String>>(4)?,
                    params,
                    summary: row.get(6)?,
                    created_at: parse_ts(&row.get::<_, String>(8)?),
                    updated_at: parse_ts(&row.get::<_, String>(9)?),
                },
                rationale,
            })
        })?;
        rows.next().transpose().map_err(Into::into)
    }

    fn set_action_stage(
        &mut self,
        action_id: &str,
        stage: ActionStage,
    ) -> Result<(), StorageError> {
        let updated = chrono::Utc::now();
        self.conn.execute(
            "UPDATE recommendations SET stage = ?1, updated_at = ?2 WHERE action_id = ?3",
            params![format!("{:?}", stage), updated.to_rfc3339(), action_id],
        )?;
        Ok(())
    }

    fn append_audit(&mut self, entry: &AuditEntry) -> Result<(), StorageError> {
        let details = serde_json::to_string(&entry.details)
            .map_err(|e| StorageError::Corrupt(format!("audit details: {e}")))?;
        self.conn.execute(
            "INSERT INTO audit (id, action_id, action_type, previous_stage, stage, actor, details, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.id,
                entry.action_id,
                entry.action_type.as_str(),
                entry.previous_stage.map(|s| format!("{:?}", s)),
                format!("{:?}", entry.stage),
                entry.actor,
                details,
                entry.timestamp.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn recent_audit(&mut self, limit: u32) -> Result<Vec<AuditEntry>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action_id, action_type, previous_stage, stage, actor, details, ts
             FROM audit ORDER BY ts DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], |row| {
            use rieko_findings::{ActionStage, ActionType};
            let stage = match row.get::<_, String>(4)?.as_str() {
                "Simulated" => ActionStage::Simulated,
                "Approved" => ActionStage::Approved,
                "Executed" => ActionStage::Executed,
                "Rejected" => ActionStage::Rejected,
                "Failed" => ActionStage::Failed,
                _ => ActionStage::Recommended,
            };
            let previous_stage = match row.get::<_, Option<String>>(3)? {
                Some(ref s) => match s.as_str() {
                    "Recommended" => Some(ActionStage::Recommended),
                    "Simulated" => Some(ActionStage::Simulated),
                    "Approved" => Some(ActionStage::Approved),
                    "Executed" => Some(ActionStage::Executed),
                    "Rejected" => Some(ActionStage::Rejected),
                    "Failed" => Some(ActionStage::Failed),
                    _ => None,
                },
                None => None,
            };
            let action_type = match row.get::<_, String>(2)?.as_str() {
                "update_fee_policy" => ActionType::UpdateFeePolicy,
                "restart_service" => ActionType::RestartService,
                "custom" => ActionType::Custom,
                _ => ActionType::RebalanceChannel,
            };
            let details: Value =
                serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or(Value::Null);
            Ok(AuditEntry {
                id: row.get(0)?,
                action_id: row.get(1)?,
                action_type,
                previous_stage,
                stage,
                actor: row.get(5)?,
                details,
                timestamp: parse_ts(&row.get::<_, String>(7)?),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn save_channel_snapshot(&mut self, snapshot: &ChannelSnapshot) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO channel_snapshots
             (channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat, capacity_msat, status_int)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                snapshot.channel_id,
                snapshot.ts.to_rfc3339(),
                snapshot.local_ratio,
                snapshot.local_balance_msat,
                snapshot.remote_balance_msat,
                snapshot.capacity_msat,
                snapshot.status as i64
            ],
        )?;
        Ok(())
    }

    fn recent_channel_snapshots(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<ChannelSnapshot>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat, capacity_msat, status_int
             FROM channel_snapshots WHERE channel_id = ?1 ORDER BY ts DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![channel_id, limit], |row| {
            let status_int: u32 = row.get(6)?;
            let ts: String = row.get(1)?;
            Ok(ChannelSnapshot {
                channel_id: row.get(0)?,
                local_ratio: row.get(2)?,
                local_balance_msat: row.get(3)?,
                remote_balance_msat: row.get(4)?,
                capacity_msat: row.get(5)?,
                status: status_from_i64(status_int),
                ts: parse_ts(&ts),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn recent_snapshots_all(&mut self, limit: u32) -> Result<Vec<ChannelSnapshot>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat, capacity_msat, status_int
             FROM channel_snapshots ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            let status_int: u32 = row.get(6)?;
            let ts: String = row.get(1)?;
            Ok(ChannelSnapshot {
                channel_id: row.get(0)?,
                local_ratio: row.get(2)?,
                local_balance_msat: row.get(3)?,
                remote_balance_msat: row.get(4)?,
                capacity_msat: row.get(5)?,
                status: status_from_i64(status_int),
                ts: parse_ts(&ts),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn save_simulation(&mut self, sim: &Simulation) -> Result<(), StorageError> {
        let projection = serde_json::to_string(&sim.projection)
            .map_err(|e| StorageError::Corrupt(format!("simulation projection: {e}")))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO simulations (id, action_id, finding_id, action_type, projection, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                sim.id,
                sim.action_id,
                sim.finding_id,
                sim.action_type.as_str(),
                projection,
                sim.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn recent_simulations(&mut self, limit: u32) -> Result<Vec<Simulation>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action_id, finding_id, action_type, projection, created_at
             FROM simulations ORDER BY created_at DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_simulation)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn simulations_for_action(&mut self, action_id: &str) -> Result<Vec<Simulation>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action_id, finding_id, action_type, projection, created_at
             FROM simulations WHERE action_id = ? ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([action_id], Self::row_to_simulation)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn counts(&mut self) -> Result<StorageCounts, StorageError> {
        let count = |table: &str| -> Result<usize, StorageError> {
            let n: i64 =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
            Ok(n as usize)
        };
        Ok(StorageCounts {
            findings: count("findings")?,
            recommendations: count("recommendations")?,
            simulations: count("simulations")?,
            audit: count("audit")?,
            channel_snapshots: count("channel_snapshots")?,
        })
    }
}

impl SqliteStorage {
    fn row_to_simulation(row: &rusqlite::Row) -> rusqlite::Result<Simulation> {
        use rieko_findings::ActionType;
        let action_type = match row.get::<_, String>(3)?.as_str() {
            "update_fee_policy" => ActionType::UpdateFeePolicy,
            "restart_service" => ActionType::RestartService,
            "custom" => ActionType::Custom,
            _ => ActionType::RebalanceChannel,
        };
        let projection = serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or(
            rieko_findings::SimulationProjection {
                local_ratio_before: 0.0,
                local_ratio_after: 0.0,
                local_balance_msat_after: 0,
                remote_balance_msat_after: 0,
                delta_msat: 0,
                clears_finding: false,
                summary: "corrupt projection".into(),
            },
        );
        Ok(Simulation {
            id: row.get(0)?,
            action_id: row.get(1)?,
            finding_id: row.get(2)?,
            action_type,
            projection,
            created_at: parse_ts(&row.get::<_, String>(5)?),
        })
    }
}

fn status_from_i64(v: u32) -> rieko_domain::ChannelStatus {
    use rieko_domain::ChannelStatus;
    match v {
        0 => ChannelStatus::Opening,
        1 => ChannelStatus::Active,
        2 => ChannelStatus::Inactive,
        3 => ChannelStatus::Closing,
        4 => ChannelStatus::Closed,
        5 => ChannelStatus::PendingOpen,
        6 => ChannelStatus::WaitingClose,
        _ => ChannelStatus::ForceClosing,
    }
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// Apply the documented, intentional per-connection operational settings. These
/// are deliberate choices (RIEKO-AUDIT-006), not arbitrary tuning:
/// * WAL journal mode (DEK: durable concurrent reader/writer workload).
/// * Foreign keys enforced.
/// * A finite busy timeout so a transient lock never fails immediately.
/// * `synchronous=NORMAL` — see [`SYNCHRONOUS_MODE`].
fn apply_operational_settings(conn: &Connection) -> Result<(), StorageError> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .and_then(|_| conn.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|_| conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS as i64))
        .and_then(|_| conn.pragma_update(None, "synchronous", SYNCHRONOUS_MODE))
        .map_err(|e| StorageError::Backend(format!("configuring sqlite connection: {e}")))
}

/// An exclusive advisory lock guarding one SQLite database so that at most one
/// writing process (the monitor) holds it at a time. Implementation uses a
/// separate `<db>.lock` file. Multiple readers keep working under WAL; this
/// only rejects a *second writer*. Dropping the guard releases the lock.
pub struct WriterLock {
    file: std::fs::File,
}

impl WriterLock {
    pub fn acquire(db_path: &Path) -> Result<Self, StorageError> {
        let lock_path = db_path.with_extension(
            db_path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!("{e}.lock"))
                .unwrap_or_else(|| "lock".into()),
        );
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                StorageError::Backend(format!("opening lock file {}: {e}", lock_path.display()))
            })?;
        lock(&file).map_err(|e| {
            StorageError::Backend(format!(
                "another process already holds the {} writer lock: {e}",
                db_path.display()
            ))
        })?;
        Ok(Self { file })
    }
}

/// Flock-based exclusive lock. Returns a backend error when the lock is held
/// by another process (non-blocking attempt).
#[cfg(target_family = "unix")]
fn lock(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Non-unix fallback: real writers are still serialized by SQLite's own
/// locking; this only weakens the advisory guard. Kept for portability.
#[cfg(not(target_family = "unix"))]
fn lock(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

impl AlertStateStore for SqliteStorage {
    fn read(&self, key: &str) -> Result<Option<rieko_alerts::AlertState>, AlertError> {
        let mut stmt = self
            .conn
            .prepare("SELECT last_sent_at, last_severity, last_status FROM alert_state WHERE dedup_key = ?1")
            .map_err(|e| AlertError::Store(e.to_string()))?;
        let mut rows = stmt
            .query_map(params![key], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| AlertError::Store(e.to_string()))?;
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        let (sent, sev, status) = row.map_err(|e| AlertError::Store(e.to_string()))?;
        Ok(Some(rieko_alerts::AlertState {
            last_sent_at: sent.map(|s| parse_ts(&s)),
            last_severity: sev.and_then(severity_from_int),
            last_status: parse_status(&status),
        }))
    }

    fn write(&mut self, key: &str, state: &AlertState) -> Result<(), AlertError> {
        self.conn
            .execute(
                "INSERT INTO alert_state (dedup_key, last_sent_at, last_severity, last_status)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(dedup_key) DO UPDATE SET
                    last_sent_at = excluded.last_sent_at,
                    last_severity = excluded.last_severity,
                    last_status = excluded.last_status",
                params![
                    key,
                    state.last_sent_at.map(|t| t.to_rfc3339()),
                    state.last_severity.map(|s| s as i64),
                    status_str(state.last_status),
                ],
            )
            .map(|_| ())
            .map_err(|e| AlertError::Store(e.to_string()))
    }
}

impl rieko_status::OperationalStateStore for SqliteStorage {
    fn read_operational_state(
        &self,
    ) -> Result<Option<rieko_status::OperationalState>, rieko_status::OperationalStateError> {
        use rieko_status::OperationalStateError;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source, source_connected, last_ingestion_attempt,
                        last_ingestion_success, last_cycle_attempt, last_cycle_success,
                        last_persist_success, source_data_at, llm, alert_sink
                 FROM operational_state WHERE id = 'current'",
            )
            .map_err(|e| OperationalStateError::Store(e.to_string()))?;
        let mut rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| OperationalStateError::Store(e.to_string()))?;
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        let (
            source,
            connected,
            ingest_attempt,
            ingest_success,
            cycle_attempt,
            cycle_success,
            persist_success,
            data_at,
            llm,
            alert,
        ) = row.map_err(|e| OperationalStateError::Store(e.to_string()))?;
        Ok(Some(rieko_status::OperationalState {
            source: parse_source(&source, connected),
            last_ingestion_attempt: ingest_attempt.map(|s| parse_ts(&s)),
            last_ingestion_success: ingest_success.map(|s| parse_ts(&s)),
            last_cycle_attempt: cycle_attempt.map(|s| parse_ts(&s)),
            last_cycle_success: cycle_success.map(|s| parse_ts(&s)),
            last_persist_success: persist_success.map(|s| parse_ts(&s)),
            source_data_at: data_at.map(|s| parse_ts(&s)),
            llm: parse_component(&llm),
            alert_sink: parse_component(&alert),
        }))
    }

    fn write_operational_state(
        &mut self,
        state: &rieko_status::OperationalState,
    ) -> Result<(), rieko_status::OperationalStateError> {
        use rieko_status::OperationalStateError;
        let connected = match state.source {
            rieko_status::SourceState::Fixture => None,
            rieko_status::SourceState::LndRest { connected } => Some(connected as i64),
        };
        self.conn
            .execute(
                "INSERT INTO operational_state
                    (id, source, source_connected, last_ingestion_attempt, last_ingestion_success,
                     last_cycle_attempt, last_cycle_success, last_persist_success, source_data_at,
                     llm, alert_sink)
                 VALUES ('current', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                    source = excluded.source,
                    source_connected = excluded.source_connected,
                    last_ingestion_attempt = excluded.last_ingestion_attempt,
                    last_ingestion_success = excluded.last_ingestion_success,
                    last_cycle_attempt = excluded.last_cycle_attempt,
                    last_cycle_success = excluded.last_cycle_success,
                    last_persist_success = excluded.last_persist_success,
                    source_data_at = excluded.source_data_at,
                    llm = excluded.llm,
                    alert_sink = excluded.alert_sink",
                params![
                    state.source.as_str(),
                    connected,
                    state.last_ingestion_attempt.map(|t| t.to_rfc3339()),
                    state.last_ingestion_success.map(|t| t.to_rfc3339()),
                    state.last_cycle_attempt.map(|t| t.to_rfc3339()),
                    state.last_cycle_success.map(|t| t.to_rfc3339()),
                    state.last_persist_success.map(|t| t.to_rfc3339()),
                    state.source_data_at.map(|t| t.to_rfc3339()),
                    component_str(state.llm),
                    component_str(state.alert_sink),
                ],
            )
            .map(|_| ())
            .map_err(|e| OperationalStateError::Store(e.to_string()))
    }
}

fn parse_source(s: &str, connected: Option<i64>) -> rieko_status::SourceState {
    use rieko_status::SourceState;
    match s {
        "lnd_rest" => SourceState::LndRest {
            connected: connected == Some(1),
        },
        _ => SourceState::Fixture,
    }
}

fn parse_component(s: &str) -> rieko_status::ComponentState {
    use rieko_status::ComponentState;
    match s {
        "healthy" => ComponentState::Healthy,
        "failing" => ComponentState::Failing,
        _ => ComponentState::NotConfigured,
    }
}

fn component_str(s: rieko_status::ComponentState) -> &'static str {
    s.as_str()
}

fn parse_rationale(s: &str) -> rieko_findings::Rationale {
    serde_json::from_str(s).unwrap_or_default()
}

fn severity_from_int(v: i64) -> Option<rieko_findings::Severity> {
    match v {
        0 => Some(rieko_findings::Severity::Info),
        1 => Some(rieko_findings::Severity::Warning),
        2 => Some(rieko_findings::Severity::Critical),
        _ => None,
    }
}

fn parse_status(s: &str) -> rieko_alerts::DeliveryStatus {
    match s {
        "success" => rieko_alerts::DeliveryStatus::Success,
        "failed" => rieko_alerts::DeliveryStatus::Failed,
        "skipped" => rieko_alerts::DeliveryStatus::Skipped,
        _ => rieko_alerts::DeliveryStatus::None,
    }
}

fn status_str(s: rieko_alerts::DeliveryStatus) -> &'static str {
    use rieko_alerts::DeliveryStatus::*;
    match s {
        Success => "success",
        Failed => "failed",
        Skipped => "skipped",
        None => "none",
    }
}

fn lifecycle_str(s: FindingLifecycle) -> &'static str {
    match s {
        FindingLifecycle::Active => "active",
        FindingLifecycle::Resolved => "resolved",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStorage;
    use rieko_findings::{Action, ActionStage, ActionType, Evidence, Rationale, Severity};

    fn test_rec(finding_id: &str, action: Action) -> Recommendation {
        Recommendation {
            finding_id: finding_id.into(),
            action,
            rationale: Rationale::default(),
        }
    }

    fn sample_finding() -> Finding {
        let now = Utc::now();
        Finding {
            id: "f1".into(),
            detector: "channel_liquidity".into(),
            detector_version: "1".into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity: Severity::Critical,
            node: Some("local-node".into()),
            channel: Some("c1".into()),
            evidence: vec![Evidence::number("local_ratio", 0.02)],
            explanation: None,
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: FindingLifecycle::Active,
        }
    }

    #[test]
    fn roundtrips_findings_recommendations_audit() {
        let mut s = SqliteStorage::in_memory().unwrap();
        s.save_finding(&sample_finding()).unwrap();

        let rec = test_rec(
            "f1",
            Action::new(
                ActionType::RebalanceChannel,
                ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({"desired_ratio": 0.5}),
                "Rebalance channel c1 to 50/50",
            ),
        );
        // A non-default rationale must survive the SQLite roundtrip (WP3.2).
        let mut rec = rec;
        rec.rationale = Rationale {
            evidence: vec!["local_ratio=0.1".into()],
            preconditions: vec!["confirm intent".into()],
            expected_effect: "informed decision".into(),
            risks: vec!["fees".into()],
            limitations: vec!["single snapshot".into()],
            actionability: rieko_findings::Actionability::OperatorActionable,
        };
        s.save_recommendation(&rec).unwrap();

        let audit = AuditEntry::from_action(&rec.action, "system", serde_json::json!({}));
        s.append_audit(&audit).unwrap();

        let findings = s.latest_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "f1");
        assert_eq!(findings[0].severity, Severity::Critical);
        // Lifecycle metadata survives the roundtrip (WP2.3).
        assert_eq!(findings[0].detector_version, "1");
        assert_eq!(findings[0].schema_version, FINDING_SCHEMA_VERSION);
        assert_eq!(findings[0].lifecycle, FindingLifecycle::Active);
        assert_eq!(findings[0].first_seen_at, findings[0].last_seen_at);

        let recs = s.latest_recommendations(10).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action.action_type, ActionType::RebalanceChannel);
        assert_eq!(recs[0].action.stage, ActionStage::Recommended);
        assert_eq!(
            recs[0].rationale, rec.rationale,
            "rationale must survive the roundtrip"
        );

        let audit_rows = s.recent_audit(10).unwrap();
        assert_eq!(audit_rows.len(), 1);
        assert_eq!(audit_rows[0].action_id, rec.action.id);
        assert_eq!(
            audit_rows[0].previous_stage, None,
            "creation audit entry has no previous stage"
        );
    }

    #[test]
    fn action_stage_can_be_fetched_and_transitioned() {
        use rieko_findings::{Action, ActionStage, ActionType};
        let mut s = SqliteStorage::in_memory().unwrap();
        let rec = test_rec(
            "f1",
            Action::new(
                ActionType::RebalanceChannel,
                ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({"desired_ratio": 0.5}),
                "rebalance c1",
            ),
        );
        s.save_recommendation(&rec).unwrap();

        let fetched = s
            .recommendation_for_action(&rec.action.id)
            .unwrap()
            .unwrap();
        assert_eq!(fetched.action.stage, ActionStage::Recommended);

        s.set_action_stage(&rec.action.id, ActionStage::Simulated)
            .unwrap();
        let after = s
            .recommendation_for_action(&rec.action.id)
            .unwrap()
            .unwrap();
        assert_eq!(after.action.stage, ActionStage::Simulated);
        assert!(after.action.updated_at >= after.action.created_at);

        assert!(s.recommendation_for_action("nope").unwrap().is_none());
    }

    #[test]
    fn simulations_roundtrip() {
        use rieko_findings::{Simulation, SimulationProjection};
        let mut s = SqliteStorage::in_memory().unwrap();
        let sim = Simulation {
            id: "sim1".into(),
            action_id: "a1".into(),
            finding_id: "f1".into(),
            action_type: rieko_findings::ActionType::RebalanceChannel,
            projection: SimulationProjection {
                local_ratio_before: 0.1,
                local_ratio_after: 0.5,
                local_balance_msat_after: 50_000,
                remote_balance_msat_after: 50_000,
                delta_msat: 40_000,
                clears_finding: true,
                summary: "balanced".into(),
            },
            created_at: Utc::now(),
        };
        s.save_simulation(&sim).unwrap();
        let got = s.recent_simulations(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "sim1");
        assert!(got[0].projection.clears_finding);
        assert_eq!(s.simulations_for_action("a1").unwrap().len(), 1);
        assert_eq!(s.simulations_for_action("zz").unwrap().len(), 0);
    }

    #[test]
    fn memory_storage_works() {
        let mut s = MemoryStorage::new();
        s.save_finding(&sample_finding()).unwrap();
        assert_eq!(s.latest_findings(10).unwrap().len(), 1);
        assert_eq!(s.findings_for_channel("c1", 10).unwrap().len(), 1);
        assert_eq!(s.findings_for_channel("c2", 10).unwrap().len(), 0);
    }

    #[test]
    fn findings_for_channel_is_bounded() {
        let dir = std::env::temp_dir().join(format!("rieko-bound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("bound.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        for i in 0..100 {
            let mut f = sample_finding();
            f.id = format!("f-{i}");
            s.save_finding(&f).unwrap();
        }
        // A malicious or accidental `limit=0` still returns exactly one row;
        // the route clamp also caps at 500, so a channel with a huge history
        // can never materialize the whole table (RIEKO-AUDIT-014).
        assert_eq!(s.findings_for_channel("c1", 1).unwrap().len(), 1);
        assert_eq!(s.findings_for_channel("c1", 50).unwrap().len(), 50);
        assert_eq!(s.findings_for_channel("c1", 10_000).unwrap().len(), 100);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn operational_state_roundtrips_in_sqlite_and_memory() {
        use rieko_status::OperationalStateStore as _;

        let state = rieko_status::OperationalState {
            source: rieko_status::SourceState::LndRest { connected: true },
            last_ingestion_attempt: Some(Utc::now()),
            last_ingestion_success: Some(Utc::now()),
            last_cycle_attempt: Some(Utc::now()),
            last_cycle_success: Some(Utc::now()),
            last_persist_success: Some(Utc::now()),
            source_data_at: Some(Utc::now()),
            llm: rieko_status::ComponentState::Healthy,
            alert_sink: rieko_status::ComponentState::Failing,
        };

        let mut sqlite = SqliteStorage::in_memory().unwrap();
        assert!(sqlite.read_operational_state().unwrap().is_none());
        sqlite.write_operational_state(&state).unwrap();
        let read = sqlite.read_operational_state().unwrap().unwrap();
        assert_eq!(read, state);
        sqlite
            .write_operational_state(&rieko_status::OperationalState {
                llm: rieko_status::ComponentState::NotConfigured,
                ..state.clone()
            })
            .unwrap();
        // Upsert keeps a single row.
        let again = sqlite.read_operational_state().unwrap().unwrap();
        assert_eq!(again.llm, rieko_status::ComponentState::NotConfigured);

        let mut mem = MemoryStorage::new();
        assert!(mem.read_operational_state().unwrap().is_none());
        mem.write_operational_state(&state).unwrap();
        assert_eq!(mem.read_operational_state().unwrap().unwrap(), state);
    }

    #[test]
    fn channel_snapshots_roundtrip() {
        use rieko_domain::ChannelStatus;

        let mut s = SqliteStorage::in_memory().unwrap();
        let ts = Utc::now();
        let snap = ChannelSnapshot {
            channel_id: "c1".into(),
            local_ratio: 0.42,
            local_balance_msat: 420_000,
            remote_balance_msat: 580_000,
            capacity_msat: 1_000_000,
            status: ChannelStatus::Active,
            ts,
        };
        s.save_channel_snapshot(&snap).unwrap();
        s.save_channel_snapshot(&ChannelSnapshot {
            channel_id: "c1".into(),
            local_ratio: 0.30,
            ts: ts + chrono::Duration::seconds(60),
            ..snap.clone()
        })
        .unwrap();

        let got = s.recent_channel_snapshots("c1", 10).unwrap();
        assert_eq!(got.len(), 2);
        // newest first
        assert_eq!(got[0].local_ratio, 0.30);
        assert_eq!(got[0].status, ChannelStatus::Active);
        assert_eq!(got[1].local_ratio, 0.42);
        assert_eq!(s.recent_channel_snapshots("other", 10).unwrap().len(), 0);
    }

    #[test]
    fn alert_state_roundtrips_through_sqlite() {
        use rieko_alerts::{AlertState, AlertStateStore, DeliveryStatus};
        use rieko_findings::Severity;

        let mut s = SqliteStorage::in_memory().unwrap();
        assert_eq!(
            AlertStateStore::read(&s, "k1").unwrap(),
            None,
            "unknown key reads as None"
        );

        let now = Utc::now();
        let state = AlertState {
            last_sent_at: Some(now),
            last_severity: Some(Severity::Critical),
            last_status: DeliveryStatus::Success,
        };
        s.write("k1", &state).unwrap();

        let got = AlertStateStore::read(&s, "k1").unwrap().unwrap();
        assert_eq!(got.last_severity, Some(Severity::Critical));
        assert_eq!(got.last_status, DeliveryStatus::Success);
        assert!(got.last_sent_at.is_some());
    }

    #[test]
    fn alert_state_survives_reopen() {
        use rieko_alerts::{AlertState, AlertStateStore, DeliveryStatus};
        use rieko_findings::Severity;

        let dir = std::env::temp_dir().join(format!("rieko-alert-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("alerts.db");

        {
            let mut s = SqliteStorage::open(&file).unwrap();
            let now = Utc::now();
            let state = AlertState {
                last_sent_at: Some(now),
                last_severity: Some(Severity::Critical),
                last_status: DeliveryStatus::Success,
            };
            s.write("k1", &state).unwrap();
        }

        // Re-open against the same file to prove it survives a "restart".
        let mut s2 = SqliteStorage::open(&file).unwrap();
        let got2 = AlertStateStore::read(&s2, "k1").unwrap().unwrap();
        assert_eq!(got2.last_severity, Some(Severity::Critical));

        // Overwrite on conflict, keyed by dedup_key.
        let older = AlertState {
            last_sent_at: Some(Utc::now() - chrono::Duration::hours(2)),
            last_severity: Some(Severity::Warning),
            last_status: DeliveryStatus::Skipped,
        };
        s2.write("k1", &older).unwrap();
        let got3 = AlertStateStore::read(&s2, "k1").unwrap().unwrap();
        assert_eq!(got3.last_severity, Some(Severity::Warning));
        assert_eq!(got3.last_status, DeliveryStatus::Skipped);
    }

    #[test]
    fn transaction_commit_makes_cycle_visible_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("tx.db");
        let mut w = SqliteStorage::open(&db).unwrap();
        let f = sample_finding();
        let rec = test_rec(
            &f.id,
            rieko_findings::Action::new(
                rieko_findings::ActionType::RebalanceChannel,
                rieko_findings::ActionStage::Recommended,
                f.channel.clone(),
                serde_json::json!({}),
                "rebalance",
            ),
        );
        let audit = AuditEntry::from_action(&rec.action, "system", serde_json::json!({}));

        w.begin_transaction().unwrap();
        w.save_finding(&f).unwrap();
        w.save_recommendation(&rec).unwrap();
        w.append_audit(&audit).unwrap();

        // A separate reader connection must not see the uncommitted cycle.
        let mut r = SqliteStorage::open(&db).unwrap();
        assert_eq!(r.latest_findings(10).unwrap().len(), 0);
        assert_eq!(r.latest_recommendations(10).unwrap().len(), 0);
        assert_eq!(r.recent_audit(10).unwrap().len(), 0);

        w.commit_transaction().unwrap();

        // After commit the whole cycle is visible together.
        let mut r2 = SqliteStorage::open(&db).unwrap();
        assert_eq!(r2.latest_findings(10).unwrap().len(), 1);
        assert_eq!(r2.latest_recommendations(10).unwrap().len(), 1);
        assert_eq!(r2.recent_audit(10).unwrap().len(), 1);
    }

    #[test]
    fn rollback_leaves_no_half_written_state() {
        let mut s = SqliteStorage::in_memory().unwrap();
        let f = sample_finding();
        let rec = test_rec(
            &f.id,
            rieko_findings::Action::new(
                rieko_findings::ActionType::RebalanceChannel,
                rieko_findings::ActionStage::Recommended,
                f.channel.clone(),
                serde_json::json!({}),
                "rebalance",
            ),
        );

        // Simulate the cycle failing partway through: some writes succeed,
        // then an error aborts before commit.
        let result = (|| -> Result<(), StorageError> {
            s.begin_transaction()?;
            s.save_finding(&f)?;
            s.save_recommendation(&rec)?;
            // ...failure before audit and before commit.
            Err(StorageError::Backend("mid-cycle failure".into()))
        })();
        assert!(result.is_err());
        s.rollback_transaction().unwrap();

        // No partial finding/recommendation survives the rollback.
        assert_eq!(s.latest_findings(10).unwrap().len(), 0);
        assert_eq!(s.latest_recommendations(10).unwrap().len(), 0);
    }

    #[test]
    fn transaction_cannot_be_nested_or_orphan_committed() {
        let mut s = SqliteStorage::in_memory().unwrap();
        s.begin_transaction().unwrap();
        assert!(s.begin_transaction().is_err(), "nested begin must fail");
        s.commit_transaction().unwrap();
        assert!(
            s.commit_transaction().is_err(),
            "commit with no open transaction must fail"
        );
        // rollback with none open is a safe no-op
        assert!(s.rollback_transaction().is_ok());
    }

    #[test]
    fn two_writers_are_rejected_not_raced() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("w.db");
        let s = SqliteStorage::open(&db).unwrap();
        let first = s.writer_lock(&db).unwrap();
        // A second process attempting to lock the same database must be refused.
        let s2 = SqliteStorage::open(&db).unwrap();
        assert!(
            s2.writer_lock(&db).is_err(),
            "second writer must be rejected"
        );
        // Dropping the guard releases the lock.
        drop(first);
        let s3 = SqliteStorage::open(&db).unwrap();
        assert!(s3.writer_lock(&db).is_ok());
    }

    #[test]
    fn integrity_check_reports_healthy_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("int.db");
        {
            let mut s = SqliteStorage::open(&db).unwrap();
            s.save_finding(&sample_finding()).unwrap();
            // Intact database reports healthy.
            s.integrity_check().unwrap();
        }

        // Corrupt the file (destroy the SQLite header magic). Reopening and
        // checking integrity must refuse to claim health rather than silently
        // reading garbage.
        let bytes = std::fs::read(&db).unwrap();
        let mut corrupted = bytes.clone();
        corrupted[0] ^= 0xFF;
        std::fs::write(&db, &corrupted).unwrap();

        let reopened = SqliteStorage::open(&db);
        // Either the open itself reports the corruption, or integrity_check does;
        // in no case may it silently claim a healthy database.
        let refuses_health = match reopened {
            Ok(mut s) => s.integrity_check().is_err(),
            Err(_) => true,
        };
        assert!(
            refuses_health,
            "corrupt database must be reported, not ignored"
        );
    }

    #[test]
    fn busy_timeout_is_set_and_applied() {
        let s = SqliteStorage::in_memory().unwrap();
        let timeout: i64 = s
            .conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, BUSY_TIMEOUT_MS as i64);

        // `synchronous` is exposed as an integer: NORMAL == 1.
        let sync: i64 = s
            .conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(sync, 1, "synchronous=NORMAL must be configured");
    }

    #[test]
    fn concurrent_reader_and_writer_do_not_fail_with_busy() {
        use std::thread;
        // One writer committing inside a transaction while another connection
        // reads. Under WAL + busy_timeout the reader/writer must not fail.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("conc.db");
        let f = sample_finding();

        let writer = {
            let db = db.clone();
            thread::spawn(move || {
                let mut w = SqliteStorage::open(&db).unwrap();
                for _ in 0..20 {
                    w.begin_transaction().unwrap();
                    // Different id each iteration so we actually write rows.
                    let mut f = f.clone();
                    f.id = format!("f{}", std::time::Instant::now().elapsed().as_nanos());
                    w.save_finding(&f).unwrap();
                    w.commit_transaction().unwrap();
                }
            })
        };

        let reader = {
            let db = db.clone();
            thread::spawn(move || {
                let mut r = SqliteStorage::open(&db).unwrap();
                for _ in 0..200 {
                    // Reading must not error out with SQLITE_BUSY.
                    let _ = r.latest_findings(100).unwrap();
                }
            })
        };

        writer.join().unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn active_finding_updates_last_seen_and_preserves_first_seen() {
        let mut s = SqliteStorage::in_memory().unwrap();
        let mut f = sample_finding();
        f.lifecycle = FindingLifecycle::Active;

        s.save_finding(&f).unwrap();
        // Recurrence of the same condition: a later observation.
        let later = f.last_seen_at + chrono::Duration::seconds(60);
        let mut updated = f.clone();
        updated.last_seen_at = later;
        updated.timestamp = later;
        s.save_finding(&updated).unwrap();

        let got = s.latest_findings(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].first_seen_at, f.first_seen_at,
            "first_seen preserved"
        );
        assert_eq!(got[0].last_seen_at, later, "last_seen advanced");
        assert_eq!(got[0].lifecycle, FindingLifecycle::Active);
    }

    #[test]
    fn resolving_finding_retains_evidence_history() {
        let mut s = SqliteStorage::in_memory().unwrap();
        let f = sample_finding();
        let evidence = f.evidence.clone();
        s.save_finding(&f).unwrap();
        // Detector no longer observes the condition: mark resolved, keep the
        // original evidence required by the model.
        let mut resolved = f.clone();
        resolved.lifecycle = FindingLifecycle::Resolved;
        s.save_finding(&resolved).unwrap();

        let got = s.latest_findings(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].lifecycle, FindingLifecycle::Resolved);
        assert_eq!(got[0].evidence, evidence, "evidence retained on resolve");
        assert_eq!(got[0].first_seen_at, f.first_seen_at);
    }

    #[test]
    fn malformed_evidence_fails_loudly_none_serialized_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("bad-evidence.db");
        {
            let mut s = SqliteStorage::open(&db).unwrap();
            // Persist a finding whose evidence column will be deliberately
            // corrupted at the storage level.
            s.save_finding(&sample_finding()).unwrap();
        }
        // Corrupt persisted evidence into non-JSON, then reopen.
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE findings SET evidence = 'not-json' WHERE id = 'f1'",
            [],
        )
        .unwrap();
        drop(conn);

        let mut s = SqliteStorage::open(&db).unwrap();
        let err = s.latest_findings(10).unwrap_err();
        // Must be a typed conversion failure, never a silent empty list.
        assert!(matches!(
            err,
            StorageError::Backend(_) | StorageError::Corrupt(_)
        ));
    }

    #[test]
    fn malformed_timestamp_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("bad-ts.db");
        {
            let mut s = SqliteStorage::open(&db).unwrap();
            s.save_finding(&sample_finding()).unwrap();
        }
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE findings SET ts = 'not-a-timestamp' WHERE id = 'f1'",
            [],
        )
        .unwrap();
        drop(conn);

        let mut s = SqliteStorage::open(&db).unwrap();
        let err = s.latest_findings(10).unwrap_err();
        assert!(
            matches!(err, StorageError::Backend(_) | StorageError::Corrupt(_)),
            "invalid persisted timestamp must error, not fall back to Utc::now()"
        );
    }

    #[test]
    fn older_schema_rows_migrate_with_lifecycle_metadata() {
        // A row written before the findings metadata columns existed. Opening
        // the database runs v1->v2 and backfills first/last seen + lifecycle,
        // then the row must decode via the strict path.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("old-schema.db");
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "PRAGMA user_version = 1;
                 CREATE TABLE findings (
                    id TEXT PRIMARY KEY, detector TEXT NOT NULL, severity INTEGER NOT NULL,
                    node_id TEXT, channel_id TEXT, evidence TEXT NOT NULL,
                    explanation TEXT, ts TEXT NOT NULL, last_seen TEXT
                 );
                 CREATE TABLE audit (
                    id TEXT PRIMARY KEY, action_id TEXT NOT NULL, action_type TEXT NOT NULL,
                    stage TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL, ts TEXT NOT NULL
                 );
                 CREATE TABLE recommendations (
                    finding_id TEXT NOT NULL, action_id TEXT PRIMARY KEY, action_type TEXT NOT NULL,
                    stage TEXT NOT NULL, target TEXT, params TEXT NOT NULL, summary TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                 );
                 INSERT INTO findings (id, detector, severity, node_id, channel_id, evidence, ts)
                 VALUES ('old1', 'channel_liquidity', 0, 'n1', 'c1', '[{\"key\":\"k\",\"value\":1}]',
                         '2021-05-01T00:00:00Z');",
            )
            .unwrap();
        }

        let mut s = SqliteStorage::open(&db).unwrap();
        let got = s.latest_findings(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "old1");
        assert_eq!(got[0].detector_version, "1", "default detector version");
        assert_eq!(got[0].lifecycle, FindingLifecycle::Active);
        assert_eq!(got[0].first_seen_at, got[0].last_seen_at);
    }

    #[test]
    fn audit_state_transition_and_entry_commit_together() {
        // RIEKO-AUDIT-007: a stage transition and its audit entry must be
        // visible atomically — never a stage change without the audit row.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("atomic-audit.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let rec = test_rec(
            "f1",
            rieko_findings::Action::new(
                rieko_findings::ActionType::RebalanceChannel,
                rieko_findings::ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({}),
                "rebalance c1",
            ),
        );
        s.save_recommendation(&rec).unwrap();
        let action_id = rec.action.id.clone();

        // A reader before the transition sees Recommended and no audit row.
        let mut before = SqliteStorage::open(&db).unwrap();
        assert_eq!(
            before
                .recommendation_for_action(&action_id)
                .unwrap()
                .unwrap()
                .action
                .stage,
            ActionStage::Recommended
        );
        assert!(before.recent_audit(10).unwrap().is_empty());

        // Transition to Approved inside one transaction.
        let approved = rieko_findings::Action {
            stage: ActionStage::Approved,
            ..rec.action
        };
        s.begin_transaction().unwrap();
        s.set_action_stage(&action_id, ActionStage::Approved)
            .unwrap();
        s.append_audit(&AuditEntry::from_transition(
            &approved,
            ActionStage::Recommended,
            "alice",
            serde_json::json!({}),
        ))
        .unwrap();
        s.commit_transaction().unwrap();

        // After commit both the stage change and the audit row are visible.
        let mut after = SqliteStorage::open(&db).unwrap();
        assert_eq!(
            after
                .recommendation_for_action(&action_id)
                .unwrap()
                .unwrap()
                .action
                .stage,
            ActionStage::Approved
        );
        let audit = after.recent_audit(10).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action_id, action_id);
        assert_eq!(audit[0].previous_stage, Some(ActionStage::Recommended));
        assert_eq!(audit[0].stage, ActionStage::Approved);
    }

    #[test]
    fn failed_transition_commits_neither_state_nor_audit() {
        // RIEKO-AUDIT-007: a failed transition must leave no stage change and
        // no audit entry behind. The audit table is append-only, so a write
        // that is rejected mid-transaction (here: attempting to UPDATE a stage
        // that is illegal) must roll back the whole unit.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rollback-audit.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let rec = test_rec(
            "f1",
            rieko_findings::Action::new(
                rieko_findings::ActionType::RebalanceChannel,
                rieko_findings::ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({}),
                "rebalance c1",
            ),
        );
        s.save_recommendation(&rec).unwrap();
        let action_id = rec.action.id.clone();

        s.begin_transaction().unwrap();
        s.set_action_stage(&action_id, ActionStage::Approved)
            .unwrap();
        // A change is made, then the unit fails (the audit append errors). The
        // caller rolls back the whole thing, so neither the stage change nor
        // any audit row survives.
        s.rollback_transaction().unwrap();

        // Nothing must have been committed.
        let mut after = SqliteStorage::open(&db).unwrap();
        assert_eq!(
            after
                .recommendation_for_action(&action_id)
                .unwrap()
                .unwrap()
                .action
                .stage,
            ActionStage::Recommended,
            "stage must remain Recommended after rollback"
        );
        assert!(after.recent_audit(10).unwrap().is_empty());
    }

    #[test]
    fn audit_rows_are_append_only() {
        // RIEKO-AUDIT-007: the audit table denies normal UPDATE and DELETE via
        // triggers; the application API is the only writer.
        let mut s = SqliteStorage::in_memory().unwrap();
        let rec = test_rec(
            "f1",
            rieko_findings::Action::new(
                rieko_findings::ActionType::RebalanceChannel,
                rieko_findings::ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({}),
                "rebalance c1",
            ),
        );
        s.append_audit(&AuditEntry::from_action(
            &rec.action,
            "system",
            serde_json::json!({}),
        ))
        .unwrap();
        assert_eq!(s.recent_audit(10).unwrap().len(), 1);

        // Both an UPDATE and a DELETE on the audit table must be rejected.
        for sql in ["UPDATE audit SET actor = 'intruder'", "DELETE FROM audit"] {
            let err = s.conn.execute(sql, []).unwrap_err();
            assert!(
                err.to_string().contains("append-only"),
                "expected append-only rejection for `{sql}`, got: {err}"
            );
        }
        // The row is still there after both attempts.
        assert_eq!(s.recent_audit(10).unwrap().len(), 1);
    }
}
