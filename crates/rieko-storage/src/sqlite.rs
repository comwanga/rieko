use std::path::Path;

use chrono::{DateTime, Utc};
use rieko_alerts::{AlertError, AlertState, AlertStateStore};
use rieko_domain::ChannelSnapshot;
use rieko_findings::{
    ActionStage, AuditEntry, Finding, FindingCycleScope, FindingLifecycle, FindingLifecycleFilter,
    FindingProvenance, Recommendation, Simulation,
};
use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::{SimulationCounts, StorageCounts, StorageError};
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
            2 => Severity::Critical,
            value => {
                return Err(invalid_finding_column(
                    2,
                    format!("invalid severity {value}"),
                ))
            }
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
        let schema_raw: i64 = row.get(9)?;
        let schema_version = u8::try_from(schema_raw).map_err(|_| {
            invalid_finding_column(9, format!("invalid schema version {schema_raw}"))
        })?;
        crate::storage::validate_finding_schema(schema_version)
            .map_err(|e| invalid_finding_column(9, e.to_string()))?;
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
            "active" => FindingLifecycle::Active,
            "resolved" => FindingLifecycle::Resolved,
            value => {
                return Err(invalid_finding_column(
                    12,
                    format!("invalid lifecycle {value:?}"),
                ))
            }
        };
        let provenance_json: Option<String> = row.get(13)?;
        let provenance: Option<FindingProvenance> = provenance_json
            .map(|json| {
                serde_json::from_str(&json).map_err(|e| {
                    invalid_finding_column(13, format!("invalid provenance {json:?}: {e}"))
                })
            })
            .transpose()?;
        Ok(Finding {
            id: row.get(0)?,
            detector: row.get(1)?,
            detector_version,
            schema_version,
            severity,
            node: row.get::<_, Option<String>>(3)?,
            channel: row.get::<_, Option<String>>(4)?,
            evidence,
            provenance,
            explanation: row.get::<_, Option<String>>(6)?,
            timestamp,
            first_seen_at,
            last_seen_at,
            lifecycle,
        })
    }

    fn row_to_recommendation(row: &rusqlite::Row) -> rusqlite::Result<Recommendation> {
        use rieko_findings::Action;

        let action_type_raw: String = row.get(2)?;
        let action_type = parse_action_type(&action_type_raw)
            .map_err(|message| invalid_storage_column(2, message))?;
        let stage_raw: String = row.get(3)?;
        let stage =
            parse_action_stage(&stage_raw).map_err(|message| invalid_storage_column(3, message))?;
        let params_raw: String = row.get(5)?;
        let params = serde_json::from_str(&params_raw).map_err(|error| {
            invalid_storage_column(5, format!("invalid recommendation params: {error}"))
        })?;
        let rationale_raw: String = row.get(7)?;
        let rationale = serde_json::from_str(&rationale_raw).map_err(|error| {
            invalid_storage_column(7, format!("invalid recommendation rationale: {error}"))
        })?;
        let created_at = parse_persisted_timestamp(8, "recommendation created_at", row.get(8)?)?;
        let updated_at = parse_persisted_timestamp(9, "recommendation updated_at", row.get(9)?)?;
        Ok(Recommendation {
            finding_id: row.get(0)?,
            action: Action {
                id: row.get(1)?,
                action_type,
                stage,
                target: row.get(4)?,
                params,
                summary: row.get(6)?,
                created_at,
                updated_at,
            },
            rationale,
        })
    }

    fn row_to_snapshot(row: &rusqlite::Row) -> rusqlite::Result<ChannelSnapshot> {
        let status_int: u32 = row.get(6)?;
        let ts = parse_persisted_timestamp(1, "snapshot timestamp", row.get(1)?)?;
        let network = row
            .get::<_, Option<String>>(10)?
            .map(|network_id| {
                serde_json::from_value(serde_json::Value::String(network_id.clone())).map_err(
                    |error| {
                        invalid_storage_column(
                            10,
                            format!("invalid snapshot network_id {network_id:?}: {error}"),
                        )
                    },
                )
            })
            .transpose()?;
        Ok(ChannelSnapshot {
            node_id: row.get(9)?,
            network,
            channel_id: row.get(0)?,
            local_ratio: row.get(2)?,
            local_balance_msat: row.get(3)?,
            remote_balance_msat: row.get(4)?,
            capacity_msat: row.get(5)?,
            status: status_from_i64(status_int)
                .map_err(|message| invalid_storage_column(6, message))?,
            ts,
            spendable_outbound_msat: row.get(7)?,
            spendable_inbound_msat: row.get(8)?,
            state_digest: row.get(11)?,
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
            return Err(StorageError::Backend(
                "rollback with no open transaction".into(),
            ));
        }
        self.conn
            .execute_batch("ROLLBACK")
            .map_err(|e| StorageError::Backend(format!("rolling back transaction: {e}")))?;
        self.in_transaction = false;
        Ok(())
    }

    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError> {
        crate::storage::validate_finding_schema(finding.schema_version)?;
        let severity = finding.severity as i64;
        let evidence = serde_json::to_string(&finding.evidence)
            .map_err(|e| StorageError::Corrupt(format!("finding evidence: {e}")))?;
        let provenance = finding
            .provenance
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StorageError::Corrupt(format!("finding provenance: {e}")))?;
        self.conn.execute(
            "INSERT INTO findings (id, detector, detector_version, severity, node_id, channel_id,
                     evidence, provenance, explanation, ts, first_seen_at, last_seen_at,
                     lifecycle, schema_version, consecutive_absent)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                      MIN(?11, COALESCE((
                         SELECT MIN(first_seen_at) FROM findings
                         WHERE detector = ?2 AND detector_version = ?3
                           AND node_id IS ?5 AND channel_id IS ?6
                           AND json_extract(provenance, '$.network') IS
                               json_extract(?8, '$.network')
                      ), ?11)), ?12, 'active', ?13, 0)
              ON CONFLICT(id) DO UPDATE SET
                first_seen_at = MIN(findings.first_seen_at, excluded.first_seen_at),
                severity = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN excluded.severity ELSE findings.severity END,
                evidence = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN excluded.evidence ELSE findings.evidence END,
                provenance = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN excluded.provenance ELSE findings.provenance END,
                explanation = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN excluded.explanation ELSE findings.explanation END,
                schema_version = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN excluded.schema_version ELSE findings.schema_version END,
                ts = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN excluded.ts ELSE findings.ts END,
                last_seen_at = MAX(findings.last_seen_at, excluded.last_seen_at),
                lifecycle = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN 'active' ELSE findings.lifecycle END,
                consecutive_absent = CASE WHEN excluded.last_seen_at >= findings.last_seen_at
                    THEN 0 ELSE findings.consecutive_absent END",
            params![
                finding.id,
                finding.detector,
                finding.detector_version,
                severity,
                finding.node,
                finding.channel,
                evidence,
                provenance,
                finding.explanation,
                finding.timestamp.to_rfc3339(),
                finding.first_seen_at.to_rfc3339(),
                finding.last_seen_at.to_rfc3339(),
                finding.schema_version,
            ],
        )?;
        Ok(())
    }

    fn resolve_findings_for_scope(
        &mut self,
        scope: &FindingCycleScope,
    ) -> Result<(), StorageError> {
        if scope.complete {
            // Hysteresis: only resolve findings that have been absent for at
            // least 2 consecutive complete cycles. Findings absent for exactly
            // 0–1 cycles get their counter incremented instead.
            self.conn.execute(
                "UPDATE findings SET lifecycle = 'resolved', consecutive_absent = 0
                 WHERE detector = ?1 AND node_id IS ?2
                   AND json_extract(provenance, '$.network') IS ?3
                   AND lifecycle = 'active'
                   AND consecutive_absent >= 2",
                params![
                    scope.detector,
                    scope.node,
                    scope.network.map(|network| network.to_string())
                ],
            )?;
            self.conn.execute(
                "UPDATE findings SET consecutive_absent = consecutive_absent + 1
                 WHERE detector = ?1 AND node_id IS ?2
                   AND json_extract(provenance, '$.network') IS ?3
                   AND lifecycle = 'active'
                   AND consecutive_absent < 2",
                params![
                    scope.detector,
                    scope.node,
                    scope.network.map(|network| network.to_string())
                ],
            )?;
        }
        Ok(())
    }

    fn latest_findings(&mut self, limit: u32) -> Result<Vec<Finding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                    detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                    provenance
             FROM findings ORDER BY ts DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_finding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn finding_by_id(&mut self, finding_id: &str) -> Result<Option<Finding>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                        detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                        provenance
                 FROM findings WHERE id = ?1",
                [finding_id],
                Self::row_to_finding,
            )
            .optional()
            .map_err(Into::into)
    }

    fn latest_findings_by_lifecycle(
        &mut self,
        limit: u32,
        lifecycle: FindingLifecycleFilter,
    ) -> Result<Vec<Finding>, StorageError> {
        let sql = match lifecycle {
            FindingLifecycleFilter::Active => {
                "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                        detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                        provenance
                 FROM findings WHERE lifecycle = 'active' ORDER BY ts DESC LIMIT ?"
            }
            FindingLifecycleFilter::Resolved => {
                "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                        detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                        provenance
                 FROM findings WHERE lifecycle = 'resolved' ORDER BY ts DESC LIMIT ?"
            }
            FindingLifecycleFilter::All => {
                return self.latest_findings(limit);
            }
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([limit], Self::row_to_finding)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn findings_for_channel(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<Finding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                    detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                    provenance
             FROM findings WHERE channel_id = ? ORDER BY ts DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(rusqlite::params![channel_id, limit], Self::row_to_finding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn findings_for_channel_by_lifecycle(
        &mut self,
        channel_id: &str,
        limit: u32,
        lifecycle: FindingLifecycleFilter,
    ) -> Result<Vec<Finding>, StorageError> {
        let sql = match lifecycle {
            FindingLifecycleFilter::Active => {
                "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                        detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                        provenance
                 FROM findings WHERE channel_id = ?1 AND lifecycle = 'active'
                 ORDER BY ts DESC LIMIT ?2"
            }
            FindingLifecycleFilter::Resolved => {
                "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts,
                        detector_version, schema_version, first_seen_at, last_seen_at, lifecycle,
                        provenance
                 FROM findings WHERE channel_id = ?1 AND lifecycle = 'resolved'
                 ORDER BY ts DESC LIMIT ?2"
            }
            FindingLifecycleFilter::All => {
                return self.findings_for_channel(channel_id, limit);
            }
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![channel_id, limit], Self::row_to_finding)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
        let rows = stmt.query_map([limit], Self::row_to_recommendation)?;
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
        let mut rows = stmt.query_map([action_id], Self::row_to_recommendation)?;
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
            let action_type_raw: String = row.get(2)?;
            let action_type = parse_action_type(&action_type_raw)
                .map_err(|message| invalid_storage_column(2, message))?;
            let previous_stage = row
                .get::<_, Option<String>>(3)?
                .map(|stage| {
                    parse_action_stage(&stage).map_err(|message| invalid_storage_column(3, message))
                })
                .transpose()?;
            let stage_raw: String = row.get(4)?;
            let stage = parse_action_stage(&stage_raw)
                .map_err(|message| invalid_storage_column(4, message))?;
            let details_raw: String = row.get(6)?;
            let details = serde_json::from_str(&details_raw).map_err(|error| {
                invalid_storage_column(6, format!("invalid audit details: {error}"))
            })?;
            let timestamp = parse_persisted_timestamp(7, "audit timestamp", row.get(7)?)?;
            Ok(AuditEntry {
                id: row.get(0)?,
                action_id: row.get(1)?,
                action_type,
                previous_stage,
                stage,
                actor: row.get(5)?,
                details,
                timestamp,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn save_channel_snapshot(&mut self, snapshot: &ChannelSnapshot) -> Result<(), StorageError> {
        let network_id = snapshot
            .network
            .as_ref()
            .map(|network| {
                serde_json::to_value(network)
                    .map_err(|error| StorageError::Corrupt(format!("snapshot network: {error}")))
                    .and_then(|value| {
                        value.as_str().map(str::to_owned).ok_or_else(|| {
                            StorageError::Corrupt(
                                "snapshot network did not encode as a string".into(),
                            )
                        })
                    })
            })
            .transpose()?;
        self.conn.execute(
            "INSERT OR REPLACE INTO channel_snapshots
             (channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat, capacity_msat,
               status_int, spendable_outbound_msat, spendable_inbound_msat, node_id,
               network_id, state_digest)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                snapshot.channel_id,
                snapshot.ts.to_rfc3339(),
                snapshot.local_ratio,
                snapshot.local_balance_msat,
                snapshot.remote_balance_msat,
                snapshot.capacity_msat,
                snapshot.status as i64,
                snapshot.spendable_outbound_msat,
                snapshot.spendable_inbound_msat,
                snapshot.node_id,
                network_id,
                snapshot.state_digest,
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
            "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
                    capacity_msat, status_int, spendable_outbound_msat,
                    spendable_inbound_msat, node_id, network_id, state_digest
             FROM channel_snapshots WHERE channel_id = ?1 ORDER BY ts DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![channel_id, limit], Self::row_to_snapshot)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn recent_channel_snapshots_for_node(
        &mut self,
        node_id: &str,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<ChannelSnapshot>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
                    capacity_msat, status_int, spendable_outbound_msat,
                    spendable_inbound_msat, node_id, network_id, state_digest
             FROM channel_snapshots
             WHERE node_id = ?1 AND channel_id = ?2
             ORDER BY ts DESC LIMIT ?3",
        )?;
        let rows =
            statement.query_map(params![node_id, channel_id, limit], Self::row_to_snapshot)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn recent_channel_snapshots_for_network(
        &mut self,
        network: rieko_domain::BitcoinNetwork,
        node_id: Option<&str>,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<ChannelSnapshot>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
                    capacity_msat, status_int, spendable_outbound_msat,
                    spendable_inbound_msat, node_id, network_id, state_digest
             FROM channel_snapshots
             WHERE network_id = ?1
               AND (?2 IS NULL OR node_id = ?2)
               AND channel_id = ?3
             ORDER BY ts DESC LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![network.to_string(), node_id, channel_id, limit],
            Self::row_to_snapshot,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn channel_snapshot_at(
        &mut self,
        network: rieko_domain::BitcoinNetwork,
        node_id: &str,
        channel_id: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<ChannelSnapshot>, StorageError> {
        self.conn
            .query_row(
                "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
                        capacity_msat, status_int, spendable_outbound_msat,
                        spendable_inbound_msat, node_id, network_id, state_digest
                 FROM channel_snapshots
                 WHERE network_id = ?1 AND node_id = ?2 AND channel_id = ?3 AND ts = ?4",
                params![
                    network.to_string(),
                    node_id,
                    channel_id,
                    observed_at.to_rfc3339()
                ],
                Self::row_to_snapshot,
            )
            .optional()
            .map_err(Into::into)
    }

    fn recent_snapshots_all(&mut self, limit: u32) -> Result<Vec<ChannelSnapshot>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
                    capacity_msat, status_int, spendable_outbound_msat,
                    spendable_inbound_msat, node_id, network_id, state_digest
             FROM channel_snapshots ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_snapshot)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn prune_channel_snapshots(
        &mut self,
        policy: &crate::RetentionPolicy,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::PruneSummary, StorageError> {
        // Runs in one transaction so the pass is atomic (RIEKO-AUDIT-016).
        // Work is bounded: each statement deletes at most CHUNK rows, looped
        // until nothing remains, so a very large table is pruned without a
        // single unbounded statement. Only channel_snapshots is ever touched.
        const CHUNK: usize = 2000;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| StorageError::Backend(format!("starting cleanup: {e}")))?;
        let mut deleted = 0usize;

        let active_cutoff = now
            - chrono::Duration::from_std(policy.snapshot_max_age)
                .unwrap_or(chrono::Duration::zero());
        let closed_cutoff = now
            - chrono::Duration::from_std(policy.closed_channel_max_age)
                .unwrap_or(chrono::Duration::zero());
        // Closed/terminated status ints: Closed=4, Closing=3, WaitingClose=6,
        // ForceClosing=7 (see rieko_domain::ChannelStatus). Each statement
        // deletes at most CHUNK rows via a bounded rowid subquery (SQLite has
        // no `LIMIT` on DELETE).
        loop {
            let n = tx
                .execute(
                    "DELETE FROM channel_snapshots
                     WHERE rowid IN (
                        SELECT rowid FROM channel_snapshots
                        WHERE ts < ?1 AND status_int NOT IN (3, 4, 6, 7)
                           OR ts < ?2 AND status_int IN (3, 4, 6, 7)
                        LIMIT ?3
                     )",
                    params![
                        active_cutoff.to_rfc3339(),
                        closed_cutoff.to_rfc3339(),
                        CHUNK as i64
                    ],
                )
                .map_err(|e| StorageError::Backend(format!("pruning stale snapshots: {e}")))?;
            deleted += n;
            if n == 0 {
                break;
            }
        }

        // Per-channel cap: keep the newest `cap` per channel.
        if let Some(cap) = policy.max_snapshots_per_channel {
            if cap > 0 {
                loop {
                    let n = tx
                        .execute(
                            "DELETE FROM channel_snapshots
                             WHERE rowid IN (
                                SELECT rowid FROM (
                                    SELECT rowid,
                                           ROW_NUMBER() OVER (
                                                PARTITION BY network_id, node_id, channel_id ORDER BY ts DESC
                                           ) AS rn
                                    FROM channel_snapshots
                                ) WHERE rn > ?1
                                LIMIT ?2
                             )",
                            params![cap as i64, CHUNK as i64],
                        )
                        .map_err(|e| {
                            StorageError::Backend(format!("pruning per-channel cap: {e}"))
                        })?;
                    deleted += n;
                    if n == 0 {
                        break;
                    }
                }
            }
        }

        // Absolute total cap: keep the newest `total` rows overall.
        if let Some(total) = policy.max_total_snapshots {
            if total > 0 {
                loop {
                    let n = tx
                        .execute(
                            "DELETE FROM channel_snapshots
                             WHERE rowid IN (
                                SELECT rowid FROM channel_snapshots
                                ORDER BY ts DESC LIMIT ?1 OFFSET ?2
                             )",
                            params![CHUNK as i64, total as i64],
                        )
                        .map_err(|e| StorageError::Backend(format!("pruning total cap: {e}")))?;
                    deleted += n;
                    if n == 0 {
                        break;
                    }
                }
            }
        }

        tx.commit()
            .map_err(|e| StorageError::Backend(format!("committing cleanup: {e}")))?;
        Ok(crate::PruneSummary {
            deleted_snapshots: deleted,
            complete: true,
        })
    }

    fn save_simulation(&mut self, sim: &Simulation) -> Result<(), StorageError> {
        let projection = serde_json::to_string(&sim.projection)
            .map_err(|e| StorageError::Corrupt(format!("simulation projection: {e}")))?;
        self.conn.execute(
            "INSERT INTO simulations
             (id, action_id, finding_id, action_type, projection, created_at,
              requested_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)",
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
             FROM simulations WHERE model_id = 'legacy' ORDER BY created_at DESC LIMIT ?",
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
             FROM simulations WHERE action_id = ? AND model_id = 'legacy'
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([action_id], Self::row_to_simulation)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ── V2 simulation persistence (ADR-0005) ──────────────────────────

    fn save_simulation_v2(&mut self, rec: &crate::SimulationRecord) -> Result<(), StorageError> {
        validate_simulation_record(rec)?;
        let proj = serde_json::to_string(&rec.projection)
            .map_err(|e| StorageError::Corrupt(format!("simulation projection: {e}")))?;
        let canonical_input =
            if rec.canonical_input.is_null() {
                None
            } else {
                Some(serde_json::to_string(&rec.canonical_input).map_err(|e| {
                    StorageError::Corrupt(format!("canonical simulation input: {e}"))
                })?)
            };
        let assumptions = serde_json::to_string(&rec.assumptions)
            .map_err(|e| StorageError::Corrupt(format!("assumptions: {e}")))?;
        let warnings = serde_json::to_string(&rec.warnings)
            .map_err(|e| StorageError::Corrupt(format!("warnings: {e}")))?;
        self.conn.execute(
            "INSERT INTO simulations
             (id, action_id, finding_id, action_type, status, model_id, model_version,
               input_hash, confidence, assumptions, warnings, explanation, projection, created_at,
               canonical_input, source_observed_at, requested_at, completed_at, error_code)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            params![
                rec.id,
                rec.action_id,
                rec.finding_id,
                rec.action_type,
                rec.status,
                rec.model_id,
                rec.model_version,
                rec.input_hash,
                rec.confidence,
                assumptions,
                warnings,
                rec.explanation,
                proj,
                rec.created_at,
                canonical_input,
                rec.source_observed_at,
                rec.requested_at,
                rec.completed_at,
                rec.error_code,
            ],
        )?;
        Ok(())
    }

    fn recent_simulations_v2(
        &mut self,
        limit: u32,
    ) -> Result<Vec<crate::SimulationRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action_id, finding_id, action_type, status, model_id, model_version,
                    input_hash, confidence, assumptions, warnings, explanation, projection, created_at,
                    canonical_input, source_observed_at, requested_at, completed_at, error_code
             FROM simulations ORDER BY created_at DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_simulation_v2)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn recent_replayable_simulations_v2(
        &mut self,
        limit: u32,
    ) -> Result<Vec<crate::SimulationRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action_id, finding_id, action_type, status, model_id, model_version,
                    input_hash, confidence, assumptions, warnings, explanation, projection, created_at,
                    canonical_input, source_observed_at, requested_at, completed_at, error_code
             FROM simulations
             WHERE canonical_input IS NOT NULL AND canonical_input <> 'null'
             ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_simulation_v2)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn simulations_v2_for_action(
        &mut self,
        action_id: &str,
    ) -> Result<Vec<crate::SimulationRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action_id, finding_id, action_type, status, model_id, model_version,
                    input_hash, confidence, assumptions, warnings, explanation, projection, created_at,
                    canonical_input, source_observed_at, requested_at, completed_at, error_code
             FROM simulations WHERE action_id = ? ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([action_id], Self::row_to_simulation_v2)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn simulation_v2_by_id(
        &mut self,
        simulation_id: &str,
    ) -> Result<Option<crate::SimulationRecord>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, action_id, finding_id, action_type, status, model_id, model_version,
                        input_hash, confidence, assumptions, warnings, explanation, projection,
                        created_at, canonical_input, source_observed_at, requested_at,
                        completed_at, error_code
                 FROM simulations WHERE id = ?1",
                [simulation_id],
                Self::row_to_simulation_v2,
            )
            .optional()
            .map_err(Into::into)
    }

    fn replayable_simulation_v2_by_id(
        &mut self,
        simulation_id: &str,
    ) -> Result<Option<crate::SimulationRecord>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, action_id, finding_id, action_type, status, model_id, model_version,
                        input_hash, confidence, assumptions, warnings, explanation, projection,
                        created_at, canonical_input, source_observed_at, requested_at,
                        completed_at, error_code
                 FROM simulations
                 WHERE id = ?1 AND canonical_input IS NOT NULL AND canonical_input <> 'null'",
                [simulation_id],
                Self::row_to_simulation_v2,
            )
            .optional()
            .map_err(Into::into)
    }

    fn simulation_v2_by_input_hash(
        &mut self,
        input_hash: &str,
    ) -> Result<Option<crate::SimulationRecord>, StorageError> {
        if input_hash.is_empty() {
            return Ok(None);
        }
        self.conn
            .query_row(
                "SELECT id, action_id, finding_id, action_type, status, model_id, model_version,
                        input_hash, confidence, assumptions, warnings, explanation, projection,
                        created_at, canonical_input, source_observed_at, requested_at,
                        completed_at, error_code
                 FROM simulations
                 WHERE input_hash = ?1
                   AND canonical_input IS NOT NULL AND canonical_input <> 'null'
                 ORDER BY created_at DESC
                 LIMIT 1",
                [input_hash],
                Self::row_to_simulation_v2,
            )
            .optional()
            .map_err(Into::into)
    }

    fn append_simulation_event(
        &mut self,
        event: &crate::SimulationEvent,
    ) -> Result<(), StorageError> {
        validate_simulation_status(&event.status)?;
        validate_rfc3339("simulation event timestamp", &event.timestamp)?;
        self.conn.execute(
            "INSERT INTO simulation_events (id, simulation_id, status, error_code, ts)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.id,
                event.simulation_id,
                event.status,
                event.error_code,
                event.timestamp
            ],
        )?;
        Ok(())
    }

    fn simulation_events(
        &mut self,
        simulation_id: &str,
    ) -> Result<Vec<crate::SimulationEvent>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT id, simulation_id, status, error_code, ts
             FROM simulation_events WHERE simulation_id = ?1 ORDER BY ts",
        )?;
        let rows = statement.query_map([simulation_id], |row| {
            let status: String = row.get(2)?;
            validate_simulation_status(&status)
                .map_err(|error| invalid_simulation_column(2, error.to_string()))?;
            let timestamp: String = row.get(4)?;
            validate_rfc3339("simulation event timestamp", &timestamp)
                .map_err(|error| invalid_simulation_column(4, error.to_string()))?;
            Ok(crate::SimulationEvent {
                id: row.get(0)?,
                simulation_id: row.get(1)?,
                status,
                error_code: row.get(3)?,
                timestamp,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn counts(&mut self) -> Result<StorageCounts, StorageError> {
        let count = |table: &str| -> Result<usize, StorageError> {
            let n: i64 =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
            Ok(n as usize)
        };
        let sim_counts = simulation_status_counts(&self.conn)?;
        Ok(StorageCounts {
            findings: count("findings")?,
            recommendations: count("recommendations")?,
            simulations: count("simulations")?,
            audit: count("audit")?,
            channel_snapshots: count("channel_snapshots")?,
            simulation_counts: sim_counts,
        })
    }
}

fn simulation_status_counts(conn: &Connection) -> Result<SimulationCounts, StorageError> {
    let mut stmt = conn
        .prepare("SELECT status, COUNT(*) FROM simulations WHERE status != '' GROUP BY status")
        .map_err(|e| StorageError::Backend(format!("preparing simulation counts: {e}")))?;
    let mut completed = 0usize;
    let mut failed = 0usize;
    let mut stale = 0usize;
    let mut other = 0usize;
    for row in stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|e| StorageError::Backend(format!("querying simulation counts: {e}")))?
    {
        let (status, count) =
            row.map_err(|e| StorageError::Backend(format!("reading simulation count row: {e}")))?;
        let count = count as usize;
        match status.as_str() {
            "completed" => completed = count,
            "failed" | "invalid_input" | "unsupported" => failed += count,
            "stale" => stale = count,
            _ => other += count,
        }
    }
    Ok(SimulationCounts {
        completed,
        failed,
        stale,
        other,
    })
}

impl SqliteStorage {
    fn row_to_simulation(row: &rusqlite::Row) -> rusqlite::Result<Simulation> {
        use rieko_findings::ActionType;
        let action_type = match row.get::<_, String>(3)?.as_str() {
            "update_fee_policy" => ActionType::UpdateFeePolicy,
            "restart_service" => ActionType::RestartService,
            "custom" => ActionType::Custom,
            "rebalance_channel" => ActionType::RebalanceChannel,
            value => {
                return Err(invalid_simulation_column(
                    3,
                    format!("invalid simulation action type {value:?}"),
                ))
            }
        };
        let projection_raw: String = row.get(4)?;
        let projection = serde_json::from_str(&projection_raw).map_err(|error| {
            invalid_simulation_column(4, format!("invalid legacy simulation projection: {error}"))
        })?;
        let created_at_raw: String = row.get(5)?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_raw)
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .map_err(|error| {
                invalid_simulation_column(
                    5,
                    format!("invalid simulation timestamp {created_at_raw:?}: {error}"),
                )
            })?;
        Ok(Simulation {
            id: row.get(0)?,
            action_id: row.get(1)?,
            finding_id: row.get(2)?,
            action_type,
            projection,
            created_at,
        })
    }

    fn row_to_simulation_v2(row: &rusqlite::Row) -> rusqlite::Result<crate::SimulationRecord> {
        let status: String = row.get(4)?;
        validate_simulation_status(&status)
            .map_err(|error| invalid_simulation_column(4, error.to_string()))?;
        let confidence: String = row.get(8)?;
        if !matches!(confidence.as_str(), "high" | "medium" | "low" | "unknown") {
            return Err(invalid_simulation_column(
                8,
                format!("invalid simulation confidence {confidence:?}"),
            ));
        }
        let parse_json = |index| -> rusqlite::Result<serde_json::Value> {
            let raw: String = row.get(index)?;
            serde_json::from_str(&raw).map_err(|error| {
                invalid_simulation_column(index, format!("invalid simulation JSON: {error}"))
            })
        };
        let created_at: String = row.get(13)?;
        validate_rfc3339("simulation created_at", &created_at)
            .map_err(|error| invalid_simulation_column(13, error.to_string()))?;
        let source_observed_at: Option<String> = row.get(15)?;
        if let Some(timestamp) = &source_observed_at {
            validate_rfc3339("simulation source_observed_at", timestamp)
                .map_err(|error| invalid_simulation_column(15, error.to_string()))?;
        }
        let requested_at: String = row.get(16)?;
        validate_rfc3339("simulation requested_at", &requested_at)
            .map_err(|error| invalid_simulation_column(16, error.to_string()))?;
        let completed_at: Option<String> = row.get(17)?;
        if let Some(timestamp) = &completed_at {
            validate_rfc3339("simulation completed_at", timestamp)
                .map_err(|error| invalid_simulation_column(17, error.to_string()))?;
        }
        let record = crate::SimulationRecord {
            id: row.get(0)?,
            action_id: row.get(1)?,
            finding_id: row.get(2)?,
            action_type: row.get(3)?,
            status,
            model_id: row.get(5)?,
            model_version: row.get(6)?,
            input_hash: row.get(7)?,
            confidence,
            assumptions: parse_json(9)?,
            warnings: parse_json(10)?,
            explanation: row.get(11)?,
            projection: parse_json(12)?,
            canonical_input: row
                .get::<_, Option<String>>(14)?
                .map(|raw| {
                    serde_json::from_str(&raw).map_err(|error| {
                        invalid_simulation_column(
                            14,
                            format!("invalid canonical simulation input: {error}"),
                        )
                    })
                })
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
            source_observed_at,
            requested_at,
            completed_at,
            error_code: row.get(18)?,
            created_at,
        };
        validate_simulation_record(&record)
            .map_err(|error| invalid_simulation_column(14, error.to_string()))?;
        Ok(record)
    }
}

fn validate_simulation_record(rec: &crate::SimulationRecord) -> Result<(), StorageError> {
    validate_simulation_status(&rec.status)?;
    if !matches!(
        rec.confidence.as_str(),
        "high" | "medium" | "low" | "unknown"
    ) {
        return Err(StorageError::Corrupt(format!(
            "invalid simulation confidence {:?}",
            rec.confidence
        )));
    }
    if !rec.input_hash.is_empty()
        && (rec.input_hash.len() != 64
            || !rec.input_hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(StorageError::Corrupt(
            "invalid simulation input hash".into(),
        ));
    }
    validate_rfc3339("simulation created_at", &rec.created_at)?;
    validate_rfc3339("simulation requested_at", &rec.requested_at)?;
    if let Some(timestamp) = &rec.source_observed_at {
        validate_rfc3339("simulation source_observed_at", timestamp)?;
    }
    if let Some(timestamp) = &rec.completed_at {
        validate_rfc3339("simulation completed_at", timestamp)?;
    }
    if !rec.canonical_input.is_null() {
        use sha2::{Digest, Sha256};

        let canonical = serde_json::to_vec(&rec.canonical_input).map_err(|error| {
            StorageError::Corrupt(format!("encoding canonical simulation input: {error}"))
        })?;
        let mut hash = Sha256::new();
        hash.update(b"rieko-simulation-input-v3");
        hash.update((canonical.len() as u64).to_be_bytes());
        hash.update(canonical);
        let expected_hash = format!("{:x}", hash.finalize());
        if rec.input_hash != expected_hash {
            return Err(StorageError::Corrupt(
                "simulation input hash does not match canonical input".into(),
            ));
        }
        for (field, expected) in [
            ("recommendation_id", rec.action_id.as_str()),
            ("finding_id", rec.finding_id.as_str()),
            ("model_id", rec.model_id.as_str()),
            ("model_version", rec.model_version.as_str()),
        ] {
            if rec.canonical_input[field].as_str() != Some(expected) {
                return Err(StorageError::Corrupt(format!(
                    "canonical simulation input {field} disagrees with record"
                )));
            }
        }
        let canonical_action_type = match rec.canonical_input["action_type"].as_str() {
            Some("RebalanceChannel") => "rebalance_channel",
            Some("UpdateFeePolicy") => "update_fee_policy",
            Some("RestartService") => "restart_service",
            Some("Custom") => "custom",
            _ => {
                return Err(StorageError::Corrupt(
                    "canonical simulation input has invalid action_type".into(),
                ))
            }
        };
        if canonical_action_type != rec.action_type {
            return Err(StorageError::Corrupt(
                "canonical simulation action type disagrees with record".into(),
            ));
        }
        let canonical_source = rec.canonical_input["source_snapshot"]["ts"]
            .as_str()
            .ok_or_else(|| {
                StorageError::Corrupt("canonical simulation input has no source timestamp".into())
            })?;
        let recorded_source = rec.source_observed_at.as_deref().ok_or_else(|| {
            StorageError::Corrupt("simulation record has no source timestamp".into())
        })?;
        let canonical_source = DateTime::parse_from_rfc3339(canonical_source).map_err(|error| {
            StorageError::Corrupt(format!("invalid canonical source timestamp: {error}"))
        })?;
        let recorded_source = DateTime::parse_from_rfc3339(recorded_source).map_err(|error| {
            StorageError::Corrupt(format!("invalid recorded source timestamp: {error}"))
        })?;
        if canonical_source != recorded_source {
            return Err(StorageError::Corrupt(format!(
                "simulation source timestamp {recorded_source} disagrees with canonical input {canonical_source}"
            )));
        }
    }
    if !rec.canonical_input.is_null() && !rec.projection.is_null() {
        for (field, expected) in [
            ("model_id", rec.model_id.as_str()),
            ("model_version", rec.model_version.as_str()),
            ("input_hash", rec.input_hash.as_str()),
        ] {
            if rec.projection[field].as_str() != Some(expected) {
                return Err(StorageError::Corrupt(format!(
                    "simulation projection {field} disagrees with record"
                )));
            }
        }
        if rec.projection["assumptions"] != rec.assumptions
            || rec.projection["warnings"] != rec.warnings
            || rec.projection["confidence"].as_str() != Some(rec.confidence.as_str())
        {
            return Err(StorageError::Corrupt(
                "simulation projection metadata disagrees with record".into(),
            ));
        }
    }
    match rec.status.as_str() {
        "completed" if rec.projection.is_null() => {
            return Err(StorageError::Corrupt(
                "completed simulation has no deterministic projection".into(),
            ));
        }
        "unsupported" | "invalid_input" | "failed" if !rec.projection.is_null() => {
            return Err(StorageError::Corrupt(format!(
                "{} simulation must not contain a projection",
                rec.status
            )));
        }
        _ => {}
    }
    Ok(())
}

fn validate_simulation_status(status: &str) -> Result<(), StorageError> {
    if matches!(
        status,
        "requested" | "completed" | "unsupported" | "invalid_input" | "stale" | "failed"
    ) {
        Ok(())
    } else {
        Err(StorageError::Corrupt(format!(
            "invalid simulation status {status:?}"
        )))
    }
}

fn validate_rfc3339(label: &str, timestamp: &str) -> Result<(), StorageError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|_| ())
        .map_err(|error| StorageError::Corrupt(format!("invalid {label} {timestamp:?}: {error}")))
}

fn parse_action_stage(value: &str) -> Result<ActionStage, String> {
    match value {
        "Recommended" => Ok(ActionStage::Recommended),
        "Simulated" => Ok(ActionStage::Simulated),
        "Approved" => Ok(ActionStage::Approved),
        "Executed" => Ok(ActionStage::Executed),
        "Rejected" => Ok(ActionStage::Rejected),
        "Failed" => Ok(ActionStage::Failed),
        _ => Err(format!("invalid action stage {value:?}")),
    }
}

fn parse_action_type(value: &str) -> Result<rieko_findings::ActionType, String> {
    use rieko_findings::ActionType;
    match value {
        "rebalance_channel" => Ok(ActionType::RebalanceChannel),
        "update_fee_policy" => Ok(ActionType::UpdateFeePolicy),
        "restart_service" => Ok(ActionType::RestartService),
        "custom" => Ok(ActionType::Custom),
        _ => Err(format!("invalid action type {value:?}")),
    }
}

fn parse_persisted_timestamp(
    index: usize,
    label: &str,
    value: String,
) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| {
            invalid_storage_column(index, format!("invalid {label} {value:?}: {error}"))
        })
}

fn invalid_storage_column(index: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, message.into())
}

fn invalid_simulation_column(index: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, message.into())
}

fn status_from_i64(v: u32) -> Result<rieko_domain::ChannelStatus, String> {
    use rieko_domain::ChannelStatus;
    match v {
        0 => Ok(ChannelStatus::Opening),
        1 => Ok(ChannelStatus::Active),
        2 => Ok(ChannelStatus::Inactive),
        3 => Ok(ChannelStatus::Closing),
        4 => Ok(ChannelStatus::Closed),
        5 => Ok(ChannelStatus::PendingOpen),
        6 => Ok(ChannelStatus::WaitingClose),
        7 => Ok(ChannelStatus::ForceClosing),
        8 => Ok(ChannelStatus::Unknown),
        _ => Err(format!("invalid channel status {v}")),
    }
}

fn parse_ts(label: &str, s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|error| format!("invalid {label} {s:?}: {error}"))
}

/// Apply the documented, intentional per-connection operational settings. These
/// are deliberate choices (RIEKO-AUDIT-006), not arbitrary tuning:
/// * WAL journal mode (DEK: durable concurrent reader/writer workload).
/// * Foreign keys enforced.
/// * A finite busy timeout so a transient lock never fails immediately.
/// * `synchronous=NORMAL` — see [`SYNCHRONOUS_MODE`].
fn apply_operational_settings(conn: &Connection) -> Result<(), StorageError> {
    // busy_timeout must be installed *before* any pragma that can take a lock
    // (journal_mode=WAL needs the write lock on a fresh database): a concurrent
    // open otherwise fails immediately with SQLITE_BUSY instead of waiting.
    conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS as i64)
        .and_then(|_| conn.pragma_update(None, "journal_mode", "WAL"))
        .and_then(|_| conn.pragma_update(None, "foreign_keys", "ON"))
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
            last_sent_at: sent
                .map(|s| parse_ts("alert last_sent_at", &s))
                .transpose()
                .map_err(AlertError::Store)?,
            last_severity: sev
                .map(severity_from_int)
                .transpose()
                .map_err(AlertError::Store)?,
            last_status: parse_delivery_status(&status).map_err(AlertError::Store)?,
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
                        last_persist_success, source_data_at, llm, alert_sink,
                        cleanup, last_cleanup_attempt, last_cleanup_success
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
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
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
            cleanup,
            cleanup_attempt,
            cleanup_success,
        ) = row.map_err(|e| OperationalStateError::Store(e.to_string()))?;
        Ok(Some(rieko_status::OperationalState {
            source: parse_source(&source, connected).map_err(OperationalStateError::Store)?,
            last_ingestion_attempt: ingest_attempt
                .map(|s| parse_ts("last_ingestion_attempt", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            last_ingestion_success: ingest_success
                .map(|s| parse_ts("last_ingestion_success", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            last_cycle_attempt: cycle_attempt
                .map(|s| parse_ts("last_cycle_attempt", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            last_cycle_success: cycle_success
                .map(|s| parse_ts("last_cycle_success", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            last_persist_success: persist_success
                .map(|s| parse_ts("last_persist_success", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            source_data_at: data_at
                .map(|s| parse_ts("source_data_at", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            llm: parse_component(&llm).map_err(OperationalStateError::Store)?,
            alert_sink: parse_component(&alert).map_err(OperationalStateError::Store)?,
            cleanup: parse_component(&cleanup).map_err(OperationalStateError::Store)?,
            last_cleanup_attempt: cleanup_attempt
                .map(|s| parse_ts("last_cleanup_attempt", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
            last_cleanup_success: cleanup_success
                .map(|s| parse_ts("last_cleanup_success", &s))
                .transpose()
                .map_err(OperationalStateError::Store)?,
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
                     llm, alert_sink, cleanup, last_cleanup_attempt, last_cleanup_success)
                 VALUES ('current', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
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
                    alert_sink = excluded.alert_sink,
                    cleanup = excluded.cleanup,
                    last_cleanup_attempt = excluded.last_cleanup_attempt,
                    last_cleanup_success = excluded.last_cleanup_success",
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
                    component_str(state.cleanup),
                    state.last_cleanup_attempt.map(|t| t.to_rfc3339()),
                    state.last_cleanup_success.map(|t| t.to_rfc3339()),
                ],
            )
            .map(|_| ())
            .map_err(|e| OperationalStateError::Store(e.to_string()))
    }

    fn update_operational_state(
        &mut self,
        f: &dyn Fn(&mut rieko_status::OperationalState),
    ) -> Result<(), rieko_status::OperationalStateError> {
        use rieko_status::OperationalStateError;
        if !self.in_transaction {
            self.conn
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| OperationalStateError::Store(e.to_string()))?;
        }
        let result = (|| -> Result<(), OperationalStateError> {
            let mut state = self.read_operational_state()?.unwrap_or_default();
            f(&mut state);
            self.write_operational_state(&state)
        })();
        if !self.in_transaction {
            if result.is_ok() {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| OperationalStateError::Store(e.to_string()))?;
            } else {
                self.conn.execute_batch("ROLLBACK").ok();
            }
        }
        result
    }
}

fn parse_source(s: &str, connected: Option<i64>) -> Result<rieko_status::SourceState, String> {
    use rieko_status::SourceState;
    match s {
        "lnd_rest" => match connected {
            Some(0) => Ok(SourceState::LndRest { connected: false }),
            Some(1) => Ok(SourceState::LndRest { connected: true }),
            _ => Err("lnd_rest source must have a boolean connection state".into()),
        },
        "fixture" if connected.is_none() => Ok(SourceState::Fixture),
        "fixture" => Err("fixture source cannot have a connection state".into()),
        _ => Err(format!("invalid operational source {s:?}")),
    }
}

fn parse_component(s: &str) -> Result<rieko_status::ComponentState, String> {
    use rieko_status::ComponentState;
    match s {
        "not_configured" => Ok(ComponentState::NotConfigured),
        "configured" => Ok(ComponentState::Configured),
        "healthy" => Ok(ComponentState::Healthy),
        "failing" => Ok(ComponentState::Failing),
        _ => Err(format!("invalid component state {s:?}")),
    }
}

fn component_str(s: rieko_status::ComponentState) -> &'static str {
    s.as_str()
}

fn severity_from_int(v: i64) -> Result<rieko_findings::Severity, String> {
    match v {
        0 => Ok(rieko_findings::Severity::Info),
        1 => Ok(rieko_findings::Severity::Warning),
        2 => Ok(rieko_findings::Severity::Critical),
        _ => Err(format!("invalid alert severity {v}")),
    }
}

fn parse_delivery_status(s: &str) -> Result<rieko_alerts::DeliveryStatus, String> {
    match s {
        "none" => Ok(rieko_alerts::DeliveryStatus::None),
        "success" => Ok(rieko_alerts::DeliveryStatus::Success),
        "failed" => Ok(rieko_alerts::DeliveryStatus::Failed),
        "skipped" => Ok(rieko_alerts::DeliveryStatus::Skipped),
        _ => Err(format!("invalid alert delivery status {s:?}")),
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

fn invalid_finding_column(index: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStorage;
    use rieko_domain::{BitcoinNetwork, ChannelStatus};
    use rieko_findings::{
        Action, ActionStage, ActionType, Evidence, FindingProvenance, ObservationReference,
        ObservationSource, ProducerRole, ProducerVersion, Rationale, Severity,
    };
    use serde_json::Value;

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
            schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
            severity: Severity::Critical,
            node: Some("local-node".into()),
            channel: Some("c1".into()),
            evidence: vec![Evidence::number("local_ratio", 0.02)],
            provenance: Some(FindingProvenance {
                network: Some(BitcoinNetwork::Regtest),
                source: ObservationSource::Fixture {
                    redacted_hash: "fixture-hash".into(),
                    configured_node: "node-1".into(),
                },
                producers: vec![ProducerVersion {
                    name: "channel_liquidity".into(),
                    version: "1".into(),
                    role: ProducerRole::Detector,
                }],
                observation: ObservationReference::ChannelState {
                    channel_id: "c1".into(),
                    snapshot: rieko_findings::ChannelSnapshotReference {
                        network: Some(BitcoinNetwork::Regtest),
                        observed_at: now,
                        state_digest: "state-hash".into(),
                    },
                },
            }),
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
        let finding = sample_finding();
        s.save_finding(&finding).unwrap();

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
        assert_eq!(
            findings[0].schema_version,
            rieko_findings::FINDING_SCHEMA_VERSION
        );
        assert_eq!(findings[0].lifecycle, FindingLifecycle::Active);
        assert_eq!(findings[0].first_seen_at, findings[0].last_seen_at);
        assert_eq!(findings[0].provenance, finding.provenance);

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
        let bridged = s.recent_simulations_v2(10).unwrap();
        assert_eq!(bridged[0].model_id, "legacy");
        assert!(bridged[0].canonical_input.is_null());
    }

    fn simulation_record(id: &str) -> crate::SimulationRecord {
        use sha2::{Digest, Sha256};

        let canonical_input = serde_json::json!({
            "action_type": "RebalanceChannel",
            "destination_snapshot": {
                "capacity_msat": 1000000,
                "channel_id": "c2",
                "node_id": "local-node",
                "local_balance_msat": 700000,
                "local_ratio": 0.7,
                "remote_balance_msat": 300000,
                "spendable_inbound_msat": 290000,
                "spendable_outbound_msat": 690000,
                "status": "Active",
                "ts": "2023-11-14T22:13:20Z"
            },
            "finding_id": "f1",
            "finding_channel": "c1",
            "model_id": "liquidity-redistribution",
            "model_version": "2",
            "node_id": "local-node",
            "parameters": {
                "amount_msat": 50000,
                "destination_channel": "c2",
                "source_channel": "c1"
            },
            "recommendation_id": "a1",
            "recommendation_target": "c1",
            "provenance": {
                "observation": {
                    "channel_id": "c1",
                    "kind": "channel_state",
                    "snapshot": {
                        "observed_at": "2023-11-14T22:13:20Z",
                        "state_digest": "state-hash"
                    }
                },
                "producers": [],
                "source": {
                    "kind": "fixture",
                    "redacted_hash": "fixture-hash"
                }
            },
            "source_snapshot": {
                "capacity_msat": 1000000,
                "channel_id": "c1",
                "node_id": "local-node",
                "local_balance_msat": 200000,
                "local_ratio": 0.2,
                "remote_balance_msat": 800000,
                "spendable_inbound_msat": 790000,
                "spendable_outbound_msat": 190000,
                "status": "Active",
                "ts": "2023-11-14T22:13:20Z"
            }
        });
        let canonical = serde_json::to_vec(&canonical_input).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"rieko-simulation-input-v3");
        hash.update((canonical.len() as u64).to_be_bytes());
        hash.update(canonical);
        let input_hash = format!("{:x}", hash.finalize());
        let assumptions = serde_json::json!([]);
        let warnings = serde_json::json!([]);
        let projection = serde_json::json!({
            "assumptions": assumptions,
            "baseline": {
                "capacity_msat": 1000000,
                "local_balance_msat": 200000,
                "local_ratio": 0.2,
                "remote_balance_msat": 800000
            },
            "confidence": "medium",
            "deltas": [],
            "input_hash": input_hash,
            "model_id": "liquidity-redistribution",
            "model_version": "2",
            "projected": {
                "capacity_msat": 1000000,
                "local_balance_msat": 150000,
                "local_ratio": 0.15,
                "remote_balance_msat": 850000
            },
            "warnings": warnings
        });
        crate::SimulationRecord {
            id: id.into(),
            action_id: "a1".into(),
            finding_id: "f1".into(),
            action_type: "rebalance_channel".into(),
            status: "completed".into(),
            model_id: "liquidity-redistribution".into(),
            model_version: "2".into(),
            input_hash,
            confidence: "medium".into(),
            assumptions,
            warnings,
            explanation: String::new(),
            canonical_input,
            projection,
            source_observed_at: Some("2023-11-14T22:13:20Z".into()),
            requested_at: "2023-11-14T22:14:20Z".into(),
            completed_at: Some("2023-11-14T22:14:20Z".into()),
            error_code: None,
            created_at: "2023-11-14T22:14:20Z".into(),
        }
    }

    #[test]
    fn replayable_simulation_and_events_roundtrip_atomically() {
        for mut storage in lifecycle_backends() {
            let record = simulation_record("sim-v2");
            let event = crate::SimulationEvent {
                id: "event-1".into(),
                simulation_id: record.id.clone(),
                status: "completed".into(),
                error_code: None,
                timestamp: record.requested_at.clone(),
            };
            let before = storage.counts().unwrap();
            storage.begin_transaction().unwrap();
            storage.save_simulation_v2(&record).unwrap();
            storage.append_simulation_event(&event).unwrap();
            storage.commit_transaction().unwrap();

            assert_eq!(
                storage.simulation_v2_by_id(&record.id).unwrap(),
                Some(record.clone())
            );
            assert_eq!(
                storage
                    .simulation_v2_by_input_hash(&record.input_hash)
                    .unwrap(),
                Some(record.clone())
            );
            assert_eq!(storage.simulation_events(&record.id).unwrap(), vec![event]);
            let after = storage.counts().unwrap();
            assert_eq!(after.findings, before.findings);
            assert_eq!(after.recommendations, before.recommendations);
            assert_eq!(after.audit, before.audit);
            assert_eq!(after.simulations, before.simulations + 1);
        }
    }

    #[test]
    fn completed_simulations_are_immutable_and_input_unique() {
        for mut storage in lifecycle_backends() {
            let record = simulation_record("sim-v2");
            storage.save_simulation_v2(&record).unwrap();

            let mut changed = record.clone();
            changed.status = "failed".into();
            assert!(storage.save_simulation_v2(&changed).is_err());

            let mut duplicate_input = record.clone();
            duplicate_input.id = "different-run".into();
            assert!(storage.save_simulation_v2(&duplicate_input).is_err());
        }
    }

    #[test]
    fn simulation_record_and_lifecycle_events_roll_back_together() {
        for mut storage in lifecycle_backends() {
            let record = simulation_record("sim-v2");
            storage.begin_transaction().unwrap();
            storage.save_simulation_v2(&record).unwrap();
            storage
                .append_simulation_event(&crate::SimulationEvent {
                    id: "event-1".into(),
                    simulation_id: record.id.clone(),
                    status: "completed".into(),
                    error_code: None,
                    timestamp: record.requested_at.clone(),
                })
                .unwrap();
            storage.rollback_transaction().unwrap();

            assert!(storage.simulation_v2_by_id(&record.id).unwrap().is_none());
            assert!(storage.simulation_events(&record.id).unwrap().is_empty());
        }
    }

    #[test]
    fn corrupt_simulation_json_hash_and_timestamp_fail_loudly() {
        for (column, value) in [
            ("canonical_input", "'not-json'"),
            ("projection", "'not-json'"),
            ("input_hash", "'abcd'"),
            ("requested_at", "'not-a-time'"),
            ("status", "'executed'"),
        ] {
            let mut storage = SqliteStorage::in_memory().unwrap();
            storage
                .save_simulation_v2(&simulation_record("sim-v2"))
                .unwrap();
            storage
                .conn
                .execute(
                    &format!("UPDATE simulations SET {column} = {value} WHERE id = 'sim-v2'"),
                    [],
                )
                .unwrap();
            assert!(
                storage.simulation_v2_by_id("sim-v2").is_err(),
                "{column} decoded silently"
            );
        }
    }

    #[test]
    fn replayable_queries_filter_legacy_rows_before_limit_in_both_backends() {
        for mut storage in lifecycle_backends() {
            let replayable = simulation_record("replayable");
            storage.save_simulation_v2(&replayable).unwrap();

            let mut legacy = replayable.clone();
            legacy.id = "legacy".into();
            legacy.canonical_input = Value::Null;
            legacy.source_observed_at = None;
            legacy.created_at = "2023-11-14T22:15:20Z".into();
            legacy.requested_at = legacy.created_at.clone();
            legacy.completed_at = Some(legacy.created_at.clone());
            storage.save_simulation_v2(&legacy).unwrap();

            assert_eq!(storage.recent_simulations_v2(1).unwrap()[0].id, "legacy");
            assert_eq!(
                storage.recent_replayable_simulations_v2(1).unwrap(),
                vec![replayable.clone()]
            );
            assert!(storage
                .replayable_simulation_v2_by_id("legacy")
                .unwrap()
                .is_none());
            assert_eq!(storage.simulation_v2_by_id("legacy").unwrap(), Some(legacy));
            assert_eq!(
                storage
                    .simulation_v2_by_input_hash(&replayable.input_hash)
                    .unwrap(),
                Some(replayable)
            );
        }
    }

    #[test]
    fn malformed_recommendation_fields_return_corrupt() {
        for (column, value) in [
            ("stage", "'unknown'"),
            ("action_type", "'unknown'"),
            ("params", "'not-json'"),
            ("rationale", "'not-json'"),
            ("created_at", "'not-a-time'"),
            ("updated_at", "'not-a-time'"),
        ] {
            let mut storage = SqliteStorage::in_memory().unwrap();
            let rec = test_rec(
                "f1",
                Action::new(
                    ActionType::RebalanceChannel,
                    ActionStage::Recommended,
                    Some("c1".into()),
                    serde_json::json!({}),
                    "rebalance",
                ),
            );
            storage.save_recommendation(&rec).unwrap();
            storage
                .conn
                .execute(
                    &format!("UPDATE recommendations SET {column} = {value} WHERE action_id = ?1"),
                    [&rec.action.id],
                )
                .unwrap();

            assert!(matches!(
                storage.latest_recommendations(1),
                Err(StorageError::Corrupt(_))
            ));
            assert!(matches!(
                storage.recommendation_for_action(&rec.action.id),
                Err(StorageError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn malformed_audit_fields_return_corrupt() {
        for column in ["stage", "previous_stage", "action_type", "details", "ts"] {
            // The table is append-only, so inject corruption as part of the
            // original row rather than attempting a forbidden UPDATE.
            let mut corrupt = SqliteStorage::in_memory().unwrap();
            corrupt
                .conn
                .execute(
                    "INSERT INTO audit
                     (id, action_id, action_type, previous_stage, stage, actor, details, ts)
                     VALUES ('audit', 'action', ?1, ?2, ?3, 'operator', ?4, ?5)",
                    params![
                        if column == "action_type" {
                            "unknown"
                        } else {
                            "rebalance_channel"
                        },
                        if column == "previous_stage" {
                            "unknown"
                        } else {
                            "Recommended"
                        },
                        if column == "stage" {
                            "unknown"
                        } else {
                            "Approved"
                        },
                        if column == "details" {
                            "not-json"
                        } else {
                            "{}"
                        },
                        if column == "ts" {
                            "not-a-time"
                        } else {
                            "2023-11-14T22:15:20Z"
                        },
                    ],
                )
                .unwrap();
            assert!(matches!(
                corrupt.recent_audit(1),
                Err(StorageError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn malformed_snapshot_identity_and_status_return_corrupt() {
        for update in [
            "UPDATE channel_snapshots SET network_id = 'unknown-network'",
            "UPDATE channel_snapshots SET status_int = 99",
        ] {
            let mut storage = SqliteStorage::in_memory().unwrap();
            storage
                .save_channel_snapshot(&snapshot_at("c1", ChannelStatus::Active, Utc::now()))
                .unwrap();
            storage.conn.execute(update, []).unwrap();
            assert!(matches!(
                storage.recent_channel_snapshots("c1", 1),
                Err(StorageError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn simulation_input_survives_snapshot_retention() {
        let mut storage = SqliteStorage::in_memory().unwrap();
        let record = simulation_record("sim-v2");
        storage.save_simulation_v2(&record).unwrap();
        let old = snapshot_at(
            "c1",
            ChannelStatus::Active,
            Utc::now() - chrono::Duration::days(60),
        );
        storage.save_channel_snapshot(&old).unwrap();
        storage
            .prune_channel_snapshots(&crate::RetentionPolicy::default(), Utc::now())
            .unwrap();

        assert!(storage
            .recent_channel_snapshots("c1", 1)
            .unwrap()
            .is_empty());
        assert_eq!(
            storage
                .simulation_v2_by_id("sim-v2")
                .unwrap()
                .unwrap()
                .canonical_input,
            record.canonical_input
        );
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

    fn snapshot_at(id: &str, status: ChannelStatus, ts: DateTime<Utc>) -> ChannelSnapshot {
        ChannelSnapshot {
            node_id: Some("local-node".into()),
            network: Some(BitcoinNetwork::Regtest),
            state_digest: Some(format!("digest-{id}")),
            channel_id: id.to_string(),
            local_ratio: 0.5,
            local_balance_msat: 500_000,
            remote_balance_msat: 500_000,
            capacity_msat: 1_000_000,
            status,
            ts,
            spendable_outbound_msat: 0,
            spendable_inbound_msat: 0,
        }
    }

    fn save_cycle(
        storage: &mut impl Storage,
        snapshot: &ChannelSnapshot,
        finding: &Finding,
        recommendation: &Recommendation,
        audit: &AuditEntry,
    ) {
        storage.save_channel_snapshot(snapshot).unwrap();
        storage.save_finding(finding).unwrap();
        storage.save_recommendation(recommendation).unwrap();
        storage.append_audit(audit).unwrap();
    }

    fn assert_cycle_rows(storage: &mut impl Storage, expected: usize) {
        assert_eq!(
            storage.recent_channel_snapshots("c1", 10).unwrap().len(),
            expected
        );
        assert_eq!(storage.latest_findings(10).unwrap().len(), expected);
        assert_eq!(storage.latest_recommendations(10).unwrap().len(), expected);
        assert_eq!(storage.recent_audit(10).unwrap().len(), expected);
    }

    #[test]
    fn retention_removes_old_snapshots_and_keeps_recent() {
        let dir = std::env::temp_dir().join(format!("rieko-ret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("ret.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let now = Utc::now();
        for days in [0, 2, 40] {
            s.save_channel_snapshot(&snapshot_at(
                "c1",
                ChannelStatus::Active,
                now - chrono::Duration::days(days),
            ))
            .unwrap();
        }
        let policy = crate::RetentionPolicy {
            snapshot_max_age: std::time::Duration::from_secs(30 * 24 * 3600),
            ..Default::default()
        };
        let summary = s.prune_channel_snapshots(&policy, now).unwrap();
        assert_eq!(summary.deleted_snapshots, 1, "only the 40-day row expires");
        let kept = s.recent_channel_snapshots("c1", 10).unwrap();
        assert_eq!(kept.len(), 2, "recent snapshots remain");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_handles_closed_channels_with_shorter_grace() {
        let dir = std::env::temp_dir().join(format!("rieko-retc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("retc.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let now = Utc::now();
        // 10 days old: fine for an active channel (30d), stale for a closed one (3d).
        s.save_channel_snapshot(&snapshot_at(
            "open",
            ChannelStatus::Active,
            now - chrono::Duration::days(10),
        ))
        .unwrap();
        s.save_channel_snapshot(&snapshot_at(
            "closed",
            ChannelStatus::Closed,
            now - chrono::Duration::days(10),
        ))
        .unwrap();
        s.save_channel_snapshot(&snapshot_at(
            "closed",
            ChannelStatus::Closed,
            now - chrono::Duration::hours(1),
        ))
        .unwrap();
        let policy = crate::RetentionPolicy {
            snapshot_max_age: std::time::Duration::from_secs(30 * 24 * 3600),
            closed_channel_max_age: std::time::Duration::from_secs(3 * 24 * 3600),
            ..Default::default()
        };
        let summary = s.prune_channel_snapshots(&policy, now).unwrap();
        assert_eq!(summary.deleted_snapshots, 1);
        // The closed channel keeps only its recent snapshot; the open channel is untouched.
        assert_eq!(s.recent_channel_snapshots("open", 10).unwrap().len(), 1);
        assert_eq!(s.recent_channel_snapshots("closed", 10).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_caps_snapshots_per_channel() {
        let dir = std::env::temp_dir().join(format!("rieko-retcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("retcap.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let now = Utc::now();
        for i in 0..10 {
            s.save_channel_snapshot(&snapshot_at(
                "c1",
                ChannelStatus::Active,
                now - chrono::Duration::minutes(i as i64),
            ))
            .unwrap();
        }
        let policy = crate::RetentionPolicy {
            max_snapshots_per_channel: Some(3),
            snapshot_max_age: std::time::Duration::from_secs(30 * 24 * 3600),
            ..Default::default()
        };
        let summary = s.prune_channel_snapshots(&policy, now).unwrap();
        assert_eq!(summary.deleted_snapshots, 7);
        assert_eq!(s.recent_channel_snapshots("c1", 100).unwrap().len(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_caps_total_snapshots() {
        let dir = std::env::temp_dir().join(format!("rieko-rettot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("rettot.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let now = Utc::now();
        for (id, days) in [("c1", 0i64), ("c1", 1), ("c2", 0), ("c2", 1), ("c2", 2)] {
            s.save_channel_snapshot(&snapshot_at(
                id,
                ChannelStatus::Active,
                now - chrono::Duration::days(days),
            ))
            .unwrap();
        }
        let policy = crate::RetentionPolicy {
            max_total_snapshots: Some(2),
            snapshot_max_age: std::time::Duration::from_secs(30 * 24 * 3600),
            ..Default::default()
        };
        let summary = s.prune_channel_snapshots(&policy, now).unwrap();
        assert_eq!(summary.deleted_snapshots, 3, "only the newest two survive");
        assert_eq!(
            s.counts().unwrap().channel_snapshots,
            2,
            "absolute cap respected"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cleanup_never_touches_findings_or_recommendations() {
        let dir = std::env::temp_dir().join(format!("rieko-retf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("retf.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let now = Utc::now();
        s.save_finding(&sample_finding()).unwrap();
        s.save_channel_snapshot(&snapshot_at(
            "c1",
            ChannelStatus::Active,
            now - chrono::Duration::days(100),
        ))
        .unwrap();
        let policy = crate::RetentionPolicy {
            snapshot_max_age: std::time::Duration::from_secs(30 * 24 * 3600),
            ..Default::default()
        };
        s.prune_channel_snapshots(&policy, now).unwrap();
        assert_eq!(s.recent_channel_snapshots("c1", 10).unwrap().len(), 0);
        // Active finding evidence survives even though its channel history expired.
        assert_eq!(s.latest_findings(10).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn large_cleanup_is_chunked_and_completes() {
        let dir = std::env::temp_dir().join(format!("rieko-retbig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("retbig.db");
        let mut s = SqliteStorage::open(&db).unwrap();
        let now = Utc::now();
        // 5000 rows across two channels, all stale.
        for i in 0..5000 {
            s.save_channel_snapshot(&snapshot_at(
                if i % 2 == 0 { "c1" } else { "c2" },
                ChannelStatus::Active,
                now - chrono::Duration::days(60) - chrono::Duration::seconds(i as i64),
            ))
            .unwrap();
        }
        let policy = crate::RetentionPolicy {
            snapshot_max_age: std::time::Duration::from_secs(30 * 24 * 3600),
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let summary = s.prune_channel_snapshots(&policy, now).unwrap();
        assert_eq!(summary.deleted_snapshots, 5000);
        assert_eq!(s.counts().unwrap().channel_snapshots, 0);
        // The chunked pass must complete promptly, not block indefinitely.
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
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
            llm: rieko_status::ComponentState::Configured,
            alert_sink: rieko_status::ComponentState::Failing,
            cleanup: rieko_status::ComponentState::Healthy,
            last_cleanup_attempt: Some(Utc::now()),
            last_cleanup_success: Some(Utc::now()),
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
    fn malformed_operational_timestamp_fails_loudly() {
        use rieko_status::OperationalStateStore as _;

        let storage = SqliteStorage::in_memory().unwrap();
        storage
            .conn
            .execute(
                "INSERT INTO operational_state
                    (id, source, source_connected, last_ingestion_attempt, llm, alert_sink, cleanup)
                 VALUES ('current', 'fixture', NULL, 'not-a-timestamp',
                         'not_configured', 'not_configured', 'not_configured')",
                [],
            )
            .unwrap();

        assert!(storage.read_operational_state().is_err());
    }

    #[test]
    fn component_state_decodes_configured() {
        assert_eq!(
            parse_component("configured").unwrap(),
            rieko_status::ComponentState::Configured
        );
        assert!(parse_component("unknown").is_err());
    }

    #[test]
    fn channel_snapshots_roundtrip() {
        use rieko_domain::ChannelStatus;

        let mut s = SqliteStorage::in_memory().unwrap();
        let ts = Utc::now();
        let snap = ChannelSnapshot {
            node_id: Some("local-node".into()),
            network: Some(BitcoinNetwork::Signet),
            state_digest: Some("state-digest".into()),
            channel_id: "c1".into(),
            local_ratio: 0.42,
            local_balance_msat: 420_000,
            remote_balance_msat: 580_000,
            capacity_msat: 1_000_000,
            status: ChannelStatus::Active,
            ts,
            spendable_outbound_msat: 0,
            spendable_inbound_msat: 0,
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
        assert_eq!(got[0].network, Some(BitcoinNetwork::Signet));
        assert_eq!(got[0].state_digest.as_deref(), Some("state-digest"));
        assert_eq!(got[1].local_ratio, 0.42);
        assert_eq!(s.recent_channel_snapshots("other", 10).unwrap().len(), 0);
    }

    #[test]
    fn same_channel_snapshot_is_isolated_by_node() {
        let timestamp = Utc::now();
        for mut storage in lifecycle_backends() {
            let first = ChannelSnapshot {
                node_id: Some("node-a".into()),
                network: Some(BitcoinNetwork::Regtest),
                state_digest: Some("node-a-state".into()),
                channel_id: "c1".into(),
                local_ratio: 0.2,
                local_balance_msat: 200_000,
                remote_balance_msat: 800_000,
                capacity_msat: 1_000_000,
                status: ChannelStatus::Active,
                ts: timestamp,
                spendable_outbound_msat: 190_000,
                spendable_inbound_msat: 790_000,
            };
            let second = ChannelSnapshot {
                node_id: Some("node-b".into()),
                local_ratio: 0.8,
                local_balance_msat: 800_000,
                remote_balance_msat: 200_000,
                spendable_outbound_msat: 790_000,
                spendable_inbound_msat: 190_000,
                ..first.clone()
            };
            storage.save_channel_snapshot(&first).unwrap();
            storage.save_channel_snapshot(&second).unwrap();

            assert_eq!(
                storage
                    .recent_channel_snapshots_for_node("node-a", "c1", 1)
                    .unwrap()[0]
                    .local_ratio,
                0.2
            );
            assert_eq!(
                storage
                    .recent_channel_snapshots_for_node("node-b", "c1", 1)
                    .unwrap()[0]
                    .local_ratio,
                0.8
            );
        }
    }

    #[test]
    fn same_snapshot_identity_is_isolated_by_network() {
        let timestamp = Utc::now();
        for mut storage in lifecycle_backends() {
            let regtest = ChannelSnapshot {
                node_id: Some("node-a".into()),
                network: Some(BitcoinNetwork::Regtest),
                state_digest: Some("regtest-state".into()),
                channel_id: "c1".into(),
                local_ratio: 0.2,
                local_balance_msat: 200_000,
                remote_balance_msat: 800_000,
                capacity_msat: 1_000_000,
                status: ChannelStatus::Active,
                ts: timestamp,
                spendable_outbound_msat: 190_000,
                spendable_inbound_msat: 790_000,
            };
            let mainnet = ChannelSnapshot {
                network: Some(BitcoinNetwork::Mainnet),
                state_digest: Some("mainnet-state".into()),
                local_ratio: 0.8,
                local_balance_msat: 800_000,
                remote_balance_msat: 200_000,
                ..regtest.clone()
            };
            storage.save_channel_snapshot(&regtest).unwrap();
            storage.save_channel_snapshot(&mainnet).unwrap();

            let regtest_history = storage
                .recent_channel_snapshots_for_network(
                    BitcoinNetwork::Regtest,
                    Some("node-a"),
                    "c1",
                    10,
                )
                .unwrap();
            assert_eq!(regtest_history.len(), 1);
            assert_eq!(
                regtest_history[0].state_digest.as_deref(),
                Some("regtest-state")
            );

            assert_eq!(
                storage
                    .channel_snapshot_at(BitcoinNetwork::Regtest, "node-a", "c1", timestamp)
                    .unwrap()
                    .unwrap()
                    .state_digest
                    .as_deref(),
                Some("regtest-state")
            );
            assert_eq!(
                storage
                    .channel_snapshot_at(BitcoinNetwork::Mainnet, "node-a", "c1", timestamp)
                    .unwrap()
                    .unwrap()
                    .state_digest
                    .as_deref(),
                Some("mainnet-state")
            );
        }
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
    fn malformed_alert_timestamp_fails_loudly() {
        let storage = SqliteStorage::in_memory().unwrap();
        storage
            .conn
            .execute(
                "INSERT INTO alert_state (dedup_key, last_sent_at, last_severity, last_status)
                 VALUES ('bad-time', 'not-a-timestamp', NULL, 'none')",
                [],
            )
            .unwrap();

        assert!(AlertStateStore::read(&storage, "bad-time").is_err());
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
        let snapshot = snapshot_at("c1", ChannelStatus::Active, Utc::now());

        w.begin_transaction().unwrap();
        save_cycle(&mut w, &snapshot, &f, &rec, &audit);

        // A separate reader connection must not see the uncommitted cycle.
        let mut r = SqliteStorage::open(&db).unwrap();
        assert_cycle_rows(&mut r, 0);

        w.commit_transaction().unwrap();

        // After commit the whole cycle is visible together.
        let mut r2 = SqliteStorage::open(&db).unwrap();
        assert_cycle_rows(&mut r2, 1);
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
        let audit = AuditEntry::from_action(&rec.action, "system", serde_json::json!({}));
        let snapshot = snapshot_at("c1", ChannelStatus::Active, Utc::now());

        // Simulate the cycle failing after all writes but before commit.
        let result = (|| -> Result<(), StorageError> {
            s.begin_transaction()?;
            save_cycle(&mut s, &snapshot, &f, &rec, &audit);
            Err(StorageError::Backend("mid-cycle failure".into()))
        })();
        assert!(result.is_err());
        s.rollback_transaction().unwrap();

        assert_cycle_rows(&mut s, 0);
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
        assert!(
            s.rollback_transaction().is_err(),
            "rollback with no open transaction must fail"
        );
    }

    #[test]
    fn memory_transaction_commits_and_rolls_back_complete_cycles() {
        let mut s = MemoryStorage::new();
        let f = sample_finding();
        let rec = test_rec(
            &f.id,
            Action::new(
                ActionType::RebalanceChannel,
                ActionStage::Recommended,
                f.channel.clone(),
                serde_json::json!({}),
                "rebalance",
            ),
        );
        let audit = AuditEntry::from_action(&rec.action, "system", serde_json::json!({}));
        let snapshot = snapshot_at("c1", ChannelStatus::Active, Utc::now());

        s.begin_transaction().unwrap();
        save_cycle(&mut s, &snapshot, &f, &rec, &audit);
        s.rollback_transaction().unwrap();
        assert_cycle_rows(&mut s, 0);

        s.begin_transaction().unwrap();
        save_cycle(&mut s, &snapshot, &f, &rec, &audit);
        s.commit_transaction().unwrap();
        assert_cycle_rows(&mut s, 1);

        let mut changed_finding = f.clone();
        changed_finding.explanation = Some("transactional update".into());
        let approved = Action {
            stage: ActionStage::Approved,
            ..rec.action.clone()
        };
        let changed_audit = AuditEntry::from_transition(
            &approved,
            ActionStage::Recommended,
            "operator",
            serde_json::json!({}),
        );
        let changed_snapshot = snapshot_at(
            "c1",
            ChannelStatus::Inactive,
            snapshot.ts + chrono::Duration::seconds(1),
        );

        s.begin_transaction().unwrap();
        s.save_channel_snapshot(&changed_snapshot).unwrap();
        s.save_finding(&changed_finding).unwrap();
        s.set_action_stage(&rec.action.id, ActionStage::Approved)
            .unwrap();
        s.append_audit(&changed_audit).unwrap();
        s.rollback_transaction().unwrap();

        assert_cycle_rows(&mut s, 1);
        assert_eq!(s.latest_findings(1).unwrap()[0].explanation, None);
        assert_eq!(
            s.recommendation_for_action(&rec.action.id)
                .unwrap()
                .unwrap()
                .action
                .stage,
            ActionStage::Recommended
        );
        assert_eq!(
            s.recent_channel_snapshots("c1", 1).unwrap()[0].status,
            ChannelStatus::Active
        );
    }

    #[test]
    fn memory_transaction_rejects_nested_and_orphan_operations() {
        let mut s = MemoryStorage::new();
        assert!(s.commit_transaction().is_err());
        assert!(s.rollback_transaction().is_err());
        s.begin_transaction().unwrap();
        assert!(s.begin_transaction().is_err());
        s.rollback_transaction().unwrap();
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
        //
        // The connections are opened *before* the threads split off:
        // `PRAGMA journal_mode=WAL` needs exclusive access to convert a fresh
        // database and — per SQLite — does not honour the busy handler, so two
        // threads racing the very first open would flake on SQLITE_BUSY
        // regardless of busy_timeout. The concurrency under test is the read
        // vs. write workload, not the open race.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("conc.db");

        let w = SqliteStorage::open(&db).unwrap();
        let r = SqliteStorage::open(&db).unwrap();
        let f = sample_finding();

        let writer = thread::spawn(move || {
            let mut w = w;
            for _ in 0..20 {
                w.begin_transaction().unwrap();
                // Different id each iteration so we actually write rows.
                let mut f = f.clone();
                f.id = format!("f{}", std::time::Instant::now().elapsed().as_nanos());
                w.save_finding(&f).unwrap();
                w.commit_transaction().unwrap();
            }
        });

        let reader = thread::spawn(move || {
            let mut r = r;
            for _ in 0..200 {
                // Reading must not error out with SQLITE_BUSY.
                let _ = r.latest_findings(100).unwrap();
            }
        });

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
        s.resolve_findings_for_scope(&FindingCycleScope {
            detector: f.detector.clone(),
            network: f.provenance.as_ref().and_then(|p| p.network),
            node: f.node.clone(),
            complete: true,
        })
        .unwrap();
        s.resolve_findings_for_scope(&FindingCycleScope {
            detector: f.detector.clone(),
            network: f.provenance.as_ref().and_then(|p| p.network),
            node: f.node.clone(),
            complete: true,
        })
        .unwrap();
        s.resolve_findings_for_scope(&FindingCycleScope {
            detector: f.detector.clone(),
            network: f.provenance.as_ref().and_then(|p| p.network),
            node: f.node.clone(),
            complete: true,
        })
        .unwrap();

        let got = s.latest_findings(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].lifecycle, FindingLifecycle::Resolved);
        assert_eq!(got[0].evidence, evidence, "evidence retained on resolve");
        assert_eq!(got[0].first_seen_at, f.first_seen_at);
    }

    fn lifecycle_backends() -> Vec<Box<dyn Storage>> {
        vec![
            Box::new(MemoryStorage::new()),
            Box::new(SqliteStorage::in_memory().unwrap()),
        ]
    }

    fn finding_by_id(storage: &mut dyn Storage, id: &str) -> Finding {
        storage
            .latest_findings(100)
            .unwrap()
            .into_iter()
            .find(|finding| finding.id == id)
            .unwrap()
    }

    #[test]
    fn stable_updates_ignore_older_replay_and_reactivate_recurrence() {
        for mut storage in lifecycle_backends() {
            let original = sample_finding();
            storage.save_finding(&original).unwrap();
            storage
                .resolve_findings_for_scope(&FindingCycleScope {
                    detector: original.detector.clone(),
                    network: original.provenance.as_ref().and_then(|p| p.network),
                    node: original.node.clone(),
                    complete: true,
                })
                .unwrap();

            let later = original.last_seen_at + chrono::Duration::minutes(1);
            let mut recurrence = original.clone();
            recurrence.severity = Severity::Warning;
            recurrence.evidence = vec![Evidence::number("local_ratio", 0.15)];
            recurrence.provenance = Some(FindingProvenance {
                network: Some(BitcoinNetwork::Regtest),
                source: ObservationSource::Fixture {
                    redacted_hash: "new-fixture-hash".into(),
                    configured_node: "node-1".into(),
                },
                producers: vec![ProducerVersion {
                    name: "channel_liquidity".into(),
                    version: "1".into(),
                    role: ProducerRole::Detector,
                }],
                observation: ObservationReference::ChannelWindow {
                    channel_id: "c1".into(),
                    snapshots: Vec::new(),
                },
            });
            recurrence.explanation = Some("new evidence".into());
            recurrence.timestamp = later;
            recurrence.last_seen_at = later;
            recurrence.lifecycle = FindingLifecycle::Resolved;
            storage.save_finding(&recurrence).unwrap();

            let mut replay = original.clone();
            replay.severity = Severity::Info;
            replay.evidence = vec![Evidence::number("local_ratio", 0.99)];
            replay.provenance = None;
            replay.explanation = Some("stale".into());
            replay.timestamp -= chrono::Duration::minutes(1);
            replay.last_seen_at -= chrono::Duration::minutes(1);
            replay.first_seen_at -= chrono::Duration::minutes(2);
            storage.save_finding(&replay).unwrap();

            let stored = finding_by_id(storage.as_mut(), &original.id);
            assert_eq!(stored.lifecycle, FindingLifecycle::Active);
            assert_eq!(stored.severity, Severity::Warning);
            assert_eq!(stored.evidence, recurrence.evidence);
            assert_eq!(stored.provenance, recurrence.provenance);
            assert_eq!(stored.explanation, recurrence.explanation);
            assert_eq!(stored.timestamp, recurrence.timestamp);
            assert_eq!(stored.last_seen_at, recurrence.last_seen_at);
            assert_eq!(stored.first_seen_at, replay.first_seen_at);
        }
    }

    #[test]
    fn reconciliation_is_complete_cycle_and_scope_isolated() {
        for mut storage in lifecycle_backends() {
            let target = sample_finding();
            let mut other_node = target.clone();
            other_node.id = "other-node".into();
            other_node.node = Some("other".into());
            let mut node_less = target.clone();
            node_less.id = "node-less".into();
            node_less.node = None;
            let mut other_detector = target.clone();
            other_detector.id = "other-detector".into();
            other_detector.detector = "drift".into();
            for finding in [&target, &other_node, &node_less, &other_detector] {
                storage.save_finding(finding).unwrap();
            }

            let mut scope = FindingCycleScope {
                detector: target.detector.clone(),
                network: target.provenance.as_ref().and_then(|p| p.network),
                node: target.node.clone(),
                complete: false,
            };
            storage.resolve_findings_for_scope(&scope).unwrap();
            assert_eq!(
                finding_by_id(storage.as_mut(), &target.id).lifecycle,
                FindingLifecycle::Active
            );

            scope.complete = true;
            storage.resolve_findings_for_scope(&scope).unwrap();
            storage.resolve_findings_for_scope(&scope).unwrap();
            storage.resolve_findings_for_scope(&scope).unwrap();
            assert_eq!(
                finding_by_id(storage.as_mut(), &target.id).lifecycle,
                FindingLifecycle::Resolved
            );
            for id in ["other-node", "node-less", "other-detector"] {
                assert_eq!(
                    finding_by_id(storage.as_mut(), id).lifecycle,
                    FindingLifecycle::Active
                );
            }
        }
    }

    #[test]
    fn reconciliation_is_network_isolated() {
        for mut storage in lifecycle_backends() {
            let regtest = sample_finding();
            let mut mainnet = regtest.clone();
            mainnet.id = "mainnet-finding".into();
            let provenance = mainnet.provenance.as_mut().unwrap();
            provenance.network = Some(BitcoinNetwork::Mainnet);
            if let ObservationReference::ChannelState { snapshot, .. } = &mut provenance.observation
            {
                snapshot.network = Some(BitcoinNetwork::Mainnet);
            }
            storage.save_finding(&regtest).unwrap();
            storage.save_finding(&mainnet).unwrap();

            for _ in 0..3 {
                storage
                    .resolve_findings_for_scope(&FindingCycleScope {
                        detector: regtest.detector.clone(),
                        network: Some(BitcoinNetwork::Regtest),
                        node: regtest.node.clone(),
                        complete: true,
                    })
                    .unwrap();
            }
            assert_eq!(
                finding_by_id(storage.as_mut(), &regtest.id).lifecycle,
                FindingLifecycle::Resolved
            );
            assert_eq!(
                finding_by_id(storage.as_mut(), &mainnet.id).lifecycle,
                FindingLifecycle::Active
            );
        }
    }

    #[test]
    fn complete_cycle_supersedes_prior_detector_version() {
        for mut storage in lifecycle_backends() {
            let old = sample_finding();
            storage.save_finding(&old).unwrap();
            for _ in 0..3 {
                storage
                    .resolve_findings_for_scope(&FindingCycleScope {
                        detector: old.detector.clone(),
                        network: old.provenance.as_ref().and_then(|p| p.network),
                        node: old.node.clone(),
                        complete: true,
                    })
                    .unwrap();
            }
            let mut new = old.clone();
            new.id = "version-2".into();
            new.detector_version = "2".into();
            new.last_seen_at += chrono::Duration::minutes(1);
            new.timestamp = new.last_seen_at;
            storage.save_finding(&new).unwrap();

            assert_eq!(
                finding_by_id(storage.as_mut(), &old.id).lifecycle,
                FindingLifecycle::Resolved
            );
            assert_eq!(
                finding_by_id(storage.as_mut(), &new.id).lifecycle,
                FindingLifecycle::Active
            );
        }
    }

    #[test]
    fn reconciliation_rolls_back_in_both_backends() {
        for mut storage in lifecycle_backends() {
            let finding = sample_finding();
            storage.save_finding(&finding).unwrap();
            storage.begin_transaction().unwrap();
            storage
                .resolve_findings_for_scope(&FindingCycleScope {
                    detector: finding.detector.clone(),
                    network: finding.provenance.as_ref().and_then(|p| p.network),
                    node: finding.node.clone(),
                    complete: true,
                })
                .unwrap();
            storage.rollback_transaction().unwrap();
            assert_eq!(
                finding_by_id(storage.as_mut(), &finding.id).lifecycle,
                FindingLifecycle::Active
            );
        }
    }

    #[test]
    fn legacy_row_does_not_bridge_first_seen_across_unknown_network() {
        let mut storage = SqliteStorage::in_memory().unwrap();
        let legacy_first = "2020-01-01T00:00:00+00:00";
        storage
            .conn
            .execute(
                "INSERT INTO findings
                 (id, detector, detector_version, schema_version, severity, node_id, channel_id,
                  evidence, provenance, explanation, ts, first_seen_at, last_seen_at, lifecycle)
                 VALUES ('legacy-id', 'channel_liquidity', '1', 1, 1, 'local-node', 'c1',
                         '[]', NULL, NULL, ?1, ?1, ?1, 'resolved')",
                [legacy_first],
            )
            .unwrap();

        let mut current = sample_finding();
        current.id = "stable-v2-id".into();
        storage.save_finding(&current).unwrap();
        let legacy = finding_by_id(&mut storage, "legacy-id");
        let bridged = finding_by_id(&mut storage, "stable-v2-id");
        assert_eq!(legacy.provenance, None);
        assert_eq!(legacy.schema_version, 1);
        assert_eq!(bridged.first_seen_at, current.first_seen_at);
        assert_ne!(bridged.first_seen_at, legacy.first_seen_at);
        assert_eq!(bridged.provenance, current.provenance);
    }

    #[test]
    fn malformed_finding_enums_schema_and_provenance_fail_loudly() {
        for (column, value) in [
            ("severity", "99"),
            ("lifecycle", "'unknown'"),
            ("schema_version", "3"),
            ("provenance", "'not-json'"),
        ] {
            let mut storage = SqliteStorage::in_memory().unwrap();
            storage.save_finding(&sample_finding()).unwrap();
            storage
                .conn
                .execute(
                    &format!("UPDATE findings SET {column} = {value} WHERE id = 'f1'"),
                    [],
                )
                .unwrap();
            assert!(
                storage.latest_findings(1).is_err(),
                "{column} decoded silently"
            );
        }
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
                 CREATE TABLE simulations (
                    id TEXT PRIMARY KEY, action_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                    action_type TEXT NOT NULL, projection TEXT NOT NULL, created_at TEXT NOT NULL
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
        assert_eq!(
            got[0].lifecycle,
            FindingLifecycle::Resolved,
            "networkless legacy findings remain historical until re-observed"
        );
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
