use std::path::Path;

use chrono::{DateTime, Utc};
use rieko_domain::ChannelSnapshot;
use rieko_findings::{ActionStage, AuditEntry, Finding, Recommendation, Simulation};
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::storage::StorageError;
use crate::Storage;

/// SQLite-backed storage, WAL mode (D6). Synchronous — used by the CLI scan
/// pipeline; the API holds it behind a `Mutex`.
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                detector    TEXT NOT NULL,
                severity    INTEGER NOT NULL,
                node_id     TEXT,
                channel_id  TEXT,
                evidence    TEXT NOT NULL,
                explanation TEXT,
                ts          TEXT NOT NULL,
                last_seen   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings (ts DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_channel ON findings (channel_id);

            CREATE TABLE IF NOT EXISTS recommendations (
                finding_id   TEXT NOT NULL,
                action_id    TEXT PRIMARY KEY,
                action_type  TEXT NOT NULL,
                stage        TEXT NOT NULL,
                target       TEXT,
                params       TEXT NOT NULL,
                summary      TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit (
                id          TEXT PRIMARY KEY,
                action_id   TEXT NOT NULL,
                action_type TEXT NOT NULL,
                stage       TEXT NOT NULL,
                actor       TEXT NOT NULL,
                details     TEXT NOT NULL,
                ts          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit (ts DESC);

            CREATE TABLE IF NOT EXISTS channel_snapshots (
                channel_id        TEXT NOT NULL,
                ts                TEXT NOT NULL,
                local_ratio       REAL NOT NULL,
                local_balance_msat INTEGER,
                remote_balance_msat INTEGER,
                capacity_msat     INTEGER,
                status_int        INTEGER NOT NULL,
                PRIMARY KEY (channel_id, ts)
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_channel_ts
                ON channel_snapshots (channel_id, ts DESC);

            CREATE TABLE IF NOT EXISTS simulations (
                id          TEXT PRIMARY KEY,
                action_id   TEXT NOT NULL,
                finding_id  TEXT NOT NULL,
                action_type TEXT NOT NULL,
                projection  TEXT NOT NULL,
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_simulations_action
                ON simulations (action_id);
            CREATE INDEX IF NOT EXISTS idx_simulations_ts
                ON simulations (created_at DESC);
            "#,
        )?;
        // Best-effort additive migration for pre-existing databases created
        // before `last_seen` was introduced. Safe to ignore if already applied.
        let _ = self
            .conn
            .execute_batch("ALTER TABLE findings ADD COLUMN last_seen TEXT;");
        Ok(())
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
        let evidence: Vec<rieko_findings::Evidence> =
            serde_json::from_str(&evidence_json).unwrap_or_default();
        let ts: String = row.get(7)?;
        Ok(Finding {
            id: row.get(0)?,
            detector: row.get(1)?,
            severity,
            node: row.get::<_, Option<String>>(3)?,
            channel: row.get::<_, Option<String>>(4)?,
            evidence,
            explanation: row.get::<_, Option<String>>(6)?,
            timestamp: DateTime::parse_from_rfc3339(&ts)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }
}

impl Storage for SqliteStorage {
    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError> {
        let severity = finding.severity as i64;
        let evidence = serde_json::to_string(&finding.evidence)
            .map_err(|e| StorageError::Corrupt(format!("finding evidence: {e}")))?;
        self.conn.execute(
            "INSERT INTO findings (id, detector, severity, node_id, channel_id, evidence, explanation, ts, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                explanation = COALESCE(excluded.explanation, findings.explanation),
                ts = excluded.ts,
                last_seen = excluded.last_seen",
            params![
                finding.id,
                finding.detector,
                severity,
                finding.node,
                finding.channel,
                evidence,
                finding.explanation,
                finding.timestamp.to_rfc3339(),
                finding.timestamp.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn latest_findings(&mut self, limit: u32) -> Result<Vec<Finding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts
             FROM findings ORDER BY ts DESC LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], Self::row_to_finding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn findings_for_channel(&mut self, channel_id: &str) -> Result<Vec<Finding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, detector, severity, node_id, channel_id, evidence, explanation, ts
             FROM findings WHERE channel_id = ? ORDER BY ts DESC",
        )?;
        let rows = stmt.query_map([channel_id], Self::row_to_finding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn save_recommendation(&mut self, rec: &Recommendation) -> Result<(), StorageError> {
        let params_json = serde_json::to_string(&rec.action.params)
            .map_err(|e| StorageError::Corrupt(format!("recommendation params: {e}")))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO recommendations
             (finding_id, action_id, action_type, stage, target, params, summary, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                rec.finding_id,
                rec.action.id,
                rec.action.action_type.as_str(),
                format!("{:?}", rec.action.stage),
                rec.action.target,
                params_json,
                rec.action.summary,
                rec.action.created_at.to_rfc3339(),
                rec.action.updated_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn latest_recommendations(&mut self, limit: u32) -> Result<Vec<Recommendation>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, action_id, action_type, stage, target, params, summary, created_at, updated_at
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
            Ok(Recommendation {
                finding_id: row.get(0)?,
                action: Action {
                    id: row.get(1)?,
                    action_type,
                    stage,
                    target: row.get::<_, Option<String>>(4)?,
                    params,
                    summary: row.get(6)?,
                    created_at: parse_ts(&row.get::<_, String>(7)?),
                    updated_at: parse_ts(&row.get::<_, String>(8)?),
                },
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
            "SELECT finding_id, action_id, action_type, stage, target, params, summary, created_at, updated_at
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
            Ok(Recommendation {
                finding_id: row.get(0)?,
                action: Action {
                    id: row.get(1)?,
                    action_type,
                    stage,
                    target: row.get::<_, Option<String>>(4)?,
                    params,
                    summary: row.get(6)?,
                    created_at: parse_ts(&row.get::<_, String>(7)?),
                    updated_at: parse_ts(&row.get::<_, String>(8)?),
                },
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
            "INSERT INTO audit (id, action_id, action_type, stage, actor, details, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.id,
                entry.action_id,
                entry.action_type.as_str(),
                format!("{:?}", entry.stage),
                entry.actor,
                details,
                entry.timestamp.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn recent_audit(&mut self, limit: u32) -> Result<Vec<AuditEntry>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, action_id, action_type, stage, actor, details, ts FROM audit ORDER BY ts DESC LIMIT ?")?;
        let rows = stmt.query_map([limit], |row| {
            use rieko_findings::{ActionStage, ActionType};
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
            let details: Value =
                serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or(Value::Null);
            Ok(AuditEntry {
                id: row.get(0)?,
                action_id: row.get(1)?,
                action_type,
                stage,
                actor: row.get(4)?,
                details,
                timestamp: parse_ts(&row.get::<_, String>(6)?),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStorage;
    use rieko_findings::{Action, ActionStage, ActionType, Evidence, Severity};

    fn sample_finding() -> Finding {
        Finding {
            id: "f1".into(),
            detector: "channel_liquidity".into(),
            severity: Severity::Critical,
            node: Some("local-node".into()),
            channel: Some("c1".into()),
            evidence: vec![Evidence::number("local_ratio", 0.02)],
            explanation: None,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn roundtrips_findings_recommendations_audit() {
        let mut s = SqliteStorage::in_memory().unwrap();
        s.save_finding(&sample_finding()).unwrap();

        let rec = Recommendation {
            finding_id: "f1".into(),
            action: Action::new(
                ActionType::RebalanceChannel,
                ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({"desired_ratio": 0.5}),
                "Rebalance channel c1 to 50/50",
            ),
        };
        s.save_recommendation(&rec).unwrap();

        let audit = AuditEntry::from_action(&rec.action, "system", serde_json::json!({}));
        s.append_audit(&audit).unwrap();

        let findings = s.latest_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "f1");
        assert_eq!(findings[0].severity, Severity::Critical);

        let recs = s.latest_recommendations(10).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].action.action_type, ActionType::RebalanceChannel);
        assert_eq!(recs[0].action.stage, ActionStage::Recommended);

        let audit_rows = s.recent_audit(10).unwrap();
        assert_eq!(audit_rows.len(), 1);
        assert_eq!(audit_rows[0].action_id, rec.action.id);
    }

    #[test]
    fn action_stage_can_be_fetched_and_transitioned() {
        use rieko_findings::{Action, ActionStage, ActionType};
        let mut s = SqliteStorage::in_memory().unwrap();
        let rec = Recommendation {
            finding_id: "f1".into(),
            action: Action::new(
                ActionType::RebalanceChannel,
                ActionStage::Recommended,
                Some("c1".into()),
                serde_json::json!({"desired_ratio": 0.5}),
                "rebalance c1",
            ),
        };
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
        assert_eq!(s.findings_for_channel("c1").unwrap().len(), 1);
        assert_eq!(s.findings_for_channel("c2").unwrap().len(), 0);
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
}
