use std::path::Path;

use chrono::{DateTime, Utc};
use rieko_findings::{AuditEntry, Finding, Recommendation};
use rusqlite::{Connection, OptionalExtension, params};
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
                ts          TEXT NOT NULL
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

            CREATE TABLE IF NOT EXISTS source_ledger (
                source     TEXT PRIMARY KEY,
                last_seen  TEXT NOT NULL
            );
            "#,
        )?;
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
        let evidence = serde_json::to_string(&finding.evidence).map_err(|e| {
            StorageError::Corrupt(format!("finding evidence: {e}"))
        })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, detector, severity, node_id, channel_id, evidence, explanation, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                finding.id,
                finding.detector,
                severity,
                finding.node,
                finding.channel,
                evidence,
                finding.explanation,
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

    fn save_source_last_seen(
        &mut self,
        source: &str,
        at: &DateTime<Utc>,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO source_ledger (source, last_seen) VALUES (?1, ?2)
             ON CONFLICT(source) DO UPDATE SET last_seen = excluded.last_seen",
            params![source, at.to_rfc3339()],
        )?;
        Ok(())
    }

    fn source_last_seen(&mut self, source: &str) -> Result<Option<DateTime<Utc>>, StorageError> {
        let ts: Option<String> = self
            .conn
            .query_row(
                "SELECT last_seen FROM source_ledger WHERE source = ?1",
                [source],
                |row| row.get(0),
            )
            .optional()?;
        Ok(ts.and_then(|t| DateTime::parse_from_rfc3339(&t).ok().map(|d| d.with_timezone(&Utc))))
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
    fn source_ledger_is_upserted() {
        let mut s = SqliteStorage::in_memory().unwrap();
        let t1 = Utc::now();
        s.save_source_last_seen("lnd", &t1).unwrap();
        assert_eq!(s.source_last_seen("lnd").unwrap(), Some(t1));

        let t2 = t1 + chrono::Duration::seconds(10);
        s.save_source_last_seen("lnd", &t2).unwrap();
        assert_eq!(s.source_last_seen("lnd").unwrap(), Some(t2));
    }

    #[test]
    fn memory_storage_works() {
        let mut s = MemoryStorage::new();
        s.save_finding(&sample_finding()).unwrap();
        assert_eq!(s.latest_findings(10).unwrap().len(), 1);
        assert_eq!(s.findings_for_channel("c1").unwrap().len(), 1);
        assert_eq!(s.findings_for_channel("c2").unwrap().len(), 0);
    }
}
