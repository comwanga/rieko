use chrono::{DateTime, Utc};
use rieko_domain::ChannelSnapshot;
use rieko_findings::{ActionStage, AuditEntry, Finding, Recommendation, Simulation};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend failure: {0}")]
    Backend(String),
    #[error("corrupt record: {0}")]
    Corrupt(String),
}

impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        StorageError::Backend(e.to_string())
    }
}

/// Durable storage behind a trait (D6). v1 ships the SQLite implementation;
/// the trait keeps the DuckDB/Postgres progression possible.
pub trait Storage: Send {
    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError>;
    fn latest_findings(&mut self, limit: u32) -> Result<Vec<Finding>, StorageError>;
    fn findings_for_channel(&mut self, channel_id: &str) -> Result<Vec<Finding>, StorageError>;

    fn save_recommendation(&mut self, rec: &Recommendation) -> Result<(), StorageError>;
    fn latest_recommendations(&mut self, limit: u32) -> Result<Vec<Recommendation>, StorageError>;
    /// Look up one recommendation by its action id (for approve/execute).
    fn recommendation_for_action(
        &mut self,
        action_id: &str,
    ) -> Result<Option<Recommendation>, StorageError>;
    /// Advance (or regress) the stage of a persisted action. The legal
    /// transitions are enforced upstream by `rieko-execution`.
    fn set_action_stage(&mut self, action_id: &str, stage: ActionStage)
        -> Result<(), StorageError>;

    fn append_audit(&mut self, entry: &AuditEntry) -> Result<(), StorageError>;
    fn recent_audit(&mut self, limit: u32) -> Result<Vec<AuditEntry>, StorageError>;

    fn save_source_last_seen(&mut self, source: &str, at: &DateTime<Utc>)
        -> Result<(), StorageError>;
    fn source_last_seen(&mut self, source: &str) -> Result<Option<DateTime<Utc>>, StorageError>;

    /// Persist one point-in-time liquidity snapshot per channel per cycle.
    fn save_channel_snapshot(&mut self, snapshot: &ChannelSnapshot) -> Result<(), StorageError>;
    fn recent_channel_snapshots(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<ChannelSnapshot>, StorageError>;

    /// Record a what-if simulation of a recommended action (D7 Simulate).
    fn save_simulation(&mut self, sim: &Simulation) -> Result<(), StorageError>;
    fn recent_simulations(&mut self, limit: u32) -> Result<Vec<Simulation>, StorageError>;
    fn simulations_for_action(&mut self, action_id: &str) -> Result<Vec<Simulation>, StorageError>;
}

/// In-memory implementation for tests and fixtures.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    findings: Vec<Finding>,
    recommendations: Vec<Recommendation>,
    audit: Vec<AuditEntry>,
    source_ledger: Vec<(String, DateTime<Utc>)>,
    channel_snapshots: Vec<ChannelSnapshot>,
    simulations: Vec<Simulation>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    fn latest_findings(&mut self, limit: u32) -> Result<Vec<Finding>, StorageError> {
        Ok(self
            .findings
            .iter()
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn findings_for_channel(&mut self, channel_id: &str) -> Result<Vec<Finding>, StorageError> {
        Ok(self
            .findings
            .iter()
            .filter(|f| f.channel.as_deref() == Some(channel_id))
            .cloned()
            .collect())
    }

    fn save_recommendation(&mut self, rec: &Recommendation) -> Result<(), StorageError> {
        self.recommendations.push(rec.clone());
        Ok(())
    }

    fn latest_recommendations(&mut self, limit: u32) -> Result<Vec<Recommendation>, StorageError> {
        Ok(self
            .recommendations
            .iter()
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn recommendation_for_action(
        &mut self,
        action_id: &str,
    ) -> Result<Option<Recommendation>, StorageError> {
        Ok(self
            .recommendations
            .iter()
            .find(|r| r.action.id == action_id)
            .cloned())
    }

    fn set_action_stage(&mut self, action_id: &str, stage: ActionStage) -> Result<(), StorageError> {
        if let Some(rec) = self
            .recommendations
            .iter_mut()
            .find(|r| r.action.id == action_id)
        {
            rec.action.stage = stage;
            rec.action.updated_at = chrono::Utc::now();
        }
        Ok(())
    }

    fn append_audit(&mut self, entry: &AuditEntry) -> Result<(), StorageError> {
        self.audit.push(entry.clone());
        Ok(())
    }

    fn recent_audit(&mut self, limit: u32) -> Result<Vec<AuditEntry>, StorageError> {
        Ok(self
            .audit
            .iter()
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn save_source_last_seen(
        &mut self,
        source: &str,
        at: &DateTime<Utc>,
    ) -> Result<(), StorageError> {
        self.source_ledger
            .retain(|(s, _)| s != source);
        self.source_ledger.push((source.to_string(), *at));
        Ok(())
    }

    fn source_last_seen(&mut self, source: &str) -> Result<Option<DateTime<Utc>>, StorageError> {
        Ok(self
            .source_ledger
            .iter()
            .find(|(s, _)| s == source)
            .map(|(_, at)| *at))
    }

    fn save_channel_snapshot(&mut self, snapshot: &ChannelSnapshot) -> Result<(), StorageError> {
        self.channel_snapshots.push(snapshot.clone());
        Ok(())
    }

    fn recent_channel_snapshots(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<ChannelSnapshot>, StorageError> {
        Ok(self
            .channel_snapshots
            .iter()
            .filter(|s| s.channel_id == channel_id)
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn save_simulation(&mut self, sim: &Simulation) -> Result<(), StorageError> {
        self.simulations.push(sim.clone());
        Ok(())
    }

    fn recent_simulations(&mut self, limit: u32) -> Result<Vec<Simulation>, StorageError> {
        Ok(self
            .simulations
            .iter()
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn simulations_for_action(&mut self, action_id: &str) -> Result<Vec<Simulation>, StorageError> {
        Ok(self
            .simulations
            .iter()
            .filter(|s| s.action_id == action_id)
            .rev()
            .cloned()
            .collect())
    }
}
