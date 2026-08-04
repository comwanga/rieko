use chrono::{DateTime, Utc};
use rieko_findings::{AuditEntry, Finding, Recommendation};
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

    fn append_audit(&mut self, entry: &AuditEntry) -> Result<(), StorageError>;
    fn recent_audit(&mut self, limit: u32) -> Result<Vec<AuditEntry>, StorageError>;

    fn save_source_last_seen(&mut self, source: &str, at: &DateTime<Utc>)
        -> Result<(), StorageError>;
    fn source_last_seen(&mut self, source: &str) -> Result<Option<DateTime<Utc>>, StorageError>;
}

/// In-memory implementation for tests and fixtures.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    findings: Vec<Finding>,
    recommendations: Vec<Recommendation>,
    audit: Vec<AuditEntry>,
    source_ledger: Vec<(String, DateTime<Utc>)>,
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
}
