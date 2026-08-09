use std::collections::HashMap;

use rieko_alerts::{AlertError, AlertState, AlertStateStore};
use rieko_domain::ChannelSnapshot;
use rieko_findings::{
    ActionStage, AuditEntry, Finding, FindingCycleScope, FindingLifecycle, FindingLifecycleFilter,
    Recommendation, Simulation, FINDING_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A v2 simulation record (ADR-0005). Stored in the `simulations` table with
/// the V8 migration columns. The `projection` contains the serialized
/// `SimulationResult` from `rieko_simulation::model`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationRecord {
    pub id: String,
    pub action_id: String,
    pub finding_id: String,
    pub action_type: String,
    pub status: String,
    pub model_id: String,
    pub model_version: String,
    pub input_hash: String,
    pub confidence: String,
    pub assumptions: serde_json::Value,
    pub warnings: serde_json::Value,
    pub explanation: String,
    pub projection: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage backend failure: {0}")]
    Backend(String),
    #[error("corrupt record: {0}")]
    Corrupt(String),
    #[error("unsupported database: {0}")]
    Unsupported(String),
}

impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        StorageError::Backend(e.to_string())
    }
}

/// Durable storage behind a trait (D6). v1 ships the SQLite implementation;
/// the trait keeps the DuckDB/Postgres progression possible.
pub trait Storage: rieko_status::OperationalStateStore + Send {
    /// Begin a write transaction covering one logical unit, such as a complete
    /// detector cycle. Every backend must provide real transaction semantics.
    fn begin_transaction(&mut self) -> Result<(), StorageError>;
    /// Commit the transaction opened by [`Storage::begin_transaction`].
    fn commit_transaction(&mut self) -> Result<(), StorageError>;
    /// Abort the transaction opened by [`Storage::begin_transaction`],
    /// discarding everything written since it began.
    fn rollback_transaction(&mut self) -> Result<(), StorageError>;

    /// Current persisted schema version for diagnostics.
    fn schema_version(&mut self) -> Result<i64, StorageError> {
        Ok(crate::CURRENT_SCHEMA_VERSION)
    }

    /// Verify database integrity. `Ok(())` when intact; an error otherwise.
    fn integrity_check(&mut self) -> Result<(), StorageError> {
        Ok(())
    }

    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError>;
    /// Resolve active findings in a detector/node scope before observations
    /// from a complete cycle are upserted. Incomplete cycles must not resolve.
    fn resolve_findings_for_scope(&mut self, scope: &FindingCycleScope)
        -> Result<(), StorageError>;
    fn latest_findings(&mut self, limit: u32) -> Result<Vec<Finding>, StorageError>;
    fn latest_findings_by_lifecycle(
        &mut self,
        limit: u32,
        lifecycle: FindingLifecycleFilter,
    ) -> Result<Vec<Finding>, StorageError>;
    fn findings_for_channel(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<Finding>, StorageError>;
    fn findings_for_channel_by_lifecycle(
        &mut self,
        channel_id: &str,
        limit: u32,
        lifecycle: FindingLifecycleFilter,
    ) -> Result<Vec<Finding>, StorageError>;

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

    /// Persist one point-in-time liquidity snapshot per channel per cycle.
    fn save_channel_snapshot(&mut self, snapshot: &ChannelSnapshot) -> Result<(), StorageError>;
    fn recent_channel_snapshots(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<ChannelSnapshot>, StorageError>;
    /// Newest-first snapshots across all channels (for the UI channel list).
    fn recent_snapshots_all(&mut self, limit: u32) -> Result<Vec<ChannelSnapshot>, StorageError>;

    /// Record a what-if simulation of a recommended action (D7 Simulate).
    fn save_simulation(&mut self, sim: &Simulation) -> Result<(), StorageError>;
    fn recent_simulations(&mut self, limit: u32) -> Result<Vec<Simulation>, StorageError>;
    fn simulations_for_action(&mut self, action_id: &str) -> Result<Vec<Simulation>, StorageError>;

    /// v2 simulation persistence (ADR-0005). Stores the full SimulationResult
    /// along with its provenance metadata. The `projection` JSON is the
    /// serialized [`crate::SimulationRecord`].
    fn save_simulation_v2(&mut self, rec: &SimulationRecord) -> Result<(), StorageError>;
    fn recent_simulations_v2(&mut self, limit: u32) -> Result<Vec<SimulationRecord>, StorageError>;
    fn simulations_v2_for_action(
        &mut self,
        action_id: &str,
    ) -> Result<Vec<SimulationRecord>, StorageError>;

    /// Apply the retention policy to `channel_snapshots`, transactionally and in
    /// bounded chunks. Only snapshots are ever removed — findings and
    /// recommendations are never touched, so active finding evidence survives
    /// (RIEKO-AUDIT-016). Returns a summary for observability.
    fn prune_channel_snapshots(
        &mut self,
        policy: &crate::RetentionPolicy,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::PruneSummary, StorageError>;

    /// Constant-size table counts for `/status` and the `status` command.
    /// Backends must compute these without scanning entire tables into memory
    /// (RIEKO-AUDIT-008: no million-row status queries).
    fn counts(&mut self) -> Result<StorageCounts, StorageError> {
        Ok(StorageCounts {
            findings: self.latest_findings(crate::COUNT_CAP)?.len(),
            recommendations: self.latest_recommendations(crate::COUNT_CAP)?.len(),
            simulations: self.recent_simulations(crate::COUNT_CAP)?.len(),
            audit: self.recent_audit(crate::COUNT_CAP)?.len(),
            channel_snapshots: self.recent_snapshots_all(crate::COUNT_CAP)?.len(),
        })
    }
}

/// Table row counts for status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCounts {
    pub findings: usize,
    pub recommendations: usize,
    pub simulations: usize,
    pub audit: usize,
    pub channel_snapshots: usize,
}

/// In-memory implementation for tests and fixtures.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    findings: Vec<Finding>,
    recommendations: Vec<Recommendation>,
    audit: Vec<AuditEntry>,
    channel_snapshots: Vec<ChannelSnapshot>,
    simulations: Vec<Simulation>,
    simulation_records: Vec<SimulationRecord>,
    alert_state: HashMap<String, AlertState>,
    operational_state: Option<rieko_status::OperationalState>,
    transaction_snapshot: Option<MemoryStorageState>,
}

#[derive(Debug, Clone)]
struct MemoryStorageState {
    findings: Vec<Finding>,
    recommendations: Vec<Recommendation>,
    audit: Vec<AuditEntry>,
    channel_snapshots: Vec<ChannelSnapshot>,
    simulations: Vec<Simulation>,
    simulation_records: Vec<SimulationRecord>,
    alert_state: HashMap<String, AlertState>,
    operational_state: Option<rieko_status::OperationalState>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

pub(crate) fn validate_finding_schema(schema_version: u8) -> Result<(), StorageError> {
    if (1..=FINDING_SCHEMA_VERSION).contains(&schema_version) {
        Ok(())
    } else {
        Err(StorageError::Corrupt(format!(
            "unsupported finding schema version {schema_version}"
        )))
    }
}

fn lifecycle_matches(finding: &Finding, lifecycle: FindingLifecycleFilter) -> bool {
    match lifecycle {
        FindingLifecycleFilter::Active => finding.lifecycle == FindingLifecycle::Active,
        FindingLifecycleFilter::Resolved => finding.lifecycle == FindingLifecycle::Resolved,
        FindingLifecycleFilter::All => true,
    }
}

impl Storage for MemoryStorage {
    fn begin_transaction(&mut self) -> Result<(), StorageError> {
        if self.transaction_snapshot.is_some() {
            return Err(StorageError::Backend("nested transaction attempted".into()));
        }
        self.transaction_snapshot = Some(MemoryStorageState {
            findings: self.findings.clone(),
            recommendations: self.recommendations.clone(),
            audit: self.audit.clone(),
            channel_snapshots: self.channel_snapshots.clone(),
            simulations: self.simulations.clone(),
            simulation_records: self.simulation_records.clone(),
            alert_state: self.alert_state.clone(),
            operational_state: self.operational_state.clone(),
        });
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), StorageError> {
        if self.transaction_snapshot.take().is_none() {
            return Err(StorageError::Backend(
                "commit with no open transaction".into(),
            ));
        }
        Ok(())
    }

    fn rollback_transaction(&mut self) -> Result<(), StorageError> {
        let snapshot = self
            .transaction_snapshot
            .take()
            .ok_or_else(|| StorageError::Backend("rollback with no open transaction".into()))?;
        self.findings = snapshot.findings;
        self.recommendations = snapshot.recommendations;
        self.audit = snapshot.audit;
        self.channel_snapshots = snapshot.channel_snapshots;
        self.simulations = snapshot.simulations;
        self.simulation_records = snapshot.simulation_records;
        self.alert_state = snapshot.alert_state;
        self.operational_state = snapshot.operational_state;
        Ok(())
    }

    fn save_finding(&mut self, finding: &Finding) -> Result<(), StorageError> {
        validate_finding_schema(finding.schema_version)?;
        let first_seen_at = self
            .findings
            .iter()
            .filter(|existing| {
                existing.detector == finding.detector
                    && existing.detector_version == finding.detector_version
                    && existing.node == finding.node
                    && existing.channel == finding.channel
            })
            .map(|existing| existing.first_seen_at)
            .chain(std::iter::once(finding.first_seen_at))
            .min()
            .expect("finding first-seen candidates are non-empty");
        if let Some(existing) = self.findings.iter_mut().find(|f| f.id == finding.id) {
            existing.first_seen_at = existing.first_seen_at.min(first_seen_at);
            if finding.last_seen_at >= existing.last_seen_at {
                existing.severity = finding.severity;
                existing.evidence = finding.evidence.clone();
                existing.provenance = finding.provenance.clone();
                existing.explanation = finding.explanation.clone();
                existing.schema_version = finding.schema_version;
                existing.timestamp = finding.timestamp;
                existing.last_seen_at = finding.last_seen_at;
                existing.lifecycle = FindingLifecycle::Active;
            }
        } else {
            let mut finding = finding.clone();
            finding.first_seen_at = first_seen_at;
            finding.lifecycle = FindingLifecycle::Active;
            self.findings.push(finding);
        }
        Ok(())
    }

    fn resolve_findings_for_scope(
        &mut self,
        scope: &FindingCycleScope,
    ) -> Result<(), StorageError> {
        if scope.complete {
            for finding in &mut self.findings {
                if finding.detector == scope.detector
                    && finding.node == scope.node
                    && finding.lifecycle == FindingLifecycle::Active
                {
                    finding.lifecycle = FindingLifecycle::Resolved;
                }
            }
        }
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

    fn latest_findings_by_lifecycle(
        &mut self,
        limit: u32,
        lifecycle: FindingLifecycleFilter,
    ) -> Result<Vec<Finding>, StorageError> {
        Ok(self
            .findings
            .iter()
            .rev()
            .filter(|finding| lifecycle_matches(finding, lifecycle))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn findings_for_channel(
        &mut self,
        channel_id: &str,
        limit: u32,
    ) -> Result<Vec<Finding>, StorageError> {
        Ok(self
            .findings
            .iter()
            .rev()
            .filter(|f| f.channel.as_deref() == Some(channel_id))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn findings_for_channel_by_lifecycle(
        &mut self,
        channel_id: &str,
        limit: u32,
        lifecycle: FindingLifecycleFilter,
    ) -> Result<Vec<Finding>, StorageError> {
        Ok(self
            .findings
            .iter()
            .rev()
            .filter(|finding| finding.channel.as_deref() == Some(channel_id))
            .filter(|finding| lifecycle_matches(finding, lifecycle))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn save_recommendation(&mut self, rec: &Recommendation) -> Result<(), StorageError> {
        if let Some(existing) = self
            .recommendations
            .iter_mut()
            .find(|r| r.action.id == rec.action.id)
        {
            existing.action.updated_at = rec.action.updated_at;
        } else {
            self.recommendations.push(rec.clone());
        }
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

    fn set_action_stage(
        &mut self,
        action_id: &str,
        stage: ActionStage,
    ) -> Result<(), StorageError> {
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

    fn recent_snapshots_all(&mut self, limit: u32) -> Result<Vec<ChannelSnapshot>, StorageError> {
        Ok(self
            .channel_snapshots
            .iter()
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn prune_channel_snapshots(
        &mut self,
        policy: &crate::RetentionPolicy,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::PruneSummary, StorageError> {
        let before = self.channel_snapshots.len();
        // Group by channel, newest first, then keep only the rows each rule
        // preserves. Rows are never replaced by finds; this touches only the
        // snapshot buffer, never findings/recommendations (RIEKO-AUDIT-016).
        use std::collections::BTreeMap;
        let mut by_channel: BTreeMap<String, Vec<&ChannelSnapshot>> = BTreeMap::new();
        for snap in &self.channel_snapshots {
            by_channel
                .entry(snap.channel_id.clone())
                .or_default()
                .push(snap);
        }
        let mut kept: Vec<ChannelSnapshot> = Vec::with_capacity(before);
        let to_chrono = |d: std::time::Duration| {
            chrono::Duration::from_std(d).unwrap_or(chrono::Duration::zero())
        };
        let active_cutoff = now - to_chrono(policy.snapshot_max_age);
        let closed_cutoff = now - to_chrono(policy.closed_channel_max_age);
        for mut snaps in by_channel.into_values() {
            snaps.sort_by_key(|b| std::cmp::Reverse(b.ts));
            if let Some(cap) = policy.max_snapshots_per_channel {
                snaps.truncate(cap);
            }
            for snap in snaps {
                let cutoff = if snap.status.is_closed() {
                    closed_cutoff
                } else {
                    active_cutoff
                };
                if snap.ts >= cutoff {
                    kept.push(snap.clone());
                }
            }
        }
        if let Some(total) = policy.max_total_snapshots {
            // Keep the newest `total` across all channels.
            kept.sort_by_key(|b| std::cmp::Reverse(b.ts));
            kept.truncate(total);
        }
        let before = self.channel_snapshots.len();
        self.channel_snapshots = kept;
        Ok(crate::PruneSummary {
            deleted_snapshots: before - self.channel_snapshots.len(),
            complete: true,
        })
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

    fn save_simulation_v2(&mut self, rec: &SimulationRecord) -> Result<(), StorageError> {
        if let Some(existing) = self.simulation_records.iter_mut().find(|s| s.id == rec.id) {
            *existing = rec.clone();
        } else {
            self.simulation_records.push(rec.clone());
        }
        Ok(())
    }

    fn recent_simulations_v2(&mut self, limit: u32) -> Result<Vec<SimulationRecord>, StorageError> {
        Ok(self
            .simulation_records
            .iter()
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn simulations_v2_for_action(
        &mut self,
        action_id: &str,
    ) -> Result<Vec<SimulationRecord>, StorageError> {
        Ok(self
            .simulation_records
            .iter()
            .filter(|s| s.action_id == action_id)
            .rev()
            .cloned()
            .collect())
    }
}

impl AlertStateStore for MemoryStorage {
    fn read(&self, key: &str) -> Result<Option<AlertState>, AlertError> {
        Ok(self.alert_state.get(key).copied())
    }

    fn write(&mut self, key: &str, state: &AlertState) -> Result<(), AlertError> {
        self.alert_state.insert(key.to_string(), *state);
        Ok(())
    }
}

impl rieko_status::OperationalStateStore for MemoryStorage {
    fn read_operational_state(
        &self,
    ) -> Result<Option<rieko_status::OperationalState>, rieko_status::OperationalStateError> {
        Ok(self.operational_state.clone())
    }

    fn write_operational_state(
        &mut self,
        state: &rieko_status::OperationalState,
    ) -> Result<(), rieko_status::OperationalStateError> {
        self.operational_state = Some(state.clone());
        Ok(())
    }
}
