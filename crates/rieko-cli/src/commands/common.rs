use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rieko_domain::NodeId;
use rieko_findings::{AuditEntry, Finding, Recommendation};
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_ingest_lnd::{LndChannelResponse, LndClient, Normalizer};
use rieko_llm::{ExplainRequest, LlmClient};
use rieko_recommendations::RecommendationEngine;
use rieko_storage::Storage;
use tracing::{debug, info, warn};

/// Where channel state comes from: a JSON fixture or a live LND REST node.
/// Both scan and monitor share this so the ingestion path stays identical.
#[derive(Debug, Clone, Default)]
pub struct GraphSource {
    pub fixture: Option<PathBuf>,
    pub lnd_rest: Option<String>,
    pub macaroon: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub node: String,
}

impl GraphSource {
    pub fn build(&self) -> Result<InMemoryGraph> {
        let local = NodeId::new(self.node.clone());
        let mut graph = InMemoryGraph::new();

        if let Some(rest) = &self.lnd_rest {
            let macaroon = self
                .macaroon
                .as_ref()
                .map(|p| std::fs::read(p).map_err(anyhow::Error::from))
                .transpose()
                .context("reading macaroon")?;
            let tls_cert = self
                .tls_cert
                .as_ref()
                .map(|p| std::fs::read(p).map_err(anyhow::Error::from))
                .transpose()
                .context("reading TLS certificate")?;
            let client = LndClient::new(rest, macaroon, tls_cert).context("building LND client")?;
            let channels = client
                .channels(&local)
                .context("fetching channels from LND")?;
            graph
                .upsert_channels(channels)
                .context("loading channels into graph")?;

            // Best-effort: routing history sharpens later volume detectors.
            match client.forwards(100) {
                Ok(forwards) => {
                    for f in forwards {
                        graph.record_forward(f);
                    }
                }
                Err(e) => tracing::warn!(error = %e, "forward fetch skipped"),
            }
            return Ok(graph);
        }

        if let Some(fixture) = &self.fixture {
            let channels = load_fixture(fixture, &local)?;
            graph
                .upsert_channels(channels)
                .context("loading channels into graph")?;
            return Ok(graph);
        }

        bail!("provide --fixture or --lnd-rest")
    }
}

fn load_fixture(path: &Path, local: &NodeId) -> Result<Vec<rieko_domain::Channel>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading fixture {}", path.display()))?;
    let parsed: LndChannelResponse =
        serde_json::from_str(&body).context("parsing fixture as LND channel response")?;
    let now = chrono::Utc::now();
    parsed
        .channels
        .iter()
        .map(|c| Normalizer::channel(c, local, now).map_err(|e| anyhow!(e.to_string())))
        .collect()
}

/// Shared per-finding pipeline used by scan and monitor: persist, ask the LLM
/// for a plain-language explanation (optional), turn the finding into auditable
/// recommendations. Returns everything that was recommended so callers can
/// alert/report.
pub fn persist_and_recommend<S: Storage>(
    storage: &mut S,
    llm: &dyn LlmClient,
    engine: &RecommendationEngine,
    node: &str,
    findings: &[Finding],
) -> Result<Vec<Recommendation>> {
    // One detector cycle is one logical unit: findings, explanations,
    // recommendations and audit transitions all commit together or roll back
    // together (D9, invariant #8). A failure mid-cycle leaves no half-written
    // recommendation/audit state behind.
    storage
        .begin_transaction()
        .context("beginning persistence transaction")?;

    let result = persist_cycle_locked(storage, llm, engine, node, findings);

    match result {
        Ok(all) => {
            storage
                .commit_transaction()
                .context("committing persistence transaction")?;
            Ok(all)
        }
        Err(e) => {
            let _ = storage.rollback_transaction();
            Err(e)
        }
    }
}

/// The body of a cycle, run inside the transaction opened by
/// [`persist_and_recommend`].
fn persist_cycle_locked<S: Storage>(
    storage: &mut S,
    llm: &dyn LlmClient,
    engine: &RecommendationEngine,
    node: &str,
    findings: &[Finding],
) -> Result<Vec<Recommendation>> {
    let mut all = Vec::new();
    for finding in findings {
        storage.save_finding(finding)?;

        match llm.explain(&ExplainRequest {
            finding,
            context: Some(format!("local node id {node}")),
        }) {
            Ok(Some(text)) => {
                let mut explained = finding.clone();
                explained.explanation = Some(text);
                storage.save_finding(&explained)?;
                debug!(finding = %finding.id, "explanation stored");
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "explanation skipped"),
        }

        for rec in engine.recommend(finding).unwrap_or_default() {
            // Idempotency: a recommendation keyed by its deterministic action id
            // is persisted only once; replays must not duplicate it (D9, inv #6).
            let is_new = storage.recommendation_for_action(&rec.action.id)?.is_none();
            if is_new {
                storage.save_recommendation(&rec)?;
            }
            if is_new {
                let audit = AuditEntry::from_action(
                    &rec.action,
                    "system",
                    serde_json::json!({"finding_id": rec.finding_id}),
                );
                storage.append_audit(&audit)?;
            }
            info!(
                action = rec.action.action_type.as_str(),
                target = rec.action.target.as_deref().unwrap_or(""),
                summary = %rec.action.summary,
                new = is_new,
                "recommendation"
            );
            all.push(rec);
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_detectors::{Detector, LiquidityDetector};
    use rieko_domain::{Channel, ChannelStatus, FeePolicy, LiquidityProfile, NodeId};
    use rieko_llm::NullClient;
    use rieko_storage::{MemoryStorage, SqliteStorage};

    fn drained_graph(local_msat: u64, remote_msat: u64) -> InMemoryGraph {
        let mut g = InMemoryGraph::new();
        let capacity = local_msat + remote_msat;
        g.upsert_channels(vec![Channel {
            id: "c1".into(),
            node: NodeId::new("local-node"),
            peer: NodeId::new("peer-1"),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(capacity, local_msat, remote_msat),
            last_seen: chrono::Utc::now(),
            opening_height: Some(1),
        }])
        .unwrap();
        g
    }

    fn detect(graph: &InMemoryGraph) -> Vec<rieko_findings::Finding> {
        let detector = LiquidityDetector::new("local-node");
        detector.run(graph, &rieko_detectors::DetectorContext::no_context())
    }

    #[test]
    fn missing_macaroon_file_fails_cleanly() {
        let source = GraphSource {
            lnd_rest: Some("http://127.0.0.1:1".into()),
            macaroon: Some(std::path::PathBuf::from("/definitely/not/a/macaroon")),
            ..Default::default()
        };
        let msg = source.build().unwrap_err().to_string();
        assert!(
            msg.contains("macaroon"),
            "missing macaroon file should fail with a clear message, got: {msg}"
        );
    }

    #[test]
    fn replay_produces_no_duplicates_in_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let engine = rieko_recommendations::RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let findings = detect(&graph);

        let run = |db_path: &std::path::Path| -> (usize, usize, usize) {
            let mut storage = SqliteStorage::open(db_path).unwrap();
            persist_and_recommend(&mut storage, &NullClient, &engine, "local-node", &findings)
                .unwrap();
            let n_f = storage.latest_findings(1000).unwrap().len();
            let n_r = storage.latest_recommendations(1000).unwrap().len();
            let n_a = storage.recent_audit(1000).unwrap().len();
            drop(storage);
            (n_f, n_r, n_a)
        };

        let first = run(&db);
        let second = run(&db);
        assert_eq!(
            second, first,
            "replay must not duplicate findings/recommendations/audit"
        );
        assert!(first.0 >= 1, "expected at least one finding");
        assert_eq!(first.1, first.0, "one recommendation per finding expected");
    }

    #[test]
    fn replay_does_not_append_duplicate_audit_in_memory() {
        let engine = rieko_recommendations::RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let findings = detect(&graph);
        let mut storage = MemoryStorage::new();
        persist_and_recommend(&mut storage, &NullClient, &engine, "local-node", &findings).unwrap();
        let n1 = storage.recent_audit(1000).unwrap().len();
        persist_and_recommend(&mut storage, &NullClient, &engine, "local-node", &findings).unwrap();
        let n2 = storage.recent_audit(1000).unwrap().len();
        assert_eq!(
            n1, n2,
            "replaying identical findings must not append audits"
        );
        assert_eq!(n1, findings.len(), "one audit entry per new finding");
    }
}
