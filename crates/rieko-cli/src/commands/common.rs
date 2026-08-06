use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rieko_domain::NodeId;
use rieko_findings::{AuditEntry, Finding, Recommendation};
use rieko_graph::{GraphStore, InMemoryGraph};
use rieko_ingest_lnd::{LndChannelResponse, LndClient, Normalizer, ShortChanResolver};
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
            let raw = client
                .raw_channels()
                .context("fetching channels from LND")?;
            let channels = raw
                .iter()
                .map(|c| {
                    Normalizer::channel(c, &local, chrono::Utc::now()).map_err(anyhow::Error::from)
                })
                .collect::<Result<Vec<_>, _>>()
                .context("normalizing channels from LND")?;
            graph
                .upsert_channels(channels)
                .context("loading channels into graph")?;

            // Best-effort: routing history sharpens later volume detectors.
            // Short channel ids are resolved to channel points where a channel
            // is known; unresolvable ids are preserved explicitly.
            let resolver = ShortChanResolver::from_channels(&raw);
            match client.forwards(&resolver) {
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

/// A successful source build reflects a reachable data source; record it so
/// `/status` and `status` know what feeds the pipeline and when it last worked.
/// Called right after [`GraphSource::build`] succeeds.
pub fn record_source_ingestion<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
    source: &GraphSource,
) -> Result<()> {
    let now = chrono::Utc::now();
    let mut state = storage
        .read_operational_state()
        .unwrap_or_default()
        .unwrap_or_default();
    if source.lnd_rest.is_some() {
        state.source = rieko_status::SourceState::LndRest { connected: true };
    } else {
        state.source = rieko_status::SourceState::Fixture;
    }
    state.last_ingestion_attempt = Some(now);
    state.last_ingestion_success = Some(now);
    storage
        .write_operational_state(&state)
        .context("recording source ingestion")?;
    Ok(())
}

/// Record the state of an optional component (LLM or alert sink). Presence and
/// health are derived from configuration/behaviour, never from secrets.
pub fn record_component<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
    kind: ComponentKind,
    state: rieko_status::ComponentState,
) -> Result<()> {
    let mut op = storage
        .read_operational_state()
        .unwrap_or_default()
        .unwrap_or_default();
    match kind {
        ComponentKind::Llm => op.llm = state,
        ComponentKind::AlertSink => op.alert_sink = state,
    }
    storage
        .write_operational_state(&op)
        .context("recording operational state")?;
    Ok(())
}

pub enum ComponentKind {
    Llm,
    AlertSink,
}

/// Shared per-finding pipeline used by scan and monitor: persist, ask the LLM
/// for a plain-language explanation (optional), turn the finding into auditable
/// recommendations. Returns everything that was recommended so callers can
/// alert/report.
pub fn persist_and_recommend<S: Storage + rieko_status::OperationalStateStore>(
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
            record_cycle_success(storage)?;
            Ok(all)
        }
        Err(e) => {
            let _ = storage.rollback_transaction();
            Err(e)
        }
    }
}

/// A completed, committed detector cycle. Updated outside the transaction so a
/// rolled-back cycle does not falsely look successful.
fn record_cycle_success<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
) -> Result<()> {
    let now = chrono::Utc::now();
    let mut state = storage
        .read_operational_state()
        .unwrap_or_default()
        .unwrap_or_default();
    state.last_cycle_attempt = Some(now);
    state.last_cycle_success = Some(now);
    state.last_persist_success = Some(now);
    storage
        .write_operational_state(&state)
        .context("recording cycle completion")?;
    Ok(())
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
            channel_point: "tx:0".into(),
            capacity_msat: capacity,
            fee_policy: FeePolicy::default(),
            status: ChannelStatus::Active,
            liquidity: LiquidityProfile::compute(capacity, local_msat, remote_msat),
            last_seen: chrono::Utc::now(),
            opening_height: Some(1),
            local_reserve_msat: None,
            remote_reserve_msat: None,
            is_private: false,
            is_initiator: true,
            total_sent_msat: None,
            total_received_msat: None,
        }])
        .unwrap();
        g
    }

    fn detect(graph: &InMemoryGraph) -> Vec<rieko_findings::Finding> {
        let detector = LiquidityDetector::new("local-node");
        detector.run(graph, &rieko_detectors::DetectorContext::no_context())
    }

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/channels.json")
    }

    #[test]
    fn fixture_vertical_slice_produces_expected_findings_and_recommendations() {
        // Phase 3 gate: the full v1 slice (fixture → ingest → detect →
        // recommend → persist) must work end to end against the committed
        // fixture and match the documented liquidity semantics (RIEKO-AUDIT-011).
        let source = GraphSource {
            fixture: Some(fixture_path()),
            node: "local-node".into(),
            ..Default::default()
        };
        let graph = source.build().expect("fixture should load");

        let findings = detect(&graph);
        // 3 imbalanced channels: one Critical (ratio 0.01), one outbound
        // Warning (0.08), one inbound Warning (0.95); two are Balanced.
        assert_eq!(findings.len(), 3, "findings: {findings:#?}");
        let critical = findings
            .iter()
            .filter(|f| f.severity == rieko_findings::Severity::Critical)
            .count();
        let warning = findings
            .iter()
            .filter(|f| f.severity == rieko_findings::Severity::Warning)
            .count();
        assert_eq!(critical, 1);
        assert_eq!(warning, 2);

        let mut storage = MemoryStorage::new();
        let engine = rieko_recommendations::RecommendationEngine;
        let recs =
            persist_and_recommend(&mut storage, &NullClient, &engine, "local-node", &findings)
                .unwrap();
        // The engine may emit more than one recommendation per finding (e.g. a
        // warning channel gets both a fee review and a rebalance review), but
        // every finding must lead to at least one, and nothing may be dropped.
        assert!(
            recs.len() >= findings.len(),
            "expected at least one recommendation per finding, got {}",
            recs.len()
        );
        for f in &findings {
            assert!(
                recs.iter().any(|r| r.finding_id == f.id),
                "no recommendation for finding {}",
                f.id
            );
        }

        for rec in &recs {
            // Recommendations are decision support: no numeric mutation params,
            // and a non-empty rationale carried through persistence.
            for banned in [
                "desired_ratio",
                "fee_rate_ppm",
                "base_fee_msat",
                "cltv_delta",
                "method",
            ] {
                assert!(
                    rec.action.params.get(banned).is_none(),
                    "recommendation for {} must not carry mutation param {banned}",
                    rec.finding_id
                );
            }
            assert!(
                !rec.rationale.expected_effect.is_empty(),
                "recommendation rationale must be populated without an LLM"
            );
        }
        assert_eq!(
            storage.latest_recommendations(10).unwrap().len(),
            recs.len()
        );
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

    #[cfg(feature = "future")]
    #[test]
    fn simulation_does_not_create_a_false_audit_transition() {
        // RIEKO-AUDIT-007: simulating a recommended action is read-only. It
        // must not append a `Simulated` audit entry, because the
        // recommendation's stage never actually changes to Simulated (v1 ends
        // at Recommend). The only audit rows allowed are the `Recommended`
        // creation entries from persist_and_recommend.
        use rieko_graph::GraphView;
        use rieko_simulation::Simulator;
        use rieko_storage::{MemoryStorage, Storage};

        let engine = rieko_recommendations::RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let findings = detect(&graph);
        let mut storage = MemoryStorage::new();
        let recs =
            persist_and_recommend(&mut storage, &NullClient, &engine, "local-node", &findings)
                .unwrap();
        assert!(!recs.is_empty(), "expected at least one recommendation");

        // Simulate each recommended action exactly as the `simulate` command
        // does, persisting the projection but never an audit transition.
        for rec in &recs {
            let Some(target) = rec.action.target.as_deref() else {
                continue;
            };
            let Some(channel) = graph.channel(&rieko_domain::ChannelId::new(target)) else {
                continue;
            };
            let sim = Simulator
                .project(channel, &rec.action, &rec.finding_id)
                .unwrap();
            storage.save_simulation(&sim).unwrap();
        }
        assert!(!storage.recent_simulations(100).unwrap().is_empty());

        let audit = storage.recent_audit(1000).unwrap();
        assert_eq!(
            audit.len(),
            recs.len(),
            "one audit entry per recommendation"
        );
        for entry in &audit {
            assert_eq!(
                entry.stage,
                rieko_findings::ActionStage::Recommended,
                "no audit row may claim a Simulated transition from a read-only simulation"
            );
            assert_eq!(
                entry.previous_stage, None,
                "creation entries have no previous stage"
            );
        }
    }
}
