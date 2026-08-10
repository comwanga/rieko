use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rieko_domain::{BitcoinNetwork, ChannelSnapshot, NodeId};
use rieko_findings::{
    AuditEntry, Finding, FindingCycleScope, ObservationSource, ProducerRole, ProducerVersion,
    Recommendation,
};
use rieko_graph::{GraphStore, GraphView, InMemoryGraph};
use rieko_ingest_lnd::{LndChannelResponse, LndClient, Normalizer, ShortChanResolver};
use rieko_llm::{ExplainRequest, LlmClient};
use rieko_recommendations::RecommendationEngine;
use rieko_storage::Storage;
use tracing::{debug, info, warn};

const MAX_LLM_EXPLANATIONS_PER_CYCLE: usize = 3;

/// Where channel state comes from: a JSON fixture or a live LND REST node.
/// Both scan and monitor share this so the ingestion path stays identical.
#[derive(Debug, Clone)]
pub struct GraphSource {
    pub network: BitcoinNetwork,
    pub fixture: Option<PathBuf>,
    pub lnd_rest: Option<String>,
    pub macaroon: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub node: String,
}

impl GraphSource {
    pub fn observation_source(&self) -> Result<ObservationSource> {
        use sha2::{Digest, Sha256};

        let redacted = |value: &str| format!("{:x}", Sha256::digest(value.as_bytes()));
        if let Some(rest) = &self.lnd_rest {
            return Ok(ObservationSource::Lnd {
                redacted_endpoint: redacted(rest.trim_end_matches('/')),
                configured_node: self.node.clone(),
            });
        }
        if let Some(fixture) = &self.fixture {
            let contents = std::fs::read(fixture).with_context(|| {
                format!("reading fixture provenance from {}", fixture.display())
            })?;
            return Ok(ObservationSource::Fixture {
                redacted_hash: format!("{:x}", Sha256::digest(contents)),
                configured_node: self.node.clone(),
            });
        }
        bail!("provide --fixture or --lnd-rest")
    }

    pub fn normalizer(&self) -> ProducerVersion {
        ProducerVersion {
            name: "rieko-ingest-lnd".into(),
            version: rieko_ingest_lnd::VERSION.into(),
            role: ProducerRole::Normalizer,
        }
    }

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
            let observed_at = chrono::Utc::now();
            let channels = raw
                .iter()
                .map(|c| Normalizer::channel(c, &local, observed_at).map_err(anyhow::Error::from))
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
            if self.network == BitcoinNetwork::Mainnet {
                bail!("fixture data cannot represent mainnet production evidence; use --network regtest, testnet, or signet with --fixture");
            }
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
    let observed_at = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(chrono::DateTime::<chrono::Utc>::from)
        .unwrap_or_else(|_| chrono::Utc::now());
    parsed
        .channels
        .iter()
        .map(|c| Normalizer::channel(c, local, observed_at).map_err(|e| anyhow!(e.to_string())))
        .collect()
}

fn source_state(source: &GraphSource, connected: bool) -> rieko_status::SourceState {
    if source.lnd_rest.is_some() {
        rieko_status::SourceState::LndRest { connected }
    } else {
        rieko_status::SourceState::Fixture
    }
}

pub fn record_ingestion_attempt<S: rieko_status::OperationalStateStore>(
    storage: &mut S,
    source: &GraphSource,
) -> Result<()> {
    let source = source.clone();
    storage.update_operational_state(&|state: &mut _| {
        let was_connected = matches!(
            state.source,
            rieko_status::SourceState::LndRest { connected: true }
        );
        state.source = super::common::source_state(&source, was_connected);
        state.last_ingestion_attempt = Some(chrono::Utc::now());
    })?;
    Ok(())
}

pub fn record_ingestion_success<S: rieko_status::OperationalStateStore>(
    storage: &mut S,
    source: &GraphSource,
    source_data_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    let source = source.clone();
    let now = chrono::Utc::now();
    storage.update_operational_state(&|state: &mut _| {
        state.source = super::common::source_state(&source, true);
        state.last_ingestion_success = Some(now);
        if source_data_at.is_some() {
            state.source_data_at = source_data_at;
        }
    })?;
    Ok(())
}

pub fn record_ingestion_failure<S: rieko_status::OperationalStateStore>(
    storage: &mut S,
    source: &GraphSource,
) -> Result<()> {
    let source = source.clone();
    storage.update_operational_state(&|state: &mut _| {
        state.source = super::common::source_state(&source, false);
    })?;
    Ok(())
}

pub fn newest_source_data_at(graph: &dyn GraphView) -> Option<chrono::DateTime<chrono::Utc>> {
    graph
        .channels()
        .into_iter()
        .map(|channel| channel.last_seen)
        .chain(
            graph
                .recent_forwards(usize::MAX)
                .into_iter()
                .map(|event| event.timestamp),
        )
        .chain(
            graph
                .recent_payments(usize::MAX)
                .into_iter()
                .map(|event| event.timestamp),
        )
        .max()
}

pub fn record_cycle_attempt<S: rieko_status::OperationalStateStore>(storage: &mut S) -> Result<()> {
    let now = chrono::Utc::now();
    storage.update_operational_state(&|state: &mut _| {
        state.last_cycle_attempt = Some(now);
    })?;
    Ok(())
}

/// Record the state of an optional component (LLM or alert sink). Presence and
/// health are derived from configuration/behaviour, never from secrets.
pub fn record_component<S: rieko_status::OperationalStateStore>(
    storage: &mut S,
    kind: ComponentKind,
    component_state: rieko_status::ComponentState,
) -> Result<()> {
    storage.update_operational_state(&|op: &mut _| match kind {
        ComponentKind::Llm => op.llm = component_state,
        ComponentKind::AlertSink => op.alert_sink = component_state,
    })?;
    Ok(())
}

pub enum ComponentKind {
    Llm,
    AlertSink,
}

/// Run channel_snapshot retention cleanup at most once per
/// `policy.cleanup_interval`. Uses the persisted `last_cleanup_success` so the
/// schedule survives restarts and is shared by both `scan` and `monitor`.
/// Returns `true` when a cleanup pass actually executed.
pub fn run_cleanup_if_due<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
    policy: &rieko_storage::RetentionPolicy,
) -> Result<bool> {
    let now = chrono::Utc::now();
    let last = storage
        .read_operational_state()
        .unwrap_or(None)
        .and_then(|op| op.last_cleanup_success);
    let interval =
        chrono::Duration::from_std(policy.cleanup_interval).unwrap_or(chrono::Duration::zero());
    if last.is_some_and(|t| now - t < interval) {
        return Ok(false);
    }
    storage.update_operational_state(&|op: &mut _| {
        op.last_cleanup_attempt = Some(now);
    })?;
    let outcome = storage
        .prune_channel_snapshots(policy, now)
        .map_err(|e| anyhow!("cleanup: {}", e));
    storage.update_operational_state(&|op: &mut _| match &outcome {
        Ok(summary) => {
            op.cleanup = rieko_status::ComponentState::Healthy;
            op.last_cleanup_success = Some(now);
            info!(
                deleted_snapshots = summary.deleted_snapshots,
                "retention cleanup complete"
            );
        }
        Err(e) => {
            op.cleanup = rieko_status::ComponentState::Failing;
            warn!(error = %e, "retention cleanup failed");
        }
    })?;
    outcome.map(|_| true)
}

/// Shared per-finding pipeline used by scan and monitor: persist, ask the LLM
/// for a plain-language explanation (optional), turn the finding into auditable
/// recommendations. Returns everything that was recommended so callers can
/// alert/report.
pub fn persist_and_recommend<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
    llm: Option<&dyn LlmClient>,
    engine: &RecommendationEngine,
    node: &str,
    scopes: &[FindingCycleScope],
    findings: &mut [Finding],
) -> Result<Vec<Recommendation>> {
    persist_cycle(storage, llm, engine, node, &[], scopes, findings)
}

pub fn persist_monitor_cycle<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
    llm: Option<&dyn LlmClient>,
    engine: &RecommendationEngine,
    node: &str,
    snapshots: &[ChannelSnapshot],
    scopes: &[FindingCycleScope],
    findings: &mut [Finding],
) -> Result<Vec<Recommendation>> {
    persist_cycle(storage, llm, engine, node, snapshots, scopes, findings)
}

fn persist_cycle<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
    llm: Option<&dyn LlmClient>,
    engine: &RecommendationEngine,
    node: &str,
    snapshots: &[ChannelSnapshot],
    scopes: &[FindingCycleScope],
    findings: &mut [Finding],
) -> Result<Vec<Recommendation>> {
    explain_findings(storage, llm, node, findings)?;

    storage
        .begin_transaction()
        .context("beginning persistence transaction")?;

    let result = (|| {
        for snapshot in snapshots {
            storage.save_channel_snapshot(snapshot)?;
        }
        for scope in scopes {
            storage.resolve_findings_for_scope(scope)?;
        }
        let recommendations = persist_cycle_locked(storage, engine, findings)?;
        record_cycle_success(storage)?;
        Ok(recommendations)
    })();

    match result {
        Ok(all) => {
            if let Err(error) = storage.commit_transaction() {
                let _ = storage.rollback_transaction();
                return Err(error).context("committing persistence transaction");
            }
            Ok(all)
        }
        Err(e) => {
            let _ = storage.rollback_transaction();
            Err(e)
        }
    }
}

fn explain_findings<S: rieko_status::OperationalStateStore>(
    storage: &mut S,
    llm: Option<&dyn LlmClient>,
    node: &str,
    findings: &mut [Finding],
) -> Result<()> {
    let Some(llm) = llm else {
        return Ok(());
    };
    if findings.is_empty() {
        return Ok(());
    }

    let mut failed = false;
    for finding in findings.iter_mut().take(MAX_LLM_EXPLANATIONS_PER_CYCLE) {
        match llm.explain(&ExplainRequest {
            finding,
            context: Some(format!("local node id {node}")),
        }) {
            Ok(Some(text)) => {
                finding.explanation = Some(text);
                debug!(finding = %finding.id, "explanation generated");
            }
            Ok(None) => {}
            Err(error) => {
                failed = true;
                warn!(error = %error, finding = %finding.id, "explanation skipped");
            }
        }
    }
    if findings.len() > MAX_LLM_EXPLANATIONS_PER_CYCLE {
        warn!(
            skipped = findings.len() - MAX_LLM_EXPLANATIONS_PER_CYCLE,
            limit = MAX_LLM_EXPLANATIONS_PER_CYCLE,
            "LLM explanation cycle limit reached"
        );
    }
    record_component(
        storage,
        ComponentKind::Llm,
        if failed {
            rieko_status::ComponentState::Failing
        } else {
            rieko_status::ComponentState::Healthy
        },
    )
}

/// Mark a completed detector cycle inside the same transaction as its data, so
/// a rollback cannot leave either side claiming success independently.
fn record_cycle_success<S: Storage + rieko_status::OperationalStateStore>(
    storage: &mut S,
) -> Result<()> {
    let now = chrono::Utc::now();
    storage.update_operational_state(&|state: &mut _| {
        state.last_cycle_success = Some(now);
        state.last_persist_success = Some(now);
    })?;
    Ok(())
}

/// The body of a cycle, run inside the transaction opened by
/// [`persist_and_recommend`].
fn persist_cycle_locked<S: Storage>(
    storage: &mut S,
    engine: &RecommendationEngine,
    findings: &[Finding],
) -> Result<Vec<Recommendation>> {
    let mut all = Vec::new();
    for finding in findings {
        storage.save_finding(finding)?;

        let recommendations = engine.recommend(finding).with_context(|| {
            format!(
                "recommending for finding {} from detector {} version {}",
                finding.id, finding.detector, finding.detector_version
            )
        })?;
        for rec in recommendations {
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
    use rieko_llm::LlmError;
    use rieko_status::OperationalStateStore;
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
        detector.run(
            graph,
            &rieko_detectors::DetectorContext::no_context(BitcoinNetwork::Regtest),
        )
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
            network: BitcoinNetwork::Regtest,
            fixture: Some(fixture_path()),
            lnd_rest: None,
            macaroon: None,
            tls_cert: None,
            node: "local-node".into(),
        };
        let graph = source.build().expect("fixture should load");

        let observation_source = source.observation_source().unwrap();
        let normalizer = source.normalizer();
        let context = rieko_detectors::DetectorContext {
            network: source.network,
            history: None,
            source: Some(&observation_source),
            normalizer: Some(&normalizer),
            node: Some("local-node"),
        };
        let cycle = LiquidityDetector::new("local-node")
            .evaluate(&graph, &context)
            .unwrap();
        let scopes = vec![cycle.scope];
        let mut findings = cycle.findings;
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
        assert!(findings.iter().all(|finding| finding.provenance.is_some()));
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&fixture_path().to_string_lossy().to_string()));

        let mut storage = MemoryStorage::new();
        let engine = rieko_recommendations::RecommendationEngine;
        let recs = persist_and_recommend(
            &mut storage,
            None,
            &engine,
            "local-node",
            &scopes,
            &mut findings,
        )
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
    fn fixture_provenance_tracks_content_without_exposing_path() {
        use std::io::Write;

        let mut fixture = tempfile::NamedTempFile::new().unwrap();
        fixture.write_all(b"first observation").unwrap();
        let source = GraphSource {
            network: BitcoinNetwork::Regtest,
            fixture: Some(fixture.path().to_path_buf()),
            lnd_rest: None,
            tls_cert: None,
            macaroon: None,
            node: "local-node".into(),
        };
        let first = source.observation_source().unwrap();
        std::fs::write(fixture.path(), b"second observation").unwrap();
        let second = source.observation_source().unwrap();

        assert_ne!(first, second);
        for provenance in [first, second] {
            let json = serde_json::to_string(&provenance).unwrap();
            assert!(!json.contains(&fixture.path().to_string_lossy().to_string()));
        }
    }

    #[test]
    fn missing_macaroon_file_fails_cleanly() {
        let source = GraphSource {
            network: BitcoinNetwork::Regtest,
            fixture: None,
            lnd_rest: Some("http://127.0.0.1:1".into()),
            macaroon: Some(std::path::PathBuf::from("/definitely/not/a/macaroon")),
            tls_cert: None,
            node: "local-node".into(),
        };
        let msg = source.build().unwrap_err().to_string();
        assert!(
            msg.contains("macaroon"),
            "missing macaroon file should fail with a clear message, got: {msg}"
        );
    }

    struct SuccessfulLlm;

    impl LlmClient for SuccessfulLlm {
        fn explain(&self, _: &ExplainRequest) -> Result<Option<String>, LlmError> {
            Ok(Some("bounded explanation".into()))
        }
    }

    struct FailingLlm;

    impl LlmClient for FailingLlm {
        fn explain(&self, _: &ExplainRequest) -> Result<Option<String>, LlmError> {
            Err(LlmError::Request("offline".into()))
        }
    }

    struct TransactionProbeLlm {
        storage: std::sync::Mutex<SqliteStorage>,
        succeeded: std::sync::atomic::AtomicBool,
    }

    struct CountingLlm(std::sync::atomic::AtomicUsize);

    impl LlmClient for CountingLlm {
        fn explain(&self, _: &ExplainRequest) -> Result<Option<String>, LlmError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some("bounded".into()))
        }
    }

    impl LlmClient for TransactionProbeLlm {
        fn explain(&self, _: &ExplainRequest) -> Result<Option<String>, LlmError> {
            let mut storage = self.storage.lock().unwrap();
            storage
                .begin_transaction()
                .map_err(|error| LlmError::Request(error.to_string()))?;
            storage
                .rollback_transaction()
                .map_err(|error| LlmError::Request(error.to_string()))?;
            self.succeeded
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Some("writer lock was free".into()))
        }
    }

    #[test]
    fn llm_explanation_is_propagated_and_persisted_before_transaction() {
        let engine = RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let mut findings = detect(&graph);
        let mut storage = MemoryStorage::new();

        persist_and_recommend(
            &mut storage,
            Some(&SuccessfulLlm),
            &engine,
            "local-node",
            &[],
            &mut findings,
        )
        .unwrap();

        assert_eq!(
            findings[0].explanation.as_deref(),
            Some("bounded explanation")
        );
        assert_eq!(
            storage.latest_findings(1).unwrap()[0]
                .explanation
                .as_deref(),
            Some("bounded explanation")
        );
        assert_eq!(
            storage.read_operational_state().unwrap().unwrap().llm,
            rieko_status::ComponentState::Healthy
        );
    }

    #[test]
    fn llm_failure_does_not_block_authoritative_cycle() {
        let engine = RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let mut findings = detect(&graph);
        let mut storage = MemoryStorage::new();

        let recommendations = persist_and_recommend(
            &mut storage,
            Some(&FailingLlm),
            &engine,
            "local-node",
            &[],
            &mut findings,
        )
        .unwrap();

        assert!(!recommendations.is_empty());
        assert!(!storage.latest_findings(10).unwrap().is_empty());
        assert_eq!(
            storage.read_operational_state().unwrap().unwrap().llm,
            rieko_status::ComponentState::Failing
        );
    }

    #[test]
    fn llm_runs_before_sqlite_writer_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("llm-order.db");
        let mut storage = SqliteStorage::open(&db).unwrap();
        let probe = TransactionProbeLlm {
            storage: std::sync::Mutex::new(SqliteStorage::open(&db).unwrap()),
            succeeded: std::sync::atomic::AtomicBool::new(false),
        };
        let engine = RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let mut findings = detect(&graph);

        persist_and_recommend(
            &mut storage,
            Some(&probe),
            &engine,
            "local-node",
            &[],
            &mut findings,
        )
        .unwrap();

        assert!(probe.succeeded.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn llm_work_is_bounded_per_cycle() {
        let graph = drained_graph(20_000, 980_000);
        let mut finding = detect(&graph).remove(0);
        finding.explanation = None;
        let mut findings = vec![finding; MAX_LLM_EXPLANATIONS_PER_CYCLE + 2];
        let llm = CountingLlm(std::sync::atomic::AtomicUsize::new(0));
        let mut storage = MemoryStorage::new();

        explain_findings(&mut storage, Some(&llm), "local-node", &mut findings).unwrap();

        assert_eq!(
            llm.0.load(std::sync::atomic::Ordering::SeqCst),
            MAX_LLM_EXPLANATIONS_PER_CYCLE
        );
        assert!(findings[..MAX_LLM_EXPLANATIONS_PER_CYCLE]
            .iter()
            .all(|finding| finding.explanation.is_some()));
        assert!(findings[MAX_LLM_EXPLANATIONS_PER_CYCLE..]
            .iter()
            .all(|finding| finding.explanation.is_none()));
    }

    #[test]
    fn monitor_cycle_commits_snapshots_with_findings_and_audit() {
        let engine = RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let now = chrono::Utc::now();
        let snapshots: Vec<_> = graph
            .channels()
            .iter()
            .map(|channel| ChannelSnapshot::from_channel(channel, now, BitcoinNetwork::Regtest))
            .collect();
        let mut findings = detect(&graph);
        let mut storage = MemoryStorage::new();

        persist_monitor_cycle(
            &mut storage,
            None,
            &engine,
            "local-node",
            &snapshots,
            &[],
            &mut findings,
        )
        .unwrap();

        assert_eq!(storage.recent_snapshots_all(10).unwrap(), snapshots);
        assert!(!storage.latest_findings(10).unwrap().is_empty());
        assert!(!storage.latest_recommendations(10).unwrap().is_empty());
        assert!(!storage.recent_audit(10).unwrap().is_empty());
    }

    #[test]
    fn changing_measurements_update_and_resolve_one_logical_finding() {
        let engine = RecommendationEngine;
        let scope = FindingCycleScope {
            detector: "channel_liquidity".into(),
            network: None,
            node: Some("local-node".into()),
            complete: true,
        };
        let mut storage = MemoryStorage::new();
        let warning_graph = drained_graph(80_000, 920_000);
        let mut warning = detect(&warning_graph);
        persist_and_recommend(
            &mut storage,
            None,
            &engine,
            "local-node",
            std::slice::from_ref(&scope),
            &mut warning,
        )
        .unwrap();
        let first = storage.latest_findings(10).unwrap().remove(0);

        let critical_graph = drained_graph(20_000, 980_000);
        let mut critical = detect(&critical_graph);
        critical[0].timestamp = first.timestamp + chrono::Duration::seconds(1);
        critical[0].first_seen_at = critical[0].timestamp;
        critical[0].last_seen_at = critical[0].timestamp;
        assert_eq!(critical[0].id, first.id);
        persist_and_recommend(
            &mut storage,
            None,
            &engine,
            "local-node",
            std::slice::from_ref(&scope),
            &mut critical,
        )
        .unwrap();

        let current = storage.latest_findings(10).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].severity, rieko_findings::Severity::Critical);
        assert_eq!(current[0].first_seen_at, first.first_seen_at);
        assert_eq!(storage.recent_audit(10).unwrap().len(), 1);

        let mut recovered = Vec::new();
        for _ in 0..3 {
            persist_and_recommend(
                &mut storage,
                None,
                &engine,
                "local-node",
                std::slice::from_ref(&scope),
                &mut recovered,
            )
            .unwrap();
        }
        assert_eq!(
            storage.latest_findings(10).unwrap()[0].lifecycle,
            rieko_findings::FindingLifecycle::Resolved
        );
    }

    #[test]
    fn malformed_finding_rolls_back_complete_monitor_cycle() {
        let engine = RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);
        let mut findings = detect(&graph);
        findings[0]
            .evidence
            .retain(|evidence| evidence.key != "direction");
        let snapshot = ChannelSnapshot::from_channel(
            graph.channels()[0],
            chrono::Utc::now(),
            BitcoinNetwork::Regtest,
        );
        let scope = FindingCycleScope {
            detector: "channel_liquidity".into(),
            network: None,
            node: Some("local-node".into()),
            complete: true,
        };
        let mut storage = MemoryStorage::new();
        record_cycle_attempt(&mut storage).unwrap();

        let result = persist_monitor_cycle(
            &mut storage,
            None,
            &engine,
            "local-node",
            &[snapshot],
            &[scope],
            &mut findings,
        );

        assert!(result.is_err());
        assert!(storage.latest_findings(10).unwrap().is_empty());
        assert!(storage.recent_snapshots_all(10).unwrap().is_empty());
        assert!(storage.latest_recommendations(10).unwrap().is_empty());
        assert!(storage.recent_audit(10).unwrap().is_empty());
        assert!(storage
            .read_operational_state()
            .unwrap()
            .unwrap()
            .last_cycle_success
            .is_none());
    }

    #[test]
    fn failed_ingestion_preserves_last_good_observation() {
        let source = GraphSource {
            network: BitcoinNetwork::Regtest,
            fixture: None,
            lnd_rest: Some("https://localhost:8080".into()),
            macaroon: None,
            tls_cert: None,
            node: "local-node".into(),
        };
        let graph = drained_graph(20_000, 980_000);
        let observed_at = newest_source_data_at(&graph);
        let mut storage = MemoryStorage::new();

        record_ingestion_attempt(&mut storage, &source).unwrap();
        record_ingestion_success(&mut storage, &source, observed_at).unwrap();
        let successful = storage.read_operational_state().unwrap().unwrap();
        record_ingestion_attempt(&mut storage, &source).unwrap();
        record_ingestion_failure(&mut storage, &source).unwrap();
        let failed = storage.read_operational_state().unwrap().unwrap();

        assert_eq!(
            failed.last_ingestion_success,
            successful.last_ingestion_success
        );
        assert_eq!(failed.source_data_at, observed_at);
        assert_eq!(
            failed.source,
            rieko_status::SourceState::LndRest { connected: false }
        );
    }

    #[test]
    fn replay_produces_no_duplicates_in_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let engine = rieko_recommendations::RecommendationEngine;
        let graph = drained_graph(20_000, 980_000);

        let run = |db_path: &std::path::Path| -> (usize, usize, usize) {
            let mut storage = SqliteStorage::open(db_path).unwrap();
            let mut findings = detect(&graph);
            persist_and_recommend(
                &mut storage,
                None,
                &engine,
                "local-node",
                &[],
                &mut findings,
            )
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
        let mut findings = detect(&graph);
        let mut storage = MemoryStorage::new();
        persist_and_recommend(
            &mut storage,
            None,
            &engine,
            "local-node",
            &[],
            &mut findings,
        )
        .unwrap();
        let n1 = storage.recent_audit(1000).unwrap().len();
        persist_and_recommend(
            &mut storage,
            None,
            &engine,
            "local-node",
            &[],
            &mut findings,
        )
        .unwrap();
        let n2 = storage.recent_audit(1000).unwrap().len();
        assert_eq!(
            n1, n2,
            "replaying identical findings must not append audits"
        );
        assert_eq!(n1, findings.len(), "one audit entry per new finding");
    }

    #[cfg(feature = "simulate")]
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
        let mut findings = detect(&graph);
        let mut storage = MemoryStorage::new();
        let recs = persist_and_recommend(
            &mut storage,
            None,
            &engine,
            "local-node",
            &[],
            &mut findings,
        )
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
