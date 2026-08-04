use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
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
                .map(|p| std::fs::read_to_string(p).map(|s| s.trim().to_string()))
                .transpose()
                .context("reading macaroon")?;
            let client = LndClient::new(rest, macaroon);
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
            storage.save_recommendation(&rec)?;
            let audit = AuditEntry::from_action(
                &rec.action,
                "system",
                serde_json::json!({"finding_id": rec.finding_id}),
            );
            storage.append_audit(&audit)?;
            info!(
                action = rec.action.action_type.as_str(),
                target = rec.action.target.as_deref().unwrap_or(""),
                summary = %rec.action.summary,
                "recommendation"
            );
            all.push(rec);
        }
    }
    Ok(all)
}
