use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rieko_findings::{Finding, FindingLifecycle};
use tokio::time::MissedTickBehavior;

use super::findings::{ApiArgs, ApiClient, Lifecycle};

#[derive(Args, Debug)]
pub struct WatchArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Maximum findings retained and compared per poll.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=500))]
    limit: u32,

    /// Seconds between bounded findings API polls.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    interval: u64,

    /// Stop after this many polls; zero watches until interrupted.
    #[arg(long, default_value_t = 0)]
    cycles: u64,
}

pub fn run(args: WatchArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building watch client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    runtime.block_on(watch(&args, &client, &mut output))
}

async fn watch<W: Write>(args: &WatchArgs, client: &ApiClient, output: &mut W) -> Result<()> {
    let mut state = WatchState::new(args.limit as usize);
    let mut polls = 0_u64;
    let mut ticker = tokio::time::interval(Duration::from_secs(args.interval));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("waiting for watch shutdown signal")?;
                return Ok(());
            }
            _ = ticker.tick() => {
                let findings = client.fetch_findings(args.limit, Lifecycle::All).await?;
                write_findings(output, &state.observe(findings))?;
                polls += 1;
                if args.cycles > 0 && polls >= args.cycles {
                    return Ok(());
                }
            }
        }
    }
}

struct WatchState {
    limit: usize,
    observed: HashMap<String, FindingLifecycle>,
}

impl WatchState {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            observed: HashMap::with_capacity(limit),
        }
    }

    fn observe(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut next = HashMap::with_capacity(self.limit);
        let mut changed = Vec::new();
        for finding in findings.into_iter().take(self.limit) {
            let meaningful_change = self
                .observed
                .get(&finding.id)
                .map_or(true, |lifecycle| *lifecycle != finding.lifecycle);
            next.insert(finding.id.clone(), finding.lifecycle);
            if meaningful_change {
                changed.push(finding);
            }
        }
        self.observed = next;
        changed
    }
}

fn write_findings<W: Write>(output: &mut W, findings: &[Finding]) -> Result<()> {
    for finding in findings {
        serde_json::to_writer(&mut *output, finding).context("rendering watched finding")?;
        writeln!(output).context("writing watched finding")?;
    }
    output.flush().context("flushing watched findings")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use rieko_findings::{Evidence, Severity, FINDING_SCHEMA_VERSION};

    fn finding(id: &str, lifecycle: FindingLifecycle, revision: i64) -> Finding {
        let observed_at = Utc.timestamp_opt(1_700_000_000 + revision, 0).unwrap();
        Finding {
            id: id.into(),
            detector: "settlement_reliability".into(),
            detector_version: "1".into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity: Severity::Warning,
            node: Some("node-test".into()),
            channel: None,
            evidence: vec![Evidence::number("revision", revision as f64)],
            provenance: None,
            explanation: None,
            timestamp: observed_at,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
            lifecycle,
        }
    }

    #[test]
    fn emits_new_findings_and_lifecycle_changes_but_not_refreshes() {
        let mut state = WatchState::new(10);
        let initial = finding("finding-1", FindingLifecycle::Active, 0);
        assert_eq!(state.observe(vec![initial.clone()]), [initial]);

        let refreshed = finding("finding-1", FindingLifecycle::Active, 1);
        assert!(state.observe(vec![refreshed]).is_empty());

        let resolved = finding("finding-1", FindingLifecycle::Resolved, 2);
        assert_eq!(state.observe(vec![resolved.clone()]), [resolved]);
    }

    #[test]
    fn observation_state_never_exceeds_the_configured_poll_limit() {
        let mut state = WatchState::new(2);
        let changed = state.observe(vec![
            finding("finding-1", FindingLifecycle::Active, 1),
            finding("finding-2", FindingLifecycle::Active, 2),
            finding("finding-3", FindingLifecycle::Active, 3),
        ]);
        assert_eq!(changed.len(), 2);
        assert_eq!(state.observed.len(), 2);
        assert!(!state.observed.contains_key("finding-3"));
    }

    #[test]
    fn output_is_newline_delimited_typed_findings_with_structured_evidence() {
        let expected = finding("finding-1", FindingLifecycle::Active, 1);
        let mut output = Vec::new();
        write_findings(&mut output, std::slice::from_ref(&expected)).unwrap();

        let rendered = String::from_utf8(output).unwrap();
        let decoded: Finding = serde_json::from_str(rendered.trim()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.evidence[0].value, serde_json::json!(1.0));
    }
}
