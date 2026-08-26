use anyhow::{Context, Result};
use clap::Args;
use rieko_findings::Finding;

use super::findings::{ApiArgs, ApiClient};

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// Stable identifier of the persisted finding.
    #[arg(value_name = "FINDING_ID")]
    finding_id: String,

    #[command(flatten)]
    api: ApiArgs,
}

pub fn run(args: ExplainArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building explain client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let finding = runtime.block_on(client.fetch_finding(&args.finding_id))?;
    println!("{}", render_finding(&finding)?);
    Ok(())
}

fn render_finding(finding: &Finding) -> Result<String> {
    serde_json::to_string_pretty(finding).context("rendering typed finding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use chrono::{TimeZone, Utc};
    use rieko_api::RiekoApi;
    use rieko_domain::BitcoinNetwork;
    use rieko_findings::{
        ChannelSnapshotReference, Evidence, FindingLifecycle, FindingProvenance,
        ObservationReference, ObservationSource, ProducerRole, ProducerVersion, Severity,
        FINDING_SCHEMA_VERSION,
    };
    use rieko_storage::{MemoryStorage, Storage};

    fn finding() -> Finding {
        let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        Finding {
            id: "finding/detail".into(),
            detector: "settlement_reliability".into(),
            detector_version: "1".into(),
            schema_version: FINDING_SCHEMA_VERSION,
            severity: Severity::Warning,
            node: Some("node-test".into()),
            channel: None,
            evidence: vec![Evidence {
                key: "invoice_ids".into(),
                value: serde_json::json!(["invoice-a", "invoice-b"]),
            }],
            provenance: Some(FindingProvenance {
                network: Some(BitcoinNetwork::Regtest),
                source: ObservationSource::BtcPay {
                    redacted_endpoint: "sha256:endpoint".into(),
                    configured_store: "store-test".into(),
                    underlying_node: Some("node-test".into()),
                },
                producers: vec![ProducerVersion {
                    name: "settlement_reliability".into(),
                    version: "1".into(),
                    role: ProducerRole::Detector,
                }],
                observation: ObservationReference::ChannelState {
                    channel_id: String::new(),
                    snapshot: ChannelSnapshotReference {
                        network: Some(BitcoinNetwork::Regtest),
                        observed_at,
                        state_digest: "digest-test".into(),
                    },
                },
            }),
            explanation: Some("Persisted explanation".into()),
            timestamp: observed_at,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
            lifecycle: FindingLifecycle::Active,
        }
    }

    async fn start(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    fn client(api_url: String, token_file: Option<std::path::PathBuf>) -> ApiClient {
        ApiClient::new(&ApiArgs {
            api_url,
            token_file,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn fetches_and_renders_the_exact_persisted_typed_finding() {
        let expected = finding();
        let mut storage = MemoryStorage::new();
        storage.save_finding(&expected).unwrap();
        let app = RiekoApi::new(Box::new(storage)).unwrap().router();
        let (api_url, server) = start(app).await;

        let actual = client(api_url, None)
            .fetch_finding(&expected.id)
            .await
            .unwrap();
        let rendered = render_finding(&actual).unwrap();
        let decoded: Finding = serde_json::from_str(&rendered).unwrap();

        server.abort();
        assert_eq!(decoded, expected);
        assert_eq!(
            decoded.evidence[0].value,
            serde_json::json!(["invoice-a", "invoice-b"])
        );
    }

    #[tokio::test]
    async fn reports_not_found_without_falling_back_to_the_bounded_list() {
        let app = RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let error = client(api_url, None)
            .fetch_finding("missing")
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("404 Not Found"));
    }

    #[tokio::test]
    async fn reports_authentication_failure_from_the_detail_api() {
        let app = RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .with_auth("correct-token")
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "wrong-token\n").unwrap();

        let error = client(api_url, Some(token_file))
            .fetch_finding("missing")
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn rejects_a_malformed_typed_finding_response() {
        let app =
            axum::Router::new().route("/findings/:finding_id", get(|| async { "not a finding" }));
        let (api_url, server) = start(app).await;

        let error = client(api_url, None)
            .fetch_finding("finding-1")
            .await
            .unwrap_err();

        server.abort();
        assert!(error
            .to_string()
            .contains("decoding typed finding response"));
    }
}
