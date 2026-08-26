use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use reqwest::{Client, Url};
use rieko_findings::Finding;
use serde::de::DeserializeOwned;
#[cfg(feature = "simulate")]
use serde::Serialize;

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Args, Debug)]
pub(super) struct ApiArgs {
    /// Base URL of the running rieko-agent local API.
    #[arg(long, default_value = DEFAULT_API_URL, value_name = "URL")]
    pub(super) api_url: String,

    /// File whose first non-empty line is the API bearer token.
    #[arg(long, value_name = "FILE")]
    pub(super) token_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct FindingsArgs {
    #[command(flatten)]
    api: ApiArgs,

    /// Maximum number of findings to return.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=500))]
    limit: u32,

    /// Finding lifecycle to include.
    #[arg(long, value_enum, default_value_t = Lifecycle::Active)]
    lifecycle: Lifecycle,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum Lifecycle {
    Active,
    Resolved,
    All,
}

impl Lifecycle {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Resolved => "resolved",
            Self::All => "all",
        }
    }
}

pub fn run(args: FindingsArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building findings client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let findings = runtime.block_on(client.fetch_findings(args.limit, args.lifecycle))?;
    println!("{}", render_findings(&findings)?);
    Ok(())
}

pub(super) struct ApiClient {
    client: Client,
    api_url: Url,
    token: Option<String>,
}

impl ApiClient {
    pub(super) fn new(args: &ApiArgs) -> Result<Self> {
        let api_url = Url::parse(&args.api_url)
            .with_context(|| format!("invalid API URL {}", args.api_url))?;
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building findings API client")?;
        Ok(Self {
            client,
            api_url,
            token: load_token(args.token_file.as_deref())?,
        })
    }

    pub(super) async fn fetch_findings(
        &self,
        limit: u32,
        lifecycle: Lifecycle,
    ) -> Result<Vec<Finding>> {
        let url = findings_url(&self.api_url, limit, lifecycle);
        self.get(
            url,
            "requesting findings",
            "findings API",
            "decoding typed findings response",
        )
        .await
    }

    pub(super) async fn fetch_finding(&self, finding_id: &str) -> Result<Finding> {
        let mut url = self.api_url.clone();
        url.set_query(None);
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("API URL cannot be used as a base URL"))?
            .clear()
            .push("findings")
            .push(finding_id);
        self.get(
            url,
            "requesting finding",
            "finding API",
            "decoding typed finding response",
        )
        .await
    }

    pub(super) async fn fetch_status(&self) -> Result<rieko_api::routes::Status> {
        let mut url = self.api_url.clone();
        url.set_path("/status");
        url.set_query(None);
        self.get(
            url,
            "requesting status",
            "status API",
            "decoding typed status response",
        )
        .await
    }

    #[cfg(feature = "execute")]
    pub(super) async fn fetch_recommendations(
        &self,
        limit: u32,
    ) -> Result<Vec<rieko_findings::Recommendation>> {
        let mut url = self.api_url.clone();
        url.set_path("/recommendations");
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string())
            .append_pair("lifecycle", "all");
        self.get(
            url,
            "requesting actions",
            "recommendations API",
            "decoding typed recommendations response",
        )
        .await
    }

    #[cfg(feature = "simulate")]
    pub(super) async fn fetch_simulations(
        &self,
        limit: u32,
    ) -> Result<Vec<rieko_simulation_app::SimulationView>> {
        let mut url = self.api_url.clone();
        url.set_path("/api/v2/simulations");
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
        self.get(
            url,
            "requesting simulations",
            "simulations API",
            "decoding typed simulations response",
        )
        .await
    }

    #[cfg(feature = "simulate")]
    pub(super) async fn fetch_simulation(
        &self,
        simulation_id: &str,
    ) -> Result<rieko_simulation_app::SimulationView> {
        let mut url = self.api_url.clone();
        url.set_query(None);
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("API URL cannot be used as a base URL"))?
            .clear()
            .push("api")
            .push("v2")
            .push("simulations")
            .push(simulation_id);
        self.get(
            url,
            "requesting simulation",
            "simulation API",
            "decoding typed simulation response",
        )
        .await
    }

    #[cfg(feature = "simulate")]
    pub(super) async fn compare_simulations(
        &self,
        command: &rieko_simulation_app::CompareSimulationsCommand,
    ) -> Result<rieko_simulation_app::SimulationComparison> {
        let mut url = self.api_url.clone();
        url.set_path("/api/v2/simulations/compare");
        url.set_query(None);
        self.post(
            url,
            command,
            "requesting simulation comparison",
            "simulation comparison API",
            "decoding typed simulation comparison response",
        )
        .await
    }

    async fn get<T: DeserializeOwned>(
        &self,
        url: Url,
        request_context: &'static str,
        api_name: &'static str,
        decode_context: &'static str,
    ) -> Result<T> {
        let mut request = self.client.get(url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.context(request_context)?;
        let status = response.status();
        let body = response.text().await.context("reading API response")?;
        if !status.is_success() {
            bail!("{api_name} returned {status}: {}", body.trim());
        }
        serde_json::from_str(&body).context(decode_context)
    }

    #[cfg(feature = "simulate")]
    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
        request_context: &'static str,
        api_name: &'static str,
        decode_context: &'static str,
    ) -> Result<T> {
        let mut request = self.client.post(url).json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.context(request_context)?;
        let status = response.status();
        let body = response.text().await.context("reading API response")?;
        if !status.is_success() {
            bail!("{api_name} returned {status}: {}", body.trim());
        }
        serde_json::from_str(&body).context(decode_context)
    }
}

fn findings_url(api_url: &Url, limit: u32, lifecycle: Lifecycle) -> Url {
    let mut url = api_url.clone();
    url.set_path("/findings");
    url.set_query(None);
    url.query_pairs_mut()
        .append_pair("limit", &limit.to_string())
        .append_pair("lifecycle", lifecycle.as_str());
    url
}

fn load_token(path: Option<&std::path::Path>) -> Result<Option<String>> {
    if let Some(path) = path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading API token file {}", path.display()))?;
        return contents
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| Some(line.to_owned()))
            .context("API token file is empty");
    }
    match std::env::var("RIEKO_API_TOKEN") {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        Ok(_) => bail!("RIEKO_API_TOKEN is empty"),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("RIEKO_API_TOKEN is not valid Unicode"),
    }
}

fn render_findings(findings: &[Finding]) -> Result<String> {
    serde_json::to_string_pretty(findings).context("rendering typed findings")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rieko_api::RiekoApi;
    use rieko_findings::{Evidence, FindingLifecycle, Severity, FINDING_SCHEMA_VERSION};
    use rieko_storage::{MemoryStorage, Storage};

    fn args(api_url: String) -> FindingsArgs {
        FindingsArgs {
            api: ApiArgs {
                api_url,
                token_file: None,
            },
            limit: 7,
            lifecycle: Lifecycle::All,
        }
    }

    fn finding() -> Finding {
        let now = Utc::now();
        Finding {
            id: "finding-1".into(),
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
            provenance: None,
            explanation: Some("Settlement reliability degraded".into()),
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: FindingLifecycle::Active,
        }
    }

    #[test]
    fn findings_url_uses_the_bounded_query_contract() {
        let url = findings_url(
            &Url::parse("http://127.0.0.1:8080/base").unwrap(),
            7,
            Lifecycle::All,
        );
        assert_eq!(url.path(), "/findings");
        assert_eq!(url.query(), Some("limit=7&lifecycle=all"));
    }

    #[test]
    fn rendering_roundtrips_typed_findings_and_structured_evidence() {
        let expected = finding();
        let rendered = render_findings(std::slice::from_ref(&expected)).unwrap();
        let decoded: Vec<Finding> = serde_json::from_str(&rendered).unwrap();
        assert_eq!(decoded, [expected]);
        assert_eq!(
            decoded[0].evidence[0].value,
            serde_json::json!(["invoice-a", "invoice-b"])
        );
    }

    #[tokio::test]
    async fn fetches_typed_findings_from_the_authenticated_local_api() {
        let mut storage = MemoryStorage::new();
        let expected = finding();
        storage.save_finding(&expected).unwrap();
        let app = RiekoApi::new(Box::new(storage))
            .unwrap()
            .with_auth("test-token")
            .unwrap()
            .router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "test-token\n").unwrap();
        let mut request_args = args(format!("http://{address}"));
        request_args.api.token_file = Some(token_file);
        let client = ApiClient::new(&request_args.api).unwrap();

        let received = client
            .fetch_findings(request_args.limit, request_args.lifecycle)
            .await
            .unwrap();

        server.abort();
        assert_eq!(received, [expected]);
    }
}
