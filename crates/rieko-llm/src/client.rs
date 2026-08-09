use std::time::Duration;

use rieko_findings::Finding;
use thiserror::Error;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A request to explain a finding. The LLM only *summarizes* structured
/// evidence — it never produces the finding (D1).
#[derive(Debug)]
pub struct ExplainRequest<'a> {
    pub finding: &'a Finding,
    /// Optional extra context, e.g. node version, uptime.
    pub context: Option<String>,
}

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("invalid LLM configuration: {0}")]
    Configuration(String),
    #[error("LLM request failed: {0}")]
    Request(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("unexpected LLM response: {0}")]
    Response(String),
}

/// A client that can explain a finding in plain language. Returns `Ok(None)`
/// when no explanation is available (e.g. not configured).
pub trait LlmClient {
    fn explain(&self, request: &ExplainRequest) -> Result<Option<String>, LlmError>;
}

/// No-op client used when no LLM is configured. Self-hosted operators can run
/// Rieko fully without any external AI dependency (D3).
pub struct NullClient;

impl LlmClient for NullClient {
    fn explain(&self, _request: &ExplainRequest) -> Result<Option<String>, LlmError> {
        Ok(None)
    }
}

/// OpenAI-compatible HTTP client (works with OpenAI, Ollama, LM Studio, etc.).
pub struct OpenAiCompatibleClient {
    endpoint: String,
    api_key: Option<String>,
    model: String,
    client: reqwest::blocking::Client,
}

impl OpenAiCompatibleClient {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: Option<String>,
        model: impl Into<String>,
    ) -> Result<Self, LlmError> {
        Self::with_timeouts(
            endpoint,
            api_key,
            model,
            DEFAULT_CONNECT_TIMEOUT,
            DEFAULT_REQUEST_TIMEOUT,
        )
    }

    /// Construct a client with explicit deadlines, primarily for callers that
    /// need stricter bounds and tests that must complete quickly.
    pub fn with_timeouts(
        endpoint: impl Into<String>,
        api_key: Option<String>,
        model: impl Into<String>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, LlmError> {
        if connect_timeout.is_zero() {
            return Err(LlmError::Configuration(
                "connect timeout must be greater than zero".into(),
            ));
        }
        if request_timeout.is_zero() {
            return Err(LlmError::Configuration(
                "request timeout must be greater than zero".into(),
            ));
        }

        let client = reqwest::blocking::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .map_err(|error| LlmError::Configuration(error.to_string()))?;

        Ok(Self {
            endpoint: endpoint.into(),
            api_key,
            model: model.into(),
            client,
        })
    }

    /// From `RIEKO_LLM_ENDPOINT`, `RIEKO_LLM_API_KEY`, `RIEKO_LLM_MODEL`.
    /// Returns `Ok(None)` when no endpoint is configured.
    pub fn from_env() -> Result<Option<Self>, LlmError> {
        let endpoint = match std::env::var("RIEKO_LLM_ENDPOINT") {
            Ok(endpoint) => endpoint,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(error) => {
                return Err(LlmError::Configuration(format!(
                    "RIEKO_LLM_ENDPOINT is invalid: {error}"
                )))
            }
        };
        let model = std::env::var("RIEKO_LLM_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
        let api_key = std::env::var("RIEKO_LLM_API_KEY").ok();
        Self::new(endpoint, api_key, model).map(Some)
    }
}

impl LlmClient for OpenAiCompatibleClient {
    fn explain(&self, request: &ExplainRequest) -> Result<Option<String>, LlmError> {
        use crate::prompt::build_explanation_prompt;

        let prompt = build_explanation_prompt(request.finding, request.context.as_deref());
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": "You are an operational intelligence engine for Bitcoin/Lightning infrastructure. Explain findings in plain language for a node operator. Be concise, specific, and cite the evidence numbers. Never invent facts." },
                { "role": "user", "content": prompt },
            ],
            "temperature": 0.2,
            "max_tokens": 300,
        });

        let mut req = self.client.post(&self.endpoint).json(&body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(LlmError::Request(format!("LLM endpoint returned {status}")));
        }
        let json: serde_json::Value = resp.json()?;
        let text = json
            .pointer("/choices/0/message/content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| LlmError::Response("no choices/0/message/content".into()))?;
        Ok(Some(text.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::TcpListener;

    use super::*;
    use crate::build_explanation_prompt;
    use rieko_findings::{Evidence, Severity};

    fn finding() -> Finding {
        let now = chrono::Utc::now();
        Finding {
            id: "f".into(),
            detector: "channel_liquidity".into(),
            detector_version: "1".into(),
            schema_version: rieko_findings::FINDING_SCHEMA_VERSION,
            severity: Severity::Critical,
            node: Some("local".into()),
            channel: Some("c1".into()),
            evidence: vec![
                Evidence::text("direction", "outbound"),
                Evidence::number("local_ratio", 0.02),
            ],
            provenance: None,
            explanation: None,
            timestamp: now,
            first_seen_at: now,
            last_seen_at: now,
            lifecycle: rieko_findings::FindingLifecycle::Active,
        }
    }

    #[test]
    fn null_client_returns_none() {
        let c = NullClient;
        let req = ExplainRequest {
            finding: &finding(),
            context: None,
        };
        assert_eq!(c.explain(&req).unwrap(), None);
    }

    #[test]
    fn prompt_includes_evidence_and_asks_for_structure() {
        let p = build_explanation_prompt(&finding(), Some("lnd 0.18.5"));
        assert!(p.contains("channel_liquidity"));
        assert!(p.contains("local_ratio"));
        assert!(p.contains("0.02"));
        assert!(p.contains("lnd 0.18.5"));
    }

    #[test]
    fn zero_timeouts_are_rejected() {
        let error = OpenAiCompatibleClient::with_timeouts(
            "http://127.0.0.1:1",
            None,
            "model",
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .err()
        .expect("zero connect timeout must fail");
        assert!(error.to_string().contains("connect timeout"));

        let error = OpenAiCompatibleClient::with_timeouts(
            "http://127.0.0.1:1",
            None,
            "model",
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .err()
        .expect("zero request timeout must fail");
        assert!(error.to_string().contains("request timeout"));
    }

    #[test]
    fn default_constructor_builds_a_client() {
        OpenAiCompatibleClient::new("http://127.0.0.1:1", None, "model").unwrap();
    }

    #[test]
    fn request_timeout_bounds_explain() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request);
            std::thread::sleep(Duration::from_millis(500));
        });
        let client = OpenAiCompatibleClient::with_timeouts(
            endpoint,
            None,
            "model",
            Duration::from_millis(100),
            Duration::from_millis(50),
        )
        .unwrap();
        let finding = finding();
        let request = ExplainRequest {
            finding: &finding,
            context: None,
        };

        let started = std::time::Instant::now();
        let error = client.explain(&request).unwrap_err();

        assert!(matches!(error, LlmError::Transport(ref error) if error.is_timeout()));
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
}
