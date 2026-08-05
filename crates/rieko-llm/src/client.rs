use rieko_findings::Finding;
use thiserror::Error;

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
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            api_key,
            model: model.into(),
            client: reqwest::blocking::Client::new(),
        }
    }

    /// From `RIEKO_LLM_ENDPOINT`, `RIEKO_LLM_API_KEY`, `RIEKO_LLM_MODEL`.
    pub fn from_env() -> Option<Self> {
        let endpoint = std::env::var("RIEKO_LLM_ENDPOINT").ok()?;
        let model = std::env::var("RIEKO_LLM_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
        let api_key = std::env::var("RIEKO_LLM_API_KEY").ok();
        Some(Self::new(endpoint, api_key, model))
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
    use super::*;
    use crate::build_explanation_prompt;
    use rieko_findings::{Evidence, Severity};

    fn finding() -> Finding {
        Finding {
            id: "f".into(),
            detector: "channel_liquidity".into(),
            severity: Severity::Critical,
            node: Some("local".into()),
            channel: Some("c1".into()),
            evidence: vec![
                Evidence::text("direction", "outbound"),
                Evidence::number("local_ratio", 0.02),
            ],
            explanation: None,
            timestamp: chrono::Utc::now(),
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
}
