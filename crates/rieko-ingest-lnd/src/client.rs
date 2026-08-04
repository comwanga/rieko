use std::time::Duration;

use rieko_domain::{Channel, NodeId};
use thiserror::Error;

use crate::model::{LndChannelResponse, LndForwardResponse};
use crate::Normalizer;

#[derive(Debug, Error)]
pub enum LndClientError {
    #[error("transport error talking to LND: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("LND returned HTTP {0}")]
    Status(reqwest::StatusCode),
    #[error("failed to parse LND response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("normalization failed: {0}")]
    Normalize(#[from] crate::NormalizerError),
}

/// Minimal LND REST client. Reads channels and forwards; macaroon is sent via
/// the `Grpc-Metadata-macaroon` header. TLS is not enforced here — operators
/// run Rieko on the same host and should use `--rest` over localhost.
pub struct LndClient {
    rest_base: String,
    macaroon: Option<String>,
    client: reqwest::blocking::Client,
}

impl LndClient {
    pub fn new(rest_base: impl Into<String>, macaroon: Option<String>) -> Self {
        Self {
            rest_base: rest_base.into(),
            macaroon,
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client builds"),
        }
    }

    fn get(&self, path: &str) -> Result<String, LndClientError> {
        let url = format!("{}{}", self.rest_base.trim_end_matches('/'), path);
        let mut req = self.client.get(url);
        if let Some(mac) = &self.macaroon {
            req = req.header("Grpc-Metadata-macaroon", mac);
        }
        let resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(LndClientError::Status(status));
        }
        Ok(resp.text()?)
    }

    pub fn channels(&self, local_node: &NodeId) -> Result<Vec<Channel>, LndClientError> {
        let body = self.get("/v1/channels")?;
        let parsed: LndChannelResponse = serde_json::from_str(&body)?;
        let now = chrono::Utc::now();
        parsed
            .channels
            .iter()
            .map(|c| Ok(Normalizer::channel(c, local_node, now)?))
            .collect()
    }

    pub fn forwards(&self, _limit: usize) -> Result<Vec<rieko_domain::ForwardEvent>, LndClientError> {
        let body = self.get("/v1/forwarding/events?num_max_events=100")?;
        let parsed: LndForwardResponse = serde_json::from_str(&body)?;
        Ok(parsed.forwarding_events.iter().map(Normalizer::forward).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_fetch_fails_cleanly_offline() {
        let client = LndClient::new("http://127.0.0.1:1", None);
        let err = client.channels(&NodeId::new("local")).unwrap_err();
        assert!(matches!(err, LndClientError::Transport(_)));
    }
}
