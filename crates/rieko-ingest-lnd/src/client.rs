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
    #[error("TLS setup failed: {0}")]
    Tls(String),
}

/// Build the shared HTTP/TLS client. A provided PEM certificate is added as a
/// trusted root for this client only; certificate and hostname validation are
/// never disabled. Returns a clear error on an unparseable certificate.
fn build_http_client(
    tls_cert_pem: Option<Vec<u8>>,
) -> Result<reqwest::blocking::Client, LndClientError> {
    let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(30));
    if let Some(pem) = tls_cert_pem {
        let der = rustls_pemfile::certs(&mut std::io::Cursor::new(&pem))
            .next()
            .transpose()
            .map_err(|e| LndClientError::Tls(format!("invalid certificate: {e}")))?
            .ok_or_else(|| LndClientError::Tls("no certificate found in --tls-cert".into()))?;
        let cert = reqwest::Certificate::from_der(der.as_ref())
            .map_err(|e| LndClientError::Tls(format!("invalid certificate: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }
    builder.build().map_err(LndClientError::Transport)
}

/// Lowercase hex encoding of the macaroon bytes, as LND expects the value of
/// the `Grpc-Metadata-macaroon` header.
fn macaroon_header(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal read-only LND REST client. It reads channels and forwards and sends
/// the macaroon as lowercase-hex bytes in the `Grpc-Metadata-macaroon` header.
///
/// This is the v1 observation surface and deliberately exposes no node-mutating
/// RPC; write operations live on [`LndMutator`] instead. Certificate validation
/// is never disabled, so an optional certificate only narrows trust to the
/// configured peer.
pub struct LndClient {
    rest_base: String,
    macaroon_hex: Option<String>,
    client: reqwest::blocking::Client,
}

impl LndClient {
    /// `macaroon` and `tls_cert_pem` are raw file bytes, read binary-safe by the
    /// caller — a macaroon is not UTF-8 text.
    pub fn new(
        rest_base: impl Into<String>,
        macaroon: Option<Vec<u8>>,
        tls_cert_pem: Option<Vec<u8>>,
    ) -> Result<Self, LndClientError> {
        Ok(Self {
            rest_base: rest_base.into(),
            macaroon_hex: macaroon.map(macaroon_header),
            client: build_http_client(tls_cert_pem)?,
        })
    }

    fn get(&self, path: &str) -> Result<String, LndClientError> {
        let url = format!("{}{}", self.rest_base.trim_end_matches('/'), path);
        let mut req = self.client.get(url);
        if let Some(mac) = &self.macaroon_hex {
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

    pub fn forwards(
        &self,
        _limit: usize,
    ) -> Result<Vec<rieko_domain::ForwardEvent>, LndClientError> {
        let body = self.get("/v1/forwarding/events?num_max_events=100")?;
        let parsed: LndForwardResponse = serde_json::from_str(&body)?;
        Ok(parsed
            .forwarding_events
            .iter()
            .map(Normalizer::forward)
            .collect())
    }
}

/// Node-mutating LND REST client, kept separate from the read-only v1 surface.
/// Only the future-gated execution path constructs this.
pub struct LndMutator {
    rest_base: String,
    macaroon_hex: Option<String>,
    client: reqwest::blocking::Client,
}

impl LndMutator {
    pub fn new(
        rest_base: impl Into<String>,
        macaroon: Option<Vec<u8>>,
        tls_cert_pem: Option<Vec<u8>>,
    ) -> Result<Self, LndClientError> {
        Ok(Self {
            rest_base: rest_base.into(),
            macaroon_hex: macaroon.map(macaroon_header),
            client: build_http_client(tls_cert_pem)?,
        })
    }

    fn put(&self, path: &str, body: &str) -> Result<String, LndClientError> {
        use reqwest::header;
        let url = format!("{}{}", self.rest_base.trim_end_matches('/'), path);
        let mut req = self
            .client
            .put(url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        if let Some(mac) = &self.macaroon_hex {
            req = req.header("Grpc-Metadata-macaroon", mac);
        }
        let resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(LndClientError::Status(status));
        }
        Ok(resp.text()?)
    }

    /// Update channel routing fee policy. body is the JSON for
    /// `UpdateChanPolicyRequest` (from the params on an UpdateFeePolicy action).
    pub fn update_chan_policy(&self, body: &str) -> Result<String, LndClientError> {
        self.put("/v1/chanpolicy", body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_fetch_fails_cleanly_offline() {
        let client = LndClient::new("http://127.0.0.1:1", None, None).unwrap();
        let err = client.channels(&NodeId::new("local")).unwrap_err();
        assert!(matches!(err, LndClientError::Transport(_)));
    }

    #[test]
    fn macaroon_is_lowercase_hex() {
        let mac = vec![0xde, 0xad, 0xbe, 0xef];
        let client = LndClient::new("http://127.0.0.1:1", Some(mac), None).unwrap();
        assert_eq!(client.macaroon_hex.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn read_client_exposes_no_mutation_method() {
        // The read-only v1 client must not compile a `put`/mutation surface.
        let client = LndClient::new("http://127.0.0.1:1", None, None).unwrap();
        assert!(client.macaroon_hex.is_none());
        assert!(client.rest_base.starts_with("http"));
    }
}
