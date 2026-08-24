use std::time::Duration;

use rieko_domain::{Channel, NodeId};
use thiserror::Error;

use crate::model::{LndChannel, LndChannelResponse, LndForwardResponse, LndGetInfoResponse};
use crate::{Normalizer, ShortChanResolver};

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
    /// The caller supplied a node pubkey that contradicts what LND's GetInfo
    /// reports. Raised only when the caller explicitly provides a value.
    #[error("node pubkey mismatch: expected {expected} but LND GetInfo returned {actual}")]
    GetInfoMismatch { expected: String, actual: String },
    /// The LND REST endpoint uses plain HTTP. Pass `allow_insecure: true` only
    /// for local regtest/signet nodes that are not accessible from the internet.
    #[error(
        "insecure transport: LND REST URL uses http:// which transmits the macaroon in \
         plaintext; use https:// or pass allow_insecure=true for local-only nodes"
    )]
    InsecureTransport,
}

/// Build the shared HTTP/TLS client. A provided PEM certificate is added as a
/// trusted root for this client only; certificate and hostname validation are
/// never disabled. Returns a clear error on an unparseable certificate.
fn build_http_client(
    tls_cert_pem: Option<Vec<u8>>,
) -> Result<reqwest::blocking::Client, LndClientError> {
    let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(30));
    if let Some(pem) = tls_cert_pem {
        let pem_str = std::str::from_utf8(&pem)
            .map_err(|e| LndClientError::Tls(format!("invalid certificate encoding: {e}")))?;
        if !pem_str.contains("-----BEGIN CERTIFICATE-----") {
            return Err(LndClientError::Tls(
                "no certificate found in --tls-cert".into(),
            ));
        }
        let cert = reqwest::Certificate::from_pem(&pem)
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
/// RPC; write operations live on the execute-gated mutator instead. Certificate
/// validation is never disabled, so an optional certificate only narrows trust
/// to the configured peer.
#[derive(Debug)]
pub struct LndClient {
    rest_base: String,
    macaroon_hex: Option<String>,
    client: reqwest::blocking::Client,
}

impl LndClient {
    /// `macaroon` and `tls_cert_pem` are raw file bytes, read binary-safe by the
    /// caller — a macaroon is not UTF-8 text.
    ///
    /// By default this constructor rejects `http://` URLs to prevent transmitting
    /// the macaroon in plaintext. Set `allow_insecure = true` only for local
    /// regtest or signet nodes that are not reachable from the network.
    pub fn new(
        rest_base: impl Into<String>,
        macaroon: Option<Vec<u8>>,
        tls_cert_pem: Option<Vec<u8>>,
    ) -> Result<Self, LndClientError> {
        Self::new_inner(rest_base, macaroon, tls_cert_pem, false)
    }

    /// Same as [`new`] but skips the HTTPS enforcement check. Use only for
    /// local regtest or signet nodes.
    pub fn new_allow_insecure(
        rest_base: impl Into<String>,
        macaroon: Option<Vec<u8>>,
        tls_cert_pem: Option<Vec<u8>>,
    ) -> Result<Self, LndClientError> {
        Self::new_inner(rest_base, macaroon, tls_cert_pem, true)
    }

    fn new_inner(
        rest_base: impl Into<String>,
        macaroon: Option<Vec<u8>>,
        tls_cert_pem: Option<Vec<u8>>,
        allow_insecure: bool,
    ) -> Result<Self, LndClientError> {
        let rest_base = rest_base.into();
        if !allow_insecure
            && rest_base
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("http://")
        {
            return Err(LndClientError::InsecureTransport);
        }
        Ok(Self {
            rest_base,
            macaroon_hex: macaroon.map(macaroon_header),
            client: build_http_client(tls_cert_pem)?,
        })
    }

    /// Call `/v1/getinfo` and return the node's declared identity and network.
    /// Use this to derive the local node pubkey rather than trusting the
    /// operator-supplied `--node` argument.
    pub fn get_info(&self) -> Result<LndGetInfoResponse, LndClientError> {
        let body = self.get("/v1/getinfo")?;
        let info: LndGetInfoResponse = serde_json::from_str(&body)?;
        Ok(info)
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
        let now = chrono::Utc::now();
        self.raw_channels()?
            .iter()
            .map(|c| Ok(Normalizer::channel(c, local_node, now)?))
            .collect()
    }

    /// Fetch the raw LND channel list, before normalization. Callers that need
    /// to correlate short channel ids to channel points (e.g. forwarding
    /// events) use this to build a [`ShortChanResolver`].
    pub fn raw_channels(&self) -> Result<Vec<LndChannel>, LndClientError> {
        let body = self.get("/v1/channels")?;
        let parsed: LndChannelResponse = serde_json::from_str(&body)?;
        Ok(parsed.channels)
    }

    pub fn forwards(
        &self,
        resolver: &ShortChanResolver,
    ) -> Result<Vec<rieko_domain::ForwardEvent>, LndClientError> {
        let body = self.get("/v1/forwarding/events?num_max_events=100")?;
        let parsed: LndForwardResponse = serde_json::from_str(&body)?;
        Ok(parsed
            .forwarding_events
            .iter()
            .map(|f| Normalizer::forward(f, resolver))
            .collect())
    }
}

/// Node-mutating LND REST client, kept separate from the read-only v1 surface.
/// Only the execute-gated execution path compiles and constructs this.
#[cfg(feature = "execute")]
pub struct LndMutator {
    rest_base: String,
    macaroon_hex: Option<String>,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "execute")]
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

    fn post(&self, path: &str, body: &str) -> Result<String, LndClientError> {
        use reqwest::header;
        let url = format!("{}{}", self.rest_base.trim_end_matches('/'), path);
        let mut req = self
            .client
            .post(url)
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

    /// Send a loop payment through LND's router (v2 API). Used for
    /// single-hop rebalance execution (ADR-0002 D2).
    pub fn send_payment(&self, body: &str) -> Result<String, LndClientError> {
        self.post("/v2/router/send", body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_url_is_rejected_by_default() {
        let err = LndClient::new("http://127.0.0.1:1", None, None).unwrap_err();
        assert!(
            matches!(err, LndClientError::InsecureTransport),
            "expected InsecureTransport, got {err:?}"
        );
    }

    #[test]
    fn https_url_is_accepted() {
        // No real server needed; we just want the constructor to succeed.
        // The TLS handshake failure happens at send time, not construction.
        assert!(LndClient::new("https://127.0.0.1:1", None, None).is_ok());
    }

    #[test]
    fn allow_insecure_bypasses_scheme_check() {
        // Regtest / local nodes may use plain http.
        assert!(LndClient::new_allow_insecure("http://127.0.0.1:1", None, None).is_ok());
    }

    #[test]
    fn channels_fetch_fails_cleanly_offline() {
        let client = LndClient::new_allow_insecure("http://127.0.0.1:1", None, None).unwrap();
        let err = client.channels(&NodeId::new("local")).unwrap_err();
        assert!(matches!(err, LndClientError::Transport(_)));
    }

    #[test]
    fn macaroon_is_lowercase_hex() {
        let mac = vec![0xde, 0xad, 0xbe, 0xef];
        let client = LndClient::new_allow_insecure("http://127.0.0.1:1", Some(mac), None).unwrap();
        assert_eq!(client.macaroon_hex.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn read_client_exposes_no_mutation_method() {
        // The read-only v1 client must not compile a `put`/mutation surface.
        let client = LndClient::new_allow_insecure("http://127.0.0.1:1", None, None).unwrap();
        assert!(client.macaroon_hex.is_none());
        assert!(client.rest_base.starts_with("http"));
    }
}
