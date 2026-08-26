use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::{StatusCode, Url};
use rieko_domain::{BitcoinCoreSnapshot, BitcoinNetwork};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreRpcError {
    #[error("Bitcoin Core RPC transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Bitcoin Core RPC authentication failed")]
    Authentication,
    #[error("Bitcoin Core RPC returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("Bitcoin Core RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("malformed Bitcoin Core RPC response: {0}")]
    Malformed(String),
    #[error("unsupported Bitcoin Core chain {0:?}")]
    UnsupportedChain(String),
}

#[derive(Clone)]
pub struct BitcoinCoreRpcClient {
    endpoint: Url,
    username: String,
    password: String,
    http: reqwest::Client,
}

impl BitcoinCoreRpcClient {
    pub fn new_with_timeout(
        endpoint: &str,
        username: impl Into<String>,
        password: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, CoreRpcError> {
        let endpoint = Url::parse(endpoint)
            .map_err(|error| CoreRpcError::Malformed(format!("invalid RPC URL: {error}")))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(CoreRpcError::Malformed(
                "RPC URL must use http or https".into(),
            ));
        }
        let http = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(Self {
            endpoint,
            username: username.into(),
            password: password.into(),
            http,
        })
    }

    /// Calls the read-only `getblockchaininfo` RPC and returns normalized state.
    pub async fn get_blockchain_snapshot(&self) -> Result<BitcoinCoreSnapshot, CoreRpcError> {
        let response = self
            .http
            .post(self.endpoint.clone())
            .basic_auth(&self.username, Some(&self.password))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "rieko-core-observation",
                "method": "getblockchaininfo",
                "params": []
            }))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(CoreRpcError::Authentication);
        }
        if !status.is_success() {
            return Err(CoreRpcError::Http {
                status: status.as_u16(),
                message: body,
            });
        }
        BitcoinCoreNormalizer::blockchain_info(&body, Utc::now())
    }
}

pub struct BitcoinCoreNormalizer;

impl BitcoinCoreNormalizer {
    pub fn blockchain_info(
        payload: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<BitcoinCoreSnapshot, CoreRpcError> {
        let response: RpcResponse = serde_json::from_str(payload)
            .map_err(|error| CoreRpcError::Malformed(error.to_string()))?;
        if let Some(error) = response.error {
            return Err(CoreRpcError::Rpc {
                code: error.code,
                message: error.message,
            });
        }
        let info = response
            .result
            .ok_or_else(|| CoreRpcError::Malformed("missing result".into()))?;
        let network = match info.chain.as_str() {
            "main" => BitcoinNetwork::Mainnet,
            "test" => BitcoinNetwork::Testnet,
            "signet" => BitcoinNetwork::Signet,
            "regtest" => BitcoinNetwork::Regtest,
            _ => return Err(CoreRpcError::UnsupportedChain(info.chain)),
        };
        Ok(BitcoinCoreSnapshot {
            network,
            block_height: info.blocks,
            header_height: info.headers,
            synchronized: !info.initial_block_download && info.blocks == info.headers,
            observed_at,
        })
    }
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<BlockchainInfo>,
    error: Option<RpcFailure>,
}

#[derive(Deserialize)]
struct BlockchainInfo {
    chain: String,
    blocks: u64,
    headers: u64,
    #[serde(rename = "initialblockdownload")]
    initial_block_download: bool,
}

#[derive(Deserialize)]
struct RpcFailure {
    code: i64,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap};
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use chrono::TimeZone;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    async fn server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), task)
    }

    fn response() -> serde_json::Value {
        json!({
            "result": {
                "chain": "regtest",
                "blocks": 201,
                "headers": 201,
                "initialblockdownload": false
            },
            "error": null,
            "id": "rieko-core-observation"
        })
    }

    #[test]
    fn normalizes_chain_height_headers_and_sync_state() {
        let observed_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let snapshot =
            BitcoinCoreNormalizer::blockchain_info(&response().to_string(), observed_at).unwrap();
        assert_eq!(snapshot.network, BitcoinNetwork::Regtest);
        assert_eq!(snapshot.block_height, 201);
        assert_eq!(snapshot.header_height, 201);
        assert!(snapshot.synchronized);
        assert_eq!(snapshot.observed_at, observed_at);
    }

    #[test]
    fn initial_block_download_is_not_synchronized() {
        let payload = json!({
            "result": {
                "chain": "main",
                "blocks": 800_000,
                "headers": 850_000,
                "initialblockdownload": true
            },
            "error": null
        });
        let snapshot = BitcoinCoreNormalizer::blockchain_info(
            &payload.to_string(),
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.network, BitcoinNetwork::Mainnet);
        assert!(!snapshot.synchronized);
    }

    #[test]
    fn rejects_malformed_and_rpc_error_responses() {
        assert!(matches!(
            BitcoinCoreNormalizer::blockchain_info("not json", Utc::now()),
            Err(CoreRpcError::Malformed(_))
        ));
        let error = BitcoinCoreNormalizer::blockchain_info(
            r#"{"result":null,"error":{"code":-28,"message":"Loading block index"}}"#,
            Utc::now(),
        )
        .unwrap_err();
        assert!(matches!(error, CoreRpcError::Rpc { code: -28, .. }));
    }

    #[tokio::test]
    async fn client_uses_basic_auth_and_returns_normalized_state() {
        let authorized = Arc::new(AtomicBool::new(false));
        let observed = authorized.clone();
        let app = Router::new().route(
            "/",
            post(move |headers: HeaderMap| {
                let observed = observed.clone();
                async move {
                    let ok = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        == Some("Basic cmlla286cmVhZG9ubHk=");
                    observed.store(ok, Ordering::SeqCst);
                    if ok {
                        Json(response()).into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }
            }),
        );
        let (url, task) = server(app).await;
        let client = BitcoinCoreRpcClient::new_with_timeout(
            &url,
            "rieko",
            "readonly",
            Duration::from_secs(1),
        )
        .unwrap();
        let snapshot = client.get_blockchain_snapshot().await.unwrap();
        task.abort();
        assert!(authorized.load(Ordering::SeqCst));
        assert_eq!(snapshot.block_height, 201);
    }

    #[tokio::test]
    async fn authentication_failure_is_typed() {
        let app = Router::new().route(
            "/",
            post(|| async { StatusCode::UNAUTHORIZED.into_response() }),
        );
        let (url, task) = server(app).await;
        let client =
            BitcoinCoreRpcClient::new_with_timeout(&url, "rieko", "wrong", Duration::from_secs(1))
                .unwrap();
        let error = client.get_blockchain_snapshot().await.unwrap_err();
        task.abort();
        assert!(matches!(error, CoreRpcError::Authentication));
    }
}
