use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use thiserror::Error;

use crate::events::NodeEvent;
use crate::snapshot::NodeSnapshot;

#[derive(Debug, Error)]
pub enum IngestionError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("protocol or normalization error: {0}")]
    Normalization(String),
    #[error("timeout while fetching telemetry: {0}")]
    Timeout(String),
    #[error("adapter is uninitialized or closed")]
    Closed,
    #[error("source error: {0}")]
    Other(String),
}

/// Operational health state of an ingestion adapter.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdapterHealth {
    pub is_connected: bool,
    pub source_name: String,
    pub latency_ms: Option<u64>,
    pub message: Option<String>,
}

pub type BoxEventStream = Pin<Box<dyn Stream<Item = NodeEvent> + Send>>;

/// Decouples the core operational intelligence engine from concrete data sources
/// (e.g. LND, BTCPay Server Greenfield, Bitcoin Core).
#[async_trait]
pub trait NodeIngestionAdapter: Send + Sync {
    /// Identifier or name of the adapter source (e.g. "btcpay", "lnd", "bitcoind").
    fn source_name(&self) -> &'static str;

    /// Fetches a current aggregate snapshot of the node and its channels.
    async fn fetch_snapshot(&self) -> Result<NodeSnapshot, IngestionError>;

    /// Subscribes to an asynchronous stream of normalized telemetry events.
    async fn event_stream(&self) -> Result<BoxEventStream, IngestionError>;

    /// Checks the health and connectivity of the underlying source.
    async fn health_check(&self) -> Result<AdapterHealth, IngestionError>;
}
