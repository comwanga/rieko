use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use rieko_domain::{
    AdapterHealth, BitcoinNetwork, BoxEventStream, ChannelSnapshot, IngestionError, NodeId,
    NodeIngestionAdapter, NodeSnapshot,
};
use tracing::warn;

use crate::client::LndClient;
use crate::normalize::Normalizer;

/// Ingestion adapter bridging LND REST into Rieko's normalized operational intelligence engine.
pub struct LndAdapter {
    client: LndClient,
    /// Fallback local node identity used when the caller explicitly supplies one.
    /// `fetch_snapshot` always prefers the live identity from `/v1/getinfo`.
    local_node_hint: Option<NodeId>,
    /// Fallback network used when GetInfo doesn't report chain info.
    network: BitcoinNetwork,
}

impl LndAdapter {
    pub fn new(client: LndClient, local_node: impl Into<NodeId>, network: BitcoinNetwork) -> Self {
        Self {
            client,
            local_node_hint: Some(local_node.into()),
            network,
        }
    }

    /// Create an adapter without a pre-supplied node identity. The identity
    /// will be derived from `/v1/getinfo` on every `fetch_snapshot` call.
    pub fn new_auto(client: LndClient, network: BitcoinNetwork) -> Self {
        Self {
            client,
            local_node_hint: None,
            network,
        }
    }

    pub fn client(&self) -> &LndClient {
        &self.client
    }

    pub fn local_node_hint(&self) -> Option<&NodeId> {
        self.local_node_hint.as_ref()
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }
}

#[async_trait]
impl NodeIngestionAdapter for LndAdapter {
    fn source_name(&self) -> &'static str {
        "lnd"
    }

    async fn fetch_snapshot(&self) -> Result<NodeSnapshot, IngestionError> {
        // Derive identity from the live node rather than trusting a CLI argument.
        let info = self
            .client
            .get_info()
            .map_err(|e| IngestionError::Connection(format!("GetInfo failed: {e}")))?;

        let local_node = NodeId::new(&info.identity_pubkey);

        // Warn if the caller supplied a different pubkey than what LND reports.
        if let Some(hint) = &self.local_node_hint {
            if hint.as_ref() != info.identity_pubkey.as_str() && hint.as_ref() != "local-node" {
                warn!(
                    supplied = %hint,
                    actual = %info.identity_pubkey,
                    "supplied --node does not match LND GetInfo identity_pubkey; using live identity"
                );
            }
        }

        let raw_channels = self
            .client
            .raw_channels()
            .map_err(|e| IngestionError::Connection(e.to_string()))?;

        let now = Utc::now();
        let mut channel_snapshots = Vec::with_capacity(raw_channels.len());

        for c in &raw_channels {
            match Normalizer::channel(c, &local_node, now) {
                Ok(channel) => {
                    channel_snapshots.push(ChannelSnapshot::from_channel(
                        &channel,
                        now,
                        self.network,
                    ));
                }
                Err(e) => {
                    warn!(
                        channel_point = %c.channel_point,
                        error = %e,
                        "skipping malformed channel during normalization"
                    );
                }
            }
        }

        let snapshot = NodeSnapshot::from_channels(
            local_node.to_string(),
            self.network,
            channel_snapshots,
            now,
            None,
            None,
        );

        Ok(snapshot)
    }

    async fn event_stream(&self) -> Result<BoxEventStream, IngestionError> {
        Ok(Box::pin(tokio_stream::empty()))
    }

    async fn health_check(&self) -> Result<AdapterHealth, IngestionError> {
        let start = Instant::now();
        // Prefer GetInfo for health checks — it confirms auth + connectivity in one call.
        match self.client.get_info() {
            Ok(info) => Ok(AdapterHealth {
                is_connected: true,
                source_name: self.source_name().to_string(),
                latency_ms: Some(start.elapsed().as_millis() as u64),
                message: Some(format!(
                    "LND online: {} ({})",
                    info.alias.unwrap_or_else(|| info.identity_pubkey.clone()),
                    info.version.unwrap_or_default()
                )),
            }),
            Err(e) => Ok(AdapterHealth {
                is_connected: false,
                source_name: self.source_name().to_string(),
                latency_ms: Some(start.elapsed().as_millis() as u64),
                message: Some(e.to_string()),
            }),
        }
    }
}
