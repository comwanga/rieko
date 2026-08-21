use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use rieko_domain::{
    AdapterHealth, BitcoinNetwork, BoxEventStream, ChannelSnapshot, IngestionError, NodeId,
    NodeIngestionAdapter, NodeSnapshot,
};

use crate::client::LndClient;
use crate::normalize::Normalizer;

/// Ingestion adapter bridging LND REST into Rieko's normalized operational intelligence engine.
pub struct LndAdapter {
    client: LndClient,
    local_node: NodeId,
    network: BitcoinNetwork,
}

impl LndAdapter {
    pub fn new(client: LndClient, local_node: impl Into<NodeId>, network: BitcoinNetwork) -> Self {
        Self {
            client,
            local_node: local_node.into(),
            network,
        }
    }

    pub fn client(&self) -> &LndClient {
        &self.client
    }

    pub fn local_node(&self) -> &NodeId {
        &self.local_node
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
        let raw_channels = self
            .client
            .raw_channels()
            .map_err(|e| IngestionError::Connection(e.to_string()))?;

        let now = Utc::now();
        let mut channel_snapshots = Vec::with_capacity(raw_channels.len());

        for c in &raw_channels {
            let channel = Normalizer::channel(c, &self.local_node, now)
                .map_err(|e| IngestionError::Normalization(e.to_string()))?;
            channel_snapshots.push(ChannelSnapshot::from_channel(&channel, now, self.network));
        }

        let snapshot = NodeSnapshot::from_channels(
            self.local_node.to_string(),
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
        match self.client.raw_channels() {
            Ok(channels) => Ok(AdapterHealth {
                is_connected: true,
                source_name: self.source_name().to_string(),
                latency_ms: Some(start.elapsed().as_millis() as u64),
                message: Some(format!("LND online, {} channels observed", channels.len())),
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
