use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use rieko_domain::{
    AdapterHealth, BitcoinNetwork, BoxEventStream, ChannelSnapshot, ChannelStatus, IngestionError,
    NodeEvent, NodeIngestionAdapter, NodeSnapshot,
};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::client::BtcPayGreenfieldClient;
use crate::error::BtcPayError;
use crate::webhook::{normalize_webhook_payload, verify_btcpay_sig};

const DEFAULT_EVENT_BUFFER_SIZE: usize = 1024;

/// Configuration for BTCPay Server Greenfield Ingestion Adapter.
#[derive(Debug, Clone)]
pub struct BtcPayAdapterConfig {
    pub store_id: String,
    pub crypto_code: String,
    pub network: BitcoinNetwork,
    pub node_id_override: Option<String>,
    pub webhook_secret: Option<String>,
}

/// Ingestion adapter bridging BTCPay Server Greenfield into Rieko's normalized operational intelligence engine.
pub struct BtcPayAdapter {
    client: BtcPayGreenfieldClient,
    config: BtcPayAdapterConfig,
    tx: mpsc::Sender<NodeEvent>,
    rx: Arc<Mutex<Option<mpsc::Receiver<NodeEvent>>>>,
}

impl BtcPayAdapter {
    pub fn new(client: BtcPayGreenfieldClient, config: BtcPayAdapterConfig) -> Self {
        let (tx, rx) = mpsc::channel(DEFAULT_EVENT_BUFFER_SIZE);
        Self {
            client,
            config,
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
        }
    }

    /// Provides a cloneable event sender allowing Axum webhook handlers or background pollers
    /// to dispatch normalized `NodeEvent` instances into the adapter's event stream.
    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.tx.clone()
    }

    /// Ingests, verifies HMAC-SHA256 signature (if configured), and normalizes a raw webhook payload.
    pub async fn handle_webhook(
        &self,
        payload_bytes: &[u8],
        sig_header: &str,
    ) -> Result<NodeEvent, BtcPayError> {
        if let Some(secret) = &self.config.webhook_secret {
            if !verify_btcpay_sig(secret.as_bytes(), payload_bytes, sig_header) {
                warn!("Rejected BTCPay webhook payload: invalid HMAC-SHA256 signature");
                return Err(BtcPayError::InvalidSignature);
            }
        }

        let event = normalize_webhook_payload(payload_bytes)?;
        debug!("Dispatched BTCPay webhook event: {:?}", event);
        let _ = self.tx.send(event.clone()).await;
        Ok(event)
    }

    pub fn client(&self) -> &BtcPayGreenfieldClient {
        &self.client
    }

    pub fn config(&self) -> &BtcPayAdapterConfig {
        &self.config
    }
}

#[async_trait]
impl NodeIngestionAdapter for BtcPayAdapter {
    fn source_name(&self) -> &'static str {
        "btcpay"
    }

    async fn fetch_snapshot(&self) -> Result<NodeSnapshot, IngestionError> {
        let store_id = &self.config.store_id;
        let crypto_code = &self.config.crypto_code;
        let network = self.config.network;
        let now = Utc::now();

        let info = self
            .client
            .get_lightning_info(store_id, crypto_code)
            .await?;

        let raw_channels = self
            .client
            .get_lightning_channels(store_id, crypto_code)
            .await?;

        let wallet = self
            .client
            .get_onchain_wallet(store_id, crypto_code)
            .await
            .ok();

        let node_id = self
            .config
            .node_id_override
            .clone()
            .or_else(|| info.node_id())
            .unwrap_or_else(|| format!("btcpay-{}", store_id));

        let mut channel_snapshots = Vec::with_capacity(raw_channels.len());
        for c in raw_channels {
            let local_msat = c.local_balance_msat();
            let remote_msat = c.remote_balance_msat();
            let capacity_msat = if c.capacity_msat() > 0 {
                c.capacity_msat()
            } else {
                local_msat.saturating_add(remote_msat)
            };
            let channel_id = c
                .channel_point
                .unwrap_or_else(|| format!("unknown-{}", channel_snapshots.len()));

            let local_ratio = if capacity_msat > 0 {
                (local_msat as f64) / (capacity_msat as f64)
            } else {
                0.0
            };

            let status = if c.is_active {
                ChannelStatus::Active
            } else {
                ChannelStatus::Inactive
            };

            channel_snapshots.push(ChannelSnapshot {
                node_id: Some(node_id.clone()),
                network: Some(network),
                state_digest: None,
                channel_id,
                local_ratio,
                local_balance_msat: local_msat,
                remote_balance_msat: remote_msat,
                capacity_msat,
                status,
                ts: now,
                spendable_outbound_msat: local_msat,
                spendable_inbound_msat: remote_msat,
            });
        }

        let onchain_sats = wallet.and_then(|w| w.confirmed_sats());
        let snapshot = NodeSnapshot::from_channels(
            node_id,
            network,
            channel_snapshots,
            now,
            info.block_height,
            onchain_sats,
        );

        Ok(snapshot)
    }

    async fn event_stream(&self) -> Result<BoxEventStream, IngestionError> {
        let mut guard = self.rx.lock().await;
        let rx = guard
            .take()
            .ok_or_else(|| IngestionError::Other("event stream already consumed".into()))?;

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn health_check(&self) -> Result<AdapterHealth, IngestionError> {
        let start = Instant::now();
        match self.client.get_server_info().await {
            Ok(info) => Ok(AdapterHealth {
                is_connected: true,
                source_name: self.source_name().to_string(),
                latency_ms: Some(start.elapsed().as_millis() as u64),
                message: Some(format!(
                    "BTCPay Server v{}, sync: {:?}",
                    info.version,
                    info.fully_synced.unwrap_or(true)
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
