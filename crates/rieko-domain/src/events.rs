use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::channel::ChannelStatus;
use crate::ids::{ChannelId, NodeId};
use crate::node::NodeStatus;
use crate::snapshot::NodeSnapshot;

/// A single forwarding event (a payment routed through this node).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardEvent {
    /// Unique per forward (e.g. LND forwarding id).
    pub id: String,
    pub channel_in: ChannelId,
    pub channel_out: ChannelId,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    InFlight,
    Succeeded,
    Failed,
}

/// A payment send attempt (relevant for outbound liquidity pressure).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentEvent {
    pub id: String,
    pub payment_hash: String,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub status: PaymentStatus,
    pub timestamp: DateTime<Utc>,
}

/// Normalized event for settled invoices (e.g. from BTCPay Server Greenfield webhook or LND invoice stream).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoiceSettledEvent {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<String>,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_hash: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Normalized event for expired invoices.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoiceExpiredEvent {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_msat: Option<u64>,
    pub timestamp: DateTime<Utc>,
}

/// Normalized event for partial or pending payment received on an invoice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoicePaymentReceivedEvent {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<String>,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub timestamp: DateTime<Utc>,
}

/// Detailed payment metrics event for tracking route performance and latency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentMetricEvent {
    pub id: String,
    pub payment_hash: String,
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub status: PaymentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Channel state transition or rebalance telemetry event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelStateChangedEvent {
    pub channel_id: ChannelId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_status: Option<ChannelStatus>,
    pub new_status: ChannelStatus,
    pub local_balance_msat: u64,
    pub remote_balance_msat: u64,
    pub timestamp: DateTime<Utc>,
}

/// Peer node connectivity status update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerStatusChangedEvent {
    pub peer_id: NodeId,
    pub status: NodeStatus,
    pub timestamp: DateTime<Utc>,
}

/// Normalized stream of operational intelligence telemetry emitted by ingestion adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeEvent {
    InvoiceSettled(InvoiceSettledEvent),
    InvoiceExpired(InvoiceExpiredEvent),
    InvoicePaymentReceived(InvoicePaymentReceivedEvent),
    ForwardRouted(ForwardEvent),
    PaymentAttempt(PaymentEvent),
    PaymentMetric(PaymentMetricEvent),
    ChannelStateChanged(ChannelStateChangedEvent),
    PeerStatusChanged(PeerStatusChangedEvent),
    SnapshotUpdated(Box<NodeSnapshot>),
    Custom {
        kind: String,
        payload: serde_json::Value,
        timestamp: DateTime<Utc>,
    },
}

impl NodeEvent {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::InvoiceSettled(e) => e.timestamp,
            Self::InvoiceExpired(e) => e.timestamp,
            Self::InvoicePaymentReceived(e) => e.timestamp,
            Self::ForwardRouted(e) => e.timestamp,
            Self::PaymentAttempt(e) => e.timestamp,
            Self::PaymentMetric(e) => e.timestamp,
            Self::ChannelStateChanged(e) => e.timestamp,
            Self::PeerStatusChanged(e) => e.timestamp,
            Self::SnapshotUpdated(e) => e.captured_at,
            Self::Custom { timestamp, .. } => *timestamp,
        }
    }
}

