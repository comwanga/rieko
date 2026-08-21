use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// Generic Greenfield webhook envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BtcPayWebhookEvent {
    pub delivery_id: String,
    pub webhook_id: String,
    #[serde(default)]
    pub original_delivery_id: Option<String>,
    #[serde(default)]
    pub is_redelivery: bool,
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: i64,
    pub store_id: String,
    #[serde(default)]
    pub invoice_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl BtcPayWebhookEvent {
    pub fn timestamp_utc(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.timestamp, 0)
            .single()
            .unwrap_or_else(Utc::now)
    }
}

/// Webhook payload for `InvoiceSettled` and `InvoiceProcessing`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceSettledPayload {
    pub delivery_id: String,
    pub webhook_id: String,
    pub store_id: String,
    pub invoice_id: String,
    pub timestamp: i64,
    #[serde(default)]
    pub payment_method: Option<String>,
    #[serde(default)]
    pub payment_method_id: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub payment: Option<InvoicePaymentData>,
}

/// Webhook payload for `InvoiceReceivedPayment`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoicePaymentReceivedPayload {
    pub delivery_id: String,
    pub webhook_id: String,
    pub store_id: String,
    pub invoice_id: String,
    pub timestamp: i64,
    #[serde(default)]
    pub payment_method: Option<String>,
    #[serde(default)]
    pub payment: Option<InvoicePaymentData>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoicePaymentData {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub fee: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub payment_hash: Option<String>,
}

/// Webhook payload for `InvoiceExpired`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceExpiredPayload {
    pub delivery_id: String,
    pub webhook_id: String,
    pub store_id: String,
    pub invoice_id: String,
    pub timestamp: i64,
}

/// Server information from `GET /api/v1/server/info`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GreenfieldServerInfo {
    pub version: String,
    #[serde(default)]
    pub supported_payment_methods: Vec<String>,
    #[serde(default)]
    pub fully_synced: Option<bool>,
}

/// Lightning node information from `GET /api/v1/stores/{storeId}/lightning/{cryptoCode}/info`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GreenfieldLightningInfo {
    #[serde(default, rename = "nodeURIs")]
    pub node_uris: Vec<String>,
    #[serde(default)]
    pub block_height: Option<u32>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub active_channels_count: Option<u32>,
    #[serde(default)]
    pub inactive_channels_count: Option<u32>,
    #[serde(default)]
    pub pending_channels_count: Option<u32>,
}

impl GreenfieldLightningInfo {
    /// Extracts the node ID / pubkey from the first node URI (e.g. `02abc...@127.0.0.1:9735`).
    pub fn node_id(&self) -> Option<String> {
        self.node_uris.first().and_then(|uri| {
            let pubkey = uri.split('@').next()?;
            if !pubkey.is_empty() {
                Some(pubkey.to_string())
            } else {
                None
            }
        })
    }
}

/// Lightning balance breakdown from `GET /api/v1/stores/{storeId}/lightning/{cryptoCode}/balance`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GreenfieldLightningBalance {
    #[serde(default)]
    pub total: Option<serde_json::Value>,
    #[serde(default)]
    pub local: Option<serde_json::Value>,
    #[serde(default)]
    pub remote: Option<serde_json::Value>,
    #[serde(default)]
    pub unsettled: Option<serde_json::Value>,
}

fn parse_balance_msat(val: &Option<serde_json::Value>) -> u64 {
    match val {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => {
            // Could be sats integer string or decimal BTC string (e.g. "0.00100000")
            if let Ok(msat) = s.parse::<u64>() {
                msat
            } else if let Ok(btc) = s.parse::<f64>() {
                (btc * 100_000_000.0 * 1000.0) as u64
            } else {
                0
            }
        }
        _ => 0,
    }
}

impl GreenfieldLightningBalance {
    pub fn local_msat(&self) -> u64 {
        parse_balance_msat(&self.local)
    }

    pub fn remote_msat(&self) -> u64 {
        parse_balance_msat(&self.remote)
    }

    pub fn total_msat(&self) -> u64 {
        parse_balance_msat(&self.total)
    }
}

/// Single Lightning channel from `GET /api/v1/stores/{storeId}/lightning/{cryptoCode}/channels`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GreenfieldLightningChannel {
    #[serde(default)]
    pub channel_point: Option<String>,
    #[serde(default)]
    pub remote_balance: Option<serde_json::Value>,
    #[serde(default)]
    pub local_balance: Option<serde_json::Value>,
    #[serde(default)]
    pub capacity: Option<serde_json::Value>,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub is_public: Option<bool>,
}

impl GreenfieldLightningChannel {
    pub fn local_balance_msat(&self) -> u64 {
        parse_balance_msat(&self.local_balance)
    }

    pub fn remote_balance_msat(&self) -> u64 {
        parse_balance_msat(&self.remote_balance)
    }

    pub fn capacity_msat(&self) -> u64 {
        parse_balance_msat(&self.capacity)
    }
}

/// On-chain wallet overview from `GET /api/v1/stores/{storeId}/onchain/{cryptoCode}/wallet`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GreenfieldOnChainWallet {
    #[serde(default)]
    pub balance: Option<serde_json::Value>,
    #[serde(default)]
    pub unconfirmed_balance: Option<serde_json::Value>,
    #[serde(default)]
    pub confirmed_balance: Option<serde_json::Value>,
}

impl GreenfieldOnChainWallet {
    pub fn confirmed_sats(&self) -> Option<u64> {
        let val = self.confirmed_balance.as_ref().or(self.balance.as_ref())?;
        match val {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => {
                if let Ok(sats) = s.parse::<u64>() {
                    Some(sats)
                } else if let Ok(btc) = s.parse::<f64>() {
                    Some((btc * 100_000_000.0) as u64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Invoice overview from `GET /api/v1/stores/{storeId}/invoices`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GreenfieldInvoice {
    pub id: String,
    pub store_id: String,
    pub amount: String,
    pub currency: String,
    #[serde(rename = "type")]
    pub invoice_type: Option<String>,
    pub status: String,
    #[serde(default)]
    pub additional_status: Option<String>,
    pub created_time: i64,
    #[serde(default)]
    pub expiration_time: Option<i64>,
}
