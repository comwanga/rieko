use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rieko_domain::{
    InvoiceExpiredEvent, InvoicePaymentReceivedEvent, InvoiceSettledEvent, NodeEvent,
};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::BtcPayError;
use crate::models::{
    BtcPayWebhookEvent, InvoiceExpiredPayload, InvoicePaymentReceivedPayload, InvoiceSettledPayload,
};

type HmacSha256 = Hmac<Sha256>;

pub const BTCPAY_SIG_HEADER: &str = "BTCPay-Sig";

/// Verifies a BTCPay Greenfield webhook signature header (`BTCPay-Sig`) against the raw payload bytes.
///
/// BTCPay Server Greenfield calculates HMAC-SHA256(secret, payload) and transmits it as:
/// `sha256=<hex_encoded_hmac>` or `<hex_encoded_hmac>`.
///
/// Uses constant-time comparison (`subtle::ConstantTimeEq`) to eliminate timing side-channel attacks.
pub fn verify_btcpay_sig(secret: &[u8], payload_bytes: &[u8], sig_header: &str) -> bool {
    if secret.is_empty() || sig_header.trim().is_empty() {
        return false;
    }

    let header_clean = sig_header.trim();
    let header_val = header_clean
        .strip_prefix("sha256=")
        .or_else(|| header_clean.strip_prefix("sha256:"))
        .unwrap_or(header_clean)
        .trim();

    let Ok(provided_bytes) = hex::decode(header_val) else {
        return false;
    };

    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };

    mac.update(payload_bytes);
    let expected_bytes = mac.finalize().into_bytes();

    if provided_bytes.len() != expected_bytes.len() {
        return false;
    }

    bool::from(expected_bytes.as_slice().ct_eq(&provided_bytes))
}

/// Parses and normalizes raw Greenfield webhook payload bytes into a `NodeEvent`.
pub fn normalize_webhook_payload(payload_bytes: &[u8]) -> Result<NodeEvent, BtcPayError> {
    let envelope: BtcPayWebhookEvent = serde_json::from_slice(payload_bytes)
        .map_err(|e| BtcPayError::MalformedPayload(e.to_string()))?;

    let timestamp = envelope.timestamp_utc();

    match envelope.event_type.as_str() {
        "InvoiceSettled" | "InvoiceProcessing" => {
            let payload: InvoiceSettledPayload = serde_json::from_slice(payload_bytes)?;
            let mut metadata_map = HashMap::new();
            if let Some(serde_json::Value::Object(map)) = payload.metadata {
                for (k, v) in map {
                    let s = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    metadata_map.insert(k, s);
                }
            }

            let amount_msat = payload
                .payment
                .as_ref()
                .and_then(|p| p.value.as_ref())
                .and_then(|v| parse_msats(v))
                .unwrap_or(0);

            let fee_msat = payload
                .payment
                .as_ref()
                .and_then(|p| p.fee.as_ref())
                .and_then(|v| parse_msats(v))
                .unwrap_or(0);

            let payment_hash = payload.payment.and_then(|p| p.payment_hash);

            Ok(NodeEvent::InvoiceSettled(InvoiceSettledEvent {
                id: payload.invoice_id,
                store_id: Some(payload.store_id),
                payment_method: payload.payment_method.or(payload.payment_method_id),
                amount_msat,
                fee_msat,
                timestamp,
                payment_hash,
                metadata: metadata_map,
            }))
        }
        "InvoiceReceivedPayment" => {
            let payload: InvoicePaymentReceivedPayload = serde_json::from_slice(payload_bytes)?;
            let amount_msat = payload
                .payment
                .as_ref()
                .and_then(|p| p.value.as_ref())
                .and_then(|v| parse_msats(v))
                .unwrap_or(0);

            let fee_msat = payload
                .payment
                .as_ref()
                .and_then(|p| p.fee.as_ref())
                .and_then(|v| parse_msats(v))
                .unwrap_or(0);

            Ok(NodeEvent::InvoicePaymentReceived(
                InvoicePaymentReceivedEvent {
                    id: payload.invoice_id,
                    store_id: Some(payload.store_id),
                    payment_method: payload.payment_method,
                    amount_msat,
                    fee_msat,
                    timestamp,
                },
            ))
        }
        "InvoiceExpired" | "InvoiceInvalid" => {
            let payload: InvoiceExpiredPayload = serde_json::from_slice(payload_bytes)?;
            Ok(NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: payload.invoice_id,
                store_id: Some(payload.store_id),
                amount_msat: None,
                timestamp,
            }))
        }
        other_type => {
            let raw_json: serde_json::Value = serde_json::from_slice(payload_bytes)?;
            Ok(NodeEvent::Custom {
                kind: other_type.to_string(),
                payload: raw_json,
                timestamp,
            })
        }
    }
}

fn parse_msats(s: &str) -> Option<u64> {
    if let Ok(msat) = s.parse::<u64>() {
        Some(msat)
    } else if let Ok(btc) = s.parse::<f64>() {
        Some((btc * 100_000_000.0 * 1000.0) as u64)
    } else {
        None
    }
}
