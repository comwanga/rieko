//! BTCPay Server Greenfield ingestion adapter for Rieko.
//!
//! Provides an asynchronous Greenfield REST API client, webhook receiver with
//! constant-time HMAC-SHA256 signature verification, and the `NodeIngestionAdapter`
//! implementation that produces a normalized `Stream<Item = NodeEvent>`.

pub mod adapter;
pub mod client;
pub mod error;
pub mod models;
pub mod webhook;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use adapter::{BtcPayAdapter, BtcPayAdapterConfig};
pub use client::BtcPayGreenfieldClient;
pub use error::BtcPayError;
pub use models::*;
pub use webhook::{normalize_webhook_payload, verify_btcpay_sig, BTCPAY_SIG_HEADER};
