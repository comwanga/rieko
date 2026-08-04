use serde::Deserialize;

/// Wire types mirroring the LND REST API (`/v1/channels`,
/// `/v1/forwarding/events`). Field names use camelCase, matching LND JSON.
///
/// NOTE: field coverage targets LND 0.17+; verify against your node's schema.
#[derive(Debug, Clone, Deserialize)]
pub struct LndChannel {
    #[serde(rename = "chan_point")]
    pub chan_point: String,
    #[serde(rename = "remote_pubkey")]
    pub remote_pubkey: String,
    pub capacity: i64,
    #[serde(rename = "local_balance")]
    pub local_balance: i64,
    #[serde(rename = "remote_balance")]
    pub remote_balance: i64,
    #[serde(rename = "commit_fee")]
    pub commit_fee: i64,
    #[serde(rename = "chan_status_flags")]
    pub chan_status_flags: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LndChannelResponse {
    pub channels: Vec<LndChannel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LndForward {
    #[serde(rename = "chan_id_in")]
    pub chan_id_in: u64,
    #[serde(rename = "chan_id_out")]
    pub chan_id_out: u64,
    pub amt_in_msat: i64,
    pub amt_out_msat: i64,
    pub fee_msat: i64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LndForwardResponse {
    #[serde(rename = "forwarding_events")]
    pub forwarding_events: Vec<LndForward>,
}
