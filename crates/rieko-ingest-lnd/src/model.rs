use serde::{Deserialize, Deserializer};

/// Wire types mirroring the LND REST API (`/v1/channels`, `/v1/forwarding/events`).
///
/// Target schema: LND 0.17+ (see the proto for field numbers). Two wire details
/// matter for correctness (RIEKO-AUDIT-019/021):
/// * The grpc-gateway serialises every 64-bit integer field as a JSON *string*
///   (protobuf JSON mapping), so 64-bit fields are accepted as either a string
///   or a number.
/// * The funding outpoint field is named `channel_point`, and the short channel
///   id is `chan_id` (a string).
#[derive(Debug, Clone, Deserialize)]
pub struct LndChannel {
    #[serde(rename = "channel_point")]
    pub channel_point: String,
    #[serde(rename = "remote_pubkey")]
    pub remote_pubkey: String,
    #[serde(deserialize_with = "de_i64")]
    pub capacity: i64,
    #[serde(rename = "local_balance", deserialize_with = "de_i64")]
    pub local_balance: i64,
    #[serde(rename = "remote_balance", deserialize_with = "de_i64")]
    pub remote_balance: i64,
    #[serde(rename = "commit_fee", deserialize_with = "de_i64")]
    pub commit_fee: i64,
    #[serde(rename = "chan_status_flags")]
    pub chan_status_flags: String,
    #[serde(rename = "chan_id", default, deserialize_with = "de_opt_u64")]
    pub chan_id: Option<u64>,
    // ── Phase 7.1: full liquidity model (RIEKO-AUDIT-011) ──
    /// Local channel reserve in satoshis. LND's API reports this as `local_chan_reserve_sat`.
    #[serde(
        rename = "local_chan_reserve_sat",
        default,
        deserialize_with = "de_opt_i64"
    )]
    pub local_chan_reserve_sat: Option<i64>,
    /// Remote channel reserve in satoshis.
    #[serde(
        rename = "remote_chan_reserve_sat",
        default,
        deserialize_with = "de_opt_i64"
    )]
    pub remote_chan_reserve_sat: Option<i64>,
    /// Whether this is an unannounced (private) channel.
    #[serde(default)]
    pub private: bool,
    /// Whether the local node opened (initiated) this channel.
    #[serde(default)]
    pub initiator: bool,
    /// Lifetime total outbound msat sent through this channel.
    #[serde(
        rename = "total_satoshis_sent",
        default,
        deserialize_with = "de_opt_i64"
    )]
    pub total_satoshis_sent: Option<i64>,
    /// Lifetime total inbound msat received through this channel.
    #[serde(
        rename = "total_satoshis_received",
        default,
        deserialize_with = "de_opt_i64"
    )]
    pub total_satoshis_received: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LndChannelResponse {
    pub channels: Vec<LndChannel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LndForward {
    #[serde(rename = "chan_id_in", deserialize_with = "de_u64")]
    pub chan_id_in: u64,
    #[serde(rename = "chan_id_out", deserialize_with = "de_u64")]
    pub chan_id_out: u64,
    #[serde(rename = "amt_in_msat", deserialize_with = "de_i64")]
    pub amt_in_msat: i64,
    #[serde(rename = "amt_out_msat", deserialize_with = "de_i64")]
    pub amt_out_msat: i64,
    #[serde(rename = "fee_msat", deserialize_with = "de_i64")]
    pub fee_msat: i64,
    #[serde(rename = "timestamp", deserialize_with = "de_i64")]
    pub timestamp: i64,
    /// Nanosecond-resolution completion time (LND 0.17+). Preferred over
    /// `timestamp` for the event timestamp. `None` on older nodes.
    #[serde(rename = "timestamp_ns", default, deserialize_with = "de_opt_u64")]
    pub timestamp_ns: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LndForwardResponse {
    #[serde(rename = "forwarding_events")]
    pub forwarding_events: Vec<LndForward>,
}

/// Response from `/v1/getinfo`. Only the fields Rieko uses are captured;
/// unknown fields are silently ignored by serde.
#[derive(Debug, Clone, Deserialize)]
pub struct LndGetInfoResponse {
    /// Node public key (33-byte compressed, hex-encoded).
    pub identity_pubkey: String,
    /// Human-readable node alias, if set.
    #[serde(default)]
    pub alias: Option<String>,
    /// LND version string, e.g. `"0.18.5-beta commit=abc"`.
    #[serde(default)]
    pub version: Option<String>,
    /// Chains this node is synced to (one entry per chain).
    #[serde(default)]
    pub chains: Vec<LndChainInfo>,
}

impl LndGetInfoResponse {
    /// Returns the first network name reported by LND (e.g. `"mainnet"`,
    /// `"testnet"`, `"regtest"`, `"signet"`).
    pub fn network(&self) -> Option<&str> {
        self.chains.first().map(|c| c.network.as_str())
    }
}

/// One entry in `GetInfoResponse.chains`.
#[derive(Debug, Clone, Deserialize)]
pub struct LndChainInfo {
    /// e.g. `"bitcoin"`
    #[serde(default)]
    pub chain: String,
    /// e.g. `"mainnet"`, `"testnet"`, `"regtest"`, `"signet"`
    #[serde(default)]
    pub network: String,
}

/// Deserialise a required 64-bit integer from either a JSON number or a JSON
/// string (grpc-gateway emits strings for 64-bit fields).
fn de_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expected u64")),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|_| serde::de::Error::custom("expected u64 string")),
        _ => Err(serde::de::Error::custom("expected number or u64 string")),
    }
}

/// Deserialise an optional 64-bit integer allowing `null`.
fn de_opt_u64<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(s) => s
            .as_u64()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("expected u64")),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected u64 string")),
        _ => Err(serde::de::Error::custom("expected u64, string, or null")),
    }
}

/// Deserialise a required signed 64-bit integer from either a JSON number or a
/// JSON string.
fn de_i64<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Number(s) => s
            .as_i64()
            .ok_or_else(|| serde::de::Error::custom("expected i64")),
        serde_json::Value::String(s) => s
            .parse::<i64>()
            .map_err(|_| serde::de::Error::custom("expected i64 string")),
        _ => Err(serde::de::Error::custom("expected number or i64 string")),
    }
}

/// Deserialise an optional signed 64-bit integer allowing `null`.
fn de_opt_i64<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(s) => s
            .as_i64()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("expected i64")),
        serde_json::Value::String(s) => s
            .parse::<i64>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected i64 string")),
        _ => Err(serde::de::Error::custom("expected i64, string, or null")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative LND 0.17 `/v1/channels` item: 64-bit fields are JSON
    /// strings, the outpoint is `channel_point`, and `chan_status_flags` is the
    /// named ChannelStatus string.
    const CHANNEL_JSON: &str = r#"{
      "channels": [{
        "channel_point": "aaa111bbb222ccc333:0",
        "remote_pubkey": "03...",
        "capacity": "160000",
        "local_balance": "150000",
        "remote_balance": "10000",
        "commit_fee": "1000",
        "chan_status_flags": "ChanStatusBorked",
        "chan_id": "725708947102208001"
      }]
    }"#;

    #[test]
    fn parses_realistic_lnd_wire_format() {
        let parsed: LndChannelResponse = serde_json::from_str(CHANNEL_JSON).unwrap();
        assert_eq!(parsed.channels.len(), 1);
        let c = &parsed.channels[0];
        assert_eq!(c.channel_point, "aaa111bbb222ccc333:0");
        assert_eq!(c.capacity, 160_000);
        assert_eq!(c.local_balance, 150_000);
        assert_eq!(c.chan_status_flags, "ChanStatusBorked");
        assert_eq!(c.chan_id, Some(725_708_947_102_208_001));
    }

    #[test]
    fn parses_numeric_fields_too() {
        let json = r#"{"channels":[{
            "channel_point":"a:0",
            "remote_pubkey":"p",
            "capacity":100,"local_balance":90,"remote_balance":10,
            "commit_fee":1,"chan_status_flags":"0","chan_id":7
        }]}"#;
        let parsed: LndChannelResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.channels[0].chan_id, Some(7));
        assert_eq!(parsed.channels[0].capacity, 100);
    }

    #[test]
    fn missing_chan_id_is_none() {
        let json = r#"{"channels":[{"channel_point":"a:0","remote_pubkey":"p",
            "capacity":100,"local_balance":90,"remote_balance":10,
            "commit_fee":1,"chan_status_flags":"0"}]}"#;
        let parsed: LndChannelResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.channels[0].chan_id.is_none());
    }

    #[test]
    fn forward_wire_uses_string_64bit_fields() {
        let json = r#"{"forwarding_events":[{
            "timestamp":"1685321004",
            "timestamp_ns":"1685321004123456789",
            "chan_id_in":"100","chan_id_out":"200",
            "amt_in":"1000","amt_out":"990","fee":"10",
            "amt_in_msat":"1000","amt_out_msat":"990","fee_msat":"10"
        }]}"#;
        let parsed: LndForwardResponse = serde_json::from_str(json).unwrap();
        let f = &parsed.forwarding_events[0];
        assert_eq!(f.chan_id_in, 100);
        assert_eq!(f.chan_id_out, 200);
        assert_eq!(f.fee_msat, 10);
        assert_eq!(f.amt_in_msat, 1000);
        assert_eq!(f.timestamp, 1_685_321_004);
        assert_eq!(f.timestamp_ns, Some(1_685_321_004_123_456_789));
    }

    #[test]
    fn absent_timestamp_ns_is_none() {
        let json = r#"{"forwarding_events":[{
            "chan_id_in":"1","chan_id_out":"2",
            "amt_in_msat":"1","amt_out_msat":"1","fee_msat":"0","timestamp":"100"
        }]}"#;
        let parsed: LndForwardResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.forwarding_events[0].timestamp_ns, None);
    }
}
