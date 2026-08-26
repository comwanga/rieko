use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rieko_domain::{
    Channel, ChannelId, ChannelStatus, FeePolicy, ForwardEvent, LightningSnapshot,
    LiquidityProfile, NodeId,
};
use thiserror::Error;

use crate::model::{LndChannel, LndForward};

#[derive(Debug, Error)]
pub enum NormalizerError {
    #[error("malformed channel point `{0}`: expected txid:index")]
    BadChannelPoint(String),
    #[error("negative balance on channel {0}")]
    NegativeBalance(String),
}

/// Pure normalizers: LND wire types → domain objects (D4). No I/O here, so
/// the semantics are unit-testable with fixtures.
pub struct Normalizer;

/// Resolves LND short channel ids to the canonical channel identity (channel
/// point) used by domain objects.
///
/// LND references channels two ways: `ListChannels` keys a channel by its
/// funding outpoint (`channel_point`, e.g. `txid:index`) *and* exposes a
/// compact short channel id (`chan_id`, an uint64). Forwarding events only
/// carry the short channel id. Because the graph keys channels by channel
/// point, forwards must be translated through this map to correlate at all
/// (RIEKO-AUDIT-019).
#[derive(Debug, Clone, Default)]
pub struct ShortChanResolver {
    scid_to_channel: HashMap<u64, ChannelId>,
}

impl ShortChanResolver {
    pub fn from_channels(channels: &[LndChannel]) -> Self {
        let mut scid_to_channel = HashMap::new();
        for c in channels {
            if let Some(scid) = c.chan_id {
                // Same canonical form Normalizer::channel uses (`:` → `x`).
                scid_to_channel
                    .entry(scid)
                    .or_insert_with(|| ChannelId::new(c.channel_point.replace(':', "x")));
            }
        }
        Self { scid_to_channel }
    }

    pub fn resolve(&self, scid: u64) -> Option<ChannelId> {
        self.scid_to_channel.get(&scid).cloned()
    }
}

impl Normalizer {
    /// Normalize the minimal LND node health fields used by the agent's
    /// durable operational-state boundary.
    pub fn lightning_snapshot(
        info: &crate::LndGetInfoResponse,
        observed_at: DateTime<Utc>,
    ) -> LightningSnapshot {
        LightningSnapshot {
            node_id: info.identity_pubkey.clone(),
            synced_to_chain: info.synced_to_chain,
            active_channels: info.num_active_channels,
            inactive_channels: info.num_inactive_channels,
            observed_at,
        }
    }

    pub fn channel(
        lnd: &LndChannel,
        local_node: &NodeId,
        seen_at: DateTime<Utc>,
    ) -> Result<Channel, NormalizerError> {
        let id = lnd.channel_point.replace(':', "x");
        if !lnd.channel_point.contains(':') {
            return Err(NormalizerError::BadChannelPoint(lnd.channel_point.clone()));
        }
        let capacity = u64::try_from(lnd.capacity).unwrap_or(0);
        let local = u64::try_from(lnd.local_balance)
            .map_err(|_| NormalizerError::NegativeBalance(id.clone()))?;
        let remote = u64::try_from(lnd.remote_balance)
            .map_err(|_| NormalizerError::NegativeBalance(id.clone()))?;

        let capacity_msat = capacity * 1_000;
        let local_msat = local * 1_000;
        let remote_msat = remote * 1_000;

        let local_reserve_msat = lnd
            .local_chan_reserve_sat
            .and_then(|s| u64::try_from(s).ok())
            .map(|s| s * 1_000);
        let remote_reserve_msat = lnd
            .remote_chan_reserve_sat
            .and_then(|s| u64::try_from(s).ok())
            .map(|s| s * 1_000);

        let spendable_outbound = local_reserve_msat
            .map(|res| local_msat.saturating_sub(res))
            .unwrap_or(0);
        let spendable_inbound = remote_reserve_msat
            .map(|res| remote_msat.saturating_sub(res))
            .unwrap_or(0);

        let mut profile = LiquidityProfile::compute(capacity_msat, local_msat, remote_msat);
        profile.spendable_outbound_msat = spendable_outbound;
        profile.spendable_inbound_msat = spendable_inbound;

        Ok(Channel {
            id: ChannelId::new(id),
            node: local_node.clone(),
            peer: NodeId::new(lnd.remote_pubkey.clone()),
            channel_point: lnd.channel_point.clone(),
            capacity_msat,
            fee_policy: FeePolicy::default(),
            status: status_from_lnd_flags(&lnd.chan_status_flags),
            liquidity: profile,
            last_seen: seen_at,
            opening_height: None,
            local_reserve_msat,
            remote_reserve_msat,
            is_private: lnd.private,
            is_initiator: lnd.initiator,
            total_sent_msat: lnd
                .total_satoshis_sent
                .and_then(|s| u64::try_from(s).ok())
                .map(|s| s * 1_000),
            total_received_msat: lnd
                .total_satoshis_received
                .and_then(|s| u64::try_from(s).ok())
                .map(|s| s * 1_000),
        })
    }

    pub fn forward(lnd: &LndForward, resolver: &ShortChanResolver) -> ForwardEvent {
        ForwardEvent {
            id: forward_event_id(lnd),
            channel_in: resolve_forward_channel(lnd.chan_id_in, resolver),
            channel_out: resolve_forward_channel(lnd.chan_id_out, resolver),
            amount_msat: u64::try_from(lnd.amt_in_msat).unwrap_or(0),
            fee_msat: u64::try_from(lnd.fee_msat).unwrap_or(0),
            timestamp: forward_timestamp(lnd),
        }
    }
}

/// A forward event's stable identity.
///
/// LND 0.17's `ForwardingEvent` exposes no per-event id, so there is no
/// source-provided unique key to borrow. We therefore derive the identity from
/// a single, high-resolution source value — `timestamp_ns` (falling back to
/// `timestamp`) — and prefix it so it cannot collide with channel or finding
/// ids. This is *not* a concatenation of loosely-correlated fields and must
/// not be assumed unique for two events sharing a nanosecond; forwards are
/// not deduplicated by this id.
fn forward_event_id(lnd: &LndForward) -> String {
    match lnd.timestamp_ns {
        Some(ns) => format!("fwd:{ns}"),
        None => format!("fwd:{}", lnd.timestamp),
    }
}

/// The event timestamp comes from the source (RIEKO-AUDIT-019): the
/// nanosecond-resolution `timestamp_ns` when present, otherwise `timestamp`
/// (unix seconds). Processing time is never substituted; an out-of-range
/// source value degrades to the unix epoch rather than `Utc::now()`.
fn forward_timestamp(lnd: &LndForward) -> DateTime<Utc> {
    if let Some(ns) = lnd.timestamp_ns {
        let secs = (ns / 1_000_000_000) as i64;
        let nanos = (ns % 1_000_000_000) as u32;
        DateTime::from_timestamp(secs, nanos).unwrap_or(DateTime::UNIX_EPOCH)
    } else {
        DateTime::from_timestamp(lnd.timestamp, 0).unwrap_or(DateTime::UNIX_EPOCH)
    }
}

/// Map an LND short channel id to the canonical channel identity.
///
/// When the id resolves to a known channel we return its channel point. When
/// resolution is unavailable — including `scid == 0`, LND's sentinel for "no
/// channel" — the raw id is preserved explicitly under an `scid:` prefix and
/// correlation is *not* claimed (RIEKO-AUDIT-019).
fn resolve_forward_channel(scid: u64, resolver: &ShortChanResolver) -> ChannelId {
    match resolver.resolve(scid) {
        Some(channel) => channel,
        None => ChannelId::new(format!("scid:{scid}")),
    }
}

// LND channel status flags (channeldb `ChannelStatus`, exposed as the
// `chan_status_flags` string on `/v1/channels`; target schema LND 0.17+):
//
// | value | token                        | meaning                                   |
// |-------|------------------------------|-------------------------------------------|
// | 0     | ChanStatusDefault            | open and usable                           |
// | 1     | ChanStatusBorked             | irreconcilable, will be force closed      |
// | 2     | ChanStatusCommitBroadcasted  | a commitment has been broadcast           |
// | 4     | ChanStatusLocalDataLoss      | local channel state lost                  |
// | 8     | ChanStatusRestored           | restored from backup, not yet active      |
// | 16    | ChanStatusCoopBroadcasted    | cooperative close broadcast               |
// | 32    | ChanStatusLocalCloseInitiator  | we initiated the close                  |
// | 64    | ChanStatusRemoteCloseInitiator | the peer initiated the close           |
//
// Multiple flags are pipe-joined; unrecognised bits are rendered as `0x…`.
// Prior to this mapping the normalizer parsed the string as a number and
// defaulted anything unrecognised to `Active` (RIEKO-AUDIT-021).
fn status_from_lnd_flags(flags: &str) -> ChannelStatus {
    const KNOWN_BITS: u64 = 1 | 2 | 4 | 8 | 16 | 32 | 64;

    let mut bits: u64 = 0;
    let mut parsed_any = false;
    for token in flags.split('|') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some(hex) = token.strip_prefix("0x") {
            let Ok(v) = u64::from_str_radix(hex, 16) else {
                return ChannelStatus::Unknown;
            };
            bits |= v;
            parsed_any = true;
        } else if let Ok(n) = token.parse::<u64>() {
            bits |= n;
            parsed_any = true;
        } else {
            match token {
                "ChanStatusDefault" => parsed_any = true,
                "ChanStatusBorked" => {
                    bits |= 1;
                    parsed_any = true;
                }
                "ChanStatusCommitBroadcasted" => {
                    bits |= 2;
                    parsed_any = true;
                }
                "ChanStatusLocalDataLoss" => {
                    bits |= 4;
                    parsed_any = true;
                }
                "ChanStatusRestored" => {
                    bits |= 8;
                    parsed_any = true;
                }
                "ChanStatusCoopBroadcasted" => {
                    bits |= 16;
                    parsed_any = true;
                }
                "ChanStatusLocalCloseInitiator" => {
                    bits |= 32;
                    parsed_any = true;
                }
                "ChanStatusRemoteCloseInitiator" => {
                    bits |= 64;
                    parsed_any = true;
                }
                _ => return ChannelStatus::Unknown,
            }
        }
    }

    if !parsed_any {
        // Empty or whitespace-only: nothing known to trust.
        return ChannelStatus::Unknown;
    }

    classify_status_bits(bits, KNOWN_BITS)
}

fn classify_status_bits(bits: u64, known: u64) -> ChannelStatus {
    if bits & !known != 0 {
        // A flag LND 0.17 does not define: the combination is not understood,
        // so the channel's real state cannot be asserted.
        return ChannelStatus::Unknown;
    }
    if bits == 0 {
        // ChanStatusDefault: open and usable.
        return ChannelStatus::Active;
    }
    if bits & (1 | 4) != 0 {
        // Borked or local data loss both end in a unilateral close.
        return ChannelStatus::ForceClosing;
    }
    if bits & (2 | 16) != 0 {
        // Commitment or cooperative close broadcast.
        return ChannelStatus::Closing;
    }
    if bits & (32 | 64) != 0 {
        // A close is underway (initiator known, broadcast flag not seen).
        return ChannelStatus::Closing;
    }
    if bits & 8 != 0 {
        // Restored from backup; not yet usable for routing.
        return ChannelStatus::Opening;
    }
    ChannelStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_minimal_lightning_operational_state() {
        let observed_at = Utc::now();
        let info = crate::LndGetInfoResponse {
            identity_pubkey: "02abcdef".into(),
            alias: Some("rieko-regtest".into()),
            version: Some("0.18.5-beta".into()),
            chains: vec![crate::LndChainInfo {
                chain: "bitcoin".into(),
                network: "regtest".into(),
            }],
            synced_to_chain: true,
            num_active_channels: 3,
            num_inactive_channels: 1,
        };

        let snapshot = Normalizer::lightning_snapshot(&info, observed_at);

        assert_eq!(snapshot.node_id, "02abcdef");
        assert!(snapshot.synced_to_chain);
        assert_eq!(snapshot.active_channels, 3);
        assert_eq!(snapshot.inactive_channels, 1);
        assert_eq!(snapshot.observed_at, observed_at);
    }

    fn lnd_channel(point: &str, flags: &str) -> LndChannel {
        LndChannel {
            channel_point: point.into(),
            remote_pubkey: "peerpubkey".into(),
            capacity: 100_000,
            local_balance: 95_000,
            remote_balance: 5_000,
            commit_fee: 100,
            chan_status_flags: flags.into(),
            chan_id: None,
            local_chan_reserve_sat: None,
            remote_chan_reserve_sat: None,
            private: false,
            initiator: true,
            total_satoshis_sent: None,
            total_satoshis_received: None,
        }
    }

    #[test]
    fn channel_maps_balances_to_msat() {
        let lnd = lnd_channel("abc123:1", "ChanStatusDefault");
        let c = Normalizer::channel(&lnd, &NodeId::new("local"), Utc::now()).unwrap();
        assert_eq!(c.capacity_msat, 100_000_000);
        assert_eq!(c.liquidity.local_balance_msat, 95_000_000);
        assert_eq!(
            c.liquidity.imbalance,
            rieko_domain::LiquidityImbalance::InboundDrained
        );
        assert_eq!(c.status, ChannelStatus::Active);
        assert!(c.status.is_open());
        assert_eq!(c.peer.as_str(), "peerpubkey");
    }

    #[test]
    fn bad_channel_point_is_rejected() {
        let lnd = lnd_channel("no-colon-here", "ChanStatusDefault");
        assert!(Normalizer::channel(&lnd, &NodeId::new("local"), Utc::now()).is_err());
    }

    #[test]
    fn status_mapping_matches_lnd_017_bitfield() {
        // Table from channeldb.ChannelStatus (LND 0.17) → domain status.
        let cases: &[(&str, ChannelStatus)] = &[
            ("ChanStatusDefault", ChannelStatus::Active),
            ("ChanStatusBorked", ChannelStatus::ForceClosing),
            ("ChanStatusCommitBroadcasted", ChannelStatus::Closing),
            ("ChanStatusLocalDataLoss", ChannelStatus::ForceClosing),
            ("ChanStatusRestored", ChannelStatus::Opening),
            ("ChanStatusCoopBroadcasted", ChannelStatus::Closing),
            ("ChanStatusLocalCloseInitiator", ChannelStatus::Closing),
            ("ChanStatusRemoteCloseInitiator", ChannelStatus::Closing),
            (
                "ChanStatusBorked|ChanStatusCommitBroadcasted",
                ChannelStatus::ForceClosing,
            ),
            (
                "ChanStatusCoopBroadcasted|ChanStatusLocalCloseInitiator",
                ChannelStatus::Closing,
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(status_from_lnd_flags(raw), *expected, "raw flags: {raw:?}");
        }
    }

    #[test]
    fn status_mapping_accepts_numeric_form() {
        // Numeric form is accepted for compact fixtures; the bit semantics are
        // identical to the named tokens.
        assert_eq!(status_from_lnd_flags("0"), ChannelStatus::Active);
        assert_eq!(status_from_lnd_flags("2"), ChannelStatus::Closing);
        assert_eq!(status_from_lnd_flags("1|2"), ChannelStatus::ForceClosing);
    }

    #[test]
    fn unknown_or_malformed_flags_never_become_active() {
        // Any flag combination outside the documented LND 0.17 table, or
        // malformed input, must map to Unknown — never Active.
        for raw in [
            "",
            "   ",
            "not-a-flag",
            "0x80",
            "ChanStatusBorked|0x80",
            "ChanStatusFutureThing",
            "80000000",
            "ChanStatusDefault|ChanStatusBorked",
            "999",
        ] {
            let status = status_from_lnd_flags(raw);
            assert_ne!(
                status,
                ChannelStatus::Active,
                "raw flags: {raw:?} must not map to Active"
            );
            assert!(
                !status.is_open(),
                "raw flags: {raw:?} must not classify as open"
            );
        }
        assert_eq!(status_from_lnd_flags("0x80"), ChannelStatus::Unknown);
        assert_eq!(
            status_from_lnd_flags("ChanStatusBorked|0x80"),
            ChannelStatus::Unknown
        );
    }

    #[test]
    fn forward_uses_source_timestamp_not_processing_time() {
        let resolver = ShortChanResolver::default();
        let lnd = LndForward {
            chan_id_in: 100,
            chan_id_out: 200,
            amt_in_msat: 1_000,
            amt_out_msat: 990,
            fee_msat: 10,
            timestamp: 1_685_321_004,
            timestamp_ns: Some(1_685_321_004_500_000_000),
        };
        let ev = Normalizer::forward(&lnd, &resolver);
        assert_eq!(
            ev.timestamp,
            DateTime::from_timestamp(1_685_321_004, 500_000_000).unwrap()
        );
        assert_eq!(ev.timestamp.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn forward_falls_back_to_seconds_timestamp() {
        let resolver = ShortChanResolver::default();
        let lnd = LndForward {
            chan_id_in: 100,
            chan_id_out: 200,
            amt_in_msat: 1_000,
            amt_out_msat: 990,
            fee_msat: 10,
            timestamp: 1_685_321_004,
            timestamp_ns: None,
        };
        let ev = Normalizer::forward(&lnd, &resolver);
        assert_eq!(
            ev.timestamp,
            DateTime::from_timestamp(1_685_321_004, 0).unwrap()
        );
    }

    #[test]
    fn forward_id_derives_from_single_source_value() {
        let resolver = ShortChanResolver::default();
        let mk = |ns: Option<u64>, ts: i64| LndForward {
            chan_id_in: 100,
            chan_id_out: 200,
            amt_in_msat: 1_000,
            amt_out_msat: 990,
            fee_msat: 10,
            timestamp: ts,
            timestamp_ns: ns,
        };
        let ev = Normalizer::forward(
            &mk(Some(1_685_321_004_500_000_000), 1_685_321_004),
            &resolver,
        );
        assert_eq!(ev.id, "fwd:1685321004500000000");
        let ev = Normalizer::forward(&mk(None, 1_685_321_004), &resolver);
        assert_eq!(ev.id, "fwd:1685321004");
    }

    #[test]
    fn forward_resolves_chan_ids_to_channel_points() {
        let raw = vec![
            LndChannel {
                chan_id: Some(1),
                ..lnd_channel("txn1:0", "ChanStatusDefault")
            },
            LndChannel {
                chan_id: Some(2),
                ..lnd_channel("txn2:1", "ChanStatusDefault")
            },
        ];
        let resolver = ShortChanResolver::from_channels(&raw);
        let lnd = LndForward {
            chan_id_in: 1,
            chan_id_out: 2,
            amt_in_msat: 1_000,
            amt_out_msat: 990,
            fee_msat: 10,
            timestamp: 1_685_321_004,
            timestamp_ns: None,
        };
        let ev = Normalizer::forward(&lnd, &resolver);
        assert_eq!(ev.channel_in.as_str(), "txn1x0");
        assert_eq!(ev.channel_out.as_str(), "txn2x1");
    }

    #[test]
    fn forward_preserves_unresolvable_chan_id_explicitly() {
        let resolver = ShortChanResolver::from_channels(&[lnd_channel("txn1:0", "0")]);
        let lnd = LndForward {
            chan_id_in: 999_999,
            chan_id_out: 0,
            amt_in_msat: 1_000,
            amt_out_msat: 990,
            fee_msat: 10,
            timestamp: 1_685_321_004,
            timestamp_ns: None,
        };
        let ev = Normalizer::forward(&lnd, &resolver);
        assert_eq!(ev.channel_in.as_str(), "scid:999999");
        assert_eq!(ev.channel_out.as_str(), "scid:0");
    }

    #[test]
    fn resolver_keeps_first_channel_point_for_a_scid() {
        let raw = vec![
            LndChannel {
                chan_id: Some(7),
                ..lnd_channel("txn1:0", "0")
            },
            LndChannel {
                chan_id: Some(7),
                ..lnd_channel("txn9:9", "0")
            },
        ];
        let resolver = ShortChanResolver::from_channels(&raw);
        assert_eq!(resolver.resolve(7).unwrap().as_str(), "txn1x0");
    }
}
