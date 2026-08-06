//! Opt-in LND regtest integration (Phase 6.1 / RIEKO-AUDIT-017).
//!
//! These tests require a running LND regtest node. They are ignored by
//! default and only execute when `RIEKO_REGTEST_LND_URL` is set.
//!
//! Prerequisites (see `regtest/README.md`):
//!   export RIEKO_REGTEST_LND_URL=https://localhost:8080
//!   export RIEKO_REGTEST_TLS_CERT=/path/to/tls.cert
//!   export RIEKO_REGTEST_MACAROON=/path/to/read-only.macaroon
//!   export RIEKO_REGTEST_NODE_ID=<your-node-pubkey>
//!
//! Run:  cargo test -p rieko-ingest-lnd --test regtest -- --ignored
//!
//! The restricted macaroon must grant:
//!   uri:/lnrpc.Lightning/Channels
//!   uri:/lnrpc.Lightning/ForwardingHistory
//!
//! Do NOT use an admin macaroon.

use rieko_domain::{ChannelStatus, NodeId};
use rieko_ingest_lnd::{LndClient, ShortChanResolver};

fn env_or_skip(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("SKIP: {key} not set");
        std::process::exit(0);
    })
}

fn setup() -> (LndClient, NodeId) {
    let url = env_or_skip("RIEKO_REGTEST_LND_URL");
    let tls_cert_path = env_or_skip("RIEKO_REGTEST_TLS_CERT");
    let macaroon_path = env_or_skip("RIEKO_REGTEST_MACAROON");
    let node_id = NodeId::new(env_or_skip("RIEKO_REGTEST_NODE_ID"));

    let macaroon = std::fs::read(&macaroon_path).expect("reading macaroon");
    let tls_cert = std::fs::read(&tls_cert_path).expect("reading TLS cert");
    let client = LndClient::new(&url, Some(macaroon), Some(tls_cert)).expect("building LND client");

    (client, node_id)
}

#[test]
#[ignore]
fn regtest_read_only_surface_accepts_restricted_macaroon() {
    let (client, node) = setup();
    let channels = client
        .channels(&node)
        .expect("channels must succeed with read-only macaroon");
    eprintln!("fetched {} channels", channels.len());
}

#[test]
#[ignore]
fn regtest_raw_channels_match_normalized_channels() {
    let (client, node) = setup();
    let raw = client.raw_channels().expect("raw channels");
    let channels = client.channels(&node).expect("channels");
    // Every raw channel must map to exactly one normalized channel.
    assert_eq!(
        raw.len(),
        channels.len(),
        "raw channel count must match normalized"
    );
    for ch in &channels {
        assert_eq!(
            ch.node, node,
            "every channel must belong to the configured node"
        );
    }
}

#[test]
#[ignore]
fn regtest_channel_status_is_not_unknown() {
    let (client, node) = setup();
    let channels = client.channels(&node).expect("channels");
    // Every channel in a controlled regtest environment should have a
    // known status. Unknown would indicate a bug in status_from_lnd_flags
    // or a new LND flag that wasn't accounted for.
    for ch in &channels {
        assert_ne!(
            ch.status,
            ChannelStatus::Unknown,
            "channel {} status is Unknown — LND may have new flags",
            ch.id
        );
    }
}

#[test]
#[ignore]
fn regtest_forwarding_resolves_channel_ids() {
    let (client, node) = setup();
    let _channels = client.channels(&node).expect("channels");
    let raw = client.raw_channels().expect("raw channels");
    let resolver = ShortChanResolver::from_channels(&raw);
    let events = client.forwards(&resolver).expect("forwarding events");
    // In regtest there may be zero forwards; that's fine.
    eprintln!("fetched {} forwarding events", events.len());
    for evt in &events {
        assert!(!evt.channel_in.to_string().is_empty());
        assert!(!evt.channel_out.to_string().is_empty());
    }
}

#[test]
#[ignore]
fn regtest_rejects_wrong_tls_certificate() {
    let url = env_or_skip("RIEKO_REGTEST_LND_URL");
    let macaroon_path = env_or_skip("RIEKO_REGTEST_MACAROON");
    let macaroon = std::fs::read(&macaroon_path).expect("reading macaroon");

    // Self-signed cert that does NOT match LND.
    let bad_cert = b"-----BEGIN CERTIFICATE-----\n\
MIIDazCCAlOgAwIBAgIUZ...\n\
-----END CERTIFICATE-----\n"
        .to_vec();

    let result = LndClient::new(&url, Some(macaroon), Some(bad_cert));
    match result {
        Err(e) => {
            // TLS setup failure (bad cert or connection error) is acceptable.
            eprintln!("wrong cert rejected: {e}");
        }
        Ok(client) => {
            // If construction succeeded, the first request should fail.
            let call_err = client
                .raw_channels()
                .unwrap_err()
                .to_string()
                .to_lowercase();
            assert!(
                call_err.contains("cert")
                    || call_err.contains("tls")
                    || call_err.contains("connect"),
                "wrong TLS cert should be rejected, got: {call_err}"
            );
        }
    }
}

#[test]
#[ignore]
fn regtest_insufficient_macaroon_is_rejected() {
    let url = env_or_skip("RIEKO_REGTEST_LND_URL");
    let tls_cert_path = env_or_skip("RIEKO_REGTEST_TLS_CERT");
    let tls_cert = std::fs::read(&tls_cert_path).expect("reading TLS cert");

    // Empty macaroon — no permissions.
    let client = LndClient::new(&url, Some(vec![]), Some(tls_cert))
        .expect("constructing client with empty macaroon");
    let call_err = client
        .raw_channels()
        .unwrap_err()
        .to_string()
        .to_lowercase();
    assert!(
        call_err.contains("unauthorized")
            || call_err.contains("forbidden")
            || call_err.contains("permission")
            || call_err.contains("status")
            || call_err.contains("401")
            || call_err.contains("403"),
        "insufficient macaroon should be rejected, got: {call_err}"
    );
}

#[test]
#[ignore]
fn regtest_source_freshness_is_reported() {
    let (client, node) = setup();
    let channels = client.channels(&node).expect("channels");
    assert!(
        !channels.is_empty(),
        "regtest node should have at least one channel"
    );
    for ch in &channels {
        let age = chrono::Utc::now() - ch.last_seen;
        let age_secs = age.num_seconds().abs();
        // In a controlled regtest environment, last_seen should be recent.
        assert!(
            age_secs < 3600,
            "channel {} last_seen is {}s old — check LND clock",
            ch.id,
            age_secs
        );
    }
}

#[test]
#[ignore]
fn regtest_node_mismatch_is_detectable() {
    let (client, node) = setup();
    let channels = client.channels(&node).expect("channels");
    // If the configured node ID doesn't own these channels, something
    // is wrong with the test setup.
    if !channels.is_empty() {
        let owned = channels.iter().any(|ch| ch.node == node);
        let peers: Vec<_> = channels.iter().map(|ch| ch.peer.to_string()).collect();
        eprintln!("channels belong to peers: {peers:?}");
        assert!(
            owned,
            "configured NODE_ID {} does not own any channels — check node identity",
            node
        );
    }
}
