use hmac::{Hmac, Mac};
use rieko_domain::{BitcoinNetwork, NodeEvent, NodeIngestionAdapter};
use rieko_ingest_btcpay::{
    normalize_webhook_payload, verify_btcpay_sig, BtcPayAdapter, BtcPayAdapterConfig,
    BtcPayGreenfieldClient,
};
use sha2::Sha256;
use tokio_stream::StreamExt;

type HmacSha256 = Hmac<Sha256>;

fn compute_hmac_hex(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

#[test]
fn verifies_valid_signature_with_sha256_prefix() {
    let secret = b"super-secret-webhook-key-12345";
    let payload = br#"{"deliveryId":"del-1","webhookId":"wh-1","type":"InvoiceSettled","timestamp":1629892019,"storeId":"store-abc","invoiceId":"inv-xyz"}"#;

    let hex_sig = compute_hmac_hex(secret, payload);
    let header_val = format!("sha256={hex_sig}");

    assert!(verify_btcpay_sig(secret, payload, &header_val));
}

#[test]
fn verifies_valid_signature_without_prefix() {
    let secret = b"another-secret-key-999";
    let payload = br#"{"deliveryId":"del-2","webhookId":"wh-2","type":"InvoiceExpired","timestamp":1629892100,"storeId":"store-abc","invoiceId":"inv-123"}"#;

    let hex_sig = compute_hmac_hex(secret, payload);
    assert!(verify_btcpay_sig(secret, payload, &hex_sig));
}

#[test]
fn rejects_tampered_payload() {
    let secret = b"super-secret-webhook-key-12345";
    let payload = br#"{"deliveryId":"del-1","webhookId":"wh-1","type":"InvoiceSettled","timestamp":1629892019,"storeId":"store-abc","invoiceId":"inv-xyz"}"#;

    let hex_sig = compute_hmac_hex(secret, payload);
    let header_val = format!("sha256={hex_sig}");

    let mut tampered_payload = payload.to_vec();
    tampered_payload[10] = if tampered_payload[10] == b'a' {
        b'b'
    } else {
        b'a'
    };

    assert!(!verify_btcpay_sig(secret, &tampered_payload, &header_val));
}

#[test]
fn rejects_wrong_secret() {
    let secret_correct = b"correct-secret";
    let secret_wrong = b"wrong-secret";
    let payload = br#"{"type":"InvoiceSettled"}"#;

    let hex_sig = compute_hmac_hex(secret_correct, payload);
    assert!(!verify_btcpay_sig(
        secret_wrong,
        payload,
        &format!("sha256={hex_sig}")
    ));
}

#[test]
fn rejects_empty_or_malformed_inputs() {
    let secret = b"valid-secret";
    let payload = br#"{"type":"InvoiceSettled"}"#;

    assert!(!verify_btcpay_sig(b"", payload, "sha256=abcdef"));
    assert!(!verify_btcpay_sig(secret, payload, ""));
    assert!(!verify_btcpay_sig(secret, payload, "   "));
    assert!(!verify_btcpay_sig(
        secret,
        payload,
        "sha256=not_hex_at_all!!"
    ));
    assert!(!verify_btcpay_sig(secret, payload, "sha256=12345")); // too short
}

#[test]
fn normalizes_invoice_settled_payload() {
    let raw = r#"{
        "deliveryId": "del-settled-1",
        "webhookId": "wh-1",
        "originalDeliveryId": null,
        "isRedelivery": false,
        "type": "InvoiceSettled",
        "timestamp": 1724248800,
        "storeId": "store-main",
        "invoiceId": "inv-999",
        "paymentMethod": "BTC-LightningNetwork",
        "payment": {
            "value": "100000",
            "fee": "100",
            "status": "Settled",
            "paymentHash": "hash123"
        },
        "metadata": {
            "orderId": "order-42",
            "posData": "item-1"
        }
    }"#;

    let event = normalize_webhook_payload(raw.as_bytes()).expect("normalization succeeds");
    match event {
        NodeEvent::InvoiceSettled(e) => {
            assert_eq!(e.id, "inv-999");
            assert_eq!(e.store_id.as_deref(), Some("store-main"));
            assert_eq!(e.payment_method.as_deref(), Some("BTC-LightningNetwork"));
            assert_eq!(e.amount_msat, 100_000);
            assert_eq!(e.fee_msat, 100);
            assert_eq!(e.payment_hash.as_deref(), Some("hash123"));
            assert_eq!(
                e.metadata.get("orderId").map(|s| s.as_str()),
                Some("order-42")
            );
        }
        other => panic!("expected InvoiceSettled, got {:?}", other),
    }
}

#[test]
fn normalizes_invoice_payment_received_payload() {
    let raw = r#"{
        "deliveryId": "del-rec-1",
        "webhookId": "wh-2",
        "type": "InvoiceReceivedPayment",
        "timestamp": 1724248850,
        "storeId": "store-main",
        "invoiceId": "inv-888",
        "paymentMethod": "BTC-LightningNetwork",
        "payment": {
            "value": "50000",
            "fee": "50",
            "status": "Processing"
        }
    }"#;

    let event = normalize_webhook_payload(raw.as_bytes()).expect("normalization succeeds");
    match event {
        NodeEvent::InvoicePaymentReceived(e) => {
            assert_eq!(e.id, "inv-888");
            assert_eq!(e.amount_msat, 50_000);
            assert_eq!(e.fee_msat, 50);
        }
        other => panic!("expected InvoicePaymentReceived, got {:?}", other),
    }
}

#[test]
fn normalizes_invoice_expired_payload() {
    let raw = r#"{
        "deliveryId": "del-exp-1",
        "webhookId": "wh-3",
        "type": "InvoiceExpired",
        "timestamp": 1724248900,
        "storeId": "store-main",
        "invoiceId": "inv-777"
    }"#;

    let event = normalize_webhook_payload(raw.as_bytes()).expect("normalization succeeds");
    match event {
        NodeEvent::InvoiceExpired(e) => {
            assert_eq!(e.id, "inv-777");
            assert_eq!(e.store_id.as_deref(), Some("store-main"));
        }
        other => panic!("expected InvoiceExpired, got {:?}", other),
    }
}

#[tokio::test]
async fn adapter_event_stream_propagates_webhook_events() {
    let client = BtcPayGreenfieldClient::new("https://btcpay.mock.test", "test-api-key")
        .expect("client creation succeeds");
    let secret = "wh-secret-secure";
    let config = BtcPayAdapterConfig {
        store_id: "store-test".into(),
        crypto_code: "BTC".into(),
        network: BitcoinNetwork::Testnet,
        node_id_override: Some("mock-node".into()),
        webhook_secret: Some(secret.into()),
    };

    let adapter = BtcPayAdapter::new(client, config);
    let mut stream = adapter
        .event_stream()
        .await
        .expect("stream subscription succeeds");

    let payload = br#"{
        "deliveryId": "del-stream-1",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724249000,
        "storeId": "store-test",
        "invoiceId": "inv-stream-1",
        "paymentMethod": "BTC-LightningNetwork",
        "payment": {
            "value": "250000",
            "fee": "25"
        }
    }"#;

    let hex_sig = compute_hmac_hex(secret.as_bytes(), payload);
    let header_val = format!("sha256={hex_sig}");

    adapter
        .handle_webhook(payload, &header_val)
        .await
        .expect("handle_webhook succeeds");

    let received = stream.next().await.expect("received event from stream");
    match received {
        NodeEvent::InvoiceSettled(e) => {
            assert_eq!(e.id, "inv-stream-1");
            assert_eq!(e.amount_msat, 250_000);
            assert_eq!(e.fee_msat, 25);
        }
        other => panic!("expected InvoiceSettled, got {:?}", other),
    }
}
