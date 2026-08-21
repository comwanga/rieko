use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use rieko_storage::SqliteStorage;
use sha2::Sha256;
use tokio::sync::mpsc;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

fn compute_sig(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[tokio::test]
async fn failure_mode_mismatched_webhook_secret_emits_no_events() {
    let (tx, mut rx) = mpsc::channel(16);
    let server_secret = "configured-server-secret-999";
    let attacker_secret = "wrong-attacker-secret-111";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(server_secret, tx);

    let app = api.router();

    let payload = br#"{
        "deliveryId": "del-mismatch-1",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-1",
        "payment": {"value": "1000", "fee": "10"}
    }"#;

    // Signed with wrong attacker secret
    let forged_sig = compute_sig(attacker_secret.as_bytes(), payload);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", forged_sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(val["error"]["code"], "invalid_signature");

    // Zero domain events must be enqueued
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn failure_mode_malformed_json_body_rejected_before_normalization() {
    let (tx, mut rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let malformed_payload = br#"{"deliveryId":"del-corrupt", "webhookId": "wh-1", "type": "InvoiceSettled", "broken_json"#;
    let sig = compute_sig(secret.as_bytes(), malformed_payload);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", sig)
        .body(Body::from(malformed_payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(val["error"]["code"], "invalid_payload");

    // Zero domain events enqueued
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn failure_mode_unknown_event_type_fails_closed_without_escape_hatch() {
    let (tx, mut rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let unknown_type_payload = br#"{
        "deliveryId": "del-unknown-type",
        "webhookId": "wh-1",
        "type": "SomeUnrecognizedCustomGreenfieldEvent",
        "timestamp": 1724250000,
        "storeId": "store-1"
    }"#;
    let sig = compute_sig(secret.as_bytes(), unknown_type_payload);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", sig)
        .body(Body::from(unknown_type_payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(val["error"]["code"], "normalization_failed");

    // Zero domain events enqueued
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn failure_mode_malformed_signature_lengths_rejected() {
    let (tx, _rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let payload = br#"{"deliveryId":"d","webhookId":"w","type":"InvoiceSettled","timestamp":1,"storeId":"s"}"#;

    for invalid_sig in [
        "sha256=",                                                                 // empty hash
        "sha256=12345",                                                            // too short
        "sha256=abcdefg", // invalid length & chars
        "sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex chars (length 64)
        "md5=00000000000000000000000000000000", // wrong algorithm
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/integrations/btcpay/webhook")
            .header("content-type", "application/json")
            .header("BTCPay-Sig", invalid_sig)
            .body(Body::from(payload.to_vec()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "signature {invalid_sig} should be rejected with 401"
        );
    }
}
