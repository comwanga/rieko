use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use rieko_domain::NodeEvent;
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
async fn webhook_accepts_valid_signature_and_dispatches_event() {
    let (tx, mut rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_auth("bearer-token-for-api")
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let payload = br#"{
        "deliveryId": "del-100",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724249999,
        "storeId": "store-alpha",
        "invoiceId": "inv-001",
        "paymentMethod": "BTC-LightningNetwork",
        "payment": {
            "value": "150000",
            "fee": "15",
            "paymentHash": "hash-abc"
        }
    }"#;

    let sig = compute_sig(secret.as_bytes(), payload);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(val["status"], "accepted");

    let received = rx.recv().await.expect("received event");
    match received {
        NodeEvent::InvoiceSettled(e) => {
            assert_eq!(e.id, "inv-001");
            assert_eq!(e.store_id.as_deref(), Some("store-alpha"));
            assert_eq!(e.amount_msat, 150_000);
            assert_eq!(e.fee_msat, 15);
            assert_eq!(e.payment_hash.as_deref(), Some("hash-abc"));
        }
        other => panic!("expected InvoiceSettled, got {:?}", other),
    }
}

#[tokio::test]
async fn webhook_rejects_invalid_signature() {
    let (tx, _rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let payload = br#"{"deliveryId":"d","webhookId":"w","type":"InvoiceSettled","timestamp":1,"storeId":"s"}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(val["error"]["code"], "invalid_signature");
}
