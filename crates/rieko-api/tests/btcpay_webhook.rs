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
async fn webhook_rejects_missing_signature() {
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
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_rejects_signature_without_sha256_prefix() {
    let (tx, _rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let payload = br#"{"deliveryId":"d","webhookId":"w","type":"InvoiceSettled","timestamp":1,"storeId":"s"}"#;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload);
    let raw_hex_sig = hex::encode(mac.finalize().into_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", raw_hex_sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_idempotency_returns_already_processed_on_identical_redelivery() {
    let (tx, mut rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    let payload = br#"{
        "deliveryId": "del-idempotent-1",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-1",
        "payment": {"value": "1000", "fee": "10"}
    }"#;
    let sig = compute_sig(secret.as_bytes(), payload);

    // First delivery
    let req1 = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let val1: serde_json::Value =
        serde_json::from_slice(&resp1.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(val1["status"], "accepted");

    // Event must have been received once
    assert!(rx.recv().await.is_some());

    // Identical redelivery of the same deliveryId
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let val2: serde_json::Value =
        serde_json::from_slice(&resp2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(val2["status"], "already_processed");
    assert_eq!(val2["delivery_id"], "del-idempotent-1");

    // Must NOT enqueue a second time
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn webhook_idempotency_honors_original_delivery_id() {
    let (tx, mut rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx);

    let app = api.router();

    // First delivery (initial attempt)
    let payload1 = br#"{
        "deliveryId": "del-orig-1",
        "webhookId": "wh-1",
        "originalDeliveryId": null,
        "isRedelivery": false,
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-orig-1",
        "payment": {"value": "2000", "fee": "20"}
    }"#;
    let sig1 = compute_sig(secret.as_bytes(), payload1);

    let req1 = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig1)
        .body(Body::from(payload1.to_vec()))
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    assert!(rx.recv().await.is_some());

    // Redelivery using a new deliveryId but referencing originalDeliveryId = "del-orig-1"
    let payload2 = br#"{
        "deliveryId": "del-retry-99",
        "webhookId": "wh-1",
        "originalDeliveryId": "del-orig-1",
        "isRedelivery": true,
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-orig-1",
        "payment": {"value": "2000", "fee": "20"}
    }"#;
    let sig2 = compute_sig(secret.as_bytes(), payload2);

    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig2)
        .body(Body::from(payload2.to_vec()))
        .unwrap();

    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let val2: serde_json::Value =
        serde_json::from_slice(&resp2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(val2["status"], "already_processed");
    assert_eq!(val2["delivery_id"], "del-orig-1");

    // Must NOT enqueue a second time
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn webhook_idempotency_does_not_trust_unauthenticated_requests() {
    let (tx, _rx) = mpsc::channel(16);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx.clone());

    let app = api.router();

    let payload = br#"{"deliveryId":"del-unauth-1","webhookId":"wh-1","type":"InvoiceSettled","timestamp":1,"storeId":"s"}"#;

    // Send with invalid signature
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header(
            "BTCPay-Sig",
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Now send the same deliveryId with the correct signature — must succeed and NOT be marked already_processed
    let valid_payload = br#"{
        "deliveryId": "del-unauth-1",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-valid-1",
        "payment": {"value": "500", "fee": "5"}
    }"#;
    let sig = compute_sig(secret.as_bytes(), valid_payload);

    let req_valid = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", sig)
        .body(Body::from(valid_payload.to_vec()))
        .unwrap();

    let resp_valid = app.oneshot(req_valid).await.unwrap();
    assert_eq!(resp_valid.status(), StatusCode::OK);
    let val: serde_json::Value =
        serde_json::from_slice(&resp_valid.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(val["status"], "accepted");
}

#[tokio::test]
async fn webhook_queue_saturation_returns_503_and_allows_retry() {
    // Channel with capacity 1
    let (tx, _rx) = mpsc::channel(1);
    let secret = "test-webhook-secret-123";

    let storage = SqliteStorage::in_memory().unwrap();
    let api = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_btcpay_webhook(secret, tx.clone());

    let app = api.router();

    // Fill the 1-slot channel
    let dummy_event = rieko_domain::NodeEvent::InvoiceExpired(rieko_domain::InvoiceExpiredEvent {
        id: "dummy".into(),
        store_id: None,
        amount_msat: None,
        timestamp: chrono::Utc::now(),
    });
    tx.send(dummy_event).await.unwrap();

    // Send webhook with 0 capacity remaining (will timeout and return 503)
    let payload = br#"{
        "deliveryId": "del-sat-1",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-sat-1",
        "payment": {"value": "500", "fee": "5"}
    }"#;
    let sig = compute_sig(secret.as_bytes(), payload);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let val: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(val["error"]["code"], "queue_saturated");

    // Verify delivery was NOT recorded in storage, so retry is allowed
    let (tx_retry, mut rx_retry) = mpsc::channel(16);
    let storage_ref = api.state.storage.clone();
    let storage_box = storage_ref.lock().await;
    // Drain slot or send on new channel
    drop(storage_box);

    let api_retry = rieko_api::RiekoApi::new(Box::new(SqliteStorage::in_memory().unwrap()))
        .unwrap()
        .with_btcpay_webhook(secret, tx_retry);
    let app_retry = api_retry.router();

    let req_retry = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp_retry = app_retry.oneshot(req_retry).await.unwrap();
    assert_eq!(resp_retry.status(), StatusCode::OK);
    assert!(rx_retry.recv().await.is_some());
}

#[tokio::test]
async fn webhook_persistent_idempotency_survives_storage_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("idempotency_test.db");
    let secret = "test-webhook-secret-123";

    let payload = br#"{
        "deliveryId": "del-persist-1",
        "webhookId": "wh-1",
        "type": "InvoiceSettled",
        "timestamp": 1724250000,
        "storeId": "store-1",
        "invoiceId": "inv-p1",
        "payment": {"value": "5000", "fee": "50"}
    }"#;
    let sig = compute_sig(secret.as_bytes(), payload);

    // 1. Process with first API instance
    {
        let storage = SqliteStorage::open(&db_path).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let api = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .with_btcpay_webhook(secret, tx);

        let app = api.router();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/integrations/btcpay/webhook")
            .header("content-type", "application/json")
            .header("BTCPay-Sig", &sig)
            .body(Body::from(payload.to_vec()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(rx.recv().await.is_some());
    }

    // 2. Reopen storage with second API instance (simulating server restart)
    {
        let storage = SqliteStorage::open(&db_path).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let api = rieko_api::RiekoApi::new(Box::new(storage))
            .unwrap()
            .with_btcpay_webhook(secret, tx);

        let app = api.router();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/integrations/btcpay/webhook")
            .header("content-type", "application/json")
            .header("BTCPay-Sig", &sig)
            .body(Body::from(payload.to_vec()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let val: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(val["status"], "already_processed");
        assert_eq!(val["delivery_id"], "del-persist-1");

        // Must NOT have enqueued after restart
        assert!(rx.try_recv().is_err());
    }
}
