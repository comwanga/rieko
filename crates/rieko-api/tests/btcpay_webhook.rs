use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use rieko_domain::NodeEvent;
use rieko_storage::{MemoryStorage, SqliteStorage, Storage};
use sha2::Sha256;
use tokio::sync::mpsc;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

fn compute_sig(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn webhook_request(secret: Option<&str>, payload: &[u8]) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json");
    if let Some(secret) = secret {
        request = request.header("BTCPay-Sig", compute_sig(secret.as_bytes(), payload));
    }
    request.body(Body::from(payload.to_vec())).unwrap()
}

#[tokio::test]
async fn signed_unsupported_event_is_ignored_and_recorded_without_detector_input() {
    for storage in [
        Box::new(MemoryStorage::new()) as Box<dyn Storage + Send>,
        Box::new(SqliteStorage::in_memory().unwrap()),
    ] {
        let (tx, mut rx) = mpsc::channel(1);
        let api = rieko_api::RiekoApi::new(storage)
            .unwrap()
            .with_btcpay_webhook("secret", tx);
        let payload = br#"{"deliveryId":"ignored-1","webhookId":"webhook","type":"InvoiceCreated","timestamp":1724250000,"storeId":"store","invoiceId":"invoice"}"#;
        let response = api
            .router()
            .oneshot(webhook_request(Some("secret"), payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "ignored");
        assert_eq!(body["delivery_id"], "ignored-1");
        assert!(rx.try_recv().is_err());
        let mut storage = api.state.storage.lock().await;
        assert!(storage.is_webhook_delivery_processed("ignored-1").unwrap());
        assert!(storage.pending_webhook_events(10).unwrap().is_empty());
        assert!(storage.latest_findings(10).unwrap().is_empty());
    }
}

#[tokio::test]
async fn ignored_event_requires_authentication_and_a_valid_envelope() {
    let (tx, mut rx) = mpsc::channel(1);
    let api = rieko_api::RiekoApi::new(Box::new(SqliteStorage::in_memory().unwrap()))
        .unwrap()
        .with_btcpay_webhook("secret", tx);
    let app = api.router();
    let valid = serde_json::json!({"deliveryId":"ignored-safe", "webhookId":"webhook",
        "type":"InvoiceCreated", "timestamp":1724250000, "storeId":"store", "invoiceId":"invoice"});
    let valid_bytes = serde_json::to_vec(&valid).unwrap();
    for secret in [None, Some("wrong-secret")] {
        let response = app
            .clone()
            .oneshot(webhook_request(secret, &valid_bytes))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let mut malformed = vec![b"{".to_vec()];
    for field in ["deliveryId", "webhookId", "type", "timestamp", "storeId"] {
        let mut payload = valid.clone();
        payload.as_object_mut().unwrap().remove(field);
        malformed.push(serde_json::to_vec(&payload).unwrap());
        if field != "timestamp" {
            payload[field] = " ".into();
            malformed.push(serde_json::to_vec(&payload).unwrap());
        }
    }
    let mut bad_telemetry = valid.clone();
    bad_telemetry["type"] = "InvoiceSettled".into();
    bad_telemetry.as_object_mut().unwrap().remove("invoiceId");
    malformed.push(serde_json::to_vec(&bad_telemetry).unwrap());
    for payload in malformed {
        let response = app
            .clone()
            .oneshot(webhook_request(Some("secret"), &payload))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&payload)
        );
    }
    assert!(!api
        .state
        .storage
        .lock()
        .await
        .is_webhook_delivery_processed("ignored-safe")
        .unwrap());
    let response = app
        .oneshot(webhook_request(Some("secret"), &valid_bytes))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Rejected requests must not consume delivery identity"
    );
    assert!(rx.try_recv().is_err());
    assert!(api
        .state
        .storage
        .lock()
        .await
        .pending_webhook_events(10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn ignored_delivery_and_canonical_redelivery_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ignored-restart.db");
    let original = br#"{"deliveryId":"ignored-original","webhookId":"webhook","type":"PayoutCreated","timestamp":1724250000,"storeId":"store","payoutId":"payout"}"#;
    {
        let (tx, mut rx) = mpsc::channel(1);
        let api = rieko_api::RiekoApi::new(Box::new(SqliteStorage::open(&path).unwrap()))
            .unwrap()
            .with_btcpay_webhook("secret", tx);
        let response = api
            .router()
            .oneshot(webhook_request(Some("secret"), original))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["status"], "ignored");
        assert!(rx.try_recv().is_err());
    }
    let (tx, mut rx) = mpsc::channel(1);
    let api = rieko_api::RiekoApi::new(Box::new(SqliteStorage::open(&path).unwrap()))
        .unwrap()
        .with_btcpay_webhook("secret", tx);
    let app = api.router();
    let redelivery = br#"{"deliveryId":"ignored-retry","originalDeliveryId":"ignored-original","isRedelivery":true,"webhookId":"webhook","type":"PayoutCreated","timestamp":1724250100,"storeId":"store","payoutId":"payout"}"#;
    for payload in [original.as_slice(), redelivery.as_slice()] {
        let response = app
            .clone()
            .oneshot(webhook_request(Some("secret"), payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["status"], "already_processed");
        assert_eq!(value["delivery_id"], "ignored-original");
    }
    assert!(rx.try_recv().is_err());
    let mut storage = api.state.storage.lock().await;
    assert!(storage
        .is_webhook_delivery_processed("ignored-original")
        .unwrap());
    assert!(!storage
        .is_webhook_delivery_processed("ignored-retry")
        .unwrap());
    assert!(storage.pending_webhook_events(10).unwrap().is_empty());
    assert!(storage
        .recent_processed_webhook_events(10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn concurrent_ignored_deliveries_never_enqueue_telemetry() {
    let (tx, mut rx) = mpsc::channel(1);
    let api = rieko_api::RiekoApi::new(Box::new(SqliteStorage::in_memory().unwrap()))
        .unwrap()
        .with_btcpay_webhook("secret", tx);
    let app = api.router();
    let payload = br#"{"deliveryId":"ignored-concurrent","webhookId":"webhook","type":"InvoiceCreated","timestamp":1724250000,"storeId":"store","invoiceId":"invoice"}"#;
    let (first, second) = tokio::join!(
        app.clone()
            .oneshot(webhook_request(Some("secret"), payload)),
        app.oneshot(webhook_request(Some("secret"), payload))
    );
    for response in [first.unwrap(), second.unwrap()] {
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert!(rx.try_recv().is_err());
    let mut storage = api.state.storage.lock().await;
    assert!(storage
        .is_webhook_delivery_processed("ignored-concurrent")
        .unwrap());
    assert!(storage.pending_webhook_events(10).unwrap().is_empty());
}

#[tokio::test]
async fn ignored_delivery_is_not_acknowledged_when_persistence_fails_and_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ignored-write-failure.db");
    let (tx, mut rx) = mpsc::channel(1);
    let api = rieko_api::RiekoApi::new(Box::new(SqliteStorage::open(&path).unwrap()))
        .unwrap()
        .with_btcpay_webhook("secret", tx);
    let app = api.router();
    let mut blocker = SqliteStorage::open(&path).unwrap();
    blocker.begin_transaction().unwrap();
    let payload = br#"{"deliveryId":"ignored-recover","webhookId":"webhook","type":"InvoiceCreated","timestamp":1724250000,"storeId":"store","invoiceId":"invoice"}"#;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        app.clone()
            .oneshot(webhook_request(Some("secret"), payload)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["error"]["code"], "persistence_failed");
    assert!(!api
        .state
        .storage
        .lock()
        .await
        .is_webhook_delivery_processed("ignored-recover")
        .unwrap());
    blocker.rollback_transaction().unwrap();
    let response = app
        .oneshot(webhook_request(Some("secret"), payload))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["status"], "ignored");
    assert!(rx.try_recv().is_err());
    let mut storage = api.state.storage.lock().await;
    assert!(storage
        .is_webhook_delivery_processed("ignored-recover")
        .unwrap());
    assert!(storage.pending_webhook_events(10).unwrap().is_empty());
}

#[tokio::test]
async fn webhook_fails_closed_when_integration_is_not_configured() {
    let storage = SqliteStorage::in_memory().unwrap();
    let app = rieko_api::RiekoApi::new(Box::new(storage))
        .unwrap()
        .router();
    let payload = br#"{"deliveryId":"d","webhookId":"w","type":"InvoiceExpired","timestamp":1,"storeId":"s","invoiceId":"i"}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"]["code"], "integration_not_configured");
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
async fn webhook_queue_saturation_preserves_the_durable_event() {
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
        partially_paid: None,
        id: "dummy".into(),
        store_id: None,
        amount_msat: None,
        timestamp: chrono::Utc::now(),
    });
    tx.send(dummy_event).await.unwrap();

    // The wake-up channel is full, but durable storage remains authoritative.
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
    assert_eq!(resp.status(), StatusCode::OK);
    let val: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(val["status"], "accepted");

    let pending = api
        .state
        .storage
        .lock()
        .await
        .pending_webhook_events(10)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].delivery_id, "del-sat-1");
    assert!(matches!(pending[0].event, NodeEvent::InvoiceSettled(_)));

    // A BTCPay retry is idempotent even while agent processing is pending.
    let req_retry = Request::builder()
        .method("POST")
        .uri("/api/v1/integrations/btcpay/webhook")
        .header("content-type", "application/json")
        .header("BTCPay-Sig", &sig)
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp_retry = app.oneshot(req_retry).await.unwrap();
    assert_eq!(resp_retry.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&resp_retry.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(value["status"], "already_processed");
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
