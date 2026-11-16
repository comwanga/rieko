use chrono::{TimeZone, Utc};
use rieko_domain::{InvoiceExpiredEvent, NodeEvent};
use rieko_storage::{MemoryStorage, SqliteStorage, Storage, CURRENT_SCHEMA_VERSION};

#[test]
fn time_window_history_is_exact_processed_only_and_has_no_count_cap() {
    for mut storage in [
        Box::new(MemoryStorage::new()) as Box<dyn Storage>,
        Box::new(SqliteStorage::in_memory().unwrap()),
    ] {
        let since = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        for i in 0..1005 {
            let id = format!("delivery-{i:04}");
            let event = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
                id: id.clone(),
                store_id: None,
                amount_msat: None,
                partially_paid: Some(false),
                timestamp: if i == 0 {
                    since - chrono::Duration::nanoseconds(1)
                } else {
                    since
                },
            });
            storage
                .enqueue_webhook_event(
                    &id,
                    None,
                    None,
                    &event,
                    since + chrono::Duration::seconds(i),
                )
                .unwrap();
            if i != 1004 {
                storage.mark_webhook_event_processed(&id, since).unwrap();
            }
        }
        let history = storage.processed_webhook_events_since(since).unwrap();
        assert_eq!(history.len(), 1003);
        assert_eq!(history.first().unwrap().delivery_id, "delivery-0001");
        assert_eq!(history.last().unwrap().delivery_id, "delivery-1003");
        assert!(history
            .iter()
            .all(|record| record.event.timestamp() >= since && record.processed_at.is_some()));
    }
}

#[test]
fn v15_event_json_decodes_missing_flags_as_unknown_and_roundtrips() {
    let legacy = [
        r#"{"type":"invoice_expired","id":"old-expired","timestamp":"2023-11-14T22:13:20Z"}"#,
        r#"{"type":"invoice_settled","id":"old-settled","amount_msat":1000,"fee_msat":0,"timestamp":"2023-11-14T22:13:20Z"}"#,
        r#"{"type":"invoice_payment_received","id":"old-received","amount_msat":1000,"fee_msat":0,"timestamp":"2023-11-14T22:13:20Z"}"#,
    ];
    let mut storage = SqliteStorage::in_memory().unwrap();
    for (i, json) in legacy.into_iter().enumerate() {
        let event: NodeEvent = serde_json::from_str(json).unwrap();
        match &event {
            NodeEvent::InvoiceExpired(e) => assert_eq!(e.partially_paid, None),
            NodeEvent::InvoiceSettled(e) => assert_eq!(e.manually_marked, None),
            NodeEvent::InvoicePaymentReceived(e) => assert_eq!(e.after_expiration, None),
            _ => panic!("unexpected legacy event"),
        }
        storage
            .enqueue_webhook_event(
                &format!("legacy-{i}"),
                None,
                None,
                &event,
                event.timestamp(),
            )
            .unwrap();
    }
    assert_eq!(storage.pending_webhook_events(10).unwrap().len(), 3);
}

fn event() -> NodeEvent {
    NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
        partially_paid: None,
        id: "invoice-1".into(),
        store_id: Some("store-1".into()),
        amount_msat: None,
        timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
    })
}

#[test]
fn normalized_webhook_event_survives_reopen_until_processed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("webhook-events.db");
    let accepted_at = Utc.timestamp_opt(1_700_000_001, 0).unwrap();

    {
        let mut storage = SqliteStorage::open(&path).unwrap();
        assert_eq!(storage.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        storage
            .enqueue_webhook_event(
                "delivery-1",
                Some("webhook-1"),
                Some("InvoiceExpired"),
                &event(),
                accepted_at,
            )
            .unwrap();
    }

    let mut reopened = SqliteStorage::open(&path).unwrap();
    let pending = reopened.pending_webhook_events(10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].delivery_id, "delivery-1");
    assert_eq!(pending[0].event, event());
    assert_eq!(pending[0].accepted_at, accepted_at);

    reopened.begin_transaction().unwrap();
    reopened
        .mark_webhook_event_processed("delivery-1", Utc::now())
        .unwrap();
    reopened.rollback_transaction().unwrap();
    assert_eq!(reopened.pending_webhook_events(10).unwrap().len(), 1);

    reopened.begin_transaction().unwrap();
    reopened
        .mark_webhook_event_processed("delivery-1", Utc::now())
        .unwrap();
    reopened.commit_transaction().unwrap();
    assert!(reopened.pending_webhook_events(10).unwrap().is_empty());
}

#[test]
fn duplicate_enqueue_preserves_the_original_normalized_event() {
    let mut storage = SqliteStorage::in_memory().unwrap();
    let accepted_at = Utc.timestamp_opt(1_700_000_001, 0).unwrap();
    storage
        .enqueue_webhook_event(
            "delivery-1",
            Some("webhook-1"),
            Some("InvoiceExpired"),
            &event(),
            accepted_at,
        )
        .unwrap();
    let replacement = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
        partially_paid: None,
        id: "different-invoice".into(),
        store_id: Some("store-1".into()),
        amount_msat: None,
        timestamp: accepted_at,
    });
    storage
        .enqueue_webhook_event(
            "delivery-1",
            Some("webhook-1"),
            Some("InvoiceExpired"),
            &replacement,
            Utc::now(),
        )
        .unwrap();

    let pending = storage.pending_webhook_events(10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event, event());
    assert_eq!(pending[0].accepted_at, accepted_at);
}

#[test]
fn processed_history_returns_the_latest_events_in_acceptance_order() {
    let mut storage = SqliteStorage::in_memory().unwrap();
    for index in 0..4 {
        let delivery_id = format!("delivery-{index}");
        let accepted_at = Utc.timestamp_opt(1_700_000_000 + index, 0).unwrap();
        let event = NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
            partially_paid: None,
            id: format!("invoice-{index}"),
            store_id: Some("store-1".into()),
            amount_msat: None,
            timestamp: accepted_at,
        });
        storage
            .enqueue_webhook_event(
                &delivery_id,
                Some("webhook-1"),
                Some("InvoiceExpired"),
                &event,
                accepted_at,
            )
            .unwrap();
        storage
            .mark_webhook_event_processed(&delivery_id, accepted_at)
            .unwrap();
    }

    let history = storage.recent_processed_webhook_events(2).unwrap();
    assert_eq!(
        history
            .iter()
            .map(|record| record.delivery_id.as_str())
            .collect::<Vec<_>>(),
        ["delivery-2", "delivery-3"]
    );
    assert!(history.iter().all(|record| record.processed_at.is_some()));
}
