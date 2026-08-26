use chrono::{TimeZone, Utc};
use rieko_domain::{InvoiceExpiredEvent, NodeEvent};
use rieko_storage::{SqliteStorage, Storage, CURRENT_SCHEMA_VERSION};

fn event() -> NodeEvent {
    NodeEvent::InvoiceExpired(InvoiceExpiredEvent {
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
