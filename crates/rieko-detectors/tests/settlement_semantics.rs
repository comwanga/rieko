use chrono::{Duration, TimeZone, Utc};
use rieko_detectors::{
    Detector, DetectorContext, SettlementReliabilityDetector, SettlementReliabilityThresholds,
};
use rieko_domain::{BitcoinNetwork, NodeEvent};
use rieko_graph::InMemoryGraph;
use rieko_ingest_btcpay::normalize_webhook_payload;

fn event(kind: &str, invoice: &str, flags: serde_json::Value) -> NodeEvent {
    let mut payload = serde_json::json!({
        "deliveryId": format!("{kind}-{invoice}"), "webhookId": "webhook",
        "storeId": "store", "invoiceId": invoice, "type": kind,
        "timestamp": Utc::now().timestamp()
    });
    payload
        .as_object_mut()
        .unwrap()
        .extend(flags.as_object().unwrap().clone());
    normalize_webhook_payload(&serde_json::to_vec(&payload).unwrap()).unwrap()
}

fn evaluate(events: &[NodeEvent]) -> Vec<rieko_findings::Finding> {
    SettlementReliabilityDetector::new("node").run(
        &InMemoryGraph::new(),
        &DetectorContext {
            node: Some("node"),
            events: Some(events),
            ..DetectorContext::no_context(BitcoinNetwork::Regtest)
        },
    )
}

#[test]
fn abandoned_checkouts_never_raise_a_settlement_finding() {
    let events: Vec<_> = (0..100)
        .map(|i| {
            event(
                "InvoiceExpired",
                &format!("invoice-{i}"),
                serde_json::json!({"partiallyPaid": false}),
            )
        })
        .collect();
    assert!(evaluate(&events).is_empty());
}

#[test]
fn payment_processing_and_settlement_count_one_invoice_once() {
    let events = vec![
        event(
            "InvoiceReceivedPayment",
            "paid",
            serde_json::json!({"afterExpiration":false}),
        ),
        event("InvoiceProcessing", "paid", serde_json::json!({})),
        event(
            "InvoiceSettled",
            "paid",
            serde_json::json!({"manuallyMarked":false}),
        ),
        event(
            "InvoiceExpired",
            "failed-1",
            serde_json::json!({"partiallyPaid":true}),
        ),
        event(
            "InvoiceExpired",
            "failed-2",
            serde_json::json!({"partiallyPaid":true}),
        ),
    ];
    let findings = evaluate(&events);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].evidence_value("settled_invoices"),
        Some(&serde_json::json!(1.0))
    );
    assert_eq!(
        findings[0].evidence_value("total_invoices"),
        Some(&serde_json::json!(3.0))
    );
}

#[test]
fn lifecycle_flags_define_failures_and_excluded_outcomes() {
    for (kind, flags, category) in [
        (
            "InvoiceExpired",
            serde_json::json!({"partiallyPaid":true}),
            "failed_invoices",
        ),
        (
            "InvoiceExpired",
            serde_json::json!({"partiallyPaid":false}),
            "abandoned_invoices",
        ),
        ("InvoiceExpired", serde_json::json!({}), "unknown_invoices"),
        (
            "InvoiceInvalid",
            serde_json::json!({"manuallyMarked":false}),
            "failed_invoices",
        ),
        (
            "InvoiceInvalid",
            serde_json::json!({"manuallyMarked":true}),
            "unknown_invoices",
        ),
        ("InvoiceInvalid", serde_json::json!({}), "unknown_invoices"),
        (
            "InvoiceSettled",
            serde_json::json!({"manuallyMarked":false}),
            "settled_invoices",
        ),
        (
            "InvoiceSettled",
            serde_json::json!({"manuallyMarked":true}),
            "unknown_invoices",
        ),
        ("InvoiceSettled", serde_json::json!({}), "unknown_invoices"),
        (
            "InvoiceProcessing",
            serde_json::json!({}),
            "pending_invoices",
        ),
        (
            "InvoiceReceivedPayment",
            serde_json::json!({"afterExpiration":true}),
            "failed_invoices",
        ),
        (
            "InvoiceReceivedPayment",
            serde_json::json!({"afterExpiration":false}),
            "pending_invoices",
        ),
        (
            "InvoiceReceivedPayment",
            serde_json::json!({}),
            "unknown_invoices",
        ),
    ] {
        let mut events = vec![
            event(
                "InvoiceExpired",
                "failure-a",
                serde_json::json!({"partiallyPaid":true}),
            ),
            event(
                "InvoiceExpired",
                "failure-b",
                serde_json::json!({"partiallyPaid":true}),
            ),
        ];
        events.push(event(kind, "target", flags));
        // Repeated delivery of the same event must not change any count.
        events.push(events.last().unwrap().clone());
        let findings = evaluate(&events);
        assert_eq!(findings.len(), 1, "{kind}");
        for key in [
            "failed_invoices",
            "settled_invoices",
            "abandoned_invoices",
            "unknown_invoices",
            "pending_invoices",
        ] {
            let expected = if key == "failed_invoices" { 2.0 } else { 0.0 }
                + if key == category { 1.0 } else { 0.0 };
            assert_eq!(
                findings[0].evidence_value(key),
                Some(&serde_json::json!(expected)),
                "{kind}: {key}"
            );
        }
        let eligible = if category == "failed_invoices" || category == "settled_invoices" {
            3.0
        } else {
            2.0
        };
        assert_eq!(
            findings[0].evidence_value("total_invoices"),
            Some(&serde_json::json!(eligible))
        );
    }
}

#[test]
fn out_of_order_lifecycle_and_multiple_failure_events_count_once() {
    let mut events = vec![
        event(
            "InvoiceExpired",
            "a",
            serde_json::json!({"partiallyPaid":true}),
        ),
        event(
            "InvoiceInvalid",
            "a",
            serde_json::json!({"manuallyMarked":false}),
        ),
        event(
            "InvoiceReceivedPayment",
            "a",
            serde_json::json!({"afterExpiration":true}),
        ),
        event(
            "InvoiceSettled",
            "a",
            serde_json::json!({"manuallyMarked":false}),
        ),
        event(
            "InvoiceExpired",
            "b",
            serde_json::json!({"partiallyPaid":true}),
        ),
    ];
    let detector = SettlementReliabilityDetector::new("node");
    let graph = InMemoryGraph::new();
    let ctx = DetectorContext {
        node: Some("node"),
        events: Some(&events),
        ..DetectorContext::no_context(BitcoinNetwork::Regtest)
    };
    let before = detector.run(&graph, &ctx);
    assert_eq!(
        before[0].evidence_value("failed_invoices"),
        Some(&serde_json::json!(2.0))
    );
    assert_eq!(
        before[0].evidence_value("settled_invoices"),
        Some(&serde_json::json!(0.0))
    );
    let evaluated_at = ctx.evaluated_at;
    events.reverse();
    let after = detector.run(
        &graph,
        &DetectorContext {
            evaluated_at,
            node: Some("node"),
            events: Some(&events),
            ..DetectorContext::no_context(BitcoinNetwork::Regtest)
        },
    );
    assert_eq!(
        before, after,
        "the evaluation clock and event facts completely determine output"
    );
}

#[test]
fn invoice_ids_in_different_stores_are_distinct() {
    let first = event(
        "InvoiceExpired",
        "same-id",
        serde_json::json!({"partiallyPaid":true}),
    );
    let mut second = first.clone();
    if let NodeEvent::InvoiceExpired(e) = &mut second {
        e.store_id = Some("other-store".into());
    }
    let findings = evaluate(&[first, second]);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].evidence_value("failed_invoices"),
        Some(&serde_json::json!(2.0))
    );
    assert_eq!(
        findings[0]
            .evidence_value("invoice_keys")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn five_failures_at_fifty_percent_are_warning_not_absolute_critical() {
    let mut events = Vec::new();
    for i in 0..5 {
        events.push(event(
            "InvoiceExpired",
            &format!("failed-{i}"),
            serde_json::json!({"partiallyPaid":true}),
        ));
        events.push(event(
            "InvoiceSettled",
            &format!("settled-{i}"),
            serde_json::json!({"manuallyMarked":false}),
        ));
    }
    let findings = evaluate(&events);
    assert_eq!(findings[0].severity, rieko_findings::Severity::Warning);
}

#[test]
fn window_boundaries_future_events_and_configured_duration_use_injected_time() {
    let now = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let mut events: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|id| {
            let mut event = event(
                "InvoiceExpired",
                id,
                serde_json::json!({"partiallyPaid":true}),
            );
            if let NodeEvent::InvoiceExpired(e) = &mut event {
                e.timestamp = now - Duration::minutes(60);
            }
            event
        })
        .collect();
    let graph = InMemoryGraph::new();
    let detector = SettlementReliabilityDetector::new("node");
    let ctx = |time| DetectorContext {
        evaluated_at: time,
        node: Some("node"),
        events: Some(events.as_slice()),
        ..DetectorContext::no_context(BitcoinNetwork::Regtest)
    };
    assert_eq!(
        detector.run(&graph, &ctx(now)).len(),
        1,
        "inclusive lower bound"
    );
    assert!(detector
        .run(&graph, &ctx(now + Duration::nanoseconds(1)))
        .is_empty());
    assert!(
        detector
            .run(&graph, &ctx(now - Duration::minutes(61)))
            .is_empty(),
        "future source timestamps are excluded"
    );
    let longer = SettlementReliabilityDetector::with_thresholds(
        "node",
        SettlementReliabilityThresholds {
            window: Duration::minutes(120),
            ..Default::default()
        },
    );
    assert_eq!(
        longer.run(&graph, &ctx(now + Duration::minutes(30))).len(),
        1
    );
    events.clear();
    let ctx = DetectorContext {
        evaluated_at: now,
        node: Some("node"),
        events: None,
        ..DetectorContext::no_context(BitcoinNetwork::Regtest)
    };
    assert!(!detector.evaluate(&graph, &ctx).unwrap().scope.complete);
}
