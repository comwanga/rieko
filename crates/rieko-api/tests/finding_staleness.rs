//! `observation_stale` on the finding routes, read back from findings that
//! were persisted with an aged `last_seen_at`. The flag is computed when the
//! finding is read; these tests also assert that reading stores nothing.

use std::time::Duration as StdDuration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use rieko_api::RiekoApi;
use rieko_findings::{
    Evidence, Finding, FindingCycleScope, FindingLifecycle, FindingLifecycleFilter, Severity,
    FINDING_SCHEMA_VERSION,
};
use rieko_storage::{SqliteStorage, Storage};
use serde_json::Value;
use tower::ServiceExt;

const CHANNEL: &str = "channel-1";

fn finding(id: &str, detector: &str, last_seen_at: DateTime<Utc>) -> Finding {
    Finding {
        id: id.into(),
        detector: detector.into(),
        detector_version: "1".into(),
        schema_version: FINDING_SCHEMA_VERSION,
        severity: Severity::Warning,
        node: Some("node-test".into()),
        channel: Some(CHANNEL.into()),
        evidence: vec![Evidence::number("local_ratio", 0.02)],
        provenance: None,
        explanation: Some("Persisted explanation".into()),
        timestamp: last_seen_at,
        first_seen_at: last_seen_at,
        last_seen_at,
        lifecycle: FindingLifecycle::Active,
    }
}

/// Persists one finding per age, each under its own detector so a finding can
/// be resolved without touching the others.
fn storage_with(aged: &[(&str, Duration)]) -> SqliteStorage {
    let now = Utc::now();
    let mut storage = SqliteStorage::in_memory().unwrap();
    for (id, age) in aged {
        storage
            .save_finding(&finding(id, &format!("detector-{id}"), now - *age))
            .unwrap();
    }
    storage
}

/// Resolves `id` the way the runtime does: three complete cycles without it.
fn resolve(storage: &mut SqliteStorage, id: &str) {
    let scope = FindingCycleScope {
        detector: format!("detector-{id}"),
        network: None,
        node: Some("node-test".into()),
        complete: true,
    };
    for _ in 0..3 {
        storage.apply_finding_cycle(&scope, &[]).unwrap();
    }
    assert_eq!(
        storage.finding_by_id(id).unwrap().unwrap().lifecycle,
        FindingLifecycle::Resolved
    );
}

async fn get_json(app: &axum::Router, uri: &str) -> Value {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

fn stale_by_id(list: &Value) -> Vec<(String, bool)> {
    let mut flags: Vec<(String, bool)> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            (
                finding["id"].as_str().unwrap().to_string(),
                finding["observation_stale"]
                    .as_bool()
                    .expect("observation_stale is always a boolean"),
            )
        })
        .collect();
    flags.sort();
    flags
}

fn flags(pairs: &[(&str, bool)]) -> Vec<(String, bool)> {
    pairs
        .iter()
        .map(|(id, stale)| (id.to_string(), *stale))
        .collect()
}

#[tokio::test]
async fn every_finding_route_marks_only_aged_active_findings_as_stale() {
    let mut storage = storage_with(&[
        ("fresh", Duration::minutes(5)),
        ("just-inside", Duration::minutes(119)),
        ("aged", Duration::hours(3)),
        ("resolved-aged", Duration::hours(30)),
    ]);
    resolve(&mut storage, "resolved-aged");
    let stored_before = storage
        .latest_findings_by_lifecycle(10, FindingLifecycleFilter::All)
        .unwrap();
    // No observation interval is configured: the one-shot case, where the
    // freshness minimum of two hours applies.
    let api = RiekoApi::new(Box::new(storage)).unwrap();
    let app = api.router();

    assert_eq!(
        stale_by_id(&get_json(&app, "/findings").await),
        flags(&[("aged", true), ("fresh", false), ("just-inside", false)])
    );
    assert_eq!(
        stale_by_id(&get_json(&app, "/findings?lifecycle=resolved").await),
        flags(&[("resolved-aged", false)])
    );
    assert_eq!(
        stale_by_id(&get_json(&app, "/findings?lifecycle=all").await),
        flags(&[
            ("aged", true),
            ("fresh", false),
            ("just-inside", false),
            ("resolved-aged", false)
        ])
    );
    assert_eq!(
        stale_by_id(&get_json(&app, &format!("/findings/channel/{CHANNEL}?lifecycle=all")).await),
        flags(&[
            ("aged", true),
            ("fresh", false),
            ("just-inside", false),
            ("resolved-aged", false)
        ])
    );
    for (id, stale) in [
        ("fresh", false),
        ("just-inside", false),
        ("aged", true),
        ("resolved-aged", false),
    ] {
        let detail = get_json(&app, &format!("/findings/{id}")).await;
        assert_eq!(detail["observation_stale"], stale, "{id}");
    }

    // Reading computes the flag; it changes nothing that is stored.
    let stored_after = api
        .state
        .storage
        .lock()
        .await
        .latest_findings_by_lifecycle(10, FindingLifecycleFilter::All)
        .unwrap();
    assert_eq!(stored_after, stored_before);
}

#[tokio::test]
async fn the_flag_is_added_without_changing_any_stored_field() {
    let mut storage = storage_with(&[("aged", Duration::hours(3))]);
    let stored = storage.finding_by_id("aged").unwrap().unwrap();
    let app = RiekoApi::new(Box::new(storage)).unwrap().router();

    let mut expected = serde_json::to_value(&stored).unwrap();
    expected["observation_stale"] = Value::Bool(true);
    assert_eq!(get_json(&app, "/findings/aged").await, expected);
    assert_eq!(
        get_json(&app, "/findings").await,
        Value::Array(vec![expected])
    );
}

#[tokio::test]
async fn a_long_observation_interval_extends_the_threshold_to_two_intervals() {
    let storage = storage_with(&[
        ("between-polls", Duration::hours(30)),
        ("just-inside", Duration::hours(47)),
        ("missed-two-polls", Duration::hours(49)),
    ]);
    // The longest interval the agent accepts: one observation a day.
    let app = RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_observation_interval(StdDuration::from_secs(86_400))
        .router();

    assert_eq!(
        stale_by_id(&get_json(&app, "/findings").await),
        flags(&[
            ("between-polls", false),
            ("just-inside", false),
            ("missed-two-polls", true)
        ])
    );
}

#[tokio::test]
async fn a_short_observation_interval_keeps_the_freshness_minimum() {
    let storage = storage_with(&[
        ("inside-minimum", Duration::minutes(119)),
        ("past-minimum", Duration::minutes(121)),
    ]);
    let app = RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_observation_interval(StdDuration::from_secs(60))
        .router();

    assert_eq!(
        stale_by_id(&get_json(&app, "/findings").await),
        flags(&[("inside-minimum", false), ("past-minimum", true)])
    );
}

#[tokio::test]
async fn the_configured_threshold_survives_the_other_api_builders() {
    let storage = storage_with(&[("between-polls", Duration::hours(30))]);
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    let api = RiekoApi::new(Box::new(storage))
        .unwrap()
        .with_observation_interval(StdDuration::from_secs(86_400))
        .with_auth("test-token")
        .unwrap()
        .with_btcpay_webhook("secret", sender);

    assert_eq!(api.state.finding_stale_after, Duration::hours(48));
}
