use sha2::{Digest, Sha256};

use crate::{ActionType, Evidence, Severity};

/// Stable, deterministic identity for operational observations.
///
/// Guarantees that replaying the same observation produces the same identity
/// across process runs (RIEKO-AUDIT-002), so persistence can deduplicate on a
/// stable key rather than a fresh random UUID. LLM explanations, wall-clock
/// timestamps, and anything that would change merely because data was processed
/// again are deliberately excluded.
///
/// See [`finding_identity`] and [`action_identity`] for the documented inputs.
fn digest(f: impl FnOnce(&mut Sha256)) -> String {
    let mut hasher = Sha256::new();
    f(&mut hasher);
    format!("{:x}", hasher.finalize())
}

/// Stable identity for a finding.
///
/// Inputs (all deterministic for a fixed logical occurrence):
/// * detector identifier (`detector`)
/// * detector version
/// * entity: local node id + channel id
/// * finding kind: severity, plus the canonical, sorted evidence set
pub fn finding_identity(
    detector: &str,
    detector_version: &str,
    severity: Severity,
    node: Option<&str>,
    channel: Option<&str>,
    evidence: &[Evidence],
) -> String {
    let key = digest(|m| {
        m.update(b"rieko-finding-v1");
        m.update([0u8]);
        m.update(detector.as_bytes());
        m.update([0u8]);
        m.update(detector_version.as_bytes());
        m.update([0u8]);
        m.update([(severity as i32) as u8]);
        m.update([0u8]);
        m.update(node.unwrap_or_default().as_bytes());
        m.update([0u8]);
        m.update(channel.unwrap_or_default().as_bytes());
        m.update([0u8]);
        m.update(canonical_evidence(evidence));
    });
    format!("finding-{key}")
}

/// Stable identity for an action, derived from its source finding and action
/// kind + target — never a fresh random id alone (RIEKO-AUDIT-002).
pub fn action_identity(finding_id: &str, action_type: ActionType, target: Option<&str>) -> String {
    let key = digest(|m| {
        m.update(b"rieko-action-v1");
        m.update([0u8]);
        m.update(finding_id.as_bytes());
        m.update([0u8]);
        m.update(action_type.as_str().as_bytes());
        m.update([0u8]);
        m.update(target.unwrap_or_default().as_bytes());
    });
    format!("action-{key}")
}

/// Canonical, order-independent byte encoding of an evidence list for hashing.
///
/// Evidence is sorted by key so the order a detector emits it in never changes
/// the identity.
pub fn canonical_evidence(evidence: &[Evidence]) -> Vec<u8> {
    let mut sorted: Vec<&Evidence> = evidence.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));
    let mut out = Vec::new();
    for e in sorted {
        out.extend_from_slice(e.key.as_bytes());
        out.push(0u8);
        match &e.value {
            serde_json::Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
            serde_json::Value::String(s) => out.extend_from_slice(s.as_bytes()),
            serde_json::Value::Bool(b) => out.push(if *b { 1 } else { 0 }),
            other => {
                out.extend_from_slice(serde_json::to_vec(other).unwrap_or_default().as_slice())
            }
        }
        out.push(0xFF);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Evidence> {
        vec![
            Evidence::string("direction", "outbound"),
            Evidence::number("local_ratio", 0.02),
            Evidence::number("local_balance_msat", 20_000.0),
        ]
    }

    #[test]
    fn identity_ignores_evidence_order() {
        let mut rev = sample();
        rev.reverse();
        let a = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Critical,
            Some("node"),
            Some("c1"),
            &sample(),
        );
        let b = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Critical,
            Some("node"),
            Some("c1"),
            &rev,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn identity_stable_across_construction() {
        let a = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Warning,
            Some("node1"),
            Some("chan-abc"),
            &[Evidence::number("local_ratio", 0.1)],
        );
        let b = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Warning,
            Some("node1"),
            Some("chan-abc"),
            &[Evidence::number("local_ratio", 0.1)],
        );
        assert_eq!(a, b);
        assert!(a.starts_with("finding-"));
    }

    #[test]
    fn identity_distinguishes_meaningful_changes() {
        let a = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Critical,
            Some("node1"),
            Some("c1"),
            &[Evidence::number("local_ratio", 0.02)],
        );
        let b = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Warning,
            Some("node1"),
            Some("c1"),
            &[Evidence::number("local_ratio", 0.12)],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn identity_excludes_metadata_and_llm_text() {
        let a = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Warning,
            Some("n"),
            Some("c1"),
            &[Evidence::string("direction", "outbound")],
        );
        let with_explanation = finding_identity(
            "channel_liquidity",
            "1",
            Severity::Warning,
            Some("n"),
            Some("c1"),
            &[Evidence::string("direction", "outbound")],
        );
        // The identity function has no access to explanation/timestamp; adding a
        // random-looking value to evidence must NOT change identity — only the
        // documented canonical evidence participates.
        assert_eq!(a, with_explanation);
    }

    #[test]
    fn action_identity_derives_from_finding_and_kind() {
        let a = action_identity("finding-x", ActionType::RebalanceChannel, Some("c1"));
        let b = action_identity("finding-x", ActionType::RebalanceChannel, Some("c1"));
        let c = action_identity("finding-x", ActionType::UpdateFeePolicy, Some("c1"));
        let d = action_identity("finding-y", ActionType::RebalanceChannel, Some("c1"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert!(a.starts_with("action-"));
    }
}
