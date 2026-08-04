use rieko_findings::Finding;

/// Builds the prompt that asks the LLM to explain a structured finding in
/// plain language. Deterministic template, no finding generation.
pub fn build_explanation_prompt(finding: &Finding, context: Option<&str>) -> String {
    let mut evidence_lines = String::new();
    for e in &finding.evidence {
        evidence_lines.push_str(&format!("- {}: {}\n", e.key, e.value));
    }

    let context = context
        .map(|c| format!("Context: {c}\n"))
        .unwrap_or_default();

    format!(
        "A detector named `{detector}` raised a {severity:?} finding.\n\
         {context}\
         Evidence:\n{evidence}\
         Write a 2-3 sentence explanation for a node operator. Start with what \
         is abnormal, then the likely operational impact, then the recommended \
         next step. Cite the evidence numbers.",
        detector = finding.detector,
        severity = finding.severity,
        evidence = evidence_lines,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rieko_findings::{Evidence, Severity};

    #[test]
    fn prompt_is_deterministic() {
        let f = Finding {
            id: "f".into(),
            detector: "channel_liquidity".into(),
            severity: Severity::Critical,
            node: Some("n".into()),
            channel: Some("c".into()),
            evidence: vec![Evidence::number("local_ratio", 0.5)],
            explanation: None,
            timestamp: chrono::Utc::now(),
        };
        let a = build_explanation_prompt(&f, Some("ctx"));
        let b = build_explanation_prompt(&f, Some("ctx"));
        assert_eq!(a, b);
    }
}
