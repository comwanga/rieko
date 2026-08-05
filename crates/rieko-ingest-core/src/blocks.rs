use thiserror::Error;

/// Minimal Bitcoin Core block summary. Placeholder for mempool/chain event
/// normalization — expected to grow (fee estimation, reorg signals, channel
/// funding/close detection).
#[derive(Debug, Clone, PartialEq)]
pub struct BlockSummary {
    pub height: u32,
    pub hash: String,
    pub tx_count: u64,
}

#[derive(Debug, Error)]
pub enum NormalizerError {
    #[error("malformed block payload: {0}")]
    Malformed(String),
}

pub struct BlockSummaryNormalizer;

impl BlockSummaryNormalizer {
    /// Normalizes a block into a summary. Accepts either a plain JSON object
    /// or a string. Kept deliberately small for the placeholder stage.
    pub fn from_json(payload: &str) -> Result<BlockSummary, NormalizerError> {
        let value: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| NormalizerError::Malformed(e.to_string()))?;
        let height = value
            .get("height")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| NormalizerError::Malformed("missing height".into()))?;
        let hash = value
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NormalizerError::Malformed("missing hash".into()))?
            .to_string();
        let tx_count = value.get("tx_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(BlockSummary {
            height: height as u32,
            hash,
            tx_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_summary() {
        let b = BlockSummaryNormalizer::from_json(
            r#"{"height": 800000, "hash": "abc", "tx_count": 4000}"#,
        )
        .unwrap();
        assert_eq!(b.height, 800_000);
        assert_eq!(b.tx_count, 4000);
    }

    #[test]
    fn rejects_missing_height() {
        assert!(BlockSummaryNormalizer::from_json(r#"{"hash": "abc"}"#).is_err());
    }
}
