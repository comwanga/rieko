//! Bitcoin Core ingestion. v1 slice ships the LND path (ADR D8); Core
//! normalization (mempool/block events, chain reorg signals) is added once
//! the vertical slice is proven. This crate exists to fix the workspace shape.

pub mod blocks;

pub use blocks::{BlockSummary, BlockSummaryNormalizer, NormalizerError};
