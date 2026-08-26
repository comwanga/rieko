//! Read-only Bitcoin Core RPC ingestion and normalization.

pub mod blocks;
pub mod rpc;

pub use blocks::{BlockSummary, BlockSummaryNormalizer, NormalizerError};
pub use rpc::{BitcoinCoreNormalizer, BitcoinCoreRpcClient, CoreRpcError};
