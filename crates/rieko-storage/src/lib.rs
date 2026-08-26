pub mod migrations;
pub mod retention;
pub mod sqlite;
pub mod storage;

pub use migrations::CURRENT_SCHEMA_VERSION;
pub use retention::{PruneSummary, RetentionPolicy};
pub use sqlite::{SqliteStorage, WriterLock};
pub use storage::{
    MemoryStorage, SimulationCounts, SimulationEvent, SimulationRecord, Storage, StorageCounts,
    StorageError, WebhookEventRecord,
};

/// Cap for table row counts loaded by the default `counts()` fallback. Real
/// backends override `counts()` with `SELECT COUNT(*)` and never hit this cap.
pub(crate) const COUNT_CAP: u32 = 100_000;
