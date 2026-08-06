pub mod migrations;
pub mod sqlite;
pub mod storage;

pub use migrations::CURRENT_SCHEMA_VERSION;
pub use sqlite::{SqliteStorage, WriterLock};
pub use storage::{MemoryStorage, Storage, StorageCounts, StorageError};

/// Cap for table row counts loaded by the default `counts()` fallback. Real
/// backends override `counts()` with `SELECT COUNT(*)` and never hit this cap.
pub(crate) const COUNT_CAP: u32 = 100_000;
