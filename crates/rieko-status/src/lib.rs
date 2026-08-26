//! Meaningful self-observability (RIEKO-AUDIT-008).
//!
//! A small, constant-size operational state record is persisted alongside the
//! data and used by both the API `/status` and the CLI `status` command so
//! status reflects actual operation without scanning the database.

pub mod health;
pub mod state;
pub mod store;

pub use health::{assess, HealthPolicy};
pub use state::{
    BitcoinCoreState, ComponentState, LightningState, OperationalState, OverallState, SourceState,
};
pub use store::{OperationalStateError, OperationalStateStore};
