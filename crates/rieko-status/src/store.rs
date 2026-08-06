use crate::state::OperationalState;
use thiserror::Error;

/// Storage boundary for [`OperationalState`] (RIEKO-AUDIT-008). Kept narrow so
/// the status query is one constant-size row, never a scan of the data tables.
pub trait OperationalStateStore {
    /// Read the current operational state; `None` when nothing has been
    /// recorded yet.
    fn read_operational_state(&self) -> Result<Option<OperationalState>, OperationalStateError>;
    /// Upsert the current operational state.
    fn write_operational_state(
        &mut self,
        state: &OperationalState,
    ) -> Result<(), OperationalStateError>;
}

#[derive(Debug, Error)]
pub enum OperationalStateError {
    #[error("operational state storage failure: {0}")]
    Store(String),
}
