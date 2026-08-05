use std::sync::{Arc, Mutex};

use rieko_storage::Storage;
use thiserror::Error;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum RiekoApiError {
    #[error("storage error: {0}")]
    Storage(#[from] rieko_storage::StorageError),
}

/// Shared state: durable storage behind a mutex. The engine is write-once at
/// v1 (CLI scan pipeline); the API is read-only (D3: read-only by default).
pub struct AppState {
    pub storage: Arc<Mutex<Box<dyn Storage + Send>>>,
}

#[derive(Clone)]
pub struct RiekoApi {
    pub state: Arc<AppState>,
}

impl RiekoApi {
    pub fn new(storage: Box<dyn Storage + Send>) -> Result<Self, RiekoApiError> {
        Ok(Self {
            state: Arc::new(AppState {
                storage: Arc::new(Mutex::new(storage)),
            }),
        })
    }

    pub fn router(&self) -> axum::Router {
        self.router_with_state(self.clone())
    }

    fn router_with_state(&self, state: RiekoApi) -> axum::Router {
        axum::Router::new()
            .route("/status", axum::routing::get(crate::routes::status))
            .route("/findings", axum::routing::get(crate::routes::findings))
            .route(
                "/findings/channel/:channel_id",
                axum::routing::get(crate::routes::findings_for_channel),
            )
            .route("/recommendations", axum::routing::get(crate::routes::recommendations))
            .route("/simulations", axum::routing::get(crate::routes::recent_simulations))
            .route("/audit", axum::routing::get(crate::routes::audit))
            .route(
                "/snapshots/channel/:channel_id",
                axum::routing::get(crate::routes::channel_snapshots),
            )
            .with_state(state)
    }
}
