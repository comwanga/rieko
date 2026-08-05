use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rieko_storage::Storage;
use thiserror::Error;
use tower_http::services::ServeDir;

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
    /// Directory of built frontend assets to serve at `/`. None disables
    /// static serving (the API-only mode).
    pub static_dir: Option<Arc<PathBuf>>,
}

impl RiekoApi {
    pub fn new(storage: Box<dyn Storage + Send>) -> Result<Self, RiekoApiError> {
        Ok(Self {
            state: Arc::new(AppState {
                storage: Arc::new(Mutex::new(storage)),
            }),
            static_dir: None,
        })
    }

    /// Serve the built UI from `dir` in addition to the JSON API.
    pub fn with_static_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.static_dir = Some(Arc::new(dir.into()));
        self
    }

    pub fn router(&self) -> axum::Router {
        let mut router = self.router_with_state(self.clone());
        if let Some(dir) = &self.static_dir {
            let dir = dir.as_path();
            router = router
                .nest_service("/assets", ServeDir::new(dir.join("assets")))
                .fallback_service(ServeDir::new(dir).append_index_html_on_directories(true));
        }
        router
    }

    fn router_with_state(&self, state: RiekoApi) -> axum::Router {
        let router = axum::Router::new()
            .route("/status", axum::routing::get(crate::routes::status))
            .route("/findings", axum::routing::get(crate::routes::findings))
            .route(
                "/findings/channel/:channel_id",
                axum::routing::get(crate::routes::findings_for_channel),
            )
            .route(
                "/recommendations",
                axum::routing::get(crate::routes::recommendations),
            )
            .route("/audit", axum::routing::get(crate::routes::audit))
            .route(
                "/snapshots",
                axum::routing::get(crate::routes::all_snapshots),
            )
            .route(
                "/snapshots/channel/:channel_id",
                axum::routing::get(crate::routes::channel_snapshots),
            );
        #[cfg(feature = "future")]
        let router = router.route(
            "/simulations",
            axum::routing::get(crate::routes::recent_simulations),
        );
        router.with_state(state)
    }
}
