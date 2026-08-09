use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use rieko_storage::Storage;
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum request body accepted by the API. The v1 surface is read-only, so
/// requests are tiny; a low ceiling rejects stray large uploads early.
const MAX_BODY_BYTES: usize = 1 << 20;
/// Upper bound for any single request, protecting the loopback server from a
/// stalled client holding a connection forever (RIEKO-AUDIT-014).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum RiekoApiError {
    #[error("storage error: {0}")]
    Storage(#[from] rieko_storage::StorageError),
    #[error("bearer token cannot be empty")]
    InvalidAuthToken,
}

/// Shared state: durable storage behind a mutex. The engine is write-once at
/// v1 (CLI scan pipeline); the API is read-only (D3: read-only by default).
pub struct AppState {
    pub storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    /// Static bearer token required on non-loopback exposure. `None` means
    /// unauthenticated (only acceptable for loopback use).
    pub auth_token: Option<String>,
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
                auth_token: None,
            }),
            static_dir: None,
        })
    }

    /// Serve the built UI from `dir` in addition to the JSON API.
    pub fn with_static_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.static_dir = Some(Arc::new(dir.into()));
        self
    }

    /// Require `Authorization: Bearer <token>` on every JSON route. The caller
    /// decides when this is mandatory (non-loopback binding); it may also be
    /// set for loopback use. Comparison is constant-time (RIEKO-AUDIT-014).
    pub fn with_auth(mut self, token: impl Into<String>) -> Result<Self, RiekoApiError> {
        let token = token.into().trim().to_string();
        if token.is_empty() {
            return Err(RiekoApiError::InvalidAuthToken);
        }
        self.state = Arc::new(AppState {
            storage: self.state.storage.clone(),
            auth_token: Some(token),
        });
        Ok(self)
    }

    pub fn router(&self) -> axum::Router {
        let mut router = self.router_with_state(self.clone());

        if let Some(dir) = &self.static_dir {
            // Dev mode: serve a filesystem build (the optional --static-dir).
            let dir = dir.as_path();
            router = router
                .nest_service(
                    "/assets",
                    tower_http::services::ServeDir::new(dir.join("assets")),
                )
                .fallback_service(
                    tower_http::services::ServeDir::new(dir).append_index_html_on_directories(true),
                );
        } else if crate::ui::embedded::available() {
            // Single binary: the frontend was embedded at compile time
            // (WP5.1 / RIEKO-AUDIT-009).
            #[cfg(rieko_ui_embedded)]
            {
                router = router
                    .route(
                        "/assets/*path",
                        axum::routing::get(crate::ui::embedded::asset),
                    )
                    .route("/", axum::routing::get(crate::ui::embedded::index))
                    // Embedding extends the router after `with_state()` which
                    // freezes the middleware layers; re-apply security headers so
                    // asset responses also receive the required headers.
                    .layer(axum::middleware::from_fn(security_headers));
            }
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
        #[cfg(feature = "simulate")]
        let router = router
            .route(
                "/simulations",
                axum::routing::get(crate::routes::recent_simulations),
            )
            .route(
                "/simulations/v2",
                axum::routing::get(crate::routes::recent_simulations_v2),
            )
            .route(
                "/simulations/:simulation_id",
                axum::routing::get(crate::routes::simulation_v2_by_id),
            );
        router
            // Bearer auth guards the JSON surface; static assets are inert.
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_auth,
            ))
            // Security headers apply to every response, API and static alike.
            .layer(axum::middleware::from_fn(security_headers))
            .layer(axum::middleware::from_fn(enforce_body_limit))
            .layer(axum::middleware::from_fn(request_timeout))
            .with_state(state)
    }
}

/// Blocking SQLite work must never run on the Tokio executor, or the runtime
/// stalls behind the `std::sync::Mutex`. Run the read on the blocking pool and
/// return the bounded result (RIEKO-AUDIT-014).
pub(crate) async fn block_read<T: Send + 'static>(
    storage: Arc<Mutex<Box<dyn Storage + Send>>>,
    f: impl FnOnce(&mut (dyn Storage + Send)) -> Result<T, String> + Send + 'static,
) -> Result<T, (StatusCode, String)> {
    match tokio::task::spawn_blocking(move || {
        let mut guard = storage
            .lock()
            .map_err(|_| "storage lock poisoned".to_string())?;
        f(&mut **guard)
    })
    .await
    {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("blocking storage task failed: {e}"),
        )),
    }
}

/// Constant-time comparison of a supplied bearer token against the configured
/// secret. Both values are fixed-length byte strings here; no user accounts.
fn token_matches(expected: &str, provided: &[u8]) -> bool {
    !expected.trim().is_empty() && bool::from(expected.as_bytes().ct_eq(provided))
}

async fn require_auth(
    State(api): State<RiekoApi>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    if let Some(token) = api.state.auth_token.as_deref() {
        let provided = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| v.trim().as_bytes())
            .unwrap_or_default();
        if !token_matches(token, provided) {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
        }
    }
    Ok(next.run(req).await)
}

/// Bounded wall-clock time for every request; a stalled client or backend can
/// never tie up the server forever (RIEKO-AUDIT-014).
async fn request_timeout(req: Request, next: Next) -> Result<Response, (StatusCode, String)> {
    tokio::time::timeout(REQUEST_TIMEOUT, next.run(req))
        .await
        .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "request timed out".into()))
}

/// Reject requests whose declared size exceeds the ceiling before they reach
/// a handler. Checked eagerly on `Content-Length` because the read-only v1
/// routes never extract a body, so a streaming limit would never fire
/// (RIEKO-AUDIT-014).
async fn enforce_body_limit(req: Request, next: Next) -> Result<Response, (StatusCode, String)> {
    let too_large = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_BODY_BYTES);
    if too_large {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large".into(),
        ));
    }
    Ok(next.run(req).await)
}

async fn security_headers(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/assets");
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    // Sensitive API data must not be cached by the browser or a shared proxy;
    // static assets keep their own cache headers.
    if !is_api {
        headers.insert(
            CACHE_CONTROL,
            header::HeaderValue::from_static("no-store, max-age=0"),
        );
    }
    // Same-origin only: no permissive CORS header is emitted, so cross-origin
    // scripts cannot read responses. This is not a complete localhost defence
    // on its own (simple GETs can still be *sent*), which is why non-loopback
    // binding additionally requires a token (RIEKO-AUDIT-014).
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    headers.insert(
        REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
             script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    resp
}
