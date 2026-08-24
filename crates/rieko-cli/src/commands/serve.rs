use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use rieko_api::RiekoApi;
use rieko_storage::SqliteStorage;
use tracing::{info, warn};

#[derive(Args, Debug)]
pub struct ServeArgs {
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    addr: SocketAddr,

    /// Directory of built frontend assets to serve at `/`.
    #[arg(long, value_name = "DIR")]
    static_dir: Option<PathBuf>,

    /// Explicitly allow binding to a non-loopback address. External exposure
    /// requires a bearer token via `--token-file` or `RIEKO_API_TOKEN`.
    #[arg(long)]
    allow_external: bool,

    /// File whose first line is the bearer token required for non-loopback
    /// requests (RIEKO-AUDIT-014). Overrides `RIEKO_API_TOKEN`.
    #[arg(long, value_name = "FILE")]
    token_file: Option<PathBuf>,

    /// Trust `X-Forwarded-For` / `X-Real-IP` headers set by an upstream
    /// reverse proxy (nginx, Caddy, Traefik). Do NOT set this flag if rieko
    /// is directly internet-accessible — any client could spoof the header.
    #[arg(long)]
    behind_proxy: bool,
}

pub fn run(args: ServeArgs) -> Result<()> {
    let db_path = args.db.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".rieko").join("rieko.db")
    });

    let mut token: Option<String> = load_token(args.token_file.as_deref())?;
    enforce_binding_policy(args.addr, args.allow_external, token.as_deref())?;

    let storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;
    let mut api = RiekoApi::new(Box::new(storage))?;
    if let Some(dir) = args.static_dir.as_ref() {
        api = api.with_static_dir(dir);
    }
    if let Some(token) = token.take() {
        api = api.with_auth(token)?;
    }

    let app = api.router();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(args.addr).await?;
        info!(
            addr = %args.addr,
            behind_proxy = args.behind_proxy,
            static_dir = args.static_dir.as_ref().map(|d| d.display().to_string()),
            "rieko api listening (read-only)"
        );
        if args.behind_proxy {
            info!("trusting X-Forwarded-For / X-Real-IP headers from upstream proxy");
        }
        axum::serve(listener, app)
            .await
            .context("axum serve failed")
    })
}

/// Refuse accidental network exposure (RIEKO-AUDIT-014): loopback binding is
/// always allowed (optionally authenticated); non-loopback binding requires an
/// explicit acknowledgement AND a bearer token. Never silently exposes the
/// API, never binds `0.0.0.0` without both gates.
fn enforce_binding_policy(
    addr: SocketAddr,
    allow_external: bool,
    token: Option<&str>,
) -> Result<()> {
    if addr.ip().is_loopback() {
        if token.is_some() {
            info!("rieko API will require a bearer token on loopback");
        }
        return Ok(());
    }
    if !allow_external {
        bail!(
            "refusing to bind {addr}: non-loopback address requires --allow-external \
             (external exposure also requires a bearer token)"
        );
    }
    if !token.is_some_and(|value| !value.trim().is_empty()) {
        bail!(
            "refusing to bind {addr}: external exposure requires a bearer token \
             (set --token-file or RIEKO_API_TOKEN)"
        );
    }
    warn!(
        addr = %addr,
        "WARNING: rieko API is exposed on a non-loopback address; all requests require a bearer token"
    );
    Ok(())
}

/// Load the bearer token from `--token-file` (first non-empty line) or the
/// `RIEKO_API_TOKEN` environment variable. Never logs the value.
fn load_token(file: Option<&std::path::Path>) -> Result<Option<String>> {
    if let Some(path) = file {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading token file {}", path.display()))?;
        let token = contents
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .context("token file is empty")?
            .to_string();
        return Ok(Some(token));
    }
    match std::env::var("RIEKO_API_TOKEN") {
        Ok(value) => {
            let token = value.trim();
            if token.is_empty() {
                bail!("RIEKO_API_TOKEN is empty");
            }
            Ok(Some(token.to_string()))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("RIEKO_API_TOKEN is not valid Unicode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_bind_succeeds_without_ack_or_token() {
        assert!(enforce_binding_policy(addr("127.0.0.1:8080"), false, None).is_ok());
        assert!(enforce_binding_policy(addr("[::1]:8080"), false, None).is_ok());
    }

    #[test]
    fn loopback_bind_accepts_optional_token() {
        assert!(enforce_binding_policy(addr("127.0.0.1:8080"), false, Some("t")).is_ok());
    }

    #[test]
    fn external_bind_without_ack_fails() {
        let err = enforce_binding_policy(addr("0.0.0.0:8080"), false, None).unwrap_err();
        assert!(err.to_string().contains("--allow-external"), "got {err}");
        let err = enforce_binding_policy(addr("192.168.1.5:8080"), false, Some("t")).unwrap_err();
        assert!(err.to_string().contains("--allow-external"), "got {err}");
    }

    #[test]
    fn external_bind_without_token_fails() {
        let err = enforce_binding_policy(addr("0.0.0.0:8080"), true, None).unwrap_err();
        assert!(err.to_string().contains("bearer token"), "got {err}");
        let err = enforce_binding_policy(addr("0.0.0.0:8080"), true, Some("  ")).unwrap_err();
        assert!(err.to_string().contains("bearer token"), "got {err}");
    }

    #[test]
    fn external_bind_with_ack_and_token_succeeds() {
        assert!(enforce_binding_policy(addr("0.0.0.0:8080"), true, Some("t")).is_ok());
    }

    #[test]
    fn token_loads_from_file_first_nonempty_line() {
        let dir = std::env::temp_dir().join(format!("rieko-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "\nsecret-token-value\n").unwrap();
        let token = load_token(Some(&path)).unwrap();
        assert_eq!(token.as_deref(), Some("secret-token-value"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_loads_from_env_and_file_overrides_env() {
        unsafe {
            std::env::set_var("RIEKO_API_TOKEN", "env-token");
        }
        assert_eq!(
            load_token(None).unwrap().as_deref(),
            Some("env-token"),
            "env fallback should be used when no file is given"
        );

        let dir = std::env::temp_dir().join(format!("rieko-token-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "file-token\n").unwrap();
        assert_eq!(
            load_token(Some(&path)).unwrap().as_deref(),
            Some("file-token"),
            "the --token-file must override the environment"
        );
        std::fs::remove_dir_all(&dir).ok();

        unsafe {
            std::env::set_var("RIEKO_API_TOKEN", " \t ");
        }
        assert!(
            load_token(None).is_err(),
            "blank environment token must fail"
        );

        unsafe {
            std::env::remove_var("RIEKO_API_TOKEN");
        }
    }
}
