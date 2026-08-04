use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use rieko_api::RiekoApi;
use rieko_storage::SqliteStorage;
use tracing::info;

#[derive(Args, Debug)]
pub struct ServeArgs {
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    addr: SocketAddr,
}

pub fn run(args: ServeArgs) -> Result<()> {
    let db_path = args.db.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".rieko").join("rieko.db")
    });

    let storage = SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;
    let api = RiekoApi::new(Box::new(storage))?;

    let app = api.router();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(args.addr).await?;
        info!(addr = %args.addr, "rieko api listening (read-only)");
        axum::serve(listener, app).await.context("axum serve failed")
    })
}
