use anyhow::{bail, Context, Result};
use clap::Args;
use rieko_api::routes::{OperationTimes, Status};

use super::findings::{ApiArgs, ApiClient};

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    api: ApiArgs,
}

pub fn run(args: StatusArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building status client runtime")?;
    let client = ApiClient::new(&args.api)?;
    let status = runtime.block_on(client.fetch_status())?;
    print!("{}", render_status(&status, &args.api.api_url));
    if status.integrity != "ok" {
        bail!("refusing to report healthy: integrity check failed");
    }
    Ok(())
}

fn render_status(status: &Status, api_url: &str) -> String {
    let integrity = if status.integrity == "ok" {
        "ok"
    } else {
        "FAILED"
    };
    let mut lines = vec![
        format!("Rieko status (api: {api_url})"),
        format!("  schema version:  {}", status.schema_version),
        format!("  integrity:      {integrity}"),
        format!("  findings:        {}", status.counts.findings),
        format!("  recommendations: {}", status.counts.recommendations),
        format!("  simulations:     {}", status.counts.simulations),
        format!("  audit entries:   {}", status.counts.audit),
        format!("  channel snapshots: {}", status.counts.channel_snapshots),
        format!("  overall:         {}", status.overall),
    ];

    match status.source.as_deref() {
        Some(source) => {
            lines.push(format!("  source:          {source}"));
            lines.push(format!(
                "  source data at:  {}",
                text_or_never(status.source_data_at.as_deref())
            ));
            lines.push(format!(
                "  last ingestion:  {}",
                operation(status.last_ingestion.as_ref())
            ));
            lines.push(format!(
                "  last cycle:      {}",
                operation(status.last_cycle.as_ref())
            ));
            lines.push(format!("  llm:             {}", status.llm));
            lines.push(format!("  alert sink:      {}", status.alert_sink));
            lines.push(format!("  cleanup:         {}", status.cleanup));
            lines.push(format!(
                "  last cleanup:    {}",
                operation(status.last_cleanup.as_ref())
            ));
        }
        None => lines.push("  source:          (never ingested)".into()),
    }
    lines.join("\n") + "\n"
}

fn operation(times: Option<&OperationTimes>) -> String {
    match times {
        Some(times) => format!(
            "attempt {} / success {}",
            text_or_never(times.attempt.as_deref()),
            text_or_never(times.success.as_deref())
        ),
        None => "attempt never / success never".into(),
    }
}

fn text_or_never(value: Option<&str>) -> &str {
    value.unwrap_or("never")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::get;
    use rieko_api::RiekoApi;
    use rieko_storage::MemoryStorage;

    async fn start(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    fn client(api_url: String, token_file: Option<std::path::PathBuf>) -> ApiClient {
        ApiClient::new(&ApiArgs {
            api_url,
            token_file,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn retrieves_and_renders_typed_status_without_a_local_database() {
        let app = RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;

        let status = client(api_url.clone(), None).fetch_status().await.unwrap();
        let rendered = render_status(&status, &api_url);

        server.abort();
        assert_eq!(status.engine, "rieko");
        assert!(rendered.contains(&format!("Rieko status (api: {api_url})")));
        assert!(rendered.contains("  schema version:"));
        assert!(rendered.contains("  integrity:      ok"));
        assert!(rendered.contains("  findings:        0"));
        assert!(rendered.contains("  source:          (never ingested)"));
        assert!(!rendered.contains("db:"));
    }

    #[tokio::test]
    async fn reports_authentication_failure() {
        let app = RiekoApi::new(Box::new(MemoryStorage::new()))
            .unwrap()
            .with_auth("correct-token")
            .unwrap()
            .router();
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        std::fs::write(&token_file, "wrong-token\n").unwrap();

        let error = client(api_url, Some(token_file))
            .fetch_status()
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn reports_non_success_status_responses() {
        let app = axum::Router::new().route(
            "/status",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "agent unavailable") }),
        );
        let (api_url, server) = start(app).await;

        let error = client(api_url, None).fetch_status().await.unwrap_err();

        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));
        assert!(error.to_string().contains("agent unavailable"));
    }

    #[tokio::test]
    async fn rejects_malformed_typed_status_responses() {
        let app = axum::Router::new().route("/status", get(|| async { "not status json" }));
        let (api_url, server) = start(app).await;

        let error = client(api_url, None).fetch_status().await.unwrap_err();

        server.abort();
        assert!(error.to_string().contains("decoding typed status response"));
    }
}
