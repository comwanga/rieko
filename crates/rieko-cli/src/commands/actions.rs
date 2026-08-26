use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use rieko_execution::{transition, ExecutionError, SYSTEM_ACTOR};
use rieko_findings::{Action, ActionStage, AuditEntry};
use rieko_storage::{SqliteStorage, Storage};
use tracing::info;

use super::findings::{ApiArgs, ApiClient};

/// Approve or execute recommended actions (D7). Approvals are human-only: the
/// system never self-approves its own recommendations.
#[derive(Args, Debug)]
pub struct ActionsArgs {
    #[command(subcommand)]
    command: ActionCommand,

    /// Path to a JSON fixture matching the LND `/v1/channels` response.
    #[arg(long, value_name = "FILE")]
    fixture: Option<PathBuf>,

    /// LND REST base URL, e.g. `https://localhost:8080`.
    #[arg(long, value_name = "URL", conflicts_with = "fixture")]
    lnd_rest: Option<String>,

    /// Path to a read-only macaroon file for the REST connection.
    #[arg(long, value_name = "FILE")]
    macaroon: Option<PathBuf>,

    /// Path to LND's TLS certificate (tls.cert), trusted for this client only.
    #[arg(long, value_name = "FILE")]
    tls_cert: Option<PathBuf>,

    /// Local node id (pubkey). Defaults to `local-node`.
    #[arg(long, default_value = "local-node")]
    node: String,
}

#[derive(Args, Debug)]
struct ActionStorageArgs {
    /// Durable database path. Defaults to `~/.rieko/rieko.db`.
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum ActionCommand {
    /// List recent actions and their stage (recommended/simulated/approved/...).
    List {
        #[command(flatten)]
        api: ApiArgs,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Approve an action for execution. Requires the `--actor` of a human.
    Approve {
        action_id: String,
        /// Human actor id approving the action. Cannot be `system`.
        #[arg(long)]
        actor: String,
        #[command(flatten)]
        storage: ActionStorageArgs,
    },
    /// Reject an action so it is never executed.
    Reject {
        action_id: String,
        /// Human actor id rejecting the action.
        #[arg(long)]
        actor: String,
        #[command(flatten)]
        storage: ActionStorageArgs,
    },
    /// Reserved for v3; currently refused by the execution interlock.
    Execute {
        action_id: String,
        /// Human actor id confirming the execution.
        #[arg(long)]
        actor: String,
    },
}

pub fn run(args: ActionsArgs) -> Result<()> {
    match &args.command {
        ActionCommand::List { api, limit } => run_list(api, *limit),
        ActionCommand::Approve {
            action_id,
            actor,
            storage,
        } => run_transition(storage, action_id, actor, ActionStage::Approved),
        ActionCommand::Reject {
            action_id,
            actor,
            storage,
        } => run_transition(storage, action_id, actor, ActionStage::Rejected),
        ActionCommand::Execute { action_id, actor } => run_execute(action_id, actor),
    }
}

fn open(args: &ActionStorageArgs) -> Result<SqliteStorage> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    SqliteStorage::open(&db_path).with_context(|| format!("opening db {}", db_path.display()))
}

fn run_list(api: &ApiArgs, limit: u32) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building actions list client runtime")?;
    let recs = runtime.block_on(ApiClient::new(api)?.fetch_recommendations(limit))?;
    println!("{}", render_actions(&recs));
    Ok(())
}

fn render_actions(recs: &[rieko_findings::Recommendation]) -> String {
    if recs.is_empty() {
        return "No actions on record.".into();
    }
    recs.iter()
        .map(|rec| {
            format!(
                "{:<12} {:?} {:?} {}",
                rec.action.id.chars().take(12).collect::<String>(),
                rec.action.stage,
                rec.action.action_type,
                rec.action.summary
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_transition(
    args: &ActionStorageArgs,
    action_id: &str,
    actor: &str,
    to: ActionStage,
) -> Result<()> {
    if to != ActionStage::Rejected && actor == SYSTEM_ACTOR {
        bail!("approval must come from a human, not `{SYSTEM_ACTOR}`");
    }
    let mut storage = open(args)?;
    let rec = storage
        .recommendation_for_action(action_id)?
        .with_context(|| format!("no action with id {action_id}"))?;

    let next =
        transition(&rec.action, to, actor).map_err(|e: ExecutionError| anyhow::anyhow!(e))?;

    // State transition and its audit entry commit together (RIEKO-AUDIT-007):
    // never record a stage change without the audit row, and never write an
    // audit row for a transition that failed.
    storage.begin_transaction()?;
    let result = (|| {
        storage.set_action_stage(action_id, next)?;
        let audit = AuditEntry::from_transition(
            &Action {
                stage: next,
                ..rec.action.clone()
            },
            rec.action.stage,
            actor,
            serde_json::json!({}),
        );
        storage.append_audit(&audit)?;
        Ok::<_, anyhow::Error>(())
    })();
    match result {
        Ok(()) => storage.commit_transaction()?,
        Err(e) => {
            let _ = storage.rollback_transaction();
            return Err(e);
        }
    }

    info!(
        action_id,
        actor,
        stage = format!("{:?}", next),
        "action transition"
    );
    println!(
        "{action_id}: {:?} -> {next:?} (actor {actor})",
        rec.action.stage
    );
    Ok(())
}

fn run_execute(_action_id: &str, actor: &str) -> Result<()> {
    let actor = actor.trim();
    if actor.is_empty() || actor == SYSTEM_ACTOR {
        bail!("execution must be confirmed by a human, not `{SYSTEM_ACTOR}`");
    }
    bail!(
        "live execution is interlocked until simulation integrity, durable idempotency, and regtest safety gates are complete"
    )
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".rieko");
    std::fs::create_dir_all(&dir).ok();
    dir.join("rieko.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use chrono::TimeZone;
    use rieko_findings::{ActionType, Actionability, Rationale, Recommendation};
    use std::collections::HashMap;

    fn recommendation(id: &str, stage: ActionStage, lifecycle: Option<&str>) -> Recommendation {
        let now = chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        Recommendation {
            finding_id: format!("finding-{id}"),
            action: Action {
                id: id.into(),
                action_type: if stage == ActionStage::Rejected {
                    ActionType::RestartService
                } else {
                    ActionType::RebalanceChannel
                },
                stage,
                target: None,
                params: serde_json::json!({}),
                summary: if lifecycle == Some("resolved") {
                    "historical action".into()
                } else {
                    "current action".into()
                },
                created_at: now,
                updated_at: now,
            },
            rationale: Rationale {
                evidence: Vec::new(),
                preconditions: Vec::new(),
                expected_effect: "operator review".into(),
                risks: Vec::new(),
                limitations: Vec::new(),
                actionability: Actionability::OperatorActionable,
            },
            lifecycle: lifecycle.map(str::to_owned),
        }
    }

    fn authenticated(headers: &HeaderMap) -> bool {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            == Some("Bearer actions-token")
    }

    fn unauthorized() -> Response {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }

    async fn start(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    fn api_args(api_url: String, token_file: Option<PathBuf>) -> ApiArgs {
        ApiArgs {
            api_url,
            token_file,
        }
    }

    #[tokio::test]
    async fn list_fetches_current_and_historical_actions_without_a_local_database() {
        let current = recommendation("abcdefghijklmnop", ActionStage::Recommended, None);
        let historical = recommendation("historical-1234", ActionStage::Rejected, Some("resolved"));
        let expected = vec![current.clone(), historical.clone()];
        let app = axum::Router::new().route(
            "/recommendations",
            get(
                move |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| {
                    let expected = expected.clone();
                    async move {
                        if !authenticated(&headers) {
                            return unauthorized();
                        }
                        if query.get("lifecycle").map(String::as_str) != Some("all")
                            || query.get("limit").map(String::as_str) != Some("2")
                        {
                            return (StatusCode::BAD_REQUEST, "unexpected query").into_response();
                        }
                        axum::Json(expected).into_response()
                    }
                },
            ),
        );
        let (api_url, server) = start(app).await;
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("token");
        let nonexistent_database = directory.path().join("must-not-be-created.db");
        std::fs::write(&token_file, "actions-token\n").unwrap();
        let client = ApiClient::new(&api_args(api_url, Some(token_file))).unwrap();

        let actions = client.fetch_recommendations(2).await.unwrap();
        let output = render_actions(&actions);

        server.abort();
        assert_eq!(actions, [current, historical]);
        assert_eq!(
            output,
            "abcdefghijkl Recommended RebalanceChannel current action\n\
             historical-1 Rejected RestartService historical action"
        );
        assert!(!nonexistent_database.exists());
    }

    #[tokio::test]
    async fn list_reports_authentication_failure() {
        let app = axum::Router::new().route(
            "/recommendations",
            get(|headers: HeaderMap| async move {
                if authenticated(&headers) {
                    axum::Json(Vec::<Recommendation>::new()).into_response()
                } else {
                    unauthorized()
                }
            }),
        );
        let (api_url, server) = start(app).await;

        let error = ApiClient::new(&api_args(api_url, None))
            .unwrap()
            .fetch_recommendations(1)
            .await
            .unwrap_err();

        server.abort();
        assert!(error.to_string().contains("401 Unauthorized"));
    }

    #[tokio::test]
    async fn list_reports_non_success_and_malformed_responses() {
        let unavailable = axum::Router::new().route(
            "/recommendations",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "agent unavailable") }),
        );
        let (api_url, server) = start(unavailable).await;
        let error = ApiClient::new(&api_args(api_url, None))
            .unwrap()
            .fetch_recommendations(1)
            .await
            .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("503 Service Unavailable"));
        assert!(error.to_string().contains("agent unavailable"));

        let malformed =
            axum::Router::new().route("/recommendations", get(|| async { "not actions" }));
        let (api_url, server) = start(malformed).await;
        let error = ApiClient::new(&api_args(api_url, None))
            .unwrap()
            .fetch_recommendations(1)
            .await
            .unwrap_err();
        server.abort();
        assert!(error
            .to_string()
            .contains("decoding typed recommendations response"));
    }

    #[test]
    fn execution_interlock_remains_unchanged() {
        let error = run_execute("action", "operator").unwrap_err();
        assert!(error.to_string().contains("interlocked"));
    }
}
