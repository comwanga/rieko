use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use rieko_execution::{
    ExecutionError, Executor, LndExecutor, RecordingExecutor, SYSTEM_ACTOR, transition,
};
use rieko_findings::{Action, ActionStage, AuditEntry};
use rieko_storage::{SqliteStorage, Storage};
use tracing::info;

use super::common::GraphSource;

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

    /// Local node id (pubkey). Defaults to `local-node`.
    #[arg(long, default_value = "local-node")]
    node: String,

    /// Durable database path. Defaults to `~/.rieko/rieko.db`.
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum ActionCommand {
    /// List recent actions and their stage (recommended/simulated/approved/...).
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Approve an action for execution. Requires the `--actor` of a human.
    Approve {
        action_id: String,
        /// Human actor id approving the action. Cannot be `system`.
        #[arg(long)]
        actor: String,
    },
    /// Reject an action so it is never executed.
    Reject {
        action_id: String,
        /// Human actor id rejecting the action.
        #[arg(long)]
        actor: String,
    },
    /// Execute an approved action against the node.
    Execute {
        action_id: String,
        /// Human actor id confirming the execution.
        #[arg(long)]
        actor: String,
    },
}

pub fn run(args: ActionsArgs) -> Result<()> {
    match &args.command {
        ActionCommand::List { limit } => run_list(&args, *limit),
        ActionCommand::Approve { action_id, actor } => {
            run_transition(&args, action_id, actor, ActionStage::Approved)
        }
        ActionCommand::Reject { action_id, actor } => {
            run_transition(&args, action_id, actor, ActionStage::Rejected)
        }
        ActionCommand::Execute { action_id, actor } => run_execute(&args, action_id, actor),
    }
}

fn open(args: &ActionsArgs) -> Result<SqliteStorage> {
    let db_path = args.db.clone().unwrap_or_else(default_db_path);
    SqliteStorage::open(&db_path)
        .with_context(|| format!("opening db {}", db_path.display()))
}

fn run_list(args: &ActionsArgs, limit: u32) -> Result<()> {
    let mut storage = open(args)?;
    let recs = storage.latest_recommendations(limit)?;
    if recs.is_empty() {
        println!("No actions on record.");
        return Ok(());
    }
    for rec in recs {
        println!(
            "{:<12} {:?} {:?} {}",
            rec.action.id.chars().take(12).collect::<String>(),
            rec.action.stage,
            rec.action.action_type,
            rec.action.summary
        );
    }
    Ok(())
}

fn run_transition(
    args: &ActionsArgs,
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

    let next = transition(&rec.action, to, actor)
        .map_err(|e: ExecutionError| anyhow::anyhow!(e))?;

    storage.set_action_stage(action_id, next)?;
    storage.append_audit(&AuditEntry::from_action(
        &Action {
            stage: next,
            ..rec.action.clone()
        },
        actor,
        serde_json::json!({ "previous_stage": format!("{:?}", rec.action.stage) }),
    ))?;

    info!(action_id, actor, stage = format!("{:?}", next), "action transition");
    println!("{action_id}: {:?} -> {next:?} (actor {actor})", rec.action.stage);
    Ok(())
}

fn run_execute(args: &ActionsArgs, action_id: &str, actor: &str) -> Result<()> {
    if actor == SYSTEM_ACTOR {
        bail!("execution must be confirmed by a human, not `{SYSTEM_ACTOR}`");
    }
    let mut storage = open(args)?;
    let rec = storage
        .recommendation_for_action(action_id)?
        .with_context(|| format!("no action with id {action_id}"))?;

    // Build the graph so an executor has live state to act on.
    let source = GraphSource {
        fixture: args.fixture.clone(),
        lnd_rest: args.lnd_rest.clone(),
        macaroon: args.macaroon.clone(),
        node: args.node.clone(),
    };
    let _graph = source.build()?;

    // Pick the executor: live node when one is configured, recording otherwise.
    let macaroon = args
        .macaroon
        .as_ref()
        .map(|p| std::fs::read_to_string(p).map(|s| s.trim().to_string()))
        .transpose()
        .context("reading macaroon")?;
    let executor: Box<dyn Executor> = match &args.lnd_rest {
        Some(rest) => Box::new(LndExecutor::new(rest.clone(), macaroon)),
        None => {
            info!("no --lnd-rest configured; using recording executor");
            Box::new(RecordingExecutor)
        }
    };
    let report = executor.execute(&rec.action).map_err(|e| anyhow::anyhow!(e))?;

    let next = if report.success {
        ActionStage::Executed
    } else {
        ActionStage::Failed
    };
    storage.set_action_stage(action_id, next)?;
    storage.append_audit(&AuditEntry {
        id: uuid::Uuid::new_v4().to_string(),
        action_id: action_id.to_string(),
        action_type: rec.action.action_type,
        stage: next,
        actor: actor.to_string(),
        details: serde_json::json!({ "result": report.detail }),
        timestamp: chrono::Utc::now(),
    })?;

    info!(action_id, actor, stage = format!("{:?}", next), detail = %report.detail, "action executed");
    println!("{action_id}: Executed ({})", report.detail);
    Ok(())
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".rieko");
    std::fs::create_dir_all(&dir).ok();
    dir.join("rieko.db")
}
