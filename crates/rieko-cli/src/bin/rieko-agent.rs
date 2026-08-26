use clap::Parser;
use rieko_cli::agent::AgentArgs;

#[derive(Parser)]
#[command(
    name = "rieko-agent",
    version,
    about = "Long-running operational runtime for Rieko"
)]
struct Cli {
    #[command(flatten)]
    agent: AgentArgs,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    rieko_cli::agent::run(Cli::parse().agent)
}
