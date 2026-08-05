mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rieko",
    version,
    about = "Operational intelligence engine for Bitcoin/Lightning infrastructure"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the detection pipeline once: ingest → detect → recommend → explain → alert → persist.
    Scan(commands::scan::ScanArgs),
    /// Run the same pipeline continuously, tracking channel state over time.
    Monitor(commands::monitor::MonitorArgs),
    /// Run the pipeline once, then project what each recommendation would do.
    Simulate(commands::simulate::SimulateArgs),
    /// Show what's stored in the durable database.
    Status(commands::status::StatusArgs),
    /// Run the read-only HTTP API.
    Serve(commands::serve::ServeArgs),
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => commands::scan::run(args),
        Command::Monitor(args) => commands::monitor::run(args),
        Command::Simulate(args) => commands::simulate::run(args),
        Command::Status(args) => commands::status::run(args),
        Command::Serve(args) => commands::serve::run(args),
    }
}
