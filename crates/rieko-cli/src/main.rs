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
    #[cfg(feature = "future")]
    Simulate(commands::simulate::SimulateArgs),
    /// Approve or execute recommended actions (human-gated).
    #[cfg(feature = "future")]
    Actions(commands::actions::ActionsArgs),
    /// Show what's stored in the durable database.
    Status(commands::status::StatusArgs),
    /// Run the read-only HTTP API.
    Serve(commands::serve::ServeArgs),
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => commands::scan::run(args),
        Command::Monitor(args) => commands::monitor::run(args),
        #[cfg(feature = "future")]
        Command::Simulate(args) => commands::simulate::run(args),
        #[cfg(feature = "future")]
        Command::Actions(args) => commands::actions::run(args),
        Command::Status(args) => commands::status::run(args),
        Command::Serve(args) => commands::serve::run(args),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "future"))]
    use super::Cli;
    #[cfg(not(feature = "future"))]
    use clap::CommandFactory;

    /// The v1 CLI must not advertise any capability that implies LND mutation
    /// or human-gated execution authority (RIEKO-AUDIT-001/015).
    #[cfg(not(feature = "future"))]
    #[test]
    fn default_cli_help_is_read_only() {
        let help = Cli::command().render_long_help().to_string();
        for banned in [
            "simulate", "Simulate", "actions", "Actions", "execute", "approve",
        ] {
            assert!(
                !help.to_lowercase().contains(&banned.to_lowercase()),
                "default CLI help must not advertise capability containing {banned:?}\n{help}"
            );
        }
        for required in ["scan", "monitor", "status", "serve"] {
            assert!(
                help.to_lowercase().contains(required),
                "default CLI help must still advertise {required:?}\n{help}"
            );
        }
    }

    #[cfg(not(feature = "future"))]
    #[test]
    fn cli_dispatches_only_read_only_commands() {
        let got = Cli::command()
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            vec!["scan", "monitor", "status", "serve"],
            "got {got:?}"
        );
    }
}
