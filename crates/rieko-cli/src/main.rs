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
    /// Create and inspect deterministic what-if projections (v2).
    #[cfg(feature = "simulate")]
    Simulations(commands::simulations::SimulationsArgs),
    /// Approve or execute recommended actions (human-gated).
    #[cfg(feature = "execute")]
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
        #[cfg(feature = "simulate")]
        Command::Simulations(args) => commands::simulations::run(args),
        #[cfg(feature = "execute")]
        Command::Actions(args) => commands::actions::run(args),
        Command::Status(args) => commands::status::run(args),
        Command::Serve(args) => commands::serve::run(args),
    }
}

#[cfg(test)]
mod tests {
    /// The default v2 CLI advertises simulation (read-only) but must not expose
    /// execution (node-mutating) commands (RIEKO-AUDIT-001/015).
    #[test]
    fn default_cli_help_is_read_only() {
        use super::Cli;
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        // When execution feature is off, these must not appear.
        #[cfg(not(feature = "execute"))]
        for banned in ["actions", "Actions", "execute", "approve"] {
            assert!(
                !help.to_lowercase().contains(&banned.to_lowercase()),
                "default CLI help must not advertise capability containing {banned:?}\n{help}"
            );
        }
        #[cfg(feature = "simulate")]
        let required = ["scan", "monitor", "simulations", "status", "serve"];
        #[cfg(not(feature = "simulate"))]
        let required = ["scan", "monitor", "status", "serve"];
        for required in required {
            assert!(
                help.to_lowercase().contains(required),
                "default CLI help must advertise {required:?}\n{help}"
            );
        }
    }

    #[test]
    fn cli_dispatches_simulation_but_not_execution() {
        use super::Cli;
        use clap::CommandFactory;
        let got = Cli::command()
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect::<Vec<_>>();
        #[cfg(all(not(feature = "execute"), feature = "simulate"))]
        let expected: &[&str] = &["scan", "monitor", "simulations", "status", "serve"];
        #[cfg(all(feature = "execute", feature = "simulate"))]
        let expected: &[&str] = &[
            "scan",
            "monitor",
            "simulations",
            "actions",
            "status",
            "serve",
        ];
        #[cfg(all(feature = "execute", not(feature = "simulate")))]
        let expected: &[&str] = &["scan", "monitor", "actions", "status", "serve"];
        #[cfg(all(not(feature = "execute"), not(feature = "simulate")))]
        let expected: &[&str] = &["scan", "monitor", "status", "serve"];
        assert_eq!(got, expected, "got {got:?}");
    }

    #[test]
    fn scan_and_monitor_require_a_network() {
        use super::Cli;
        use clap::Parser;

        for command in ["scan", "monitor"] {
            assert!(Cli::try_parse_from(["rieko", command, "--fixture", "channels.json"]).is_err());
            assert!(Cli::try_parse_from([
                "rieko",
                command,
                "--network",
                "signet",
                "--fixture",
                "channels.json",
            ])
            .is_ok());
        }
    }
}
