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
    /// Configure external infrastructure connections without contacting them.
    Attach(commands::attach::AttachArgs),
    /// Create and inspect deterministic what-if projections (v2).
    #[cfg(feature = "simulate")]
    Simulations(commands::simulations::SimulationsArgs),
    /// Approve or execute recommended actions (human-gated).
    #[cfg(feature = "execute")]
    Actions(commands::actions::ActionsArgs),
    /// Return one exact persisted finding from the running agent.
    Explain(commands::explain::ExplainArgs),
    /// List typed findings and structured evidence from the running agent.
    Findings(commands::findings::FindingsArgs),
    /// Stream newly observed findings and lifecycle changes from the running agent.
    Watch(commands::watch::WatchArgs),
    /// Show operational status reported by the running agent.
    Status(commands::status::StatusArgs),
    /// Summarize persisted operational state and active findings.
    Doctor(commands::doctor::DoctorArgs),
    /// Inspect detailed normalized state reported by the running agent.
    Inspect(commands::inspect::InspectArgs),
    /// Run the read-only HTTP API.
    Serve(Box<commands::serve::ServeArgs>),
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
        Command::Attach(args) => commands::attach::run(args),
        #[cfg(feature = "simulate")]
        Command::Simulations(args) => commands::simulations::run(args),
        #[cfg(feature = "execute")]
        Command::Actions(args) => commands::actions::run(args),
        Command::Explain(args) => commands::explain::run(args),
        Command::Findings(args) => commands::findings::run(args),
        Command::Watch(args) => commands::watch::run(args),
        Command::Status(args) => commands::status::run(args),
        Command::Doctor(args) => commands::doctor::run(args),
        Command::Inspect(args) => commands::inspect::run(args),
        Command::Serve(args) => commands::serve::run(*args),
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
        let required = [
            "scan",
            "monitor",
            "attach",
            "simulations",
            "explain",
            "findings",
            "watch",
            "status",
            "doctor",
            "inspect",
            "serve",
        ];
        #[cfg(not(feature = "simulate"))]
        let required = [
            "scan", "monitor", "attach", "explain", "findings", "watch", "status", "doctor",
            "inspect", "serve",
        ];
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
        let expected: &[&str] = &[
            "scan",
            "monitor",
            "attach",
            "simulations",
            "explain",
            "findings",
            "watch",
            "status",
            "doctor",
            "inspect",
            "serve",
        ];
        #[cfg(all(feature = "execute", feature = "simulate"))]
        let expected: &[&str] = &[
            "scan",
            "monitor",
            "attach",
            "simulations",
            "actions",
            "explain",
            "findings",
            "watch",
            "status",
            "doctor",
            "inspect",
            "serve",
        ];
        #[cfg(all(feature = "execute", not(feature = "simulate")))]
        let expected: &[&str] = &[
            "scan", "monitor", "attach", "actions", "explain", "findings", "watch", "status",
            "doctor", "inspect", "serve",
        ];
        #[cfg(all(not(feature = "execute"), not(feature = "simulate")))]
        let expected: &[&str] = &[
            "scan", "monitor", "attach", "explain", "findings", "watch", "status", "doctor",
            "inspect", "serve",
        ];
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

    #[test]
    fn watch_polling_configuration_is_bounded() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from(["rieko", "watch", "--cycles", "1"]).is_ok());
        assert!(Cli::try_parse_from(["rieko", "watch", "--interval", "0"]).is_err());
        assert!(Cli::try_parse_from(["rieko", "watch", "--limit", "501"]).is_err());
    }

    #[test]
    fn status_uses_api_configuration_and_has_no_database_flag() {
        use super::Cli;
        use clap::Parser;

        assert!(
            Cli::try_parse_from(["rieko", "status", "--api-url", "http://127.0.0.1:9000"]).is_ok()
        );
        assert!(Cli::try_parse_from(["rieko", "status", "--db", "local.db"]).is_err());
    }

    #[test]
    fn attach_btcpay_requires_connection_fields_and_rejects_database_flags() {
        use super::Cli;
        use clap::Parser;

        let valid = [
            "rieko",
            "attach",
            "btcpay",
            "--config",
            "rieko.json",
            "--greenfield-url",
            "https://btcpay.example.com",
            "--store",
            "store-1",
            "--api-key-file",
            "greenfield.key",
            "--network",
            "regtest",
            "--node",
            "node-1",
        ];
        assert!(Cli::try_parse_from(valid).is_ok());
        assert!(Cli::try_parse_from([
            "rieko",
            "attach",
            "btcpay",
            "--config",
            "rieko.json",
            "--greenfield-url",
            "https://btcpay.example.com",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "rieko",
            "attach",
            "btcpay",
            "--config",
            "rieko.json",
            "--greenfield-url",
            "https://btcpay.example.com",
            "--store",
            "store-1",
            "--api-key-file",
            "greenfield.key",
            "--network",
            "regtest",
            "--db",
            "rieko.db",
        ])
        .is_err());
    }

    #[test]
    fn doctor_uses_api_configuration_and_has_no_database_flag() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "rieko",
            "doctor",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
            "--json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["rieko", "doctor", "--db", "local.db"]).is_err());
    }

    #[test]
    fn inspect_lightning_uses_api_configuration_and_has_no_database_flag() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "rieko",
            "inspect",
            "lightning",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
            "--json",
        ])
        .is_ok());
        assert!(
            Cli::try_parse_from(["rieko", "inspect", "lightning", "--db", "local.db"]).is_err()
        );
    }

    #[test]
    fn inspect_bitcoin_uses_api_configuration_and_has_no_database_flag() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "rieko",
            "inspect",
            "bitcoin",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
            "--json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["rieko", "inspect", "bitcoin", "--db", "local.db"]).is_err());
    }

    #[test]
    fn inspect_btcpay_uses_api_configuration_and_has_no_database_flag() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "rieko",
            "inspect",
            "btcpay",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
            "--json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["rieko", "inspect", "btcpay", "--db", "local.db"]).is_err());
    }

    #[test]
    fn inspect_all_uses_api_configuration_and_has_no_database_flag() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "rieko",
            "inspect",
            "all",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
            "--json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["rieko", "inspect", "all", "--db", "local.db"]).is_err());
    }

    #[cfg(feature = "simulate")]
    #[test]
    fn simulation_reads_use_api_configuration_and_reject_database_flags() {
        use super::Cli;
        use clap::Parser;

        for args in [
            vec!["rieko", "simulations", "list"],
            vec!["rieko", "simulations", "show", "simulation-1"],
            vec![
                "rieko",
                "simulations",
                "compare",
                "simulation-1",
                "simulation-2",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }

        for args in [
            vec!["rieko", "simulations", "list", "--db", "local.db"],
            vec![
                "rieko",
                "simulations",
                "show",
                "simulation-1",
                "--db",
                "local.db",
            ],
            vec![
                "rieko",
                "simulations",
                "compare",
                "simulation-1",
                "simulation-2",
                "--db",
                "local.db",
            ],
            vec!["rieko", "simulations", "--db", "local.db", "list"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }

        assert!(Cli::try_parse_from([
            "rieko",
            "simulations",
            "list",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
        ])
        .is_ok());
    }

    #[cfg(feature = "simulate")]
    #[test]
    fn simulation_create_remains_storage_backed() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from([
            "rieko",
            "simulations",
            "create",
            "--db",
            "local.db",
            "--recommendation",
            "recommendation-1",
            "--source-channel",
            "source",
            "--destination-channel",
            "destination",
            "--amount-sats",
            "42",
        ])
        .is_ok());
    }

    #[cfg(feature = "execute")]
    #[test]
    fn actions_list_uses_api_configuration_and_rejects_database_flags() {
        use super::Cli;
        use clap::Parser;

        assert!(Cli::try_parse_from(["rieko", "actions", "list"]).is_ok());
        assert!(Cli::try_parse_from([
            "rieko",
            "actions",
            "list",
            "--api-url",
            "http://127.0.0.1:9000",
            "--token-file",
            "token",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["rieko", "actions", "list", "--db", "local.db"]).is_err());
        assert!(Cli::try_parse_from(["rieko", "actions", "--db", "local.db", "list"]).is_err());
    }

    #[cfg(feature = "execute")]
    #[test]
    fn action_transition_commands_remain_storage_backed() {
        use super::Cli;
        use clap::Parser;

        for command in ["approve", "reject"] {
            assert!(Cli::try_parse_from([
                "rieko", "actions", command, "action-1", "--actor", "operator", "--db", "local.db",
            ])
            .is_ok());
        }
        assert!(Cli::try_parse_from([
            "rieko", "actions", "execute", "action-1", "--actor", "operator",
        ])
        .is_ok());
    }
}
