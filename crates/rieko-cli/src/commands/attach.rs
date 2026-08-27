use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use reqwest::Url;
use rieko_cli::config::{self, BtcPayConnectionConfig, RiekoConfig};
use rieko_domain::BitcoinNetwork;

#[derive(Args, Debug)]
pub struct AttachArgs {
    #[command(subcommand)]
    command: AttachCommand,
}

#[derive(Subcommand, Debug)]
enum AttachCommand {
    /// Save non-secret BTCPay Greenfield connection settings.
    Btcpay(BtcPayArgs),
}

#[derive(Args, Debug)]
struct BtcPayArgs {
    /// Rieko agent configuration file to create or update.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,

    /// BTCPay Server Greenfield base URL.
    #[arg(long, value_name = "URL")]
    greenfield_url: String,

    /// BTCPay store to observe.
    #[arg(long, value_name = "STORE")]
    store: String,

    /// File containing the scoped, read-only Greenfield API key.
    #[arg(long, value_name = "FILE")]
    api_key_file: PathBuf,

    /// Bitcoin network associated with the BTCPay store.
    #[arg(long, value_name = "NETWORK")]
    network: BitcoinNetwork,

    /// Optional stable node identity scope.
    #[arg(long, value_name = "NODE")]
    node: Option<String>,
}

pub fn run(args: AttachArgs) -> Result<()> {
    match args.command {
        AttachCommand::Btcpay(args) => attach_btcpay(args),
    }
}

fn attach_btcpay(args: BtcPayArgs) -> Result<()> {
    let greenfield_base_url = validate_url(&args.greenfield_url)?;
    let store_id = required_text("store ID", &args.store)?;
    let node = args
        .node
        .as_deref()
        .map(|node| required_text("node scope", node))
        .transpose()?;
    let metadata = std::fs::metadata(&args.api_key_file).with_context(|| {
        format!(
            "reading API-key file metadata {}",
            args.api_key_file.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "API-key path is not a regular file: {}",
            args.api_key_file.display()
        );
    }

    let mut persisted = if args.config.exists() {
        config::load(&args.config)?
    } else {
        RiekoConfig::default()
    };
    persisted.btcpay = Some(BtcPayConnectionConfig {
        greenfield_base_url,
        store_id,
        api_key_file: args.api_key_file,
        network: args.network,
        node,
    });
    config::write(&args.config, &persisted)?;
    println!("BTCPay configuration saved to {}", args.config.display());
    println!(
        "Start the agent with: rieko-agent --config {}",
        args.config.display()
    );
    Ok(())
}

fn validate_url(value: &str) -> Result<String> {
    let value = required_text("Greenfield base URL", value)?;
    let url = Url::parse(&value).context("Greenfield base URL is not a valid URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("Greenfield base URL must use http or https");
    }
    if url.host_str().is_none() {
        bail!("Greenfield base URL must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Greenfield base URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("Greenfield base URL must not contain a query or fragment");
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn required_text(label: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(config: PathBuf, api_key_file: PathBuf, store: &str, node: Option<&str>) -> BtcPayArgs {
        BtcPayArgs {
            config,
            greenfield_url: "https://btcpay.example.com/".into(),
            store: store.into(),
            api_key_file,
            network: BitcoinNetwork::Regtest,
            node: node.map(str::to_owned),
        }
    }

    #[test]
    fn valid_configuration_preserves_only_the_secret_file_reference() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("rieko.json");
        let secret_path = directory.path().join("greenfield.key");
        let secret = "sensitive-greenfield-key";
        std::fs::write(&secret_path, secret).unwrap();

        attach_btcpay(args(
            config_path.clone(),
            secret_path.clone(),
            "store-1",
            Some("node-1"),
        ))
        .unwrap();

        let persisted = config::load(&config_path).unwrap();
        let btcpay = persisted.btcpay.unwrap();
        assert_eq!(btcpay.greenfield_base_url, "https://btcpay.example.com");
        assert_eq!(btcpay.store_id, "store-1");
        assert_eq!(btcpay.api_key_file, secret_path);
        assert_eq!(btcpay.network, BitcoinNetwork::Regtest);
        assert_eq!(btcpay.node.as_deref(), Some("node-1"));
        let encoded = std::fs::read_to_string(config_path).unwrap();
        assert!(!encoded.contains(secret));
    }

    #[test]
    fn rejects_obvious_invalid_input_without_writing_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("rieko.json");
        let secret_path = directory.path().join("greenfield.key");
        std::fs::write(&secret_path, "secret").unwrap();

        let mut invalid_url = args(config_path.clone(), secret_path.clone(), "store-1", None);
        invalid_url.greenfield_url = "ftp://btcpay.example.com".into();
        assert!(attach_btcpay(invalid_url).is_err());

        assert!(attach_btcpay(args(config_path.clone(), secret_path, "   ", None,)).is_err());
        assert!(attach_btcpay(args(
            config_path.clone(),
            directory.path().join("missing.key"),
            "store-1",
            None,
        ))
        .is_err());
        assert!(!config_path.exists());
    }

    #[test]
    fn repeated_attach_is_deterministic_and_updates_the_existing_entry() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("rieko.json");
        let secret_path = directory.path().join("greenfield.key");
        std::fs::write(&secret_path, "secret").unwrap();

        attach_btcpay(args(
            config_path.clone(),
            secret_path.clone(),
            "store-1",
            None,
        ))
        .unwrap();
        let first = std::fs::read(&config_path).unwrap();
        attach_btcpay(args(
            config_path.clone(),
            secret_path.clone(),
            "store-1",
            None,
        ))
        .unwrap();
        assert_eq!(std::fs::read(&config_path).unwrap(), first);

        attach_btcpay(args(
            config_path.clone(),
            secret_path,
            "store-2",
            Some("node-2"),
        ))
        .unwrap();
        let updated = config::load(&config_path).unwrap().btcpay.unwrap();
        assert_eq!(updated.store_id, "store-2");
        assert_eq!(updated.node.as_deref(), Some("node-2"));
    }
}
