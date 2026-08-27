use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rieko_domain::BitcoinNetwork;
use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiekoConfig {
    pub version: u8,
    pub btcpay: Option<BtcPayConnectionConfig>,
}

impl Default for RiekoConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            btcpay: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcPayConnectionConfig {
    pub greenfield_base_url: String,
    pub store_id: String,
    pub api_key_file: PathBuf,
    pub network: BitcoinNetwork,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

pub fn load(path: &Path) -> Result<RiekoConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading Rieko config {}", path.display()))?;
    let config: RiekoConfig = serde_json::from_str(&contents)
        .with_context(|| format!("decoding Rieko config {}", path.display()))?;
    if config.version != CONFIG_VERSION {
        bail!(
            "unsupported Rieko config version {} in {}; expected {}",
            config.version,
            path.display(),
            CONFIG_VERSION
        );
    }
    Ok(config)
}

pub fn write(path: &Path, config: &RiekoConfig) -> Result<()> {
    if config.version != CONFIG_VERSION {
        bail!(
            "cannot write unsupported Rieko config version {}",
            config.version
        );
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }
    let mut encoded = serde_json::to_string_pretty(config).context("encoding Rieko config")?;
    encoded.push('\n');
    std::fs::write(path, encoded)
        .with_context(|| format!("writing Rieko config {}", path.display()))
}
