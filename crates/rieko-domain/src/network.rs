use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Bitcoin chain on which an observation was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl fmt::Display for BitcoinNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown Bitcoin network {0:?}; expected mainnet, testnet, signet, or regtest")]
pub struct ParseBitcoinNetworkError(String);

impl FromStr for BitcoinNetwork {
    type Err = ParseBitcoinNetworkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(ParseBitcoinNetworkError(value.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_and_text_forms_are_snake_case() {
        for (network, name) in [
            (BitcoinNetwork::Mainnet, "mainnet"),
            (BitcoinNetwork::Testnet, "testnet"),
            (BitcoinNetwork::Signet, "signet"),
            (BitcoinNetwork::Regtest, "regtest"),
        ] {
            assert_eq!(network.to_string(), name);
            assert_eq!(name.parse::<BitcoinNetwork>().unwrap(), network);
            assert_eq!(
                serde_json::to_string(&network).unwrap(),
                format!("\"{name}\"")
            );
        }
    }

    #[test]
    fn parsing_rejects_unknown_networks() {
        assert!("bitcoin".parse::<BitcoinNetwork>().is_err());
    }
}
