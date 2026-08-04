use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::NodeId;

/// Whether we have a live connection to a peer node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Disconnected,
    Unknown,
}

/// Structured node version. Kept structured (not a free string) so the
/// security-intelligence feed can correlate CVEs against running versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub commit: Option<String>,
}

impl NodeVersion {
    /// Parse common Lightning version strings, e.g. `0.18.5`, `v0.18.5-beta`,
    /// `lnd 0.18.5-beta commit=abc`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut num = String::new();
        let mut commit: Option<String> = None;

        for tok in s.split_whitespace() {
            if let Some(idx) = tok.find("commit=") {
                commit = Some(tok[idx + "commit=".len()..].to_string());
            }
            let clean = tok.trim_start_matches('v');
            if let Some(idx) = clean.find(char::is_numeric) {
                num = clean[idx..].to_string();
            }
        }

        let mut parts = num
            .split('.')
            .map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
            .filter(|p| !p.is_empty());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().map(|p| p.parse().unwrap_or(0)).unwrap_or(0);

        Some(Self {
            major,
            minor,
            patch,
            commit,
        })
    }

    pub fn display(&self) -> String {
        match &self.commit {
            Some(c) => format!("{}.{}.{}-{}", self.major, self.minor, self.patch, c),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

/// A node in the operator's environment (or a peer we observe via gossip).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub alias: Option<String>,
    pub version: Option<NodeVersion>,
    pub status: NodeStatus,
    pub last_seen: DateTime<Utc>,
}
