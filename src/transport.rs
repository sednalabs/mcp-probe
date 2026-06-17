use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported MCP transport types for probing.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TransportType {
    Stdio,
    Sse,
    #[serde(alias = "streamable_http")]
    StreamableHttp,
}

impl TransportType {
    /// Return the canonical string value for this transport.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportType::Stdio => "stdio",
            TransportType::Sse => "sse",
            TransportType::StreamableHttp => "streamable-http",
        }
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransportType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "stdio" => Ok(TransportType::Stdio),
            "sse" => Ok(TransportType::Sse),
            "streamable-http" | "streamable_http" => Ok(TransportType::StreamableHttp),
            other => Err(format!("Unsupported transport type: {other}")),
        }
    }
}

impl TransportType {
    /// Deserialize helper that accepts streamable_http as an alias.
    pub fn from_alias(value: &str) -> Result<Self, String> {
        Self::from_str(value)
    }
}

/// Base transport configuration shared by probe targets.
#[derive(Debug, Clone)]
pub struct TransportOptions {
    pub transport_type: TransportType,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<std::collections::HashMap<String, String>>,
    pub url: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
}
