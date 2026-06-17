//! Version metadata for the probe server.

use rmcp::model::ProtocolVersion;

pub const SERVER_NAME: &str = "mcp-probe";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

pub fn latest_protocol_version() -> ProtocolVersion {
    serde_json::from_str(&format!("\"{MCP_PROTOCOL_VERSION}\""))
        .expect("valid MCP protocol version")
}
