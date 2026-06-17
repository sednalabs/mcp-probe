//! # MCP Probe (Rust)
//!
//! Headless MCP probe implementation with a CLI and stdio MCP server.
//!
//! ## Rationale
//! Provides a deterministic, automatable probe for MCP servers in Rust,
//! with a report format suitable for repeated CI and connector-readiness checks.
//!
//! ## Security Boundaries
//! * **Outbound allowlist**: restricts target hosts for HTTP transports.
//! * **Token safety**: token paths are constrained to the probe token directory.
//! * **stdio guard**: stdio transports are opt-in via environment.

pub mod admission;
pub mod allowlist;
pub mod auth;
pub mod cli;
pub mod guidance;
pub mod help_text;
pub mod http;
pub mod logging;
pub mod probe;
pub mod provenance;
pub mod replay;
pub mod report;
pub mod scenario;
pub mod trace;
pub mod transport;

pub mod server;
pub mod version;
