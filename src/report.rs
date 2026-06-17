use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Status for a probe step.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeStepStatus {
    Ok,
    Error,
}

/// A single named step in a probe report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ProbeStep {
    pub name: String,
    pub status: ProbeStepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Severity for a tool schema compatibility finding.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolSchemaCompatibilitySeverity {
    Error,
    Warning,
}

/// Client-compatibility issue found in an advertised MCP tool schema.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ToolSchemaCompatibilityFinding {
    pub severity: ToolSchemaCompatibilitySeverity,
    pub code: String,
    pub tool_name: String,
    pub schema_path: String,
    pub message: String,
    pub hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<Value>,
}

/// Redacted JSON-RPC trace entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEntry {
    pub direction: String,
    pub timestamp: String,
    pub message: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

/// Auth discovery metadata captured from PRM/OAuth endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthDiscovery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_metadata_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_metadata_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
}

/// Report for a full probe run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeReport {
    pub ok: bool,
    pub started_at: String,
    pub finished_at: String,
    pub steps: Vec<ProbeStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthDiscovery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<TraceEntry>>,
}

/// Report for Last-Event-ID replay validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayProbeReport {
    pub ok: bool,
    pub started_at: String,
    pub finished_at: String,
    pub steps: Vec<ProbeStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
}

/// Report for HTTP smoke checks (PRM + OAuth discovery).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpSmokeReport {
    pub ok: bool,
    pub started_at: String,
    pub finished_at: String,
    pub steps: Vec<ProbeStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthDiscovery>,
}

/// Report for a raw JSON-RPC request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RawRequestReport {
    pub ok: bool,
    pub started_at: String,
    pub finished_at: String,
    pub steps: Vec<ProbeStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthDiscovery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<TraceEntry>>,
}

/// Output verbosity for probe reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReportVerbosity {
    Summary,
    Full,
}

/// Return the current UTC timestamp in RFC 3339 format.
pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn summarize_auth(auth: Option<AuthDiscovery>) -> Option<AuthDiscovery> {
    let auth = auth?;
    let mut summary = AuthDiscovery {
        resource_metadata_url: None,
        resource_metadata: None,
        authorization_server: None,
        oauth_metadata_url: None,
        oauth_metadata: None,
        registration_endpoint: None,
    };
    if auth.resource_metadata_url.is_some() {
        summary.resource_metadata_url = auth.resource_metadata_url;
    }
    if auth.authorization_server.is_some() {
        summary.authorization_server = auth.authorization_server;
    }
    if auth.oauth_metadata_url.is_some() {
        summary.oauth_metadata_url = auth.oauth_metadata_url;
    }
    if auth.registration_endpoint.is_some() {
        summary.registration_endpoint = auth.registration_endpoint;
    }
    if summary.resource_metadata_url.is_none()
        && summary.authorization_server.is_none()
        && summary.oauth_metadata_url.is_none()
        && summary.registration_endpoint.is_none()
    {
        None
    } else {
        Some(summary)
    }
}

/// Apply report verbosity by trimming large payloads when in summary mode.
pub fn apply_report_verbosity(
    mut report: ProbeReport,
    verbosity: Option<ReportVerbosity>,
) -> ProbeReport {
    match verbosity {
        Some(ReportVerbosity::Full) => report,
        _ => {
            report.tools = None;
            report.resources = None;
            report.prompts = None;
            report.trace = None;
            report.auth = summarize_auth(report.auth);
            report
        }
    }
}
