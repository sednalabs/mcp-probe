use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use mcp_toolkit_observability::redaction::{
    redact_json_keys, redact_telemetry_text, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE,
};

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

/// Summary of one catalog discovery method in a shareable catalog artifact.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CatalogMethodSummary {
    pub method: String,
    pub status: ProbeStepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_count: Option<usize>,
}

/// Redaction policy metadata for a shareable catalog artifact.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CatalogRedaction {
    pub state: String,
    pub policy: String,
}

/// Host/client catalog-discovery profile applied to a probe run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CatalogProfile {
    RawMcp,
    ChatgptTool,
    AppsSdkUi,
    CodexDeferred,
    ClaudeCode,
    GeminiCli,
}

impl CatalogProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RawMcp => "raw_mcp",
            Self::ChatgptTool => "chatgpt_tool",
            Self::AppsSdkUi => "apps_sdk_ui",
            Self::CodexDeferred => "codex_deferred",
            Self::ClaudeCode => "claude_code",
            Self::GeminiCli => "gemini_cli",
        }
    }
}

impl std::str::FromStr for CatalogProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "raw_mcp" | "raw-mcp" => Ok(Self::RawMcp),
            "chatgpt_tool" | "chatgpt-tool" => Ok(Self::ChatgptTool),
            "apps_sdk_ui" | "apps-sdk-ui" => Ok(Self::AppsSdkUi),
            "codex_deferred" | "codex-deferred" => Ok(Self::CodexDeferred),
            "claude_code" | "claude-code" => Ok(Self::ClaudeCode),
            "gemini_cli" | "gemini-cli" => Ok(Self::GeminiCli),
            _ => Err(format!(
                "Invalid catalog profile `{value}`. Expected one of: raw_mcp, chatgpt_tool, apps_sdk_ui, codex_deferred, claude_code, gemini_cli."
            )),
        }
    }
}

/// One required or optional catalog-profile assertion.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CatalogProfileRequirement {
    pub name: String,
    pub required: bool,
    pub status: ProbeStepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_count: Option<usize>,
}

/// Host-profile verdict derived from the catalog discovery methods.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CatalogProfileVerdict {
    pub profile: CatalogProfile,
    pub status: ProbeStepStatus,
    pub detail: String,
    pub requirements: Vec<CatalogProfileRequirement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<String>,
}

fn default_catalog_contract_schema_version() -> u32 {
    1
}

/// Expected native MCP catalog contract consumed by probe runs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct CatalogContract {
    #[serde(default = "default_catalog_contract_schema_version")]
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_profile: Option<CatalogProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_tool_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tool_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_resource_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_resource_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_resource_template_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_resource_template_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_prompt_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_prompt_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_resource_templates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_prompts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_budget: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// One assertion made while comparing a live catalog to a contract.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CatalogContractRequirement {
    pub name: String,
    pub status: ProbeStepStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<Value>,
}

/// Probe verdict for an expected native MCP catalog contract.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CatalogContractVerdict {
    pub schema_version: u32,
    pub status: ProbeStepStatus,
    pub detail: String,
    pub actual_fingerprint: String,
    pub requirements: Vec<CatalogContractRequirement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<String>,
    pub contract: CatalogContract,
}

/// MCP catalog evidence suitable for Ops work-item receipts.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CatalogArtifact {
    pub schema_version: u32,
    pub generated_at: String,
    pub redaction: CatalogRedaction,
    pub methods: Vec<CatalogMethodSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<CatalogProfileVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<CatalogContractVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_templates: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Value>,
}

/// Raw discovery payload references used to build a redacted catalog artifact.
#[derive(Debug, Clone, Copy, Default)]
pub struct CatalogPayloadRefs<'a> {
    pub server_info: Option<&'a Value>,
    pub capabilities: Option<&'a Value>,
    pub tools: Option<&'a Value>,
    pub resources: Option<&'a Value>,
    pub resource_templates: Option<&'a Value>,
    pub prompts: Option<&'a Value>,
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
    pub resource_templates: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogArtifact>,
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

fn redact_strings(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_prefixed_tokens(&redact_telemetry_text(&text))),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_strings).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, redact_strings(value)))
                .collect(),
        ),
        other => other,
    }
}

fn redact_prefixed_tokens(text: &str) -> String {
    const SENSITIVE_PREFIXES: &[&str] = &["sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "ya29."];

    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0usize;

    while offset < text.len() {
        let remaining = &text[offset..];
        if let Some(prefix) = SENSITIVE_PREFIXES
            .iter()
            .find(|prefix| remaining.starts_with(**prefix))
        {
            redacted.push_str(DEFAULT_REDACT_VALUE);
            offset += prefix.len();
            while offset < text.len() {
                let next = text[offset..]
                    .chars()
                    .next()
                    .expect("offset is within string bounds");
                if next.is_ascii_alphanumeric() || matches!(next, '-' | '_' | '.') {
                    offset += next.len_utf8();
                } else {
                    break;
                }
            }
        } else {
            let next = remaining
                .chars()
                .next()
                .expect("remaining string is non-empty");
            redacted.push(next);
            offset += next.len_utf8();
        }
    }

    redacted
}

fn redact_catalog_value(value: Option<&Value>) -> Option<Value> {
    let mut value = value.cloned()?;
    redact_json_keys(&mut value, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
    Some(redact_strings(value))
}

/// Build a redacted catalog artifact from raw probe discovery payloads.
pub fn build_catalog_artifact(
    generated_at: String,
    methods: Vec<CatalogMethodSummary>,
    profile: Option<CatalogProfileVerdict>,
    contract: Option<CatalogContractVerdict>,
    payloads: CatalogPayloadRefs<'_>,
) -> CatalogArtifact {
    CatalogArtifact {
        schema_version: 1,
        generated_at,
        redaction: CatalogRedaction {
            state: "redacted".to_string(),
            policy: "mcp-probe default key and telemetry-text redaction".to_string(),
        },
        methods,
        profile,
        contract,
        server_info: redact_catalog_value(payloads.server_info),
        capabilities: redact_catalog_value(payloads.capabilities),
        tools: redact_catalog_value(payloads.tools),
        resources: redact_catalog_value(payloads.resources),
        resource_templates: redact_catalog_value(payloads.resource_templates),
        prompts: redact_catalog_value(payloads.prompts),
    }
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

fn summarize_catalog(catalog: Option<CatalogArtifact>) -> Option<CatalogArtifact> {
    catalog.map(|mut catalog| {
        catalog.server_info = None;
        catalog.capabilities = None;
        catalog.tools = None;
        catalog.resources = None;
        catalog.resource_templates = None;
        catalog.prompts = None;
        catalog
    })
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
            report.resource_templates = None;
            report.prompts = None;
            report.trace = None;
            report.auth = summarize_auth(report.auth);
            report.catalog = summarize_catalog(report.catalog);
            report
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_artifact_redacts_and_summarizes() {
        let server_info = json!({"name": "server"});
        let capabilities = json!({"tools": {}});
        let tools = json!({
            "tools": [{
                "name": "secret_tool",
                "_meta": {
                    "authorization": "Bearer should-not-survive",
                    "description": "call with token sk-live-secret"
                }
            }]
        });

        let artifact = build_catalog_artifact(
            "2026-06-20T00:00:00Z".to_string(),
            vec![CatalogMethodSummary {
                method: "tools/list".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                page_count: Some(2),
                item_count: Some(3),
            }],
            None,
            None,
            CatalogPayloadRefs {
                server_info: Some(&server_info),
                capabilities: Some(&capabilities),
                tools: Some(&tools),
                ..CatalogPayloadRefs::default()
            },
        );

        let rendered = serde_json::to_string(&artifact).expect("serialize artifact");
        assert!(!rendered.contains("Bearer should-not-survive"));
        assert!(!rendered.contains("sk-live-secret"));
        assert_eq!(artifact.methods[0].page_count, Some(2));

        let summarized = summarize_catalog(Some(artifact)).expect("summary artifact");
        assert!(summarized.tools.is_none());
        assert_eq!(summarized.methods[0].item_count, Some(3));
    }
}
