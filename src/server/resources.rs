//! MCP resource definitions for the probe server.

use crate::provenance::{build_attestation_envelope, RuntimeAdmissionExtension, RuntimeProvenance};
use crate::report::now_iso;
use crate::version::SERVER_NAME;
use mcp_toolkit_core::rmcp_models;
use rmcp::model::{RawResource, ReadResourceResult, Resource, ResourceContents};
use serde_json::Value;

pub const LOGGING_SCHEMA_URI: &str = "mcp-probe://logging/schema";
pub const STATUS_URI: &str = "mcp-probe://status";
pub const ATTEST_URI: &str = "mcp-probe://attest";

fn logging_schema() -> Value {
    serde_json::json!({
        "version": 1,
        "notes": [
            "All MCP log payloads include an `event` field.",
            "Payloads are redacted and size-capped before emission."
        ],
        "events": [
            {
                "name": "session.initialize",
                "fields": {
                    "protocol_version": "string",
                    "client_name": "string",
                    "client_version": "string"
                }
            },
            { "name": "session.initialized", "fields": {} },
            { "name": "session.disconnect", "fields": { "error": "boolean", "error_type": "string" } },
            {
                "name": "tool.call.start",
                "fields": { "tool_name": "string", "arg_keys": "string[]" }
            },
            {
                "name": "tool.call.error",
                "fields": {
                    "tool_name": "string",
                    "error": "string",
                    "reason": "string",
                    "retry_after_s": "number"
                }
            },
            {
                "name": "tool.call.finish",
                "fields": { "tool_name": "string", "duration_ms": "number", "error": "boolean" }
            },
            {
                "name": "discovery.tools.list.*",
                "fields": { "duration_ms": "number", "count": "number", "error": "boolean" }
            },
            {
                "name": "discovery.resources.list.*",
                "fields": { "duration_ms": "number", "count": "number", "error": "boolean" }
            },
            {
                "name": "discovery.resource_templates.list.*",
                "fields": { "duration_ms": "number", "count": "number", "error": "boolean" }
            },
            {
                "name": "discovery.prompts.list.*",
                "fields": { "duration_ms": "number", "count": "number", "error": "boolean" }
            },
            {
                "name": "resource.read.*",
                "fields": { "uri": "string", "duration_ms": "number", "error": "boolean" }
            },
            {
                "name": "resource.subscribe.*",
                "fields": { "uri": "string", "duration_ms": "number", "error": "boolean" }
            },
            {
                "name": "resource.unsubscribe.*",
                "fields": { "uri": "string", "duration_ms": "number", "error": "boolean" }
            },
            {
                "name": "prompt.render.*",
                "fields": { "prompt_name": "string", "duration_ms": "number", "error": "boolean" }
            }
        ]
    })
}

fn logging_resource() -> Resource {
    let raw = RawResource {
        uri: LOGGING_SCHEMA_URI.to_string(),
        name: "logging-schema".to_string(),
        title: Some("MCP logging schema".to_string()),
        description: Some(
            "Event names and payload shapes emitted via MCP logging notifications.".to_string(),
        ),
        mime_type: Some("application/json".to_string()),
        size: None,
        icons: None,
        meta: None,
    };
    Resource::new(raw, None)
}

fn status_resource() -> Resource {
    let raw = RawResource {
        uri: STATUS_URI.to_string(),
        name: "status".to_string(),
        title: Some("Status".to_string()),
        description: Some("Probe server status and runtime provenance (JSON).".to_string()),
        mime_type: Some("application/json".to_string()),
        size: None,
        icons: None,
        meta: None,
    };
    Resource::new(raw, None)
}

fn attest_resource() -> Resource {
    let raw = RawResource {
        uri: ATTEST_URI.to_string(),
        name: "attest".to_string(),
        title: Some("Build attestation".to_string()),
        description: Some("Fleet v2 attestation envelope for this running probe.".to_string()),
        mime_type: Some("application/json".to_string()),
        size: None,
        icons: None,
        meta: None,
    };
    Resource::new(raw, None)
}

pub fn list_resources() -> Vec<Resource> {
    vec![logging_resource(), status_resource(), attest_resource()]
}

pub fn read_resource(
    uri: &str,
    provenance: &RuntimeProvenance,
    runtime_admission: &RuntimeAdmissionExtension,
) -> Result<ReadResourceResult, rmcp::ErrorData> {
    match uri {
        LOGGING_SCHEMA_URI => {
            let payload = logging_schema();
            let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
            Ok(rmcp_models::read_resource_result(vec![
                ResourceContents::TextResourceContents {
                    uri: LOGGING_SCHEMA_URI.to_string(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ]))
        }
        STATUS_URI => {
            let payload = serde_json::json!({
                "status": "ok",
                "server": SERVER_NAME,
                "version": provenance.build.server_version,
                "timestamp": now_iso(),
                "provenance": provenance,
                "startup_admission": runtime_admission,
            });
            let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
            Ok(rmcp_models::read_resource_result(vec![
                ResourceContents::TextResourceContents {
                    uri: STATUS_URI.to_string(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ]))
        }
        ATTEST_URI => {
            let payload = build_attestation_envelope(provenance, runtime_admission);
            let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
            Ok(rmcp_models::read_resource_result(vec![
                ResourceContents::TextResourceContents {
                    uri: ATTEST_URI.to_string(),
                    mime_type: Some("application/json".to_string()),
                    text,
                    meta: None,
                },
            ]))
        }
        other => Err(rmcp::ErrorData::resource_not_found(
            "resource_not_found",
            Some(serde_json::json!({ "uri": other })),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{list_resources, read_resource, ATTEST_URI, STATUS_URI};
    use crate::provenance::{capture_runtime_provenance, RuntimeAdmissionExtension};
    use serde_json::Value;

    fn sample_provenance() -> crate::provenance::RuntimeProvenance {
        let exe = std::env::current_exe().expect("resolve test executable path");
        capture_runtime_provenance(&exe)
    }

    fn sample_runtime_admission() -> RuntimeAdmissionExtension {
        RuntimeAdmissionExtension {
            enforcement_phase: "warn".to_string(),
            required_gate_level: "fast".to_string(),
            outcome: "passed".to_string(),
            reason_code: None,
            override_active: false,
        }
    }

    fn text_payload(payload: &rmcp::model::ReadResourceResult) -> &str {
        match &payload.contents[0] {
            rmcp::model::ResourceContents::TextResourceContents { text, .. } => text,
            _ => panic!("expected text resource payload"),
        }
    }

    #[test]
    fn list_resources_includes_attest_uri() {
        let resources = list_resources();
        assert!(
            resources
                .iter()
                .any(|resource| resource.raw.uri == ATTEST_URI),
            "attest resource URI should be listed"
        );
    }

    #[test]
    fn read_attest_resource_returns_v2_envelope() {
        let provenance = sample_provenance();
        let runtime_admission = sample_runtime_admission();
        let payload = read_resource(ATTEST_URI, &provenance, &runtime_admission)
            .expect("read attest resource");
        let parsed: Value =
            serde_json::from_str(text_payload(&payload)).expect("parse attest resource JSON");
        assert_eq!(
            parsed.get("schema_version").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            parsed
                .get("component")
                .and_then(Value::as_str)
                .map(str::to_string),
            Some(provenance.build.component.clone())
        );
        assert_eq!(
            parsed
                .get("extensions")
                .and_then(|value| value.get("runtime_admission"))
                .and_then(|value| value.get("outcome"))
                .and_then(Value::as_str),
            Some("passed")
        );
    }

    #[test]
    fn status_payload_embeds_runtime_provenance() {
        let provenance = sample_provenance();
        let runtime_admission = sample_runtime_admission();
        let payload = read_resource(STATUS_URI, &provenance, &runtime_admission)
            .expect("read status resource");
        let parsed: Value =
            serde_json::from_str(text_payload(&payload)).expect("parse status resource JSON");
        assert!(parsed.get("provenance").is_some());
        assert_eq!(
            parsed
                .get("provenance")
                .and_then(|value| value.get("build"))
                .and_then(|value| value.get("build_identity"))
                .and_then(Value::as_str),
            Some(provenance.build.build_identity.as_str())
        );
        assert_eq!(
            parsed
                .get("startup_admission")
                .and_then(|value| value.get("required_gate_level"))
                .and_then(Value::as_str),
            Some("fast")
        );
    }
}
