use mcp_toolkit_observability::redaction::redact_telemetry_text;
use serde_json::Value;

/// Structured summary of an error for probe step reporting.
#[derive(Debug, Clone)]
pub struct ErrorDetails {
    pub message: String,
    pub data: Option<Value>,
}

fn redact_text(value: &str) -> String {
    redact_telemetry_text(value)
}

/// Summarize an error into a message and optional structured data.
pub fn describe_error(error: &anyhow::Error) -> ErrorDetails {
    let message = redact_text(&error.to_string());
    let mut data = serde_json::Map::new();
    if let Some(source) = error.source() {
        data.insert(
            "cause".to_string(),
            Value::String(redact_text(&source.to_string())),
        );
    }
    data.insert(
        "raw".to_string(),
        Value::String(redact_text(&format!("{error:?}"))),
    );
    let data = if data.is_empty() {
        None
    } else {
        Some(Value::Object(data))
    };
    ErrorDetails { message, data }
}

/// Extract optional error data for probe step payloads.
pub fn error_data(details: &ErrorDetails) -> Option<Value> {
    details.data.clone()
}
