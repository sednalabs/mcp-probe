use crate::report::{now_iso, TraceEntry};
use mcp_toolkit_observability::redaction::{
    redact_json_keys, redact_telemetry_text, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Collects redacted MCP trace entries with size limits.
///
/// Notes:
/// - Stores entries in memory only and drops the oldest when over limit.
/// - Redacts common secret keys and value patterns before recording.
#[derive(Clone)]
pub struct TraceCollector {
    entries: Arc<Mutex<Vec<TraceEntry>>>,
    limit: usize,
    max_bytes: usize,
}

impl TraceCollector {
    /// Create a new trace collector with entry and size limits.
    pub fn new(limit: usize, max_bytes: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            limit,
            max_bytes,
        }
    }

    /// Add a trace entry for the given direction and JSON-RPC message.
    pub fn add(&self, direction: &str, message: Value) {
        let (method, id) = summarize_trace_message(&message);
        let sanitized = sanitize_trace_message(message, self.max_bytes);
        let entry = TraceEntry {
            direction: direction.to_string(),
            timestamp: now_iso(),
            message: sanitized,
            method,
            id,
        };
        let mut guard = self.entries.lock().expect("trace lock");
        guard.push(entry);
        if guard.len() > self.limit {
            guard.remove(0);
        }
    }

    /// Return a snapshot of collected trace entries.
    pub fn entries(&self) -> Vec<TraceEntry> {
        self.entries.lock().expect("trace lock").clone()
    }
}

fn summarize_trace_message(message: &Value) -> (Option<String>, Option<Value>) {
    let Some(obj) = message.as_object() else {
        return (None, None);
    };
    let method = obj
        .get("method")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    let id = obj.get("id").cloned().and_then(|value| match value {
        Value::String(_) | Value::Number(_) => Some(value),
        _ => None,
    });
    (method, id)
}

fn sanitize_trace_message(mut message: Value, max_bytes: usize) -> Value {
    redact_json_keys(&mut message, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
    message = redact_strings(message);
    let serialized = serde_json::to_string(&message);
    match serialized {
        Ok(text) => {
            if text.len() <= max_bytes {
                message
            } else {
                Value::Object(
                    vec![
                        ("truncated".to_string(), Value::Bool(true)),
                        (
                            "bytes".to_string(),
                            Value::Number(serde_json::Number::from(text.len() as u64)),
                        ),
                        (
                            "preview".to_string(),
                            Value::String(text.chars().take(max_bytes).collect()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                )
            }
        }
        Err(err) => Value::Object(
            vec![
                ("truncated".to_string(), Value::Bool(true)),
                (
                    "preview".to_string(),
                    Value::String(format!("Unserializable trace payload: {err}")),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

fn redact_strings(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_telemetry_text(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_strings).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, redact_strings(value)))
                .collect(),
        ),
        other => other,
    }
}
