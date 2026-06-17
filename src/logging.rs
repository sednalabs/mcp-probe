use mcp_toolkit_observability::redaction::{
    redact_json_keys, redact_telemetry_text, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Log levels for probe diagnostics.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    #[serde(alias = "warning")]
    Warn,
    Error,
}

impl LogLevel {
    /// Parse a log level string (debug|info|warn|error).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    fn level_value(self) -> u8 {
        match self {
            Self::Debug => 10,
            Self::Info => 20,
            Self::Warn => 30,
            Self::Error => 40,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Output format for probe logs.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    #[serde(alias = "text")]
    Logfmt,
}

impl LogFormat {
    /// Parse a log format string (json|logfmt|text).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "logfmt" | "text" => Some(Self::Logfmt),
            _ => None,
        }
    }
}

/// Lightweight structured logger with redaction.
pub struct Logger {
    level: LogLevel,
    format: LogFormat,
    writer: Box<dyn Write + Send>,
}

impl Logger {
    /// Create a new logger writing to the provided sink.
    pub fn new(level: LogLevel, format: LogFormat, writer: Box<dyn Write + Send>) -> Self {
        Self {
            level,
            format,
            writer,
        }
    }

    /// Return true when the provided level should be emitted.
    pub fn enabled(&self, level: LogLevel) -> bool {
        level.level_value() >= self.level.level_value()
    }

    /// Emit an info-level log entry.
    pub fn info(&mut self, message: &str, extra: Option<Value>) {
        self.log(LogLevel::Info, message, extra);
    }

    /// Emit a warn-level log entry.
    pub fn warn(&mut self, message: &str, extra: Option<Value>) {
        self.log(LogLevel::Warn, message, extra);
    }

    /// Emit an error-level log entry.
    pub fn error(&mut self, message: &str, extra: Option<Value>) {
        self.log(LogLevel::Error, message, extra);
    }

    /// Emit a debug-level log entry.
    pub fn debug(&mut self, message: &str, extra: Option<Value>) {
        self.log(LogLevel::Debug, message, extra);
    }

    /// Emit a log entry at the requested level.
    pub fn log(&mut self, level: LogLevel, message: &str, extra: Option<Value>) {
        if !self.enabled(level) {
            return;
        }
        let timestamp = unix_timestamp_ms();
        let sanitized_message = redact_telemetry_text(message);
        let sanitized_extra = extra.map(sanitize_extra);
        let payload = match self.format {
            LogFormat::Json => format_json(timestamp, level, &sanitized_message, sanitized_extra),
            LogFormat::Logfmt => {
                format_logfmt(timestamp, level, &sanitized_message, sanitized_extra)
            }
        };
        let _ = writeln!(self.writer, "{payload}");
    }
}

fn unix_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn sanitize_extra(mut extra: Value) -> Value {
    if let Value::Object(_) = extra {
        redact_json_keys(&mut extra, DEFAULT_REDACT_KEYS, DEFAULT_REDACT_VALUE);
    }
    extra
}

fn format_json(timestamp: u128, level: LogLevel, message: &str, extra: Option<Value>) -> String {
    let mut record = serde_json::json!({
        "ts": timestamp,
        "level": level.as_str(),
        "msg": message,
    });
    if let Some(extra) = extra {
        if let Value::Object(map) = extra {
            if let Value::Object(ref mut base) = record {
                for (key, value) in map {
                    base.insert(key, value);
                }
            }
        } else if let Value::Object(ref mut base) = record {
            base.insert("data".to_string(), extra);
        }
    }
    record.to_string()
}

fn format_logfmt(timestamp: u128, level: LogLevel, message: &str, extra: Option<Value>) -> String {
    let mut parts = vec![
        format!("ts={timestamp}"),
        format!("level={}", level.as_str()),
        format!("msg={}", escape_logfmt(message)),
    ];
    if let Some(extra) = extra {
        if let Value::Object(map) = extra {
            for (key, value) in map {
                parts.push(format!("{}={}", key, escape_logfmt(&value.to_string())));
            }
        } else {
            parts.push(format!("data={}", escape_logfmt(&extra.to_string())));
        }
    }
    parts.join(" ")
}

fn escape_logfmt(value: &str) -> String {
    if value.contains(' ') || value.contains('"') || value.contains('=') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Build a logger that writes to stderr.
pub fn stderr_logger(level: LogLevel, format: LogFormat) -> Logger {
    Logger::new(level, format, Box::new(io::stderr()))
}
