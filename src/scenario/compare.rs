//! Snapshot comparison helpers for scripted scenarios.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const REDACTED_VALUE: &str = "[ignored]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathToken {
    Key(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternToken {
    Key(String),
    Index(usize),
    Wildcard,
}

/// Difference entry emitted when snapshot comparison fails.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct DiffEntry {
    pub path: String,
    pub expected: Value,
    pub actual: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<DiffKind>,
}

/// Classifier for missing values in diffs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DiffKind {
    MissingExpected,
    MissingActual,
}

fn path_to_string(tokens: &[PathToken]) -> String {
    if tokens.is_empty() {
        return "$".to_string();
    }
    let mut out = String::from("$");
    for token in tokens {
        match token {
            PathToken::Key(key) => {
                out.push('.');
                out.push_str(key);
            }
            PathToken::Index(index) => {
                out.push('[');
                out.push_str(&index.to_string());
                out.push(']');
            }
        }
    }
    out
}

fn parse_pattern(pattern: &str) -> Vec<PatternToken> {
    let mut tokens = Vec::new();
    let mut buffer = String::new();
    let mut chars = pattern.chars().peekable();

    let flush = |buf: &mut String, tokens: &mut Vec<PatternToken>| {
        if buf.is_empty() {
            return;
        }
        if buf == "*" {
            tokens.push(PatternToken::Wildcard);
        } else {
            tokens.push(PatternToken::Key(buf.clone()));
        }
        buf.clear();
    };

    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                flush(&mut buffer, &mut tokens);
            }
            '[' => {
                flush(&mut buffer, &mut tokens);
                let mut inside = String::new();
                for next in chars.by_ref() {
                    if next == ']' {
                        break;
                    }
                    inside.push(next);
                }
                if inside.is_empty() || inside == "*" {
                    tokens.push(PatternToken::Wildcard);
                } else if let Ok(index) = inside.parse::<usize>() {
                    tokens.push(PatternToken::Index(index));
                } else {
                    tokens.push(PatternToken::Key(inside));
                }
            }
            _ => buffer.push(ch),
        }
    }
    flush(&mut buffer, &mut tokens);
    tokens
}

fn matches_pattern(path: &[PathToken], pattern: &[PatternToken]) -> bool {
    if pattern.len() > path.len() {
        return false;
    }
    for (i, pattern_token) in pattern.iter().enumerate() {
        let path_token = match path.get(i) {
            Some(token) => token,
            None => return false,
        };
        match (pattern_token, path_token) {
            (PatternToken::Wildcard, _) => continue,
            (PatternToken::Key(lhs), PathToken::Key(rhs)) if lhs == rhs => continue,
            (PatternToken::Index(lhs), PathToken::Index(rhs)) if lhs == rhs => continue,
            _ => return false,
        }
    }
    true
}

fn compile_patterns(patterns: &[String]) -> Vec<Vec<PatternToken>> {
    patterns
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .map(parse_pattern)
        .collect()
}

fn should_redact(path: &[PathToken], compiled: &[Vec<PatternToken>]) -> bool {
    compiled
        .iter()
        .any(|pattern| matches_pattern(path, pattern))
}

fn parse_path(path: &str) -> Vec<PathToken> {
    let mut tokens = Vec::new();
    let mut i = if path.starts_with('$') { 1 } else { 0 };
    let chars: Vec<char> = path.chars().collect();
    while i < chars.len() {
        match chars[i] {
            '.' => {
                i += 1;
                let mut buffer = String::new();
                while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                    buffer.push(chars[i]);
                    i += 1;
                }
                if !buffer.is_empty() {
                    tokens.push(PathToken::Key(buffer));
                }
            }
            '[' => {
                i += 1;
                let mut buffer = String::new();
                while i < chars.len() && chars[i] != ']' {
                    buffer.push(chars[i]);
                    i += 1;
                }
                i += 1;
                if buffer.is_empty() {
                    continue;
                }
                if let Ok(index) = buffer.parse::<usize>() {
                    tokens.push(PathToken::Index(index));
                } else {
                    tokens.push(PathToken::Key(buffer));
                }
            }
            _ => i += 1,
        }
    }
    tokens
}

/// Apply redactions to a JSON value based on ignore patterns.
pub fn apply_redactions(value: Value, ignore_patterns: &[String]) -> Value {
    if ignore_patterns.is_empty() {
        return value;
    }
    let compiled = compile_patterns(ignore_patterns);

    fn walk(current: Value, path: &mut Vec<PathToken>, compiled: &[Vec<PatternToken>]) -> Value {
        if should_redact(path, compiled) {
            return Value::String(REDACTED_VALUE.to_string());
        }
        match current {
            Value::Array(values) => {
                let items = values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        path.push(PathToken::Index(index));
                        let next = walk(value, path, compiled);
                        path.pop();
                        next
                    })
                    .collect();
                Value::Array(items)
            }
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, value) in map.into_iter() {
                    path.push(PathToken::Key(key.clone()));
                    let next = walk(value, path, compiled);
                    path.pop();
                    out.insert(key, next);
                }
                Value::Object(out)
            }
            other => other,
        }
    }

    walk(value, &mut Vec::new(), &compiled)
}

/// Compute diffs between two JSON values.
pub fn diff_objects(expected: &Value, actual: &Value) -> Vec<DiffEntry> {
    let mut diffs = Vec::new();

    fn walk(
        expected: &Value,
        actual: &Value,
        path: &mut Vec<PathToken>,
        diffs: &mut Vec<DiffEntry>,
    ) {
        if expected == actual {
            return;
        }
        match (expected, actual) {
            (Value::Array(expected), Value::Array(actual)) => {
                let max_len = expected.len().max(actual.len());
                for index in 0..max_len {
                    path.push(PathToken::Index(index));
                    if index >= expected.len() {
                        diffs.push(DiffEntry {
                            path: path_to_string(path),
                            expected: Value::Null,
                            actual: actual.get(index).cloned().unwrap_or(Value::Null),
                            kind: Some(DiffKind::MissingExpected),
                        });
                    } else if index >= actual.len() {
                        diffs.push(DiffEntry {
                            path: path_to_string(path),
                            expected: expected.get(index).cloned().unwrap_or(Value::Null),
                            actual: Value::Null,
                            kind: Some(DiffKind::MissingActual),
                        });
                    } else {
                        walk(&expected[index], &actual[index], path, diffs);
                    }
                    path.pop();
                }
            }
            (Value::Object(expected), Value::Object(actual)) => {
                let keys: std::collections::BTreeSet<&String> =
                    expected.keys().chain(actual.keys()).collect();
                for key in keys {
                    path.push(PathToken::Key(key.clone()));
                    let has_expected = expected.contains_key(key);
                    let has_actual = actual.contains_key(key);
                    match (has_expected, has_actual) {
                        (true, true) => {
                            let exp = expected.get(key).unwrap_or(&Value::Null);
                            let act = actual.get(key).unwrap_or(&Value::Null);
                            walk(exp, act, path, diffs);
                        }
                        (false, true) => {
                            diffs.push(DiffEntry {
                                path: path_to_string(path),
                                expected: Value::Null,
                                actual: actual.get(key).cloned().unwrap_or(Value::Null),
                                kind: Some(DiffKind::MissingExpected),
                            });
                        }
                        (true, false) => {
                            diffs.push(DiffEntry {
                                path: path_to_string(path),
                                expected: expected.get(key).cloned().unwrap_or(Value::Null),
                                actual: Value::Null,
                                kind: Some(DiffKind::MissingActual),
                            });
                        }
                        (false, false) => {}
                    }
                    path.pop();
                }
            }
            _ => diffs.push(DiffEntry {
                path: path_to_string(path),
                expected: expected.clone(),
                actual: actual.clone(),
                kind: None,
            }),
        }
    }

    walk(expected, actual, &mut Vec::new(), &mut diffs);
    diffs
}

/// Filter diff entries based on ignore patterns.
pub fn filter_diff_entries(entries: Vec<DiffEntry>, ignore_patterns: &[String]) -> Vec<DiffEntry> {
    if ignore_patterns.is_empty() {
        return entries;
    }
    let compiled = compile_patterns(ignore_patterns);
    entries
        .into_iter()
        .filter(|entry| {
            let tokens = parse_path(&entry.path);
            !should_redact(&tokens, &compiled)
        })
        .collect()
}

fn format_value(value: &Value, missing_kind: Option<&DiffKind>) -> String {
    if let Some(kind) = missing_kind {
        return match kind {
            DiffKind::MissingExpected | DiffKind::MissingActual => "[missing]".to_string(),
        };
    }
    match value {
        Value::String(text) => format!("\"{text}\""),
        Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    }
}

/// Format a list of diffs for human-readable output.
pub fn format_diff(entries: &[DiffEntry]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let lines: Vec<String> = entries
        .iter()
        .map(|entry| {
            let expected_missing = entry
                .kind
                .as_ref()
                .filter(|kind| matches!(kind, DiffKind::MissingExpected));
            let actual_missing = entry
                .kind
                .as_ref()
                .filter(|kind| matches!(kind, DiffKind::MissingActual));
            let expected = format_value(&entry.expected, expected_missing);
            let actual = format_value(&entry.actual, actual_missing);
            format!("- {}: expected {} got {}", entry.path, expected, actual)
        })
        .collect();
    Some(format!("Differences:\n{}", lines.join("\n")))
}

/// Merge ignore pattern lists, trimming empty entries.
pub fn resolve_ignore_patterns(base: Option<&[String]>, extra: Option<&[String]>) -> Vec<String> {
    let mut merged = Vec::new();
    if let Some(base) = base {
        merged.extend(base.iter().cloned());
    }
    if let Some(extra) = extra {
        merged.extend(extra.iter().cloned());
    }
    merged
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}
