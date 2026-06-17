//! Scripted scenario runner for MCP tool calls.

use crate::allowlist::{enforce_stdio_allowlist, parse_allowed_hosts_env};
use crate::logging::{stderr_logger, LogFormat, LogLevel, Logger};
use crate::probe::connect::connect_with_retry;
use crate::probe::options::resolve_probe_options;
use crate::report::{now_iso, ProbeStep, ProbeStepStatus};
use crate::scenario::allowlist::enforce_host_allowlist;
use crate::scenario::auth::{resolve_auth_headers, AuthHeaderResult, ScenarioAuthInput};
use crate::scenario::compare::{
    apply_redactions, diff_objects, filter_diff_entries, format_diff, resolve_ignore_patterns,
    DiffEntry,
};
use crate::scenario::options::resolve_scenario_timing;
use crate::scenario::snapshots::{load_snapshots, save_snapshots, SnapshotFile};
use crate::scenario::timing::{with_retry, with_timeout};
use crate::scenario::types::{
    ScenarioExpectError, ScenarioSnapshot, ScriptClientInfo, ScriptReport, ScriptRunOptions,
    ScriptScenario, ScriptStep,
};
use crate::scenario::validation::{
    build_scenario_summary, resolve_snapshot_path, resolve_step_key, uses_snapshots,
    validate_scenario,
};
use rmcp::model::CallToolRequestParams;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;

const DEFAULT_CLIENT_NAME: &str = "mcp-toolkit-client";
const DEFAULT_CLIENT_VERSION: &str = "0.0.0";

fn scenario_logger(log_level: Option<LogLevel>, log_format: Option<LogFormat>) -> Option<Logger> {
    log_level.map(|level| {
        let format = log_format.unwrap_or(LogFormat::Json);
        stderr_logger(level, format)
    })
}

fn resolve_expect_error(expect_error: &Option<ScenarioExpectError>) -> (bool, Option<&str>) {
    match expect_error {
        None => (false, None),
        Some(ScenarioExpectError::Bool(false)) => (false, None),
        Some(ScenarioExpectError::Bool(true)) => (true, None),
        Some(ScenarioExpectError::String(value)) => (true, Some(value.as_str())),
    }
}

fn snapshot_key(step: &ScriptStep, step_key: &str) -> Option<String> {
    match step.snapshot.as_ref()? {
        ScenarioSnapshot::Bool(true) => Some(step_key.to_string()),
        ScenarioSnapshot::Bool(false) => None,
        ScenarioSnapshot::String(value) => Some(value.clone()),
    }
}

fn format_error(error: anyhow::Error) -> String {
    error.to_string()
}

fn format_tool_is_error_detail(actual: Option<&Value>) -> String {
    let mut detail = "Tool returned isError=true".to_string();
    if let Some(actual) = actual {
        if let Ok(serialized) = serde_json::to_string(actual) {
            detail.push_str(": ");
            detail.push_str(&serialized);
        }
    }
    detail
}

fn normalize_value(value: &Value, ignore_paths: &[String]) -> Value {
    apply_redactions(value.clone(), ignore_paths)
}

fn build_diff(
    expected: &Value,
    actual: &Value,
    ignore_paths: &[String],
) -> (Vec<DiffEntry>, Option<String>) {
    let diffs = filter_diff_entries(diff_objects(expected, actual), ignore_paths);
    let detail = format_diff(&diffs);
    (diffs, detail)
}

/// Run a scripted scenario and return a structured report.
///
/// # Errors
/// Does not return errors; failures are encoded in the report steps.
pub async fn run_script_scenario(
    scenario: ScriptScenario,
    options: ScriptRunOptions,
) -> ScriptReport {
    let started_at = now_iso();
    let mut steps: Vec<ProbeStep> = Vec::new();
    let allowed_hosts = parse_allowed_hosts_env();

    if let Err(err) = validate_scenario(&scenario) {
        steps.push(ProbeStep {
            name: "script".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format_error(err)),
            data: None,
        });
        return ScriptReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            scenario: Some(build_scenario_summary(
                &scenario,
                options.scenario_path.as_deref(),
                None,
            )),
        };
    }

    let stdio_ok = enforce_stdio_allowlist(scenario.transport.as_str(), &mut steps);
    let allowlist_ok = if stdio_ok {
        enforce_host_allowlist(
            scenario.transport,
            scenario.url.as_deref(),
            &mut steps,
            allowed_hosts.as_deref(),
        )
    } else {
        false
    };
    if !stdio_ok || !allowlist_ok {
        return ScriptReport {
            ok: false,
            started_at,
            finished_at: now_iso(),
            steps,
            scenario: Some(build_scenario_summary(
                &scenario,
                options.scenario_path.as_deref(),
                None,
            )),
        };
    }

    let (timeout_ms, retries, retry_delay_ms) = resolve_scenario_timing(
        scenario.timeout_ms,
        scenario.retries,
        scenario.retry_delay_ms,
    );

    let mut logger = scenario_logger(scenario.log_level, scenario.log_format);

    let auth_input = ScenarioAuthInput {
        transport: scenario.transport,
        url: scenario.url.clone(),
        headers: scenario.headers.clone(),
        use_auth: scenario.use_auth,
        access_token: scenario.access_token.clone(),
        access_token_path: scenario.access_token_path.clone(),
        refresh_token: scenario.refresh_token.clone(),
        refresh_token_path: scenario.refresh_token_path.clone(),
        client_id: scenario.client_id.clone(),
        client_secret: scenario.client_secret.clone(),
        token_endpoint: scenario.token_endpoint.clone(),
        scope: scenario.scope.clone(),
        timeout_ms: scenario.timeout_ms,
    };

    let headers = match resolve_auth_headers(&auth_input).await {
        AuthHeaderResult::Ok(headers) => headers,
        AuthHeaderResult::Err(detail) => {
            steps.push(ProbeStep {
                name: "auth".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(detail),
                data: None,
            });
            return ScriptReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                scenario: Some(build_scenario_summary(
                    &scenario,
                    options.scenario_path.as_deref(),
                    None,
                )),
            };
        }
    };

    let mut snapshot_path: Option<PathBuf> = None;
    if uses_snapshots(&scenario) {
        snapshot_path = resolve_snapshot_path(&scenario, options.scenario_path.as_deref());
        if snapshot_path.is_none() {
            steps.push(ProbeStep {
                name: "snapshot".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some("snapshot_path is required when using snapshots".to_string()),
                data: None,
            });
            return ScriptReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                scenario: Some(build_scenario_summary(
                    &scenario,
                    options.scenario_path.as_deref(),
                    None,
                )),
            };
        }
    }

    let mut snapshots = if let Some(path) = snapshot_path.as_ref() {
        load_snapshots(path).await
    } else {
        SnapshotFile {
            version: 1,
            snapshots: std::collections::BTreeMap::new(),
        }
    };
    let mut snapshot_updated = false;

    let probe_options =
        resolve_probe_options(Some(timeout_ms), Some(retries), Some(retry_delay_ms));
    let client_info = options.client_info.unwrap_or_else(|| ScriptClientInfo {
        name: DEFAULT_CLIENT_NAME.to_string(),
        version: DEFAULT_CLIENT_VERSION.to_string(),
    });

    let connect_result = connect_with_retry(
        scenario.transport,
        scenario.command.as_deref(),
        scenario.args.as_deref(),
        scenario.cwd.as_deref(),
        scenario.env.as_ref(),
        scenario.url.as_deref(),
        headers.as_ref(),
        probe_options,
        false,
        None,
        None,
        &client_info.name,
        &client_info.version,
    )
    .await;

    let mut connection = match connect_result {
        Ok(connection) => {
            steps.push(ProbeStep {
                name: "connect".to_string(),
                status: ProbeStepStatus::Ok,
                detail: None,
                data: None,
            });
            if let Some(logger) = logger.as_mut() {
                logger.info("script.connect.ok", None);
            }
            connection
        }
        Err(error) => {
            steps.push(ProbeStep {
                name: "connect".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(format_error(error)),
                data: None,
            });
            if let Some(logger) = logger.as_mut() {
                logger.error("script.connect.error", None);
            }
            return ScriptReport {
                ok: false,
                started_at,
                finished_at: now_iso(),
                steps,
                scenario: Some(build_scenario_summary(
                    &scenario,
                    options.scenario_path.as_deref(),
                    snapshot_path.as_deref(),
                )),
            };
        }
    };

    let peer = connection.service.peer().clone();

    for (index, step) in scenario.steps.iter().enumerate() {
        let step_key = resolve_step_key(step, index);
        let step_name = format!("tool.{}", step_key);
        let ignore_paths = resolve_ignore_patterns(
            scenario.ignore_paths.as_deref(),
            step.ignore_paths.as_deref(),
        );
        let snapshot_key = snapshot_key(step, &step_key);

        let input_map: HashMap<String, Value> = step.input.clone().unwrap_or_default();
        let arguments: serde_json::Map<String, Value> = input_map.clone().into_iter().collect();
        let label = format!("tools.call:{}", step.tool);

        let call_result = with_retry(
            || {
                let params = CallToolRequestParams::new(Cow::Owned(step.tool.clone()))
                    .with_arguments(arguments.clone());
                with_timeout(peer.call_tool(params), timeout_ms, &label)
            },
            retries,
            retry_delay_ms,
        )
        .await;

        let mut call_error: Option<String> = None;
        let mut call_value: Option<Value> = None;

        match call_result {
            Ok(result) => {
                call_value = serde_json::to_value(&result).ok();
                if result.is_error.unwrap_or(false) {
                    call_error = Some(format_tool_is_error_detail(call_value.as_ref()));
                }
            }
            Err(err) => {
                call_error = Some(format_error(err));
            }
        }

        let redacted_actual = call_value
            .as_ref()
            .map(|value| normalize_value(value, &ignore_paths));

        let mut expected = step.expect.clone();
        let mut snapshot_written = false;
        let mut diff_entries: Vec<DiffEntry> = Vec::new();
        let mut diff_detail: Option<String> = None;

        if expected.is_none() {
            if let Some(snapshot_key) = snapshot_key.as_ref() {
                if let Some(snapshot) = snapshots.snapshots.get(snapshot_key).cloned() {
                    expected = Some(snapshot);
                } else if options.snapshot_write {
                    let value = redacted_actual.clone().unwrap_or(Value::Null);
                    snapshots.snapshots.insert(snapshot_key.clone(), value);
                    expected = redacted_actual.clone();
                    snapshot_updated = true;
                    snapshot_written = true;
                } else {
                    call_error =
                        call_error.or_else(|| Some(format!("Missing snapshot for {snapshot_key}")));
                }
            }
        }

        let redacted_expected = expected
            .as_ref()
            .map(|value| normalize_value(value, &ignore_paths));

        let (expect_error, expect_match) = resolve_expect_error(&step.expect_error);

        let mut status = ProbeStepStatus::Ok;
        let mut detail: Option<String> = None;

        if expect_error {
            if call_error.is_none() {
                status = ProbeStepStatus::Error;
                detail = Some("Expected tool call to fail but it succeeded".to_string());
            } else if let Some(matcher) = expect_match {
                if let Some(error) = call_error.as_ref() {
                    if !error.contains(matcher) {
                        status = ProbeStepStatus::Error;
                        detail = Some(format!("Expected error containing \"{matcher}\""));
                    }
                }
            }
        } else if let Some(error) = call_error.as_ref() {
            status = ProbeStepStatus::Error;
            detail = Some(error.clone());
        } else if let (Some(expected), Some(actual)) =
            (redacted_expected.as_ref(), redacted_actual.as_ref())
        {
            let (diffs, diff_text) = build_diff(expected, actual, &ignore_paths);
            diff_entries = diffs;
            diff_detail = diff_text.clone();
            if !diff_entries.is_empty() {
                status = ProbeStepStatus::Error;
                detail = diff_text;
                if options.snapshot_write {
                    if let Some(snapshot_key) = snapshot_key.as_ref() {
                        snapshots
                            .snapshots
                            .insert(snapshot_key.clone(), actual.clone());
                        snapshot_updated = true;
                        snapshot_written = true;
                        status = ProbeStepStatus::Ok;
                        detail = Some("Snapshot updated".to_string());
                    }
                }
            }
        } else {
            detail = Some("No assertion provided".to_string());
        }

        let mut step_data = serde_json::Map::new();
        step_data.insert("tool".to_string(), Value::String(step.tool.clone()));
        step_data.insert("input".to_string(), Value::Object(arguments.clone()));
        if let Some(expected) = redacted_expected.as_ref() {
            step_data.insert("expected".to_string(), expected.clone());
        }
        if let Some(actual) = redacted_actual.as_ref() {
            step_data.insert("actual".to_string(), actual.clone());
        }
        step_data.insert(
            "diff".to_string(),
            serde_json::to_value(&diff_entries).unwrap_or(Value::Null),
        );
        if let Some(diff_text) = diff_detail {
            step_data.insert("diff_text".to_string(), Value::String(diff_text));
        }
        if let Some(snapshot_key) = snapshot_key.as_ref() {
            step_data.insert(
                "snapshot_key".to_string(),
                Value::String(snapshot_key.clone()),
            );
        }
        step_data.insert(
            "snapshot_written".to_string(),
            Value::Bool(snapshot_written),
        );
        if !ignore_paths.is_empty() {
            step_data.insert(
                "ignore_paths".to_string(),
                serde_json::to_value(ignore_paths.clone()).unwrap_or(Value::Null),
            );
        }
        if expect_error {
            step_data.insert(
                "expect_error".to_string(),
                serde_json::to_value(step.expect_error.clone()).unwrap_or(Value::Null),
            );
        }
        if let Some(error) = call_error {
            step_data.insert("error".to_string(), serde_json::json!({ "message": error }));
        }

        steps.push(ProbeStep {
            name: step_name,
            status,
            detail,
            data: Some(Value::Object(step_data)),
        });
    }

    match connection.service.close().await {
        Ok(_) => steps.push(ProbeStep {
            name: "disconnect".to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        }),
        Err(err) => steps.push(ProbeStep {
            name: "disconnect".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(err.to_string()),
            data: None,
        }),
    }

    if let Some(path) = snapshot_path.as_ref() {
        if snapshot_updated {
            if let Err(err) = save_snapshots(path, &snapshots).await {
                steps.push(ProbeStep {
                    name: "snapshot.save".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(err.to_string()),
                    data: None,
                });
            }
        }
    }

    let ok = steps.iter().all(|step| step.status == ProbeStepStatus::Ok);
    ScriptReport {
        ok,
        started_at,
        finished_at: now_iso(),
        steps,
        scenario: Some(build_scenario_summary(
            &scenario,
            options.scenario_path.as_deref(),
            snapshot_path.as_deref(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::format_tool_is_error_detail;
    use serde_json::json;

    #[test]
    fn tool_is_error_detail_includes_serialized_payload_when_available() {
        let detail = format_tool_is_error_detail(Some(&json!({
            "isError": true,
            "structuredContent": {
                "error": {
                    "code": "approval.no_content"
                }
            }
        })));
        assert!(detail.contains("Tool returned isError=true"));
        assert!(detail.contains("approval.no_content"));
    }

    #[test]
    fn tool_is_error_detail_defaults_when_payload_is_missing() {
        assert_eq!(
            format_tool_is_error_detail(None),
            "Tool returned isError=true".to_string()
        );
    }
}
