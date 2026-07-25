//! Validation helpers for scripted scenarios.

use crate::scenario::types::{
    ScenarioExpectError, ScenarioSnapshot, ScriptScenario, ScriptScenarioSummary, ScriptStep,
};
use crate::transport::TransportType;
use std::path::{Path, PathBuf};

/// Resolve a stable step key from id/name/tool fields.
pub fn resolve_step_key(step: &ScriptStep, index: usize) -> String {
    step.id
        .clone()
        .or_else(|| step.name.clone())
        .unwrap_or_else(|| {
            let mut key = step.tool.clone();
            key.push('-');
            key.push_str(&(index + 1).to_string());
            key
        })
}

fn step_has_assertion(step: &ScriptStep) -> bool {
    step.expect.is_some()
        || matches!(
            step.expect_error.as_ref(),
            Some(ScenarioExpectError::Bool(true) | ScenarioExpectError::String(_))
        )
        || matches!(
            step.snapshot.as_ref(),
            Some(ScenarioSnapshot::Bool(true) | ScenarioSnapshot::String(_))
        )
}

/// Validate a scenario configuration for required fields.
pub fn validate_scenario(scenario: &ScriptScenario) -> anyhow::Result<()> {
    if scenario.steps.is_empty() {
        return Err(anyhow::anyhow!("Scenario must include at least one step."));
    }
    for (index, step) in scenario.steps.iter().enumerate() {
        if !step_has_assertion(step) {
            let step_key = resolve_step_key(step, index);
            return Err(anyhow::anyhow!(
                "Scenario step \"{step_key}\" must include expect, expect_error=true, \
                 expect_error=<matcher>, snapshot=true, or snapshot=<key>. Use \
                 probe_call_tool for an execution-only tool call."
            ));
        }
    }
    match scenario.transport {
        TransportType::Stdio => {
            if scenario.command.is_none() {
                return Err(anyhow::anyhow!(
                    "Scenario missing command for stdio transport."
                ));
            }
        }
        _ => {
            if scenario.url.is_none() {
                return Err(anyhow::anyhow!("Scenario missing URL for HTTP transport."));
            }
        }
    }
    Ok(())
}

/// Resolve the snapshot path for a scenario.
pub fn resolve_snapshot_path(
    scenario: &ScriptScenario,
    scenario_path: Option<&str>,
) -> Option<PathBuf> {
    if let Some(snapshot_path) = scenario.snapshot_path.as_deref() {
        if let Some(scenario_path) = scenario_path {
            let base = Path::new(scenario_path)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            return Some(base.join(snapshot_path));
        }
        return Some(PathBuf::from(snapshot_path));
    }
    scenario_path.map(|path| PathBuf::from(format!("{path}.snapshots.json")))
}

/// Return true if any step uses snapshots.
pub fn uses_snapshots(scenario: &ScriptScenario) -> bool {
    scenario.steps.iter().any(|step| step.snapshot.is_some())
}

/// Build a scenario summary for reports.
pub fn build_scenario_summary(
    scenario: &ScriptScenario,
    scenario_path: Option<&str>,
    snapshot_path: Option<&Path>,
) -> ScriptScenarioSummary {
    ScriptScenarioSummary {
        name: scenario.name.clone(),
        description: scenario.description.clone(),
        path: scenario_path.map(|value| value.to_string()),
        snapshot_path: snapshot_path.map(|value| value.to_string_lossy().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_scenario;
    use crate::scenario::types::{
        ScenarioExpectError, ScenarioSnapshot, ScriptScenario, ScriptStep,
    };
    use crate::transport::TransportType;
    use serde_json::json;

    fn scenario_with_step(step: ScriptStep) -> ScriptScenario {
        ScriptScenario {
            name: None,
            description: None,
            transport: TransportType::Stdio,
            command: Some("example-mcp".to_string()),
            args: None,
            cwd: None,
            env: None,
            url: None,
            headers: None,
            timeout_ms: None,
            retries: None,
            retry_delay_ms: None,
            log_level: None,
            log_format: None,
            use_auth: None,
            access_token: None,
            access_token_path: None,
            refresh_token: None,
            refresh_token_path: None,
            client_id: None,
            client_secret: None,
            token_endpoint: None,
            scope: None,
            steps: vec![step],
            snapshot_path: None,
            ignore_paths: None,
        }
    }

    fn step() -> ScriptStep {
        ScriptStep {
            id: Some("status".to_string()),
            name: None,
            tool: "status.get".to_string(),
            input: None,
            expect: None,
            expect_error: None,
            snapshot: None,
            ignore_paths: None,
        }
    }

    #[test]
    fn rejects_unasserted_steps_before_connecting() {
        let error = validate_scenario(&scenario_with_step(step()))
            .expect_err("unasserted scripted step must fail closed");

        let detail = error.to_string();
        assert!(detail.contains("Scenario step \"status\""));
        assert!(detail.contains("must include expect"));
        assert!(detail.contains("probe_call_tool"));
    }

    #[test]
    fn false_expect_error_and_snapshot_flags_are_not_assertions() {
        let mut expect_error_false = step();
        expect_error_false.expect_error = Some(ScenarioExpectError::Bool(false));
        assert!(validate_scenario(&scenario_with_step(expect_error_false)).is_err());

        let mut snapshot_false = step();
        snapshot_false.snapshot = Some(ScenarioSnapshot::Bool(false));
        assert!(validate_scenario(&scenario_with_step(snapshot_false)).is_err());
    }

    #[test]
    fn accepts_explicit_value_error_and_snapshot_assertions() {
        let mut expected_value = step();
        expected_value.expect = Some(json!({"ok": true}));
        assert!(validate_scenario(&scenario_with_step(expected_value)).is_ok());

        let mut expected_error = step();
        expected_error.expect_error = Some(ScenarioExpectError::Bool(true));
        assert!(validate_scenario(&scenario_with_step(expected_error)).is_ok());

        let mut expected_snapshot = step();
        expected_snapshot.snapshot = Some(ScenarioSnapshot::Bool(true));
        assert!(validate_scenario(&scenario_with_step(expected_snapshot)).is_ok());
    }
}
