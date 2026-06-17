//! Validation helpers for scripted scenarios.

use crate::scenario::types::{ScriptScenario, ScriptScenarioSummary, ScriptStep};
use crate::transport::TransportType;
use std::path::{Path, PathBuf};

/// Resolve a stable step key from id/name/tool fields.
pub fn resolve_step_key(step: &ScriptStep, index: usize) -> String {
    step.id
        .clone()
        .or_else(|| step.name.clone())
        .unwrap_or_else(|| format!("{}-{}", step.tool, index + 1))
}

/// Validate a scenario configuration for required fields.
pub fn validate_scenario(scenario: &ScriptScenario) -> anyhow::Result<()> {
    if scenario.steps.is_empty() {
        return Err(anyhow::anyhow!("Scenario must include at least one step."));
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
