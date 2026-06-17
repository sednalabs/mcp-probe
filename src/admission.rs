//! Startup admission policy for test-gate enforcement.

use std::env;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::provenance::RuntimeProvenance;

const CODE_DISABLED: &str = "admission.disabled";
const CODE_OVERRIDE: &str = "admission.override.active";
const CODE_MISSING: &str = "admission.gate.missing";
const CODE_EXPIRED: &str = "admission.gate.expired";
const CODE_STATUS_INVALID: &str = "admission.gate.status_invalid";
const CODE_COMPONENT_MISMATCH: &str = "admission.gate.component_mismatch";
const CODE_LEVEL_MISMATCH: &str = "admission.gate.level_mismatch";
const CODE_BUILD_MISMATCH: &str = "admission.gate.build_mismatch";
const CODE_SOURCE_MISMATCH: &str = "admission.gate.source_mismatch";
const CODE_MANIFEST_MISMATCH: &str = "admission.gate.manifest_mismatch";
const CODE_TIMESTAMP_INVALID: &str = "admission.gate.timestamp_invalid";
const CODE_PROVENANCE_UNAVAILABLE: &str = "admission.runtime.provenance_unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupAdmissionMode {
    Off,
    Warn,
    Strict,
}

impl StartupAdmissionMode {
    pub fn enforcement_phase(self) -> &'static str {
        match self {
            StartupAdmissionMode::Off => "off",
            StartupAdmissionMode::Warn => "warn",
            StartupAdmissionMode::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestGateProfile {
    Fast,
    Standard,
}

impl TestGateProfile {
    pub fn label(self) -> &'static str {
        match self {
            TestGateProfile::Fast => "fast",
            TestGateProfile::Standard => "standard",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StartupAdmissionConfig {
    pub mode: StartupAdmissionMode,
    pub required_profile: TestGateProfile,
    pub fast_gate_artifact_path: PathBuf,
    pub standard_gate_artifact_path: PathBuf,
    pub bypass: bool,
    pub bypass_reason: Option<String>,
    pub bypass_ttl_s: Option<u64>,
    pub production_mode: bool,
    pub allow_production_bypass: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Disabled,
    Bypassed,
    Passed,
    Warning,
    Rejected,
}

impl AdmissionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            AdmissionOutcome::Disabled => "disabled",
            AdmissionOutcome::Bypassed => "bypassed",
            AdmissionOutcome::Passed => "passed",
            AdmissionOutcome::Warning => "warn",
            AdmissionOutcome::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionEvaluation {
    pub outcome: AdmissionOutcome,
    pub profile: TestGateProfile,
    pub gate_path: PathBuf,
    pub reason_code: Option<String>,
    pub detail: String,
    pub override_active: bool,
}

#[derive(Debug, Deserialize)]
struct GateArtifact {
    schema_version: u32,
    component: String,
    gate_level: String,
    status: String,
    build_identity: String,
    source_fingerprint: String,
    command_manifest_digest: String,
    expires_at: String,
}

/// Load startup admission configuration from environment variables.
pub fn load_startup_admission_config() -> Result<StartupAdmissionConfig, String> {
    let production_mode = env_flag(
        "MCP_PROBE_BUILD_PRODUCTION",
        env_flag("MCP_BUILD_PRODUCTION", false)?,
    )?;
    let mode_default = if production_mode { "strict" } else { "warn" };
    let mode = parse_startup_admission_mode(&env_setting(
        "MCP_PROBE_STARTUP_ADMISSION_MODE",
        mode_default,
    ))?;

    let profile_default = if production_mode { "standard" } else { "fast" };
    let required_profile = parse_test_gate_profile(&env_setting(
        "MCP_PROBE_TEST_GATE_REQUIRED_PROFILE",
        profile_default,
    ))?;

    let bypass = env_flag("MCP_PROBE_STARTUP_ADMISSION_BYPASS", false)?;
    let bypass_reason = env_optional_string("MCP_PROBE_STARTUP_ADMISSION_BYPASS_REASON");
    let bypass_ttl_s = env_optional_u64("MCP_PROBE_STARTUP_ADMISSION_BYPASS_TTL_S")?;
    let allow_production_bypass =
        env_flag("MCP_PROBE_STARTUP_ADMISSION_ALLOW_PROD_BYPASS", false)?;

    if production_mode && matches!(mode, StartupAdmissionMode::Off) {
        return Err(
            "MCP_PROBE_STARTUP_ADMISSION_MODE=off is not allowed when MCP_PROBE_BUILD_PRODUCTION=1."
                .to_string(),
        );
    }
    if bypass {
        if bypass_reason
            .as_deref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(
                "MCP_PROBE_STARTUP_ADMISSION_BYPASS requires MCP_PROBE_STARTUP_ADMISSION_BYPASS_REASON."
                    .to_string(),
            );
        }
        if bypass_ttl_s.unwrap_or(0) == 0 {
            return Err(
                "MCP_PROBE_STARTUP_ADMISSION_BYPASS requires MCP_PROBE_STARTUP_ADMISSION_BYPASS_TTL_S>0."
                    .to_string(),
            );
        }
        if production_mode && !allow_production_bypass {
            return Err(
                "Production bypass requires MCP_PROBE_STARTUP_ADMISSION_ALLOW_PROD_BYPASS=1."
                    .to_string(),
            );
        }
    }

    Ok(StartupAdmissionConfig {
        mode,
        required_profile,
        fast_gate_artifact_path: PathBuf::from(env_setting(
            "MCP_PROBE_TEST_GATE_FAST_ARTIFACT_PATH",
            "data/test-gates/mcp-probe/fast.json",
        )),
        standard_gate_artifact_path: PathBuf::from(env_setting(
            "MCP_PROBE_TEST_GATE_STANDARD_ARTIFACT_PATH",
            "data/test-gates/mcp-probe/standard.json",
        )),
        bypass,
        bypass_reason,
        bypass_ttl_s,
        production_mode,
        allow_production_bypass,
    })
}

/// Evaluate startup admission for the current binary against the required gate artifact.
pub fn evaluate_startup_admission(
    config: &StartupAdmissionConfig,
    executable_path: &Path,
    runtime: &RuntimeProvenance,
) -> AdmissionEvaluation {
    let gate_path = required_gate_path(config);
    let profile = config.required_profile;
    if matches!(config.mode, StartupAdmissionMode::Off) {
        return AdmissionEvaluation {
            outcome: AdmissionOutcome::Disabled,
            profile,
            gate_path,
            reason_code: Some(CODE_DISABLED.to_string()),
            detail: "startup admission disabled by configuration".to_string(),
            override_active: false,
        };
    }
    if config.bypass {
        let ttl = config.bypass_ttl_s.unwrap_or_default();
        let reason = config
            .bypass_reason
            .as_deref()
            .unwrap_or("unspecified")
            .to_string();
        return AdmissionEvaluation {
            outcome: AdmissionOutcome::Bypassed,
            profile,
            gate_path,
            reason_code: Some(CODE_OVERRIDE.to_string()),
            detail: format!("startup admission bypass active (ttl_s={ttl}, reason={reason})"),
            override_active: true,
        };
    }

    if runtime.build.build_identity.trim().is_empty()
        || runtime.build.source_fingerprint.trim().is_empty()
    {
        return warning_or_reject(
            config.mode,
            profile,
            gate_path,
            CODE_PROVENANCE_UNAVAILABLE,
            "runtime provenance unavailable".to_string(),
        );
    }

    let gate_meta = match std::fs::metadata(&gate_path) {
        Ok(meta) => meta,
        Err(err) => {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_MISSING,
                format!("required gate artifact missing or unreadable: {err}"),
            );
        }
    };
    let gate_modified = match gate_meta.modified() {
        Ok(ts) => ts,
        Err(err) => {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_TIMESTAMP_INVALID,
                format!("required gate artifact has no readable modified time: {err}"),
            );
        }
    };
    let exe_modified = match std::fs::metadata(executable_path).and_then(|meta| meta.modified()) {
        Ok(ts) => ts,
        Err(err) => {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_TIMESTAMP_INVALID,
                format!("failed to read executable modified time: {err}"),
            );
        }
    };

    if is_json_artifact(&gate_path) {
        let contents = match std::fs::read_to_string(&gate_path) {
            Ok(value) => value,
            Err(err) => {
                return warning_or_reject(
                    config.mode,
                    profile,
                    gate_path,
                    CODE_MISSING,
                    format!("failed to read gate artifact JSON: {err}"),
                );
            }
        };
        let artifact = match serde_json::from_str::<GateArtifact>(&contents) {
            Ok(value) => value,
            Err(err) => {
                return warning_or_reject(
                    config.mode,
                    profile,
                    gate_path,
                    CODE_STATUS_INVALID,
                    format!("invalid gate artifact JSON payload: {err}"),
                );
            }
        };
        if artifact.schema_version != 1 {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_STATUS_INVALID,
                format!(
                    "unsupported gate artifact schema_version {}; expected 1",
                    artifact.schema_version
                ),
            );
        }
        if artifact.component != runtime.build.component {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_COMPONENT_MISMATCH,
                format!(
                    "gate component mismatch: expected {}, found {}",
                    runtime.build.component, artifact.component
                ),
            );
        }
        if artifact.gate_level != profile.label() {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_LEVEL_MISMATCH,
                format!(
                    "gate level mismatch: expected {}, found {}",
                    profile.label(),
                    artifact.gate_level
                ),
            );
        }
        if artifact.status != "pass" {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_STATUS_INVALID,
                format!("gate status is not pass: {}", artifact.status),
            );
        }
        if artifact.build_identity != runtime.build.build_identity {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_BUILD_MISMATCH,
                format!(
                    "gate build_identity mismatch: expected {}, found {}",
                    runtime.build.build_identity, artifact.build_identity
                ),
            );
        }
        if artifact.source_fingerprint != runtime.build.source_fingerprint {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_SOURCE_MISMATCH,
                format!(
                    "gate source_fingerprint mismatch: expected {}, found {}",
                    runtime.build.source_fingerprint, artifact.source_fingerprint
                ),
            );
        }
        if !artifact.command_manifest_digest.starts_with("sha256:") {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_MANIFEST_MISMATCH,
                "gate command_manifest_digest must start with sha256:".to_string(),
            );
        }
        let expires_at = match OffsetDateTime::parse(&artifact.expires_at, &Rfc3339) {
            Ok(value) => value,
            Err(err) => {
                return warning_or_reject(
                    config.mode,
                    profile,
                    gate_path,
                    CODE_TIMESTAMP_INVALID,
                    format!("gate expires_at is not valid RFC3339: {err}"),
                );
            }
        };
        if OffsetDateTime::now_utc() > expires_at {
            return warning_or_reject(
                config.mode,
                profile,
                gate_path,
                CODE_EXPIRED,
                format!("gate artifact expired at {}", artifact.expires_at),
            );
        }
    }

    if is_stale(gate_modified, exe_modified) {
        return warning_or_reject(
            config.mode,
            profile,
            gate_path,
            CODE_EXPIRED,
            format!(
                "required gate artifact is older than executable ({})",
                executable_path.display()
            ),
        );
    }

    AdmissionEvaluation {
        outcome: AdmissionOutcome::Passed,
        profile,
        gate_path,
        reason_code: None,
        detail: "startup admission checks passed".to_string(),
        override_active: false,
    }
}

fn required_gate_path(config: &StartupAdmissionConfig) -> PathBuf {
    match config.required_profile {
        TestGateProfile::Fast => config.fast_gate_artifact_path.clone(),
        TestGateProfile::Standard => config.standard_gate_artifact_path.clone(),
    }
}

fn warning_or_reject(
    mode: StartupAdmissionMode,
    profile: TestGateProfile,
    gate_path: PathBuf,
    reason_code: &str,
    detail: String,
) -> AdmissionEvaluation {
    let outcome = match mode {
        StartupAdmissionMode::Strict => AdmissionOutcome::Rejected,
        StartupAdmissionMode::Warn => AdmissionOutcome::Warning,
        StartupAdmissionMode::Off => AdmissionOutcome::Disabled,
    };
    AdmissionEvaluation {
        outcome,
        profile,
        gate_path,
        reason_code: Some(reason_code.to_string()),
        detail,
        override_active: false,
    }
}

fn parse_startup_admission_mode(value: &str) -> Result<StartupAdmissionMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "off" | "0" | "false" => Ok(StartupAdmissionMode::Off),
        "warn" => Ok(StartupAdmissionMode::Warn),
        "strict" => Ok(StartupAdmissionMode::Strict),
        other => Err(format!(
            "Unsupported MCP_PROBE_STARTUP_ADMISSION_MODE={other:?}; use off, warn, or strict."
        )),
    }
}

fn parse_test_gate_profile(value: &str) -> Result<TestGateProfile, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "fast" => Ok(TestGateProfile::Fast),
        "standard" => Ok(TestGateProfile::Standard),
        other => Err(format!(
            "Unsupported MCP_PROBE_TEST_GATE_REQUIRED_PROFILE={other:?}; use fast or standard."
        )),
    }
}

fn env_setting(name: &str, fallback: &str) -> String {
    env::var(name).unwrap_or_else(|_| fallback.to_string())
}

fn env_optional_string(name: &str) -> Option<String> {
    let Ok(value) = env::var(name) else {
        return None;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn env_optional_u64(name: &str) -> Result<Option<u64>, String> {
    let Some(value) = env_optional_string(name) else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|err| format!("invalid {name}: {err}"))
}

fn env_flag(name: &str, fallback: bool) -> Result<bool, String> {
    let Some(value) = env_optional_string(name) else {
        return Ok(fallback);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid boolean for {name}: {value}")),
    }
}

fn is_json_artifact(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn is_stale(gate_modified: SystemTime, exe_modified: SystemTime) -> bool {
    gate_modified < exe_modified
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::capture_runtime_provenance;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use time::Duration;

    fn temp_path(prefix: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{nonce}"))
    }

    fn base_config(mode: StartupAdmissionMode) -> StartupAdmissionConfig {
        StartupAdmissionConfig {
            mode,
            required_profile: TestGateProfile::Fast,
            fast_gate_artifact_path: temp_path("mcp-probe-fast-gate").join("fast.json"),
            standard_gate_artifact_path: temp_path("mcp-probe-standard-gate").join("standard.json"),
            bypass: false,
            bypass_reason: None,
            bypass_ttl_s: None,
            production_mode: false,
            allow_production_bypass: false,
        }
    }

    fn write_gate_json(path: &Path, runtime: &RuntimeProvenance, status: &str, expires_at: &str) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let payload = serde_json::json!({
            "schema_version": 1,
            "component": runtime.build.component,
            "gate_level": "fast",
            "status": status,
            "build_identity": runtime.build.build_identity,
            "source_fingerprint": runtime.build.source_fingerprint,
            "command_manifest_digest": "sha256:test",
            "expires_at": expires_at
        });
        fs::write(path, serde_json::to_vec(&payload).expect("serialize gate"))
            .expect("write gate");
    }

    #[test]
    fn admission_warn_mode_allows_missing_gate() {
        let config = base_config(StartupAdmissionMode::Warn);
        let exe = temp_path("mcp-probe-exe");
        fs::write(&exe, "bin").expect("write exe");
        let runtime = capture_runtime_provenance(&exe);
        let result = evaluate_startup_admission(&config, &exe, &runtime);
        assert_eq!(result.outcome, AdmissionOutcome::Warning);
        let _ = fs::remove_file(exe);
    }

    #[test]
    fn admission_strict_rejects_missing_gate() {
        let config = base_config(StartupAdmissionMode::Strict);
        let exe = temp_path("mcp-probe-exe");
        fs::write(&exe, "bin").expect("write exe");
        let runtime = capture_runtime_provenance(&exe);
        let result = evaluate_startup_admission(&config, &exe, &runtime);
        assert_eq!(result.outcome, AdmissionOutcome::Rejected);
        let _ = fs::remove_file(exe);
    }

    #[test]
    fn admission_strict_passes_with_valid_gate_json() {
        let config = base_config(StartupAdmissionMode::Strict);
        let exe = temp_path("mcp-probe-exe");
        fs::write(&exe, "bin").expect("write exe");
        std::thread::sleep(std::time::Duration::from_millis(25));
        let runtime = capture_runtime_provenance(&exe);
        let expires = (OffsetDateTime::now_utc() + Duration::hours(1))
            .format(&Rfc3339)
            .expect("format expires");
        write_gate_json(&config.fast_gate_artifact_path, &runtime, "pass", &expires);
        let result = evaluate_startup_admission(&config, &exe, &runtime);
        assert_eq!(result.outcome, AdmissionOutcome::Passed);
        let _ = fs::remove_file(exe);
        let _ = fs::remove_file(&config.fast_gate_artifact_path);
    }

    #[test]
    fn admission_strict_rejects_stale_gate() {
        let config = base_config(StartupAdmissionMode::Strict);
        let exe = temp_path("mcp-probe-exe");
        fs::write(&exe, "bin").expect("write exe");
        let runtime = capture_runtime_provenance(&exe);
        let expires = (OffsetDateTime::now_utc() + Duration::hours(1))
            .format(&Rfc3339)
            .expect("format expires");
        write_gate_json(&config.fast_gate_artifact_path, &runtime, "pass", &expires);
        std::thread::sleep(std::time::Duration::from_millis(25));
        fs::write(&exe, "bin-newer").expect("rewrite exe to make gate stale");

        let result = evaluate_startup_admission(&config, &exe, &runtime);
        assert_eq!(result.outcome, AdmissionOutcome::Rejected);
        assert_eq!(result.reason_code.as_deref(), Some(CODE_EXPIRED));

        let _ = fs::remove_file(exe);
        let _ = fs::remove_file(&config.fast_gate_artifact_path);
    }
}
