//! Runtime provenance capture and fleet attestation envelope helpers.

use std::path::Path;

use mcp_toolkit_provenance::{
    build_attestation_envelope as toolkit_build_attestation_envelope,
    capture_runtime_provenance as toolkit_capture_runtime_provenance, AttestationOptions,
    BuildProvenanceInput, UNKNOWN_VALUE,
};
pub use mcp_toolkit_provenance::{
    AttestationEnvelope, AttestationIdentity, AttestationPayload, AttestationRuntime,
    BinaryProvenance, BuildMetadata, BuildProvenance, ProcessProvenance, RuntimeProvenance,
    SourceProvenance, UnavailableField,
};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeAdmissionExtension {
    pub enforcement_phase: String,
    pub required_gate_level: String,
    pub outcome: String,
    pub reason_code: Option<String>,
    pub override_active: bool,
}

/// Build truthful compile-time provenance from the validated build-script inputs.
pub fn build_provenance() -> BuildProvenance {
    let revision = known_env(option_env!("MCP_PROBE_BUILD_GIT_SHA"));
    let reference = known_env(option_env!("MCP_PROBE_BUILD_GIT_REF"));
    let dirty = parse_dirty(option_env!("MCP_PROBE_BUILD_GIT_DIRTY"));
    let usable_identity = revision.is_some() && dirty.is_some();
    let build_identity_override = if usable_identity {
        known_env(option_env!("MCP_PROBE_BUILD_IDENTITY_OVERRIDE"))
    } else {
        None
    };

    BuildProvenance::from_input(BuildProvenanceInput {
        component: option_env!("MCP_PROBE_BUILD_COMPONENT").unwrap_or(env!("CARGO_PKG_NAME")),
        server_version: option_env!("MCP_PROBE_BUILD_SERVER_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION")),
        revision,
        reference,
        dirty,
        profile: known_env(option_env!("MCP_PROBE_BUILD_PROFILE")),
        target: known_env(option_env!("MCP_PROBE_BUILD_TARGET")),
        rustc_version: known_env(option_env!("MCP_PROBE_BUILD_RUSTC_VERSION")),
        source_date_epoch: known_env(option_env!("MCP_PROBE_BUILD_SOURCE_DATE_EPOCH")),
        build_identity_override,
    })
}

/// Capture advisory runtime metadata using the shared Toolkit provenance model.
pub fn capture_runtime_provenance(executable_path: &Path) -> RuntimeProvenance {
    toolkit_capture_runtime_provenance(build_provenance(), executable_path)
}

/// Build the shared schema-v2 envelope and retain Probe's existing admission extension.
pub fn build_attestation_envelope(
    provenance: &RuntimeProvenance,
    admission: &RuntimeAdmissionExtension,
) -> AttestationEnvelope {
    let extension = json!(admission);
    toolkit_build_attestation_envelope(
        provenance,
        AttestationOptions::default().with_extension("runtime_admission", extension),
    )
}

fn known_env(value: Option<&'static str>) -> Option<&'static str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case(UNKNOWN_VALUE))
}

fn parse_dirty(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("1" | "true" | "yes" | "on") => Some(true),
        Some("0" | "false" | "no" | "off") => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_attestation_envelope, known_env, parse_dirty, RuntimeAdmissionExtension};
    use mcp_toolkit_provenance::{
        capture_runtime_provenance as capture_shared, BuildProvenance, BuildProvenanceInput,
        UNKNOWN_VALUE,
    };
    use std::path::Path;

    #[test]
    fn dirty_state_preserves_unknown_instead_of_coercing_it_to_clean() {
        assert_eq!(parse_dirty(Some("true")), Some(true));
        assert_eq!(parse_dirty(Some("false")), Some(false));
        assert_eq!(parse_dirty(Some(UNKNOWN_VALUE)), None);
        assert_eq!(parse_dirty(None), None);
    }

    #[test]
    fn unknown_compile_time_values_are_not_trusted_identity_inputs() {
        assert_eq!(known_env(Some("unknown")), None);
        assert_eq!(known_env(Some("  ")), None);
        assert_eq!(known_env(Some("abc123")), Some("abc123"));
    }

    #[test]
    fn unknown_dirty_state_stays_null_and_degrades_the_shared_envelope() {
        let build = BuildProvenance::from_input(BuildProvenanceInput {
            component: "mcp-probe",
            server_version: "0.1.0",
            revision: Some("abc123"),
            reference: Some("main"),
            dirty: None,
            profile: Some("debug"),
            target: Some("x86_64-unknown-linux-gnu"),
            rustc_version: Some("rustc 1.99.0"),
            source_date_epoch: None,
            build_identity_override: None,
        });
        let runtime = capture_shared(build, Path::new("/not-a-real-executable"));
        let envelope = build_attestation_envelope(
            &runtime,
            &RuntimeAdmissionExtension {
                enforcement_phase: "warn".to_string(),
                required_gate_level: "fast".to_string(),
                outcome: "warn".to_string(),
                reason_code: None,
                override_active: false,
            },
        );
        let value = serde_json::to_value(envelope).expect("serialize envelope");
        assert!(value["attestation"]["source"]["dirty"].is_null());
        assert_eq!(value["status"], "degraded");
        assert_eq!(
            value["extensions"]["runtime_admission"]["required_gate_level"],
            "fast"
        );
        assert!(value["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| { field["field"] == "attestation.source.dirty" }));
    }
}
