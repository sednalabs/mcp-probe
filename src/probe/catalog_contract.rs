//! Catalog contract comparison for repeatable native MCP discovery proof.

use crate::probe::catalog_profile::descriptor_profile_for_catalog_profile;
use crate::probe::schema_compat::ToolDescriptorProfile;
use crate::report::{
    CatalogContract, CatalogContractRequirement, CatalogContractVerdict, CatalogProfile, ProbeStep,
    ProbeStepStatus,
};
use crate::transport::TransportType;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::str::FromStr;

pub const CATALOG_CONTRACT_STEP: &str = "catalog.contract";

#[derive(Debug, Clone, Copy)]
pub struct CatalogContractSnapshot<'a> {
    pub transport: TransportType,
    pub catalog_profile: Option<CatalogProfile>,
    pub descriptor_profile: ToolDescriptorProfile,
    pub tools: Option<&'a Value>,
    pub resources: Option<&'a Value>,
    pub resource_templates: Option<&'a Value>,
    pub prompts: Option<&'a Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatalogIdentifiers {
    tools: Vec<String>,
    resources: Vec<String>,
    resource_templates: Vec<String>,
    prompts: Vec<String>,
}

pub fn effective_descriptor_profile(
    descriptor_profile: Option<ToolDescriptorProfile>,
    catalog_profile: Option<CatalogProfile>,
) -> ToolDescriptorProfile {
    descriptor_profile
        .or_else(|| catalog_profile.map(descriptor_profile_for_catalog_profile))
        .unwrap_or_default()
}

pub fn evaluate_catalog_contract(
    contract: &CatalogContract,
    snapshot: CatalogContractSnapshot<'_>,
) -> CatalogContractVerdict {
    let actual = CatalogIdentifiers {
        tools: extract_identifiers(snapshot.tools, &["tools"], &["name"]),
        resources: extract_identifiers(snapshot.resources, &["resources"], &["uri"]),
        resource_templates: extract_identifiers(
            snapshot.resource_templates,
            &["resourceTemplates", "resource_templates"],
            &["uriTemplate", "uri_template"],
        ),
        prompts: extract_identifiers(snapshot.prompts, &["prompts"], &["name"]),
    };
    let actual_fingerprint = catalog_fingerprint(&actual);
    let mut requirements = Vec::new();
    let mut findings = Vec::new();

    if contract.schema_version != 1 {
        push_requirement(
            &mut requirements,
            &mut findings,
            "schema_version",
            ProbeStepStatus::Error,
            format!(
                "unsupported catalog contract schema_version {}",
                contract.schema_version
            ),
            Some(json!(1)),
            Some(json!(contract.schema_version)),
        );
    } else {
        push_requirement(
            &mut requirements,
            &mut findings,
            "schema_version",
            ProbeStepStatus::Ok,
            "schema_version 1".to_string(),
            Some(json!(1)),
            Some(json!(1)),
        );
    }

    if let Some(expected_transport) = contract.transport.as_deref() {
        match TransportType::from_str(expected_transport) {
            Ok(expected) if expected == snapshot.transport => push_requirement(
                &mut requirements,
                &mut findings,
                "transport",
                ProbeStepStatus::Ok,
                format!("transport {} matched", snapshot.transport.as_str()),
                Some(json!(expected.as_str())),
                Some(json!(snapshot.transport.as_str())),
            ),
            Ok(expected) => push_requirement(
                &mut requirements,
                &mut findings,
                "transport",
                ProbeStepStatus::Error,
                format!(
                    "expected transport {}, observed {}",
                    expected.as_str(),
                    snapshot.transport.as_str()
                ),
                Some(json!(expected.as_str())),
                Some(json!(snapshot.transport.as_str())),
            ),
            Err(err) => push_requirement(
                &mut requirements,
                &mut findings,
                "transport",
                ProbeStepStatus::Error,
                err,
                Some(json!(expected_transport)),
                Some(json!(snapshot.transport.as_str())),
            ),
        }
    }

    if let Some(expected_profile) = contract.catalog_profile {
        let actual_profile = snapshot.catalog_profile.map(CatalogProfile::as_str);
        let expected_profile_name = expected_profile.as_str();
        let status = if actual_profile == Some(expected_profile_name) {
            ProbeStepStatus::Ok
        } else {
            ProbeStepStatus::Error
        };
        let detail = if status == ProbeStepStatus::Ok {
            format!("catalog_profile {expected_profile_name} matched")
        } else {
            format!(
                "expected catalog_profile {}, observed {}",
                expected_profile_name,
                actual_profile.unwrap_or("none")
            )
        };
        push_requirement(
            &mut requirements,
            &mut findings,
            "catalog_profile",
            status,
            detail,
            Some(json!(expected_profile_name)),
            actual_profile.map(|value| json!(value)),
        );
    }

    if let Some(expected_descriptor) = contract.descriptor_profile.as_deref() {
        match ToolDescriptorProfile::from_str(expected_descriptor) {
            Ok(expected) if expected == snapshot.descriptor_profile => push_requirement(
                &mut requirements,
                &mut findings,
                "descriptor_profile",
                ProbeStepStatus::Ok,
                format!("descriptor_profile {} matched", expected.as_str()),
                Some(json!(expected.as_str())),
                Some(json!(snapshot.descriptor_profile.as_str())),
            ),
            Ok(expected) => push_requirement(
                &mut requirements,
                &mut findings,
                "descriptor_profile",
                ProbeStepStatus::Error,
                format!(
                    "expected descriptor_profile {}, observed {}",
                    expected.as_str(),
                    snapshot.descriptor_profile.as_str()
                ),
                Some(json!(expected.as_str())),
                Some(json!(snapshot.descriptor_profile.as_str())),
            ),
            Err(err) => push_requirement(
                &mut requirements,
                &mut findings,
                "descriptor_profile",
                ProbeStepStatus::Error,
                err,
                Some(json!(expected_descriptor)),
                Some(json!(snapshot.descriptor_profile.as_str())),
            ),
        }
    }

    if let Some(expected_fingerprint) = contract.catalog_fingerprint.as_deref() {
        let status = if expected_fingerprint == actual_fingerprint {
            ProbeStepStatus::Ok
        } else {
            ProbeStepStatus::Error
        };
        let detail = if status == ProbeStepStatus::Ok {
            "catalog_fingerprint matched".to_string()
        } else {
            format!(
                "expected catalog_fingerprint {}, observed {}",
                expected_fingerprint, actual_fingerprint
            )
        };
        push_requirement(
            &mut requirements,
            &mut findings,
            "catalog_fingerprint",
            status,
            detail,
            Some(json!(expected_fingerprint)),
            Some(json!(actual_fingerprint)),
        );
    }

    push_count_requirements(
        &mut requirements,
        &mut findings,
        "tools",
        actual.tools.len(),
        contract.expected_tool_count,
        contract.min_tool_count,
    );
    push_count_requirements(
        &mut requirements,
        &mut findings,
        "resources",
        actual.resources.len(),
        contract.expected_resource_count,
        contract.min_resource_count,
    );
    push_count_requirements(
        &mut requirements,
        &mut findings,
        "resource_templates",
        actual.resource_templates.len(),
        contract.expected_resource_template_count,
        contract.min_resource_template_count,
    );
    push_count_requirements(
        &mut requirements,
        &mut findings,
        "prompts",
        actual.prompts.len(),
        contract.expected_prompt_count,
        contract.min_prompt_count,
    );

    push_required_identifiers(
        &mut requirements,
        &mut findings,
        "required_tools",
        &contract.required_tools,
        &actual.tools,
    );
    push_required_identifiers(
        &mut requirements,
        &mut findings,
        "required_resources",
        &contract.required_resources,
        &actual.resources,
    );
    push_required_identifiers(
        &mut requirements,
        &mut findings,
        "required_resource_templates",
        &contract.required_resource_templates,
        &actual.resource_templates,
    );
    push_required_identifiers(
        &mut requirements,
        &mut findings,
        "required_prompts",
        &contract.required_prompts,
        &actual.prompts,
    );

    let status = if findings.is_empty() {
        ProbeStepStatus::Ok
    } else {
        ProbeStepStatus::Error
    };
    let detail = if findings.is_empty() {
        "catalog contract passed".to_string()
    } else {
        format!("catalog contract failed with {} finding(s)", findings.len())
    };

    CatalogContractVerdict {
        schema_version: 1,
        status,
        detail,
        actual_fingerprint,
        requirements,
        findings,
        contract: contract.clone(),
    }
}

pub fn build_catalog_contract_step(verdict: &CatalogContractVerdict) -> ProbeStep {
    ProbeStep {
        name: CATALOG_CONTRACT_STEP.to_string(),
        status: verdict.status.clone(),
        detail: Some(verdict.detail.clone()),
        data: Some(json!(verdict)),
    }
}

fn push_requirement(
    requirements: &mut Vec<CatalogContractRequirement>,
    findings: &mut Vec<String>,
    name: &str,
    status: ProbeStepStatus,
    detail: String,
    expected: Option<Value>,
    actual: Option<Value>,
) {
    if status == ProbeStepStatus::Error {
        findings.push(format!("{name}: {detail}"));
    }
    requirements.push(CatalogContractRequirement {
        name: name.to_string(),
        status,
        detail,
        expected,
        actual,
    });
}

fn push_count_requirements(
    requirements: &mut Vec<CatalogContractRequirement>,
    findings: &mut Vec<String>,
    name: &str,
    actual_count: usize,
    expected_count: Option<usize>,
    min_count: Option<usize>,
) {
    if let Some(expected_count) = expected_count {
        let status = if actual_count == expected_count {
            ProbeStepStatus::Ok
        } else {
            ProbeStepStatus::Error
        };
        let detail = if status == ProbeStepStatus::Ok {
            format!("{name} count matched {expected_count}")
        } else {
            format!("expected {expected_count} {name}, observed {actual_count}")
        };
        push_requirement(
            requirements,
            findings,
            &format!("{name}.expected_count"),
            status,
            detail,
            Some(json!(expected_count)),
            Some(json!(actual_count)),
        );
    }

    if let Some(min_count) = min_count {
        let status = if actual_count >= min_count {
            ProbeStepStatus::Ok
        } else {
            ProbeStepStatus::Error
        };
        let detail = if status == ProbeStepStatus::Ok {
            format!("{name} count {actual_count} met minimum {min_count}")
        } else {
            format!("expected at least {min_count} {name}, observed {actual_count}")
        };
        push_requirement(
            requirements,
            findings,
            &format!("{name}.min_count"),
            status,
            detail,
            Some(json!(min_count)),
            Some(json!(actual_count)),
        );
    }
}

fn push_required_identifiers(
    requirements: &mut Vec<CatalogContractRequirement>,
    findings: &mut Vec<String>,
    name: &str,
    expected: &[String],
    actual: &[String],
) {
    if expected.is_empty() {
        return;
    }
    let actual_set: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    let missing: Vec<&str> = expected
        .iter()
        .map(String::as_str)
        .filter(|item| !actual_set.contains(item))
        .collect();
    let status = if missing.is_empty() {
        ProbeStepStatus::Ok
    } else {
        ProbeStepStatus::Error
    };
    let detail = if missing.is_empty() {
        format!("all {} {name} matched", expected.len())
    } else {
        format!("missing {} {name}: {}", missing.len(), missing.join(", "))
    };
    push_requirement(
        requirements,
        findings,
        name,
        status,
        detail,
        Some(json!(expected)),
        Some(json!(actual)),
    );
}

fn extract_identifiers(
    value: Option<&Value>,
    array_keys: &[&str],
    identifier_keys: &[&str],
) -> Vec<String> {
    let mut identifiers = BTreeSet::new();
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(items) = catalog_array(value, array_keys) else {
        return Vec::new();
    };
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        for key in identifier_keys {
            if let Some(identifier) = object
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                identifiers.insert(identifier.to_string());
                break;
            }
        }
    }
    identifiers.into_iter().collect()
}

fn catalog_array<'a>(value: &'a Value, array_keys: &[&str]) -> Option<&'a Vec<Value>> {
    if let Value::Array(items) = value {
        return Some(items);
    }
    let object = value.as_object()?;
    array_keys
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_array))
}

fn catalog_fingerprint(actual: &CatalogIdentifiers) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for (section, values) in [
        ("tools", &actual.tools),
        ("resources", &actual.resources),
        ("resource_templates", &actual.resource_templates),
        ("prompts", &actual.prompts),
    ] {
        fnv1a_update(&mut hash, section.as_bytes());
        fnv1a_update(&mut hash, b"\0");
        for value in values {
            fnv1a_update(&mut hash, value.as_bytes());
            fnv1a_update(&mut hash, b"\0");
        }
    }
    format!("fnv1a64:{hash:016x}")
}

fn fnv1a_update(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x100000001b3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(contract: &CatalogContract) -> CatalogContractVerdict {
        let tools = json!({
            "tools": [
                { "name": "work_items_find" },
                { "name": "work_items_create" },
                { "name": "work_item_dependency_view" }
            ]
        });
        let resources = json!({
            "resources": [
                { "uri": "ops://work_item/w4760" }
            ]
        });
        let resource_templates = json!({
            "resourceTemplates": [
                { "uriTemplate": "ops://work_item/{work_item_ref}" }
            ]
        });
        let prompts = json!({
            "prompts": [
                { "name": "summarize_work_item" }
            ]
        });
        evaluate_catalog_contract(
            contract,
            CatalogContractSnapshot {
                transport: TransportType::StreamableHttp,
                catalog_profile: Some(CatalogProfile::CodexDeferred),
                descriptor_profile: ToolDescriptorProfile::Basic,
                tools: Some(&tools),
                resources: Some(&resources),
                resource_templates: Some(&resource_templates),
                prompts: Some(&prompts),
            },
        )
    }

    #[test]
    fn contract_passes_required_catalog_items() {
        let contract = CatalogContract {
            schema_version: 1,
            transport: Some("streamable-http".to_string()),
            catalog_profile: Some(CatalogProfile::CodexDeferred),
            descriptor_profile: Some("basic".to_string()),
            min_tool_count: Some(3),
            required_tools: vec![
                "work_items_find".to_string(),
                "work_item_dependency_view".to_string(),
            ],
            required_resource_templates: vec!["ops://work_item/{work_item_ref}".to_string()],
            required_prompts: vec!["summarize_work_item".to_string()],
            ..Default::default()
        };

        let verdict = evaluate(&contract);

        assert_eq!(verdict.status, ProbeStepStatus::Ok);
        assert!(verdict.findings.is_empty());
        assert!(verdict
            .requirements
            .iter()
            .any(|requirement| requirement.name == "required_tools"));
        assert!(verdict.actual_fingerprint.starts_with("fnv1a64:"));
    }

    #[test]
    fn contract_reports_missing_required_tools() {
        let contract = CatalogContract {
            schema_version: 1,
            required_tools: vec![
                "work_items_find".to_string(),
                "apply_link_commands_bundle".to_string(),
            ],
            ..Default::default()
        };

        let verdict = evaluate(&contract);

        assert_eq!(verdict.status, ProbeStepStatus::Error);
        assert!(verdict
            .findings
            .iter()
            .any(|finding| finding.contains("apply_link_commands_bundle")));
    }

    #[test]
    fn contract_reports_fingerprint_mismatch() {
        let contract = CatalogContract {
            schema_version: 1,
            catalog_fingerprint: Some("fnv1a64:0000000000000000".to_string()),
            ..Default::default()
        };

        let verdict = evaluate(&contract);

        assert_eq!(verdict.status, ProbeStepStatus::Error);
        assert!(verdict
            .findings
            .iter()
            .any(|finding| finding.contains("catalog_fingerprint")));
    }
}
