//! Catalog profile conformance checks for host-oriented MCP discovery.

use crate::probe::schema_compat::ToolDescriptorProfile;
use crate::report::{
    CatalogMethodSummary, CatalogProfile, CatalogProfileRequirement, CatalogProfileVerdict,
    ProbeStep, ProbeStepStatus,
};
use serde_json::json;

pub const CATALOG_PROFILE_STEP: &str = "catalog.profile";

pub fn descriptor_profile_for_catalog_profile(profile: CatalogProfile) -> ToolDescriptorProfile {
    match profile {
        CatalogProfile::ChatgptTool => ToolDescriptorProfile::ChatgptTool,
        CatalogProfile::AppsSdkUi => ToolDescriptorProfile::AppsSdkUi,
        CatalogProfile::RawMcp
        | CatalogProfile::CodexDeferred
        | CatalogProfile::ClaudeCode
        | CatalogProfile::GeminiCli => ToolDescriptorProfile::Basic,
    }
}

pub fn evaluate_catalog_profile(
    profile: CatalogProfile,
    methods: &[CatalogMethodSummary],
) -> CatalogProfileVerdict {
    let mut requirements = Vec::new();
    let mut findings = Vec::new();
    let descriptor_profile = descriptor_profile_for_catalog_profile(profile);

    requirements.push(CatalogProfileRequirement {
        name: "descriptor_profile".to_string(),
        required: true,
        status: ProbeStepStatus::Ok,
        detail: Some(format!(
            "uses descriptor_profile={}",
            descriptor_profile.as_str()
        )),
        item_count: None,
    });

    push_method_requirement(
        methods,
        &mut requirements,
        &mut findings,
        "tools/list",
        true,
        profile != CatalogProfile::RawMcp,
    );

    if profile == CatalogProfile::CodexDeferred {
        push_pagination_requirement(methods, &mut requirements, &mut findings);
    }

    let requires_resource_templates = profile == CatalogProfile::AppsSdkUi;
    push_method_requirement(
        methods,
        &mut requirements,
        &mut findings,
        "resources/templates/list",
        requires_resource_templates,
        requires_resource_templates,
    );

    push_method_requirement(
        methods,
        &mut requirements,
        &mut findings,
        "resources/list",
        false,
        false,
    );
    push_method_requirement(
        methods,
        &mut requirements,
        &mut findings,
        "prompts/list",
        false,
        false,
    );

    let status = if findings.is_empty() {
        ProbeStepStatus::Ok
    } else {
        ProbeStepStatus::Error
    };
    let detail = if findings.is_empty() {
        format!("catalog profile {} passed", profile.as_str())
    } else {
        format!(
            "catalog profile {} failed with {} finding(s)",
            profile.as_str(),
            findings.len()
        )
    };

    CatalogProfileVerdict {
        profile,
        status,
        detail,
        requirements,
        findings,
    }
}

pub fn build_catalog_profile_step(verdict: &CatalogProfileVerdict) -> ProbeStep {
    ProbeStep {
        name: CATALOG_PROFILE_STEP.to_string(),
        status: verdict.status.clone(),
        detail: Some(verdict.detail.clone()),
        data: Some(json!(verdict)),
    }
}

fn push_method_requirement(
    methods: &[CatalogMethodSummary],
    requirements: &mut Vec<CatalogProfileRequirement>,
    findings: &mut Vec<String>,
    method: &str,
    required: bool,
    require_non_empty: bool,
) {
    let Some(summary) = methods.iter().find(|summary| summary.method == method) else {
        let detail = "method was not captured".to_string();
        requirements.push(CatalogProfileRequirement {
            name: method.to_string(),
            required,
            status: if required {
                ProbeStepStatus::Error
            } else {
                ProbeStepStatus::Ok
            },
            detail: Some(detail.clone()),
            item_count: None,
        });
        if required {
            findings.push(format!("{method}: {detail}"));
        }
        return;
    };

    let unsupported = summary.detail.as_deref() == Some("not supported");
    let mut status = summary.status.clone();
    let mut detail = summary.detail.clone();

    if required && unsupported {
        status = ProbeStepStatus::Error;
        detail = Some("method is required by this profile but is not supported".to_string());
    } else if require_non_empty
        && status == ProbeStepStatus::Ok
        && summary.item_count.unwrap_or(0) == 0
    {
        status = ProbeStepStatus::Error;
        detail = Some("method returned no discoverable items".to_string());
    }

    if required && status == ProbeStepStatus::Error {
        let reason = detail
            .clone()
            .unwrap_or_else(|| "method did not satisfy profile requirement".to_string());
        findings.push(format!("{method}: {reason}"));
    }

    requirements.push(CatalogProfileRequirement {
        name: method.to_string(),
        required,
        status,
        detail,
        item_count: summary.item_count,
    });
}

fn push_pagination_requirement(
    methods: &[CatalogMethodSummary],
    requirements: &mut Vec<CatalogProfileRequirement>,
    findings: &mut Vec<String>,
) {
    let Some(summary) = methods
        .iter()
        .find(|summary| summary.method == "tools/list")
    else {
        requirements.push(CatalogProfileRequirement {
            name: "tools/list pagination drain".to_string(),
            required: true,
            status: ProbeStepStatus::Error,
            detail: Some("tools/list was not captured".to_string()),
            item_count: None,
        });
        findings.push("tools/list pagination drain: tools/list was not captured".to_string());
        return;
    };

    let status = if summary.status == ProbeStepStatus::Ok && summary.page_count.is_some() {
        ProbeStepStatus::Ok
    } else {
        ProbeStepStatus::Error
    };
    let detail = match (status.clone(), summary.page_count) {
        (ProbeStepStatus::Ok, Some(page_count)) => {
            Some(format!("drained {page_count} tools/list page(s)"))
        }
        _ => Some("tools/list pagination drain did not complete".to_string()),
    };
    if status == ProbeStepStatus::Error {
        findings.push(
            "tools/list pagination drain: tools/list pagination drain did not complete".to_string(),
        );
    }

    requirements.push(CatalogProfileRequirement {
        name: "tools/list pagination drain".to_string(),
        required: true,
        status,
        detail,
        item_count: summary.item_count,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(method: &str, item_count: Option<usize>) -> CatalogMethodSummary {
        CatalogMethodSummary {
            method: method.to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("ok".to_string()),
            page_count: Some(1),
            item_count,
        }
    }

    #[test]
    fn apps_sdk_ui_requires_resource_templates() {
        let verdict = evaluate_catalog_profile(
            CatalogProfile::AppsSdkUi,
            &[
                method("tools/list", Some(2)),
                method("resources/list", Some(0)),
                CatalogMethodSummary {
                    method: "resources/templates/list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some("not supported".to_string()),
                    page_count: None,
                    item_count: None,
                },
                method("prompts/list", Some(0)),
            ],
        );

        assert_eq!(verdict.status, ProbeStepStatus::Error);
        assert!(verdict.findings.iter().any(|finding| {
            finding.contains("resources/templates/list") && finding.contains("not supported")
        }));
    }

    #[test]
    fn codex_deferred_requires_tools_and_pagination_receipt() {
        let verdict = evaluate_catalog_profile(
            CatalogProfile::CodexDeferred,
            &[
                CatalogMethodSummary {
                    method: "tools/list".to_string(),
                    status: ProbeStepStatus::Ok,
                    detail: Some("discovered 3 tools across 2 page(s)".to_string()),
                    page_count: Some(2),
                    item_count: Some(3),
                },
                method("resources/templates/list", Some(0)),
                method("resources/list", Some(0)),
                method("prompts/list", Some(0)),
            ],
        );

        assert_eq!(verdict.status, ProbeStepStatus::Ok);
        assert!(verdict.requirements.iter().any(|requirement| {
            requirement.name == "tools/list pagination drain"
                && requirement.status == ProbeStepStatus::Ok
        }));
    }

    #[test]
    fn method_failure_detail_is_not_masked_by_non_empty_requirement() {
        let verdict = evaluate_catalog_profile(
            CatalogProfile::CodexDeferred,
            &[
                CatalogMethodSummary {
                    method: "tools/list".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some("upstream tool registry failed".to_string()),
                    page_count: None,
                    item_count: Some(0),
                },
                method("resources/templates/list", Some(0)),
                method("resources/list", Some(0)),
                method("prompts/list", Some(0)),
            ],
        );

        assert_eq!(verdict.status, ProbeStepStatus::Error);
        assert!(verdict.findings.iter().any(|finding| {
            finding.contains("tools/list") && finding.contains("upstream tool registry failed")
        }));
        assert!(!verdict
            .findings
            .iter()
            .any(|finding| finding.contains("method returned no discoverable items")));
    }
}
