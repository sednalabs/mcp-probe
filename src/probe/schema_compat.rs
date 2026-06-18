//! Tool schema compatibility checks for client-facing MCP tool surfaces.

use crate::report::{
    ProbeStep, ProbeStepStatus, ToolSchemaCompatibilityFinding, ToolSchemaCompatibilitySeverity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;

pub const TOOL_SCHEMA_COMPATIBILITY_STEP: &str = "tools.schema_compatibility";

const ARRAY_ITEMS_NOT_OBJECT_HINT: &str =
    "Advertise arrays with an object-valued `items` schema. Avoid raw Value/boolean schemas in client-facing tool inputs.";
const BOOLEAN_SCHEMA_HINT: &str =
    "Replace unconstrained boolean schemas with typed object/string/number/boolean schemas or an explicit object wrapper.";
const INPUT_SCHEMA_HINT: &str =
    "Expose each tool inputSchema as an object-shaped JSON Schema suitable for function-style MCP clients.";
const OUTPUT_SCHEMA_HINT: &str =
    "Expose outputSchema as an object-shaped JSON Schema so ChatGPT can validate structuredContent.";
const ANNOTATIONS_HINT: &str =
    "Advertise MCP tool annotations with explicit readOnlyHint and destructiveHint booleans.";
const SECURITY_SCHEMES_HINT: &str =
    "Mirror security schemes in `_meta.securitySchemes` for ChatGPT connector compatibility.";
const INVOCATION_STATUS_HINT: &str =
    "Set `_meta.openai/toolInvocation/invoking` and `_meta.openai/toolInvocation/invoked` to concise strings.";
const TOOL_ONLY_UI_HINT: &str =
    "For tool-only ChatGPT connectors, omit UI template metadata and keep model visibility available.";
const APPS_SDK_UI_HINT: &str =
    "For Apps SDK UI tools, advertise a component template with `_meta.ui.resourceUri` or `_meta.openai/outputTemplate`, and keep app visibility available when visibility is explicit.";

/// Descriptor-readiness profile applied after `tools/list` succeeds.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ToolDescriptorProfile {
    /// Validate only generic MCP input schema compatibility.
    #[default]
    Basic,
    /// Validate a tool-only ChatGPT connector descriptor surface.
    ChatgptTool,
    /// Validate ChatGPT Apps SDK descriptors that are expected to expose UI templates.
    AppsSdkUi,
}

impl ToolDescriptorProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::ChatgptTool => "chatgpt_tool",
            Self::AppsSdkUi => "apps_sdk_ui",
        }
    }

    fn requires_chatgpt_metadata(self) -> bool {
        matches!(self, Self::ChatgptTool | Self::AppsSdkUi)
    }

    fn requires_apps_sdk_ui(self) -> bool {
        matches!(self, Self::AppsSdkUi)
    }
}

impl FromStr for ToolDescriptorProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "basic" => Ok(Self::Basic),
            "chatgpt_tool" | "chatgpt-tool" => Ok(Self::ChatgptTool),
            "apps_sdk_ui" | "apps-sdk-ui" => Ok(Self::AppsSdkUi),
            _ => Err(format!(
                "Invalid descriptor profile `{value}`. Expected one of: basic, chatgpt_tool, apps_sdk_ui."
            )),
        }
    }
}

/// Build the probe step that audits the advertised `tools/list` schema payload.
pub fn build_tool_schema_compatibility_step(tools_response: &Value) -> ProbeStep {
    build_tool_schema_compatibility_step_for_profile(tools_response, ToolDescriptorProfile::Basic)
}

/// Build the probe step with an explicit descriptor-readiness profile.
pub fn build_tool_schema_compatibility_step_for_profile(
    tools_response: &Value,
    descriptor_profile: ToolDescriptorProfile,
) -> ProbeStep {
    let findings = audit_tool_schema_compatibility_for_profile(tools_response, descriptor_profile);
    let error_count = findings
        .iter()
        .filter(|finding| finding.severity == ToolSchemaCompatibilitySeverity::Error)
        .count();
    let warning_count = findings.len().saturating_sub(error_count);

    let detail = if error_count > 0 {
        Some(format!(
            "{error_count} tool schema compatibility error(s); see data.findings"
        ))
    } else if warning_count > 0 {
        Some(format!(
            "{warning_count} tool schema compatibility warning(s); see data.findings"
        ))
    } else {
        None
    };

    ProbeStep {
        name: TOOL_SCHEMA_COMPATIBILITY_STEP.to_string(),
        status: if error_count > 0 {
            ProbeStepStatus::Error
        } else {
            ProbeStepStatus::Ok
        },
        detail,
        data: if findings.is_empty() {
            None
        } else {
            Some(json!({
                "error_count": error_count,
                "warning_count": warning_count,
                "findings": findings,
            }))
        },
    }
}

pub fn audit_tool_schema_compatibility(
    tools_response: &Value,
) -> Vec<ToolSchemaCompatibilityFinding> {
    audit_tool_schema_compatibility_for_profile(tools_response, ToolDescriptorProfile::Basic)
}

pub fn audit_tool_schema_compatibility_for_profile(
    tools_response: &Value,
    descriptor_profile: ToolDescriptorProfile,
) -> Vec<ToolSchemaCompatibilityFinding> {
    let Some(tools) = extract_tools(tools_response) else {
        return vec![finding(
            ToolSchemaCompatibilitySeverity::Error,
            "tools_list_shape_invalid",
            "<tools/list>",
            "",
            "tools/list response did not contain a `tools` array.",
            "Inspect the raw tools/list response; MCP clients expect a list result with a `tools` array.",
            Some(tools_response.clone()),
        )];
    };

    let mut findings = Vec::new();
    let mut apps_sdk_ui_descriptor_count = 0usize;
    for (index, tool) in tools.iter().enumerate() {
        let tool_name = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("<unnamed>");
        let schema_path = format!("/tools/{index}/inputSchema");
        match tool.get("inputSchema") {
            Some(schema) => audit_schema_node(tool_name, &schema_path, schema, &mut findings),
            None => findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "input_schema_missing",
                tool_name,
                &schema_path,
                "Tool descriptor is missing inputSchema.",
                INPUT_SCHEMA_HINT,
                Some(tool.clone()),
            )),
        }
        if descriptor_profile.requires_chatgpt_metadata() {
            audit_chatgpt_descriptor(
                tool_name,
                index,
                tool,
                descriptor_profile,
                &mut apps_sdk_ui_descriptor_count,
                &mut findings,
            );
        }
    }

    if descriptor_profile.requires_apps_sdk_ui() && apps_sdk_ui_descriptor_count == 0 {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "apps_sdk_ui_template_missing",
            "<tools/list>",
            "/tools",
            "No tool descriptor advertised an Apps SDK UI template.",
            APPS_SDK_UI_HINT,
            Some(tools_response.clone()),
        ));
    }
    findings
}

fn extract_tools(value: &Value) -> Option<&[Value]> {
    if let Some(tools) = value.get("tools").and_then(Value::as_array) {
        return Some(tools.as_slice());
    }
    value.as_array().map(Vec::as_slice)
}

fn audit_chatgpt_descriptor(
    tool_name: &str,
    index: usize,
    tool: &Value,
    descriptor_profile: ToolDescriptorProfile,
    apps_sdk_ui_descriptor_count: &mut usize,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    audit_output_schema(tool_name, index, tool, findings);
    audit_annotations(tool_name, index, tool, findings);
    audit_meta(
        tool_name,
        index,
        tool,
        descriptor_profile,
        apps_sdk_ui_descriptor_count,
        findings,
    );
}

fn audit_output_schema(
    tool_name: &str,
    index: usize,
    tool: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let path = format!("/tools/{index}/outputSchema");
    match tool.get("outputSchema") {
        Some(schema) if schema.is_object() => {
            audit_schema_root_object(
                "output_schema_root_not_object",
                tool_name,
                &path,
                schema,
                "Tool outputSchema root is not object-shaped.",
                OUTPUT_SCHEMA_HINT,
                findings,
            );
            audit_schema_node(tool_name, &path, schema, findings);
        }
        Some(schema) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "output_schema_not_object",
            tool_name,
            &path,
            "Tool outputSchema is not an object schema.",
            OUTPUT_SCHEMA_HINT,
            Some(schema.clone()),
        )),
        None => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "output_schema_missing",
            tool_name,
            &path,
            "Tool descriptor is missing outputSchema.",
            OUTPUT_SCHEMA_HINT,
            Some(tool.clone()),
        )),
    }
}

fn audit_annotations(
    tool_name: &str,
    index: usize,
    tool: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let path = format!("/tools/{index}/annotations");
    let Some(annotations) = tool.get("annotations") else {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "annotations_missing",
            tool_name,
            &path,
            "Tool descriptor is missing annotations.",
            ANNOTATIONS_HINT,
            Some(tool.clone()),
        ));
        return;
    };
    if !annotations.is_object() {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "annotations_not_object",
            tool_name,
            &path,
            "Tool annotations are not an object.",
            ANNOTATIONS_HINT,
            Some(annotations.clone()),
        ));
        return;
    }

    for key in ["readOnlyHint", "destructiveHint"] {
        let key_path = format!("{path}/{key}");
        if !matches!(annotations.get(key), Some(Value::Bool(_))) {
            findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                &format!("annotation_{}_missing", camel_to_snake(key)),
                tool_name,
                &key_path,
                &format!("Tool annotations.{key} is missing or not a boolean."),
                ANNOTATIONS_HINT,
                annotations.get(key).cloned(),
            ));
        }
    }
}

fn audit_meta(
    tool_name: &str,
    index: usize,
    tool: &Value,
    descriptor_profile: ToolDescriptorProfile,
    apps_sdk_ui_descriptor_count: &mut usize,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let path = format!("/tools/{index}/_meta");
    let Some(meta) = tool.get("_meta") else {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "_meta_missing",
            tool_name,
            &path,
            "Tool descriptor is missing `_meta` compatibility metadata.",
            SECURITY_SCHEMES_HINT,
            Some(tool.clone()),
        ));
        return;
    };
    if !meta.is_object() {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "_meta_not_object",
            tool_name,
            &path,
            "Tool `_meta` is not an object.",
            SECURITY_SCHEMES_HINT,
            Some(meta.clone()),
        ));
        return;
    }

    audit_security_schemes(tool_name, &path, meta, findings);
    audit_invocation_status(tool_name, &path, meta, findings);

    let has_apps_ui = has_apps_sdk_ui_template(meta);
    if has_apps_ui {
        *apps_sdk_ui_descriptor_count += 1;
    }

    if descriptor_profile == ToolDescriptorProfile::ChatgptTool {
        audit_tool_only_ui_metadata(tool_name, &path, meta, has_apps_ui, findings);
    } else if descriptor_profile.requires_apps_sdk_ui() && has_apps_ui {
        audit_apps_sdk_ui_metadata(tool_name, &path, meta, findings);
    }
}

fn audit_security_schemes(
    tool_name: &str,
    meta_path: &str,
    meta: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let path = format!("{meta_path}/securitySchemes");
    match meta.get("securitySchemes") {
        Some(Value::Array(values)) if !values.is_empty() => {}
        Some(Value::Array(_)) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "security_schemes_empty",
            tool_name,
            &path,
            "`_meta.securitySchemes` is empty.",
            SECURITY_SCHEMES_HINT,
            Some(Value::Array(Vec::new())),
        )),
        Some(value) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "security_schemes_not_array",
            tool_name,
            &path,
            "`_meta.securitySchemes` is not an array.",
            SECURITY_SCHEMES_HINT,
            Some(value.clone()),
        )),
        None => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "security_schemes_missing",
            tool_name,
            &path,
            "Tool descriptor is missing `_meta.securitySchemes`.",
            SECURITY_SCHEMES_HINT,
            Some(meta.clone()),
        )),
    }
}

fn audit_invocation_status(
    tool_name: &str,
    meta_path: &str,
    meta: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    for key in [
        "openai/toolInvocation/invoking",
        "openai/toolInvocation/invoked",
    ] {
        let path = format!("{meta_path}/{}", escape_json_pointer(key));
        match meta.get(key).and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() && value.chars().count() <= 64 => {}
            Some(value) if !value.trim().is_empty() => findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "invocation_status_too_long",
                tool_name,
                &path,
                "Tool invocation status text is longer than 64 characters.",
                INVOCATION_STATUS_HINT,
                Some(Value::String(value.to_string())),
            )),
            Some(value) => findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "invocation_status_blank",
                tool_name,
                &path,
                "Tool invocation status text is blank.",
                INVOCATION_STATUS_HINT,
                Some(Value::String(value.to_string())),
            )),
            None => findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "invocation_status_missing",
                tool_name,
                &path,
                "Tool descriptor is missing OpenAI invocation status text.",
                INVOCATION_STATUS_HINT,
                Some(meta.clone()),
            )),
        }
    }
}

fn audit_tool_only_ui_metadata(
    tool_name: &str,
    meta_path: &str,
    meta: &Value,
    has_apps_ui: bool,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let widget_path = format!(
        "{meta_path}/{}",
        escape_json_pointer("openai/widgetAccessible")
    );
    match meta.get("openai/widgetAccessible") {
        None | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "widget_accessible_true_for_tool_only",
            tool_name,
            &widget_path,
            "Tool-only descriptor enables widget-originated tool calls without an Apps SDK UI template.",
            TOOL_ONLY_UI_HINT,
            Some(Value::Bool(true)),
        )),
        Some(value) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "widget_accessible_not_boolean",
            tool_name,
            &widget_path,
            "`_meta.openai/widgetAccessible` is not a boolean.",
            TOOL_ONLY_UI_HINT,
            Some(value.clone()),
        )),
    }

    let visibility_path = format!("{meta_path}/ui/visibility");
    match meta.pointer("/ui/visibility") {
        Some(value) if includes_model_visibility(value) => {
            if includes_app_visibility(value) {
                findings.push(finding(
                    ToolSchemaCompatibilitySeverity::Warning,
                    "tool_only_ui_visibility_includes_app",
                    tool_name,
                    &visibility_path,
                    "Tool-only descriptor explicitly includes app visibility without an Apps SDK UI template.",
                    TOOL_ONLY_UI_HINT,
                    Some(value.clone()),
                ));
            }
        }
        Some(value) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "ui_visibility_excludes_model",
            tool_name,
            &visibility_path,
            "Tool-only descriptor UI visibility excludes the model.",
            TOOL_ONLY_UI_HINT,
            Some(value.clone()),
        )),
        None => {}
    }

    if has_apps_ui {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "tool_only_ui_template_present",
            tool_name,
            meta_path,
            "Tool-only descriptor advertised Apps SDK UI template metadata.",
            "Use descriptor_profile=apps_sdk_ui for UI-backed tools, or remove the UI template metadata from tool-only connectors.",
            Some(meta.clone()),
        ));
    }
}

fn audit_apps_sdk_ui_metadata(
    tool_name: &str,
    meta_path: &str,
    meta: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let widget_path = format!(
        "{meta_path}/{}",
        escape_json_pointer("openai/widgetAccessible")
    );
    if let Some(value) = meta.get("openai/widgetAccessible") {
        if !value.is_boolean() {
            findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "widget_accessible_not_boolean",
                tool_name,
                &widget_path,
                "`_meta.openai/widgetAccessible` is not a boolean.",
                APPS_SDK_UI_HINT,
                Some(value.clone()),
            ));
        }
    }

    let visibility_path = format!("{meta_path}/ui/visibility");
    if let Some(value) = meta.pointer("/ui/visibility") {
        if !includes_app_visibility(value) {
            findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "ui_visibility_excludes_app",
                tool_name,
                &visibility_path,
                "Apps SDK UI descriptor visibility excludes the app.",
                APPS_SDK_UI_HINT,
                Some(value.clone()),
            ));
        }
    }
}

fn includes_model_visibility(value: &Value) -> bool {
    visibility_contains(value, is_model_visibility_value)
}

fn includes_app_visibility(value: &Value) -> bool {
    visibility_contains(value, is_app_visibility_value)
}

fn visibility_contains(value: &Value, predicate: fn(&str) -> bool) -> bool {
    match value {
        Value::String(value) => predicate(value),
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str().map(predicate).unwrap_or(false)),
        _ => false,
    }
}

fn is_model_visibility_value(value: &str) -> bool {
    matches!(value, "model" | "model-only" | "model_only")
}

fn is_app_visibility_value(value: &str) -> bool {
    matches!(value, "app")
}

fn has_apps_sdk_ui_template(meta: &Value) -> bool {
    meta.get("openai/outputTemplate")
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || meta
            .pointer("/ui/resourceUri")
            .and_then(Value::as_str)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
}

fn audit_schema_node(
    tool_name: &str,
    path: &str,
    schema: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    match schema {
        Value::Bool(_) => {
            findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "boolean_schema",
                tool_name,
                path,
                "Schema node is a boolean schema, which is too unconstrained for common MCP function validators.",
                BOOLEAN_SCHEMA_HINT,
                Some(schema.clone()),
            ));
        }
        Value::Object(object) => {
            if path.ends_with("/inputSchema") {
                audit_input_schema_root(tool_name, path, schema, findings);
            }
            if is_array_schema(schema) {
                audit_array_items(tool_name, path, schema, findings);
            }

            for keyword in ["anyOf", "oneOf", "allOf"] {
                if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
                    for (index, branch) in branches.iter().enumerate() {
                        audit_schema_node(
                            tool_name,
                            &format!("{path}/{keyword}/{index}"),
                            branch,
                            findings,
                        );
                    }
                }
            }

            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                for (name, property_schema) in properties {
                    audit_schema_node(
                        tool_name,
                        &format!("{path}/properties/{}", escape_json_pointer(name)),
                        property_schema,
                        findings,
                    );
                }
            }

            if let Some(items) = object.get("items").filter(|_| is_array_schema(schema)) {
                if items.is_object() {
                    audit_schema_node(tool_name, &format!("{path}/items"), items, findings);
                }
            }

            for defs_keyword in ["$defs", "definitions"] {
                if let Some(defs) = object.get(defs_keyword).and_then(Value::as_object) {
                    for (name, def_schema) in defs {
                        audit_schema_node(
                            tool_name,
                            &format!("{path}/{defs_keyword}/{}", escape_json_pointer(name)),
                            def_schema,
                            findings,
                        );
                    }
                }
            }

            if let Some(additional_properties) = object.get("additionalProperties") {
                if additional_properties.is_object() {
                    audit_schema_node(
                        tool_name,
                        &format!("{path}/additionalProperties"),
                        additional_properties,
                        findings,
                    );
                }
            }
        }
        _ => {
            findings.push(finding(
                ToolSchemaCompatibilitySeverity::Error,
                "schema_node_not_object",
                tool_name,
                path,
                "Schema node is not an object schema.",
                "Use object-valued JSON Schema nodes for tool input properties and union branches.",
                Some(schema.clone()),
            ));
        }
    }
}

fn audit_input_schema_root(
    tool_name: &str,
    path: &str,
    schema: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    audit_schema_root_object(
        "input_schema_root_not_object",
        tool_name,
        path,
        schema,
        "Tool inputSchema root is not object-shaped.",
        INPUT_SCHEMA_HINT,
        findings,
    );
}

fn audit_schema_root_object(
    code: &str,
    tool_name: &str,
    path: &str,
    schema: &Value,
    message: &str,
    hint: &str,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let Some(schema_type) = schema.get("type") else {
        return;
    };
    let object_allowed = match schema_type {
        Value::String(value) => value == "object",
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some("object")),
        _ => false,
    };
    if !object_allowed {
        findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            code,
            tool_name,
            path,
            message,
            hint,
            Some(schema.clone()),
        ));
    }
}

fn audit_array_items(
    tool_name: &str,
    path: &str,
    schema: &Value,
    findings: &mut Vec<ToolSchemaCompatibilityFinding>,
) {
    let items_path = format!("{path}/items");
    match schema.get("items") {
        Some(Value::Object(_)) => {}
        Some(items) => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "array_items_not_object",
            tool_name,
            &items_path,
            "Array schema `items` is not an object schema.",
            ARRAY_ITEMS_NOT_OBJECT_HINT,
            Some(items.clone()),
        )),
        None => findings.push(finding(
            ToolSchemaCompatibilitySeverity::Error,
            "array_items_missing",
            tool_name,
            &items_path,
            "Array schema is missing `items`.",
            ARRAY_ITEMS_NOT_OBJECT_HINT,
            Some(schema.clone()),
        )),
    }
}

fn is_array_schema(schema: &Value) -> bool {
    let Some(schema_type) = schema.get("type") else {
        return false;
    };
    match schema_type {
        Value::String(value) => value == "array",
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some("array")),
        _ => false,
    }
}

fn finding(
    severity: ToolSchemaCompatibilitySeverity,
    code: &str,
    tool_name: &str,
    schema_path: &str,
    message: &str,
    hint: &str,
    fragment: Option<Value>,
) -> ToolSchemaCompatibilityFinding {
    ToolSchemaCompatibilityFinding {
        severity,
        code: code.to_string(),
        tool_name: tool_name.to_string(),
        schema_path: schema_path.to_string(),
        message: message.to_string(),
        hint: hint.to_string(),
        fragment,
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if ch.is_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.extend(ch.to_lowercase());
        } else {
            output.push(ch);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chatgpt_tool_descriptor() -> Value {
        json!({
            "name": "work_items_read",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "work_item_refs": {
                        "type": "array",
                        "items": { "type": "object", "properties": { "ref": { "type": "string" } } }
                    }
                }
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": { "type": "object", "properties": { "ref": { "type": "string" } } }
                    }
                }
            },
            "annotations": {
                "title": "Work Items Read",
                "readOnlyHint": true,
                "destructiveHint": false
            },
            "_meta": {
                "securitySchemes": [{ "type": "oauth2", "scopes": ["ops:read"] }],
                "openai/toolInvocation/invoking": "Reading work items",
                "openai/toolInvocation/invoked": "Read work items",
                "openai/widgetAccessible": false,
                "ui": { "visibility": ["model"] }
            }
        })
    }

    #[test]
    fn flags_boolean_array_items_from_tools_list() {
        let step = build_tool_schema_compatibility_step(&json!({
            "tools": [{
                "name": "work_items_read",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "work_item_refs": {
                            "type": "array",
                            "items": true
                        }
                    }
                }
            }]
        }));

        assert_eq!(
            serde_json::to_value(step).expect("serialize step"),
            json!({
                "name": "tools.schema_compatibility",
                "status": "error",
                "detail": "1 tool schema compatibility error(s); see data.findings",
                "data": {
                    "error_count": 1,
                    "warning_count": 0,
                    "findings": [{
                        "severity": "error",
                        "code": "array_items_not_object",
                        "tool_name": "work_items_read",
                        "schema_path": "/tools/0/inputSchema/properties/work_item_refs/items",
                        "message": "Array schema `items` is not an object schema.",
                        "hint": ARRAY_ITEMS_NOT_OBJECT_HINT,
                        "fragment": true
                    }]
                }
            })
        );
    }

    #[test]
    fn flags_array_union_branch_with_missing_items() {
        let findings = audit_tool_schema_compatibility(&json!({
            "tools": [{
                "name": "work_item_create",
                "inputSchema": {
                    "anyOf": [
                        { "type": "array" },
                        { "type": "object", "properties": {} }
                    ]
                }
            }]
        }));

        assert_eq!(
            serde_json::to_value(findings).expect("serialize findings"),
            json!([{
                "severity": "error",
                "code": "array_items_missing",
                "tool_name": "work_item_create",
                "schema_path": "/tools/0/inputSchema/anyOf/0/items",
                "message": "Array schema is missing `items`.",
                "hint": ARRAY_ITEMS_NOT_OBJECT_HINT,
                "fragment": { "type": "array" }
            }])
        );
    }

    #[test]
    fn flags_initial_links_array_branch_with_boolean_items() {
        let findings = audit_tool_schema_compatibility(&json!({
            "tools": [{
                "name": "work_item_create",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "initial_links": {
                            "anyOf": [
                                {
                                    "type": "array",
                                    "items": true
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "relation": { "type": "string" }
                                    }
                                }
                            ]
                        }
                    }
                }
            }]
        }));

        assert_eq!(
            serde_json::to_value(findings).expect("serialize findings"),
            json!([{
                "severity": "error",
                "code": "array_items_not_object",
                "tool_name": "work_item_create",
                "schema_path": "/tools/0/inputSchema/properties/initial_links/anyOf/0/items",
                "message": "Array schema `items` is not an object schema.",
                "hint": ARRAY_ITEMS_NOT_OBJECT_HINT,
                "fragment": true
            }])
        );
    }

    #[test]
    fn accepts_object_array_items_and_refs() {
        let step = build_tool_schema_compatibility_step(&json!({
            "tools": [{
                "name": "work_item_create",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "initial_links": {
                            "anyOf": [
                                { "type": "object", "properties": {} },
                                {
                                    "type": "array",
                                    "items": { "$ref": "#/$defs/InitialLinkArgItem" }
                                }
                            ]
                        }
                    },
                    "$defs": {
                        "InitialLinkArgItem": {
                            "type": "object",
                            "properties": {
                                "relation": { "type": "string" }
                            }
                        }
                    }
                }
            }]
        }));

        assert_eq!(
            serde_json::to_value(step).expect("serialize step"),
            json!({
                "name": "tools.schema_compatibility",
                "status": "ok"
            })
        );
    }

    #[test]
    fn basic_profile_does_not_require_chatgpt_descriptor_metadata() {
        let findings = audit_tool_schema_compatibility_for_profile(
            &json!({
                "tools": [{
                    "name": "plain_tool",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }]
            }),
            ToolDescriptorProfile::Basic,
        );

        assert_eq!(findings, Vec::new());
    }

    #[test]
    fn chatgpt_tool_profile_flags_missing_descriptor_metadata() {
        let findings = audit_tool_schema_compatibility_for_profile(
            &json!({
                "tools": [{
                    "name": "plain_tool",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }]
            }),
            ToolDescriptorProfile::ChatgptTool,
        );
        let codes: Vec<&str> = findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect();

        assert_eq!(
            codes,
            vec![
                "output_schema_missing",
                "annotations_missing",
                "_meta_missing"
            ]
        );
    }

    #[test]
    fn chatgpt_tool_profile_accepts_ops_style_tool_only_descriptor() {
        let step = build_tool_schema_compatibility_step_for_profile(
            &json!({
                "tools": [chatgpt_tool_descriptor()]
            }),
            ToolDescriptorProfile::ChatgptTool,
        );

        assert_eq!(
            serde_json::to_value(step).expect("serialize step"),
            json!({
                "name": "tools.schema_compatibility",
                "status": "ok"
            })
        );
    }

    #[test]
    fn chatgpt_tool_profile_accepts_tool_only_descriptor_defaults() {
        let mut descriptor = chatgpt_tool_descriptor();
        let meta = descriptor
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .expect("_meta object");
        meta.remove("openai/widgetAccessible");
        meta.remove("ui");

        let step = build_tool_schema_compatibility_step_for_profile(
            &json!({
                "tools": [descriptor]
            }),
            ToolDescriptorProfile::ChatgptTool,
        );

        assert_eq!(
            serde_json::to_value(step).expect("serialize step"),
            json!({
                "name": "tools.schema_compatibility",
                "status": "ok"
            })
        );
    }

    #[test]
    fn chatgpt_tool_profile_rejects_widget_access_without_ui_template() {
        let mut descriptor = chatgpt_tool_descriptor();
        let meta = descriptor
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .expect("_meta object");
        meta.insert("openai/widgetAccessible".to_string(), Value::Bool(true));

        let findings = audit_tool_schema_compatibility_for_profile(
            &json!({
                "tools": [descriptor]
            }),
            ToolDescriptorProfile::ChatgptTool,
        );

        assert_eq!(
            serde_json::to_value(findings).expect("serialize findings"),
            json!([{
                "severity": "error",
                "code": "widget_accessible_true_for_tool_only",
                "tool_name": "work_items_read",
                "schema_path": "/tools/0/_meta/openai~1widgetAccessible",
                "message": "Tool-only descriptor enables widget-originated tool calls without an Apps SDK UI template.",
                "hint": TOOL_ONLY_UI_HINT,
                "fragment": true
            }])
        );
    }

    #[test]
    fn apps_sdk_ui_profile_requires_a_ui_template() {
        let findings = audit_tool_schema_compatibility_for_profile(
            &json!({
                "tools": [chatgpt_tool_descriptor()]
            }),
            ToolDescriptorProfile::AppsSdkUi,
        );
        let codes: Vec<&str> = findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect();

        assert_eq!(codes, vec!["apps_sdk_ui_template_missing"]);
    }

    #[test]
    fn apps_sdk_ui_profile_accepts_openai_output_template_descriptor() {
        let mut descriptor = chatgpt_tool_descriptor();
        let meta = descriptor
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .expect("_meta object");
        meta.insert(
            "openai/outputTemplate".to_string(),
            Value::String("ui://widget/work-items.html".to_string()),
        );
        meta.insert("openai/widgetAccessible".to_string(), Value::Bool(true));
        meta.remove("ui");

        let step = build_tool_schema_compatibility_step_for_profile(
            &json!({
                "tools": [descriptor]
            }),
            ToolDescriptorProfile::AppsSdkUi,
        );

        assert_eq!(
            serde_json::to_value(step).expect("serialize step"),
            json!({
                "name": "tools.schema_compatibility",
                "status": "ok"
            })
        );
    }

    #[test]
    fn apps_sdk_ui_profile_accepts_standard_resource_uri_descriptor() {
        let mut descriptor = chatgpt_tool_descriptor();
        let meta = descriptor
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .expect("_meta object");
        meta.remove("openai/widgetAccessible");
        meta.insert(
            "ui".to_string(),
            json!({
                "resourceUri": "ui://widget/work-items.html",
                "visibility": ["model", "app"]
            }),
        );

        let step = build_tool_schema_compatibility_step_for_profile(
            &json!({
                "tools": [descriptor]
            }),
            ToolDescriptorProfile::AppsSdkUi,
        );

        assert_eq!(
            serde_json::to_value(step).expect("serialize step"),
            json!({
                "name": "tools.schema_compatibility",
                "status": "ok"
            })
        );
    }

    #[test]
    fn apps_sdk_ui_profile_rejects_explicit_visibility_without_app() {
        let mut descriptor = chatgpt_tool_descriptor();
        let meta = descriptor
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .expect("_meta object");
        meta.remove("openai/widgetAccessible");
        meta.insert(
            "ui".to_string(),
            json!({
                "resourceUri": "ui://widget/work-items.html",
                "visibility": ["model"]
            }),
        );

        let findings = audit_tool_schema_compatibility_for_profile(
            &json!({
                "tools": [descriptor]
            }),
            ToolDescriptorProfile::AppsSdkUi,
        );

        assert_eq!(
            serde_json::to_value(findings).expect("serialize findings"),
            json!([{
                "severity": "error",
                "code": "ui_visibility_excludes_app",
                "tool_name": "work_items_read",
                "schema_path": "/tools/0/_meta/ui/visibility",
                "message": "Apps SDK UI descriptor visibility excludes the app.",
                "hint": APPS_SDK_UI_HINT,
                "fragment": ["model"]
            }])
        );
    }
}
