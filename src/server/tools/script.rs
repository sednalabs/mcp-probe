use super::*;

#[rmcp::tool_router(router = tool_router_probe_script, vis = "pub")]
impl ProbeMcp {
    /// Run a scripted MCP probe scenario.
    #[tool(
        name = "probe_run_script",
        description = "Run a scripted MCP probe (tool calls with assertions, snapshots, and diffs)."
    )]
    async fn probe_run_script(
        &self,
        Parameters(args): Parameters<ProbeScriptArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let options = ScriptRunOptions {
                snapshot_write: args.snapshot_write.unwrap_or(false),
                scenario_path: args.scenario_path.clone(),
                client_info: None,
            };
            let report = run_script_scenario(args.scenario.clone(), options).await;
            let summary = if report.ok {
                "Script completed successfully."
            } else {
                "Script completed with errors."
            };
            let hints = if report.ok {
                Vec::new()
            } else {
                vec![
                    "Verify the target supports the requested tools and that auth is configured."
                        .to_string(),
                ]
            };
            let guidance = format_guidance(&hints);
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if !report.ok {
                parts.push(format_probe_script_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_run_script");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(report).unwrap_or(Value::Null),
            );
            if !hints.is_empty() {
                structured.insert(
                    "guidance".to_string(),
                    serde_json::to_value(hints).unwrap_or(Value::Null),
                );
            }
            Ok(build_result(content_text, Value::Object(structured), false))
        }
        .await;

        match result {
            Ok(value) => Ok(value),
            Err(message) => {
                let hints = vec![
                    "Confirm the scenario JSON is valid and required fields are set.".to_string(),
                ];
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(message.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_script_example());
                let content_text = format!("Script failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_run_script");
                structured.insert("error".to_string(), Value::String(message));
                structured.insert(
                    "guidance".to_string(),
                    serde_json::to_value(hints).unwrap_or(Value::Null),
                );
                Ok(build_result(content_text, Value::Object(structured), true))
            }
        }
    }

    /// Provide help text and examples for probe tools.
    #[tool(
        name = "probe_help",
        description = "List MCP probe tools, examples, and usage notes."
    )]
    async fn probe_help(
        &self,
        Parameters(args): Parameters<ProbeHelpArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let known_tools: Vec<String> = list_probe_tools()
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        let is_known = args
            .tool
            .as_ref()
            .map(|tool| known_tools.iter().any(|known| known == tool))
            .unwrap_or(true);
        let text = format_probe_help_text(args.tool.as_deref());

        let mut structured = structured_base("probe_help");
        structured.insert(
            "known_tools".to_string(),
            serde_json::to_value(&known_tools).unwrap_or(Value::Null),
        );
        if let Some(tool) = args.tool.as_ref() {
            structured.insert("tool_name".to_string(), Value::String(tool.clone()));
        }

        if !is_known {
            structured.insert(
                "error".to_string(),
                Value::String(format!(
                    "Unknown tool: {}",
                    args.tool.clone().unwrap_or_default()
                )),
            );
            return Ok(build_result(text, Value::Object(structured), true));
        }

        Ok(build_result(text, Value::Object(structured), false))
    }
}
