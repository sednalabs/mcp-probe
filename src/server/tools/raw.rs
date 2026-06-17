use super::*;

#[rmcp::tool_router(router = tool_router_probe_raw, vis = "pub")]
impl ProbeMcp {
    /// Send a raw MCP request for low-level debugging.
    #[tool(
        name = "probe_raw_request",
        description = "Send an MCP request by method name for low-level debugging."
    )]
    async fn probe_raw_request(
        &self,
        Parameters(args): Parameters<ProbeRawRequestArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let dry_run = if let Some(dry_run) = args.dry_run {
                dry_run
            } else {
                matches!(args.allow_tool_calls, Some(false))
            };

            let resolved = resolve_auth_headers(
                args.transport,
                args.url.as_deref(),
                args.headers.clone(),
                args.use_auth,
                args.access_token.as_deref(),
                args.access_token_path.as_deref(),
                args.refresh_token.as_deref(),
                args.refresh_token_path.as_deref(),
                args.client_id.as_deref(),
                args.client_secret.as_deref(),
                args.token_endpoint.as_deref(),
                args.scope.as_deref(),
                args.timeout_ms,
                dry_run,
            )
            .await?;

            if dry_run {
                let param_keys: Vec<String> = args
                    .params
                    .as_ref()
                    .map(|params| params.keys().cloned().collect())
                    .unwrap_or_default();
                let mut lines = vec![
                    "Dry run: request not sent.".to_string(),
                    format!("Method: {}", args.method),
                    format!("Transport: {}", args.transport),
                ];
                if let Some(url) = args.url.as_ref() {
                    let mut line = String::from("URL: ");
                    line.push_str(url);
                    lines.push(line);
                }
                lines.push(format!("Auth: {}", resolved.auth_source));
                lines.push(format!("Params: {} key(s)", param_keys.len()));
                if !param_keys.is_empty() {
                    lines.push(format!("Param keys: {}", param_keys.join(", ")));
                }
                if resolved.refresh_skipped {
                    lines.push("Note: refresh_token not exchanged in dry_run.".to_string());
                }
                let mut structured = structured_base("probe_raw_request");
                structured.insert("dry_run".to_string(), Value::Bool(true));
                let mut request = serde_json::Map::new();
                request.insert(
                    "transport".to_string(),
                    Value::String(args.transport.as_str().to_string()),
                );
                if let Some(url) = args.url.as_ref() {
                    request.insert("url".to_string(), Value::String(url.to_string()));
                }
                request.insert("method".to_string(), Value::String(args.method.clone()));
                request.insert(
                    "param_keys".to_string(),
                    serde_json::to_value(param_keys).unwrap_or(Value::Null),
                );
                request.insert(
                    "auth_source".to_string(),
                    Value::String(resolved.auth_source),
                );
                if resolved.refresh_skipped {
                    request.insert("auth_refresh_skipped".to_string(), Value::Bool(true));
                }
                structured.insert("request".to_string(), Value::Object(request));
                return Ok(build_result(
                    lines.join("\n"),
                    Value::Object(structured),
                    false,
                ));
            }

            let params_value = args
                .params
                .as_ref()
                .map(|params| serde_json::to_value(params).unwrap_or(Value::Null))
                .filter(|value| !value.is_null());

            let report = run_raw_request(
                RawRequestTarget {
                    transport_type: args.transport,
                    command: args.command.clone(),
                    args: args.args.clone(),
                    cwd: args.cwd.clone(),
                    env: args.env.clone(),
                    url: args.url.clone(),
                    headers: resolved.headers,
                    timeout_ms: args.timeout_ms,
                    retries: args.retries,
                    retry_delay_ms: args.retry_delay_ms,
                    expect_auth_required: args.expect_auth_required,
                    log_level: args.log_level,
                    log_format: args.log_format,
                    trace: args.trace,
                    trace_limit: args.trace_limit,
                    trace_max_bytes: args.trace_max_bytes,
                    method: args.method.clone(),
                    params: params_value,
                    expect_error: args.expect_error.clone(),
                },
                None,
                None,
            )
            .await;

            let output_report = apply_raw_report_verbosity(report.clone(), args.verbosity);
            let summary = if report.ok {
                "Raw request completed successfully."
            } else {
                "Raw request completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let diagnostics = failure_diagnostics_from_raw_report(
                &report,
                Some(args.method.clone()),
                Some(args.transport),
            );
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            let guidance = format_guidance(&hints);
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(summary) = failure_summary {
                parts.push(summary);
            }
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if !report.ok {
                parts.push(format_probe_raw_request_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_raw_request");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(output_report).unwrap_or(Value::Null),
            );
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
                    "method": args.method,
                }),
            );
            if let Some(diagnostics) = diagnostics.as_ref() {
                structured.insert(
                    "diagnostics".to_string(),
                    serde_json::to_value(diagnostics).unwrap_or(Value::Null),
                );
            }
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
                let translated = translate_verbosity_error(&message);
                let hints = build_common_guidance_from_error(&translated);
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(translated.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_raw_request_example());
                let content_text = format!("Raw request failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_raw_request");
                structured.insert("error".to_string(), Value::String(translated));
                if !hints.is_empty() {
                    structured.insert(
                        "guidance".to_string(),
                        serde_json::to_value(hints).unwrap_or(Value::Null),
                    );
                }
                Ok(build_result(content_text, Value::Object(structured), true))
            }
        }
    }

    /// Connect and call a single MCP tool.
    #[tool(
        name = "probe_call_tool",
        description = "Connect and call a single tool by name with arguments."
    )]
    async fn probe_call_tool(
        &self,
        Parameters(args): Parameters<ProbeCallToolArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let dry_run = if let Some(dry_run) = args.dry_run {
                dry_run
            } else {
                matches!(args.allow_tool_calls, Some(false))
            };

            let resolved = resolve_auth_headers(
                args.transport,
                args.url.as_deref(),
                args.headers.clone(),
                args.use_auth,
                args.access_token.as_deref(),
                args.access_token_path.as_deref(),
                args.refresh_token.as_deref(),
                args.refresh_token_path.as_deref(),
                args.client_id.as_deref(),
                args.client_secret.as_deref(),
                args.token_endpoint.as_deref(),
                args.scope.as_deref(),
                args.timeout_ms,
                dry_run,
            )
            .await?;

            if dry_run {
                let argument_keys: Vec<String> = args
                    .arguments
                    .as_ref()
                    .map(|params| params.keys().cloned().collect())
                    .unwrap_or_default();
                let mut lines = vec![
                    "Dry run: tools/call not sent.".to_string(),
                    format!("Tool: {}", args.tool_name),
                    format!("Transport: {}", args.transport),
                ];
                if let Some(url) = args.url.as_ref() {
                    let mut line = String::from("URL: ");
                    line.push_str(url);
                    lines.push(line);
                }
                lines.push(format!("Auth: {}", resolved.auth_source));
                lines.push(format!("Arguments: {} key(s)", argument_keys.len()));
                if !argument_keys.is_empty() {
                    lines.push(format!("Argument keys: {}", argument_keys.join(", ")));
                }
                if resolved.refresh_skipped {
                    lines.push("Note: refresh_token not exchanged in dry_run.".to_string());
                }
                let mut structured = structured_base("probe_call_tool");
                structured.insert("dry_run".to_string(), Value::Bool(true));
                let mut request = serde_json::Map::new();
                request.insert(
                    "transport".to_string(),
                    Value::String(args.transport.as_str().to_string()),
                );
                if let Some(url) = args.url.as_ref() {
                    request.insert("url".to_string(), Value::String(url.to_string()));
                }
                request.insert(
                    "method".to_string(),
                    Value::String("tools/call".to_string()),
                );
                request.insert(
                    "tool_name".to_string(),
                    Value::String(args.tool_name.clone()),
                );
                request.insert(
                    "argument_keys".to_string(),
                    serde_json::to_value(argument_keys).unwrap_or(Value::Null),
                );
                request.insert(
                    "auth_source".to_string(),
                    Value::String(resolved.auth_source),
                );
                if resolved.refresh_skipped {
                    request.insert("auth_refresh_skipped".to_string(), Value::Bool(true));
                }
                structured.insert("request".to_string(), Value::Object(request));
                return Ok(build_result(
                    lines.join("\n"),
                    Value::Object(structured),
                    false,
                ));
            }

            let params = json!({
                "name": args.tool_name,
                "arguments": args.arguments.unwrap_or_default(),
            });

            let report = run_raw_request(
                RawRequestTarget {
                    transport_type: args.transport,
                    command: args.command.clone(),
                    args: args.args.clone(),
                    cwd: args.cwd.clone(),
                    env: args.env.clone(),
                    url: args.url.clone(),
                    headers: resolved.headers,
                    timeout_ms: args.timeout_ms,
                    retries: args.retries,
                    retry_delay_ms: args.retry_delay_ms,
                    expect_auth_required: args.expect_auth_required,
                    log_level: args.log_level,
                    log_format: args.log_format,
                    trace: args.trace,
                    trace_limit: args.trace_limit,
                    trace_max_bytes: args.trace_max_bytes,
                    method: "tools/call".to_string(),
                    params: Some(params),
                    expect_error: args.expect_error.clone(),
                },
                None,
                None,
            )
            .await;

            let output_report = apply_raw_report_verbosity(report.clone(), args.verbosity);
            let summary = if report.ok {
                "Tool call completed successfully."
            } else {
                "Tool call completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let diagnostics = failure_diagnostics_from_raw_report(
                &report,
                Some(format!("tools/call -> {}", args.tool_name)),
                Some(args.transport),
            );
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            let guidance = format_guidance(&hints);
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(summary) = failure_summary {
                parts.push(summary);
            }
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if !report.ok {
                parts.push(format_probe_call_tool_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_call_tool");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(output_report).unwrap_or(Value::Null),
            );
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
                    "method": "tools/call",
                    "tool_name": args.tool_name,
                }),
            );
            if let Some(diagnostics) = diagnostics.as_ref() {
                structured.insert(
                    "diagnostics".to_string(),
                    serde_json::to_value(diagnostics).unwrap_or(Value::Null),
                );
            }
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
                let translated = translate_verbosity_error(&message);
                let hints = build_common_guidance_from_error(&translated);
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(translated.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_call_tool_example());
                let content_text = format!("Tool call failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_call_tool");
                structured.insert("error".to_string(), Value::String(translated));
                if !hints.is_empty() {
                    structured.insert(
                        "guidance".to_string(),
                        serde_json::to_value(hints).unwrap_or(Value::Null),
                    );
                }
                Ok(build_result(content_text, Value::Object(structured), true))
            }
        }
    }

    /// Connect and render a single MCP prompt.
    #[tool(
        name = "probe_prompt_render",
        description = "Connect and render a single prompt by name with arguments."
    )]
    async fn probe_prompt_render(
        &self,
        Parameters(args): Parameters<ProbePromptRenderArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let dry_run = args.dry_run.unwrap_or(false);
            let resolved = resolve_auth_headers(
                args.transport,
                args.url.as_deref(),
                args.headers.clone(),
                args.use_auth,
                args.access_token.as_deref(),
                args.access_token_path.as_deref(),
                args.refresh_token.as_deref(),
                args.refresh_token_path.as_deref(),
                args.client_id.as_deref(),
                args.client_secret.as_deref(),
                args.token_endpoint.as_deref(),
                args.scope.as_deref(),
                args.timeout_ms,
                dry_run,
            )
            .await?;

            if dry_run {
                let argument_keys: Vec<String> = args
                    .arguments
                    .as_ref()
                    .map(|params| params.keys().cloned().collect())
                    .unwrap_or_default();
                let mut lines = vec![
                    "Dry run: prompts/get not sent.".to_string(),
                    format!("Prompt: {}", args.prompt_name),
                    format!("Transport: {}", args.transport),
                ];
                if let Some(url) = args.url.as_ref() {
                    let mut line = String::from("URL: ");
                    line.push_str(url);
                    lines.push(line);
                }
                lines.push(format!("Auth: {}", resolved.auth_source));
                lines.push(format!("Arguments: {} key(s)", argument_keys.len()));
                if !argument_keys.is_empty() {
                    lines.push(format!("Argument keys: {}", argument_keys.join(", ")));
                }
                if resolved.refresh_skipped {
                    lines.push("Note: refresh_token not exchanged in dry_run.".to_string());
                }
                let mut structured = structured_base("probe_prompt_render");
                structured.insert("dry_run".to_string(), Value::Bool(true));
                let mut request = serde_json::Map::new();
                request.insert(
                    "transport".to_string(),
                    Value::String(args.transport.as_str().to_string()),
                );
                if let Some(url) = args.url.as_ref() {
                    request.insert("url".to_string(), Value::String(url.to_string()));
                }
                request.insert(
                    "method".to_string(),
                    Value::String("prompts/get".to_string()),
                );
                request.insert(
                    "prompt_name".to_string(),
                    Value::String(args.prompt_name.clone()),
                );
                request.insert(
                    "argument_keys".to_string(),
                    serde_json::to_value(argument_keys).unwrap_or(Value::Null),
                );
                request.insert(
                    "auth_source".to_string(),
                    Value::String(resolved.auth_source),
                );
                if resolved.refresh_skipped {
                    request.insert("auth_refresh_skipped".to_string(), Value::Bool(true));
                }
                structured.insert("request".to_string(), Value::Object(request));
                return Ok(build_result(
                    lines.join("\n"),
                    Value::Object(structured),
                    false,
                ));
            }

            let report = run_raw_request(
                RawRequestTarget {
                    transport_type: args.transport,
                    command: args.command.clone(),
                    args: args.args.clone(),
                    cwd: args.cwd.clone(),
                    env: args.env.clone(),
                    url: args.url.clone(),
                    headers: resolved.headers,
                    timeout_ms: args.timeout_ms,
                    retries: args.retries,
                    retry_delay_ms: args.retry_delay_ms,
                    expect_auth_required: args.expect_auth_required,
                    log_level: args.log_level,
                    log_format: args.log_format,
                    trace: args.trace,
                    trace_limit: args.trace_limit,
                    trace_max_bytes: args.trace_max_bytes,
                    method: "prompts/get".to_string(),
                    params: Some(build_prompt_render_params(
                        &args.prompt_name,
                        args.arguments.clone(),
                    )),
                    expect_error: args.expect_error.clone(),
                },
                None,
                None,
            )
            .await;

            let output_report = apply_raw_report_verbosity(report.clone(), args.verbosity);
            let summary = if report.ok {
                "Prompt render completed successfully."
            } else {
                "Prompt render completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let diagnostics = failure_diagnostics_from_raw_report(
                &report,
                Some(format!("prompts/get -> {}", args.prompt_name)),
                Some(args.transport),
            );
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            let guidance = format_guidance(&hints);
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(summary) = failure_summary {
                parts.push(summary);
            }
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if !report.ok {
                parts.push(format_probe_prompt_render_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_prompt_render");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(output_report).unwrap_or(Value::Null),
            );
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
                    "method": "prompts/get",
                    "prompt_name": args.prompt_name,
                }),
            );
            if let Some(diagnostics) = diagnostics.as_ref() {
                structured.insert(
                    "diagnostics".to_string(),
                    serde_json::to_value(diagnostics).unwrap_or(Value::Null),
                );
            }
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
                let translated = translate_verbosity_error(&message);
                let hints = build_common_guidance_from_error(&translated);
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(translated.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_prompt_render_example());
                let content_text = format!("Prompt render failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_prompt_render");
                structured.insert("error".to_string(), Value::String(translated));
                if !hints.is_empty() {
                    structured.insert(
                        "guidance".to_string(),
                        serde_json::to_value(hints).unwrap_or(Value::Null),
                    );
                }
                Ok(build_result(content_text, Value::Object(structured), true))
            }
        }
    }

    /// Connect and read one MCP resource by URI.
    #[tool(
        name = "probe_resource_read",
        description = "Connect and read one resource URI, returning resource contents and metadata."
    )]
    async fn probe_resource_read(
        &self,
        Parameters(args): Parameters<ProbeResourceReadArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let dry_run = args.dry_run.unwrap_or(false);
            let resolved = resolve_auth_headers(
                args.transport,
                args.url.as_deref(),
                args.headers.clone(),
                args.use_auth,
                args.access_token.as_deref(),
                args.access_token_path.as_deref(),
                args.refresh_token.as_deref(),
                args.refresh_token_path.as_deref(),
                args.client_id.as_deref(),
                args.client_secret.as_deref(),
                args.token_endpoint.as_deref(),
                args.scope.as_deref(),
                args.timeout_ms,
                dry_run,
            )
            .await?;

            if dry_run {
                let mut lines = vec![
                    "Dry run: resources/read not sent.".to_string(),
                    format!("URI: {}", args.uri),
                    format!("Transport: {}", args.transport),
                ];
                if let Some(url) = args.url.as_ref() {
                    let mut line = String::from("URL: ");
                    line.push_str(url);
                    lines.push(line);
                }
                lines.push(format!("Auth: {}", resolved.auth_source));
                if resolved.refresh_skipped {
                    lines.push("Note: refresh_token not exchanged in dry_run.".to_string());
                }
                let mut structured = structured_base("probe_resource_read");
                structured.insert("dry_run".to_string(), Value::Bool(true));
                structured.insert(
                    "request".to_string(),
                    json!({
                        "transport": args.transport.as_str(),
                        "url": args.url,
                        "method": "resources/read",
                        "uri": args.uri,
                        "auth_source": resolved.auth_source,
                        "auth_refresh_skipped": resolved.refresh_skipped,
                    }),
                );
                return Ok(build_result(
                    lines.join("\n"),
                    Value::Object(structured),
                    false,
                ));
            }

            let report = run_raw_request(
                RawRequestTarget {
                    transport_type: args.transport,
                    command: args.command.clone(),
                    args: args.args.clone(),
                    cwd: args.cwd.clone(),
                    env: args.env.clone(),
                    url: args.url.clone(),
                    headers: resolved.headers,
                    timeout_ms: args.timeout_ms,
                    retries: args.retries,
                    retry_delay_ms: args.retry_delay_ms,
                    expect_auth_required: args.expect_auth_required,
                    log_level: args.log_level,
                    log_format: args.log_format,
                    trace: args.trace,
                    trace_limit: args.trace_limit,
                    trace_max_bytes: args.trace_max_bytes,
                    method: "resources/read".to_string(),
                    params: Some(build_resource_uri_params(&args.uri)),
                    expect_error: args.expect_error.clone(),
                },
                None,
                None,
            )
            .await;

            let output_report = apply_raw_report_verbosity(report.clone(), args.verbosity);
            let summary = if report.ok {
                "Resource read completed successfully."
            } else {
                "Resource read completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let diagnostics = failure_diagnostics_from_raw_report(
                &report,
                Some(format!("resources/read -> {}", args.uri)),
                Some(args.transport),
            );
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            let guidance = format_guidance(&hints);
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(summary) = failure_summary {
                parts.push(summary);
            }
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if !report.ok {
                parts.push(format_probe_resource_read_example());
            }
            let mut structured = structured_base("probe_resource_read");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(output_report).unwrap_or(Value::Null),
            );
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
                    "method": "resources/read",
                    "uri": args.uri,
                }),
            );
            if let Some(diagnostics) = diagnostics.as_ref() {
                structured.insert(
                    "diagnostics".to_string(),
                    serde_json::to_value(diagnostics).unwrap_or(Value::Null),
                );
            }
            if !hints.is_empty() {
                structured.insert(
                    "guidance".to_string(),
                    serde_json::to_value(hints).unwrap_or(Value::Null),
                );
            }
            Ok(build_result(
                parts.join("\n\n"),
                Value::Object(structured),
                false,
            ))
        }
        .await;

        match result {
            Ok(value) => Ok(value),
            Err(message) => {
                let translated = translate_verbosity_error(&message);
                let hints = build_common_guidance_from_error(&translated);
                let guidance = format_guidance(&hints);
                let mut parts = vec![translated.clone()];
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_resource_read_example());
                let mut structured = structured_base("probe_resource_read");
                structured.insert("error".to_string(), Value::String(translated));
                if !hints.is_empty() {
                    structured.insert(
                        "guidance".to_string(),
                        serde_json::to_value(hints).unwrap_or(Value::Null),
                    );
                }
                Ok(build_result(
                    format!("Resource read failed: {}", parts.join("\n\n")),
                    Value::Object(structured),
                    true,
                ))
            }
        }
    }

    /// Connect, subscribe to one MCP resource URI, then unsubscribe.
    #[tool(
        name = "probe_resource_subscribe",
        description = "Connect, send resources/subscribe for a URI, then send resources/unsubscribe."
    )]
    async fn probe_resource_subscribe(
        &self,
        Parameters(args): Parameters<ProbeResourceSubscribeArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let dry_run = args.dry_run.unwrap_or(false);
            let resolved = resolve_auth_headers(
                args.transport,
                args.url.as_deref(),
                args.headers.clone(),
                args.use_auth,
                args.access_token.as_deref(),
                args.access_token_path.as_deref(),
                args.refresh_token.as_deref(),
                args.refresh_token_path.as_deref(),
                args.client_id.as_deref(),
                args.client_secret.as_deref(),
                args.token_endpoint.as_deref(),
                args.scope.as_deref(),
                args.timeout_ms,
                dry_run,
            )
            .await?;

            if dry_run {
                let mut lines = vec![
                    "Dry run: resources/subscribe and resources/unsubscribe not sent.".to_string(),
                    format!("URI: {}", args.uri),
                    format!("Transport: {}", args.transport),
                ];
                if let Some(url) = args.url.as_ref() {
                    let mut line = String::from("URL: ");
                    line.push_str(url);
                    lines.push(line);
                }
                lines.push(format!("Auth: {}", resolved.auth_source));
                if resolved.refresh_skipped {
                    lines.push("Note: refresh_token not exchanged in dry_run.".to_string());
                }
                let mut structured = structured_base("probe_resource_subscribe");
                structured.insert("dry_run".to_string(), Value::Bool(true));
                structured.insert(
                    "request".to_string(),
                    json!({
                        "transport": args.transport.as_str(),
                        "url": args.url,
                        "methods": ["resources/subscribe", "resources/unsubscribe"],
                        "uri": args.uri,
                        "auth_source": resolved.auth_source,
                        "auth_refresh_skipped": resolved.refresh_skipped,
                    }),
                );
                return Ok(build_result(
                    lines.join("\n"),
                    Value::Object(structured),
                    false,
                ));
            }

            let params = Some(build_resource_uri_params(&args.uri));
            let subscribe_report = run_raw_request(
                RawRequestTarget {
                    transport_type: args.transport,
                    command: args.command.clone(),
                    args: args.args.clone(),
                    cwd: args.cwd.clone(),
                    env: args.env.clone(),
                    url: args.url.clone(),
                    headers: resolved.headers.clone(),
                    timeout_ms: args.timeout_ms,
                    retries: args.retries,
                    retry_delay_ms: args.retry_delay_ms,
                    expect_auth_required: args.expect_auth_required,
                    log_level: args.log_level,
                    log_format: args.log_format,
                    trace: args.trace,
                    trace_limit: args.trace_limit,
                    trace_max_bytes: args.trace_max_bytes,
                    method: "resources/subscribe".to_string(),
                    params: params.clone(),
                    expect_error: args.expect_error.clone(),
                },
                None,
                None,
            )
            .await;

            let should_unsubscribe = subscribe_report.ok && args.expect_error.is_none();
            let unsubscribe_report = if should_unsubscribe {
                Some(
                    run_raw_request(
                        RawRequestTarget {
                            transport_type: args.transport,
                            command: args.command.clone(),
                            args: args.args.clone(),
                            cwd: args.cwd.clone(),
                            env: args.env.clone(),
                            url: args.url.clone(),
                            headers: resolved.headers,
                            timeout_ms: args.timeout_ms,
                            retries: args.retries,
                            retry_delay_ms: args.retry_delay_ms,
                            expect_auth_required: args.expect_auth_required,
                            log_level: args.log_level,
                            log_format: args.log_format,
                            trace: args.trace,
                            trace_limit: args.trace_limit,
                            trace_max_bytes: args.trace_max_bytes,
                            method: "resources/unsubscribe".to_string(),
                            params,
                            expect_error: args.unsubscribe_expect_error.clone(),
                        },
                        None,
                        None,
                    )
                    .await,
                )
            } else {
                None
            };

            let unsubscribe_ok = unsubscribe_report
                .as_ref()
                .map(|report| report.ok)
                .unwrap_or(!should_unsubscribe);
            let ok = subscribe_report.ok && unsubscribe_ok;
            let summary = if ok {
                "Resource subscription check completed successfully."
            } else {
                "Resource subscription check completed with errors."
            };
            let failure_summary = if !subscribe_report.ok {
                format_failure_summary(&subscribe_report.steps, 3)
            } else if let Some(report) = unsubscribe_report.as_ref() {
                if !report.ok {
                    format_failure_summary(&report.steps, 3)
                } else {
                    None
                }
            } else {
                None
            };
            let diagnostic_source = if !subscribe_report.ok {
                Some((&subscribe_report, "resources/subscribe"))
            } else if let Some(report) = unsubscribe_report.as_ref() {
                if !report.ok {
                    Some((report, "resources/unsubscribe"))
                } else {
                    None
                }
            } else {
                None
            };
            let diagnostics = diagnostic_source.and_then(|(report, method)| {
                failure_diagnostics_from_raw_report(
                    report,
                    Some(format!("{method} -> {}", args.uri)),
                    Some(args.transport),
                )
            });
            let mut hints = if ok {
                Vec::new()
            } else if !subscribe_report.ok {
                build_common_guidance_from_report(&subscribe_report.steps)
            } else if let Some(report) = unsubscribe_report.as_ref() {
                build_common_guidance_from_report(&report.steps)
            } else {
                Vec::new()
            };
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            let mut parts = vec![summary.to_string()];
            if let Some(summary) = failure_summary {
                parts.push(summary);
            }
            if !should_unsubscribe {
                parts.push(
                    "Unsubscribe was skipped because subscribe did not establish a normal active subscription."
                        .to_string(),
                );
            }
            if let Some(guidance) = format_guidance(&hints) {
                parts.push(guidance);
            }
            if !ok {
                parts.push(format_probe_resource_subscribe_example());
            }

            let mut reports = serde_json::Map::new();
            reports.insert(
                "subscribe".to_string(),
                serde_json::to_value(apply_raw_report_verbosity(
                    subscribe_report,
                    args.verbosity.clone(),
                ))
                .unwrap_or(Value::Null),
            );
            if let Some(report) = unsubscribe_report {
                reports.insert(
                    "unsubscribe".to_string(),
                    serde_json::to_value(apply_raw_report_verbosity(report, args.verbosity))
                        .unwrap_or(Value::Null),
                );
            } else {
                reports.insert("unsubscribe".to_string(), Value::Null);
            }

            let mut structured = structured_base("probe_resource_subscribe");
            structured.insert("ok".to_string(), Value::Bool(ok));
            structured.insert("reports".to_string(), Value::Object(reports));
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
                    "methods": ["resources/subscribe", "resources/unsubscribe"],
                    "uri": args.uri,
                }),
            );
            if let Some(diagnostics) = diagnostics.as_ref() {
                structured.insert(
                    "diagnostics".to_string(),
                    serde_json::to_value(diagnostics).unwrap_or(Value::Null),
                );
            }
            if !hints.is_empty() {
                structured.insert(
                    "guidance".to_string(),
                    serde_json::to_value(hints).unwrap_or(Value::Null),
                );
            }
            Ok(build_result(parts.join("\n\n"), Value::Object(structured), false))
        }
        .await;

        match result {
            Ok(value) => Ok(value),
            Err(message) => {
                let translated = translate_verbosity_error(&message);
                let hints = build_common_guidance_from_error(&translated);
                let guidance = format_guidance(&hints);
                let mut parts = vec![translated.clone()];
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_resource_subscribe_example());
                let mut structured = structured_base("probe_resource_subscribe");
                structured.insert("error".to_string(), Value::String(translated));
                if !hints.is_empty() {
                    structured.insert(
                        "guidance".to_string(),
                        serde_json::to_value(hints).unwrap_or(Value::Null),
                    );
                }
                Ok(build_result(
                    format!("Resource subscription check failed: {}", parts.join("\n\n")),
                    Value::Object(structured),
                    true,
                ))
            }
        }
    }
}
