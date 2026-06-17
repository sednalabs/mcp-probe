use super::*;

#[rmcp::tool_router(router = tool_router_probe_core, vis = "pub")]
impl ProbeMcp {
    /// Run a headless MCP probe against a target server.
    #[tool(
        name = "probe_run",
        description = "Run a headless MCP probe against a target server using stdio, SSE, or streamable HTTP."
    )]
    async fn probe_run(
        &self,
        Parameters(args): Parameters<ProbeRunArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut auth_sources: Vec<String> = Vec::new();
        let result: Result<CallToolResult, String> = async {
            auth_sources = collect_auth_sources(
                args.use_auth,
                args.access_token.as_deref(),
                args.access_token_path.as_deref(),
                args.refresh_token.as_deref(),
                args.refresh_token_path.as_deref(),
            );
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
                false,
            )
            .await?;

            let report = run_probe(
                ProbeTarget {
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
                    descriptor_profile: args.descriptor_profile,
                },
                None,
                None,
            )
            .await;

            let output_report = apply_report_verbosity(report.clone(), args.verbosity);
            let auth_required_as_expected = handshake_auth_required_as_expected(&report);
            let summary = if auth_required_as_expected {
                "Auth challenge detected as expected; probe stopped before authenticated requests."
            } else if report.ok {
                "Probe completed successfully."
            } else {
                "Probe completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let diagnostics = failure_diagnostics_from_probe_report(&report, Some(args.transport));
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if auth_required_as_expected {
                hints.push(
                    "To continue past auth discovery, rerun with access_token or use_auth: true so the probe can authenticate before initialize.".to_string(),
                );
            }
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            let auth_failure = auth_failure_from_report(&report);
            let guidance = format_guidance(&hints);
            let example_ids = if report.ok {
                Vec::new()
            } else {
                select_probe_run_examples(auth_sources.first().map(|s| s.as_str()), auth_failure)
            };
            let examples = if report.ok || example_ids.is_empty() {
                None
            } else {
                Some(format_probe_run_examples_for(&example_ids))
            };
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(summary) = failure_summary {
                parts.push(summary);
            }
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if let Some(examples) = examples {
                parts.push(examples);
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_run");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(output_report).unwrap_or(Value::Null),
            );
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
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
                let translated = crate::server::tools::translate_verbosity_error(&message);
                let hints = build_common_guidance_from_error(&translated);
                let guidance = format_guidance(&hints);
                let auth_failure = is_auth_failure_detail(&translated);
                let example_ids = select_probe_run_examples(
                    auth_sources.first().map(|s| s.as_str()),
                    auth_failure,
                );
                let examples = format_probe_run_examples_for(&example_ids);
                let mut parts = Vec::new();
                parts.push(translated.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                if !examples.is_empty() {
                    parts.push(examples);
                }
                let content_text = format!("Probe failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_run");
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

    /// Run a fast handshake probe (connect + ping + list tools).
    #[tool(
        name = "probe_handshake",
        description = "Connect, ping, and list tools to confirm readiness, or verify that an expected bearer challenge blocks unauthenticated handshake."
    )]
    async fn probe_handshake(
        &self,
        Parameters(args): Parameters<ProbeHandshakeArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
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
                false,
            )
            .await?;

            let report = run_probe_handshake(
                ProbeTarget {
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
                    descriptor_profile: args.descriptor_profile,
                },
                None,
                None,
            )
            .await;

            let output_report = apply_report_verbosity(report.clone(), args.verbosity);
            let auth_required_as_expected = handshake_auth_required_as_expected(&report);
            let summary = if auth_required_as_expected {
                "Auth challenge detected as expected; handshake stopped before authenticated requests."
            } else if report.ok {
                "Handshake completed successfully."
            } else {
                "Handshake completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let diagnostics = failure_diagnostics_from_probe_report(&report, Some(args.transport));
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if auth_required_as_expected {
                hints.push(
                    "To complete the handshake, rerun with access_token or use_auth: true so the probe can initialize after the bearer challenge.".to_string(),
                );
            }
            if let Some(diagnostics) = diagnostics.as_ref() {
                merge_diagnostic_hints(&mut hints, diagnostics);
            }
            if report.steps.iter().any(|step| {
                step.name == "ping" && step.status == crate::report::ProbeStepStatus::Error
            }) && !hints.iter().any(|hint| hint.contains("Ping failed"))
            {
                hints.push(
                    "Ping failed: confirm the server completed initialization and supports the ping request.".to_string(),
                );
            }
            if report.steps.iter().any(|step| {
                step.name == "tools.list" && step.status == crate::report::ProbeStepStatus::Error
            }) && !hints.iter().any(|hint| hint.contains("Tools list"))
            {
                hints.push(
                    "Tools list failed: confirm tool registration and that the client is authorized to list tools.".to_string(),
                );
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
                parts.push(format_probe_handshake_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_handshake");
            structured.insert(
                "report".to_string(),
                serde_json::to_value(output_report).unwrap_or(Value::Null),
            );
            structured.insert(
                "target".to_string(),
                json!({
                    "transport": args.transport.as_str(),
                    "url": args.url,
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
                content_text,
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
                let mut parts = Vec::new();
                parts.push(translated.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_handshake_example());
                let content_text = format!("Handshake failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_handshake");
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
}
