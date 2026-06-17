use super::*;

#[rmcp::tool_router(router = tool_router_probe_http, vis = "pub")]
impl ProbeMcp {
    /// HTTP smoke check for PRM and OAuth metadata endpoints.
    #[tool(
        name = "probe_http_smoke",
        description = "HTTP smoke check for PRM and OAuth metadata endpoints."
    )]
    async fn probe_http_smoke(
        &self,
        Parameters(args): Parameters<ProbeHttpSmokeArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let report = run_http_smoke(HttpSmokeTarget {
                url: Some(args.url.clone()),
                timeout_ms: args.timeout_ms,
                expect_auth_required: args.expect_auth_required,
                expect_registration_endpoint: args.expect_registration_endpoint,
            })
            .await;

            let summary = if report.ok {
                "HTTP smoke check completed successfully."
            } else {
                "HTTP smoke check completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let mut hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            if report.steps.iter().any(|step| {
                step.name == "auth.oauth.fetch"
                    && step.status == crate::report::ProbeStepStatus::Error
                    && step
                        .detail
                        .as_deref()
                        .map(|detail| detail.contains("authorization server"))
                        .unwrap_or(false)
            }) {
                hints.push(
                    "PRM metadata should include authorization_servers (or ensure the listed server exposes OAuth metadata)."
                        .to_string(),
                );
            }
            if report.steps.iter().any(|step| {
                step.name == "auth.oauth.registration"
                    && step.status == crate::report::ProbeStepStatus::Error
            }) {
                hints.push(
                    "OAuth metadata is missing registration_endpoint. Enable dynamic client registration on the issuer or disable expect_registration_endpoint."
                        .to_string(),
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
                parts.push(format_probe_http_smoke_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_http_smoke");
            structured.insert("report".to_string(), serde_json::to_value(report).unwrap_or(Value::Null));
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
                let hints = build_common_guidance_from_error(&message);
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(message.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_http_smoke_example());
                let content_text = format!("HTTP smoke failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_http_smoke");
                structured.insert("error".to_string(), Value::String(message));
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

    /// Discover auth metadata without opening a session.
    #[tool(
        name = "probe_discover_auth",
        description = "Fetch PRM and OAuth metadata without opening an MCP session."
    )]
    async fn probe_discover_auth(
        &self,
        Parameters(args): Parameters<ProbeDiscoverAuthArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            let report = run_auth_discovery(AuthDiscoveryTarget {
                url: Some(args.url.clone()),
                timeout_ms: args.timeout_ms,
                expect_auth_required: args.expect_auth_required,
                expect_registration_endpoint: args.expect_registration_endpoint,
            })
            .await;

            let summary = if report.ok {
                "Auth discovery completed successfully."
            } else {
                "Auth discovery completed with errors."
            };
            let hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
            let guidance = format_guidance(&hints);
            let mut parts = Vec::new();
            parts.push(summary.to_string());
            if let Some(guidance) = guidance {
                parts.push(guidance);
            }
            if !report.ok {
                parts.push(format_probe_discover_auth_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_discover_auth");
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
                let hints = build_common_guidance_from_error(&message);
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(message.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_discover_auth_example());
                let content_text = format!("Auth discovery failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_discover_auth");
                structured.insert("error".to_string(), Value::String(message));
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

    /// Exercise streamable HTTP replay using Last-Event-ID.
    #[tool(
        name = "probe_replay",
        description = "Exercise streamable HTTP replay by capturing an event id and resuming with Last-Event-ID."
    )]
    async fn probe_replay(
        &self,
        Parameters(args): Parameters<ProbeReplayArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let result: Result<CallToolResult, String> = async {
            if let Some(transport) = args.transport {
                if transport != TransportType::StreamableHttp {
                    return Err("probe_replay only supports streamable-http transport.".to_string());
                }
            }

            let resolved = resolve_auth_headers(
                TransportType::StreamableHttp,
                Some(args.url.as_str()),
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

            let report = run_replay_probe(ReplayProbeTarget {
                transport_type: Some(TransportType::StreamableHttp),
                url: Some(args.url.clone()),
                headers: resolved.headers,
                timeout_ms: args.timeout_ms,
            })
            .await;

            let summary = if report.ok {
                "Replay probe completed successfully."
            } else {
                "Replay probe completed with errors."
            };
            let failure_summary = if report.ok {
                None
            } else {
                format_failure_summary(&report.steps, 3)
            };
            let hints = if report.ok {
                Vec::new()
            } else {
                build_common_guidance_from_report(&report.steps)
            };
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
                parts.push(format_probe_replay_example());
            }
            let content_text = parts.join("\n\n");

            let mut structured = structured_base("probe_replay");
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
                let hints = build_common_guidance_from_error(&message);
                let guidance = format_guidance(&hints);
                let mut parts = Vec::new();
                parts.push(message.clone());
                if let Some(guidance) = guidance {
                    parts.push(guidance);
                }
                parts.push(format_probe_replay_example());
                let content_text = format!("Replay probe failed: {}", parts.join("\n\n"));
                let mut structured = structured_base("probe_replay");
                structured.insert("error".to_string(), Value::String(message));
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
