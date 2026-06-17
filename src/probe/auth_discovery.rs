use crate::allowlist::ensure_host_allowed;
use crate::auth::extract_resource_metadata_url;
use crate::http::fetch_with_timeout;
use crate::probe::auth_diagnostics::{
    attach_prior_attempt, classify_request_error, classify_stateful_session_required_response,
    http_status_detail, invalid_json_detail, issuer_mismatch_detail, malformed_url_detail,
    normalize_issuer, validate_url,
};
use crate::report::{AuthDiscovery, ProbeStep, ProbeStepStatus};
use crate::transport::TransportType;
use anyhow::anyhow;
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde_json::json;
use serde_json::Value;
use url::Url;

fn registration_endpoint_from_metadata(metadata: Option<&Value>) -> Option<String> {
    metadata
        .and_then(|value| value.get("registration_endpoint"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

async fn fetch_json_with_diagnostics(
    client: &reqwest::Client,
    url: &str,
    timeout_ms: u64,
    endpoint: &str,
) -> Result<Value, (String, Value)> {
    validate_url(endpoint, url)?;

    let response = fetch_with_timeout(client, client.get(url), timeout_ms)
        .await
        .map_err(|err| {
            let error = anyhow!(err);
            classify_request_error(endpoint, url, &error)
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(http_status_detail(endpoint, url, status));
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response.bytes().await.map_err(|err| {
        let error = anyhow!(err);
        classify_request_error(endpoint, url, &error)
    })?;
    serde_json::from_slice::<Value>(&bytes).map_err(|error| {
        let body_preview = String::from_utf8_lossy(&bytes)
            .chars()
            .take(160)
            .collect::<String>()
            .replace('\n', " ");
        invalid_json_detail(
            endpoint,
            url,
            content_type.as_deref(),
            body_preview.trim(),
            &error.to_string(),
        )
    })
}

fn push_error_step(steps: &mut Vec<ProbeStep>, name: &str, detail: String, data: Value) {
    steps.push(ProbeStep {
        name: name.to_string(),
        status: ProbeStepStatus::Error,
        detail: Some(detail),
        data: Some(data),
    });
}

fn prm_alias_paths_for_resource(resource_path: &str) -> Vec<String> {
    let canonical = "/.well-known/oauth-protected-resource".to_string();
    let trimmed = resource_path
        .trim()
        .trim_start_matches('/')
        .trim_end_matches('/');
    if trimmed.is_empty() {
        return vec![canonical];
    }
    vec![
        format!("{canonical}/{trimmed}"),
        format!("/{trimmed}/.well-known/oauth-protected-resource"),
        canonical,
    ]
}

fn prm_alias_urls_for_target(target_url: &str) -> Option<Vec<String>> {
    let parsed = Url::parse(target_url).ok()?;
    let mut origin = parsed.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let origin = origin.to_string().trim_end_matches('/').to_string();
    let aliases = prm_alias_paths_for_resource(parsed.path());
    Some(
        aliases
            .into_iter()
            .map(|path| format!("{origin}{path}"))
            .collect(),
    )
}

async fn probe_prm_alias_statuses(
    client: &reqwest::Client,
    alias_urls: &[String],
    timeout_ms: u64,
) -> Vec<Value> {
    let mut results = Vec::with_capacity(alias_urls.len());
    for url in alias_urls {
        let result = fetch_with_timeout(client, client.get(url), timeout_ms).await;
        let entry = match result {
            Ok(response) => json!({
                "url": url,
                "status": response.status().as_u16(),
                "ok": response.status().is_success(),
            }),
            Err(error) => json!({
                "url": url,
                "error": error.to_string(),
                "ok": false,
            }),
        };
        results.push(entry);
    }
    results
}

fn validate_issuer_alignment(
    target_url: &str,
    authorization_server: &str,
    oauth_metadata: Option<&Value>,
    steps: &mut Vec<ProbeStep>,
) {
    let Some(raw_issuer) = oauth_metadata
        .and_then(|value| value.get("issuer"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    let Some(expected_issuer) = normalize_issuer(authorization_server) else {
        let (detail, data) = malformed_url_detail(
            "authorization_server",
            authorization_server,
            "authorization server is not a valid issuer URL",
        );
        push_error_step(steps, "auth.oauth.issuer", detail, data);
        return;
    };
    let Some(discovered_issuer) = normalize_issuer(raw_issuer) else {
        let (detail, data) = malformed_url_detail(
            "oauth_issuer",
            raw_issuer,
            "OAuth metadata issuer is malformed",
        );
        push_error_step(steps, "auth.oauth.issuer", detail, data);
        return;
    };

    if expected_issuer != discovered_issuer {
        let (detail, data) = issuer_mismatch_detail(
            target_url,
            authorization_server,
            raw_issuer,
            &expected_issuer,
            &discovered_issuer,
        );
        push_error_step(steps, "auth.oauth.issuer", detail, data);
        return;
    }

    steps.push(ProbeStep {
        name: "auth.oauth.issuer".to_string(),
        status: ProbeStepStatus::Ok,
        detail: Some("OAuth issuer matches PRM authorization_server".to_string()),
        data: Some(json!({
            "code": "issuer_validated",
            "matched": true,
            "expected_issuer": expected_issuer,
            "discovered_issuer": discovered_issuer
        })),
    });
}

/// Discover PRM and OAuth metadata for an HTTP target.
pub async fn discover_auth(
    transport: TransportType,
    url: Option<&str>,
    steps: &mut Vec<ProbeStep>,
    timeout_ms: u64,
    allowed_hosts: Option<&[String]>,
) -> Option<AuthDiscovery> {
    if transport == TransportType::Stdio || url.is_none() {
        steps.push(ProbeStep {
            name: "auth.prm".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("not applicable".to_string()),
            data: None,
        });
        return None;
    }
    let url = url.unwrap_or_default();
    if let Err((detail, data)) = validate_url("target", url) {
        push_error_step(steps, "auth.prm", detail, data);
        return Some(AuthDiscovery {
            resource_metadata_url: None,
            resource_metadata: None,
            authorization_server: None,
            oauth_metadata_url: None,
            oauth_metadata: None,
            registration_endpoint: None,
        });
    }

    if let Err(err) = ensure_host_allowed(url, allowed_hosts, "Target") {
        steps.push(ProbeStep {
            name: "auth.prm".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(err.to_string()),
            data: None,
        });
        return None;
    }

    let client = reqwest::Client::new();
    let mut auth = AuthDiscovery {
        resource_metadata_url: None,
        resource_metadata: None,
        authorization_server: None,
        oauth_metadata_url: None,
        oauth_metadata: None,
        registration_endpoint: None,
    };

    let response = fetch_with_timeout(&client, client.get(url), timeout_ms).await;
    let response = match response {
        Ok(resp) => resp,
        Err(err) => {
            let error = anyhow!(err);
            let (detail, data) = classify_request_error("target", url, &error);
            push_error_step(steps, "auth.prm", detail, data);
            return Some(auth);
        }
    };

    let status = response.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        let header = response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let prm_url = extract_resource_metadata_url(header);
        if prm_url.is_none() {
            push_error_step(
                steps,
                "auth.prm",
                "Missing resource_metadata in WWW-Authenticate header".to_string(),
                json!({ "code": "resource_metadata_missing" }),
            );
            return Some(auth);
        }
        let prm_url = prm_url.unwrap();
        if let Err((detail, data)) = validate_url("prm_metadata", &prm_url) {
            push_error_step(steps, "auth.prm", detail, data);
            return Some(auth);
        }
        if let Err(err) = ensure_host_allowed(&prm_url, allowed_hosts, "PRM") {
            steps.push(ProbeStep {
                name: "auth.prm".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some(err.to_string()),
                data: None,
            });
            return Some(auth);
        }
        auth.resource_metadata_url = Some(prm_url);
        steps.push(ProbeStep {
            name: "auth.prm".to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        });
    } else if status.is_success() {
        steps.push(ProbeStep {
            name: "auth.prm".to_string(),
            status: ProbeStepStatus::Ok,
            detail: Some("no auth required".to_string()),
            data: None,
        });
        return Some(auth);
    } else if status == StatusCode::BAD_REQUEST {
        if let Some((_detail, data)) =
            classify_stateful_session_required_response("target", url, response).await
        {
            steps.push(ProbeStep {
                name: "auth.prm".to_string(),
                status: ProbeStepStatus::Ok,
                detail: Some(
                    "no auth required; endpoint is stateful and expects a session id".to_string(),
                ),
                data: Some(data),
            });
            return Some(auth);
        }
        steps.push(ProbeStep {
            name: "auth.prm".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("Unexpected status {}", status)),
            data: None,
        });
        return Some(auth);
    } else {
        steps.push(ProbeStep {
            name: "auth.prm".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(format!("Unexpected status {}", status)),
            data: None,
        });
        return Some(auth);
    }

    if let Some(prm_url) = auth.resource_metadata_url.clone() {
        let prm_metadata = match fetch_json_with_diagnostics(
            &client,
            &prm_url,
            timeout_ms,
            "prm_metadata",
        )
        .await
        {
            Ok(value) => value,
            Err((mut detail, mut data)) => {
                let status_404 = data
                    .get("code")
                    .and_then(Value::as_str)
                    .map(|code| code == "http_status")
                    .unwrap_or(false)
                    && data
                        .get("status")
                        .and_then(Value::as_u64)
                        .map(|status| status == 404)
                        .unwrap_or(false);
                if status_404 {
                    if let Some(alias_urls) = prm_alias_urls_for_target(url) {
                        let alias_results =
                            probe_prm_alias_statuses(&client, &alias_urls, timeout_ms).await;
                        let any_reachable = alias_results
                            .iter()
                            .any(|entry| entry.get("ok").and_then(Value::as_bool) == Some(true));
                        let classification = if any_reachable {
                            "challenged_prm_url_unreachable_but_alias_reachable"
                        } else {
                            "all_prm_aliases_unreachable"
                        };
                        if let Some(object) = data.as_object_mut() {
                            object.insert(
                                "challenged_resource_metadata_url".to_string(),
                                Value::String(prm_url.clone()),
                            );
                            object.insert(
                                "expected_prm_alias_urls".to_string(),
                                Value::Array(
                                    alias_urls
                                        .iter()
                                        .map(|entry| Value::String(entry.clone()))
                                        .collect(),
                                ),
                            );
                            object.insert(
                                "alias_probe_results".to_string(),
                                Value::Array(alias_results),
                            );
                            object.insert(
                                "classification".to_string(),
                                Value::String(classification.to_string()),
                            );
                        }
                        if any_reachable {
                            detail.push_str(
                                " (challenged URL appears wrong: another PRM alias is reachable)",
                            );
                        }
                    }
                }
                push_error_step(steps, "auth.prm.fetch", detail, data);
                return Some(auth);
            }
        };
        auth.resource_metadata = Some(prm_metadata.clone());
        steps.push(ProbeStep {
            name: "auth.prm.fetch".to_string(),
            status: ProbeStepStatus::Ok,
            detail: None,
            data: None,
        });
        let servers = auth
            .resource_metadata
            .as_ref()
            .and_then(|value| value.get("authorization_servers").cloned())
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        let server = servers
            .iter()
            .find_map(|value| value.as_str().map(|s| s.to_string()));
        if let Some(candidate) = server {
            if let Err((detail, data)) = validate_url("authorization_server", &candidate) {
                push_error_step(steps, "auth.oauth.fetch", detail, data);
                return Some(auth);
            }
            if let Err(err) = ensure_host_allowed(&candidate, allowed_hosts, "Authorization server")
            {
                steps.push(ProbeStep {
                    name: "auth.oauth.fetch".to_string(),
                    status: ProbeStepStatus::Error,
                    detail: Some(err.to_string()),
                    data: None,
                });
                return Some(auth);
            }
            auth.authorization_server = Some(candidate);
        }
    }

    let Some(auth_server) = auth.authorization_server.clone() else {
        push_error_step(
            steps,
            "auth.oauth.fetch",
            "No authorization server found in PRM metadata".to_string(),
            json!({ "code": "authorization_server_missing" }),
        );
        return Some(auth);
    };

    let issuer = if auth_server.ends_with('/') {
        auth_server.clone()
    } else {
        format!("{auth_server}/")
    };
    let oidc_url = Url::parse(&issuer).and_then(|url| url.join(".well-known/openid-configuration"));
    let oauth_url =
        Url::parse(&issuer).and_then(|url| url.join(".well-known/oauth-authorization-server"));
    let (oidc_url, oauth_url) = match (oidc_url, oauth_url) {
        (Ok(oidc), Ok(oauth)) => (oidc, oauth),
        _ => {
            steps.push(ProbeStep {
                name: "auth.oauth.fetch".to_string(),
                status: ProbeStepStatus::Error,
                detail: Some("Invalid authorization server URL".to_string()),
                data: None,
            });
            return Some(auth);
        }
    };

    if let Err(err) = ensure_host_allowed(oidc_url.as_str(), allowed_hosts, "OAuth metadata") {
        steps.push(ProbeStep {
            name: "auth.oauth.fetch".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(err.to_string()),
            data: None,
        });
        return Some(auth);
    }
    if let Err(err) = ensure_host_allowed(oauth_url.as_str(), allowed_hosts, "OAuth metadata") {
        steps.push(ProbeStep {
            name: "auth.oauth.fetch".to_string(),
            status: ProbeStepStatus::Error,
            detail: Some(err.to_string()),
            data: None,
        });
        return Some(auth);
    }

    let (oauth_metadata_url, oauth_metadata) =
        match fetch_json_with_diagnostics(&client, oidc_url.as_str(), timeout_ms, "oauth_metadata")
            .await
        {
            Ok(value) => (oidc_url.as_str().to_string(), value),
            Err((first_detail, first_data)) => {
                match fetch_json_with_diagnostics(
                    &client,
                    oauth_url.as_str(),
                    timeout_ms,
                    "oauth_metadata",
                )
                .await
                {
                    Ok(value) => (oauth_url.as_str().to_string(), value),
                    Err((detail, data)) => {
                        push_error_step(
                            steps,
                            "auth.oauth.fetch",
                            detail,
                            attach_prior_attempt(data, first_detail, first_data),
                        );
                        return Some(auth);
                    }
                }
            }
        };
    auth.oauth_metadata_url = Some(oauth_metadata_url);
    auth.oauth_metadata = Some(oauth_metadata);
    auth.registration_endpoint = registration_endpoint_from_metadata(auth.oauth_metadata.as_ref());
    steps.push(ProbeStep {
        name: "auth.oauth.fetch".to_string(),
        status: ProbeStepStatus::Ok,
        detail: None,
        data: None,
    });
    validate_issuer_alignment(url, &auth_server, auth.oauth_metadata.as_ref(), steps);
    Some(auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::auth_diagnostics::{
        CODE_HTTP_STATUS, CODE_INVALID_JSON, CODE_ISSUER_MISMATCH, CODE_NETWORK_UNREACHABLE,
        CODE_URL_MALFORMED,
    };
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[derive(Clone)]
    struct TestResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Error",
        }
    }

    async fn spawn_server<F>(handler: F) -> (String, JoinHandle<()>)
    where
        F: Fn(&str, &str) -> TestResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("listener addr");
        let base_url = format!("http://{addr}");
        let base_for_task = base_url.clone();
        let handler = Arc::new(handler);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                let base_url = base_for_task.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let response = handler(path, &base_url);
                    let mut payload = format!(
                        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        response.status,
                        reason_phrase(response.status),
                        response.body.len()
                    );
                    for (name, value) in response.headers {
                        payload.push_str(&format!("{name}: {value}\r\n"));
                    }
                    payload.push_str("\r\n");
                    payload.push_str(&response.body);
                    let _ = socket.write_all(payload.as_bytes()).await;
                });
            }
        });
        (base_url, task)
    }

    fn step_code<'a>(steps: &'a [ProbeStep], name: &str) -> Option<&'a str> {
        steps
            .iter()
            .find(|step| step.name == name)
            .and_then(|step| {
                step.data
                    .as_ref()
                    .and_then(|data| data.get("code"))
                    .and_then(|value| value.as_str())
            })
    }

    #[tokio::test]
    async fn discover_auth_reports_malformed_target_url() {
        let mut steps = Vec::new();
        let _ = discover_auth(
            TransportType::StreamableHttp,
            Some("not-a-url"),
            &mut steps,
            1_000,
            None,
        )
        .await;
        assert_eq!(step_code(&steps, "auth.prm"), Some(CODE_URL_MALFORMED));
    }

    #[tokio::test]
    async fn discover_auth_reports_unreachable_target() {
        let reserved_port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve local port")
            .local_addr()
            .expect("reserved addr")
            .port();
        let url = format!("http://127.0.0.1:{reserved_port}/mcp");
        let mut steps = Vec::new();
        let _ = discover_auth(
            TransportType::StreamableHttp,
            Some(url.as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        assert_eq!(
            step_code(&steps, "auth.prm"),
            Some(CODE_NETWORK_UNREACHABLE)
        );
    }

    #[tokio::test]
    async fn discover_auth_reports_404_prm_metadata() {
        let (base, task) = spawn_server(|path, base| match path {
            "/mcp" => TestResponse {
                status: 401,
                headers: vec![(
                    "WWW-Authenticate".to_string(),
                    format!(
                        "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
                    ),
                )],
                body: String::new(),
            },
            "/.well-known/oauth-protected-resource" => TestResponse {
                status: 404,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: "not found".to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;
        let mut steps = Vec::new();
        let _ = discover_auth(
            TransportType::StreamableHttp,
            Some(format!("{base}/mcp").as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        task.abort();
        assert_eq!(step_code(&steps, "auth.prm.fetch"), Some(CODE_HTTP_STATUS));
        let status = steps
            .iter()
            .find(|step| step.name == "auth.prm.fetch")
            .and_then(|step| step.data.as_ref())
            .and_then(|data| data.get("status"))
            .and_then(|value| value.as_u64());
        assert_eq!(status, Some(404));
        let classification = steps
            .iter()
            .find(|step| step.name == "auth.prm.fetch")
            .and_then(|step| step.data.as_ref())
            .and_then(|data| data.get("classification"))
            .and_then(|value| value.as_str());
        assert_eq!(classification, Some("all_prm_aliases_unreachable"));
        let alias_probe_results = steps
            .iter()
            .find(|step| step.name == "auth.prm.fetch")
            .and_then(|step| step.data.as_ref())
            .and_then(|data| data.get("alias_probe_results"))
            .and_then(|value| value.as_array())
            .map(|entries| entries.len());
        assert_eq!(alias_probe_results, Some(3));
    }

    #[tokio::test]
    async fn discover_auth_reports_prm_alias_reachable_when_challenge_url_is_dead() {
        let (base, task) = spawn_server(|path, base| match path {
            "/mcp" => TestResponse {
                status: 401,
                headers: vec![(
                    "WWW-Authenticate".to_string(),
                    format!(
                        "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource/mcp\""
                    ),
                )],
                body: String::new(),
            },
            "/.well-known/oauth-protected-resource/mcp" => TestResponse {
                status: 404,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: "missing canonical".to_string(),
            },
            "/.well-known/oauth-protected-resource" => TestResponse {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: r#"{"resource":"http://example.test/mcp"}"#.to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;
        let mut steps = Vec::new();
        let _ = discover_auth(
            TransportType::StreamableHttp,
            Some(format!("{base}/mcp").as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        task.abort();
        let classification = steps
            .iter()
            .find(|step| step.name == "auth.prm.fetch")
            .and_then(|step| step.data.as_ref())
            .and_then(|data| data.get("classification"))
            .and_then(|value| value.as_str());
        assert_eq!(
            classification,
            Some("challenged_prm_url_unreachable_but_alias_reachable")
        );
        let has_root_success = steps
            .iter()
            .find(|step| step.name == "auth.prm.fetch")
            .and_then(|step| step.data.as_ref())
            .and_then(|data| data.get("alias_probe_results"))
            .and_then(|value| value.as_array())
            .map(|entries| {
                entries.iter().any(|entry| {
                    entry.get("url").and_then(Value::as_str).unwrap_or_default()
                        == format!("{base}/.well-known/oauth-protected-resource")
                        && entry.get("ok").and_then(Value::as_bool) == Some(true)
                })
            })
            .unwrap_or(false);
        assert!(has_root_success);
    }

    #[tokio::test]
    async fn discover_auth_accepts_stateful_session_required_target_without_auth() {
        let (base, task) = spawn_server(|path, _base| match path {
            "/mcp" => TestResponse {
                status: 400,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: r#"{"status":"error","error":"Missing session ID.","hint":"Initialize with POST /mcp to obtain a session id."}"#.to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;
        let mut steps = Vec::new();
        let auth = discover_auth(
            TransportType::StreamableHttp,
            Some(format!("{base}/mcp").as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        task.abort();
        let prm = steps
            .iter()
            .find(|step| step.name == "auth.prm")
            .expect("auth.prm step");
        assert_eq!(prm.status, ProbeStepStatus::Ok);
        assert_eq!(
            step_code(&steps, "auth.prm"),
            Some("stateful_session_required")
        );
        assert!(prm
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("no auth required"));
        let classification = prm
            .data
            .as_ref()
            .and_then(|data| data.get("classification"))
            .and_then(|value| value.as_str());
        assert_eq!(classification, Some("stateful_mcp_requires_session"));
        let auth = auth.expect("auth payload");
        assert!(auth.resource_metadata_url.is_none());
        assert!(auth.authorization_server.is_none());
    }

    #[tokio::test]
    async fn discover_auth_accepts_stateful_session_required_on_custom_mount_path() {
        let (base, task) = spawn_server(|path, _base| match path {
            "/api/mcp" => TestResponse {
                status: 400,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: r#"{"status":"error","error":"Missing session ID.","hint":"Initialize with POST /api/mcp to obtain a session id."}"#.to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;
        let mut steps = Vec::new();
        let auth = discover_auth(
            TransportType::StreamableHttp,
            Some(format!("{base}/api/mcp").as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        task.abort();
        let prm = steps
            .iter()
            .find(|step| step.name == "auth.prm")
            .expect("auth.prm step");
        assert_eq!(prm.status, ProbeStepStatus::Ok);
        assert_eq!(
            step_code(&steps, "auth.prm"),
            Some("stateful_session_required")
        );
        let path = prm
            .data
            .as_ref()
            .and_then(|data| data.get("path"))
            .and_then(|value| value.as_str());
        assert_eq!(path, Some("/api/mcp"));
        let auth = auth.expect("auth payload");
        assert!(auth.resource_metadata_url.is_none());
        assert!(auth.authorization_server.is_none());
    }

    #[tokio::test]
    async fn discover_auth_reports_non_json_prm_metadata() {
        let (base, task) = spawn_server(|path, base| match path {
            "/mcp" => TestResponse {
                status: 401,
                headers: vec![(
                    "WWW-Authenticate".to_string(),
                    format!(
                        "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
                    ),
                )],
                body: String::new(),
            },
            "/.well-known/oauth-protected-resource" => TestResponse {
                status: 200,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: "not json".to_string(),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;
        let mut steps = Vec::new();
        let _ = discover_auth(
            TransportType::StreamableHttp,
            Some(format!("{base}/mcp").as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        task.abort();
        assert_eq!(step_code(&steps, "auth.prm.fetch"), Some(CODE_INVALID_JSON));
    }

    #[tokio::test]
    async fn discover_auth_reports_issuer_mismatch() {
        let (base, task) = spawn_server(|path, base| match path {
            "/mcp" => TestResponse {
                status: 401,
                headers: vec![(
                    "WWW-Authenticate".to_string(),
                    format!(
                        "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
                    ),
                )],
                body: String::new(),
            },
            "/.well-known/oauth-protected-resource" => TestResponse {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: format!(r#"{{"authorization_servers":["{base}/auth-server"]}}"#),
            },
            "/auth-server/.well-known/openid-configuration" => TestResponse {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: format!(
                    r#"{{"issuer":"{base}/different-issuer","registration_endpoint":"{base}/register"}}"#
                ),
            },
            _ => TestResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        })
        .await;
        let mut steps = Vec::new();
        let _ = discover_auth(
            TransportType::StreamableHttp,
            Some(format!("{base}/mcp").as_str()),
            &mut steps,
            1_000,
            None,
        )
        .await;
        task.abort();
        assert_eq!(
            step_code(&steps, "auth.oauth.issuer"),
            Some(CODE_ISSUER_MISMATCH)
        );
    }
}
