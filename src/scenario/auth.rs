use crate::auth::{
    attach_access_token, attach_auth_header, format_auth_source_error, read_access_token_from_path,
    read_refresh_token_from_path, refresh_access_token,
};
use crate::transport::TransportType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of resolving auth headers for a scenario.
#[derive(Debug, Clone)]
pub enum AuthHeaderResult {
    Ok(Option<HashMap<String, String>>),
    Err(String),
}

/// Scenario auth inputs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ScenarioAuthInput {
    pub transport: TransportType,
    pub url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub use_auth: Option<bool>,
    pub access_token: Option<String>,
    pub access_token_path: Option<String>,
    pub refresh_token: Option<String>,
    pub refresh_token_path: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub token_endpoint: Option<String>,
    pub scope: Option<String>,
    pub timeout_ms: Option<u64>,
}

fn format_error(error: anyhow::Error) -> String {
    error.to_string()
}

fn ok(headers: Option<HashMap<String, String>>) -> AuthHeaderResult {
    AuthHeaderResult::Ok(headers)
}

/// Resolve auth headers based on scenario settings.
pub async fn resolve_auth_headers(scenario: &ScenarioAuthInput) -> AuthHeaderResult {
    let headers = scenario.headers.clone();
    let auth_sources = [
        scenario.use_auth.filter(|v| *v).map(|_| "use_auth"),
        scenario.access_token.as_ref().map(|_| "access_token"),
        scenario
            .access_token_path
            .as_ref()
            .map(|_| "access_token_path"),
        scenario.refresh_token.as_ref().map(|_| "refresh_token"),
        scenario
            .refresh_token_path
            .as_ref()
            .map(|_| "refresh_token_path"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if auth_sources.len() > 1 {
        return AuthHeaderResult::Err(format_auth_source_error(
            &auth_sources
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ));
    }

    if let Some(token) = scenario.access_token.as_ref() {
        if scenario.url.is_none() {
            return AuthHeaderResult::Err("access_token requires a target URL".to_string());
        }
        match attach_access_token(headers, token) {
            Ok(updated) => return ok(Some(updated)),
            Err(err) => return AuthHeaderResult::Err(format_error(err)),
        }
    }

    if let Some(path) = scenario.access_token_path.as_ref() {
        if scenario.url.is_none() {
            return AuthHeaderResult::Err("access_token_path requires a target URL".to_string());
        }
        match read_access_token_from_path(path).await {
            Ok(token) => match attach_access_token(headers, &token) {
                Ok(updated) => return ok(Some(updated)),
                Err(err) => return AuthHeaderResult::Err(format_error(err)),
            },
            Err(err) => return AuthHeaderResult::Err(format_error(err)),
        }
    }

    if scenario.refresh_token.is_some() || scenario.refresh_token_path.is_some() {
        if scenario.transport == TransportType::Stdio {
            return AuthHeaderResult::Err(
                "refresh_token auth is only supported for HTTP transports.".to_string(),
            );
        }
        if scenario.url.is_none() {
            return AuthHeaderResult::Err("refresh_token requires a target URL".to_string());
        }
        let file_data = if let Some(path) = scenario.refresh_token_path.as_ref() {
            match read_refresh_token_from_path(path).await {
                Ok(data) => Some(data),
                Err(err) => return AuthHeaderResult::Err(format_error(err)),
            }
        } else {
            None
        };
        let refresh_token = scenario
            .refresh_token
            .clone()
            .or_else(|| file_data.as_ref().map(|data| data.refresh_token.clone()));
        let client_id = scenario
            .client_id
            .clone()
            .or_else(|| file_data.as_ref().and_then(|data| data.client_id.clone()));
        let client_secret = scenario.client_secret.clone().or_else(|| {
            file_data
                .as_ref()
                .and_then(|data| data.client_secret.clone())
        });
        let token_endpoint = scenario.token_endpoint.clone().or_else(|| {
            file_data
                .as_ref()
                .and_then(|data| data.token_endpoint.clone())
        });
        let scope = scenario
            .scope
            .clone()
            .or_else(|| file_data.as_ref().and_then(|data| data.scope.clone()));
        let server_url = scenario
            .url
            .clone()
            .or_else(|| file_data.as_ref().and_then(|data| data.server_url.clone()));

        let Some(refresh_token) = refresh_token else {
            return AuthHeaderResult::Err("refresh_token is required.".to_string());
        };
        let Some(client_id) = client_id else {
            return AuthHeaderResult::Err("client_id is required to refresh tokens.".to_string());
        };

        match refresh_access_token(crate::auth::RefreshTokenOptions {
            refresh_token,
            client_id,
            client_secret,
            scope,
            server_url,
            token_endpoint,
            timeout_ms: scenario.timeout_ms,
        })
        .await
        {
            Ok(refreshed) => match attach_access_token(headers, &refreshed.access_token) {
                Ok(updated) => return ok(Some(updated)),
                Err(err) => return AuthHeaderResult::Err(format_error(err)),
            },
            Err(err) => return AuthHeaderResult::Err(format_error(err)),
        }
    }

    if scenario.use_auth.unwrap_or(false) {
        if scenario.url.is_none() {
            return AuthHeaderResult::Err("use_auth requires a target URL".to_string());
        }
        match attach_auth_header(headers, scenario.url.as_deref().unwrap_or("")).await {
            Ok(updated) => return ok(Some(updated)),
            Err(err) => return AuthHeaderResult::Err(format_error(err)),
        }
    }

    ok(headers)
}
