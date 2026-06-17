use anyhow::Error;
use reqwest::StatusCode;
use serde_json::{json, Map, Value};
use url::Url;

pub const CODE_HTTP_REQUEST_FAILED: &str = "http_request_failed";
pub const CODE_HTTP_STATUS: &str = "http_status";
pub const CODE_INVALID_JSON: &str = "invalid_json";
pub const CODE_ISSUER_MISMATCH: &str = "issuer_mismatch";
pub const CODE_NETWORK_TIMEOUT: &str = "network_timeout";
pub const CODE_NETWORK_UNREACHABLE: &str = "network_unreachable";
pub const CODE_STATEFUL_SESSION_REQUIRED: &str = "stateful_session_required";
pub const CODE_URL_MALFORMED: &str = "url_malformed";

fn base_data(code: &str, endpoint: &str, url: &str) -> Map<String, Value> {
    let mut data = Map::new();
    data.insert("code".to_string(), Value::String(code.to_string()));
    data.insert("endpoint".to_string(), Value::String(endpoint.to_string()));
    data.insert("url".to_string(), Value::String(url.to_string()));
    data
}

/// Validate a URL and return a structured malformed URL diagnostic on parse failure.
pub fn validate_url(endpoint: &str, url: &str) -> Result<Url, (String, Value)> {
    Url::parse(url).map_err(|error| malformed_url_detail(endpoint, url, &error.to_string()))
}

/// Build a structured malformed URL diagnostic.
pub fn malformed_url_detail(endpoint: &str, url: &str, error: &str) -> (String, Value) {
    let mut data = base_data(CODE_URL_MALFORMED, endpoint, url);
    data.insert("error".to_string(), Value::String(error.to_string()));
    (format!("Malformed {endpoint} URL"), Value::Object(data))
}

/// Build a structured request failure diagnostic.
pub fn classify_request_error(endpoint: &str, url: &str, error: &Error) -> (String, Value) {
    let reqwest_error = error.downcast_ref::<reqwest::Error>();
    let (code, detail) = if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
        || reqwest_error
            .map(|value| value.is_timeout())
            .unwrap_or(false)
    {
        (
            CODE_NETWORK_TIMEOUT,
            format!("{endpoint} request timed out"),
        )
    } else if reqwest_error
        .map(|value| value.is_connect())
        .unwrap_or(false)
    {
        (
            CODE_NETWORK_UNREACHABLE,
            format!("{endpoint} endpoint is unreachable"),
        )
    } else if reqwest_error
        .map(|value| value.is_request())
        .unwrap_or(false)
        && reqwest_error
            .map(|value| value.to_string().to_lowercase().contains("url"))
            .unwrap_or(false)
    {
        (CODE_URL_MALFORMED, format!("Malformed {endpoint} URL"))
    } else {
        (
            CODE_HTTP_REQUEST_FAILED,
            format!("Failed to request {endpoint} endpoint"),
        )
    };
    let mut data = base_data(code, endpoint, url);
    data.insert("error".to_string(), Value::String(error.to_string()));
    (detail, Value::Object(data))
}

/// Build a structured non-success HTTP status diagnostic.
pub fn http_status_detail(endpoint: &str, url: &str, status: StatusCode) -> (String, Value) {
    let mut data = base_data(CODE_HTTP_STATUS, endpoint, url);
    data.insert("status".to_string(), Value::from(status.as_u16()));
    (
        format!("{endpoint} returned HTTP {}", status.as_u16()),
        Value::Object(data),
    )
}

pub async fn classify_stateful_session_required_response(
    endpoint: &str,
    url: &str,
    response: reqwest::Response,
) -> Option<(String, Value)> {
    if response.status() != StatusCode::BAD_REQUEST {
        return None;
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response.bytes().await.ok()?;
    let body_preview = String::from_utf8_lossy(&bytes)
        .chars()
        .take(160)
        .collect::<String>()
        .replace('\n', " ");
    let payload = serde_json::from_slice::<Value>(&bytes).ok();
    let error = payload
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let hint = payload
        .as_ref()
        .and_then(|value| value.get("hint"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let body_lower = body_preview.to_ascii_lowercase();
    let error_lower = error.to_ascii_lowercase();
    let hint_lower = hint.to_ascii_lowercase();
    let path = Url::parse(url)
        .ok()
        .map(|parsed| parsed.path().to_ascii_lowercase())
        .unwrap_or_default();

    let mentions_missing_session =
        error_lower.contains("missing session id") || body_lower.contains("missing session id");
    let mentions_init_post = hint_lower.contains("initialize with post")
        || body_lower.contains("initialize with post")
        || hint_lower.contains("obtain a session id")
        || body_lower.contains("obtain a session id")
        || (!path.is_empty()
            && path != "/"
            && (hint_lower.contains(&format!("post {path}"))
                || body_lower.contains(&format!("post {path}"))));

    if !mentions_missing_session || !mentions_init_post {
        return None;
    }

    let mut data = base_data(CODE_STATEFUL_SESSION_REQUIRED, endpoint, url);
    data.insert(
        "status".to_string(),
        Value::from(StatusCode::BAD_REQUEST.as_u16()),
    );
    data.insert("error".to_string(), Value::String(error.to_string()));
    data.insert("hint".to_string(), Value::String(hint.to_string()));
    data.insert(
        "classification".to_string(),
        Value::String("stateful_mcp_requires_session".to_string()),
    );
    data.insert(
        "path".to_string(),
        Value::String(if path.is_empty() {
            "/".to_string()
        } else {
            path
        }),
    );
    data.insert(
        "body_preview".to_string(),
        Value::String(body_preview.trim().to_string()),
    );
    if let Some(content_type) = content_type {
        data.insert("content_type".to_string(), Value::String(content_type));
    }

    Some((
        format!("{endpoint} requires an initialized session before GET/DELETE requests"),
        Value::Object(data),
    ))
}

/// Build a structured invalid JSON response diagnostic.
pub fn invalid_json_detail(
    endpoint: &str,
    url: &str,
    content_type: Option<&str>,
    body_preview: &str,
    error: &str,
) -> (String, Value) {
    let mut data = base_data(CODE_INVALID_JSON, endpoint, url);
    if let Some(content_type) = content_type {
        data.insert(
            "content_type".to_string(),
            Value::String(content_type.to_string()),
        );
    }
    data.insert(
        "body_preview".to_string(),
        Value::String(body_preview.to_string()),
    );
    data.insert("error".to_string(), Value::String(error.to_string()));
    (
        format!("{endpoint} did not return valid JSON"),
        Value::Object(data),
    )
}

fn normalize_path(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    }
}

/// Normalize issuer URL values for deterministic comparison.
pub fn normalize_issuer(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let mut normalized = parsed.clone();
    normalized.set_query(None);
    normalized.set_fragment(None);
    let normalized_path = normalize_path(parsed.path());
    normalized.set_path(&normalized_path);
    Some(normalized.to_string())
}

/// Build a structured issuer mismatch diagnostic.
pub fn issuer_mismatch_detail(
    target_url: &str,
    authorization_server: &str,
    oauth_issuer: &str,
    expected_issuer: &str,
    discovered_issuer: &str,
) -> (String, Value) {
    let target = Url::parse(target_url).ok();
    let auth_server = Url::parse(authorization_server).ok();
    let issuer = Url::parse(oauth_issuer).ok();
    let mut data = base_data(CODE_ISSUER_MISMATCH, "oauth_metadata", oauth_issuer);
    data.insert(
        "configured_url".to_string(),
        Value::String(target_url.to_string()),
    );
    data.insert(
        "authorization_server".to_string(),
        Value::String(authorization_server.to_string()),
    );
    data.insert(
        "oauth_issuer".to_string(),
        Value::String(oauth_issuer.to_string()),
    );
    data.insert(
        "expected_issuer".to_string(),
        Value::String(expected_issuer.to_string()),
    );
    data.insert(
        "discovered_issuer".to_string(),
        Value::String(discovered_issuer.to_string()),
    );
    if let Some(target) = target {
        data.insert(
            "configured_origin".to_string(),
            Value::String(target.origin().ascii_serialization()),
        );
        data.insert(
            "configured_path".to_string(),
            Value::String(target.path().to_string()),
        );
    }
    if let Some(auth_server) = auth_server {
        data.insert(
            "authorization_server_origin".to_string(),
            Value::String(auth_server.origin().ascii_serialization()),
        );
    }
    if let Some(issuer) = issuer {
        data.insert(
            "oauth_issuer_origin".to_string(),
            Value::String(issuer.origin().ascii_serialization()),
        );
    }
    (
        "OAuth issuer does not match PRM authorization server".to_string(),
        Value::Object(data),
    )
}

/// Attach a prior attempt diagnostic to a fallback diagnostic.
pub fn attach_prior_attempt(data: Value, prior_detail: String, prior_data: Value) -> Value {
    let mut data = match data {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    data.insert(
        "prior_attempt".to_string(),
        json!({
            "detail": prior_detail,
            "data": prior_data
        }),
    );
    Value::Object(data)
}
