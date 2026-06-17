use crate::allowlist::{ensure_host_allowed, parse_allowed_hosts_env};
use crate::http::{fetch_json, fetch_with_timeout};
use crate::report::now_iso;
use anyhow::{anyhow, Result};
use oauth2::TokenResponse;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rmcp::transport::auth::{AuthorizationManager, OAuthClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use url::Url;

const DEFAULT_CACHE_RELATIVE: &str = ".codex/mcp-probe/tokens.json";

/// Cached OAuth tokens stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedTokens {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub obtained_at: String,
}

/// Shape for refresh-token JSON files on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RefreshTokenFile {
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

/// Token cache entry keyed by server URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenCacheEntry {
    pub server_url: String,
    pub tokens: CachedTokens,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub updated_at: String,
}

/// Token cache file structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenCache {
    pub version: u32,
    pub entries: HashMap<String, TokenCacheEntry>,
}

/// Options for refreshing an access token.
#[derive(Debug, Clone)]
pub struct RefreshTokenOptions {
    pub refresh_token: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub server_url: Option<String>,
    pub token_endpoint: Option<String>,
    pub timeout_ms: Option<u64>,
}

/// Result of refreshing an access token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RefreshTokenResult {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// CLI options for OAuth authorization.
#[derive(Debug, Clone)]
pub struct OAuthFlowOptions {
    pub server_url: String,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub allow_dcr: bool,
    pub expect_registration_endpoint: bool,
    pub redirect_host: String,
    pub redirect_port: u16,
    pub open_browser: bool,
}

fn enforce_registration_endpoint_expectation(
    registration_endpoint: Option<&str>,
    expected: bool,
) -> Result<()> {
    if expected && registration_endpoint.is_none() {
        return Err(anyhow!(
            "OAuth metadata is missing registration_endpoint. Enable dynamic client registration on the issuer or omit --expect-registration-endpoint."
        ));
    }
    Ok(())
}

/// Format an auth-source conflict message.
pub fn format_auth_source_error(auth_sources: &[String]) -> String {
    let joined = auth_sources.join(", ");
    let has_use_auth = auth_sources.iter().any(|s| s == "use_auth");
    let has_refresh = auth_sources
        .iter()
        .any(|s| s == "refresh_token" || s == "refresh_token_path");
    let base = format!("Specify only one auth source: {joined}.");
    if has_use_auth && has_refresh {
        return format!("{base} use_auth uses cached tokens; refresh_token* refreshes in-memory. Remove use_auth when using refresh_token*.");
    }
    format!("{base} Choose one: use_auth (cached), access_token/access_token_path, or refresh_token/refresh_token_path.")
}

/// Resolve the token cache path from the environment.
pub fn resolve_token_cache_path() -> PathBuf {
    if let Ok(override_path) = env::var("MCP_PROBE_TOKEN_CACHE") {
        return PathBuf::from(override_path);
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(DEFAULT_CACHE_RELATIVE);
    }
    PathBuf::from("/tmp/mcp-probe-tokens.json")
}

/// Resolve the allowed token directory.
pub fn resolve_token_dir() -> PathBuf {
    if let Ok(override_dir) = env::var("MCP_PROBE_TOKEN_DIR") {
        return PathBuf::from(override_dir);
    }
    resolve_token_cache_path()
        .parent()
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn normalize_server_key(server_url: &str) -> Result<String> {
    let mut parsed = Url::parse(server_url)?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let path = parsed.path().trim_end_matches('/').to_string();
    let normalized_path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    Ok(format!(
        "{}{}",
        parsed.origin().ascii_serialization(),
        normalized_path
    ))
}

async fn load_cache(path: &Path) -> TokenCache {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or(TokenCache {
            version: 1,
            entries: HashMap::new(),
        }),
        Err(_) => TokenCache {
            version: 1,
            entries: HashMap::new(),
        },
    }
}

async fn save_cache(path: &Path, cache: &TokenCache) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_vec_pretty(cache)?;
    #[cfg(unix)]
    {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .await?;
        file.write_all(&payload).await?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(path, payload).await?;
    }
    Ok(())
}

/// Return true when cached tokens are expired.
pub fn is_token_expired(token: &CachedTokens) -> bool {
    let Some(expires_at) = token.expires_at else {
        return false;
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    expires_at <= now + 30
}

/// Store tokens in the cache for the given server URL.
pub async fn store_tokens(
    server_url: &str,
    tokens: CachedTokens,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<()> {
    let cache_path = resolve_token_cache_path();
    let mut cache = load_cache(&cache_path).await;
    let key = normalize_server_key(server_url)?;
    let entry = TokenCacheEntry {
        server_url: key.clone(),
        tokens,
        updated_at: now_iso(),
        client_id,
        client_secret,
    };
    cache.entries.insert(key, entry);
    save_cache(&cache_path, &cache).await?;
    Ok(())
}

/// Fetch cached tokens for a server URL.
pub async fn get_cached_tokens(server_url: &str) -> Result<Option<TokenCacheEntry>> {
    let cache_path = resolve_token_cache_path();
    let cache = load_cache(&cache_path).await;
    let key = normalize_server_key(server_url)?;
    Ok(cache.entries.get(&key).cloned())
}

/// Resolve an access token from the cache or fail with guidance.
pub async fn resolve_access_token(server_url: &str) -> Result<String> {
    let entry = get_cached_tokens(server_url).await?;
    let entry = entry.ok_or_else(|| {
        anyhow!("No cached tokens found for this server URL. Run `mcp-probe auth` first, or pass access_token_path/refresh_token_path (token files must live under MCP_PROBE_TOKEN_DIR).")
    })?;
    if is_token_expired(&entry.tokens) {
        return Err(anyhow!("Cached access token has expired. Run `mcp-probe auth` again, or pass access_token_path/refresh_token_path (token files must live under MCP_PROBE_TOKEN_DIR)."));
    }
    Ok(entry.tokens.access_token)
}

/// Attach a cached Authorization header to the provided headers.
pub async fn attach_auth_header(
    headers: Option<HashMap<String, String>>,
    server_url: &str,
) -> Result<HashMap<String, String>> {
    let token = resolve_access_token(server_url).await?;
    Ok(attach_access_token(headers, &token)?)
}

/// Attach a bearer token to headers, failing if Authorization is already present.
pub fn attach_access_token(
    headers: Option<HashMap<String, String>>,
    access_token: &str,
) -> Result<HashMap<String, String>> {
    let mut headers = headers.unwrap_or_default();
    if headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("authorization"))
    {
        return Err(anyhow!(
            "Authorization header already provided; remove it or disable auth."
        ));
    }
    headers.insert(
        "Authorization".to_string(),
        format!("Bearer {access_token}"),
    );
    Ok(headers)
}

fn is_path_within(base_dir: &Path, target_path: &Path) -> bool {
    if base_dir == target_path {
        return true;
    }
    target_path.starts_with(base_dir)
}

fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
            Component::Normal(seg) => normalized.push(seg),
        }
    }
    normalized
}

async fn resolve_token_path(token_path: &str) -> Result<PathBuf> {
    let base_dir = resolve_token_dir();
    let base_resolved = tokio::fs::canonicalize(&base_dir)
        .await
        .unwrap_or_else(|_| normalize_path(&base_dir));
    let candidate = PathBuf::from(token_path);
    let resolved_candidate = if candidate.is_absolute() {
        tokio::fs::canonicalize(&candidate)
            .await
            .unwrap_or_else(|_| normalize_path(&candidate))
    } else {
        let joined = base_resolved.join(candidate);
        tokio::fs::canonicalize(&joined)
            .await
            .unwrap_or_else(|_| normalize_path(&joined))
    };
    if !is_path_within(&base_resolved, &resolved_candidate) {
        return Err(anyhow!(
            "Token path is outside the allowed directory: {}. Set MCP_PROBE_TOKEN_DIR to allow other locations.",
            base_resolved.display()
        ));
    }
    Ok(resolved_candidate)
}

/// Read an access token from a file path (raw token or JSON with access_token).
pub async fn read_access_token_from_path(token_path: &str) -> Result<String> {
    let resolved = resolve_token_path(token_path).await?;
    let raw = tokio::fs::read_to_string(&resolved).await?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Token file is empty."));
    }
    if trimmed.starts_with('{') {
        let parsed: Value = serde_json::from_str(trimmed)
            .map_err(|err| anyhow!("Token file contains invalid JSON: {err}"))?;
        let token = parsed
            .get("access_token")
            .and_then(|value| value.as_str())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("Token JSON must include a non-empty access_token string."))?;
        return Ok(token.to_string());
    }
    Ok(trimmed.to_string())
}

/// Read a refresh token record from a file path.
pub async fn read_refresh_token_from_path(token_path: &str) -> Result<RefreshTokenFile> {
    let resolved = resolve_token_path(token_path).await?;
    let raw = tokio::fs::read_to_string(&resolved).await?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Token file is empty."));
    }
    if trimmed.starts_with('{') {
        let parsed: Value = serde_json::from_str(trimmed)
            .map_err(|err| anyhow!("Token file contains invalid JSON: {err}"))?;
        let token = parsed
            .get("refresh_token")
            .and_then(|value| value.as_str())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("Token JSON must include a non-empty refresh_token string."))?;
        let record = parsed.as_object().cloned().unwrap_or_default();
        return Ok(RefreshTokenFile {
            refresh_token: token.to_string(),
            client_id: record
                .get("client_id")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            client_secret: record
                .get("client_secret")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            token_endpoint: record
                .get("token_endpoint")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            scope: record
                .get("scope")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            server_url: record
                .get("server_url")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
        });
    }
    Ok(RefreshTokenFile {
        refresh_token: trimmed.to_string(),
        client_id: None,
        client_secret: None,
        token_endpoint: None,
        scope: None,
        server_url: None,
    })
}

/// Normalize token timestamps into the cache format.
pub fn normalize_tokens(
    access_token: String,
    refresh_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    expires_in: Option<i64>,
    expires_at: Option<i64>,
) -> CachedTokens {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let resolved_expires = expires_at.or_else(|| expires_in.map(|value| now + value));
    CachedTokens {
        access_token,
        refresh_token,
        token_type,
        scope,
        expires_at: resolved_expires,
        obtained_at: now_iso(),
    }
}

fn parse_header_value(fragment: &str) -> Option<(String, usize)> {
    let trimmed = fragment.trim_start();
    let leading_ws = fragment.len() - trimmed.len();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let mut escaped = false;
        let mut result = String::new();
        for (idx, ch) in stripped.char_indices() {
            if escaped {
                result.push(ch);
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => return Some((result, leading_ws + idx + 2)),
                _ => result.push(ch),
            }
        }
        None
    } else {
        let end = trimmed
            .find(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .unwrap_or(trimmed.len());
        Some((trimmed[..end].to_string(), leading_ws + end))
    }
}

/// Extract resource_metadata URL from a WWW-Authenticate header.
pub fn extract_resource_metadata_url(header: &str) -> Option<String> {
    let needle = "resource_metadata=";
    let lower = header.to_lowercase();
    let index = lower.find(needle)?;
    let fragment = &header[index + needle.len()..];
    let (value, _consumed) = parse_header_value(fragment)?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

async fn resolve_token_endpoint(options: &RefreshTokenOptions) -> Result<String> {
    if let Some(endpoint) = &options.token_endpoint {
        let allowed_hosts = parse_allowed_hosts_env();
        ensure_host_allowed(endpoint, allowed_hosts.as_deref(), "Token endpoint")?;
        return Ok(endpoint.clone());
    }
    let server_url = options
        .server_url
        .as_ref()
        .ok_or_else(|| anyhow!("token_endpoint or serverUrl is required to refresh tokens."))?;

    let allowed_hosts = parse_allowed_hosts_env();
    ensure_host_allowed(server_url, allowed_hosts.as_deref(), "Server")?;

    let client = reqwest::Client::new();
    let response = client.get(server_url).send().await?;
    let status = response.status();
    if status != reqwest::StatusCode::UNAUTHORIZED && status != reqwest::StatusCode::FORBIDDEN {
        return Err(anyhow!("Failed to discover OAuth token endpoint."));
    }
    let www_auth = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let prm_url = extract_resource_metadata_url(www_auth)
        .ok_or_else(|| anyhow!("Failed to discover OAuth token endpoint."))?;
    ensure_host_allowed(&prm_url, allowed_hosts.as_deref(), "PRM")?;

    let (ok, data, error) =
        fetch_json(&client, &prm_url, options.timeout_ms.unwrap_or(10_000)).await?;
    if !ok {
        return Err(anyhow!(
            "Failed to discover OAuth token endpoint. {}",
            error.unwrap_or_default()
        ));
    }
    let metadata = data.unwrap_or(Value::Null);
    let auth_server = metadata
        .get("authorization_servers")
        .and_then(|value| value.as_array())
        .and_then(|values| values.first())
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("Failed to discover OAuth token endpoint."))?;
    ensure_host_allowed(
        auth_server,
        allowed_hosts.as_deref(),
        "Authorization server",
    )?;

    let issuer = if auth_server.ends_with('/') {
        auth_server.to_string()
    } else {
        format!("{auth_server}/")
    };
    let oidc_url = Url::parse(&issuer)?.join(".well-known/openid-configuration")?;
    let oauth_url = Url::parse(&issuer)?.join(".well-known/oauth-authorization-server")?;
    ensure_host_allowed(
        oidc_url.as_str(),
        allowed_hosts.as_deref(),
        "OAuth metadata",
    )?;
    ensure_host_allowed(
        oauth_url.as_str(),
        allowed_hosts.as_deref(),
        "OAuth metadata",
    )?;

    let (ok_oidc, oidc_data, _) = fetch_json(
        &client,
        oidc_url.as_str(),
        options.timeout_ms.unwrap_or(10_000),
    )
    .await?;
    let oauth_data = if ok_oidc {
        oidc_data
    } else {
        let (ok_oauth, oauth_data, error) = fetch_json(
            &client,
            oauth_url.as_str(),
            options.timeout_ms.unwrap_or(10_000),
        )
        .await?;
        if !ok_oauth {
            return Err(anyhow!(
                "Failed to discover OAuth token endpoint. {}",
                error.unwrap_or_default()
            ));
        }
        oauth_data
    };
    let token_endpoint = oauth_data
        .and_then(|value| value.get("token_endpoint").cloned())
        .and_then(|value| value.as_str().map(|v| v.to_string()))
        .ok_or_else(|| anyhow!("Failed to discover OAuth token endpoint."))?;
    ensure_host_allowed(&token_endpoint, allowed_hosts.as_deref(), "Token endpoint")?;
    Ok(token_endpoint)
}

/// Refresh an access token using a refresh token.
pub async fn refresh_access_token(options: RefreshTokenOptions) -> Result<RefreshTokenResult> {
    let timeout_ms = options.timeout_ms.unwrap_or(10_000);
    let token_endpoint = resolve_token_endpoint(&options).await?;
    let allowed_hosts = parse_allowed_hosts_env();
    ensure_host_allowed(&token_endpoint, allowed_hosts.as_deref(), "Token endpoint")?;

    let mut body = HashMap::new();
    body.insert("grant_type", "refresh_token");
    body.insert("refresh_token", options.refresh_token.as_str());
    body.insert("client_id", options.client_id.as_str());
    if let Some(secret) = options.client_secret.as_ref() {
        body.insert("client_secret", secret.as_str());
    }
    if let Some(scope) = options.scope.as_ref() {
        body.insert("scope", scope.as_str());
    }

    let form_body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(body)
        .finish();
    let client = reqwest::Client::new();
    let request = client
        .post(&token_endpoint)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .body(form_body);
    let response = fetch_with_timeout(&client, request, timeout_ms).await?;
    let status = response.status();
    let raw = response.text().await?;
    if !status.is_success() {
        let detail = raw.trim();
        let suffix = if detail.is_empty() {
            "".to_string()
        } else {
            format!(" {detail}")
        };
        return Err(anyhow!("Token endpoint HTTP {}.{}", status, suffix));
    }
    let parsed: Value = if raw.trim().is_empty() {
        Value::Object(Default::default())
    } else {
        serde_json::from_str(&raw)
            .map_err(|err| anyhow!("Token endpoint returned invalid JSON: {err}"))?
    };
    let record = parsed
        .as_object()
        .ok_or_else(|| anyhow!("Token endpoint response must be a JSON object."))?;
    let access_token = record
        .get("access_token")
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Token endpoint response missing access_token."))?;
    Ok(RefreshTokenResult {
        access_token: access_token.to_string(),
        refresh_token: record
            .get("refresh_token")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        token_type: record
            .get("token_type")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        expires_in: record.get("expires_in").and_then(|value| value.as_i64()),
        scope: record
            .get("scope")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
    })
}

struct CallbackResult {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn wait_for_oauth_callback(host: &str, port: u16) -> Result<CallbackResult> {
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}")).await?;
    let (mut socket, _) = listener.accept().await?;
    let mut buffer = Vec::new();
    let mut temp = [0u8; 1024];
    loop {
        let _ = socket.readable().await?;
        let bytes = match socket.try_read(&mut temp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err.into()),
        };
        buffer.extend_from_slice(&temp[..bytes]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&buffer);
    let line = request.lines().next().unwrap_or("");
    let path = line.split_whitespace().nth(1).unwrap_or("");
    let url = Url::parse(&format!("http://{host}:{port}{path}"))?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            "error" => error = Some(value.to_string()),
            "error_description" => error_description = Some(value.to_string()),
            _ => {}
        }
    }
    let body = if error.is_some() {
        "OAuth error received. You may close this window."
    } else {
        "Authorization complete. You may close this window."
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = socket.write_all(response.as_bytes()).await;
    Ok(CallbackResult {
        code,
        state,
        error,
        error_description,
    })
}

fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        if std::process::Command::new("xdg-open")
            .arg(url)
            .status()
            .is_ok()
        {
            return true;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if std::process::Command::new("open").arg(url).status().is_ok() {
            return true;
        }
    }
    #[cfg(target_os = "windows")]
    {
        if std::process::Command::new("cmd")
            .arg("/C")
            .arg("start")
            .arg(url)
            .status()
            .is_ok()
        {
            return true;
        }
    }
    false
}

/// Run an OAuth authorization flow and store tokens in the cache.
pub async fn run_oauth_flow(options: OAuthFlowOptions) -> Result<CachedTokens> {
    let mut manager = AuthorizationManager::new(options.server_url.clone()).await?;
    let metadata = manager.discover_metadata().await?;
    enforce_registration_endpoint_expectation(
        metadata.registration_endpoint.as_deref(),
        options.expect_registration_endpoint,
    )?;
    manager.set_metadata(metadata);

    let redirect_url = format!(
        "http://{}:{}/oauth/callback",
        options.redirect_host, options.redirect_port
    );
    let scopes: Vec<String> = options
        .scope
        .as_ref()
        .map(|value| value.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();

    let (client_id, client_secret) = if let Some(client_id) = options.client_id.clone() {
        let mut client_config = OAuthClientConfig::new(client_id.clone(), redirect_url.clone())
            .with_scopes(scopes.clone());
        if let Some(client_secret) = options.client_secret.clone() {
            client_config = client_config.with_client_secret(client_secret);
        }
        manager.configure_client(client_config)?;
        (client_id, options.client_secret.clone())
    } else if options.allow_dcr {
        let config = manager
            .register_client("mcp-probe", &redirect_url, &scope_refs)
            .await?;
        (config.client_id, config.client_secret)
    } else {
        return Err(anyhow!("client_id is required unless --allow-dcr is set."));
    };

    let auth_url = manager.get_authorization_url(&scope_refs).await?;
    if options.open_browser {
        if !open_browser(&auth_url) {
            eprintln!("Open this URL to authorize:\n{auth_url}");
        }
    } else {
        eprintln!("Open this URL to authorize:\n{auth_url}");
    }

    let callback = wait_for_oauth_callback(&options.redirect_host, options.redirect_port).await?;
    if let Some(error) = callback.error {
        let detail = callback
            .error_description
            .map(|desc| format!("{error}: {desc}"))
            .unwrap_or(error);
        return Err(anyhow!("OAuth error: {detail}"));
    }
    let code = callback
        .code
        .ok_or_else(|| anyhow!("No authorization code received."))?;
    let state = callback
        .state
        .ok_or_else(|| anyhow!("No state received from callback."))?;

    let token_response = manager.exchange_code_for_token(&code, &state).await?;
    let access_token = token_response.access_token().secret().to_string();
    let refresh_token = token_response
        .refresh_token()
        .map(|token| token.secret().to_string());
    let token_type = Some(token_response.token_type().as_ref().to_string());
    let expires_in = token_response
        .expires_in()
        .map(|duration| duration.as_secs() as i64);
    let scope = token_response.scopes().map(|scopes| {
        scopes
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>()
            .join(" ")
    });

    let cached = normalize_tokens(
        access_token,
        refresh_token,
        token_type,
        scope,
        expires_in,
        None,
    );
    store_tokens(
        &options.server_url,
        cached.clone(),
        Some(client_id),
        client_secret,
    )
    .await?;
    Ok(cached)
}

#[cfg(test)]
mod tests {
    use super::enforce_registration_endpoint_expectation;

    #[test]
    fn registration_endpoint_expectation_accepts_present_endpoint() {
        let result = enforce_registration_endpoint_expectation(
            Some("https://issuer.example/register"),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn registration_endpoint_expectation_rejects_missing_endpoint() {
        let result = enforce_registration_endpoint_expectation(None, true);
        assert!(result.is_err());
        let message = result.expect_err("should fail").to_string();
        assert!(message.contains("missing registration_endpoint"));
    }
}
