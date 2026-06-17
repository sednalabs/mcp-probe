use anyhow::Result;
use reqwest::header::ACCEPT;
use reqwest::Response;
use std::time::Duration;
use tokio::time::timeout;

/// Execute an HTTP request with a timeout in milliseconds.
pub async fn fetch_with_timeout(
    _client: &reqwest::Client,
    request: reqwest::RequestBuilder,
    timeout_ms: u64,
) -> Result<Response> {
    if timeout_ms == 0 {
        return Ok(request.send().await?);
    }
    let duration = Duration::from_millis(timeout_ms);
    let response = timeout(duration, request.send()).await??;
    Ok(response)
}

/// Fetch JSON from a URL with an optional timeout.
///
/// Returns `(ok, data, error)` where `error` is a human-readable message.
pub async fn fetch_json(
    client: &reqwest::Client,
    url: &str,
    timeout_ms: u64,
) -> Result<(bool, Option<serde_json::Value>, Option<String>)> {
    let request = client.get(url).header(ACCEPT, "application/json");
    let response = fetch_with_timeout(client, request, timeout_ms).await;
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            return Ok((false, None, Some(err.to_string())));
        }
    };
    if !response.status().is_success() {
        return Ok((false, None, Some(format!("HTTP {}", response.status()))));
    }
    let data = response.json::<serde_json::Value>().await;
    match data {
        Ok(value) => Ok((true, Some(value), None)),
        Err(err) => Ok((false, None, Some(err.to_string()))),
    }
}
