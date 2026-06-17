use anyhow::Result;
use std::future::Future;
use std::time::Duration;

/// Sleep for the requested number of milliseconds.
pub async fn sleep(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Retry an async operation with optional delay.
pub async fn with_retry<F, Fut, T>(mut op: F, retries: u32, delay_ms: u64) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 0;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if attempt >= retries {
                    return Err(err);
                }
                attempt += 1;
                if delay_ms > 0 {
                    sleep(delay_ms).await;
                }
            }
        }
    }
}

/// Wrap an async operation with a timeout.
pub async fn with_timeout<F, T, E>(future: F, timeout_ms: u64, label: &str) -> Result<T>
where
    F: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    if timeout_ms == 0 {
        return future.await.map_err(anyhow::Error::new);
    }
    match tokio::time::timeout(Duration::from_millis(timeout_ms), future).await {
        Ok(result) => result.map_err(anyhow::Error::new),
        Err(_) => Err(anyhow::anyhow!(
            "{} timed out after {}ms",
            label,
            timeout_ms
        )),
    }
}
