/// Default per-step timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// Default retry count for transient failures.
pub const DEFAULT_RETRIES: u32 = 0;
/// Default delay between retries in milliseconds.
pub const DEFAULT_RETRY_DELAY_MS: u64 = 250;

/// Resolve timing options for scripted scenarios.
pub fn resolve_scenario_timing(
    timeout_ms: Option<u64>,
    retries: Option<u32>,
    retry_delay_ms: Option<u64>,
) -> (u64, u32, u64) {
    (
        timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
        retries.unwrap_or(DEFAULT_RETRIES),
        retry_delay_ms.unwrap_or(DEFAULT_RETRY_DELAY_MS),
    )
}
