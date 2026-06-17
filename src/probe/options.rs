/// Default per-step timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// Default retry count for transient failures.
pub const DEFAULT_RETRIES: u32 = 0;
/// Default delay between retries in milliseconds.
pub const DEFAULT_RETRY_DELAY_MS: u64 = 250;

/// Resolved probe timing options.
#[derive(Debug, Clone, Copy)]
pub struct ProbeOptions {
    pub timeout_ms: u64,
    pub retries: u32,
    pub retry_delay_ms: u64,
}

/// Resolve timing options from a target, applying defaults.
pub fn resolve_probe_options(
    timeout_ms: Option<u64>,
    retries: Option<u32>,
    retry_delay_ms: Option<u64>,
) -> ProbeOptions {
    ProbeOptions {
        timeout_ms: timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
        retries: retries.unwrap_or(DEFAULT_RETRIES),
        retry_delay_ms: retry_delay_ms.unwrap_or(DEFAULT_RETRY_DELAY_MS),
    }
}
