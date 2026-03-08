use super::*;

/// パフォーマンス統計にアクセス
pub fn with_perf_stats<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&PerfStats) -> R,
{
    let guard = PERF_STATS.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

/// リソースモニターにアクセス
pub fn with_resource_monitor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&ResourceMonitor) -> R,
{
    let guard = RESOURCE_MONITOR.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

/// トレースバッファにアクセス
pub fn with_trace_buffer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&TraceBuffer) -> R,
{
    let guard = TRACE_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

// Removed: `with_profiler()` — deprecated. Use `crate::profiler::profiler().cpu` instead.

/// 統計を記録
pub fn record(name: &'static str, value: u64) {
    with_perf_stats(|s| s.record(name, value));
}

/// カウンタをインクリメント
pub fn increment(name: &'static str) {
    with_perf_stats(|s| s.increment(name));
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
