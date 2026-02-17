use super::*;


/// パフォーマンス統計にアクセス
pub fn with_perf_stats<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&PerfStats) -> R,
{
    PERF_STATS.lock().as_ref().map(f)
}

/// リソースモニターにアクセス
pub fn with_resource_monitor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&ResourceMonitor) -> R,
{
    RESOURCE_MONITOR.lock().as_ref().map(f)
}

/// トレースバッファにアクセス
pub fn with_trace_buffer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&TraceBuffer) -> R,
{
    TRACE_BUFFER.lock().as_ref().map(f)
}

/// CPUプロファイラにアクセス
pub fn with_profiler<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&CpuProfiler) -> R,
{
    CPU_PROFILER.lock().as_ref().map(f)
}

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
mod tests;

