use super::*;

// =============================================================================
// グローバルインスタンス
// =============================================================================

pub(crate) static PROFILER: spin::Once<Profiler> = spin::Once::new();

pub fn profiler() -> &'static Profiler {
    PROFILER.call_once(Profiler::new)
}

/// プロファイラを初期化
pub fn init() {
    let _ = profiler();
}

/// CPUプロファイリングを開始
pub fn start_cpu_profiling(sample_rate_hz: u64) {
    profiler().cpu.start(sample_rate_hz);
}

/// 全プロファイリングを開始
pub fn start_all(cpu_sample_rate: u64) {
    profiler().start_all(cpu_sample_rate);
}

/// 全プロファイリングを停止
pub fn stop_all() {
    profiler().stop_all();
}

/// レポートを取得
pub fn report() -> ProfileReport {
    profiler().report()
}

/// レイテンシ測定マクロ用
#[macro_export]
macro_rules! profile_latency {
    ($name:expr) => {
        let _guard = $crate::profiler::profiler().latency.scope($name);
    };
}
