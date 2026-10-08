use super::*;

// =============================================================================
// グローバルインスタンス
// =============================================================================

pub(crate) static PROFILER: crate::sync::InitOnce<Profiler> = crate::sync::InitOnce::new();

// Allocator-boundary telemetry must not initialize the profiler, allocate, or
// capture a stack: those operations can themselves enter the allocator.
static KERNEL_HEAP_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_kernel_heap_allocation() {
    if !crate::cpu::CurrentCpu::acquire().is_some_and(|cpu| cpu.record_heap_allocation()) {
        // Early boot has no CPU-local binding yet.
        KERNEL_HEAP_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn kernel_heap_allocations() -> u64 {
    let mut total = KERNEL_HEAP_ALLOCATIONS.load(Ordering::Relaxed);
    if let Some(runtime) = crate::cpu::try_runtime() {
        for slot in runtime.snapshot().slots() {
            if let Some(local) = runtime.cpu_local(slot.id) {
                total = total.wrapping_add(local.remote().heap_allocations());
            }
        }
    }
    total
}

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
