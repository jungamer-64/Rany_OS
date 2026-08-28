use super::*;

/// ハイブリッドコーディネーターを取得
pub fn hybrid_coordinator() -> Arc<HybridIoCoordinator> {
    HYBRID_COORDINATOR.call_once(|| Arc::new(HybridIoCoordinator::new(io_scheduler())));
    HYBRID_COORDINATOR
        .get()
        .expect("HYBRID_COORDINATOR must be initialized")
        .clone()
}

// ============================================================================
// Helper Functions
// ============================================================================

/// 現在のtickを取得（仮実装）
pub(crate) fn current_tick() -> u64 {
    #[cfg(feature = "task")]
    {
        crate::task::current_tick()
    }
    #[cfg(not(feature = "task"))]
    {
        static TICK: AtomicU64 = AtomicU64::new(0);
        TICK.fetch_add(1, Ordering::Relaxed)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;
