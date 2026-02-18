use super::*;


/// ハイブリッドコーディネーターを取得
pub fn hybrid_coordinator() -> Arc<HybridIoCoordinator> {
    HYBRID_COORDINATOR
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(HybridIoCoordinator::new(io_scheduler())))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// 現在のtickを取得（仮実装）
pub(crate) fn current_tick() -> u64 {
    #[cfg(feature = "task")]
    {
        crate::task::timer::current_tick()
    }
    #[cfg(not(feature = "task"))]
    {
        static TICK: AtomicU64 = AtomicU64::new(0);
        TICK.fetch_add(1, Ordering::Relaxed)
    }
}

// ============================================================================
// Convenience API
// ============================================================================

/// 非同期I/O読み取り
pub async fn async_read(device: DeviceId, priority: IoPriority) -> Result<usize, IoError> {
    hybrid_coordinator()
        .submit_io(device, IoOperationType::Read, priority)
        .await
}

/// 非同期I/O書き込み
pub async fn async_write(device: DeviceId, priority: IoPriority) -> Result<usize, IoError> {
    hybrid_coordinator()
        .submit_io(device, IoOperationType::Write, priority)
        .await
}

/// 非同期フラッシュ
pub async fn async_flush(device: DeviceId) -> Result<usize, IoError> {
    hybrid_coordinator()
        .submit_io(device, IoOperationType::Flush, IoPriority::High)
        .await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;

