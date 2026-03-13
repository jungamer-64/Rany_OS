// ============================================================================
// kernel/src/epoch/mod.rs - Epoch facade for live-update reclamation
// ============================================================================
//!
//! `loader::live_update` をエポックの正実装とし、このモジュールは
//! 後方互換のための薄い facade と deferred-free キューだけを提供する。

#![allow(dead_code)]

use crate::loader::live_update;
use crate::sync::PoisonLock;
use alloc::vec::Vec;

struct DeferredFree {
    address: usize,
    size: usize,
    retire_epoch: u64,
}

static DEFERRED_QUEUE: PoisonLock<Vec<DeferredFree>> = PoisonLock::new(Vec::new());

/// クリティカルセクションの開始/終了を管理する RAII ガード
pub struct EpochGuard;

impl EpochGuard {
    pub fn enter(_core_id: usize) -> Self {
        live_update::enter_critical_section();
        Self
    }

    pub fn current_epoch(&self) -> u64 {
        live_update::current_epoch()
    }
}

impl Drop for EpochGuard {
    fn drop(&mut self) {
        live_update::leave_critical_section();
    }
}

pub fn advance_epoch() -> u64 {
    live_update::advance_epoch()
}

pub fn current_epoch() -> u64 {
    live_update::current_epoch()
}

pub fn all_cores_past_epoch(target_epoch: u64) -> bool {
    live_update::all_cores_past_epoch(target_epoch)
}

pub fn wait_for_quiescent_state(target_epoch: u64, max_attempts: u64) -> bool {
    live_update::wait_for_quiescent_state_with_timeout(target_epoch, max_attempts)
}

pub fn defer_free(address: usize, size: usize) {
    let current = current_epoch();
    let mut queue = DEFERRED_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    queue.push(DeferredFree {
        address,
        size,
        retire_epoch: current,
    });
}

pub fn process_deferred_frees() -> usize {
    let mut freed = 0usize;

    let mut queue = DEFERRED_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    queue.retain(|entry| {
        if all_cores_past_epoch(entry.retire_epoch) {
            log::info!(
                "[EPOCH] Freed deferred memory: addr=0x{:x}, size={}\n",
                entry.address,
                entry.size
            );
            freed = freed.saturating_add(entry.size);
            false
        } else {
            true
        }
    });

    freed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUpdateState {
    Idle,
    Loading,
    WaitingForQuiescent,
    Completed,
    RolledBack,
}

pub struct LiveUpdateController {
    state: LiveUpdateState,
    start_epoch: u64,
    rollback_timeout_ms: u64,
}

impl LiveUpdateController {
    pub fn new() -> Self {
        Self {
            state: LiveUpdateState::Idle,
            start_epoch: 0,
            rollback_timeout_ms: 60_000,
        }
    }

    pub fn begin_update(&mut self) -> u64 {
        self.state = LiveUpdateState::Loading;
        self.start_epoch = advance_epoch();
        log::info!(
            "[LIVE_UPDATE] Started update at epoch {}\n",
            self.start_epoch
        );
        self.start_epoch
    }

    pub fn try_switch(&mut self, max_wait_ms: u64) -> bool {
        self.state = LiveUpdateState::WaitingForQuiescent;
        let attempts = max_wait_ms.saturating_mul(1000);
        if wait_for_quiescent_state(self.start_epoch, attempts) {
            self.state = LiveUpdateState::Completed;
            log::info!("[LIVE_UPDATE] Switch completed\n");
            true
        } else {
            log::info!("[LIVE_UPDATE] Quiescent wait timeout, rolling back\n");
            self.rollback();
            false
        }
    }

    pub fn rollback(&mut self) {
        self.state = LiveUpdateState::RolledBack;
        log::info!("[LIVE_UPDATE] Rolled back\n");
    }

    pub fn state(&self) -> LiveUpdateState {
        self.state
    }

    pub fn set_rollback_timeout(&mut self, timeout_ms: u64) {
        self.rollback_timeout_ms = timeout_ms;
    }
}

impl Default for LiveUpdateController {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct EpochStats {
    pub current_epoch: u64,
    pub deferred_queue_size: usize,
    pub active_cores: usize,
}

pub fn stats() -> EpochStats {
    let runtime_stats = live_update::epoch_stats();
    EpochStats {
        current_epoch: runtime_stats.current_epoch,
        deferred_queue_size: DEFERRED_QUEUE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
        active_cores: runtime_stats.active_cores,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_epoch_advance() {
        let e1 = current_epoch();
        let e2 = advance_epoch();
        assert_eq!(e2, e1 + 1);
        assert_eq!(current_epoch(), e2);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_epoch_guard() {
        live_update::set_active_cores(1);
        let start_epoch = current_epoch();
        let guard = EpochGuard::enter(0);
        let _ = advance_epoch();
        assert!(!all_cores_past_epoch(start_epoch));
        drop(guard);
        assert!(all_cores_past_epoch(start_epoch));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_quiescent_detection() {
        live_update::set_active_cores(1);
        let guard = EpochGuard::enter(0);
        let start_epoch = current_epoch();
        let _ = advance_epoch();
        assert!(!wait_for_quiescent_state(start_epoch, 8));
        drop(guard);
        assert!(wait_for_quiescent_state(start_epoch, 8));
    }
}
