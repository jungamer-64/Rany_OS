// ============================================================================
// kernel/src/heap/oom.rs - OOM Killer for Memory Exhaustion Handling
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(any(
    not(any(test, feature = "bench")),
    feature = "full_mm_tests",
    feature = "qemu-test-export"
))]
pub use crate::domain::quota::DomainPriority;
#[cfg(any(
    not(any(test, feature = "bench")),
    feature = "full_mm_tests",
    feature = "qemu-test-export"
))]
use crate::domain::quota::quota_manager;

// テストビルド用フォールバック: domain モジュールが存在しない構成向け
#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DomainPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// OOM統計情報
#[derive(Debug, Clone)]
pub struct OomStats {
    pub total_domains: usize,
    pub kill_count: u64,
    pub freed_memory: u64,
    pub in_progress: bool,
}

pub struct OomKiller {
    in_progress: AtomicBool,
    kill_count: AtomicU64,
    freed_memory: AtomicU64,
}

static OOM_KILLER: OomKiller = OomKiller {
    in_progress: AtomicBool::new(false),
    kill_count: AtomicU64::new(0),
    freed_memory: AtomicU64::new(0),
};

struct OomPass<'a>(&'a AtomicBool);

impl Drop for OomPass<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl OomKiller {
    fn try_free_memory(&self) -> Option<u64> {
        if self
            .in_progress
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            log::info!("[OOM] Already in progress, skipping\n");
            return None;
        }
        // This flag owns admission of one recovery pass. Unwinding ends that
        // admission too; it publishes no payload or cache state of its own.
        let _pass = OomPass(&self.in_progress);

        // OOM bookkeeping must remain possible when the triggering domain's
        // quota is exhausted or is retired by this recovery. Recovery may run
        // destructors, so funding must not grant a kernel security identity. The
        // guard retains the prior admission and restores it before returning.
        let execution = crate::cpu::CurrentCpu::acquire().map(|current| {
            let context = crate::task::ExecutionContext::housekeeping(current.execution());
            current.enter_execution(context)
        });
        let result = self.select_and_kill_victim();
        drop(execution);
        result
    }

    #[cfg(any(
        not(any(test, feature = "bench")),
        feature = "full_mm_tests",
        feature = "qemu-test-export"
    ))]
    fn select_and_kill_victim(&self) -> Option<u64> {
        let victim = quota_manager().select_oom_victim()?;
        let stats = quota_manager().get_stats(victim.domain_id)?;

        log::info!(
            "[OOM] Killing domain {} (priority={:?}, memory={}KB)\n",
            victim.domain_id.as_u64(),
            victim.priority,
            stats.memory_used / 1024
        );

        if let Err(error) = crate::domain::terminate_domain(victim.domain_id) {
            log::warn!(
                "[OOM] Domain {} termination failed: {}",
                victim.domain_id,
                error
            );
            return None;
        }
        // Termination is not evidence that retained allocations were freed.
        // The retired account remains observable until actual credits return.
        let remaining = quota_manager()
            .get_stats(victim.domain_id)
            .map_or(0, |stats| stats.memory_used);
        let freed = stats.memory_used.saturating_sub(remaining);
        log::info!(
            "[OOM] Domain {} terminated, returned {} charged bytes",
            victim.domain_id,
            freed
        );
        self.kill_count.fetch_add(1, Ordering::Relaxed);
        self.freed_memory.fetch_add(freed, Ordering::Relaxed);
        Some(freed)
    }

    #[cfg(not(any(
        not(any(test, feature = "bench")),
        feature = "full_mm_tests",
        feature = "qemu-test-export"
    )))]
    fn select_and_kill_victim(&self) -> Option<u64> {
        None
    }

    fn stats(&self) -> OomStats {
        #[cfg(any(
            not(any(test, feature = "bench")),
            feature = "full_mm_tests",
            feature = "qemu-test-export"
        ))]
        let total_domains = crate::domain::list_domain_snapshots().len();

        #[cfg(not(any(
            not(any(test, feature = "bench")),
            feature = "full_mm_tests",
            feature = "qemu-test-export"
        )))]
        let total_domains = 0;

        OomStats {
            total_domains,
            kill_count: self.kill_count.load(Ordering::Relaxed),
            freed_memory: self.freed_memory.load(Ordering::Relaxed),
            in_progress: self.in_progress.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

pub fn try_free_memory() -> bool {
    let local = crate::heap::reclaim_local_caches();
    let shared = crate::heap::reclaim_shared_pools();
    let physical_reclaimed = local.physical_reclaimed_bytes + shared.reclaimed_bytes;
    log::debug!(
        "cache recovery returned {} heap reservation bytes, published {} Buddy bytes and returned {} physical bytes",
        local.heap_returned_bytes,
        shared.heap_recovered_bytes,
        physical_reclaimed
    );
    if shared.busy_pools != 0 || shared.poisoned_pools != 0 {
        log::warn!("shared pool reclaim deferred: {shared:?}");
    }
    crate::heap::request_remote_reclaim();
    local.made_progress() || shared.made_progress() || OOM_KILLER.try_free_memory().is_some()
}

pub fn stats() -> OomStats {
    OOM_KILLER.stats()
}

#[cfg(all(test, any(feature = "full_mm_tests", feature = "qemu-test-export")))]
mod tests {
    use super::*;
    use crate::domain::quota::DomainPriority;
    use crate::domain::quota::quota_manager;
    use crate::domain::{
        create_domain, get_domain_snapshot, set_domain_priority, set_domain_resource_limits,
        terminate_domain,
    };
    use alloc::string::String;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_oom_killer_uses_quota_victim_selection() {
        let low = create_domain(String::from("oom_quota_low")).expect("create_domain low failed");
        let normal =
            create_domain(String::from("oom_quota_normal")).expect("create_domain normal failed");

        set_domain_priority(low, DomainPriority::Low).expect("set low priority failed");
        set_domain_priority(normal, DomainPriority::Normal).expect("set normal priority failed");
        set_domain_resource_limits(low, 100, u64::MAX, 0).expect("set low limits failed");
        set_domain_resource_limits(normal, 100, 2 * 1024 * 1024 * 1024, 0)
            .expect("set normal limits failed");

        let low_binding = quota_manager().bind_memory(low).expect("low quota binding");
        let normal_binding = quota_manager()
            .bind_memory(normal)
            .expect("normal quota binding");
        let _low_credit = low_binding
            .reserve(1_000_000_000_000)
            .expect("charge low memory failed");
        let _normal_credit = normal_binding
            .reserve(8 * 1024 * 1024)
            .expect("charge normal memory failed");

        let expected = quota_manager()
            .select_oom_victim()
            .expect("expected an OOM victim");
        assert_eq!(
            expected.domain_id, low,
            "quota manager should pick low domain"
        );

        let before = stats();
        assert_eq!(
            OOM_KILLER.try_free_memory(),
            Some(0),
            "retained credits are not freed by termination"
        );
        assert_eq!(
            get_domain_snapshot(low)
                .expect("domain lifecycle record")
                .state,
            crate::domain::DomainState::Terminated
        );
        assert_eq!(
            quota_manager()
                .get_stats(low)
                .expect("retained quota account")
                .memory_used,
            1_000_000_000_000
        );
        assert_eq!(stats().freed_memory, before.freed_memory);
        assert!(
            stats().kill_count >= before.kill_count + 1,
            "kill count should increase after victim termination"
        );

        let _ = terminate_domain(normal);
    }
}
