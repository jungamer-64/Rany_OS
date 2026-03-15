// ============================================================================
// kernel/src/memory/oom_killer.rs - OOM Killer for Memory Exhaustion Handling
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use crate::domain::quota::quota_manager;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::format;

// DomainPriority は domain::quota の正規定義を使用する。
// 以前はローカルに3段階版(Low/Normal/Critical)を定義していたが、
// domain::quota の4段階版(Low/Normal/High/Critical)に統一し、
// 情報損失(High→Normal)を解消した。
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub use crate::domain::quota::DomainPriority;

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

impl OomKiller {
    // Removed: register_domain(), unregister_domain(), update_memory_usage()
    // These were deprecated stubs; quota manager is the authoritative source.

    fn try_free_memory(&self) -> Option<u64> {
        if self.in_progress.swap(true, Ordering::SeqCst) {
            log::info!("[OOM] Already in progress, skipping\n");
            return None;
        }

        let result = self.select_and_kill_victim();
        self.in_progress.store(false, Ordering::SeqCst);
        result
    }

    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    fn select_and_kill_victim(&self) -> Option<u64> {
        let victim = quota_manager().select_oom_victim()?;
        let stats = quota_manager().get_stats(victim.domain_id)?;

        let domain_name = crate::domain_system::get_domain_snapshot(victim.domain_id)
            .map(|s| s.name)
            .unwrap_or_else(|| format!("domain-{}", victim.domain_id.as_u64()));

        log::info!(
            "[OOM] Killing domain '{}' (id={}, priority={:?}, memory={}KB)\n",
            domain_name,
            victim.domain_id.as_u64(),
            victim.priority,
            stats.memory_used / 1024
        );

        let freed = self.kill_domain(victim.domain_id.as_u64(), &domain_name, stats.memory_used);
        self.kill_count.fetch_add(1, Ordering::Relaxed);
        self.freed_memory.fetch_add(freed, Ordering::Relaxed);
        Some(freed)
    }

    #[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
    fn select_and_kill_victim(&self) -> Option<u64> {
        None
    }

    fn kill_domain(&self, domain_id: u64, domain_name: &str, freed: u64) -> u64 {
        if let Err(e) =
            crate::domain_system::terminate_domain(crate::domain_system::DomainId::new(domain_id))
        {
            log::warn!(
                "[OOM] Domain {} termination hook failed: {}\n",
                domain_id,
                e
            );
        }

        log::info!(
            "[OOM] Domain '{}' killed, freed {}KB\n",
            domain_name,
            freed / 1024
        );

        freed
    }

    fn stats(&self) -> OomStats {
        #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
        let total_domains = crate::domain_system::list_domain_snapshots().len();

        #[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
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

// Removed: register_domain(), unregister_domain(), update_memory_usage(), register_simple()
// These were deprecated no-op stubs. The quota manager is the authoritative
// source for domain memory tracking. Use `crate::domain::quota::quota_manager()`.

pub fn try_free_memory() -> bool {
    OOM_KILLER.try_free_memory().is_some()
}

pub fn stats() -> OomStats {
    OOM_KILLER.stats()
}

#[cfg(all(test, any(feature = "full_mm_tests", feature = "qemu-test-export")))]
mod tests {
    use super::*;
    use crate::domain::quota::DomainPriority;
    use crate::domain::quota::quota_manager;
    use crate::domain_system::{
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

        quota_manager()
            .try_allocate_memory(low, 1_000_000_000_000)
            .expect("charge low memory failed");
        quota_manager()
            .try_allocate_memory(normal, 8 * 1024 * 1024)
            .expect("charge normal memory failed");

        let expected = quota_manager()
            .select_oom_victim()
            .expect("expected an OOM victim");
        assert_eq!(
            expected.domain_id, low,
            "quota manager should pick low domain"
        );

        let before = stats().kill_count;
        assert!(try_free_memory(), "oom killer should free memory");
        assert!(
            get_domain_snapshot(low).is_none(),
            "low domain should be terminated"
        );
        assert!(
            stats().kill_count >= before + 1,
            "kill count should increase after victim termination"
        );

        let _ = terminate_domain(normal);
    }
}
