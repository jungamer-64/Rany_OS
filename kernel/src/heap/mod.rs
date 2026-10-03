//! Canonical heap and allocator namespace.

mod allocator;
mod buddy;
mod exchange_blocks;
mod exchange_cache;
mod memory;
mod raw;
mod reclaim;
pub(crate) use exchange_blocks::ExchangeBlocks;
pub use exchange_blocks::ExtendedHeapStats;
pub(crate) use exchange_cache::{CacheClass, CachedAllocation, ExchangeCache, ExchangeMagazine};
pub(crate) use exchange_cache::{ExchangeDrainError, drain_current_cache as drain_exchange_cache};
pub(crate) use memory::{BootstrapHeaps, HeapMemory};
pub(crate) use raw::HeapCache;
pub(crate) use reclaim::{
    CacheDrainProgress, LocalCacheDrainError, drain_local_caches, reclaim_local_caches,
};

pub use allocator::{
    ALLOCATOR, free_memory_kb, heap_stats, is_initialized, oom, total_memory_kb, used_memory_kb,
    verify_buddy_integrity,
};

pub(crate) use allocator::{init, physical_memory_offset, set_physical_memory_offset};

#[cfg(test)]
mod exchange_blocks_tests;
#[cfg(test)]
mod exchange_tests;

pub(crate) fn reclaim_shared_pools() -> crate::mm::reclaim::PoolReclaim {
    raw::reclaim_shared_pools().merge(crate::mm::phys::frame_allocator::reclaim_node_caches())
}

/// Queue bounded owner-CPU work without waiting inside GlobalAlloc. An offline
/// transition drains its cache independently, so failed wake/admission cannot
/// manufacture completion or grant another CPU access to its storage.
pub(crate) fn request_remote_reclaim() {
    let Some(runtime) = crate::cpu::try_runtime() else {
        return;
    };
    let snapshot = runtime.snapshot();
    let current = crate::cpu::CurrentCpu::acquire().map(|cpu| cpu.id());
    for cpu in snapshot.online() {
        if Some(cpu) == current {
            continue;
        }
        if let Some(local) = runtime.cpu_local(cpu) {
            let remote = local.remote();
            if remote
                .send(crate::cpu::CpuControlMessage::ReclaimMemory)
                .is_ok()
            {
                remote.request_wake();
                // The queued request remains owned by the CPU's mailbox if the
                // destination changes lifecycle before the IPI is admitted.
                if let Err(error) = crate::cpu::send_ipi(cpu, crate::cpu::IpiKind::ExecutorWake) {
                    log::warn!("memory reclaim wake for CPU {cpu} was not admitted: {error:?}");
                }
            }
        }
    }
}
