use super::{DomainId, DomainState, DomainStats};
use crate::domain::registry::REGISTRY;
use core::alloc::Layout;

pub use super::registry::{
    add_task_to_domain, create_domain, domain_security_handle, get_domain_numa,
    get_domain_snapshot, get_domain_state, handle_domain_panic, init, is_domain_runnable_now,
    list_domain_snapshots, quota_suspend_deadline_ns, report_cpu_quota_exceeded,
    report_cpu_quota_ok, resume_domain, set_domain_capabilities, set_domain_numa,
    set_domain_priority, set_domain_resource_limits, set_domain_state, spawn_domain_with_caps,
    start_domain, stop_domain, terminate_domain, with_domain, with_domain_mut,
};

pub fn remove_task_from_domain(domain_id: DomainId, task_id: u64) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == domain_id) {
                domain.remove_task(task_id);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (remove_task_from_domain) - no-op"),
    }
}

pub fn register_heap_object(ptr: usize, layout: Layout, owner: DomainId) {
    crate::sas::register_object(
        ptr,
        layout.size(),
        crate::sas::DomainId::new(owner.as_u64()),
    );

    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == owner) {
                domain.increment_rref();
                domain.add_memory(layout.size() as u64);
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (register_heap_object) - stats not updated")
        }
    }
}

pub fn unregister_heap_object(ptr: usize) {
    if let Some((owner, size)) = crate::sas::unregister_any(ptr) {
        match REGISTRY.lock() {
            Ok(mut guard) => {
                let owner = DomainId::new(owner.as_u64());
                if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == owner) {
                    domain.decrement_rref();
                    domain.free_memory(size as u64);
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (unregister_heap_object) - stats not updated"
            ),
        }
    }
}

pub fn transfer_ownership(ptr: usize, new_owner: DomainId) -> bool {
    let Some(old_owner) = crate::sas::get_owner(ptr) else {
        return false;
    };

    if crate::sas::transfer_ownership(
        ptr,
        old_owner,
        crate::sas::DomainId::new(new_owner.as_u64()),
    )
    .is_err()
    {
        return false;
    }

    match REGISTRY.lock() {
        Ok(mut registry) => {
            let old_owner = DomainId::new(old_owner.as_u64());
            if let Some(old_domain) = registry.domains.iter_mut().find(|d| d.id == old_owner) {
                old_domain.decrement_rref();
            }
            if let Some(new_domain) = registry.domains.iter_mut().find(|d| d.id == new_owner) {
                new_domain.increment_rref();
            }
            true
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (transfer_ownership) - stats not updated");
            true
        }
    }
}

pub fn reclaim_domain_resources(domain: DomainId) {
    let count = crate::sas::with_sas_manager_mut(|m| {
        m.reclaim_domain_resources(crate::sas::DomainId::new(domain.as_u64()))
    });

    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    let cleanup = crate::resource_registry::cleanup_owner_domain(domain);
    #[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
    let cleanup = crate::resource_registry::OwnerCleanupStats::default();

    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(d) = guard.domains.iter_mut().find(|d| d.id == domain) {
                d.rref_count = 0;
                d.allocated_memory = 0;
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (reclaim_domain_resources) - stats not reset")
        }
    }

    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    if count > 0 || cleanup.dma.handles > 0 {
        log::info!(
            "[DOMAIN] Reclaimed {} SAS resources and {} DMA handles ({} bytes) from {}\n",
            count,
            cleanup.dma.handles,
            cleanup.dma.bytes,
            domain
        );
    }

    #[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
    if count > 0 || cleanup.dma.handles > 0 {
        log::info!(
            "[DOMAIN] Reclaimed {} SAS resources and {} DMA handles ({} bytes) from {}\n",
            count,
            cleanup.dma.handles,
            cleanup.dma.bytes,
            domain
        );
    }
}

pub fn get_domain_stats() -> DomainStats {
    match REGISTRY.lock() {
        Ok(guard) => {
            let mut stats = DomainStats {
                total: guard.domains.len(),
                running: 0,
                stopped: 0,
                terminated: 0,
                memory_used: 0,
                total_rrefs: 0,
            };

            for domain in guard.domains.iter() {
                match domain.state {
                    DomainState::Running | DomainState::Initializing => stats.running += 1,
                    DomainState::Stopped | DomainState::Suspended => stats.stopped += 1,
                    DomainState::Terminated => stats.terminated += 1,
                }
                stats.memory_used += domain.allocated_memory;
                stats.total_rrefs += domain.rref_count;
            }

            stats
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_stats)");
            DomainStats::default()
        }
    }
}

pub fn get_stats() -> DomainStats {
    get_domain_stats()
}

pub fn print_domain_list() {
    match REGISTRY.lock() {
        Ok(guard) => {
            log::info!("[DOMAIN] === Domain List ===\n");
            for domain in guard.domains.iter() {
                log::info!(
                    "[DOMAIN] {} '{}': {:?}, tasks={}, rrefs={}, mem={}KB\n",
                    domain.id,
                    domain.name,
                    domain.state,
                    domain.tasks.len(),
                    domain.rref_count,
                    domain.allocated_memory / 1024
                );
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (print_domain_list) - skipping"),
    }
}

pub fn current_domain() -> DomainId {
    crate::task::current_subject().domain
}

pub fn is_kernel_domain() -> bool {
    current_domain() == DomainId::KERNEL
}
