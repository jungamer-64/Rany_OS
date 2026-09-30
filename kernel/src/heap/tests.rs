use super::*;
#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::string::String;
#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
use core::alloc::{GlobalAlloc, Layout};

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn buddy_coordinates_follow_absolute_alignment() {
    let allocator = BuddyHeapAllocator::new();
    assert_eq!(allocator.buddy_addr(0x14000, 6), 0x15000);
    assert_eq!(allocator.buddy_addr(0x15000, 6), 0x14000);
}

#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_global_alloc_quota_charge_and_uncharge_with_header() {
    use crate::domain::quota::quota_manager;
    use crate::domain::{create_domain, set_domain_resource_limits, terminate_domain};
    use crate::task::{ExecutionContext, TaskId};

    let allocator = LockedBuddyHeap::new();
    let slab = boot_proto::BootstrapHeapLayout::new(256 * 1024, 4096).expect("slab layout");
    // SAFETY: valid nonzero Layout; the returned allocation is uniquely owned
    // and retained rather than freed while this allocator or its blocks live.
    let base = unsafe { alloc::alloc::alloc(slab.allocation()) };
    assert!(!base.is_null());
    let geometry = slab
        .at(base.expose_provenance() as u64, 0, u64::MAX)
        .expect("identity-mapped fixture");
    // SAFETY: fresh page-aligned exclusive RAM, identity mapped in this test.
    // No source reclaimer or alias survives; only these two owners may use it.
    let heaps =
        unsafe { super::super::BootstrapHeaps::from_handoff(geometry.descriptor(), 0, u64::MAX) }
            .expect("valid retained allocation");
    let (memory, _exchange, _) = heaps.into_parts();
    {
        let mut guard = allocator.0.lock().expect("heap lock poisoned");
        guard.init(memory).expect("initial admission");
    }

    let domain = create_domain(String::from("alloc_quota_header")).expect("create_domain failed");
    set_domain_resource_limits(domain, 100, 2 * 1024 * 1024, 0)
        .expect("set_domain_resource_limits failed");

    let current = crate::cpu::CurrentCpu::acquire().expect("test requires a bound CPU");
    let execution = current.enter_execution(ExecutionContext::for_task(
        TaskId::from_raw(0x4845_4150),
        domain,
    ));

    let before = quota_manager()
        .get_stats(domain)
        .expect("quota stats missing")
        .memory_used;

    let layout = Layout::from_size_align(512, 16).expect("layout");
    let ptr = unsafe { allocator.alloc(layout) };
    assert!(!ptr.is_null(), "allocation should succeed");

    let (_, user_offset) = Layout::new::<AllocHeader>()
        .extend(layout)
        .expect("extended layout");
    let header_ptr = unsafe { ptr.sub(user_offset) as *const AllocHeader };
    let header = unsafe { core::ptr::read(header_ptr) };
    assert_eq!(header.magic, ALLOC_HEADER_MAGIC);
    assert_eq!(header.owner_domain, domain.as_u64());
    assert_eq!(header.charged_bytes, layout.size() as u64);

    let charged = quota_manager()
        .get_stats(domain)
        .expect("quota stats missing after alloc")
        .memory_used;
    assert!(
        charged >= before + layout.size() as u64,
        "quota charge should increase used bytes"
    );

    unsafe {
        allocator.dealloc(ptr, layout);
    }

    let after = quota_manager()
        .get_stats(domain)
        .expect("quota stats missing after dealloc")
        .memory_used;
    assert_eq!(after, before, "quota usage should return after dealloc");

    drop(execution);
    let _ = terminate_domain(domain);
}
