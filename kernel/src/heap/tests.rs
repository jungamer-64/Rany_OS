use super::*;
#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::string::String;
#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
use core::alloc::{GlobalAlloc, Layout};

#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_global_alloc_quota_charge_and_uncharge_with_header() {
    use crate::domain::quota::quota_manager;
    use crate::domain::{create_domain, set_domain_resource_limits, terminate_domain};
    use crate::task::{ExecutionContext, TaskId};

    let allocator = KernelHeap::new();
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
    let execution = current.enter_execution(
        ExecutionContext::for_task(TaskId::from_raw(0x4845_4150), domain)
            .expect("execution quota binding"),
    );

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
    let header = unsafe { &*header_ptr };
    assert_eq!(header.magic, ALLOC_HEADER_MAGIC);
    assert!(
        header.quota.is_some(),
        "allocation must retain its quota return right"
    );

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

#[cfg(all(
    any(feature = "full_mm_tests", feature = "qemu-test-export"),
    any(feature = "std", target_os = "linux")
))]
#[test]
fn heap_credit_survives_execution_exit_retirement_and_cross_cpu_free() {
    let allocator = alloc::sync::Arc::new(KernelHeap::new());
    let domain = crate::domain::create_domain(String::from("retained_heap_credit")).unwrap();
    crate::domain::set_domain_resource_limits(domain, 100, 513, 0).unwrap();
    let current = crate::cpu::CurrentCpu::acquire().expect("bound test CPU");
    let context =
        crate::task::ExecutionContext::for_task(crate::task::TaskId::from_raw(21), domain).unwrap();
    let execution = current.enter_execution(context);
    let layout = Layout::from_size_align(512, 128).unwrap();
    // SAFETY: nonzero valid Layout, consumed by exactly one deallocation below.
    let pointer = unsafe { allocator.alloc(layout) };
    assert!(!pointer.is_null());
    assert_eq!(pointer.addr() % 128, 0);
    assert_eq!(
        crate::domain::quota_manager()
            .get_stats(domain)
            .unwrap()
            .memory_used,
        512
    );
    let refused = Layout::from_size_align(2, 1).unwrap();
    // SAFETY: a valid request; the policy rejects it before raw RAM admission.
    assert!(unsafe { allocator.alloc(refused) }.is_null());
    assert_eq!(
        crate::domain::quota_manager()
            .get_stats(domain)
            .unwrap()
            .memory_used,
        512
    );
    drop(execution);
    crate::domain::terminate_domain(domain).unwrap();
    assert_eq!(
        crate::domain::quota_manager()
            .get_stats(domain)
            .unwrap()
            .memory_used,
        512
    );
    let address = pointer.expose_provenance();
    std::thread::spawn(move || {
        // SAFETY: this closure receives the sole live allocation/return right.
        // Parent never accesses it again; its allocating heap and Layout survive.
        unsafe { allocator.dealloc(core::ptr::with_exposed_provenance_mut(address), layout) };
    })
    .join()
    .unwrap();
    assert!(crate::domain::quota_manager().get_stats(domain).is_none());
}

#[cfg(all(
    any(feature = "full_mm_tests", feature = "qemu-test-export"),
    any(feature = "std", target_os = "linux")
))]
#[test]
fn failed_raw_allocation_rolls_back_heap_credit() {
    let allocator = KernelHeap::new();
    let domain = crate::domain::create_domain(String::from("failed_heap_credit")).unwrap();
    let current = crate::cpu::CurrentCpu::acquire().expect("bound test CPU");
    let execution = current.enter_execution(
        crate::task::ExecutionContext::for_task(crate::task::TaskId::from_raw(22), domain).unwrap(),
    );
    // A representable request beyond addressable host/kernel RAM. Layout
    // extension remains valid, so quota is reserved before physical exhaustion.
    let layout = Layout::from_size_align(1usize << 60, 4096).unwrap();
    // SAFETY: nonzero valid Layout; no payload access occurs on failure.
    assert!(unsafe { allocator.alloc(layout) }.is_null());
    // OOM may retire this domain, but the execution binding retains its account
    // for observation until exit. Failure leaves no requested-byte charge.
    assert_eq!(
        crate::domain::quota_manager()
            .get_stats(domain)
            .unwrap()
            .memory_used,
        0
    );
    drop(execution);
    crate::domain::terminate_domain(domain).unwrap();
}
