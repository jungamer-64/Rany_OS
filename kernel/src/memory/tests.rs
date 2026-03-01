use super::*;
#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::string::String;
#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
use core::alloc::{GlobalAlloc, Layout};

#[test_case]
fn exchange_heap_after_global_heap() {
    // Exchange heap must be placed after the global heap (no overlap)
    let heap_end = heap_start().saturating_add(HEAP_SIZE as u64);
    assert!(exchange_heap_start() >= heap_end);
}

#[cfg(any(feature = "full_mm_tests", feature = "qemu-test-export"))]
#[test_case]
fn test_global_alloc_quota_charge_and_uncharge_with_header() {
    use crate::domain::quota::quota_manager;
    use crate::domain_system::{
        create_domain, current_domain, set_current_domain, set_domain_resource_limits,
        terminate_domain,
    };

    #[repr(align(4096))]
    struct LocalHeap([u8; 256 * 1024]);

    static mut TEST_HEAP: LocalHeap = LocalHeap([0; 256 * 1024]);

    let allocator = LockedBuddyHeap::new();
    let heap_base = unsafe { core::ptr::addr_of_mut!(TEST_HEAP.0).cast::<u8>() as usize };
    {
        let mut guard = allocator.0.lock().expect("heap lock poisoned");
        unsafe { guard.init(heap_base, 256 * 1024); }
    }

    let domain = create_domain(String::from("alloc_quota_header")).expect("create_domain failed");
    set_domain_resource_limits(domain, 100, 2 * 1024 * 1024, 0)
        .expect("set_domain_resource_limits failed");

    let prev = current_domain();
    set_current_domain(domain);

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

    unsafe { allocator.dealloc(ptr, layout); }

    let after = quota_manager()
        .get_stats(domain)
        .expect("quota stats missing after dealloc")
        .memory_used;
    assert_eq!(after, before, "quota usage should return after dealloc");

    set_current_domain(prev);
    let _ = terminate_domain(domain);
}
