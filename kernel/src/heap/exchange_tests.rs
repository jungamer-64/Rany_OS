use crate::mm::cache::exchange_heap::ExchangeHeap;
use core::alloc::Layout;

fn owned_exchange(bytes: usize) -> crate::heap::HeapMemory {
    let layout = boot_proto::BootstrapHeapLayout::new(4096, bytes).expect("fixture slab layout");
    // SAFETY: valid page-aligned nonzero allocation; no alias or source
    // reclaimer survives the ownership transfer into the two heap owners.
    let base = unsafe { alloc::alloc::alloc(layout.allocation()) };
    assert!(!base.is_null());
    let geometry = layout
        .at(base.addr() as u64, 0, u64::MAX)
        .expect("identity-mapped fixture");
    // SAFETY: fresh exclusive RAM is stable for the test/kernel lifetime and
    // remains retained; identity mapping covers this exact allocation.
    let heaps =
        unsafe { crate::heap::BootstrapHeaps::from_handoff(geometry.descriptor(), 0, u64::MAX) }
            .expect("fixture ownership admission");
    let (_kernel, exchange, _) = heaps.into_parts();
    exchange
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_exchange_heap() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(4096))
        .expect("heap admission");

    // アロケーション
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = heap.allocate(layout).expect("Allocation failed");

    // 統計確認
    let stats = heap.stats();
    assert!(stats.allocated > 0);

    // SAFETY: exclusive allocation from this heap, with the exact original layout.
    unsafe {
        heap.deallocate(ptr, layout);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn duplicate_admission_preserves_existing_allocations_and_returns_owner() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(4096))
        .expect("first admission");
    let layout = Layout::from_size_align(64, 8).expect("allocation layout");
    let ptr = heap.allocate(layout).expect("allocation");
    // SAFETY: this live exclusive allocation contains at least 64 bytes.
    unsafe {
        ptr.as_ptr().write_bytes(0x5a, 64);
    }
    let incoming = owned_exchange(8192);
    let incoming_start = incoming.start();
    let retained = heap
        .initialize(incoming)
        .expect_err("duplicate admission must fail");
    assert_eq!(retained.start(), incoming_start);
    // SAFETY: duplicate admission did not free or reinitialize the first heap;
    // the allocation stays exclusively owned and fully initialized above.
    assert!(
        unsafe { core::slice::from_raw_parts(ptr.as_ptr(), 64) }
            .iter()
            .all(|byte| *byte == 0x5a)
    );
    // SAFETY: same allocation and exact original Layout, no remaining borrow.
    unsafe {
        heap.deallocate(ptr, layout);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_block_coalescing() {
    let heap = ExchangeHeap::new();
    heap.initialize(owned_exchange(8192))
        .expect("heap admission");

    // Allocate three blocks
    // Coalescing is a backing-allocator contract, not a cache eviction policy.
    // Use an uncached size so CPU availability cannot change this test's meaning.
    let layout = Layout::from_size_align(512, 8).unwrap();
    let ptr1 = heap.allocate(layout).expect("Allocation 1 failed");
    let ptr2 = heap.allocate(layout).expect("Allocation 2 failed");
    let ptr3 = heap.allocate(layout).expect("Allocation 3 failed");

    // Get initial stats
    let stats_before = heap.extended_stats().unwrap();
    let coalesce_before = stats_before.coalesce_count;

    // Free middle block first
    // SAFETY: exact original allocation/layout from this heap; no live borrow.
    unsafe {
        heap.deallocate(ptr2, layout);
    }

    // Free first block - should coalesce with ptr2's freed block
    // SAFETY: exact original allocation/layout from this heap; no live borrow.
    unsafe {
        heap.deallocate(ptr1, layout);
    }

    // Free third block - should coalesce with the combined block
    // SAFETY: exact original allocation/layout from this heap; no live borrow.
    unsafe {
        heap.deallocate(ptr3, layout);
    }

    // Check that coalescing occurred
    let stats_after = heap.extended_stats().unwrap();
    assert!(
        stats_after.coalesce_count > coalesce_before,
        "Expected coalescing to occur: before={}, after={}",
        coalesce_before,
        stats_after.coalesce_count
    );
}
