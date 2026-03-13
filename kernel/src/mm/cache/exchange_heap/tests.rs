use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_exchange_heap_poisoned_allocation_fails() {
    use crate::sync::set_panicking;

    let heap = ExchangeHeap::new();
    unsafe { heap.init(0x1000, 4096) }

    // Poison the lock by simulating a panic while holding the guard
    set_panicking(true);
    {
        let _guard = heap.heap.lock().unwrap();
        // dropping _guard while panicking will mark the lock as poisoned
    }
    set_panicking(false);

    let layout = core::alloc::Layout::from_size_align(64, 8).unwrap();
    assert!(heap.allocate(layout).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_exchange_heap() {
    // メモリ領域を確保（テスト用）
    const HEAP_SIZE: usize = 4096;
    static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

    unsafe {
        // Use addr_of_mut! to avoid creating a shared reference to a mutable static
        EXCHANGE_HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
    }

    // アロケーション
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = EXCHANGE_HEAP.allocate(layout).expect("Allocation failed");

    // 統計確認
    let stats = EXCHANGE_HEAP.stats();
    assert!(stats.allocated > 0);

    // デアロケーション
    unsafe {
        EXCHANGE_HEAP.deallocate(ptr, layout);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_block_coalescing() {
    // Test that adjacent freed blocks are coalesced
    const HEAP_SIZE: usize = 8192;
    static mut HEAP_MEM2: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

    let heap = ExchangeHeap::new();
    unsafe {
        heap.init(core::ptr::addr_of_mut!(HEAP_MEM2) as usize, HEAP_SIZE);
    }

    // Allocate three blocks
    let layout = Layout::from_size_align(128, 8).unwrap();
    let ptr1 = heap.allocate(layout).expect("Allocation 1 failed");
    let ptr2 = heap.allocate(layout).expect("Allocation 2 failed");
    let ptr3 = heap.allocate(layout).expect("Allocation 3 failed");

    // Get initial stats
    let stats_before = heap.extended_stats().unwrap();
    let coalesce_before = stats_before.coalesce_count;

    // Free middle block first
    unsafe {
        heap.deallocate(ptr2, layout);
    }

    // Free first block - should coalesce with ptr2's freed block
    unsafe {
        heap.deallocate(ptr1, layout);
    }

    // Free third block - should coalesce with the combined block
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
