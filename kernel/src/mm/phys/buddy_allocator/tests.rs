use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_buddy_allocator() {
    let mut allocator = BuddyFrameAllocator::new();

    // テスト用のメモリ領域（4MiB、MAX_ORDER=18に対応）
    let regions = [(PhysAddr::new(0x100000), 0x400000u64)];
    unsafe {
        allocator.init(&regions);
    }

    // フレーム割り当て
    let frame1 = allocator.allocate_4k_frame();
    assert!(frame1.is_some());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_buddy_allocator_reserves_frame_zero() {
    let mut allocator = BuddyFrameAllocator::new();
    let regions = [(PhysAddr::new(0), 3 * PAGE_SIZE_4K as u64)];
    unsafe {
        allocator.init(&regions);
    }

    let first = allocator.allocate_4k_frame().expect("first frame");
    let second = allocator.allocate_4k_frame().expect("second frame");
    assert_eq!(first.start_address().as_u64(), PAGE_SIZE_4K as u64);
    assert_eq!(second.start_address().as_u64(), 2 * PAGE_SIZE_4K as u64);
    assert!(allocator.allocate_4k_frame().is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn overlapping_region_admission_cannot_republish_live_frames() {
    let mut allocator = BuddyFrameAllocator::new();
    let start = FrameIndex::new(512);
    let end = start.offset(512);
    // SAFETY: the fixture does not dereference or publish physical frame identities.
    assert_eq!(
        unsafe { allocator.register_numa_region(NumaNodeId::NODE_0, start, end) },
        Ok(())
    );
    let frame = allocator.allocate_order(2).expect("live extent");
    let free = allocator.free_frame_count();
    // SAFETY: no external physical users exist; the constructor must still
    // reject overlap with its own previously admitted inventory.
    assert_eq!(
        unsafe { allocator.register_numa_region(NumaNodeId::new(1), start, end) },
        Err(FrameInventoryError::Overlap)
    );
    assert_eq!(allocator.free_frame_count(), free);
    assert_eq!(allocator.deallocate_order(frame, 2), Ok(()));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_order_calculation() {
    assert_eq!(BuddyFrameAllocator::frames_to_order(1), 0);
    assert_eq!(BuddyFrameAllocator::frames_to_order(2), 1);
    assert_eq!(BuddyFrameAllocator::frames_to_order(3), 2);
    assert_eq!(BuddyFrameAllocator::frames_to_order(4), 2);
    assert_eq!(BuddyFrameAllocator::frames_to_order(512), 9);
    assert_eq!(BuddyFrameAllocator::frames_to_order(262144), 18);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_numa_register_and_alloc_local() {
    let mut allocator = BuddyFrameAllocator::new();

    // Register a NUMA region (small area)
    let start = PhysAddr::new(0x1000_0000);
    let size = 0x20_000; // 128 KiB
    let start_frame = FrameIndex::from_phys_addr(start.as_u64());
    let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

    // SAFETY: this local inventory fixture never publishes physical memory.
    assert_eq!(
        unsafe { allocator.register_numa_region(NumaNodeId::new(0), start_frame, end_frame) },
        Ok(())
    );

    // Allocate a 4K frame preferring node 0
    let frame = allocator
        .allocate_4k_frame_on_node(NumaNodeId::new(0))
        .expect("alloc local");
    assert!(frame.start_address().as_u64() >= start.as_u64());
    assert!(frame.start_address().as_u64() < start.as_u64() + size);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_numa_2m_alloc_local() {
    let mut allocator = BuddyFrameAllocator::new();

    // Register a larger NUMA region suitable for 2MiB allocations
    let start = PhysAddr::new(0x2000_0000);
    let size = 0x10_0000; // 1 MiB (smaller than 2MiB but for test we can still allocate a 4K)
    let start_frame = FrameIndex::from_phys_addr(start.as_u64());
    let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

    // SAFETY: this local inventory fixture never publishes physical memory.
    assert_eq!(
        unsafe { allocator.register_numa_region(NumaNodeId::new(1), start_frame, end_frame) },
        Ok(())
    );

    // Try 4K allocation on node 1 (2M allocation may fail due to size)
    let frame = allocator
        .allocate_4k_frame_on_node(NumaNodeId::new(1))
        .expect("alloc 4K local");
    assert!(frame.start_address().as_u64() >= start.as_u64());
    assert!(frame.start_address().as_u64() < start.as_u64() + size);
}
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn compound_release_requires_exact_extent() {
    let mut allocator = BuddyFrameAllocator::new();
    // SAFETY: this isolated inventory fixture never dereferences or publishes
    // the physical frame identities.
    unsafe { allocator.init(&[(PhysAddr::new(0x200000), 0x200000)]) };
    let free = allocator.free_frame_count();
    let frame = allocator.allocate_order(2).expect("order two allocation");
    assert_eq!(allocator.free_frame_count(), free - 4);
    assert_eq!(
        allocator.deallocate_order(frame.offset(1), 0),
        Err(ExtentError::NotAllocationHead)
    );
    assert_eq!(
        allocator.deallocate_order(frame, 0),
        Err(ExtentError::OrderMismatch {
            allocated: 2,
            requested: 0
        })
    );
    assert_eq!(allocator.free_frame_count(), free - 4);
    assert_eq!(allocator.deallocate_order(frame, 2), Ok(()));
    assert_eq!(allocator.free_frame_count(), free);
    assert_eq!(
        allocator.deallocate_order(frame, 2),
        Err(ExtentError::NotAllocationHead)
    );
    assert_eq!(allocator.free_frame_count(), free);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn numa_and_zeroed_allocations_track_the_same_extent_contract() {
    let mut allocator = BuddyFrameAllocator::new();
    let start = FrameIndex::from_phys_addr(0x200000);
    let end = start.offset(512);
    // SAFETY: bookkeeping-only fixture with exclusive frame identities.
    assert_eq!(
        unsafe { allocator.register_numa_region(NumaNodeId::NODE_0, start, end) },
        Ok(())
    );
    let free = allocator.free_frame_count();
    let local = allocator
        .allocate_order_in_range(2, start.as_usize(), end.as_usize())
        .expect("NUMA extent");
    assert_eq!(allocator.deallocate_order(local, 2), Ok(()));
    let zeroed = allocator.find_dirty_free_page(2).expect("returned extent");
    allocator.mark_scrubbed(zeroed, 2);
    let (frame, was_zeroed) = allocator
        .allocate_order_prefer_zeroed(2)
        .expect("zeroed extent");
    assert!(was_zeroed);
    assert_eq!(allocator.deallocate_order(frame, 2), Ok(()));
    assert_eq!(allocator.free_frame_count(), free);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn zero_size_allocation_does_not_consume_a_frame() {
    let mut allocator = BuddyFrameAllocator::new();
    // SAFETY: bookkeeping-only fixture, never published to a physical consumer.
    unsafe { allocator.init(&[(PhysAddr::new(0x200000), 0x200000)]) };
    let free = allocator.free_frame_count();
    assert!(allocator.allocate_contiguous(0).is_none());
    assert_eq!(allocator.free_frame_count(), free);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn coalescing_invalidates_zeroed_state_before_extent_reuse() {
    let mut allocator = BuddyFrameAllocator::new();
    // SAFETY: isolated bookkeeping fixture, never used as physical storage.
    unsafe { allocator.init(&[(PhysAddr::new(0x200000), 0x4000)]) };
    let left = allocator.allocate_order(1).expect("left half");
    let right = allocator.allocate_order(1).expect("right half");
    assert_eq!(allocator.deallocate_order(left, 1), Ok(()));
    assert_eq!(allocator.deallocate_order(right, 1), Ok(()));
    allocator.mark_scrubbed(left, 1);
    allocator.mark_scrubbed(right, 1);
    allocator.try_coalesce_all();
    let combined = allocator.allocate_order(2).expect("coalesced extent");
    assert_eq!(allocator.deallocate_order(combined, 2), Ok(()));
    let (_, was_zeroed) = allocator
        .allocate_order_prefer_zeroed(1)
        .expect("split extent");
    assert!(!was_zeroed, "old child zeroed state survived reuse");
}
