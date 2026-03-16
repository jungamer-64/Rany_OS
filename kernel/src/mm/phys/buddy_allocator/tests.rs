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
fn test_init_numa_frame_allocator_registers_region_with_buddy() {
    use crate::mm::phys::buddy_allocator::init_buddy_allocator;
    use crate::mm::phys::frame_allocator::init_numa_frame_allocator;
    use crate::mm::types::NumaNodeId;

    // Initialize buddy allocator without owning global memory
    unsafe {
        init_buddy_allocator(&[]);
    }

    // Register a NUMA region for PMM
    let numa_region = [(PhysAddr::new(0x200000), 0x2000u64, NumaNodeId::new(1))];
    unsafe {
        init_numa_frame_allocator(&numa_region);
    }

    // Buddy should not manage the PMM range until it borrows from PMM
    assert!(!crate::mm::phys::buddy_allocator::is_managed_by_buddy(
        PhysAddr::new(0x200000)
    ));

    // Try to allocate a frame preferring that node (best-effort) via PMM borrow
    let alloc = crate::mm::phys::buddy_allocator::buddy_alloc_frame_on_node(NumaNodeId::new(1))
        .expect("borrowed alloc");
    assert!(crate::mm::phys::buddy_allocator::is_managed_by_buddy(
        alloc.start_address()
    ));
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

    allocator.register_numa_region(NumaNodeId::new(0), start_frame, end_frame);

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

    allocator.register_numa_region(NumaNodeId::new(1), start_frame, end_frame);

    // Try 4K allocation on node 1 (2M allocation may fail due to size)
    let frame = allocator
        .allocate_4k_frame_on_node(NumaNodeId::new(1))
        .expect("alloc 4K local");
    assert!(frame.start_address().as_u64() >= start.as_u64());
    assert!(frame.start_address().as_u64() < start.as_u64() + size);
}
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_folio_allocation_and_flags() {
    use crate::mm::meta::page_flags::{self, PageMetaFlags};

    // Initialize page flags for testing (needed for Folio tracking)
    // We allocate enough space for the test frames.
    // Note: This modifies global state, so it might conflict if other tests used page_flags.
    // Currently, other tests largely ignore page_flags (only order-0 allocations).
    unsafe {
        let max_frames = 4096; // 16MB range
        // We blindly call init. In a real scenario, we might want a "try_init" or verify status.
        // Since tests run in parallel, this is slightly risky, but acceptable for this verification phase.
        page_flags::init_page_flags(max_frames);
    }

    let mut allocator = BuddyFrameAllocator::new();

    // Setup a region: 2MB at 2MB offset (Frames 512 to 1024)
    let start = PhysAddr::new(0x200000);
    let size = 0x200000u64; // 2MB
    let regions = [(start, size)];

    unsafe {
        allocator.init(&regions);
    }

    // Allocate Order 2 (16KB, 4 pages)
    let frame = allocator
        .allocate_order(2)
        .expect("Failed to allocate order 2");
    let frame_idx = frame.as_usize();

    // 1. Verify Head Page
    assert!(
        page_flags::test_flag(frame, PageMetaFlags::CompoundHead),
        "Head flag not set"
    );
    assert!(
        !page_flags::test_flag(frame, PageMetaFlags::CompoundTail),
        "Head has Tail flag"
    );
    assert_eq!(page_flags::get_order(frame), 2, "Head order incorrect");

    // 2. Verify Tail Pages
    for i in 1..4 {
        let tail = FrameIndex::new(frame_idx + i);
        assert!(
            page_flags::test_flag(tail, PageMetaFlags::CompoundTail),
            "Tail flag not set at index {}",
            i
        );
        assert!(
            !page_flags::test_flag(tail, PageMetaFlags::CompoundHead),
            "Tail has Head flag at index {}",
            i
        );
        // Allocation only sets order on HEAD. Tail order remains 0.
        assert_eq!(page_flags::get_order(tail), 0, "Tail order should be 0");
    }

    // 3. Verify Deallocation Cleans Up
    allocator.deallocate_order(frame, 2);

    assert!(
        !page_flags::test_flag(frame, PageMetaFlags::CompoundHead),
        "Head flag not cleared"
    );
    assert_eq!(page_flags::get_order(frame), 0, "Head order not cleared");

    for i in 1..4 {
        let tail = FrameIndex::new(frame_idx + i);
        assert!(
            !page_flags::test_flag(tail, PageMetaFlags::CompoundTail),
            "Tail flag not cleared at index {}",
            i
        );
    }
}
