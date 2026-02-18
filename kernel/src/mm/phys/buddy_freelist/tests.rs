use super::*;

#[test_case]
fn test_migrate_type_fallback() {
    let fallbacks = MigrateType::Movable.fallback_order();
    assert!(fallbacks.contains(&MigrateType::Reclaimable));
    assert!(fallbacks.contains(&MigrateType::Unmovable));
}

#[test_case]
fn test_frame_to_color() {
    assert_eq!(frame_to_color(0), 0);
    assert_eq!(frame_to_color(64), 0);
    assert_eq!(frame_to_color(1), 1);
    assert_eq!(frame_to_color(63), 63);
}

#[test_case]
fn test_page_flags() {
    let mut flags = PageFlags::NONE;
    assert!(!flags.contains(PageFlags::FREE));

    flags.insert(PageFlags::FREE);
    assert!(flags.contains(PageFlags::FREE));

    flags.insert(PageFlags::ZEROED);
    assert!(flags.contains(PageFlags::FREE));
    assert!(flags.contains(PageFlags::ZEROED));

    flags.remove(PageFlags::FREE);
    assert!(!flags.contains(PageFlags::FREE));
    assert!(flags.contains(PageFlags::ZEROED));
}

#[test_case]
fn test_freelist_basic_alloc_dealloc() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 4MB at 1MB
    let regions = [(PhysAddr::new(0x100000), 0x400000u64)];
    unsafe { allocator.init(&regions); }

    let frame = allocator.allocate_4k_frame();
    assert!(frame.is_some());

    let frame = frame.unwrap();
    allocator.deallocate_4k_frame(frame);
}

#[test_case]
fn test_freelist_buddy_coalescing() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 2MB at 2MB boundary
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    let initial_free = allocator.free_count();

    // 隣接するorder-0ブロックを2つ割り当て
    let f1 = allocator.allocate(0, MigrateType::Movable).unwrap();
    let f2 = allocator.allocate(0, MigrateType::Movable).unwrap();

    // 両方解放 — order-1にコアレスするはず
    allocator.deallocate(f1, 0);
    allocator.deallocate(f2, 0);

    assert_eq!(allocator.free_count(), initial_free);
}

#[test_case]
fn test_freelist_split_and_merge() {
    let mut allocator = FreeListBuddyAllocator::new();
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    let initial_free = allocator.free_count();

    // order 0 の割り当て（上位オーダーからの分割が発生）
    let f = allocator.allocate(0, MigrateType::Movable).unwrap();
    assert_eq!(allocator.free_count(), initial_free - 1);

    let stats = allocator.stats();
    assert!(stats.split_count > 0);

    allocator.deallocate(f, 0);
    assert_eq!(allocator.free_count(), initial_free);
}

#[test_case]
fn test_freelist_migrate_fallback_alloc() {
    let mut allocator = FreeListBuddyAllocator::new();
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    // 初期メモリは全てMovable。Unmovableの割り当てはフォールバックが発生する。
    let frame = allocator.allocate(0, MigrateType::Unmovable);
    assert!(frame.is_some());

    let stats = allocator.stats();
    assert!(stats.fallback_count > 0);
}

#[test_case]
fn test_freelist_stats() {
    let mut allocator = FreeListBuddyAllocator::new();
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    let stats = allocator.stats();
    assert!(stats.total_frames > 0);
    assert!(stats.free_frames > 0);
}

#[test_case]
fn test_freelist_2m_allocation() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 2MB at 2MB boundary
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    let frame = allocator.allocate_2m_frame();
    assert!(frame.is_some());
    let frame = frame.unwrap();
    // 2MBアライメントを確認
    assert_eq!(frame.start_address().as_u64() % (PAGE_SIZE_2M as u64), 0);
}

#[test_case]
fn test_freelist_contiguous_allocation() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 4MB at 1MB
    let regions = [(PhysAddr::new(0x100000), 0x400000u64)];
    unsafe { allocator.init(&regions); }

    // 16ページ連続割り当て（order 4に切り上げ）
    let addr = allocator.allocate_contiguous(16);
    assert!(addr.is_some());

    let addr = addr.unwrap();
    // 16ページ = 64KB アライメントを確認
    assert_eq!(addr.as_u64() % (16 * PAGE_SIZE_4K as u64), 0);
}

#[test_case]
fn test_freelist_frames_to_order() {
    assert_eq!(FreeListBuddyAllocator::frames_to_order(0), 0);
    assert_eq!(FreeListBuddyAllocator::frames_to_order(1), 0);
    assert_eq!(FreeListBuddyAllocator::frames_to_order(2), 1);
    assert_eq!(FreeListBuddyAllocator::frames_to_order(3), 2);
    assert_eq!(FreeListBuddyAllocator::frames_to_order(4), 2);
    assert_eq!(FreeListBuddyAllocator::frames_to_order(5), 3);
    assert_eq!(FreeListBuddyAllocator::frames_to_order(512), 9);
}

#[test_case]
fn test_freelist_allocate_with_color() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 4MB at 2MB boundary — 十分なフレームでカラー分散を確保
    let regions = [(PhysAddr::new(0x200000), 0x400000u64)];
    unsafe { allocator.init(&regions); }

    let preferred_color = 3u8;
    let frame = allocator.allocate_with_color(0, MigrateType::Movable, preferred_color);
    assert!(frame.is_some());
    let frame = frame.unwrap();
    let actual_color = frame_to_color(frame.as_usize());
    assert_eq!(actual_color, preferred_color);
}

#[test_case]
fn test_freelist_max_order_rejection() {
    let mut allocator = FreeListBuddyAllocator::new();
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    // MAX_ORDER + 1 は拒否される
    let result = allocator.allocate(MAX_ORDER + 1, MigrateType::Movable);
    assert!(result.is_none());
}

#[test_case]
fn test_freelist_allocate_from_empty() {
    // 未初期化アロケータからの割り当ては None を返す
    let mut allocator = FreeListBuddyAllocator::new();
    let result = allocator.allocate(0, MigrateType::Movable);
    assert!(result.is_none());
}

#[test_case]
fn test_freelist_multi_order_coalescing() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 2MB at 2MB boundary
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    let initial_free = allocator.free_count();

    // 4つのorder-0フレームを割り当て
    let f1 = allocator.allocate(0, MigrateType::Movable).unwrap();
    let f2 = allocator.allocate(0, MigrateType::Movable).unwrap();
    let f3 = allocator.allocate(0, MigrateType::Movable).unwrap();
    let f4 = allocator.allocate(0, MigrateType::Movable).unwrap();

    // 全て解放 — 少なくとも3回のコアレスが発生するはず
    allocator.deallocate(f1, 0);
    allocator.deallocate(f2, 0);
    allocator.deallocate(f3, 0);
    allocator.deallocate(f4, 0);

    assert_eq!(allocator.free_count(), initial_free);
    let stats = allocator.stats();
    assert!(stats.coalesce_count >= 3, "coalesce_count={}", stats.coalesce_count);
}

#[test_case]
fn test_freelist_fragmentation_stress() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 2MB at 2MB boundary
    let regions = [(PhysAddr::new(0x200000), 0x200000u64)];
    unsafe { allocator.init(&regions); }

    // 全ページをorder-0で割り当て
    let mut frames = alloc::vec::Vec::new();
    while let Some(f) = allocator.allocate(0, MigrateType::Movable) {
        frames.push(f);
    }

    assert!(frames.len() >= 512); // 2MB / 4KB = 512 pages

    // 交互に解放（最大断片化）
    for i in (0..frames.len()).step_by(2) {
        allocator.deallocate(frames[i], 0);
    }

    // order-1 (8KB) 割り当ては失敗するはず（連続ペアがない）
    let big = allocator.allocate(1, MigrateType::Movable);
    assert!(big.is_none(), "Expected None but got {:?}", big);

    // 残りのページを解放
    for i in (1..frames.len()).step_by(2) {
        allocator.deallocate(frames[i], 0);
    }
}

#[test_case]
fn test_freelist_move_freepages_block() {
    let mut allocator = FreeListBuddyAllocator::new();
    // 4MB at 2MB boundary
    let regions = [(PhysAddr::new(0x200000), 0x400000u64)];
    unsafe { allocator.init(&regions); }

    // 初期メモリは全てMovable。Unmovableの割り当てはフォールバック+pageblock盗用を引き起こす。
    let frame = allocator.allocate(0, MigrateType::Unmovable);
    assert!(frame.is_some());
    assert!(allocator.fallback_count() > 0);

    // フォールバック時にpageblockのタイプがUnmovableに変更されているか確認
    let frame_idx = frame.unwrap().as_usize();
    let block_mt = allocator.get_pageblock_migratetype(frame_idx);
    assert_eq!(block_mt, MigrateType::Unmovable);
}
