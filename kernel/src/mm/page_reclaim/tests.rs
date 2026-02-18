use super::*;

fn cleanup_frame_if_allocated(frame: FrameIndex) {
    let _ = crate::mm::frame_backing::untrack_frame_backing(frame);
    if crate::mm::buddy_allocator::is_frame_allocated(frame.as_usize()) {
        let physf = unsafe {
            x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                x86_64::PhysAddr::new(frame.to_phys_addr()),
            )
        };
        crate::mm::buddy_allocator::buddy_dealloc_frame(physf);
    }
}

fn reset_test_overrides() {
    crate::mm::async_swapout::set_test_enqueue_override(None);
    clear_test_writeback_overrides();
}

/// Allocate a real frame, create a Gen3 MglruEntry, and insert it into
/// `controller.lru_lists[0]` at generation 3.  Returns just the FrameIndex.
fn setup_gen3_victim(
    controller: &PageReclaimController,
    page_type: PageType,
    dirty: bool,
) -> FrameIndex {
    let frame = crate::mm::alloc_frame().expect("alloc frame");
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let mut entry = MglruEntry::new(frame_idx, page_type, 0);
    entry.generation = MglruGen::Gen3;
    if dirty { entry.flags = LruFlags::DIRTY; }
    entry.referenced.store(false, Ordering::Relaxed);
    controller.lru_lists[0].add_page_to_generation(entry, 3);
    frame_idx
}

/// Allocate a real frame and build a dirty MglruEntry (not added to any LRU).
fn alloc_dirty_entry(page_type: PageType) -> (FrameIndex, MglruEntry) {
    let frame = crate::mm::alloc_frame().expect("alloc frame");
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let mut entry = MglruEntry::new(frame_idx, page_type, 0);
    entry.flags = LruFlags::DIRTY;
    (frame_idx, entry)
}

#[test_case]
fn test_watermarks_calculation() {
    let wm = Watermarks::calculate(100000);
    assert!(wm.high > wm.low);
    assert!(wm.low > wm.min);
    assert!(wm.min > wm.critical);
}

#[test_case]
fn test_pressure_level() {
    let wm = Watermarks::calculate(10000);
    
    assert_eq!(wm.pressure_level(10000), MemoryPressure::None);
    assert_eq!(wm.pressure_level(wm.low - 1), MemoryPressure::Background);
    assert_eq!(wm.pressure_level(wm.min - 1), MemoryPressure::Direct);
    assert_eq!(wm.pressure_level(wm.critical - 1), MemoryPressure::Critical);
}

#[test_case]
fn test_mglru_list_add() {
    let lru = MglruList::new();
    let entry = MglruEntry::new(FrameIndex::new(100), PageType::Anonymous, 0);
    
    lru.add_page(entry);
    let stats = lru.stats();
    assert_eq!(stats.gen_sizes[0], 1); // Gen0に追加される
}

#[test_case]
fn test_blocked_unsafe_requeues_victim() {
    let controller = PageReclaimController::new();
    let mut entry = MglruEntry::new(FrameIndex::new(123), PageType::Anonymous, 0);
    entry.generation = MglruGen::Gen3;
    entry.referenced.store(false, Ordering::Relaxed);
    controller.lru_lists[0].add_page_to_generation(entry, 3);

    let reclaimed = controller.direct_reclaim(1);
    assert_eq!(reclaimed, 0);

    let stats = controller.stats();
    assert_eq!(stats.total_reclaimed, 0);
    assert_eq!(stats.blocked_unsafe, 1);
    assert_eq!(stats.requeued, 1);
    assert_eq!(stats.lru_stats[0].gen_sizes[1], 1);
}

#[test_case]
fn test_blocked_unsafe_requeues_anonymous_dirty_victim() {
    reset_test_overrides();

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::Anonymous, true);

    let reclaimed = controller.direct_reclaim(1);
    assert_eq!(reclaimed, 0);

    let stats = controller.stats();
    assert_eq!(stats.total_reclaimed, 0);
    assert_eq!(stats.blocked_unsafe, 1);
    assert_eq!(stats.requeued, 1);
    assert_eq!(stats.lru_stats[0].gen_sizes[1], 1);

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
fn test_file_backed_clean_reclaims_with_unsafe_disabled() {
    reset_test_overrides();

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::FileBacked, false);

    let reclaimed = controller.direct_reclaim(1);
    assert_eq!(reclaimed, 1);

    let stats = controller.stats();
    assert_eq!(stats.total_reclaimed, 1);
    assert_eq!(stats.blocked_unsafe, 0);
    assert_eq!(stats.lru_stats[0].reclaimed, 1);
    assert!(!crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));
    reset_test_overrides();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::QueueFull,
    ));
    set_test_sync_page_writeback_override(Some(true));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::FileBacked, true);
    crate::mm::frame_backing::track_frame_backing(frame_idx, 0x10, 0);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();
    assert_eq!(reclaimed, 1);
    assert_eq!(after.total_reclaimed, before.total_reclaimed + 1);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);
    assert_eq!(after.lru_stats[0].reclaimed, before.lru_stats[0].reclaimed + 1);
    assert!(!crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));
    assert!(crate::mm::frame_backing::get_frame_backing(frame_idx).is_none());

    reset_test_overrides();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::QueueFull,
    ));
    set_test_sync_page_writeback_override(Some(false));
    set_test_sync_all_writeback_override(Some(false));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::FileBacked, true);
    crate::mm::frame_backing::track_frame_backing(frame_idx, 0x11, 1);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();
    assert_eq!(reclaimed, 0);
    assert_eq!(after.total_reclaimed, before.total_reclaimed);
    assert_eq!(after.writeback_skipped, before.writeback_skipped + 1);
    assert_eq!(after.requeued, before.requeued + 1);
    assert_eq!(after.lru_stats[0].gen_sizes[1], before.lru_stats[0].gen_sizes[1] + 1);
    assert!(crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_file_backed_dirty_without_backing_requeues_with_unsafe_disabled() {
    reset_test_overrides();
    set_test_sync_all_writeback_override(Some(true));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::FileBacked, true);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();
    assert_eq!(reclaimed, 0);
    assert_eq!(after.total_reclaimed, before.total_reclaimed);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);
    assert_eq!(after.requeued, before.requeued + 1);
    assert_eq!(after.blocked_unsafe, before.blocked_unsafe);
    assert!(crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
fn test_already_pending_does_not_count_writeback_skipped() {
    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(true);

    let (frame_idx, entry) = alloc_dirty_entry(PageType::Anonymous);

    controller.enqueue_pending_async(&entry, 0);
    crate::mm::page_flags::set_flag(frame_idx, crate::mm::page_flags::PageMetaFlags::SwapPending);

    let before = controller.stats();
    let outcome = controller.reclaim_page(&entry, 0);
    let after = controller.stats();

    assert_eq!(outcome, ReclaimOutcome::DeferredAsync);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);

    crate::mm::page_flags::clear_flag(frame_idx, crate::mm::page_flags::PageMetaFlags::SwapPending);
    controller.on_async_swapout_complete(frame_idx, false);
    cleanup_frame_if_allocated(frame_idx);
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_already_pending_without_registered_pending_requeues() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::AlreadyPending,
    ));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(true);

    let (frame_idx, entry) = alloc_dirty_entry(PageType::Anonymous);

    let before = controller.stats();
    let outcome = controller.reclaim_page(&entry, 0);
    let after = controller.stats();

    assert_eq!(outcome, ReclaimOutcome::Requeued);
    assert_eq!(after.requeued, before.requeued);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_already_pending_without_registered_pending_requeues_once_in_direct_reclaim() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::AlreadyPending,
    ));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(true);

    let frame_idx = setup_gen3_victim(&controller, PageType::Anonymous, true);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();

    assert_eq!(reclaimed, 0);
    assert_eq!(after.requeued, before.requeued + 1);
    assert_eq!(after.pending_async, before.pending_async);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
fn test_queuefull_does_not_count_writeback_skipped() {
    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(true);

    crate::mm::async_swapout::start_worker();
    crate::mm::async_swapout::set_token_count(0);

    let (frame_idx, entry) = alloc_dirty_entry(PageType::Anonymous);

    let before = controller.stats();
    let outcome = controller.reclaim_page(&entry, 0);
    let after = controller.stats();

    assert_eq!(outcome, ReclaimOutcome::Requeued);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);

    cleanup_frame_if_allocated(frame_idx);
    crate::mm::async_swapout::set_token_count(1);
    crate::mm::async_swapout::stop_worker();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_notsupported_anonymous_dirty_requeues_without_writeback_skipped() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::NotSupported,
    ));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(true);

    let frame_idx = setup_gen3_victim(&controller, PageType::Anonymous, true);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();

    assert_eq!(reclaimed, 0);
    assert_eq!(after.total_reclaimed, before.total_reclaimed);
    assert_eq!(after.requeued, before.requeued + 1);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);
    assert_eq!(after.pending_async, before.pending_async);
    assert_eq!(after.blocked_unsafe, before.blocked_unsafe);

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_notsupported_file_dirty_falls_back_without_writeback_skipped_on_success() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::NotSupported,
    ));
    set_test_sync_page_writeback_override(Some(true));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::FileBacked, true);
    crate::mm::frame_backing::track_frame_backing(frame_idx, 0x22, 2);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();

    assert_eq!(reclaimed, 1);
    assert_eq!(after.total_reclaimed, before.total_reclaimed + 1);
    assert_eq!(after.writeback_skipped, before.writeback_skipped);
    assert!(!crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));

    reset_test_overrides();
}

#[test_case]
#[cfg(not(feature = "full_mm_tests"))]
fn test_notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure() {
    reset_test_overrides();
    crate::mm::async_swapout::set_test_enqueue_override(Some(
        crate::mm::async_swapout::SwapError::NotSupported,
    ));
    set_test_sync_page_writeback_override(Some(false));
    set_test_sync_all_writeback_override(Some(false));

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let frame_idx = setup_gen3_victim(&controller, PageType::FileBacked, true);
    crate::mm::frame_backing::track_frame_backing(frame_idx, 0x33, 3);

    let before = controller.stats();
    let reclaimed = controller.direct_reclaim(1);
    let after = controller.stats();

    assert_eq!(reclaimed, 0);
    assert_eq!(after.total_reclaimed, before.total_reclaimed);
    assert_eq!(after.requeued, before.requeued + 1);
    assert_eq!(after.writeback_skipped, before.writeback_skipped + 1);
    assert!(crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));

    cleanup_frame_if_allocated(frame_idx);
    reset_test_overrides();
}

#[test_case]
fn test_async_success_clears_pending_and_accounts_success() {
    let controller = PageReclaimController::new();
    let entry = MglruEntry::new(FrameIndex::new(200), PageType::FileBacked, 0);
    controller.enqueue_pending_async(&entry, 2);

    assert_eq!(controller.stats().pending_async, 1);
    controller.on_async_swapout_complete(entry.frame, true);

    let stats = controller.stats();
    assert_eq!(stats.pending_async, 0);
    assert_eq!(stats.async_success, 1);
    assert_eq!(stats.total_reclaimed, 1);
    assert_eq!(stats.lru_stats[2].reclaimed, 1);
}

#[test_case]
fn test_async_failure_requeues_and_clears_pending() {
    let controller = PageReclaimController::new();
    let entry = MglruEntry::new(FrameIndex::new(201), PageType::FileBacked, 0);
    controller.enqueue_pending_async(&entry, 3);

    controller.on_async_swapout_complete(entry.frame, false);
    let after = controller.stats();
    assert_eq!(after.pending_async, 0);
    assert_eq!(after.async_fail, 1);
    assert_eq!(after.requeued, 1);
    assert_eq!(after.lru_stats[3].gen_sizes[1], 1);

    // Duplicate notify must be a no-op when pending entry is already consumed.
    controller.on_async_swapout_complete(entry.frame, false);
    let after_duplicate = controller.stats();
    assert_eq!(after_duplicate.pending_async, after.pending_async);
    assert_eq!(after_duplicate.async_fail, after.async_fail);
    assert_eq!(after_duplicate.requeued, after.requeued);
    assert_eq!(after_duplicate.total_reclaimed, after.total_reclaimed);
}
