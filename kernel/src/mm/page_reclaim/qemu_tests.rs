use super::*;
use core::sync::atomic::Ordering;

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

pub fn wave7_watermarks_calculation_smoke() -> bool {
    let wm = Watermarks::calculate(100_000);
    wm.high > wm.low && wm.low > wm.min && wm.min > wm.critical
}

pub fn wave7_pressure_level_smoke() -> bool {
    let wm = Watermarks::calculate(10_000);
    wm.pressure_level(10_000) == MemoryPressure::None
        && wm.pressure_level(wm.low.saturating_sub(1)) == MemoryPressure::Background
        && wm.pressure_level(wm.min.saturating_sub(1)) == MemoryPressure::Direct
        && wm.pressure_level(wm.critical.saturating_sub(1)) == MemoryPressure::Critical
}

pub fn wave7_mglru_list_add_smoke() -> bool {
    let lru = MglruList::new();
    lru.add_page(MglruEntry::new(FrameIndex::new(100), PageType::Anonymous, 0));
    lru.stats().gen_sizes[0] == 1
}

pub fn wave7_blocked_unsafe_requeues_victim_smoke() -> bool {
    let controller = PageReclaimController::new();
    let mut entry = MglruEntry::new(FrameIndex::new(123), PageType::Anonymous, 0);
    entry.generation = MglruGen::Gen3;
    entry.referenced.store(false, Ordering::Relaxed);
    controller.lru_lists[0].add_page_to_generation(entry, 3);

    let reclaimed = controller.direct_reclaim(1);
    let stats = controller.stats();

    reclaimed == 0
        && stats.total_reclaimed == 0
        && stats.blocked_unsafe == 1
        && stats.requeued == 1
        && stats.lru_stats[0].gen_sizes[1] >= 1
}

pub fn wave7_blocked_unsafe_requeues_anonymous_dirty_victim_smoke() -> bool {
    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let mut entry = MglruEntry::new(FrameIndex::new(124), PageType::Anonymous, 0);
    entry.generation = MglruGen::Gen3;
    entry.flags = LruFlags::DIRTY;
    entry.referenced.store(false, Ordering::Relaxed);
    controller.lru_lists[0].add_page_to_generation(entry, 3);

    let reclaimed = controller.direct_reclaim(1);
    let stats = controller.stats();

    reclaimed == 0
        && stats.total_reclaimed == 0
        && stats.blocked_unsafe == 1
        && stats.requeued == 1
        && stats.lru_stats[0].gen_sizes[1] >= 1
}

pub fn wave7_file_backed_clean_reclaims_with_unsafe_disabled_smoke() -> bool {
    let Some(frame) = crate::mm::alloc_frame() else {
        return true;
    };
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

    let controller = PageReclaimController::new();
    controller.set_unsafe_eviction_enabled(false);

    let mut entry = MglruEntry::new(frame_idx, PageType::FileBacked, 0);
    entry.generation = MglruGen::Gen3;
    entry.referenced.store(false, Ordering::Relaxed);
    controller.lru_lists[0].add_page_to_generation(entry, 3);

    let reclaimed = controller.direct_reclaim(1);
    let stats = controller.stats();
    let ok = reclaimed == 1
        && stats.total_reclaimed == 1
        && stats.blocked_unsafe == 0
        && stats.lru_stats[0].reclaimed == 1
        && !crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize());

    if !ok {
        cleanup_frame_if_allocated(frame_idx);
    }

    ok
}

pub fn wave7_async_success_clears_pending_and_accounts_success_smoke() -> bool {
    let controller = PageReclaimController::new();
    let entry = MglruEntry::new(FrameIndex::new(200), PageType::FileBacked, 0);
    controller.enqueue_pending_async(&entry, 2);

    if controller.stats().pending_async != 1 {
        return false;
    }

    controller.on_async_swapout_complete(entry.frame, true);
    let stats = controller.stats();
    stats.pending_async == 0
        && stats.async_success == 1
        && stats.total_reclaimed == 1
        && stats.lru_stats[2].reclaimed == 1
}

pub fn wave7_async_failure_requeues_and_clears_pending_smoke() -> bool {
    let controller = PageReclaimController::new();
    let entry = MglruEntry::new(FrameIndex::new(201), PageType::FileBacked, 0);
    controller.enqueue_pending_async(&entry, 3);
    controller.on_async_swapout_complete(entry.frame, false);

    let after = controller.stats();
    if after.pending_async != 0
        || after.async_fail != 1
        || after.requeued != 1
        || after.lru_stats[3].gen_sizes[1] < 1
    {
        return false;
    }

    controller.on_async_swapout_complete(entry.frame, false);
    let after_duplicate = controller.stats();
    after_duplicate.pending_async == after.pending_async
        && after_duplicate.async_fail == after.async_fail
        && after_duplicate.requeued == after.requeued
        && after_duplicate.total_reclaimed == after.total_reclaimed
}
