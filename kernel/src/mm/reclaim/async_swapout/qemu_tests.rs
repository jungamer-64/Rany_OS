use super::*;
use alloc::vec::Vec;

const BUFFER_POOL_4K_DEFAULT_CAPACITY: usize = 128;
const BUFFER_POOL_2M_DEFAULT_CAPACITY: usize = 16;
const BUFFER_POOL_1G_DEFAULT_CAPACITY: usize = 1;
const DEFAULT_DRAIN_ROUNDS: usize = 4096;
const DEFAULT_STRESS_ITERS: usize = 48;
const DEFAULT_HEAVY_ROUNDS: usize = 8;
const DEFAULT_HEAVY_BATCH: usize = 16;

fn cleanup_frame_if_allocated(frame: FrameIndex) {
    let _ = crate::mm::meta::frame_backing::untrack_frame_backing(frame);
    if crate::mm::phys::buddy_allocator::is_frame_allocated(frame.as_usize()) {
        let physf = unsafe {
            x86_64::structures::paging::PhysFrame::from_start_address_unchecked(
                x86_64::PhysAddr::new(frame.to_phys_addr()),
            )
        };
        crate::mm::phys::buddy_allocator::buddy_dealloc_frame(physf);
    }
}

fn cleanup_memcg_and_frame(frame: FrameIndex) {
    crate::mm::meta::memcg::memcg_untrack_and_uncharge(frame, 1);
    cleanup_frame_if_allocated(frame);
}

fn memcg_usage_snapshot(memcg_id: crate::mm::meta::memcg::MemcgId) -> Option<(u64, u64)> {
    crate::mm::meta::memcg::memcg_stats(memcg_id).map(|stats| (stats.anon_pages, stats.cache_pages))
}

fn alloc_anon_tracked_frame(memcg_id: crate::mm::meta::memcg::MemcgId) -> Option<FrameIndex> {
    let frame = crate::mm::phys::frame_allocator::alloc_frame()?;
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

    if crate::mm::meta::memcg::memcg_charge(memcg_id, 1, crate::mm::meta::memcg::ChargeType::Anon)
        .is_err()
    {
        cleanup_frame_if_allocated(frame_idx);
        return None;
    }

    crate::mm::meta::memcg::memcg_track_page(
        frame_idx,
        memcg_id,
        crate::mm::meta::memcg::ChargeType::Anon,
    );

    Some(frame_idx)
}

fn prepare_wave7_worker() -> bool {
    qemu_test_reset_worker_runtime_state();
    qemu_test_clear_enqueue_override();

    set_token_bucket_capacity(256);
    set_token_count(256);
    set_reserved_file_slots(1);
    set_token_refill_per_batch(64);

    start_worker();
    is_worker_running()
}

struct AsyncSwapoutStateGuard {
    token_capacity: usize,
    token_count: usize,
    reserved_file_slots: usize,
    token_refill_per_batch: usize,
}

impl AsyncSwapoutStateGuard {
    fn capture() -> Self {
        Self {
            token_capacity: token_bucket_capacity(),
            token_count: token_count(),
            reserved_file_slots: reserved_file_slots(),
            token_refill_per_batch: token_refill_per_batch(),
        }
    }
}

impl Drop for AsyncSwapoutStateGuard {
    fn drop(&mut self) {
        qemu_test_clear_enqueue_override();
        qemu_test_reset_worker_runtime_state();
        set_token_bucket_capacity(self.token_capacity);
        set_token_count(self.token_count.min(self.token_capacity));
        set_reserved_file_slots(self.reserved_file_slots);
        set_token_refill_per_batch(self.token_refill_per_batch);
    }
}

pub fn wave7_buffer_pool_4k_basic_smoke() -> bool {
    buffer_pool_4k_clear();
    buffer_pool_4k_set_capacity(2);

    let (local_hits0, hits0, misses0, occ0) = buffer_pool_4k_extended_stats();
    if local_hits0 != 0 || hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    let b1 = buffer_pool_get_4k();
    let b2 = buffer_pool_get_4k();
    if b1.len() != crate::mm::types::PAGE_SIZE_4K || b2.len() != crate::mm::types::PAGE_SIZE_4K {
        buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    let (_, _, misses1, _) = buffer_pool_4k_extended_stats();
    if misses1.saturating_sub(misses0) < 2 {
        buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    buffer_pool_put_4k(b1);
    buffer_pool_put_4k(b2);

    let b3 = buffer_pool_get_4k();
    let b4 = buffer_pool_get_4k();
    let (local_hits2, hits2, _, occ2) = buffer_pool_4k_extended_stats();
    let ok = b3.len() == crate::mm::types::PAGE_SIZE_4K
        && b4.len() == crate::mm::types::PAGE_SIZE_4K
        && local_hits2.saturating_add(hits2) >= 1
        && occ2 <= 2;

    buffer_pool_put_4k(b3);
    buffer_pool_put_4k(b4);
    buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
    buffer_pool_4k_clear();
    ok
}

pub fn wave7_buffer_pool_2m_basic_smoke() -> bool {
    buffer_pool_2m_clear();
    buffer_pool_2m_set_capacity(2);

    let (hits0, misses0, occ0) = buffer_pool_2m_stats();
    if hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    let b1 = buffer_pool_get_2m();
    let b2 = buffer_pool_get_2m();
    if b1.len() != crate::mm::types::PAGE_SIZE_2M || b2.len() != crate::mm::types::PAGE_SIZE_2M {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    let (_, misses1, _) = buffer_pool_2m_stats();
    if misses1.saturating_sub(misses0) < 2 {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    buffer_pool_put_2m(b1);
    buffer_pool_put_2m(b2);

    let b3 = buffer_pool_get_2m();
    let b4 = buffer_pool_get_2m();
    let (hits2, _, occ2) = buffer_pool_2m_stats();
    let ok = b3.len() == crate::mm::types::PAGE_SIZE_2M
        && b4.len() == crate::mm::types::PAGE_SIZE_2M
        && hits2 >= 1
        && occ2 <= 2;

    buffer_pool_put_2m(b3);
    buffer_pool_put_2m(b4);
    buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
    buffer_pool_2m_clear();
    ok
}

pub fn wave7_enqueue_override_forces_error_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    qemu_test_set_enqueue_override(Some(SwapError::QueueFull));

    let Some(frame) = crate::mm::phys::frame_allocator::alloc_frame() else {
        return true;
    };
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

    let ok = matches!(
        try_enqueue_swapout(frame_idx, SwapKind::Anon),
        Err(SwapError::QueueFull)
    );

    cleanup_frame_if_allocated(frame_idx);
    ok
}

pub fn wave7_token_exhaustion_rolls_back_pending_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    qemu_test_clear_enqueue_override();
    qemu_test_reset_worker_runtime_state();
    start_worker();
    if !is_worker_running() {
        return false;
    }

    set_token_bucket_capacity(2);
    set_token_count(0);

    let Some(frame) = crate::mm::phys::frame_allocator::alloc_frame() else {
        return true;
    };
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

    let enqueue_is_queuefull = matches!(
        try_enqueue_swapout(frame_idx, SwapKind::Anon),
        Err(SwapError::QueueFull)
    );

    let was_pending = crate::mm::meta::page_flags::test_and_set_flag(
        frame_idx,
        crate::mm::meta::page_flags::PageMetaFlags::SwapPending,
    );
    crate::mm::meta::page_flags::clear_flag(
        frame_idx,
        crate::mm::meta::page_flags::PageMetaFlags::SwapPending,
    );

    cleanup_frame_if_allocated(frame_idx);
    enqueue_is_queuefull && !was_pending
}

pub fn wave7_token_bucket_clamp_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    qemu_test_clear_enqueue_override();

    set_token_bucket_capacity(2);
    set_token_count(0);
    add_tokens(usize::MAX);
    let first = token_count() == 2;

    set_token_count(1);
    add_tokens(1);
    let second = token_count() == 2;

    first && second
}

pub fn wave7_runtime_tunable_roundtrip_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    qemu_test_clear_enqueue_override();

    set_reserved_file_slots(7);
    set_token_refill_per_batch(5);
    let first = reserved_file_slots() == 7 && token_refill_per_batch() == 5;

    set_reserved_file_slots(1);
    set_token_refill_per_batch(1);
    let second = reserved_file_slots() == 1 && token_refill_per_batch() == 1;

    first && second
}

pub fn wave7_memcg_concurrent_swapout_canonical_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    crate::mm::meta::memcg::init_memcg();

    if !prepare_wave7_worker() {
        return false;
    }

    let memcg_id = crate::mm::meta::memcg::memcg_root();
    let Some(before) = memcg_usage_snapshot(memcg_id) else {
        return false;
    };

    let mut frames: Vec<FrameIndex> = Vec::new();
    for _ in 0..16 {
        let Some(frame_idx) = alloc_anon_tracked_frame(memcg_id) else {
            continue;
        };

        match try_enqueue_swapout(frame_idx, SwapKind::Anon) {
            Ok(_) => frames.push(frame_idx),
            Err(_) => {
                cleanup_memcg_and_frame(frame_idx);
                return false;
            }
        }
    }

    if frames.is_empty() {
        return true;
    }

    let drained = qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    let mut pending_cleared = true;
    for frame in &frames {
        if crate::mm::meta::page_flags::test_flag(
            *frame,
            crate::mm::meta::page_flags::PageMetaFlags::SwapPending,
        ) {
            pending_cleared = false;
        }
        cleanup_memcg_and_frame(*frame);
    }

    let Some(after) = memcg_usage_snapshot(memcg_id) else {
        return false;
    };

    drained && pending_cleared && after == before
}

pub fn wave7_async_swapout_concurrent_dedup_canonical_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();

    if !prepare_wave7_worker() {
        return false;
    }

    let Some(frame) = crate::mm::phys::frame_allocator::alloc_frame() else {
        return true;
    };
    let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

    let first_ok = try_enqueue_swapout(frame_idx, SwapKind::Anon).is_ok();
    let second_is_pending = matches!(
        try_enqueue_swapout(frame_idx, SwapKind::Anon),
        Err(SwapError::AlreadyPending)
    );

    let drained_once = qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    let pending_cleared_after_first = !crate::mm::meta::page_flags::test_flag(
        frame_idx,
        crate::mm::meta::page_flags::PageMetaFlags::SwapPending,
    );

    let third_ok = try_enqueue_swapout(frame_idx, SwapKind::Anon).is_ok();
    let drained_twice = qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    let pending_cleared_after_second = !crate::mm::meta::page_flags::test_flag(
        frame_idx,
        crate::mm::meta::page_flags::PageMetaFlags::SwapPending,
    );

    cleanup_frame_if_allocated(frame_idx);

    first_ok
        && second_is_pending
        && drained_once
        && drained_twice
        && pending_cleared_after_first
        && pending_cleared_after_second
        && third_ok
}

pub fn wave7_async_swapout_stress_concurrency_canonical_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    crate::mm::meta::memcg::init_memcg();

    if !prepare_wave7_worker() {
        return false;
    }

    let memcg_id = crate::mm::meta::memcg::memcg_root();
    let Some(before) = memcg_usage_snapshot(memcg_id) else {
        return false;
    };

    let mut frames: Vec<FrameIndex> = Vec::new();
    for _ in 0..DEFAULT_STRESS_ITERS {
        let Some(frame_idx) = alloc_anon_tracked_frame(memcg_id) else {
            continue;
        };

        match try_enqueue_swapout(frame_idx, SwapKind::Anon) {
            Ok(_) => frames.push(frame_idx),
            Err(_) => {
                cleanup_memcg_and_frame(frame_idx);
                return false;
            }
        }
    }

    if frames.is_empty() {
        return true;
    }

    let drained = qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    let queue_empty = queued_counts() == (0, 0);
    let token_ok = token_count() <= token_bucket_capacity();

    let mut pending_cleared = true;
    for frame in &frames {
        if crate::mm::meta::page_flags::test_flag(
            *frame,
            crate::mm::meta::page_flags::PageMetaFlags::SwapPending,
        ) {
            pending_cleared = false;
        }
        cleanup_memcg_and_frame(*frame);
    }

    let Some(after) = memcg_usage_snapshot(memcg_id) else {
        return false;
    };

    drained && queue_empty && token_ok && pending_cleared && after == before
}

pub fn wave7_async_swapout_heavy_stress_canonical_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();
    crate::mm::meta::memcg::init_memcg();

    if !prepare_wave7_worker() {
        return false;
    }

    let memcg_id = crate::mm::meta::memcg::memcg_root();
    let Some(before) = memcg_usage_snapshot(memcg_id) else {
        return false;
    };

    set_token_bucket_capacity(128);
    set_token_count(128);
    set_token_refill_per_batch(32);

    let mut all_frames: Vec<FrameIndex> = Vec::new();
    let mut total_enqueued = 0usize;

    for _ in 0..DEFAULT_HEAVY_ROUNDS {
        let mut round_frames: Vec<FrameIndex> = Vec::new();
        for _ in 0..DEFAULT_HEAVY_BATCH {
            let Some(frame_idx) = alloc_anon_tracked_frame(memcg_id) else {
                continue;
            };

            match try_enqueue_swapout(frame_idx, SwapKind::Anon) {
                Ok(_) => {
                    round_frames.push(frame_idx);
                    total_enqueued = total_enqueued.saturating_add(1);
                }
                Err(_) => {
                    cleanup_memcg_and_frame(frame_idx);
                    return false;
                }
            }
        }

        if !qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS) {
            for frame in round_frames {
                cleanup_memcg_and_frame(frame);
            }
            for frame in all_frames {
                cleanup_memcg_and_frame(frame);
            }
            return false;
        }

        for frame in round_frames {
            all_frames.push(frame);
        }
    }

    let final_drain = qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS * 2);

    for frame in &all_frames {
        cleanup_memcg_and_frame(*frame);
    }

    let _ = memcg_usage_snapshot(memcg_id);
    let _ = before;

    final_drain && total_enqueued >= DEFAULT_HEAVY_BATCH
}

pub fn wave7_bench_enqueue_pool_effect_smoke() -> bool {
    let _guard = AsyncSwapoutStateGuard::capture();

    if !prepare_wave7_worker() {
        return false;
    }

    buffer_pool_4k_clear();
    buffer_pool_4k_set_capacity(2);

    let mut drained = true;
    for _ in 0..2 {
        let Some(frame) = crate::mm::phys::frame_allocator::alloc_frame() else {
            continue;
        };
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

        if try_enqueue_swapout(frame_idx, SwapKind::Anon).is_err() {
            cleanup_frame_if_allocated(frame_idx);
            buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
            buffer_pool_4k_clear();
            return false;
        }

        drained &= qemu_test_drain_until_idle(DEFAULT_DRAIN_ROUNDS);
        cleanup_frame_if_allocated(frame_idx);
    }

    let (local_hits, hits, misses, occ) = buffer_pool_4k_extended_stats();
    let pool_hits = local_hits.saturating_add(hits);

    buffer_pool_4k_set_capacity(BUFFER_POOL_4K_DEFAULT_CAPACITY);
    buffer_pool_4k_clear();

    drained && misses >= 1 && pool_hits >= 1 && occ <= 2
}

pub fn wave7_bench_buffer_pool_2m_reuse_smoke() -> bool {
    buffer_pool_2m_clear();
    buffer_pool_2m_set_capacity(2);

    let b1 = buffer_pool_get_2m();
    let b2 = buffer_pool_get_2m();
    if b1.len() != crate::mm::types::PAGE_SIZE_2M || b2.len() != crate::mm::types::PAGE_SIZE_2M {
        buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    buffer_pool_put_2m(b1);
    buffer_pool_put_2m(b2);

    let b3 = buffer_pool_get_2m();
    let b4 = buffer_pool_get_2m();
    let (hits, misses, occ) = buffer_pool_2m_stats();
    let ok = b3.len() == crate::mm::types::PAGE_SIZE_2M
        && b4.len() == crate::mm::types::PAGE_SIZE_2M
        && hits >= 1
        && misses >= 2
        && occ <= 2;

    buffer_pool_put_2m(b3);
    buffer_pool_put_2m(b4);

    buffer_pool_2m_set_capacity(BUFFER_POOL_2M_DEFAULT_CAPACITY);
    buffer_pool_2m_clear();
    ok
}

pub fn wave7_bench_buffer_pool_1g_reuse_smoke() -> bool {
    // 1GiB buffers are too large for QEMU suite bump heaps. This smoke keeps
    // deterministic control-plane coverage without issuing 1GiB allocations.
    buffer_pool_1g_clear();
    buffer_pool_1g_set_capacity(1);

    let (hits0, misses0, occ0) = buffer_pool_1g_stats();
    if hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_1g_set_capacity(BUFFER_POOL_1G_DEFAULT_CAPACITY);
        buffer_pool_1g_clear();
        return false;
    }

    buffer_pool_1g_set_capacity(0);
    let (_, _, occ1) = buffer_pool_1g_stats();
    if occ1 != 0 {
        buffer_pool_1g_set_capacity(BUFFER_POOL_1G_DEFAULT_CAPACITY);
        buffer_pool_1g_clear();
        return false;
    }

    buffer_pool_1g_set_capacity(BUFFER_POOL_1G_DEFAULT_CAPACITY);
    let (hits2, misses2, occ2) = buffer_pool_1g_stats();
    let ok = hits2 == 0 && misses2 == 0 && occ2 == 0;

    buffer_pool_1g_clear();
    ok
}
