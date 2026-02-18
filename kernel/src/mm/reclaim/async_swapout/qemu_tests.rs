use super::*;

const BUFFER_POOL_4K_DEFAULT_CAPACITY: usize = 128;
const BUFFER_POOL_2M_DEFAULT_CAPACITY: usize = 16;

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
    crate::mm::meta::page_flags::clear_flag(frame_idx, crate::mm::meta::page_flags::PageMetaFlags::SwapPending);

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
