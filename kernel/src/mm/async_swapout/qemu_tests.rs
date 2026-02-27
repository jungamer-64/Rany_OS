use super::*;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::PhysFrame;

const DEFAULT_4K_CAPACITY: usize = 128;
const DEFAULT_2M_CAPACITY: usize = 16;
const DEFAULT_1G_CAPACITY: usize = 1;
const DEFAULT_DRAIN_ROUNDS: usize = 256;
const WAVE7_QEMU_FAKE_REGION_BASE: u64 = 0x2000_0000;
const WAVE7_QEMU_FAKE_REGION_SIZE: u64 = 64 * 1024 * 1024;
const WAVE7_QEMU_PAGE_FLAGS_FRAMES: usize = 262_144;

static WAVE7_QEMU_PAGE_FLAGS_READY: AtomicBool = AtomicBool::new(false);

fn prepare_qemu_mm_backing() {
    unsafe {
        crate::mm::init_buddy_allocator(&[(
            PhysAddr::new(WAVE7_QEMU_FAKE_REGION_BASE),
            WAVE7_QEMU_FAKE_REGION_SIZE,
        )]);
    }

    if !WAVE7_QEMU_PAGE_FLAGS_READY.swap(true, Ordering::AcqRel) {
        unsafe {
            crate::mm::page_flags::init_page_flags(WAVE7_QEMU_PAGE_FLAGS_FRAMES);
        }
    }

    crate::mm::zswap::zswap_set_enabled(false);
}

fn cleanup_frame(frame: FrameIndex) {
    crate::mm::memcg::memcg_untrack_and_uncharge(frame, 1);
    let _ = crate::mm::frame_backing::untrack_frame_backing(frame);
    if crate::mm::buddy_allocator::is_frame_allocated(frame.as_usize()) {
        let physf =
            unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(frame.to_phys_addr())) };
        crate::mm::buddy_allocator::buddy_dealloc_frame(physf);
    }
    crate::mm::page_flags::clear_flag(frame, crate::mm::page_flags::PageMetaFlags::SwapPending);
}

fn cleanup_frames(frames: &[FrameIndex]) {
    for frame in frames {
        cleanup_frame(*frame);
    }
}

fn alloc_frame_index_from_allocators() -> Option<FrameIndex> {
    if let Some(frame) = crate::mm::alloc_frame() {
        return Some(FrameIndex::from_phys_addr(frame.start_address().as_u64()));
    }

    let frame = crate::mm::buddy_alloc_frame()?;
    Some(FrameIndex::from_phys_addr(frame.start_address().as_u64()))
}

fn alloc_frame_index() -> Option<FrameIndex> {
    if let Some(frame) = alloc_frame_index_from_allocators() {
        return Some(frame);
    }

    for (drain_rounds, reclaim_pages) in [
        (DEFAULT_DRAIN_ROUNDS / 4, 32usize),
        (DEFAULT_DRAIN_ROUNDS / 2, 128usize),
        (DEFAULT_DRAIN_ROUNDS, 256usize),
        (DEFAULT_DRAIN_ROUNDS * 2, 512usize),
    ] {
        let _ = qemu_test_drain_until_idle(drain_rounds);
        let _ = crate::mm::try_to_free_pages(reclaim_pages);
        if let Some(frame) = alloc_frame_index_from_allocators() {
            return Some(frame);
        }
    }

    None
}

fn prepare_runtime_for_wave7() {
    prepare_qemu_mm_backing();
    crate::fs::init_page_cache(64 * 1024);
    stop_worker();
    qemu_test_reset_worker_runtime_state();
    let _ = crate::mm::try_to_free_pages(256);
    set_reserved_file_slots(128);
    set_token_bucket_capacity(256);
    set_token_count(token_bucket_capacity());
}

fn restore_runtime_after_wave7() {
    stop_worker();
    qemu_test_reset_worker_runtime_state();
    set_reserved_file_slots(128);
    set_token_bucket_capacity(256);
    set_token_count(token_bucket_capacity());
    crate::mm::zswap::zswap_set_enabled(true);
}

fn enqueue_file(frame: FrameIndex, ino: u64, page_num: u64) -> Result<(), SwapError> {
    let cache = crate::fs::page_cache();
    let data = alloc::vec![0u8; crate::mm::PAGE_SIZE_4K];
    cache.insert(ino, page_num, data, crate::mm::PAGE_SIZE_4K as u64);
    if !cache.mark_dirty(ino, page_num) {
        return Err(SwapError::NotSupported);
    }
    crate::mm::frame_backing::track_frame_backing(frame, ino, page_num);
    try_enqueue_swapout(frame, SwapKind::File { ino, page_num }).map(|_| ())
}

fn enqueue_anon(frame: FrameIndex) -> Result<(), SwapError> {
    try_enqueue_swapout(frame, SwapKind::Anon).map(|_| ())
}

fn enqueue_file_with_retry(
    frame: FrameIndex,
    ino: u64,
    page_num: u64,
    retries: usize,
    drain_rounds: usize,
) -> Result<(), SwapError> {
    let mut attempts = 0usize;
    loop {
        match enqueue_file(frame, ino, page_num) {
            Ok(()) => return Ok(()),
            Err(SwapError::QueueFull) if attempts < retries => {
                if !drain_until_idle(drain_rounds) {
                    return Err(SwapError::QueueFull);
                }
                attempts += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

fn enqueue_anon_with_retry(
    frame: FrameIndex,
    retries: usize,
    drain_rounds: usize,
) -> Result<(), SwapError> {
    let mut attempts = 0usize;
    loop {
        match enqueue_anon(frame) {
            Ok(()) => return Ok(()),
            Err(SwapError::QueueFull) if attempts < retries => {
                if !drain_until_idle(drain_rounds) {
                    return Err(SwapError::QueueFull);
                }
                attempts += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

fn drain_until_idle(rounds: usize) -> bool {
    qemu_test_drain_until_idle(rounds) && queued_counts().0 == 0
}

fn memcg_zero(id: crate::mm::memcg::MemcgId) -> bool {
    if let Some(stats) = crate::mm::memcg::memcg_stats(id) {
        stats.cache_pages == 0 && stats.anon_pages == 0
    } else {
        false
    }
}

pub fn wave7_buffer_pool_4k_basic_smoke() -> bool {
    buffer_pool_4k_clear();
    buffer_pool_4k_set_capacity(2);

    let (local_hits0, hits0, misses0, occ0) = buffer_pool_4k_extended_stats();
    if local_hits0 != 0 || hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_4k_set_capacity(DEFAULT_4K_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    let b1 = buffer_pool_get_4k();
    let b2 = buffer_pool_get_4k();
    if b1.len() != crate::mm::PAGE_SIZE_4K || b2.len() != crate::mm::PAGE_SIZE_4K {
        buffer_pool_4k_set_capacity(DEFAULT_4K_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    let (_, _, misses1, _) = buffer_pool_4k_extended_stats();
    if misses1.saturating_sub(misses0) < 2 {
        buffer_pool_4k_set_capacity(DEFAULT_4K_CAPACITY);
        buffer_pool_4k_clear();
        return false;
    }

    buffer_pool_put_4k(b1);
    buffer_pool_put_4k(b2);

    let b3 = buffer_pool_get_4k();
    let b4 = buffer_pool_get_4k();
    let (local_hits2, hits2, _, occ2) = buffer_pool_4k_extended_stats();
    let ok = b3.len() == crate::mm::PAGE_SIZE_4K
        && b4.len() == crate::mm::PAGE_SIZE_4K
        && local_hits2.saturating_add(hits2) >= 1
        && occ2 <= 2;

    buffer_pool_put_4k(b3);
    buffer_pool_put_4k(b4);
    buffer_pool_4k_set_capacity(DEFAULT_4K_CAPACITY);
    buffer_pool_4k_clear();
    ok
}

pub fn wave7_buffer_pool_2m_basic_smoke() -> bool {
    buffer_pool_2m_clear();
    buffer_pool_2m_set_capacity(2);

    let (hits0, misses0, occ0) = buffer_pool_2m_stats();
    if hits0 != 0 || misses0 != 0 || occ0 != 0 {
        buffer_pool_2m_set_capacity(DEFAULT_2M_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    let b1 = buffer_pool_get_2m();
    let b2 = buffer_pool_get_2m();
    if b1.len() != crate::mm::PAGE_SIZE_2M as usize || b2.len() != crate::mm::PAGE_SIZE_2M as usize
    {
        buffer_pool_2m_set_capacity(DEFAULT_2M_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    let (_, misses1, _) = buffer_pool_2m_stats();
    if misses1.saturating_sub(misses0) < 2 {
        buffer_pool_2m_set_capacity(DEFAULT_2M_CAPACITY);
        buffer_pool_2m_clear();
        return false;
    }

    buffer_pool_put_2m(b1);
    buffer_pool_put_2m(b2);

    let b3 = buffer_pool_get_2m();
    let b4 = buffer_pool_get_2m();
    let (hits2, _, occ2) = buffer_pool_2m_stats();
    let ok = b3.len() == crate::mm::PAGE_SIZE_2M as usize
        && b4.len() == crate::mm::PAGE_SIZE_2M as usize
        && hits2 >= 1
        && occ2 <= 2;

    buffer_pool_put_2m(b3);
    buffer_pool_put_2m(b4);
    buffer_pool_2m_set_capacity(DEFAULT_2M_CAPACITY);
    buffer_pool_2m_clear();
    ok
}

pub fn wave7_memcg_concurrent_swapout_canonical_smoke() -> bool {
    crate::mm::memcg::init_memcg();
    let cg = match crate::mm::memcg::memcg_create(
        String::from("wave7_memcg_qemu"),
        crate::mm::memcg::memcg_root(),
    ) {
        Ok(cg) => cg,
        Err(_) => return false,
    };

    prepare_runtime_for_wave7();

    let mut ok = true;
    let mut frames: Vec<FrameIndex> = Vec::with_capacity(2);
    let mut successful_enqueues = 0usize;
    let mut file_attempts = 0usize;
    let mut anon_attempts = 0usize;
    let mut file_successes = 0usize;
    let mut anon_successes = 0usize;

    for i in 0..2usize {
        let Some(frame) = alloc_frame_index() else {
            crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: alloc_frame failed\n");
            ok = false;
            break;
        };
        frames.push(frame);

        let (charge_type, enqueue_result, is_file) = if i % 2 == 0 {
            let charge_type = crate::mm::memcg::ChargeType::Cache;
            file_attempts += 1;
            if crate::mm::memcg::memcg_charge(cg, 1, charge_type).is_err() {
                crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: cache charge failed\n");
                ok = false;
                break;
            }
            crate::mm::memcg::memcg_track_page(frame, cg, charge_type);
            (
                charge_type,
                enqueue_file_with_retry(
                    frame,
                    9100 + (i as u64 % 4),
                    i as u64,
                    2,
                    DEFAULT_DRAIN_ROUNDS / 2,
                ),
                true,
            )
        } else {
            let charge_type = crate::mm::memcg::ChargeType::Anon;
            anon_attempts += 1;
            if crate::mm::memcg::memcg_charge(cg, 1, charge_type).is_err() {
                crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: anon charge failed\n");
                ok = false;
                break;
            }
            crate::mm::memcg::memcg_track_page(frame, cg, charge_type);
            (
                charge_type,
                enqueue_anon_with_retry(frame, 2, DEFAULT_DRAIN_ROUNDS / 2),
                false,
            )
        };

        match enqueue_result {
            Ok(()) => {
                successful_enqueues += 1;
                if is_file {
                    file_successes += 1;
                } else {
                    anon_successes += 1;
                }
            }
            Err(SwapError::QueueFull) => {
                if !drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2) {
                    crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: drain after queue full failed\n");
                    ok = false;
                }
            }
            Err(err) => {
                let _ = (charge_type, err);
                crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: enqueue failed\n");
                ok = false;
            }
        }

        if i % 2 == 1 && !drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2) {
            crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: periodic drain failed\n");
            ok = false;
        }
    }


    if file_attempts == 0 || anon_attempts == 0 {
        crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: mixed workload not exercised\n");
        ok = false;
    }
    if successful_enqueues < 2 || file_successes == 0 || anon_successes == 0 {
        crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: insufficient enqueue coverage\n");
        ok = false;
    }
    if !drain_until_idle(DEFAULT_DRAIN_ROUNDS) {
        crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: final drain failed\n");
        ok = false;
    }
    if queued_counts().0 != 0 {
        crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: queue not empty\n");
        ok = false;
    }

    cleanup_frames(&frames);

    for frame in &frames {
        if crate::mm::memcg::memcg_get_page_info(*frame).is_some() {
            crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: page info remained\n");
            ok = false;
            break;
        }
    }

    if !memcg_zero(cg) {
        crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: memcg stats not zero\n");
        ok = false;
    }

    qemu_test_reset_worker_runtime_state();
    restore_runtime_after_wave7();

    if crate::mm::memcg::memcg_remove(cg).is_err() {
        crate::io::log::early_print("[qemu-suite] mm_wave7_memcg: memcg_remove failed\n");
        ok = false;
    }

    ok
}

pub fn wave7_async_swapout_concurrent_dedup_canonical_smoke() -> bool {
    prepare_runtime_for_wave7();
    qemu_test_reset_worker_runtime_state();

    let mut ok = true;
    let frame = match alloc_frame_index() {
        Some(frame) => frame,
        None => {
            qemu_test_reset_worker_runtime_state();
            restore_runtime_after_wave7();
            return false;
        }
    };

    let first = try_enqueue_swapout(frame, SwapKind::Anon).map(|_| ());
    let second = try_enqueue_swapout(frame, SwapKind::Anon).map(|_| ());
    ok &= first.is_ok();
    ok &= matches!(second, Err(SwapError::AlreadyPending));

    ok &= drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    ok &= queued_counts().0 == 0;
    ok &= !crate::mm::page_flags::test_flag(frame, crate::mm::page_flags::PageMetaFlags::SwapPending);

    cleanup_frame(frame);
    ok &= crate::mm::memcg::memcg_get_page_info(frame).is_none();

    qemu_test_reset_worker_runtime_state();
    restore_runtime_after_wave7();

    ok
}

pub fn wave7_async_swapout_stress_concurrency_canonical_smoke() -> bool {
    crate::mm::memcg::init_memcg();
    let cg = match crate::mm::memcg::memcg_create(
        String::from("wave7_stress_qemu"),
        crate::mm::memcg::memcg_root(),
    ) {
        Ok(cg) => cg,
        Err(_) => return false,
    };

    prepare_runtime_for_wave7();
    set_reserved_file_slots(64);
    set_token_bucket_capacity(128);
    set_token_count(128);
    qemu_test_reset_worker_runtime_state();

    let mut ok = true;
    let mut frames: Vec<FrameIndex> = Vec::new();
    let mut successful_enqueues = 0usize;

    for i in 0..24usize {
        let Some(frame) = alloc_frame_index() else {
            ok = false;
            break;
        };
        frames.push(frame);

        if i % 2 == 0 {
            if crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_err() {
                ok = false;
                break;
            }
            crate::mm::memcg::memcg_track_page(frame, cg, crate::mm::memcg::ChargeType::Cache);
            match enqueue_file_with_retry(
                frame,
                9300 + (i as u64 % 8),
                i as u64,
                2,
                DEFAULT_DRAIN_ROUNDS / 2,
            ) {
                Ok(()) => successful_enqueues += 1,
                Err(SwapError::QueueFull) => {
                    let _ = drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2);
                }
                Err(_) => ok = false,
            }
        } else {
            if crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_err() {
                ok = false;
                break;
            }
            crate::mm::memcg::memcg_track_page(frame, cg, crate::mm::memcg::ChargeType::Anon);
            match enqueue_anon_with_retry(frame, 2, DEFAULT_DRAIN_ROUNDS / 2) {
                Ok(()) => successful_enqueues += 1,
                Err(SwapError::QueueFull) => {
                    let _ = drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2);
                }
                Err(_) => ok = false,
            }
        }

        if i % 6 == 5 {
            ok &= drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2);
        }
    }


    ok &= successful_enqueues >= 10;
    ok &= drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    ok &= queued_counts().0 == 0;

    cleanup_frames(&frames);
    ok &= memcg_zero(cg);

    qemu_test_reset_worker_runtime_state();
    restore_runtime_after_wave7();
    ok &= crate::mm::memcg::memcg_remove(cg).is_ok();

    ok
}

pub fn wave7_async_swapout_heavy_stress_canonical_smoke() -> bool {
    crate::mm::memcg::init_memcg();
    let cg = match crate::mm::memcg::memcg_create(
        String::from("wave7_heavy_qemu"),
        crate::mm::memcg::memcg_root(),
    ) {
        Ok(cg) => cg,
        Err(_) => return false,
    };

    prepare_runtime_for_wave7();
    set_token_bucket_capacity(16);
    set_token_count(16);
    set_reserved_file_slots(16);
    qemu_test_reset_worker_runtime_state();

    let mut ok = true;
    let mut frames: Vec<FrameIndex> = Vec::new();
    let mut successful_enqueues = 0usize;

    for i in 0..40usize {
        let Some(frame) = alloc_frame_index() else {
            ok = false;
            break;
        };
        frames.push(frame);

        if i % 2 == 0 {
            if crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_err() {
                ok = false;
                break;
            }
            crate::mm::memcg::memcg_track_page(frame, cg, crate::mm::memcg::ChargeType::Cache);
            match enqueue_file_with_retry(
                frame,
                9400 + (i as u64 % 16),
                i as u64,
                3,
                DEFAULT_DRAIN_ROUNDS / 2,
            ) {
                Ok(()) => successful_enqueues += 1,
                Err(SwapError::QueueFull) => {
                    let _ = drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2);
                }
                Err(_) => ok = false,
            }
        } else {
            if crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_err() {
                ok = false;
                break;
            }
            crate::mm::memcg::memcg_track_page(frame, cg, crate::mm::memcg::ChargeType::Anon);
            match enqueue_anon_with_retry(frame, 3, DEFAULT_DRAIN_ROUNDS / 2) {
                Ok(()) => successful_enqueues += 1,
                Err(SwapError::QueueFull) => {
                    let _ = drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2);
                }
                Err(_) => ok = false,
            }
        }

        if i % 8 == 7 {
            ok &= drain_until_idle(DEFAULT_DRAIN_ROUNDS / 2);
        }
    }


    ok &= successful_enqueues >= 16;
    ok &= drain_until_idle(DEFAULT_DRAIN_ROUNDS);
    ok &= queued_counts().0 == 0;
    ok &= token_count() <= token_bucket_capacity();

    cleanup_frames(&frames);
    ok &= memcg_zero(cg);

    qemu_test_reset_worker_runtime_state();
    restore_runtime_after_wave7();
    ok &= crate::mm::memcg::memcg_remove(cg).is_ok();

    ok
}

pub fn wave7_bench_enqueue_pool_effect_smoke() -> bool {
    buffer_pool_4k_clear();
    buffer_pool_4k_set_capacity(0);

    let (lh0, gh0, m0, _o0) = buffer_pool_4k_extended_stats();

    for _ in 0..8 {
        let b = buffer_pool_get_4k();
        buffer_pool_put_4k(b);
    }

    let (lh1, gh1, m1, _o1) = buffer_pool_4k_extended_stats();

    buffer_pool_4k_set_capacity(32);

    // Warmup for pool-backed reuse
    for _ in 0..8 {
        let b = buffer_pool_get_4k();
        buffer_pool_put_4k(b);
    }
    // Measured phase
    for _ in 0..8 {
        let b = buffer_pool_get_4k();
        buffer_pool_put_4k(b);
    }

    let (lh2, gh2, m2, occ2) = buffer_pool_4k_extended_stats();

    let no_pool_miss_delta = m1.saturating_sub(m0);
    let no_pool_hits_total = lh1
        .saturating_add(gh1)
        .saturating_sub(lh0.saturating_add(gh0));
    let pool_hit_delta = lh2
        .saturating_add(gh2)
        .saturating_sub(lh1.saturating_add(gh1));
    let pool_miss_delta = m2.saturating_sub(m1);

    buffer_pool_4k_set_capacity(DEFAULT_4K_CAPACITY);
    buffer_pool_4k_clear();

    no_pool_miss_delta >= 1
        && pool_hit_delta >= 1
        && pool_miss_delta <= 8
        && occ2 <= 32
        && no_pool_hits_total <= 8
}

pub fn wave7_bench_buffer_pool_2m_reuse_smoke() -> bool {
    buffer_pool_2m_clear();
    buffer_pool_2m_set_capacity(4);

    let b = buffer_pool_get_2m();
    buffer_pool_put_2m(b);
    let _ = buffer_pool_get_2m();

    let (hits, misses, occ) = buffer_pool_2m_stats();

    buffer_pool_2m_set_capacity(DEFAULT_2M_CAPACITY);
    buffer_pool_2m_clear();

    hits >= 1 && misses >= 1 && occ <= 4
}

pub fn wave7_bench_buffer_pool_1g_reuse_smoke() -> bool {
    // 1GiB実バッファ確保はQEMU full-boot heap制約に対して過大なため、
    // pending監視では制御面（capacity/stats/reset）の決定性のみを検証する。
    buffer_pool_1g_clear();
    buffer_pool_1g_set_capacity(1);

    let (_, _, occ0) = buffer_pool_1g_stats();

    buffer_pool_1g_set_capacity(0);
    let (_, _, occ1) = buffer_pool_1g_stats();

    buffer_pool_1g_set_capacity(DEFAULT_1G_CAPACITY);
    buffer_pool_1g_clear();

    occ0 == 0 && occ1 == 0
}
