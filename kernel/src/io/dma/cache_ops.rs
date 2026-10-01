use super::*;

// ============================================================================
// Cache Range Operations
// ============================================================================

/// 指定範囲のキャッシュをフラッシュ（DMA転送開始前 CPU→デバイス）
pub fn flush_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while current < end {
        flush_line(current as *const u8);
        current += CACHE_LINE_SIZE;
    }
    // CLFLUSH は MFENCE が必要、CLFLUSHOPT は SFENCE で十分だが
    // 互換性のため MFENCE を使用
    mfence();
}

/// 指定範囲のキャッシュを無効化（DMA転送完了後 デバイス→CPU）
pub fn invalidate_cache_range(addr: *const u8, size: usize) {
    flush_cache_range(addr, size);
    lfence();
}

/// 指定範囲のキャッシュを書き戻し（永続メモリ用、無効化なし）
pub fn writeback_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while current < end {
        // CLWBがサポートされていればCLWB、なければCLFLUSHOPT/CLFLUSHにフォールバック
        if SUPPORTS_CLWB.load(Ordering::Relaxed) {
            clwb(current as *const u8);
        } else {
            flush_line(current as *const u8);
        }
        current += CACHE_LINE_SIZE;
    }
    mfence();
}

