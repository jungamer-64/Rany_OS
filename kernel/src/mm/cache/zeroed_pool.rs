// ============================================================================
// src/mm/zeroed_pool.rs - Pre-zeroed Frame Pool for Idle Zeroing
// 設計書 5.2: PMM改善 - アイドル時のバックグラウンドゼロクリア
//
// ## 概要
//
// ページ割り当て時のゼロクリアはレイテンシを増加させる（数マイクロ秒）。
// CPUがアイドル状態のときに事前にゼロクリアし、「ゼロ済みプール」に
// 蓄えることで、allocate_zeroed のレイテンシを削減する。
//
// ## 設計
//
// - Per-NUMA ノードでプールを管理（ローカルメモリ優先）
// - アイドルタスクまたは低優先度カーネルスレッドがバックグラウンドでゼロクリア
// - プールが枯渇した場合は従来通りオンデマンドでゼロクリア
// ============================================================================
#![allow(dead_code)]

use crate::mm::types::NumaNodeId;
use crate::sync::IrqMutex;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

// ============================================================================
// Non-Temporal Zeroing (Cache Pollution Prevention)
// ============================================================================

/// ページを Non-Temporal Store でゼロクリア（AVX2/SSE2）
///
/// キャッシュを汚さずにメモリを初期化する。アイドル時のバックグラウンド
/// ゼロクリアに最適。
///
/// # Safety
/// - `virt_addr` は 4096 バイト以上のアクセス可能なメモリを指すこと
/// - `virt_addr` は 64 バイトアライン推奨（パフォーマンス最適化）
#[inline]
pub unsafe fn zero_page_nontemporal(virt_addr: u64) {
    super::zero_page::clear_page_nt(virt_addr as *mut u8);
}

/// ページを標準的な方法でゼロクリア（通常のストア命令）
///
/// 即座にゼロクリアされたページを使う場合（ユーザー空間への
/// ページ割り当て直前など）に使用。キャッシュに載るので
/// 直後の読み書きが高速。
#[inline]
pub unsafe fn zero_page_standard(virt_addr: u64) {
    super::zero_page::clear_page_memset(virt_addr as *mut u8);
}

/// Per-NUMAノードのゼロ済みフレームプール容量
const ZEROED_POOL_CAPACITY: usize = 256;

/// プール補充の閾値（この割合を下回ったら補充開始）
const REFILL_THRESHOLD_PERCENT: usize = 25;

/// 一度の補充で処理するフレーム数
const REFILL_BATCH_SIZE: usize = 16;

/// Per-NUMAノードのゼロ済みフレームプール
#[repr(align(64))] // キャッシュラインアライン
pub struct ZeroedFramePool {
    /// ゼロ済みフレームのスタック（物理アドレス）
    frames: [u64; ZEROED_POOL_CAPACITY],
    /// 現在のフレーム数
    count: usize,
    /// このプールのNUMAノードID
    numa_node: usize,
    /// 統計: 補充回数
    refill_count: u64,
    /// 統計: ヒット回数（プールから取得）
    hit_count: u64,
    /// 統計: ミス回数（オンデマンドゼロクリア）
    miss_count: u64,
}

impl ZeroedFramePool {
    /// 空のプールを作成
    pub const fn new(numa_node: usize) -> Self {
        Self {
            frames: [0; ZEROED_POOL_CAPACITY],
            count: 0,
            numa_node,
            refill_count: 0,
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// ゼロ済みフレームを取得
    ///
    /// プールが空の場合はNoneを返す
    #[inline]
    pub fn pop(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.count == 0 {
            self.miss_count += 1;
            return None;
        }

        self.count -= 1;
        let phys_addr = self.frames[self.count];
        self.frames[self.count] = 0;
        self.hit_count += 1;

        Some(PhysFrame::containing_address(PhysAddr::new(phys_addr)))
    }

    /// ゼロ済みフレームをプールに追加
    ///
    /// プールが満杯の場合はfalseを返す
    #[inline]
    pub fn push(&mut self, frame: PhysFrame<Size4KiB>) -> bool {
        if self.count >= ZEROED_POOL_CAPACITY {
            return false;
        }

        self.frames[self.count] = frame.start_address().as_u64();
        self.count += 1;
        true
    }

    /// プールが補充を必要としているかチェック
    #[inline]
    pub fn needs_refill(&self) -> bool {
        self.count * 100 / ZEROED_POOL_CAPACITY < REFILL_THRESHOLD_PERCENT
    }

    /// 現在のフレーム数を取得
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// プールが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// プールが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= ZEROED_POOL_CAPACITY
    }

    /// 統計情報を取得
    pub fn stats(&self) -> ZeroedPoolStats {
        ZeroedPoolStats {
            capacity: ZEROED_POOL_CAPACITY,
            current_count: self.count,
            numa_node: self.numa_node,
            refill_count: self.refill_count,
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            hit_rate_percent: if self.hit_count + self.miss_count > 0 {
                (self.hit_count * 100) / (self.hit_count + self.miss_count)
            } else {
                0
            },
        }
    }
}

/// ゼロ済みプールの統計情報
#[derive(Debug, Clone, Copy)]
pub struct ZeroedPoolStats {
    pub capacity: usize,
    pub current_count: usize,
    pub numa_node: usize,
    pub refill_count: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub hit_rate_percent: u64,
}

/// 最大NUMAノード数
const MAX_NUMA_NODES: usize = 8;

/// グローバルなゼロ済みプール（Per-NUMAノード）
static ZEROED_POOLS: [IrqMutex<ZeroedFramePool>; MAX_NUMA_NODES] = [
    IrqMutex::new(ZeroedFramePool::new(0)),
    IrqMutex::new(ZeroedFramePool::new(1)),
    IrqMutex::new(ZeroedFramePool::new(2)),
    IrqMutex::new(ZeroedFramePool::new(3)),
    IrqMutex::new(ZeroedFramePool::new(4)),
    IrqMutex::new(ZeroedFramePool::new(5)),
    IrqMutex::new(ZeroedFramePool::new(6)),
    IrqMutex::new(ZeroedFramePool::new(7)),
];

/// バックグラウンドゼロクリアタスクが動作中かどうか
static ZEROING_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// 初期化完了フラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// ゼロ済みプールを初期化
pub fn init() {
    INITIALIZED.store(true, Ordering::Release);
    log::info!(
        "[PMM] Zeroed frame pools initialized ({} per node)",
        ZEROED_POOL_CAPACITY
    );
}

/// ゼロ済みフレームを取得
///
/// 優先ノードから取得を試み、失敗した場合は他ノードにフォールバック
pub fn allocate_zeroed_frame(preferred_node: usize) -> Option<PhysFrame<Size4KiB>> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    // 優先ノードから取得
    if preferred_node < MAX_NUMA_NODES {
        if let Some(frame) = ZEROED_POOLS[preferred_node].lock().pop() {
            return Some(frame);
        }
    }

    // フォールバック: 他のノードから取得
    for node in 0..MAX_NUMA_NODES {
        if node != preferred_node {
            if let Some(frame) = ZEROED_POOLS[node].lock().pop() {
                return Some(frame);
            }
        }
    }

    None
}

/// バックグラウンドでゼロクリアを実行（アイドルタスクから呼び出し）
///
/// # Returns
/// 処理したフレーム数
pub fn idle_zero_frames() -> usize {
    if !INITIALIZED.load(Ordering::Acquire) {
        return 0;
    }

    // 他のタスクがゼロクリア中なら何もしない
    if ZEROING_IN_PROGRESS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return 0;
    }

    let mut total_zeroed = 0;

    // 現在のCPUのNUMAノードを取得
    let current_node = crate::mm::numa::topology::current_node();

    // 自分のノードを優先的に補充
    total_zeroed += refill_pool_if_needed(current_node);

    // 他のノードも補充（負荷分散）
    for node in 0..MAX_NUMA_NODES {
        if node != current_node {
            total_zeroed += refill_pool_if_needed(node);
        }
    }

    ZEROING_IN_PROGRESS.store(false, Ordering::Release);
    total_zeroed
}

/// 指定ノードのプールを必要に応じて補充
fn refill_pool_if_needed(node: usize) -> usize {
    if node >= MAX_NUMA_NODES {
        return 0;
    }

    // まずロックなしでチェック（最適化）
    let needs_refill = {
        let pool = ZEROED_POOLS[node].lock();
        pool.needs_refill()
    };

    if !needs_refill {
        return 0;
    }

    let mut zeroed_count = 0;
    let numa_node_id = NumaNodeId::new(node as u8);

    for _ in 0..REFILL_BATCH_SIZE {
        // PMMから通常のフレームを取得
        let frame = match crate::mm::phys::frame_allocator::alloc_frame_on_numa_node(numa_node_id) {
            Some(f) => f,
            None => break,
        };

        // フレームをゼロクリア（Non-Temporal Store でキャッシュ汚染を防止）
        let virt_addr = crate::mm::virt::mapping::phys_to_virt(frame.start_address());
        unsafe {
            zero_page_nontemporal(virt_addr.as_u64());
        }

        // プールに追加
        let mut pool = ZEROED_POOLS[node].lock();
        if !pool.push(frame) {
            // プールが満杯になった場合、フレームをPMMに戻す
            crate::mm::phys::frame_allocator::dealloc_frame(frame);
            break;
        }

        zeroed_count += 1;
    }

    if zeroed_count > 0 {
        let mut pool = ZEROED_POOLS[node].lock();
        pool.refill_count += 1;
    }

    zeroed_count
}

/// 全ノードの統計情報を取得
pub fn get_all_stats() -> [ZeroedPoolStats; MAX_NUMA_NODES] {
    let mut stats = [ZeroedPoolStats {
        capacity: 0,
        current_count: 0,
        numa_node: 0,
        refill_count: 0,
        hit_count: 0,
        miss_count: 0,
        hit_rate_percent: 0,
    }; MAX_NUMA_NODES];

    for (i, pool_mutex) in ZEROED_POOLS.iter().enumerate() {
        let pool = pool_mutex.lock();
        stats[i] = pool.stats();
    }

    stats
}

/// 特定ノードの統計情報を取得
pub fn get_node_stats(node: usize) -> Option<ZeroedPoolStats> {
    if node >= MAX_NUMA_NODES {
        return None;
    }

    let pool = ZEROED_POOLS[node].lock();
    Some(pool.stats())
}

/// ゼロ済みフレームを返却（使用済みだがゼロ状態が保証されている場合）
///
/// 通常は使用しない。特殊なケース（例: ページテーブルの再利用）のみ。
pub fn return_zeroed_frame(frame: PhysFrame<Size4KiB>, node: usize) -> bool {
    if !INITIALIZED.load(Ordering::Acquire) || node >= MAX_NUMA_NODES {
        return false;
    }

    let mut pool = ZEROED_POOLS[node].lock();
    pool.push(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_zeroed_pool_basic() {
        let mut pool = ZeroedFramePool::new(0);
        assert!(pool.is_empty());
        assert!(!pool.is_full());
        assert_eq!(pool.len(), 0);
    }
}
