// ============================================================================
// src/mm/huge_page.rs - Huge Page Direct Allocation with Direct Compaction
//
// ## 概要
//
// 2MB/1GB Huge Pageの直接割り当てを管理する。
// 割り当て失敗時にはDirect Compactionを実行して連続メモリを確保する。
//
// ## 設計
//
// 1. **Free List Pool**: 事前割り当てされたHuge Pageのプール
// 2. **On-demand Allocation**: プールが空の場合はBuddyから取得
// 3. **Direct Compaction**: Buddy失敗時にメモリコンパクションを試行
// 4. **NUMA Affinity**: NUMA ノードごとのプール管理
// 5. **CPU Feature Detection**: 1GBページサポートの検出
//
// ## Huge Page サイズ
//
// - 2MB (Order-9): 通常のHuge Page
// - 1GB (Order-18): Giant Page（サポートがあれば）
#![allow(dead_code)]
//
// ## フォールバック戦略
//
// 1. プールから取得を試行
// 2. Buddyアロケータから直接取得を試行
// 3. Direct Compactionを実行して再試行
// 4. 4KB ページへのフォールバック（オプション）
//
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use alloc::collections::VecDeque;
use x86_64::structures::paging::PhysFrame;

// types.rs から共通定数をインポート
use super::types::{HUGE_PAGE_SIZE_2MB, HUGE_PAGE_SIZE_1GB, HUGE_PAGE_ORDER_2MB, HUGE_PAGE_ORDER_1GB};

// ============================================================================
// CPU Feature Detection (huge_pages.rs から統合)
// ============================================================================

/// 1GB Huge Page機能が検出されたか
static HUGE_PAGE_1G_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// 1GBページサポートを検出
///
/// CPUID.80000001H:EDX.Page1GB (bit 26) をチェック
pub fn detect_1g_page_support() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;

        // Extended features: CPUID.80000001H
        let result = __cpuid(0x80000001);
        let supported = (result.edx & (1 << 26)) != 0;

        HUGE_PAGE_1G_AVAILABLE.store(supported, Ordering::Release);

        if supported {
            log::info!("[HUGE_PAGE] 1GB page support detected");
        } else {
            log::info!("[HUGE_PAGE] 1GB page not supported, using 2MB pages");
        }

        supported
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        log::info!("[HUGE_PAGE] 1GB page not available on this architecture");
        false
    }
}

/// 1GBページがサポートされているかチェック
#[inline]
pub fn is_1g_page_supported() -> bool {
    HUGE_PAGE_1G_AVAILABLE.load(Ordering::Acquire)
}

// ============================================================================
// Configuration
// ============================================================================

/// プールの初期サイズ（2MB Huge Pages）
pub const INITIAL_POOL_SIZE: usize = 64;

/// プールの最大サイズ
pub const MAX_POOL_SIZE: usize = 256;

/// プールの最小維持サイズ（この数以下でrefill）
pub const POOL_LOW_WATERMARK: usize = 16;

/// NUMAノード数
pub const MAX_NUMA_NODES: usize = 8;

// ============================================================================
// Huge Page Types
// ============================================================================

/// Huge Page サイズタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HugePageSize {
    /// 2MB Huge Page
    Size2MB = 0,
    /// 1GB Giant Page
    Size1GB = 1,
}

impl HugePageSize {
    /// バイトサイズを取得
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::Size2MB => HUGE_PAGE_SIZE_2MB,
            Self::Size1GB => HUGE_PAGE_SIZE_1GB,
        }
    }
    
    /// Buddyアロケータのオーダーを取得
    pub const fn order(self) -> usize {
        match self {
            Self::Size2MB => HUGE_PAGE_ORDER_2MB,
            Self::Size1GB => HUGE_PAGE_ORDER_1GB,
        }
    }
    
    /// アラインメントを取得
    pub const fn alignment(self) -> usize {
        self.size_bytes()
    }
    
    /// 1GBページがサポートされていない場合のフォールバック
    pub fn effective_size(self) -> HugePageSize {
        match self {
            Self::Size1GB if !is_1g_page_supported() => Self::Size2MB,
            other => other,
        }
    }
}

/// Huge Page エントリ
#[derive(Debug, Clone)]
pub struct HugePageEntry {
    /// 物理フレーム
    pub frame: PhysFrame,
    /// サイズタイプ
    pub size: HugePageSize,
    /// NUMAノードID
    pub numa_node: u8,
    /// 割り当て時刻
    pub alloc_time: u64,
}

impl HugePageEntry {
    pub fn new(frame: PhysFrame, size: HugePageSize, numa_node: u8) -> Self {
        Self {
            frame,
            size,
            numa_node,
            alloc_time: crate::time::current_time_ns(),
        }
    }
}

// ============================================================================
// Allocation Result
// ============================================================================

/// 割り当て結果
#[derive(Debug)]
pub enum HugePageAllocResult {
    /// 成功
    Success(HugePageEntry),
    /// プールから取得成功
    PoolHit(HugePageEntry),
    /// Compaction後に成功
    CompactionSuccess(HugePageEntry),
    /// 失敗
    Failed(HugePageAllocError),
}

/// 割り当てエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageAllocError {
    /// メモリ不足
    OutOfMemory,
    /// Compaction後もメモリ不足
    CompactionFailed,
    /// サポートされていないサイズ
    UnsupportedSize,
    /// NUMAノードが無効
    InvalidNumaNode,
    /// アラインメントエラー
    AlignmentError,
}

// ============================================================================
// Huge Page Pool
// ============================================================================

/// Per-NUMAノードのHuge Pageプール
pub struct HugePagePool {
    /// 2MB Huge Pageのフリーリスト
    free_2mb: VecDeque<PhysFrame>,
    /// 1GB Giant Pageのフリーリスト
    free_1gb: VecDeque<PhysFrame>,
    /// NUMAノードID
    numa_node: u8,
    /// 統計: 割り当て成功回数
    alloc_success: u64,
    /// 統計: プールヒット回数
    pool_hits: u64,
    /// 統計: Compaction成功回数
    compaction_success: u64,
    /// 統計: 失敗回数
    alloc_failed: u64,
}

impl HugePagePool {
    /// 新しいプールを作成
    pub const fn new(numa_node: u8) -> Self {
        Self {
            free_2mb: VecDeque::new(),
            free_1gb: VecDeque::new(),
            numa_node,
            alloc_success: 0,
            pool_hits: 0,
            compaction_success: 0,
            alloc_failed: 0,
        }
    }
    
    /// プールから2MBページを取得
    fn try_get_2mb(&mut self) -> Option<PhysFrame> {
        self.free_2mb.pop_front()
    }
    
    /// プールから1GBページを取得
    fn try_get_1gb(&mut self) -> Option<PhysFrame> {
        self.free_1gb.pop_front()
    }
    
    /// 2MBページをプールに返却
    fn put_2mb(&mut self, frame: PhysFrame) {
        if self.free_2mb.len() < MAX_POOL_SIZE {
            self.free_2mb.push_back(frame);
        }
        // プールが満杯の場合はBuddyに返却（呼び出し元で処理）
    }
    
    /// 1GBページをプールに返却
    fn put_1gb(&mut self, frame: PhysFrame) {
        if self.free_1gb.len() < MAX_POOL_SIZE {
            self.free_1gb.push_back(frame);
        }
    }
    
    /// プールサイズを取得
    pub fn pool_size(&self, size: HugePageSize) -> usize {
        match size {
            HugePageSize::Size2MB => self.free_2mb.len(),
            HugePageSize::Size1GB => self.free_1gb.len(),
        }
    }
    
    /// Low watermark以下か
    pub fn needs_refill(&self, size: HugePageSize) -> bool {
        self.pool_size(size) <= POOL_LOW_WATERMARK
    }
}

// ============================================================================
// Huge Page Allocator
// ============================================================================

/// グローバルHuge Pageアロケータ
pub struct HugePageAllocator {
    /// Per-NUMAノードプール
    pools: [Mutex<HugePagePool>; MAX_NUMA_NODES],
    /// Compaction実行中フラグ
    compaction_in_progress: AtomicU64,
    /// グローバル統計
    stats: HugePageGlobalStats,
}

/// グローバル統計
pub struct HugePageGlobalStats {
    /// 総割り当て要求数
    pub total_requests: AtomicU64,
    /// Buddyから直接取得した回数
    pub buddy_allocations: AtomicU64,
    /// Compaction実行回数
    pub compaction_runs: AtomicU64,
    /// フォールバックして4KBで割り当てた回数
    pub fallback_to_small: AtomicU64,
}

impl HugePageAllocator {
    /// 新しいアロケータを作成
    pub const fn new() -> Self {
        Self {
            pools: [
                Mutex::new(HugePagePool::new(0)),
                Mutex::new(HugePagePool::new(1)),
                Mutex::new(HugePagePool::new(2)),
                Mutex::new(HugePagePool::new(3)),
                Mutex::new(HugePagePool::new(4)),
                Mutex::new(HugePagePool::new(5)),
                Mutex::new(HugePagePool::new(6)),
                Mutex::new(HugePagePool::new(7)),
            ],
            compaction_in_progress: AtomicU64::new(0),
            stats: HugePageGlobalStats {
                total_requests: AtomicU64::new(0),
                buddy_allocations: AtomicU64::new(0),
                compaction_runs: AtomicU64::new(0),
                fallback_to_small: AtomicU64::new(0),
            },
        }
    }
    
    /// Huge Pageを割り当て
    pub fn allocate(
        &self,
        size: HugePageSize,
        numa_node: usize,
        allow_compaction: bool,
    ) -> HugePageAllocResult {
        if numa_node >= MAX_NUMA_NODES {
            return HugePageAllocResult::Failed(HugePageAllocError::InvalidNumaNode);
        }
        
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);
        
        // Step 1: プールから取得を試行
        {
            let mut pool = self.pools[numa_node].lock();
            let frame_opt = match size {
                HugePageSize::Size2MB => pool.try_get_2mb(),
                HugePageSize::Size1GB => pool.try_get_1gb(),
            };
            
            if let Some(frame) = frame_opt {
                pool.pool_hits += 1;
                pool.alloc_success += 1;
                let entry = HugePageEntry::new(frame, size, numa_node as u8);
                return HugePageAllocResult::PoolHit(entry);
            }
        }
        
        // Step 2: Buddyから直接取得
        if let Some(frame) = self.try_allocate_from_buddy(size, numa_node) {
            self.stats.buddy_allocations.fetch_add(1, Ordering::Relaxed);
            let entry = HugePageEntry::new(frame, size, numa_node as u8);
            return HugePageAllocResult::Success(entry);
        }
        
        // Step 3: Direct Compaction
        if allow_compaction {
            if let Some(frame) = self.try_allocate_with_compaction(size, numa_node) {
                let entry = HugePageEntry::new(frame, size, numa_node as u8);
                return HugePageAllocResult::CompactionSuccess(entry);
            }
        }
        
        // Step 4: 失敗
        {
            let mut pool = self.pools[numa_node].lock();
            pool.alloc_failed += 1;
        }
        
        HugePageAllocResult::Failed(HugePageAllocError::OutOfMemory)
    }
    
    /// Buddyアロケータから直接取得
    fn try_allocate_from_buddy(&self, size: HugePageSize, _numa_node: usize) -> Option<PhysFrame> {
        let order = size.order();
        
        // TODO: 実際のBuddyアロケータとの連携
        // buddy_allocator::allocate_order(order, numa_node)
        
        // プレースホルダー: 仮のアドレスを返す
        // 実際の実装ではbuddyアロケータを呼び出す
        let _ = order;
        None
    }
    
    /// Compactionを実行して取得を試行
    fn try_allocate_with_compaction(&self, size: HugePageSize, numa_node: usize) -> Option<PhysFrame> {
        // Compactionが既に実行中かチェック
        let node_bit = 1u64 << numa_node;
        let prev = self.compaction_in_progress.fetch_or(node_bit, Ordering::AcqRel);
        if prev & node_bit != 0 {
            // 既に実行中
            return None;
        }
        
        self.stats.compaction_runs.fetch_add(1, Ordering::Relaxed);
        
        // Direct Compaction実行
        let result = self.run_direct_compaction(size, numa_node);
        
        // フラグをクリア
        self.compaction_in_progress.fetch_and(!node_bit, Ordering::Release);
        
        if result {
            // Compaction成功、再度Buddyから取得を試行
            self.try_allocate_from_buddy(size, numa_node)
        } else {
            None
        }
    }
    
    /// Direct Compactionを実行
    fn run_direct_compaction(&self, size: HugePageSize, numa_node: usize) -> bool {
        let required_pages = match size {
            HugePageSize::Size2MB => 512,  // 512 * 4KB = 2MB
            HugePageSize::Size1GB => 262144, // 256K * 4KB = 1GB
        };
        
        log::debug!(
            "[HugePage] Running direct compaction for {} pages on NUMA node {}",
            required_pages,
            numa_node
        );
        
        // Compaction戦略:
        // 1. Movable ページをスキャンして移動候補を選定
        // 2. 連続する空き領域を探す
        // 3. ページを移動して連続領域を作成
        
        // TODO: memory_compaction.rs との連携
        // memory_compaction::compact_zone(numa_node, required_pages)
        
        // プレースホルダー
        let _ = required_pages;
        let _ = numa_node;
        false
    }
    
    /// Huge Pageを解放
    pub fn free(&self, entry: HugePageEntry) {
        let numa_node = entry.numa_node as usize;
        if numa_node >= MAX_NUMA_NODES {
            return;
        }
        
        let mut pool = self.pools[numa_node].lock();
        match entry.size {
            HugePageSize::Size2MB => pool.put_2mb(entry.frame),
            HugePageSize::Size1GB => pool.put_1gb(entry.frame),
        }
    }
    
    /// プールを補充
    pub fn refill_pool(&self, numa_node: usize, size: HugePageSize, count: usize) -> usize {
        if numa_node >= MAX_NUMA_NODES {
            return 0;
        }
        
        let mut filled = 0;
        for _ in 0..count {
            if let Some(frame) = self.try_allocate_from_buddy(size, numa_node) {
                let mut pool = self.pools[numa_node].lock();
                match size {
                    HugePageSize::Size2MB => pool.put_2mb(frame),
                    HugePageSize::Size1GB => pool.put_1gb(frame),
                }
                filled += 1;
            } else {
                break;
            }
        }
        
        filled
    }
    
    /// プール統計を取得
    pub fn pool_stats(&self, numa_node: usize) -> Option<HugePagePoolStats> {
        if numa_node >= MAX_NUMA_NODES {
            return None;
        }
        
        let pool = self.pools[numa_node].lock();
        Some(HugePagePoolStats {
            free_2mb: pool.free_2mb.len(),
            free_1gb: pool.free_1gb.len(),
            alloc_success: pool.alloc_success,
            pool_hits: pool.pool_hits,
            compaction_success: pool.compaction_success,
            alloc_failed: pool.alloc_failed,
        })
    }
}

/// プール統計
#[derive(Debug, Clone)]
pub struct HugePagePoolStats {
    pub free_2mb: usize,
    pub free_1gb: usize,
    pub alloc_success: u64,
    pub pool_hits: u64,
    pub compaction_success: u64,
    pub alloc_failed: u64,
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルHuge Pageアロケータ
pub static HUGE_PAGE_ALLOCATOR: HugePageAllocator = HugePageAllocator::new();

// ============================================================================
// Public API
// ============================================================================

/// 2MB Huge Pageを割り当て
pub fn allocate_huge_page_2mb(numa_node: usize) -> HugePageAllocResult {
    HUGE_PAGE_ALLOCATOR.allocate(HugePageSize::Size2MB, numa_node, true)
}

/// 1GB Giant Pageを割り当て
pub fn allocate_huge_page_1gb(numa_node: usize) -> HugePageAllocResult {
    HUGE_PAGE_ALLOCATOR.allocate(HugePageSize::Size1GB, numa_node, true)
}

/// Huge Pageを解放
pub fn free_huge_page(entry: HugePageEntry) {
    HUGE_PAGE_ALLOCATOR.free(entry);
}

/// Compactionなしで2MB Huge Pageを割り当て（低遅延用）
pub fn allocate_huge_page_2mb_fast(numa_node: usize) -> HugePageAllocResult {
    HUGE_PAGE_ALLOCATOR.allocate(HugePageSize::Size2MB, numa_node, false)
}

// ============================================================================
// Transparent Huge Page (THP) Support
// ============================================================================

/// THP ポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThpPolicy {
    /// THP無効
    Never,
    /// 常にTHPを使用
    Always,
    /// madvise()で指定された領域のみ
    Madvise,
}

/// THP 設定
pub struct ThpConfig {
    /// ポリシー
    pub policy: ThpPolicy,
    /// デフラグモード
    pub defrag: ThpDefragMode,
    /// khugepaged 有効化
    pub khugepaged_enabled: bool,
    /// khugepaged スキャン間隔（ミリ秒）
    pub khugepaged_scan_interval_ms: u64,
}

/// デフラグモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThpDefragMode {
    /// デフラグしない
    Never,
    /// 常にデフラグ
    Always,
    /// madvise()で指定された領域のみ
    Madvise,
    /// 遅延デフラグ（バックグラウンド）
    Defer,
}

impl Default for ThpConfig {
    fn default() -> Self {
        Self {
            policy: ThpPolicy::Madvise,
            defrag: ThpDefragMode::Defer,
            khugepaged_enabled: true,
            khugepaged_scan_interval_ms: 10_000,
        }
    }
}

// ============================================================================
// khugepaged - Background Huge Page Creation
// ============================================================================

/// khugepaged 統計
pub struct KhugepagedStats {
    /// スキャンしたページ数
    pub pages_scanned: AtomicU64,
    /// 折りたたんだページ数
    pub pages_collapsed: AtomicU64,
    /// 失敗回数
    pub collapse_failed: AtomicU64,
}

pub static KHUGEPAGED_STATS: KhugepagedStats = KhugepagedStats {
    pages_scanned: AtomicU64::new(0),
    pages_collapsed: AtomicU64::new(0),
    collapse_failed: AtomicU64::new(0),
};

/// khugepaged のメインループ（バックグラウンドスレッド用）
/// 
/// 512個の連続した4KBページをスキャンし、可能であれば
/// 2MB Huge Pageに折りたたむ。
pub fn khugepaged_scan_cycle() {
    // TODO: VMA領域をスキャンして折りたたみ候補を探す
    // 1. プロセスのVMAを順にスキャン
    // 2. 512個の連続ページが同じ特性を持つか確認
    // 3. Huge Page を割り当てて移行
    // 4. 元の4KBページを解放
    
    KHUGEPAGED_STATS.pages_scanned.fetch_add(512, Ordering::Relaxed);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_huge_page_sizes() {
        assert_eq!(HugePageSize::Size2MB.size_bytes(), 2 * 1024 * 1024);
        assert_eq!(HugePageSize::Size1GB.size_bytes(), 1024 * 1024 * 1024);
        assert_eq!(HugePageSize::Size2MB.order(), 9);
        assert_eq!(HugePageSize::Size1GB.order(), 18);
    }
    
    #[test]
    fn test_pool_new() {
        let pool = HugePagePool::new(0);
        assert_eq!(pool.numa_node, 0);
        assert_eq!(pool.pool_size(HugePageSize::Size2MB), 0);
        assert_eq!(pool.pool_size(HugePageSize::Size1GB), 0);
    }
    
    #[test]
    fn test_pool_needs_refill() {
        let pool = HugePagePool::new(0);
        assert!(pool.needs_refill(HugePageSize::Size2MB));
    }
    
    #[test]
    fn test_thp_config_default() {
        let config = ThpConfig::default();
        assert_eq!(config.policy, ThpPolicy::Madvise);
        assert_eq!(config.defrag, ThpDefragMode::Defer);
        assert!(config.khugepaged_enabled);
    }
}
