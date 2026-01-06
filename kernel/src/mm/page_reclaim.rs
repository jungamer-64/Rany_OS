// ============================================================================
// src/mm/page_reclaim.rs - Page Reclaim and LRU Management
//
// ## 概要
//
// メモリ不足時のページ回収（Page Reclaim）システムを実装。
// Active/Inactive LRUリストによりページの使用頻度を追跡し、
// メモリ圧迫時に低使用頻度のページを回収する。
//
// ## 設計
//
// 1. **Active/Inactive LRU**: 2つのリストでページ活性度を管理
//    - Active: 最近アクセスされたページ
//    - Inactive: しばらくアクセスされていないページ
//
// 2. **Watermarks**: メモリ圧迫レベルの監視
//    - High: 十分な空きあり
//    - Low: バックグラウンド回収開始
//    - Min: 直接回収（Direct Reclaim）
//    - Critical: OOM killer発動
//
// 3. **Page Types**:
//    - Anon: 匿名ページ（スワップ対象）
//    - File: ファイルバックページ（クリーンなら破棄可能）
//    - Slab: Slabキャッシュ（縮小可能）
//
// ## 参考
//
// - Linux mm/vmscan.c
// - FreeBSD vm/vm_pageout.c
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::types::FrameIndex;

// ============================================================================
// Watermarks
// ============================================================================

/// メモリウォーターマーク（ページ数単位）
#[derive(Debug, Clone, Copy)]
pub struct Watermarks {
    /// High watermark: この上ならkswapd停止
    pub high: usize,
    /// Low watermark: この下ならkswapdが起動
    pub low: usize,
    /// Min watermark: この下なら直接回収
    pub min: usize,
    /// Critical: この下ならOOM
    pub critical: usize,
}

impl Watermarks {
    /// 総メモリサイズから適切なウォーターマークを計算
    pub fn calculate(total_pages: usize) -> Self {
        // 典型的な比率（調整可能）
        let min = (total_pages * 1) / 100;      // 1%
        let low = (total_pages * 2) / 100;      // 2%
        let high = (total_pages * 3) / 100;     // 3%
        let critical = (total_pages * 5) / 1000; // 0.5%
        
        Self {
            high: high.max(128),
            low: low.max(64),
            min: min.max(32),
            critical: critical.max(16),
        }
    }
    
    /// 現在の空きページ数からメモリ圧迫レベルを判定
    pub fn pressure_level(&self, free_pages: usize) -> MemoryPressure {
        if free_pages <= self.critical {
            MemoryPressure::Critical
        } else if free_pages <= self.min {
            MemoryPressure::Direct
        } else if free_pages <= self.low {
            MemoryPressure::Background
        } else {
            MemoryPressure::None
        }
    }
}

/// メモリ圧迫レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryPressure {
    /// 十分な空きあり
    None = 0,
    /// バックグラウンド回収（kswapd）
    Background = 1,
    /// 直接回収（Direct Reclaim）
    Direct = 2,
    /// OOM状態
    Critical = 3,
}

// ============================================================================
// LRU Page Entry
// ============================================================================

/// LRU追跡対象のページエントリ
#[derive(Debug)]
pub struct LruPageEntry {
    /// 物理フレームインデックス
    pub frame: FrameIndex,
    /// ページタイプ
    pub page_type: PageType,
    /// 参照ビット（最近アクセスされたか）
    pub referenced: AtomicBool,
    /// マッピング数（何個のPTEから参照されているか）
    pub mapcount: AtomicU64,
    /// 追加時刻（TSC or jiffies）
    pub add_time: u64,
    /// フラグ
    pub flags: LruFlags,
}

/// ページタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    /// 匿名ページ（ヒープ、スタック等）
    Anonymous = 0,
    /// ファイルバックページ
    FileBacked = 1,
    /// Slabキャッシュ
    Slab = 2,
    /// カーネルページ（回収不可）
    Kernel = 3,
}

/// LRUフラグ
#[derive(Debug, Clone, Copy, Default)]
#[repr(transparent)]
pub struct LruFlags(u32);

impl LruFlags {
    pub const NONE: Self = Self(0);
    pub const DIRTY: Self = Self(1 << 0);      // ダーティ（書き込み必要）
    pub const LOCKED: Self = Self(1 << 1);     // ロック中
    pub const WRITEBACK: Self = Self(1 << 2);  // ライトバック中
    pub const RECLAIM: Self = Self(1 << 3);    // 回収中
    pub const UNEVICTABLE: Self = Self(1 << 4); // 回収不可
    pub const MLOCKED: Self = Self(1 << 5);    // mlock()済み
    
    #[inline]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

impl LruPageEntry {
    pub fn new(frame: FrameIndex, page_type: PageType, timestamp: u64) -> Self {
        Self {
            frame,
            page_type,
            referenced: AtomicBool::new(true),
            mapcount: AtomicU64::new(1),
            add_time: timestamp,
            flags: LruFlags::NONE,
        }
    }
    
    /// 参照ビットをクリアして以前の値を返す
    #[inline]
    pub fn test_clear_referenced(&self) -> bool {
        self.referenced.swap(false, Ordering::AcqRel)
    }
    
    /// 参照をセット
    #[inline]
    pub fn set_referenced(&self) {
        self.referenced.store(true, Ordering::Release);
    }
    
    /// 回収可能かどうか
    pub fn is_reclaimable(&self) -> bool {
        !self.flags.contains(LruFlags::LOCKED)
            && !self.flags.contains(LruFlags::UNEVICTABLE)
            && !self.flags.contains(LruFlags::MLOCKED)
            && !self.flags.contains(LruFlags::WRITEBACK)
            && self.mapcount.load(Ordering::Relaxed) == 0
    }
}

// ============================================================================
// LRU List (per NUMA node)
// ============================================================================

/// Active/Inactive LRUリスト
/// 
/// Clock Algorithm対応: select_victim_clock()で効率的な犠牲者選択
pub struct LruList {
    /// Activeリスト（最近アクセスされたページ）
    active: spin::Mutex<VecDeque<LruPageEntry>>,
    /// Inactiveリスト（回収候補）
    inactive: spin::Mutex<VecDeque<LruPageEntry>>,
    /// Activeリストのサイズ
    active_size: AtomicUsize,
    /// Inactiveリストのサイズ
    inactive_size: AtomicUsize,
    /// Clock Algorithm: Inactive内の現在位置
    clock_hand: AtomicUsize,
    /// 統計: Active→Inactiveへの移動数
    demoted: AtomicU64,
    /// 統計: Inactive→Activeへの昇格数
    promoted: AtomicU64,
    /// 統計: 回収されたページ数
    reclaimed: AtomicU64,
    /// 統計: Clock Algorithmで与えたセカンドチャンス数
    second_chances: AtomicU64,
}

impl LruList {
    pub const fn new() -> Self {
        Self {
            active: spin::Mutex::new(VecDeque::new()),
            inactive: spin::Mutex::new(VecDeque::new()),
            active_size: AtomicUsize::new(0),
            inactive_size: AtomicUsize::new(0),
            clock_hand: AtomicUsize::new(0),
            demoted: AtomicU64::new(0),
            promoted: AtomicU64::new(0),
            reclaimed: AtomicU64::new(0),
            second_chances: AtomicU64::new(0),
        }
    }
    
    /// 新しいページをActiveリストに追加
    pub fn add_to_active(&self, entry: LruPageEntry) {
        let mut active = self.active.lock();
        active.push_back(entry);
        self.active_size.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 新しいページをInactiveリストに追加
    pub fn add_to_inactive(&self, entry: LruPageEntry) {
        let mut inactive = self.inactive.lock();
        inactive.push_back(entry);
        self.inactive_size.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Activeリストのサイズ
    pub fn active_count(&self) -> usize {
        self.active_size.load(Ordering::Relaxed)
    }
    
    /// Inactiveリストのサイズ
    pub fn inactive_count(&self) -> usize {
        self.inactive_size.load(Ordering::Relaxed)
    }
    
    /// Activeリストをスキャンし、非参照ページをInactiveに降格
    /// 
    /// 返り値: 降格したページ数
    pub fn shrink_active(&self, scan_count: usize) -> usize {
        let mut active = self.active.lock();
        let mut inactive = self.inactive.lock();
        
        let mut demoted = 0;
        let mut scanned = 0;
        
        while scanned < scan_count && !active.is_empty() {
            if let Some(entry) = active.pop_front() {
                scanned += 1;
                
                // 参照ビットをチェック
                if entry.test_clear_referenced() {
                    // 最近参照された → Activeの末尾に戻す
                    active.push_back(entry);
                } else {
                    // 参照されていない → Inactiveへ降格
                    inactive.push_back(entry);
                    demoted += 1;
                }
            }
        }
        
        // サイズを更新
        self.active_size.fetch_sub(demoted, Ordering::Relaxed);
        self.inactive_size.fetch_add(demoted, Ordering::Relaxed);
        self.demoted.fetch_add(demoted as u64, Ordering::Relaxed);
        
        demoted
    }
    
    /// Inactiveリストから回収可能なページを取得
    /// 
    /// 返り値: 回収するページのリスト
    pub fn get_reclaimable(&self, count: usize) -> Vec<LruPageEntry> {
        let mut inactive = self.inactive.lock();
        let mut active = self.active.lock();
        
        let mut reclaimable = Vec::new();
        let mut promoted = 0;
        
        let mut i = 0;
        while i < inactive.len() && reclaimable.len() < count {
            // 安全のため remove は使わず、swap_remove_back などで効率化可能
            if let Some(entry) = inactive.get(i) {
                // 参照されているページはActiveに昇格
                if entry.referenced.load(Ordering::Relaxed) {
                    if let Some(e) = inactive.remove(i) {
                        e.referenced.store(false, Ordering::Relaxed);
                        active.push_back(e);
                        promoted += 1;
                    }
                    continue;
                }
                
                // 回収可能なページを取り出す
                if entry.is_reclaimable() {
                    if let Some(e) = inactive.remove(i) {
                        reclaimable.push(e);
                    }
                    continue;
                }
            }
            i += 1;
        }
        
        // サイズを更新
        let reclaimed_count = reclaimable.len();
        self.inactive_size.fetch_sub(reclaimed_count + promoted, Ordering::Relaxed);
        self.active_size.fetch_add(promoted, Ordering::Relaxed);
        self.promoted.fetch_add(promoted as u64, Ordering::Relaxed);
        self.reclaimed.fetch_add(reclaimed_count as u64, Ordering::Relaxed);
        
        reclaimable
    }
    
    /// 統計
    pub fn stats(&self) -> LruStats {
        LruStats {
            active: self.active_size.load(Ordering::Relaxed),
            inactive: self.inactive_size.load(Ordering::Relaxed),
            demoted: self.demoted.load(Ordering::Relaxed),
            promoted: self.promoted.load(Ordering::Relaxed),
            reclaimed: self.reclaimed.load(Ordering::Relaxed),
            second_chances: self.second_chances.load(Ordering::Relaxed),
        }
    }
    
    /// Clock Algorithm による効率的な犠牲者選択
    /// 
    /// 従来のLRU走査と異なり、clock handを使って循環的に走査。
    /// 参照ビットが立っているページには「セカンドチャンス」を与え、
    /// ビットをクリアして次回まで保護する。
    /// 
    /// ## アルゴリズム
    /// 
    /// ```text
    /// while not found:
    ///   if page[hand].referenced:
    ///     page[hand].referenced = false  // セカンドチャンス
    ///     hand = (hand + 1) % len
    ///   else:
    ///     return page[hand]  // 犠牲者発見
    /// ```
    /// 
    /// ## 利点
    /// 
    /// - O(1) 最良ケース（最初のページが未参照）
    /// - リスト先頭への偏りを防止
    /// - 公平な回収（全ページに均等なチャンス）
    /// 
    /// # Arguments
    /// * `count` - 取得する犠牲者の最大数
    /// 
    /// # Returns
    /// 回収対象のページエントリのベクタ
    pub fn select_victim_clock(&self, count: usize) -> Vec<LruPageEntry> {
        let mut inactive = self.inactive.lock();
        let list_len = inactive.len();
        
        if list_len == 0 || count == 0 {
            return Vec::new();
        }
        
        let mut victims = Vec::with_capacity(count.min(list_len));
        let mut hand = self.clock_hand.load(Ordering::Relaxed) % list_len;
        let mut scanned = 0;
        let max_scan = list_len * 2; // 最大2周
        let mut second_chances_given = 0u64;
        
        while victims.len() < count && scanned < max_scan {
            // 現在位置のページをチェック
            if let Some(entry) = inactive.get(hand) {
                if entry.referenced.load(Ordering::Relaxed) {
                    // セカンドチャンス: 参照ビットをクリアして次へ
                    entry.referenced.store(false, Ordering::Relaxed);
                    second_chances_given += 1;
                } else if entry.is_reclaimable() {
                    // 犠牲者発見！ リストから除去
                    if let Some(victim) = inactive.remove(hand) {
                        victims.push(victim);
                        // hand位置は変わらない（次の要素が詰められる）
                        // ただしリストが縮んだのでhand >= new_lenなら調整
                        if hand >= inactive.len() && !inactive.is_empty() {
                            hand = 0;
                        }
                        continue;
                    }
                }
            }
            
            // 次の位置へ
            hand = (hand + 1) % list_len.max(1);
            scanned += 1;
        }
        
        // Clock handを更新
        self.clock_hand.store(hand, Ordering::Relaxed);
        
        // 統計更新
        let victim_count = victims.len();
        self.inactive_size.fetch_sub(victim_count, Ordering::Relaxed);
        self.reclaimed.fetch_add(victim_count as u64, Ordering::Relaxed);
        self.second_chances.fetch_add(second_chances_given, Ordering::Relaxed);
        
        victims
    }
}

/// LRU統計
#[derive(Debug, Clone, Copy)]
pub struct LruStats {
    pub active: usize,
    pub inactive: usize,
    pub demoted: u64,
    pub promoted: u64,
    pub reclaimed: u64,
    pub second_chances: u64,
}

// ============================================================================
// Page Reclaim Controller
// ============================================================================

/// ページ回収コントローラ
pub struct PageReclaimController {
    /// NUMAノードごとのLRUリスト
    /// インデックス = NUMAノードID
    lru_lists: [LruList; 8],
    
    /// ウォーターマーク
    watermarks: Watermarks,
    
    /// kswapd起動フラグ
    kswapd_wake: AtomicBool,
    
    /// 現在のメモリ圧迫レベル
    pressure: AtomicU64,
    
    /// 統計: 直接回収の回数
    direct_reclaim_count: AtomicU64,
    
    /// 統計: バックグラウンド回収の回数
    background_reclaim_count: AtomicU64,
    
    /// 統計: 回収したページ数（合計）
    total_reclaimed: AtomicU64,
    
    /// スキャン比率（Active:Inactive）
    scan_ratio: AtomicU64,
}

const fn lru_list_array() -> [LruList; 8] {
    const LRU: LruList = LruList::new();
    [LRU; 8]
}

impl PageReclaimController {
    /// 新しいコントローラを作成
    pub const fn new() -> Self {
        Self {
            lru_lists: lru_list_array(),
            watermarks: Watermarks {
                high: 1024,
                low: 512,
                min: 256,
                critical: 64,
            },
            kswapd_wake: AtomicBool::new(false),
            pressure: AtomicU64::new(0),
            direct_reclaim_count: AtomicU64::new(0),
            background_reclaim_count: AtomicU64::new(0),
            total_reclaimed: AtomicU64::new(0),
            scan_ratio: AtomicU64::new(1), // 1:1
        }
    }
    
    /// ウォーターマークを設定
    pub fn set_watermarks(&mut self, watermarks: Watermarks) {
        self.watermarks = watermarks;
    }
    
    /// 空きページ数を更新し、必要なアクションを返す
    pub fn update_free_pages(&self, free_pages: usize) -> MemoryPressure {
        let pressure = self.watermarks.pressure_level(free_pages);
        self.pressure.store(pressure as u64, Ordering::Release);
        
        // Low watermark以下ならkswapdを起動
        if pressure >= MemoryPressure::Background {
            self.kswapd_wake.store(true, Ordering::Release);
        }
        
        pressure
    }
    
    /// kswapdが起動すべきか
    pub fn should_wake_kswapd(&self) -> bool {
        self.kswapd_wake.swap(false, Ordering::AcqRel)
    }
    
    /// 現在のメモリ圧迫レベル
    pub fn current_pressure(&self) -> MemoryPressure {
        match self.pressure.load(Ordering::Acquire) {
            0 => MemoryPressure::None,
            1 => MemoryPressure::Background,
            2 => MemoryPressure::Direct,
            _ => MemoryPressure::Critical,
        }
    }
    
    /// ページをLRUに追加
    pub fn add_page(&self, frame: FrameIndex, page_type: PageType, node: usize, timestamp: u64) {
        let entry = LruPageEntry::new(frame, page_type, timestamp);
        
        let node_idx = node.min(7);
        self.lru_lists[node_idx].add_to_active(entry);
    }
    
    /// ページアクセスを記録（参照ビットをセット）
    pub fn mark_accessed(&self, frame: FrameIndex, node: usize) {
        // 実際の実装ではフレームからエントリを検索する必要がある
        // ここでは簡略化
        let _ = (frame, node);
    }
    
    /// バックグラウンド回収（kswapd相当）
    /// 
    /// 返り値: 回収したページ数
    pub fn background_reclaim(&self, target_pages: usize) -> usize {
        let mut total_reclaimed = 0;
        
        for lru in &self.lru_lists {
            if total_reclaimed >= target_pages {
                break;
            }
            
            // まずActiveリストを縮小
            let scan_active = (target_pages - total_reclaimed).min(32);
            lru.shrink_active(scan_active);
            
            // Inactiveから回収
            let to_reclaim = target_pages - total_reclaimed;
            let reclaimable = lru.get_reclaimable(to_reclaim);
            
            for entry in &reclaimable {
                // 実際にフレームを解放
                self.reclaim_page(entry);
                total_reclaimed += 1;
            }
        }
        
        if total_reclaimed > 0 {
            self.background_reclaim_count.fetch_add(1, Ordering::Relaxed);
            self.total_reclaimed.fetch_add(total_reclaimed as u64, Ordering::Relaxed);
        }
        
        total_reclaimed
    }
    
    /// 直接回収（Direct Reclaim）
    /// 
    /// 割り当てパスから呼ばれる同期的な回収
    pub fn direct_reclaim(&self, needed_pages: usize) -> usize {
        self.direct_reclaim_count.fetch_add(1, Ordering::Relaxed);
        
        // より積極的に回収
        let mut total_reclaimed = 0;
        let scan_count = needed_pages * 4; // 4倍スキャン
        
        for lru in &self.lru_lists {
            if total_reclaimed >= needed_pages {
                break;
            }
            
            // Activeを積極的に縮小
            lru.shrink_active(scan_count);
            
            // Inactiveから回収
            let reclaimable = lru.get_reclaimable(needed_pages - total_reclaimed);
            
            for entry in &reclaimable {
                self.reclaim_page(entry);
                total_reclaimed += 1;
            }
        }
        
        self.total_reclaimed.fetch_add(total_reclaimed as u64, Ordering::Relaxed);
        total_reclaimed
    }
    
    /// ページを実際に回収
    fn reclaim_page(&self, entry: &LruPageEntry) {
        match entry.page_type {
            PageType::Anonymous => {
                // スワップアウト（未実装の場合はスキップ）
                // TODO: swap subsystem
            }
            PageType::FileBacked => {
                // ダーティならライトバック、そうでなければ破棄
                if entry.flags.contains(LruFlags::DIRTY) {
                    // TODO: writeback
                }
                // クリーンなら即座に回収可能
                self.free_frame(entry.frame);
            }
            PageType::Slab => {
                // Slabキャッシュの縮小
                // TODO: slab shrink callback
            }
            PageType::Kernel => {
                // 回収不可
            }
        }
    }
    
    /// フレームをBuddyに返却
    fn free_frame(&self, frame: FrameIndex) {
        use super::buddy_allocator::buddy_dealloc_frame;
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;
        
        let phys_frame = unsafe {
            PhysFrame::<Size4KiB>::from_start_address_unchecked(
                PhysAddr::new(frame.to_phys_addr())
            )
        };
        buddy_dealloc_frame(phys_frame);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> ReclaimStats {
        let mut lru_stats = [LruStats {
            active: 0,
            inactive: 0,
            demoted: 0,
            promoted: 0,
            reclaimed: 0,
            second_chances: 0,
        }; 8];
        
        for (i, lru) in self.lru_lists.iter().enumerate() {
            lru_stats[i] = lru.stats();
        }
        
        ReclaimStats {
            direct_reclaim_count: self.direct_reclaim_count.load(Ordering::Relaxed),
            background_reclaim_count: self.background_reclaim_count.load(Ordering::Relaxed),
            total_reclaimed: self.total_reclaimed.load(Ordering::Relaxed),
            pressure: self.current_pressure(),
            lru_stats,
        }
    }
}

/// 回収統計
#[derive(Debug)]
pub struct ReclaimStats {
    pub direct_reclaim_count: u64,
    pub background_reclaim_count: u64,
    pub total_reclaimed: u64,
    pub pressure: MemoryPressure,
    pub lru_stats: [LruStats; 8],
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルページ回収コントローラ
pub static PAGE_RECLAIM: PageReclaimController = PageReclaimController::new();

/// ページ回収を初期化
pub fn init_page_reclaim(total_pages: usize) {
    let watermarks = Watermarks::calculate(total_pages);
    log::info!(
        "[PageReclaim] Initialized: high={}, low={}, min={}, critical={}",
        watermarks.high,
        watermarks.low,
        watermarks.min,
        watermarks.critical
    );
}

// ============================================================================
// LRU Page API (fault_handler/cow/demand_paging/stack_growth から使用)
// ============================================================================

/// ページをLRUリストに追加（公開API）
///
/// 新しく割り当てられたページをLRUに追加する。
/// ページフォルトハンドラ、CoW、demand paging、stack growthから呼び出される。
///
/// # Arguments
/// * `frame` - 追加する物理フレーム
/// * `page_type` - ページタイプ (Anonymous, FileBacked, etc.)
///
/// # Example
/// ```ignore
/// use crate::mm::page_reclaim::{lru_add_page, PageType};
///
/// // 匿名ページをLRUに追加
/// lru_add_page(frame, PageType::Anonymous);
/// ```
pub fn lru_add_page(frame: x86_64::structures::paging::PhysFrame, page_type: PageType) {
    // フレームアドレスからFrameIndexに変換
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    
    // NUMA ノードIDを取得
    // 簡易実装: 物理アドレスから推測（単一ノード環境では常に0）
    // 将来的にはACPI SRATテーブルを参照
    let numa_node = numa_node_for_phys_addr(frame.start_address().as_u64());
    
    // タイムスタンプ（ナノ秒精度）
    let timestamp = crate::time::current_time_ns();
    
    PAGE_RECLAIM.add_page(frame_index, page_type, numa_node, timestamp);
}

/// ページをLRUリストに追加（NUMAノード指定版）
pub fn lru_add_page_on_node(
    frame: x86_64::structures::paging::PhysFrame,
    page_type: PageType,
    numa_node: usize,
) {
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let timestamp = crate::time::current_time_ns();
    PAGE_RECLAIM.add_page(frame_index, page_type, numa_node, timestamp);
}

/// ページアクセスを記録（参照ビットをセット）
pub fn lru_mark_accessed(frame: x86_64::structures::paging::PhysFrame) {
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let numa_node = numa_node_for_phys_addr(frame.start_address().as_u64());
    PAGE_RECLAIM.mark_accessed(frame_index, numa_node);
}

/// 物理アドレスからNUMAノードIDを取得
/// 
/// 簡易実装: 単一ノード環境では常に0を返す
/// 将来的にはACPI SRATテーブルを参照して正確なマッピングを行う
#[inline]
fn numa_node_for_phys_addr(_phys_addr: u64) -> usize {
    // 単一NUMA環境を想定（マルチノードの場合はSRATから取得）
    0
}

/// 空きメモリチェック（割り当て前に呼ぶ）
pub fn check_memory_pressure(free_pages: usize) -> MemoryPressure {
    PAGE_RECLAIM.update_free_pages(free_pages)
}

/// 必要に応じて直接回収を実行
pub fn try_to_free_pages(needed: usize) -> usize {
    PAGE_RECLAIM.direct_reclaim(needed)
}

// ============================================================================
// kswapd (Background Reclaim Thread)
// ============================================================================

/// kswapd相当のバックグラウンド回収タスク
/// 
/// この関数はカーネルスレッドから定期的に呼び出される想定
pub fn kswapd_cycle() {
    if !PAGE_RECLAIM.should_wake_kswapd() {
        return;
    }
    
    // Watermark高まで回収
    let target = 64; // 1サイクルの回収目標
    let reclaimed = PAGE_RECLAIM.background_reclaim(target);
    
    if reclaimed > 0 {
        log::trace!("[kswapd] Reclaimed {} pages", reclaimed);
    }
}

// ============================================================================
// Phase 2 最適化: Memory Pressure Notifier
// ============================================================================

/// メモリ圧力レベル（詳細版）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PressureLevel {
    /// 十分な空きあり（通常動作）
    Low = 0,
    /// やや逼迫（キャッシュ縮小推奨）
    Medium = 1,
    /// 高負荷（積極的な解放が必要）
    High = 2,
    /// 危機的（OOM間近）
    Critical = 3,
}

impl PressureLevel {
    /// MemoryPressureから変換
    pub fn from_memory_pressure(mp: MemoryPressure) -> Self {
        match mp {
            MemoryPressure::None => PressureLevel::Low,
            MemoryPressure::Background => PressureLevel::Medium,
            MemoryPressure::Direct => PressureLevel::High,
            MemoryPressure::Critical => PressureLevel::Critical,
        }
    }
}

/// 圧力通知コールバックの型
pub type PressureCallback = fn(PressureLevel);

/// 最大コールバック登録数
const MAX_PRESSURE_CALLBACKS: usize = 16;

/// Memory Pressure Notifier
/// 
/// メモリ圧力が変化したときにサブシステムに通知する仕組み。
/// Slabキャッシュ、バッファキャッシュ、ページキャッシュなどが
/// 圧力に応じてメモリを解放できる。
pub struct MemoryPressureNotifier {
    /// 登録されたコールバック
    callbacks: spin::Mutex<[Option<PressureCallback>; MAX_PRESSURE_CALLBACKS]>,
    /// 登録済みコールバック数
    callback_count: AtomicUsize,
    /// 現在の圧力レベル
    current_level: AtomicU64,
    /// 前回の圧力レベル
    previous_level: AtomicU64,
    /// 通知回数（統計）
    notification_count: AtomicU64,
    /// レベル変更回数（統計）
    level_change_count: AtomicU64,
    /// 通知を抑制する閾値（連続通知防止、ミリ秒）
    suppression_threshold_ms: AtomicU64,
    /// 最後の通知時刻（TSC）
    last_notification_tsc: AtomicU64,
}

impl MemoryPressureNotifier {
    pub const fn new() -> Self {
        Self {
            callbacks: spin::Mutex::new([None; MAX_PRESSURE_CALLBACKS]),
            callback_count: AtomicUsize::new(0),
            current_level: AtomicU64::new(PressureLevel::Low as u64),
            previous_level: AtomicU64::new(PressureLevel::Low as u64),
            notification_count: AtomicU64::new(0),
            level_change_count: AtomicU64::new(0),
            suppression_threshold_ms: AtomicU64::new(100), // 100ms
            last_notification_tsc: AtomicU64::new(0),
        }
    }
    
    /// コールバックを登録
    /// 
    /// # Returns
    /// 登録成功時はコールバックID（解除用）、失敗時はNone
    pub fn register(&self, callback: PressureCallback) -> Option<usize> {
        let mut callbacks = self.callbacks.lock();
        
        for (i, slot) in callbacks.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(callback);
                self.callback_count.fetch_add(1, Ordering::Relaxed);
                return Some(i);
            }
        }
        
        None // 満杯
    }
    
    /// コールバックを解除
    pub fn unregister(&self, id: usize) {
        if id >= MAX_PRESSURE_CALLBACKS {
            return;
        }
        
        let mut callbacks = self.callbacks.lock();
        if callbacks[id].is_some() {
            callbacks[id] = None;
            self.callback_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
    
    /// 圧力レベルを更新し、必要なら通知を発行
    /// 
    /// 圧力が上昇した場合は即座に通知。
    /// 圧力が低下した場合は抑制閾値後に通知（チャタリング防止）。
    pub fn update_pressure(&self, new_level: PressureLevel) {
        let old = self.current_level.swap(new_level as u64, Ordering::AcqRel);
        let old_level = match old {
            0 => PressureLevel::Low,
            1 => PressureLevel::Medium,
            2 => PressureLevel::High,
            _ => PressureLevel::Critical,
        };
        
        if new_level != old_level {
            self.previous_level.store(old, Ordering::Relaxed);
            self.level_change_count.fetch_add(1, Ordering::Relaxed);
            
            // 圧力上昇は即座に通知（緊急性が高い）
            if new_level > old_level {
                self.notify_all(new_level);
            } else {
                // 圧力低下は抑制閾値を確認
                let current_tsc = read_tsc();
                let last_tsc = self.last_notification_tsc.load(Ordering::Relaxed);
                let threshold = self.suppression_threshold_ms.load(Ordering::Relaxed);
                
                // TSCをms概算変換（3GHz想定）
                let elapsed_ms = (current_tsc.saturating_sub(last_tsc)) / 3_000_000;
                
                if elapsed_ms >= threshold {
                    self.notify_all(new_level);
                }
            }
        }
    }
    
    /// 全コールバックに通知
    fn notify_all(&self, level: PressureLevel) {
        let callbacks = self.callbacks.lock();
        
        for slot in callbacks.iter() {
            if let Some(callback) = slot {
                callback(level);
            }
        }
        
        self.notification_count.fetch_add(1, Ordering::Relaxed);
        self.last_notification_tsc.store(read_tsc(), Ordering::Relaxed);
    }
    
    /// 現在の圧力レベルを取得
    #[inline]
    pub fn current_level(&self) -> PressureLevel {
        match self.current_level.load(Ordering::Acquire) {
            0 => PressureLevel::Low,
            1 => PressureLevel::Medium,
            2 => PressureLevel::High,
            _ => PressureLevel::Critical,
        }
    }
    
    /// 圧力上昇中かどうか
    pub fn is_pressure_rising(&self) -> bool {
        let current = self.current_level.load(Ordering::Relaxed);
        let previous = self.previous_level.load(Ordering::Relaxed);
        current > previous
    }
    
    /// 通知抑制閾値を設定（ミリ秒）
    pub fn set_suppression_threshold(&self, ms: u64) {
        self.suppression_threshold_ms.store(ms, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> PressureNotifierStats {
        PressureNotifierStats {
            registered_callbacks: self.callback_count.load(Ordering::Relaxed),
            notification_count: self.notification_count.load(Ordering::Relaxed),
            level_change_count: self.level_change_count.load(Ordering::Relaxed),
            current_level: self.current_level(),
        }
    }
}

/// TSCを読み取る
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// 圧力通知統計
#[derive(Debug, Clone)]
pub struct PressureNotifierStats {
    pub registered_callbacks: usize,
    pub notification_count: u64,
    pub level_change_count: u64,
    pub current_level: PressureLevel,
}

/// グローバル Memory Pressure Notifier
pub static PRESSURE_NOTIFIER: MemoryPressureNotifier = MemoryPressureNotifier::new();

/// 圧力通知コールバックを登録
/// 
/// # Example
/// 
/// ```ignore
/// fn my_pressure_handler(level: PressureLevel) {
///     match level {
///         PressureLevel::High | PressureLevel::Critical => {
///             // キャッシュを縮小
///             shrink_my_cache();
///         }
///         _ => {}
///     }
/// }
/// 
/// register_pressure_callback(my_pressure_handler);
/// ```
pub fn register_pressure_callback(callback: PressureCallback) -> Option<usize> {
    PRESSURE_NOTIFIER.register(callback)
}

/// 圧力レベルを更新（PMM/Buddyから呼び出し）
pub fn update_memory_pressure(free_pages: usize, total_pages: usize) {
    // 空き率から圧力レベルを計算
    let free_percent = if total_pages > 0 {
        (free_pages * 100) / total_pages
    } else {
        0
    };
    
    let level = if free_percent <= 2 {
        PressureLevel::Critical
    } else if free_percent <= 5 {
        PressureLevel::High
    } else if free_percent <= 15 {
        PressureLevel::Medium
    } else {
        PressureLevel::Low
    };
    
    PRESSURE_NOTIFIER.update_pressure(level);
}

// ============================================================================
// Clock-Pro Algorithm (Phase 3 Optimization)
// ============================================================================
//
// Clock-Proは、従来のClock（Second Chance）アルゴリズムを改良した
// 高度なページ置換アルゴリズム。3つのハンド（Clock Hand）を使用して
// ページの「使用頻度」と「最近性」の両方を考慮する。
//
// 特徴:
// - Cold/Hot ページの区別
// - ワンタイムアクセスページの迅速な追い出し
// - ワーキングセットサイズの適応的推定
//
// 設計:
// - Hand Cold: 非参照Coldページを回収
// - Hand Hot: 非参照Hotページを降格
// - Hand Test: Testページを管理
//
// 参考: USENIX ATC'05 "CLOCK-Pro: An Effective Improvement of the CLOCK Replacement"
// ============================================================================

/// Clock-Pro ページ状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockProState {
    /// Cold: 最近追加されたページ（回収候補）
    Cold = 0,
    /// Hot: 頻繁にアクセスされるページ（保護）
    Hot = 1,
    /// Test: 回収されたが履歴を保持（再アクセス検知用）
    Test = 2,
}

/// Clock-Pro ページエントリ
#[derive(Debug)]
pub struct ClockProEntry {
    /// フレームインデックス
    pub frame: FrameIndex,
    /// ページ状態
    pub state: ClockProState,
    /// 参照ビット
    pub referenced: AtomicBool,
    /// Testからの昇格フラグ
    pub promoted_from_test: bool,
    /// 追加時刻（TSC）
    pub timestamp: u64,
}

impl ClockProEntry {
    pub fn new(frame: FrameIndex, state: ClockProState, timestamp: u64) -> Self {
        Self {
            frame,
            state,
            referenced: AtomicBool::new(false),
            promoted_from_test: false,
            timestamp,
        }
    }

    /// 参照ビットをテストしてクリア
    #[inline]
    pub fn test_clear_referenced(&self) -> bool {
        self.referenced.swap(false, Ordering::AcqRel)
    }

    /// 参照ビットをセット
    #[inline]
    pub fn set_referenced(&self) {
        self.referenced.store(true, Ordering::Release);
    }
}

/// Clock-Pro アルゴリズム実装
pub struct ClockProList {
    /// 循環リスト（Cold + Hot + Test）
    /// VecDequeを循環バッファとして使用
    pages: spin::Mutex<VecDeque<ClockProEntry>>,
    
    /// Hand Cold位置
    hand_cold: AtomicUsize,
    /// Hand Hot位置
    hand_hot: AtomicUsize,
    /// Hand Test位置
    hand_test: AtomicUsize,
    
    /// Cold ページ数
    cold_count: AtomicUsize,
    /// Hot ページ数
    hot_count: AtomicUsize,
    /// Test ページ数（メタデータのみ）
    test_count: AtomicUsize,
    
    /// ターゲット Cold ページ数（適応的に調整）
    target_cold: AtomicUsize,
    
    /// 統計: Cold回収数
    cold_evictions: AtomicU64,
    /// 統計: Hot降格数
    hot_demotions: AtomicU64,
    /// 統計: Test昇格数
    test_promotions: AtomicU64,
    /// 統計: ターゲット調整回数
    target_adjustments: AtomicU64,
}

impl ClockProList {
    pub const fn new() -> Self {
        Self {
            pages: spin::Mutex::new(VecDeque::new()),
            hand_cold: AtomicUsize::new(0),
            hand_hot: AtomicUsize::new(0),
            hand_test: AtomicUsize::new(0),
            cold_count: AtomicUsize::new(0),
            hot_count: AtomicUsize::new(0),
            test_count: AtomicUsize::new(0),
            target_cold: AtomicUsize::new(0),
            cold_evictions: AtomicU64::new(0),
            hot_demotions: AtomicU64::new(0),
            test_promotions: AtomicU64::new(0),
            target_adjustments: AtomicU64::new(0),
        }
    }

    /// 新しいページを追加（常にColdとして開始）
    pub fn add_page(&self, frame: FrameIndex, timestamp: u64) {
        let entry = ClockProEntry::new(frame, ClockProState::Cold, timestamp);
        
        let mut pages = self.pages.lock();
        pages.push_back(entry);
        self.cold_count.fetch_add(1, Ordering::Relaxed);
    }

    /// ページアクセスを記録
    pub fn access_page(&self, frame: FrameIndex) {
        let pages = self.pages.lock();
        
        for entry in pages.iter() {
            if entry.frame == frame {
                entry.set_referenced();
                break;
            }
        }
    }

    /// Hand Coldを進めて非参照Coldページを回収
    /// 
    /// # Returns
    /// 回収するフレームのリスト
    pub fn run_hand_cold(&self, target_count: usize) -> Vec<FrameIndex> {
        let mut pages = self.pages.lock();
        let mut victims = Vec::new();
        
        if pages.is_empty() {
            return victims;
        }
        
        let mut hand = self.hand_cold.load(Ordering::Relaxed) % pages.len().max(1);
        let mut scanned = 0;
        let max_scan = pages.len() * 2; // 最大2周
        
        while victims.len() < target_count && scanned < max_scan {
            if pages.is_empty() {
                break;
            }
            
            hand = hand % pages.len();
            
            if let Some(entry) = pages.get(hand) {
                match entry.state {
                    ClockProState::Cold => {
                        if entry.test_clear_referenced() {
                            // 参照あり → Hotに昇格
                            // (実際の昇格は後で処理)
                        } else {
                            // 参照なし → 回収
                            victims.push(entry.frame);
                            
                            // Testエントリに変換（履歴保持）
                            if let Some(mut removed) = pages.remove(hand) {
                                removed.state = ClockProState::Test;
                                pages.push_back(removed);
                                self.cold_count.fetch_sub(1, Ordering::Relaxed);
                                self.test_count.fetch_add(1, Ordering::Relaxed);
                            }
                            
                            self.cold_evictions.fetch_add(1, Ordering::Relaxed);
                            continue; // handは同じ位置で次の要素を見る
                        }
                    }
                    ClockProState::Hot => {
                        // Hand Coldはスキップ
                    }
                    ClockProState::Test => {
                        // Test: 期限切れなら削除
                        // (簡略化: ここでは何もしない)
                    }
                }
            }
            
            hand = (hand + 1) % pages.len().max(1);
            scanned += 1;
        }
        
        self.hand_cold.store(hand, Ordering::Relaxed);
        victims
    }

    /// Hand Hotを進めて非参照Hotページを降格
    pub fn run_hand_hot(&self, scan_count: usize) -> usize {
        let mut pages = self.pages.lock();
        
        if pages.is_empty() {
            return 0;
        }
        
        let mut hand = self.hand_hot.load(Ordering::Relaxed) % pages.len().max(1);
        let mut demoted = 0;
        
        for _ in 0..scan_count {
            if pages.is_empty() {
                break;
            }
            
            hand = hand % pages.len();
            
            if let Some(entry) = pages.get_mut(hand) {
                if entry.state == ClockProState::Hot {
                    if entry.test_clear_referenced() {
                        // 参照あり → そのまま維持
                    } else {
                        // 参照なし → Coldに降格
                        entry.state = ClockProState::Cold;
                        self.hot_count.fetch_sub(1, Ordering::Relaxed);
                        self.cold_count.fetch_add(1, Ordering::Relaxed);
                        self.hot_demotions.fetch_add(1, Ordering::Relaxed);
                        demoted += 1;
                    }
                }
            }
            
            hand = (hand + 1) % pages.len().max(1);
        }
        
        self.hand_hot.store(hand, Ordering::Relaxed);
        demoted
    }

    /// Testエントリにヒットした場合の処理
    /// 
    /// Testにあるページが再度アクセスされた場合、
    /// そのページはワーキングセットの一部とみなしてHotに昇格する。
    /// また、ターゲットCold数を増加させる。
    pub fn handle_test_hit(&self, frame: FrameIndex) -> bool {
        let mut pages = self.pages.lock();
        
        for entry in pages.iter_mut() {
            if entry.frame == frame && entry.state == ClockProState::Test {
                // Test → Hot昇格
                entry.state = ClockProState::Hot;
                entry.promoted_from_test = true;
                
                self.test_count.fetch_sub(1, Ordering::Relaxed);
                self.hot_count.fetch_add(1, Ordering::Relaxed);
                self.test_promotions.fetch_add(1, Ordering::Relaxed);
                
                // ターゲットCold数を増加（ワーキングセット拡大の兆候）
                let old_target = self.target_cold.fetch_add(1, Ordering::Relaxed);
                if old_target < 1000 { // 上限
                    self.target_adjustments.fetch_add(1, Ordering::Relaxed);
                }
                
                return true;
            }
        }
        
        false
    }

    /// 統計情報を取得
    pub fn stats(&self) -> ClockProStats {
        ClockProStats {
            cold_pages: self.cold_count.load(Ordering::Relaxed),
            hot_pages: self.hot_count.load(Ordering::Relaxed),
            test_pages: self.test_count.load(Ordering::Relaxed),
            target_cold: self.target_cold.load(Ordering::Relaxed),
            cold_evictions: self.cold_evictions.load(Ordering::Relaxed),
            hot_demotions: self.hot_demotions.load(Ordering::Relaxed),
            test_promotions: self.test_promotions.load(Ordering::Relaxed),
        }
    }

    /// リストのサイズ
    pub fn len(&self) -> usize {
        let pages = self.pages.lock();
        pages.len()
    }

    /// リストが空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Clock-Pro統計
#[derive(Debug, Clone, Copy)]
pub struct ClockProStats {
    /// Cold ページ数
    pub cold_pages: usize,
    /// Hot ページ数
    pub hot_pages: usize,
    /// Test エントリ数
    pub test_pages: usize,
    /// ターゲット Cold 数
    pub target_cold: usize,
    /// Cold 回収数
    pub cold_evictions: u64,
    /// Hot 降格数
    pub hot_demotions: u64,
    /// Test 昇格数
    pub test_promotions: u64,
}

/// グローバル Clock-Pro リスト（NUMAノードごと）
pub static CLOCK_PRO_LISTS: [ClockProList; 8] = {
    const INIT: ClockProList = ClockProList::new();
    [INIT; 8]
};

/// Clock-Proにページを追加
pub fn clock_pro_add_page(frame: FrameIndex, node: usize) {
    let node_idx = node.min(7);
    CLOCK_PRO_LISTS[node_idx].add_page(frame, read_tsc());
}

/// Clock-Proでページアクセスを記録
pub fn clock_pro_access_page(frame: FrameIndex, node: usize) {
    let node_idx = node.min(7);
    CLOCK_PRO_LISTS[node_idx].access_page(frame);
}

/// Clock-Proで回収対象ページを取得
pub fn clock_pro_reclaim(node: usize, target_count: usize) -> Vec<FrameIndex> {
    let node_idx = node.min(7);
    
    // まずHand Hotでスキャン
    CLOCK_PRO_LISTS[node_idx].run_hand_hot(target_count * 2);
    
    // Hand Coldで回収
    CLOCK_PRO_LISTS[node_idx].run_hand_cold(target_count)
}

/// Clock-Pro統計を取得
pub fn clock_pro_stats(node: usize) -> ClockProStats {
    let node_idx = node.min(7);
    CLOCK_PRO_LISTS[node_idx].stats()
}

// ============================================================================
// Phase 5: 6.3 Swap Prefetch 基盤
// ============================================================================
//
// ## 概要
//
// ページフォールトが発生する前に、予測的にスワップアウトされたページを
// 先読みする基盤機能。以下のヒューリスティクスを使用：
//
// 1. **Spatial Locality**: 連続アドレスのページを先読み
// 2. **Temporal Locality**: 最近アクセスされたVMAの他ページを先読み
// 3. **Working Set Prediction**: 過去のワーキングセットパターンを学習
//
// ## 設計
//
// - `SwapPrefetchHint`: 先読みヒント情報
// - `SwapPrefetcher`: 先読みロジック
// - `PrefetchStats`: 効果測定用統計
//
// ## 注意
//
// Rany_OSはExokernelベースのため、実際のスワップはユーザー空間ドメインで
// 管理される。この基盤はカーネル側のヒント生成とインターフェースを提供する。
//
// ============================================================================

/// スワップ先読みヒント
#[derive(Debug, Clone, Copy)]
pub struct SwapPrefetchHint {
    /// フォールトしたアドレス
    pub fault_addr: u64,
    /// 先読み対象の開始ページ番号
    pub prefetch_start: u64,
    /// 先読みするページ数
    pub prefetch_count: usize,
    /// 先読みの優先度（0-255）
    pub priority: u8,
    /// 先読みの理由
    pub reason: PrefetchReason,
}

/// 先読みの理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrefetchReason {
    /// 空間的局所性（連続アクセス）
    SpatialLocality = 0,
    /// 時間的局所性（最近のアクセスパターン）
    TemporalLocality = 1,
    /// ワーキングセット予測
    WorkingSetPrediction = 2,
    /// 明示的なヒント（アプリケーションから）
    ExplicitHint = 3,
}

/// 先読みウィンドウサイズ
const PREFETCH_WINDOW_SIZE: usize = 8;

/// 先読み履歴サイズ
const PREFETCH_HISTORY_SIZE: usize = 32;

/// スワップ先読み器
pub struct SwapPrefetcher {
    /// 最近のフォールトアドレス履歴
    fault_history: spin::Mutex<VecDeque<u64>>,
    /// 先読み成功カウンタ
    hits: AtomicU64,
    /// 先読み失敗（不要だった）カウンタ
    misses: AtomicU64,
    /// 総先読みページ数
    total_prefetched: AtomicU64,
    /// 有効フラグ
    enabled: AtomicBool,
    /// デフォルトの先読みページ数
    default_prefetch_count: AtomicUsize,
}

impl SwapPrefetcher {
    pub const fn new() -> Self {
        Self {
            fault_history: spin::Mutex::new(VecDeque::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            total_prefetched: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            default_prefetch_count: AtomicUsize::new(PREFETCH_WINDOW_SIZE),
        }
    }
    
    /// 先読み機能を有効/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }
    
    /// 先読み機能が有効か
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    
    /// デフォルト先読みページ数を設定
    pub fn set_default_prefetch_count(&self, count: usize) {
        self.default_prefetch_count.store(count.min(32).max(1), Ordering::Release);
    }
    
    /// ページフォールト時に先読みヒントを生成
    /// 
    /// # Arguments
    /// * `fault_addr` - フォールトしたアドレス
    /// * `is_sequential` - 直前のフォールトから連続しているか
    /// 
    /// # Returns
    /// 先読みすべきページのヒント（先読み不要の場合はNone）
    pub fn generate_hint(&self, fault_addr: u64, is_sequential: bool) -> Option<SwapPrefetchHint> {
        if !self.is_enabled() {
            return None;
        }
        
        let page_addr = fault_addr & !0xFFF; // 4KB境界にアライン
        let page_num = page_addr >> 12;
        
        // フォールト履歴に追加
        {
            let mut history = self.fault_history.lock();
            history.push_back(page_addr);
            if history.len() > PREFETCH_HISTORY_SIZE {
                history.pop_front();
            }
        }
        
        let prefetch_count = self.default_prefetch_count.load(Ordering::Relaxed);
        
        // 連続アクセスの場合は空間的局所性を利用
        if is_sequential {
            return Some(SwapPrefetchHint {
                fault_addr,
                prefetch_start: page_num + 1, // 次のページから
                prefetch_count,
                priority: 200, // 高優先度
                reason: PrefetchReason::SpatialLocality,
            });
        }
        
        // 履歴からパターンを検出
        if let Some(hint) = self.detect_access_pattern(page_addr) {
            return Some(hint);
        }
        
        // デフォルト: 近傍ページを先読み
        Some(SwapPrefetchHint {
            fault_addr,
            prefetch_start: page_num.saturating_sub((prefetch_count / 2) as u64),
            prefetch_count,
            priority: 100, // 中優先度
            reason: PrefetchReason::TemporalLocality,
        })
    }
    
    /// アクセスパターンを検出
    fn detect_access_pattern(&self, current_addr: u64) -> Option<SwapPrefetchHint> {
        let history = self.fault_history.lock();
        
        if history.len() < 3 {
            return None;
        }
        
        // ストライドパターンを検出
        let recent: Vec<u64> = history.iter().rev().take(4).cloned().collect();
        if recent.len() >= 3 {
            let stride1 = recent[0].wrapping_sub(recent[1]) as i64;
            let stride2 = recent[1].wrapping_sub(recent[2]) as i64;
            
            // 同じストライドで連続している場合
            if stride1 == stride2 && stride1.abs() <= 16 * 4096 {
                let next_addr = if stride1 >= 0 {
                    current_addr.wrapping_add(stride1 as u64)
                } else {
                    current_addr.wrapping_sub((-stride1) as u64)
                };
                
                return Some(SwapPrefetchHint {
                    fault_addr: current_addr,
                    prefetch_start: next_addr >> 12,
                    prefetch_count: 4, // ストライドパターンは少数の先読み
                    priority: 180,
                    reason: PrefetchReason::WorkingSetPrediction,
                });
            }
        }
        
        None
    }
    
    /// 先読み成功を記録
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 先読み失敗を記録
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 先読み実行を記録
    pub fn record_prefetch(&self, page_count: usize) {
        self.total_prefetched.fetch_add(page_count as u64, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> SwapPrefetchStats {
        SwapPrefetchStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            total_prefetched: self.total_prefetched.load(Ordering::Relaxed),
            enabled: self.is_enabled(),
        }
    }
    
    /// ヒット率を計算（%）
    pub fn hit_rate(&self) -> f32 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            (hits as f32 / total as f32) * 100.0
        }
    }
}

/// スワップ先読み統計
#[derive(Debug, Clone, Copy)]
pub struct SwapPrefetchStats {
    /// 先読み成功数
    pub hits: u64,
    /// 先読み失敗数
    pub misses: u64,
    /// 総先読みページ数
    pub total_prefetched: u64,
    /// 有効かどうか
    pub enabled: bool,
}

/// グローバルスワップ先読み器
pub static SWAP_PREFETCHER: SwapPrefetcher = SwapPrefetcher::new();

/// ページフォールト時の先読みヒント生成（便利関数）
pub fn prefetch_hint_on_fault(fault_addr: u64, is_sequential: bool) -> Option<SwapPrefetchHint> {
    SWAP_PREFETCHER.generate_hint(fault_addr, is_sequential)
}

/// 先読み統計を取得
pub fn swap_prefetch_stats() -> SwapPrefetchStats {
    SWAP_PREFETCHER.stats()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_watermarks_calculation() {
        let wm = Watermarks::calculate(100000);
        assert!(wm.high > wm.low);
        assert!(wm.low > wm.min);
        assert!(wm.min > wm.critical);
    }
    
    #[test]
    fn test_pressure_level() {
        let wm = Watermarks::calculate(10000);
        
        assert_eq!(wm.pressure_level(10000), MemoryPressure::None);
        assert_eq!(wm.pressure_level(wm.low - 1), MemoryPressure::Background);
        assert_eq!(wm.pressure_level(wm.min - 1), MemoryPressure::Direct);
        assert_eq!(wm.pressure_level(wm.critical - 1), MemoryPressure::Critical);
    }
    
    #[test]
    fn test_lru_list_add() {
        let lru = LruList::new();
        let entry = LruPageEntry::new(FrameIndex::new(100), PageType::Anonymous, 0);
        
        lru.add_to_active(entry);
        assert_eq!(lru.active_count(), 1);
        assert_eq!(lru.inactive_count(), 0);
    }
}
