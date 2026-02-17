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
mod _split_1;
use _split_1::*;
#[cfg(any(test, feature = "qemu-test-export"))]
use core::sync::atomic::AtomicU8;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use crate::sync::IrqMutex;

use super::types::FrameIndex;
use super::types::AddressUnit;
use super::types::FixedVec;

/// 一度に若返らせる最大エントリ数
const MAX_REJUVENATE_BATCH: usize = 64;

// ============================================================================
// PageVec - Batched LRU Updates (Linux pagevec equivalent)
// ============================================================================

/// PageVec容量（Linuxは15、キャッシュライン最適化）
const PAGEVEC_SIZE: usize = 15;

/// 最大CPU数
const MAX_CPUS: usize = 256;

/// Per-CPU PageVec for batched LRU additions
/// 
/// ## 概要
/// 
/// LRUリストへの追加をPer-CPUでバッファリングし、一定数溜まったら
/// 一括でフラッシュする。これにより、ロック取得回数を最大15分の1に削減。
/// 
/// ## 使用パターン
/// 
/// ```ignore
/// // ページをバッファに追加
/// pagevec_add(cpu_id, entry);
/// 
/// // バッファが満杯なら自動フラッシュ
/// // または明示的にフラッシュ
/// pagevec_lru_add_flush(cpu_id);
/// ```
/// 
/// ## パフォーマンス
/// 
/// - ロック取得: 15回のadd → 1回のロック取得
/// - キャッシュ効率: エントリがL1に載った状態でまとめて処理
#[repr(C, align(64))]
pub struct PageVec {
    /// バッファされたエントリ（フレームインデックス + メタデータ）
    entries: [PageVecEntry; PAGEVEC_SIZE],
    /// 現在のエントリ数
    count: usize,
    /// 統計: フラッシュ回数
    flush_count: u64,
    /// 統計: 追加されたページ総数
    total_added: u64,
}

/// PageVec内のエントリ（軽量版）
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PageVecEntry {
    /// 物理フレームインデックス
    pub frame: u64,
    /// ページタイプ (PageType as u8)
    pub page_type: u8,
    /// NUMAノードID
    pub numa_node: u8,
    /// 追加先 (0 = Active, 1 = Inactive)
    pub target_list: u8,
    /// Reserved padding
    _pad: u8,
    /// タイムスタンプ
    pub timestamp: u64,
}

impl PageVecEntry {
    pub const fn empty() -> Self {
        Self {
            frame: 0,
            page_type: 0,
            numa_node: 0,
            target_list: 0,
            _pad: 0,
            timestamp: 0,
        }
    }

    pub fn new(frame: FrameIndex, page_type: PageType, numa_node: u8, timestamp: u64) -> Self {
        Self {
            frame: frame.as_u64(),
            page_type: page_type as u8,
            numa_node,
            target_list: 0, // Active by default
            _pad: 0,
            timestamp,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.frame == 0
    }

    pub fn frame_index(&self) -> FrameIndex {
        FrameIndex::from_phys_addr(self.frame)
    }

    pub fn page_type(&self) -> PageType {
        match self.page_type {
            0 => PageType::Anonymous,
            1 => PageType::FileBacked,
            2 => PageType::Slab,
            _ => PageType::Kernel,
        }
    }
}

impl PageVec {
    pub const fn new() -> Self {
        Self {
            entries: [PageVecEntry::empty(); PAGEVEC_SIZE],
            count: 0,
            flush_count: 0,
            total_added: 0,
        }
    }

    /// エントリを追加（満杯ならfalseを返す）
    #[inline]
    pub fn add(&mut self, entry: PageVecEntry) -> bool {
        if self.count >= PAGEVEC_SIZE {
            return false;
        }
        self.entries[self.count] = entry;
        self.count += 1;
        self.total_added += 1;
        true
    }

    /// バッファが満杯か
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= PAGEVEC_SIZE
    }

    /// バッファが空か
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// 現在のエントリ数
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// バッファをフラッシュしてLRUリストに追加
    pub fn flush(&mut self, lru_lists: &[MglruList; 8]) {
        if self.count == 0 {
            return;
        }

        // Phase 6.2: Batch pages per NUMA node for reduced lock contention
        for node_idx in 0..8 {
             for i in 0..self.count {
                 let entry = &self.entries[i];
                 if entry.is_empty() { continue; }
                 
                 let e_node = (entry.numa_node as usize).min(7);
                 if e_node != node_idx { continue; }

                 // Check for tail pages early
                 if crate::mm::page_flags::test_flag(FrameIndex::from_phys_addr(entry.frame), crate::mm::page_flags::PageMetaFlags::CompoundTail) {
                     continue;
                 }

                 let mglru_entry = MglruEntry::new(
                     entry.frame_index(),
                     entry.page_type(),
                     entry.timestamp,
                 );

                 // Active/Inactive distinction is handled by Generation 0 (Active-like)
                 lru_lists[node_idx].add_page(mglru_entry);
             }
        }

        self.flush_count += 1;
        self.count = 0;
    }

    /// 統計情報
    pub fn stats(&self) -> PageVecStats {
        PageVecStats {
            current_count: self.count,
            flush_count: self.flush_count,
            total_added: self.total_added,
        }
    }
}

/// PageVec統計
#[derive(Debug, Clone, Copy, Default)]
pub struct PageVecStats {
    pub current_count: usize,
    pub flush_count: u64,
    pub total_added: u64,
}

/// Per-CPU PageVec配列
static mut PER_CPU_PAGEVEC: [PageVec; MAX_CPUS] = {
    const INIT: PageVec = PageVec::new();
    [INIT; MAX_CPUS]
};

/// 現在のCPUのPageVecにエントリを追加
/// 
/// # Safety
/// 割り込み禁止状態で呼び出すこと
#[inline]
pub unsafe fn pagevec_add(cpu_id: usize, entry: PageVecEntry) -> bool {
    let pv = &mut PER_CPU_PAGEVEC[cpu_id.min(MAX_CPUS - 1)];
    pv.add(entry)
}

/// 現在のCPUのPageVecが満杯か
#[inline]
pub fn pagevec_is_full(cpu_id: usize) -> bool {
    unsafe {
        PER_CPU_PAGEVEC[cpu_id.min(MAX_CPUS - 1)].is_full()
    }
}

/// 現在のCPUのPageVecをフラッシュ
/// 
/// # Safety
/// 割り込み禁止状態で呼び出すこと
pub unsafe fn pagevec_lru_add_flush(cpu_id: usize) {
    let pv = &mut PER_CPU_PAGEVEC[cpu_id.min(MAX_CPUS - 1)];
    pv.flush(&PAGE_RECLAIM.lru_lists);
}

/// 全CPUのPageVecをフラッシュ（kswapdから呼び出し）
pub fn pagevec_flush_all() {
    for cpu_id in 0..MAX_CPUS {
        unsafe {
            let pv = &mut PER_CPU_PAGEVEC[cpu_id];
            if !pv.is_empty() {
                pv.flush(&PAGE_RECLAIM.lru_lists);
            }
        }
    }
}

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

// Legacy LruPageEntry removed.
// ============================================================================
// LRU List (per NUMA node)
// ============================================================================

// ============================================================================
// Multi-Generational LRU (MGLRU) - Linux 6.1+ inspired
// ============================================================================
//
// MGLRU は従来の Active/Inactive 二分法を超え、4世代のリストで
// より精密なページ年齢追跡を実現する。
//
// ## 世代 (Generation)
//
// - Gen 0: 最も新しいページ（直近でアクセス）
// - Gen 1: 比較的新しいページ
// - Gen 2: 比較的古いページ
// - Gen 3: 最も古いページ（回収候補）
//
// ## 昇格/降格ロジック
//
// - アクセスビット検出 → 世代を0にリセット
// - aging cycle → 各ページの世代を+1
// - Gen 3 の unreferenced ページを回収
//
// ## 参考
//
// - Linux mm/vmscan.c (Multi-Gen LRU)
// - https://lwn.net/Articles/856931/
// ============================================================================

/// MGLRU世代数
pub const MGLRU_GENERATIONS: usize = 4;

/// MGLRU世代のインデックス型
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MglruGen {
    /// 世代0: 最も新しい（最近アクセス）
    Gen0 = 0,
    /// 世代1: 比較的新しい
    Gen1 = 1,
    /// 世代2: 比較的古い
    Gen2 = 2,
    /// 世代3: 最も古い（回収候補）
    Gen3 = 3,
}

impl MglruGen {
    /// 世代番号から変換
    #[inline]
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Gen0,
            1 => Self::Gen1,
            2 => Self::Gen2,
            _ => Self::Gen3,
        }
    }
    
    /// 次の世代（古い方向へ）
    #[inline]
    pub fn age(self) -> Self {
        match self {
            Self::Gen0 => Self::Gen1,
            Self::Gen1 => Self::Gen2,
            Self::Gen2 => Self::Gen3,
            Self::Gen3 => Self::Gen3, // 既に最も古い
        }
    }
    
    /// 若返り（アクセス検出時）
    #[inline]
    pub fn rejuvenate(self) -> Self {
        Self::Gen0
    }
    
    /// 数値として取得
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
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

/// Reclaim attempt result for a single candidate page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimOutcome {
    /// Page was freed immediately in reclaim context.
    FreedNow,
    /// Reclaim deferred to async worker; completion is tracked separately.
    DeferredAsync,
    /// Page was requeued to LRU and not reclaimed.
    Requeued,
    /// Reclaim path is blocked by safety policy (unsafe eviction disabled).
    BlockedUnsafe,
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

/// MGLRU用ページエントリ
#[derive(Debug)]
pub struct MglruEntry {
    /// 物理フレームインデックス
    pub frame: FrameIndex,
    /// ページタイプ
    pub page_type: PageType,
    /// 現在の世代
    pub generation: MglruGen,
    /// 参照ビット（世代更新時にチェック）
    pub referenced: AtomicBool,
    /// 追加時刻
    pub add_time: u64,
    /// フラグ
    pub flags: LruFlags,
}

#[derive(Debug, Clone, Copy)]
struct PendingAsyncMeta {
    frame: FrameIndex,
    page_type: PageType,
    generation: MglruGen,
    flags: LruFlags,
    node: u8,
}

impl MglruEntry {
    /// 新しいエントリを作成（Gen0で開始）
    pub fn new(frame: FrameIndex, page_type: PageType, timestamp: u64) -> Self {
        Self {
            frame,
            page_type,
            generation: MglruGen::Gen0,
            referenced: AtomicBool::new(true),
            add_time: timestamp,
            flags: LruFlags::NONE,
        }
    }
    
    /// 参照ビットをテスト＆クリア
    #[inline]
    pub fn test_clear_referenced(&self) -> bool {
        self.referenced.swap(false, Ordering::AcqRel)
    }
    
    /// 回収可能か
    pub fn is_reclaimable(&self) -> bool {
        !self.flags.contains(LruFlags::LOCKED)
            && !self.flags.contains(LruFlags::UNEVICTABLE)
            && !self.flags.contains(LruFlags::MLOCKED)
            && !self.flags.contains(LruFlags::WRITEBACK)
    }
}

/// MGLRU統計
#[derive(Debug, Clone, Copy, Default)]
pub struct MglruStats {
    pub gen_sizes: [usize; MGLRU_GENERATIONS],
    pub aging_cycles: u64,
    pub reclaimed: u64,
    pub rejuvenated: u64,
}

/// Multi-Generational LRU リスト
/// 
/// 世代ごとに分離されたリストを管理し、効率的なaging/reclaimを実現。
pub struct MglruList {
    /// 世代ごとのページリスト [Gen0, Gen1, Gen2, Gen3]
    generations: [IrqMutex<VecDeque<MglruEntry>>; MGLRU_GENERATIONS],
    /// 各世代のサイズ
    gen_sizes: [AtomicUsize; MGLRU_GENERATIONS],
    /// 現在のaging generation（次のaging対象）
    aging_gen: AtomicUsize,
    /// 統計: aging cycle回数
    aging_cycles: AtomicU64,
    /// 統計: 回収ページ数
    reclaimed: AtomicU64,
    /// 統計: 若返り回数
    rejuvenated: AtomicU64,
}

impl MglruList {
    /// 新しいMGLRUリストを作成
    pub const fn new() -> Self {
        const EMPTY: IrqMutex<VecDeque<MglruEntry>> = IrqMutex::new(VecDeque::new());
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            generations: [EMPTY; MGLRU_GENERATIONS],
            gen_sizes: [ZERO; MGLRU_GENERATIONS],
            aging_gen: AtomicUsize::new(0),
            aging_cycles: AtomicU64::new(0),
            reclaimed: AtomicU64::new(0),
            rejuvenated: AtomicU64::new(0),
        }
    }
    
    /// 新しいページを追加（Gen0へ）
    pub fn add_page(&self, entry: MglruEntry) {
        self.add_page_to_generation(entry, 0);
    }

    /// Add a page to a specific generation list.
    pub fn add_page_to_generation(&self, entry: MglruEntry, generation_idx: usize) {
        let idx = generation_idx.min(MGLRU_GENERATIONS - 1);
        let mut target = self.generations[idx].lock();
        target.push_back(entry);
        self.gen_sizes[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// 単一世代のagingを実行する
    ///
    /// `gen_idx` のエントリを走査し:
    /// - 参照ビットが立っているページ → Gen0 に若返り
    /// - それ以外 → gen_idx + 1 に老化
    ///
    /// 返り値: (aged, rejuvenated)
    fn age_single_generation(&self, gen_idx: usize) -> (usize, usize) {
        let target_gen_idx = gen_idx + 1;
        if target_gen_idx >= MGLRU_GENERATIONS {
            return (0, 0);
        }

        let mut aged = 0usize;
        let mut rejuvenated = 0usize;

        let mut source = self.generations[gen_idx].lock();
        let count = source.len();
        let mut remaining = VecDeque::with_capacity(count);
        let mut to_rejuvenate = Vec::new();
        let mut to_age = Vec::new();

        while let Some(mut entry) = source.pop_front() {
            if entry.test_clear_referenced() {
                // 参照ビットあり → Gen0に若返り
                entry.generation = MglruGen::Gen0;
                to_rejuvenate.push(entry);
                rejuvenated += 1;
            } else {
                // 参照ビットなし → 次の世代へ老化
                entry.generation = entry.generation.age();
                to_age.push(entry);
                aged += 1;
            }
        }
        drop(source);

        // Gen0に若返りページを追加
        if !to_rejuvenate.is_empty() && gen_idx != 0 {
            let mut gen0 = self.generations[0].lock();
            for entry in to_rejuvenate {
                gen0.push_back(entry);
            }
        } else {
            // gen_idx == 0 の場合、若返りはそのまま元に戻す
            remaining.extend(to_rejuvenate);
        }

        // 次の世代に老化ページを追加
        let mut target = self.generations[target_gen_idx].lock();
        for entry in to_age {
            target.push_back(entry);
        }
        drop(target);

        // 残りページを元の世代に戻す
        if !remaining.is_empty() {
            let mut source = self.generations[gen_idx].lock();
            while let Some(entry) = remaining.pop_front() {
                source.push_back(entry);
            }
        }

        (aged, rejuvenated)
    }
    
    /// Aging cycle: 全世代を1つずつ古くする
    /// 
    /// 参照ビットが立っているページはGen0に戻す（若返り）
    pub fn run_aging_cycle(&self) -> MglruAgingStats {
        let mut aged = 0usize;
        let mut rejuvenated = 0usize;
        
        // Gen2 → Gen3, Gen1 → Gen2, Gen0 → Gen1 の順で処理
        // (逆順で処理して世代間の移動を効率化)
        for gen_idx in (0..MGLRU_GENERATIONS - 1).rev() {
            let (gen_aged, gen_rejuvenated) = self.age_single_generation(gen_idx);
            aged += gen_aged;
            rejuvenated += gen_rejuvenated;
        }
        
        // サイズを再計算
        for (i, generation) in self.generations.iter().enumerate() {
            let len = generation.lock().len();
            self.gen_sizes[i].store(len, Ordering::Relaxed);
        }
        
        self.aging_cycles.fetch_add(1, Ordering::Relaxed);
        self.rejuvenated.fetch_add(rejuvenated as u64, Ordering::Relaxed);
        
        MglruAgingStats { aged, rejuvenated }
    }
    
    /// Gen3から回収可能なページを取得
    pub fn reclaim_from_oldest(&self, count: usize) -> Vec<MglruEntry> {
        let mut gen3 = self.generations[3].lock();
        let mut victims = Vec::with_capacity(count.min(gen3.len()));
        
        let mut i = 0;
        while victims.len() < count && i < gen3.len() {
            if let Some(entry) = gen3.get(i) {
                if entry.is_reclaimable() && !entry.referenced.load(Ordering::Relaxed) {
                    if let Some(e) = gen3.remove(i) {
                        victims.push(e);
                        continue;
                    }
                }
            }
            i += 1;
        }
        
        self.gen_sizes[3].fetch_sub(victims.len(), Ordering::Relaxed);
        
        victims
    }

    /// Account successfully reclaimed pages.
    pub fn account_reclaimed(&self, count: usize) {
        self.reclaimed.fetch_add(count as u64, Ordering::Relaxed);
    }

    /// 統計を取得
    pub fn stats(&self) -> MglruStats {
        let mut sizes = [0; MGLRU_GENERATIONS];
        for i in 0..MGLRU_GENERATIONS {
            sizes[i] = self.gen_sizes[i].load(Ordering::Relaxed);
        }
        MglruStats {
            gen_sizes: sizes,
            aging_cycles: self.aging_cycles.load(Ordering::Relaxed),
            reclaimed: self.reclaimed.load(Ordering::Relaxed),
            rejuvenated: self.rejuvenated.load(Ordering::Relaxed),
        }
    }
    
    /// 各世代のサイズを取得
    pub fn generation_sizes(&self) -> [usize; MGLRU_GENERATIONS] {
        [
            self.gen_sizes[0].load(Ordering::Relaxed),
            self.gen_sizes[1].load(Ordering::Relaxed),
            self.gen_sizes[2].load(Ordering::Relaxed),
            self.gen_sizes[3].load(Ordering::Relaxed),
        ]
    }
}

/// MGLRU Aging統計
#[derive(Debug, Clone, Copy)]
pub struct MglruAgingStats {
    /// 世代が進んだページ数
    pub aged: usize,
    /// 若返ったページ数
    pub rejuvenated: usize,
}



// ============================================================================
// MGLRU Dynamic Tuning (Phase 1.2)
// ============================================================================
//
// MGLRU の aging interval を動的に調整し、ワークロードに適応する。
//
// ## 調整の指針
//
// - Refault rate が高い → aging interval を延長（ページを長く保持）
// - Refault rate が低い → aging interval を短縮（より積極的に回収）
// - メモリ圧が高い → aging interval を短縮（緊急回収モード）
//
// ============================================================================

/// MGLRU 動的チューニングコントローラ
#[derive(Debug)]
pub struct MglruTuningController {
    /// 現在の aging interval (ナノ秒)
    aging_interval_ns: AtomicU64,
    /// 最小 aging interval (100ms)
    min_interval_ns: u64,
    /// 最大 aging interval (10s)
    max_interval_ns: u64,
    /// 最後の aging 時刻
    last_aging_time_ns: AtomicU64,
    /// 最後の調整時の refault 統計
    last_workingset_refaults: AtomicU64,
    last_normal_refaults: AtomicU64,
    /// 調整回数
    adjustments: AtomicU64,
    /// interval 増加回数
    interval_increases: AtomicU64,
    /// interval 減少回数
    interval_decreases: AtomicU64,
}
