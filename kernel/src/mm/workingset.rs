// ============================================================================
// kernel/src/mm/workingset.rs - Workingset Refault Detection
// ============================================================================
//
// ## 概要
//
// evict されたページが再度フォルトした際に、そのページが working set 内か
// どうかを判定する仕組み。Working set 内と判定されたページは即座に Active
// LRU に昇格させることで、LRU の精度を大幅に向上させる。
//
// ## アルゴリズム
//
// 1. ページが evict される際、現在の LRU 時刻を shadow entry として記録
// 2. 同じページが再度 page fault した際 (refault)、shadow を参照
// 3. refault distance (現在時刻 - eviction時刻) が閾値以下なら working set
// 4. Working set 内なら Active LRU に直接追加 (通常は Inactive から開始)
//
// ## 参考
//
// - Linux kernel mm/workingset.c
// - "Thrashing Mitigation" and "Refault Distance" papers
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use super::types::FrameIndex;
use super::page_reclaim::{MglruGen, MGLRU_GENERATIONS};

// ============================================================================
// Configuration
// ============================================================================

/// Shadow entry の最大保持数 (evict したページのメタデータ)
/// メモリオーバーヘッドとのトレードオフ
const MAX_SHADOW_ENTRIES: usize = 65536;

/// Refault distance 閾値 (LRU ticks)
/// この閾値より近い refault は working set 内と判定
const REFAULT_DISTANCE_THRESHOLD: u64 = 1000;

/// 非アクティブリストのサイズ推定用カウンタ更新間隔
const INACTIVE_SIZE_UPDATE_INTERVAL: u64 = 64;

// ============================================================================
// Shadow Entry
// ============================================================================

/// Evict されたページのシャドウ情報
///
/// ページが evict される際に、このエントリが shadow slot に格納される。
/// 再 fault 時にこの情報を参照して working set 判定を行う。
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ShadowEntry {
    /// Evict された時刻 (LRU ticks or TSC)
    eviction_timestamp: u64,
    /// Evict 時の MGLRU 世代
    generation: u8,
    /// ページタイプ (Anonymous=0, FileBacked=1)
    page_type: u8,
    /// NUMA ノード
    numa_node: u8,
    /// 予約
    _reserved: u8,
}

impl ShadowEntry {
    /// 空のエントリ (未使用スロット)
    pub const EMPTY: Self = Self {
        eviction_timestamp: 0,
        generation: 0,
        page_type: 0,
        numa_node: 0,
        _reserved: 0,
    };

    /// 新しい shadow entry を作成
    #[inline]
    pub fn new(eviction_timestamp: u64, generation: MglruGen, page_type: u8, numa_node: u8) -> Self {
        Self {
            eviction_timestamp,
            generation: generation.as_u8(),
            page_type,
            numa_node,
            _reserved: 0,
        }
    }

    /// 有効なエントリかどうか
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.eviction_timestamp != 0
    }

    /// Eviction タイムスタンプを取得
    #[inline]
    pub fn eviction_timestamp(&self) -> u64 {
        self.eviction_timestamp
    }

    /// MGLRU 世代を取得
    #[inline]
    pub fn generation(&self) -> MglruGen {
        MglruGen::from_u8(self.generation)
    }

    /// NUMA ノードを取得
    #[inline]
    pub fn numa_node(&self) -> u8 {
        self.numa_node
    }
}

// ============================================================================
// Refault Result
// ============================================================================

/// Refault 判定結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefaultResult {
    /// Working set 内: Active LRU に直接追加すべき
    WorkingSet {
        /// 推奨開始世代 (Gen0 = 最もホット)
        target_generation: MglruGen,
    },
    /// Working set 外: 通常通り Inactive から開始
    NotWorkingSet,
    /// Shadow entry が見つからない (初回 fault 等)
    NoShadow,
}

// ============================================================================
// Shadow Table (Hash-based)
// ============================================================================

use core::cell::UnsafeCell;

/// Shadow entry 格納用スロット
#[repr(C)]
struct ShadowSlot {
    /// フレームキー (MSB=valid flag)
    key: AtomicU64,
    /// Shadow entry (UnsafeCell for interior mutability)
    entry: UnsafeCell<ShadowEntry>,
}

impl ShadowSlot {
    const fn new() -> Self {
        Self {
            key: AtomicU64::new(0),
            entry: UnsafeCell::new(ShadowEntry::EMPTY),
        }
    }
}

// SAFETY: ShadowSlot is only accessed with proper synchronization via atomic key
unsafe impl Sync for ShadowSlot {}

/// Shadow entry 格納用のハッシュテーブル
///
/// Frame index をキーとして shadow entry を格納。
/// Robin Hood hashing でオープンアドレッシング。
#[repr(C, align(64))]
pub struct ShadowTable {
    /// エントリ配列
    entries: [ShadowSlot; MAX_SHADOW_ENTRIES],
    /// 現在のエントリ数
    count: AtomicUsize,
    /// 挿入カウンタ (統計用)
    insertions: AtomicU64,
    /// ヒットカウンタ
    hits: AtomicU64,
    /// ミスカウンタ
    misses: AtomicU64,
}

impl ShadowTable {
    /// 新しい shadow table を作成
    pub const fn new() -> Self {
        const INIT_SLOT: ShadowSlot = ShadowSlot::new();
        Self {
            entries: [INIT_SLOT; MAX_SHADOW_ENTRIES],
            count: AtomicUsize::new(0),
            insertions: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Frame index からハッシュスロットを計算
    #[inline]
    fn hash_slot(frame_index: usize) -> usize {
        // 簡易ハッシュ: FNV-1a 風の混合
        let mut h = frame_index as u64;
        h = h.wrapping_mul(0x517cc1b727220a95);
        h ^= h >> 32;
        (h as usize) % MAX_SHADOW_ENTRIES
    }

    /// Shadow entry を挿入
    ///
    /// ページが evict される際に呼び出す。
    pub fn insert(&self, frame: FrameIndex, shadow: ShadowEntry) {
        let frame_idx = frame.as_usize();
        let mut slot = Self::hash_slot(frame_idx);
        let frame_key = (frame_idx as u64) | (1 << 63); // MSB = valid flag

        // Linear probing (最大 8 スロット)
        for _ in 0..8 {
            let current = self.entries[slot].key.load(Ordering::Relaxed);
            
            if current == 0 || current == frame_key {
                // 空きスロット or 同じ frame の更新
                self.entries[slot].key.store(frame_key, Ordering::Relaxed);
                // SAFETY: UnsafeCell経由、アトミックキーで同期
                unsafe {
                    core::ptr::write_volatile(self.entries[slot].entry.get(), shadow);
                }
                
                if current == 0 {
                    self.count.fetch_add(1, Ordering::Relaxed);
                }
                self.insertions.fetch_add(1, Ordering::Relaxed);
                return;
            }
            
            slot = (slot + 1) % MAX_SHADOW_ENTRIES;
        }
        
        // 満杯の場合は古いエントリを上書き
        let evict_slot = Self::hash_slot(frame_idx);
        self.entries[evict_slot].key.store(frame_key, Ordering::Relaxed);
        unsafe {
            core::ptr::write_volatile(self.entries[evict_slot].entry.get(), shadow);
        }
        self.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Shadow entry を検索して削除
    ///
    /// Refault 時に呼び出す。見つかったら消費 (一度きり)。
    pub fn lookup_and_remove(&self, frame: FrameIndex) -> Option<ShadowEntry> {
        let frame_idx = frame.as_usize();
        let mut slot = Self::hash_slot(frame_idx);
        let frame_key = (frame_idx as u64) | (1 << 63);

        for _ in 0..8 {
            let current = self.entries[slot].key.load(Ordering::Relaxed);
            
            if current == frame_key {
                // 見つかった: 削除してエントリを返す
                self.entries[slot].key.store(0, Ordering::Relaxed);
                self.count.fetch_sub(1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                
                // SAFETY: UnsafeCell経由、エントリは前の insert で書かれている
                let shadow = unsafe {
                    core::ptr::read_volatile(self.entries[slot].entry.get())
                };
                return Some(shadow);
            }
            
            if current == 0 {
                // 空きに到達 = 見つからない
                break;
            }
            
            slot = (slot + 1) % MAX_SHADOW_ENTRIES;
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// 統計を取得
    pub fn stats(&self) -> ShadowTableStats {
        ShadowTableStats {
            count: self.count.load(Ordering::Relaxed),
            capacity: MAX_SHADOW_ENTRIES,
            insertions: self.insertions.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

/// Shadow table 統計
#[derive(Debug, Clone, Copy)]
pub struct ShadowTableStats {
    pub count: usize,
    pub capacity: usize,
    pub insertions: u64,
    pub hits: u64,
    pub misses: u64,
}

impl ShadowTableStats {
    /// ヒット率を計算 (0.0 - 1.0)
    pub fn hit_rate(&self) -> f32 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f32 / total as f32
        }
    }
}

// ============================================================================
// Workingset Controller
// ============================================================================

/// Workingset 追跡コントローラ
#[repr(C, align(64))]
pub struct WorkingsetController {
    /// Shadow entry テーブル
    shadow_table: ShadowTable,
    /// 現在の LRU 時刻 (単調増加)
    lru_clock: AtomicU64,
    /// 非アクティブリストの推定サイズ
    inactive_size: AtomicU64,
    /// Refault distance 閾値 (動的調整可能)
    refault_threshold: AtomicU64,
    /// Working set refault カウント
    workingset_refaults: AtomicU64,
    /// 通常 refault カウント
    normal_refaults: AtomicU64,
}

impl WorkingsetController {
    /// 新しいコントローラを作成
    pub const fn new() -> Self {
        Self {
            shadow_table: ShadowTable::new(),
            lru_clock: AtomicU64::new(1), // 0 は invalid
            inactive_size: AtomicU64::new(0),
            refault_threshold: AtomicU64::new(REFAULT_DISTANCE_THRESHOLD),
            workingset_refaults: AtomicU64::new(0),
            normal_refaults: AtomicU64::new(0),
        }
    }

    /// LRU clock を進める (ページ操作ごとに呼び出し)
    #[inline]
    pub fn advance_clock(&self) -> u64 {
        self.lru_clock.fetch_add(1, Ordering::Relaxed)
    }

    /// 現在の LRU clock を取得
    #[inline]
    pub fn current_clock(&self) -> u64 {
        self.lru_clock.load(Ordering::Relaxed)
    }

    /// ページが evict された際に shadow を記録
    ///
    /// Page reclaim から evict 時に呼び出す。
    pub fn on_evict(&self, frame: FrameIndex, generation: MglruGen, page_type: u8, numa_node: u8) {
        let timestamp = self.current_clock();
        let shadow = ShadowEntry::new(timestamp, generation, page_type, numa_node);
        self.shadow_table.insert(frame, shadow);
    }

    /// Refault 時に working set 判定を行う
    ///
    /// Page fault handler から呼び出す。
    /// 
    /// # Returns
    /// 
    /// - `WorkingSet`: Active LRU 世代に直接追加推奨
    /// - `NotWorkingSet`: 通常通り Inactive から開始
    /// - `NoShadow`: shadow entry なし (初回 fault)
    pub fn on_refault(&self, frame: FrameIndex) -> RefaultResult {
        let shadow = match self.shadow_table.lookup_and_remove(frame) {
            Some(s) => s,
            None => return RefaultResult::NoShadow,
        };

        let current_clock = self.current_clock();
        let eviction_clock = shadow.eviction_timestamp();
        
        // Refault distance = eviction からの経過時間
        let refault_distance = current_clock.saturating_sub(eviction_clock);
        let threshold = self.refault_threshold.load(Ordering::Relaxed);

        if refault_distance <= threshold {
            // Working set 内: すぐに戻ってきたページ
            self.workingset_refaults.fetch_add(1, Ordering::Relaxed);
            
            // Evict 時より 1 世代若い世代から開始 (より長く居座れる)
            let target_gen = shadow.generation().rejuvenate();
            
            RefaultResult::WorkingSet {
                target_generation: target_gen,
            }
        } else {
            // Working set 外: 通常の cold ページ
            self.normal_refaults.fetch_add(1, Ordering::Relaxed);
            RefaultResult::NotWorkingSet
        }
    }

    /// 非アクティブリストサイズを更新
    pub fn update_inactive_size(&self, size: u64) {
        self.inactive_size.store(size, Ordering::Relaxed);
    }

    /// Refault 閾値を動的調整
    ///
    /// Working set refault が多い場合は閾値を上げる (より広く認定)
    /// 少ない場合は閾値を下げる
    pub fn adjust_threshold(&self) {
        let ws_refaults = self.workingset_refaults.load(Ordering::Relaxed);
        let normal_refaults = self.normal_refaults.load(Ordering::Relaxed);
        
        if ws_refaults + normal_refaults < 100 {
            return; // 十分なサンプルがない
        }

        let current = self.refault_threshold.load(Ordering::Relaxed);
        let ws_ratio = ws_refaults as f64 / (ws_refaults + normal_refaults) as f64;

        let new_threshold = if ws_ratio > 0.5 {
            // Working set refault が多い: 閾値を上げる
            (current + current / 10).min(10000)
        } else if ws_ratio < 0.1 {
            // Working set refault が少ない: 閾値を下げる
            (current - current / 10).max(100)
        } else {
            current
        };

        self.refault_threshold.store(new_threshold, Ordering::Relaxed);
        
        // カウンタをリセット
        self.workingset_refaults.store(0, Ordering::Relaxed);
        self.normal_refaults.store(0, Ordering::Relaxed);
    }

    /// 統計を取得
    pub fn stats(&self) -> WorkingsetStats {
        WorkingsetStats {
            lru_clock: self.current_clock(),
            inactive_size: self.inactive_size.load(Ordering::Relaxed),
            refault_threshold: self.refault_threshold.load(Ordering::Relaxed),
            workingset_refaults: self.workingset_refaults.load(Ordering::Relaxed),
            normal_refaults: self.normal_refaults.load(Ordering::Relaxed),
            shadow_table: self.shadow_table.stats(),
        }
    }
}

/// Workingset 統計
#[derive(Debug, Clone)]
pub struct WorkingsetStats {
    pub lru_clock: u64,
    pub inactive_size: u64,
    pub refault_threshold: u64,
    pub workingset_refaults: u64,
    pub normal_refaults: u64,
    pub shadow_table: ShadowTableStats,
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバル Workingset コントローラ
pub static WORKINGSET: WorkingsetController = WorkingsetController::new();

// ============================================================================
// Public API
// ============================================================================

/// ページ evict 時に呼び出す
///
/// Page reclaim の evict 処理から呼び出すこと。
#[inline]
pub fn workingset_evict(frame: FrameIndex, generation: MglruGen, page_type: u8, numa_node: u8) {
    WORKINGSET.on_evict(frame, generation, page_type, numa_node);
}

/// ページ refault 時に呼び出す
///
/// Page fault handler から呼び出し、戻り値に応じて
/// Active/Inactive LRU への追加を決定する。
#[inline]
pub fn workingset_refault(frame: FrameIndex) -> RefaultResult {
    WORKINGSET.on_refault(frame)
}

/// LRU clock を進める
#[inline]
pub fn workingset_advance_clock() -> u64 {
    WORKINGSET.advance_clock()
}

/// 統計を取得
#[inline]
pub fn workingset_stats() -> WorkingsetStats {
    WORKINGSET.stats()
}

/// 閾値の動的調整 (kswapd から定期的に呼び出し)
#[inline]
pub fn workingset_adjust_threshold() {
    WORKINGSET.adjust_threshold();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_entry_basic() {
        let shadow = ShadowEntry::new(100, MglruGen::Gen1, 0, 0);
        assert!(shadow.is_valid());
        assert_eq!(shadow.eviction_timestamp(), 100);
        assert_eq!(shadow.generation(), MglruGen::Gen1);
    }

    #[test]
    fn test_shadow_table_insert_lookup() {
        let table = ShadowTable::new();
        let frame = FrameIndex::new(1234);
        let shadow = ShadowEntry::new(500, MglruGen::Gen2, 1, 0);
        
        table.insert(frame, shadow);
        
        let result = table.lookup_and_remove(frame);
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found.eviction_timestamp(), 500);
        assert_eq!(found.generation(), MglruGen::Gen2);
        
        // 2回目の lookup は None
        assert!(table.lookup_and_remove(frame).is_none());
    }

    #[test]
    fn test_workingset_controller() {
        let ctrl = WorkingsetController::new();
        let frame = FrameIndex::new(9999);
        
        // Evict を記録
        let evict_time = ctrl.current_clock();
        ctrl.on_evict(frame, MglruGen::Gen1, 0, 0);
        
        // 少し clock を進める (threshold 以内)
        for _ in 0..100 {
            ctrl.advance_clock();
        }
        
        // Refault: working set 内のはず
        let result = ctrl.on_refault(frame);
        match result {
            RefaultResult::WorkingSet { target_generation } => {
                // Gen1 の rejuvenate で Gen0 になる
                assert_eq!(target_generation, MglruGen::Gen0);
            }
            _ => panic!("Expected WorkingSet result"),
        }
    }

    #[test]
    fn test_workingset_not_in_workingset() {
        let ctrl = WorkingsetController::new();
        let frame = FrameIndex::new(8888);
        
        ctrl.on_evict(frame, MglruGen::Gen3, 0, 0);
        
        // Clock を大きく進める (threshold 超過)
        for _ in 0..2000 {
            ctrl.advance_clock();
        }
        
        let result = ctrl.on_refault(frame);
        assert_eq!(result, RefaultResult::NotWorkingSet);
    }
}
