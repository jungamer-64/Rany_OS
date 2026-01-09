// ============================================================================
// src/mm/thp_promotion.rs - Transparent Huge Page Promotion
//
// 連続した4KBページを2MBページに透過的に昇格させる機構
//
// ## 設計概要
//
// 1. **昇格候補の検出**: 512個の連続した4KBページが使用中かつ
//    2MB境界にアラインされているかを検出
//
// 2. **昇格の実行**: ページテーブルエントリを更新し、
//    512個のPTEを1つの2MB PMDエントリに置き換え
//
// 3. **コンパクション**: 断片化した領域を移動させて
//    2MB連続領域を作り出すバックグラウンド処理
//
// ## 利点
//
// - TLBミスの劇的な削減（512エントリ → 1エントリ）
// - ページテーブル walk の高速化
// - メモリフットプリントの削減
//
// ## 制約
//
// - 2MB境界アラインメント必須
// - 全512ページが同じ属性（RW/NX等）である必要
// - ページマイグレーション中はロックが必要
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use crate::sync::IrqMutex;
use alloc::vec::Vec;

use super::types::{FixedVec, PAGE_SIZE_4K, PAGE_SIZE_2M};
use super::higher_half::VirtAddr;
use super::address_space::ProcessAddressSpace;

// ============================================================================
// Constants
// ============================================================================

/// 2MBページを構成する4KBページ数
pub const PAGES_PER_HUGE_PAGE: usize = PAGE_SIZE_2M / PAGE_SIZE_4K; // 512

/// 昇格候補をスキャンする間隔（4KBページ単位）
/// スキャン効率とCPU使用率のバランス
const SCAN_STRIDE: usize = 512;

/// 一度のスキャンで検出する最大候補数
const MAX_CANDIDATES_PER_SCAN: usize = 16;

/// THP候補の最大数
const MAX_THP_CANDIDATES: usize = 32;

// ============================================================================
// Phase 6: THP Promotion Statistics
// ============================================================================

/// THP昇格グローバル統計
pub struct PromotionGlobalStats {
    /// 昇格成功数
    pub promotions: AtomicU64,
    /// 昇格されたページ数
    pub pages_promoted: AtomicU64,
    /// 降格数
    pub demotions: AtomicU64,
    /// スキャン回数
    pub scans: AtomicU64,
}

impl PromotionGlobalStats {
    pub const fn new() -> Self {
        Self {
            promotions: AtomicU64::new(0),
            pages_promoted: AtomicU64::new(0),
            demotions: AtomicU64::new(0),
            scans: AtomicU64::new(0),
        }
    }
}

/// グローバル統計
pub static PROMOTION_STATS: PromotionGlobalStats = PromotionGlobalStats::new();

/// 昇格を実行するしきい値（候補数がこれを超えたら実行）
const PROMOTION_THRESHOLD: usize = 4;

/// コンパクション試行の最大回数
const MAX_COMPACTION_ATTEMPTS: usize = 8;

// ============================================================================
// THP Region Descriptor
// ============================================================================

/// 昇格候補領域の情報
#[derive(Debug, Clone, Copy)]
pub struct ThpCandidate {
    /// 2MB境界アラインされた開始仮想アドレス
    pub start_addr: VirtAddr,
    /// 使用中の4KBページ数（512なら完全に利用中）
    pub used_pages: u16,
    /// 属性フラグ（全ページで一致する必要あり）
    pub flags: u64,
    /// 昇格優先度（高いほど優先）
    pub priority: u8,
}

impl ThpCandidate {
    /// 完全な昇格候補かどうか
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.used_pages == PAGES_PER_HUGE_PAGE as u16
    }

    /// コンパクション対象かどうか（部分的に使用中）
    #[inline]
    pub fn needs_compaction(&self) -> bool {
        self.used_pages > 0 && self.used_pages < PAGES_PER_HUGE_PAGE as u16
    }
}

// ============================================================================
// THP Promotion State
// ============================================================================

/// THP昇格の統計情報
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpStats {
    /// スキャン回数
    pub scan_count: u64,
    /// 検出した候補数
    pub candidates_found: u64,
    /// 昇格成功数
    pub promotions_success: u64,
    /// 昇格失敗数（ロック競合等）
    pub promotions_failed: u64,
    /// コンパクション試行数
    pub compaction_attempts: u64,
    /// コンパクション成功数
    pub compaction_success: u64,
}

/// THP昇格マネージャ
pub struct ThpPromotionManager {
    /// 昇格候補リスト - 固定容量
    candidates: FixedVec<ThpCandidate, MAX_THP_CANDIDATES>,
    /// 現在のスキャン位置（仮想アドレス）
    scan_addr: VirtAddr,
    /// 統計情報
    stats: ThpStats,
    /// 有効化フラグ
    enabled: bool,
}

impl ThpPromotionManager {
    /// 新しいTHP昇格マネージャを作成
    pub const fn new() -> Self {
        Self {
            candidates: FixedVec::new(),
            scan_addr: VirtAddr::new(super::address_space::USER_SPACE_START),
            stats: ThpStats {
                scan_count: 0,
                candidates_found: 0,
                promotions_success: 0,
                promotions_failed: 0,
                compaction_attempts: 0,
                compaction_success: 0,
            },
            enabled: false,
        }
    }

    /// 初期化
    pub fn init(&mut self) {
        self.scan_addr = VirtAddr::new(super::address_space::USER_SPACE_START);
        self.candidates.clear();
        self.enabled = true;
    }

    /// THP昇格を有効化/無効化
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// THP昇格が有効かどうか
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 昇格候補をスキャン（バックグラウンドタスクから呼び出し）
    ///
    /// 一度のスキャンで一定範囲のメモリをチェックし、
    /// 昇格候補を検出する。
    /// 昇格候補をスキャン（バックグラウンドタスクから呼び出し）
    ///
    /// 指定されたアドレス空間の仮想メモリ領域をスキャンし、
    /// 昇格候補を検出する。
    pub fn scan_for_candidates(&mut self, space: &ProcessAddressSpace) -> usize {
        if !self.enabled {
            return 0;
        }

        self.stats.scan_count += 1;
        let mut found = 0;

        // Current scan position
        let start_addr = self.scan_addr;
        let current_addr = start_addr;
        
        // Limit scan range per invocation to avoid stalls
        const SCAN_BYTES: u64 = SCAN_STRIDE as u64 * MAX_CANDIDATES_PER_SCAN as u64 * PAGE_SIZE_4K as u64; 
        let _end_addr_limit = current_addr.as_u64() + SCAN_BYTES;

        // Iterate regions starting from current_addr
        // Note: We need access to space.regions. Since it's locked, we rely on helper?
        // Actually, we can just use `space.find_region` or similar, but iterating is better.
        // Given we can't easily iterate a private BTreeMap from here (it's in address_space.rs),
        // we might need to add a "scan_regions" helper in address_space.rs or expose an iterator.
        
        // For now, let's assume we use a public method `scan_vma_for_thp` on ProcessAddressSpace
        // that accepts a closure or returns candidates?
        // Or we iterate using `brute force` via `find_region`? Brute force is slow.
        // Let's assume we added `scan_numa_hints` style iterator in address_space.rs.
        // I will implement a `scan_vma_range` helper in address_space.rs next. 
        // For this step, I'll write the logic assuming `space.scan_vma_gap(start, limit)` exists or similar.
        
        // Actually, let's use the `space.scan_numa_hints` logic I saw earlier as inspiration.
        // But since I can't modify address_space.rs in the same tool call easily without context,
        // let's define the loop here assuming we can peek into regions if they were pub.
        // They are private.
        
        // Pivot: Let's move the actual iteration logic to `ProcessAddressSpace` and call it here?
        // "scan_for_candidates" -> "space.find_thp_candidates(start, limit)"
        
        // Updating this method to delegate:
        let (candidates_found, next_addr) = space.find_thp_candidates(current_addr, MAX_CANDIDATES_PER_SCAN);
        
        for candidate in candidates_found {
             self.candidates.push(candidate);
             self.stats.candidates_found += 1;
             found += 1;
        }
        
        self.scan_addr = next_addr;
        // Wrap around if we hit end of user space or didn't advance (end of regions)
        if self.scan_addr.as_u64() >= super::address_space::USER_SPACE_END {
             self.scan_addr = VirtAddr::new(super::address_space::USER_SPACE_START);
        }

        found
    }

    /// ページ属性を取得（簡略化版）
    #[inline]
    fn get_page_flags(&self, _frame_idx: usize) -> u64 {
        // TODO: 実際のページテーブルから属性を読み取る
        // 現在は標準的なユーザーページ属性を返す
        0x7 // Present | Writable | User
    }
    
    /// 昇格優先度を計算
    #[inline]
    fn calculate_priority(&self, used_pages: u16) -> u8 {
        // 使用率が高いほど優先度が高い
        let usage_ratio = (used_pages as u32 * 100) / PAGES_PER_HUGE_PAGE as u32;
        (usage_ratio.min(255)) as u8
    }

    /// 昇格を実行（候補が十分に溜まったら）
    ///
    /// # Returns
    /// 昇格に成功した数
    pub fn try_promote(&mut self, space: &ProcessAddressSpace) -> usize {
        if !self.enabled || self.candidates.len() < PROMOTION_THRESHOLD {
            return 0;
        }

        let mut promoted = 0;

        // 完全な候補（512ページ全て使用中）を優先的に昇格
        // CHECK: Now considering all candidates since we support compaction during promotion
        let candidates: Vec<_> = self.candidates.iter().cloned().collect();

        for candidate in candidates {
            if self.promote_to_huge_page(space, &candidate) {
                self.stats.promotions_success += 1;
                promoted += 1;
            } else {
                self.stats.promotions_failed += 1;
            }
        }

        // 成功した候補をリストから削除（scan_addrが進むので再スキャンされないはずだが念のため）
        self.candidates.clear();

        promoted
    }

    /// 単一の候補を2MBページに昇格
    fn promote_to_huge_page(&mut self, space: &ProcessAddressSpace, candidate: &ThpCandidate) -> bool {
        // Delegate to ProcessAddressSpace which holds the page table lock/logic
        let result = space.promote_huge_page(candidate.start_addr);
        
        if result {
            // 3. 統計更新
            PROMOTION_STATS.promotions.fetch_add(1, Ordering::Relaxed);
            PROMOTION_STATS.pages_promoted.fetch_add(PAGES_PER_HUGE_PAGE as u64, Ordering::Relaxed);
        }
        
        result
    }

    /// コンパクション（断片化解消）を試行
    ///
    /// 部分的に使用中の領域を移動させて、
    /// 2MB連続領域を作り出す。
    pub fn try_compact(&mut self, space: &ProcessAddressSpace) -> usize {
        if !self.enabled {
            return 0;
        }

        let mut compacted = 0;

        // コンパクション候補（部分使用領域）を取得
        let compaction_candidates: Vec<_> = self.candidates
            .iter()
            .filter(|c| c.needs_compaction())
            .cloned()
            .collect();

        for candidate in compaction_candidates.iter().take(MAX_COMPACTION_ATTEMPTS) {
            self.stats.compaction_attempts += 1;
            
            if self.compact_region(space, candidate) {
                self.stats.compaction_success += 1;
                compacted += 1;
            }
        }

        compacted
    }

    /// 単一領域のコンパクション
    fn compact_region(&mut self, _space: &ProcessAddressSpace, _candidate: &ThpCandidate) -> bool {
        // TODO: ページマイグレーションを実装
        //
        // 1. 移動先の空き領域を確保
        // 2. ページ内容をコピー
        // 3. ページテーブルを更新
        // 4. 元の領域を解放
        // 5. TLBフラッシュ

        // プレースホルダ
        false
    }

    /// 統計情報を取得
    pub fn stats(&self) -> ThpStats {
        self.stats
    }

    /// 統計情報をリセット
    pub fn reset_stats(&mut self) {
        self.stats = ThpStats::default();
    }

    /// 候補リストをクリア
    pub fn clear_candidates(&mut self) {
        self.candidates.clear();
    }
}

// ============================================================================
// Global THP Manager
// ============================================================================

/// グローバルTHP昇格マネージャ
static THP_MANAGER: IrqMutex<ThpPromotionManager> = IrqMutex::new(ThpPromotionManager::new());

/// THP昇格マネージャを初期化
pub fn init_thp_manager() {
    THP_MANAGER.lock().init();
}

/// THP昇格を有効化
pub fn enable_thp() {
    THP_MANAGER.lock().set_enabled(true);
}

/// THP昇格を無効化
pub fn disable_thp() {
    THP_MANAGER.lock().set_enabled(false);
}

/// THP昇格候補をスキャン（アイドルタスクから呼び出し）
///
/// # Returns
/// 検出した候補数
pub fn thp_scan(space: &ProcessAddressSpace) -> usize {
    THP_MANAGER.lock().scan_for_candidates(space)
}

/// THP昇格を試行
///
/// # Returns
/// 昇格に成功した数
pub fn thp_promote(space: &ProcessAddressSpace) -> usize {
    THP_MANAGER.lock().try_promote(space)
}

/// コンパクションを試行
///
/// # Returns
/// コンパクションに成功した領域数
pub fn thp_compact(space: &ProcessAddressSpace) -> usize {
    THP_MANAGER.lock().try_compact(space)
}

/// THP統計情報を取得
pub fn thp_stats() -> ThpStats {
    THP_MANAGER.lock().stats()
}

/// アイドル時のTHP処理（バックグラウンドタスク用）
///
/// スキャン → 昇格 → コンパクションの順に処理を行う。
/// CPUがアイドル状態のときに呼び出すことで、
/// ユーザー処理への影響を最小化する。
pub fn thp_idle_work(space: &ProcessAddressSpace) -> (usize, usize, usize) {
    let scanned = thp_scan(space);
    let promoted = thp_promote(space);
    let compacted = thp_compact(space);
    (scanned, promoted, compacted)
}
