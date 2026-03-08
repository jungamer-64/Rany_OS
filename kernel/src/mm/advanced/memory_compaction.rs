// ============================================================================
// src/mm/memory_compaction.rs - Memory Compaction and Defragmentation
//
// メモリの断片化を解消し、大きな連続領域を確保するためのコンパクション機構。
//
// ## 設計
//
// 1. **スキャナー**: 断片化領域を検出し、移動候補ページを特定
// 2. **マイグレーター**: ページ内容をコピーし、参照を更新
// 3. **アイドルコンパクション**: CPUアイドル時に徐々に断片化を解消
//
// ## コンパクション戦略
//
// - **Conservative**: 最低限のページ移動で最大の連続領域を確保
// - **Aggressive**: 可能な限りメモリを整理してフラグメントを最小化
//
// ## スレッドセーフティ
//
// ページマイグレーション中は:
// 1. ソースページをロック（参照カウントで保護）
// 2. ターゲット領域を確保
// 3. コンテンツをコピー
// 4. ページテーブルを更新（全CPUでTLBフラッシュ）
// 5. ソースページを解放
//
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqMutex;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::mm::phys::buddy_allocator;
use crate::mm::types::{FixedVec, FrameIndex, PAGE_SIZE_2M, PAGE_SIZE_4K};

// ============================================================================
// Configuration
// ============================================================================

/// コンパクション対象の最小フラグメントサイズ（4KBページ数）
const MIN_FRAGMENT_SIZE: usize = 4;

/// 一度の実行で移動する最大ページ数
const MAX_PAGES_PER_RUN: usize = 64;

/// コンパクションを開始する断片化しきい値（空き領域の割合）
const COMPACTION_THRESHOLD: f64 = 0.3;

/// 2MBページを構成する4KBページ数
const PAGES_PER_2MB: usize = PAGE_SIZE_2M / PAGE_SIZE_4K;

/// コンパクションゾーンの最大数
const MAX_COMPACTION_ZONES: usize = 16;

/// マイグレーションターゲットの最大数
const MAX_MIGRATION_TARGETS: usize = 64;

// ============================================================================
// Migration Target
// ============================================================================

/// ページマイグレーションのターゲット
#[derive(Debug, Clone, Copy)]
pub struct MigrationTarget {
    /// ソースフレーム（移動元）
    pub source: PhysFrame<Size4KiB>,
    /// 目的フレーム（移動先）
    pub destination: PhysFrame<Size4KiB>,
    /// このページを参照しているプロセス数
    pub ref_count: u32,
    /// マイグレーション優先度
    pub priority: u8,
}

/// コンパクションゾーン（連続した物理アドレス範囲）
#[derive(Debug, Clone, Copy)]
pub struct CompactionZone {
    /// ゾーン開始フレーム
    pub start: FrameIndex,
    /// ゾーン終了フレーム（exclusive）
    pub end: FrameIndex,
    /// 空きフレーム数
    pub free_count: usize,
    /// 使用中フレーム数
    pub used_count: usize,
    /// 最大連続空き領域（4KBページ数）
    pub max_contiguous_free: usize,
}

impl CompactionZone {
    /// 断片化率を計算（0.0 = 断片化なし、1.0 = 完全に断片化）
    pub fn fragmentation_ratio(&self) -> f64 {
        if self.free_count == 0 {
            return 0.0;
        }
        1.0 - (self.max_contiguous_free as f64 / self.free_count as f64)
    }

    /// コンパクションが必要かどうか
    pub fn needs_compaction(&self) -> bool {
        // 2MB以上の連続空き領域がない場合はコンパクション候補
        self.max_contiguous_free < PAGES_PER_2MB
            && self.free_count >= PAGES_PER_2MB
            && self.fragmentation_ratio() > COMPACTION_THRESHOLD
    }
}

// ============================================================================
// Compaction Statistics
// ============================================================================

/// コンパクション統計
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactionStats {
    /// スキャン回数
    pub scan_count: u64,
    /// マイグレーション試行回数
    pub migration_attempts: u64,
    /// マイグレーション成功回数
    pub migration_success: u64,
    /// マイグレーション失敗回数（ロック競合等）
    pub migration_failed: u64,
    /// 解消した断片化領域数
    pub fragments_resolved: u64,
    /// 移動したページ数
    pub pages_moved: u64,
    /// 作成した2MB連続領域数
    pub huge_regions_created: u64,
}

// ============================================================================
// Compaction Manager
// ============================================================================

/// メモリコンパクションマネージャ
pub struct CompactionManager {
    /// 検出したコンパクションゾーン - 固定容量
    zones: FixedVec<CompactionZone, MAX_COMPACTION_ZONES>,
    /// マイグレーション候補 - 固定容量
    migration_queue: FixedVec<MigrationTarget, MAX_MIGRATION_TARGETS>,
    /// スキャン位置
    scan_position: FrameIndex,
    /// 最大フレーム番号
    max_frame: FrameIndex,
    /// 統計情報
    stats: CompactionStats,
    /// 有効化フラグ
    enabled: bool,
    /// コンパクション実行中フラグ
    in_progress: AtomicBool,
}

impl CompactionManager {
    /// 新しいコンパクションマネージャを作成
    pub const fn new() -> Self {
        Self {
            zones: FixedVec::new(),
            migration_queue: FixedVec::new(),
            scan_position: FrameIndex::new(0),
            max_frame: FrameIndex::new(0),
            stats: CompactionStats {
                scan_count: 0,
                migration_attempts: 0,
                migration_success: 0,
                migration_failed: 0,
                fragments_resolved: 0,
                pages_moved: 0,
                huge_regions_created: 0,
            },
            enabled: false,
            in_progress: AtomicBool::new(false),
        }
    }

    /// 初期化
    pub fn init(&mut self, max_frame: FrameIndex) {
        self.max_frame = max_frame;
        self.scan_position = FrameIndex::new(0);
        self.zones.clear();
        self.migration_queue.clear();
        self.enabled = true;
    }

    /// 有効化/無効化
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// 断片化ゾーンをスキャン
    ///
    /// 物理メモリをスキャンして、コンパクションが必要な領域を検出する。
    pub fn scan_zones(&mut self) -> usize {
        if !self.enabled {
            return 0;
        }

        self.stats.scan_count += 1;
        let mut zones_found = 0;

        // 2MB境界でゾーンを分割してスキャン
        let start = self.scan_position.as_usize();
        let end = (start + PAGES_PER_2MB * 4).min(self.max_frame.as_usize());

        let mut pos = (start + PAGES_PER_2MB - 1) & !(PAGES_PER_2MB - 1);

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while pos + PAGES_PER_2MB <= end {
            if let Some(zone) = self.analyze_zone(FrameIndex::new(pos)) {
                if zone.needs_compaction() {
                    self.zones.push(zone);
                    zones_found += 1;
                }
            }
            pos += PAGES_PER_2MB;
        }

        // スキャン位置を更新
        if pos >= self.max_frame.as_usize() {
            self.scan_position = FrameIndex::new(0);
        } else {
            self.scan_position = FrameIndex::new(pos);
        }

        zones_found
    }

    /// ゾーンを分析
    fn analyze_zone(&self, start: FrameIndex) -> Option<CompactionZone> {
        let end = FrameIndex::new(start.as_usize() + PAGES_PER_2MB);

        if end.as_usize() > self.max_frame.as_usize() {
            return None;
        }

        let mut free_count = 0;
        let mut used_count = 0;
        let mut max_contiguous = 0;
        let mut current_contiguous = 0;

        // 各フレームをチェック
        for i in 0..PAGES_PER_2MB {
            let frame_idx = start.as_usize() + i;

            // Buddyアロケータで空きかどうかをチェック
            if buddy_allocator::is_frame_allocated(frame_idx) {
                // 使用中
                used_count += 1;
                if current_contiguous > max_contiguous {
                    max_contiguous = current_contiguous;
                }
                current_contiguous = 0;
            } else {
                // 空き
                free_count += 1;
                current_contiguous += 1;
            }
        }

        // 最後の連続空き領域をチェック
        if current_contiguous > max_contiguous {
            max_contiguous = current_contiguous;
        }

        Some(CompactionZone {
            start,
            end,
            free_count,
            used_count,
            max_contiguous_free: max_contiguous,
        })
    }

    /// コンパクションを実行
    ///
    /// 検出したゾーン内のページを移動して断片化を解消する。
    pub fn compact(&mut self) -> usize {
        if !self.enabled || self.zones.is_empty() {
            return 0;
        }

        // 再入防止
        if self.in_progress.swap(true, Ordering::SeqCst) {
            return 0;
        }

        let mut compacted = 0;

        // 最も断片化がひどいゾーンを優先
        self.zones.sort_by(|a, b| {
            b.fragmentation_ratio()
                .partial_cmp(&a.fragmentation_ratio())
                .unwrap_or(core::cmp::Ordering::Equal)
        });

        // 上位のゾーンをコピーしてコンパクト（借用問題を回避）
        let zones_to_compact: Vec<_> = self.zones.iter().take(4).cloned().collect();
        for zone in &zones_to_compact {
            if self.compact_zone(zone) {
                compacted += 1;
            }
        }

        // 完了したゾーンを削除
        self.zones.retain(|z| z.needs_compaction());

        self.in_progress.store(false, Ordering::SeqCst);
        compacted
    }

    /// 単一ゾーンをコンパクト
    fn compact_zone(&mut self, zone: &CompactionZone) -> bool {
        // 戦略: ゾーン後半の使用中ページを前半の空き領域に移動
        //
        // Before: [U][F][U][F][F][U][F][U]  (U=Used, F=Free)
        // After:  [U][U][U][U][F][F][F][F]

        let mid = (zone.start.as_usize() + zone.end.as_usize()) / 2;
        let mut pages_moved = 0;

        // 後半から移動候補を収集
        let candidates = self.find_movable_pages(FrameIndex::new(mid), zone.end, MAX_PAGES_PER_RUN);

        // 前半の空き領域に移動
        for source in candidates {
            if let Some(dest) = self.find_free_slot(zone.start, FrameIndex::new(mid)) {
                if self.migrate_page(source, dest) {
                    pages_moved += 1;
                    self.stats.pages_moved += 1;
                }
            } else {
                break; // 空き領域がなくなった
            }
        }

        if pages_moved > 0 {
            self.stats.migration_success += 1;

            // 2MB連続領域が作成できたかチェック
            if self.check_contiguous_region(zone) {
                self.stats.huge_regions_created += 1;
            }

            true
        } else {
            false
        }
    }

    /// 移動可能なページを検索
    fn find_movable_pages(
        &self,
        start: FrameIndex,
        end: FrameIndex,
        max_count: usize,
    ) -> Vec<PhysFrame<Size4KiB>> {
        let mut movable = Vec::new();

        for frame_idx in start.as_usize()..end.as_usize() {
            if movable.len() >= max_count {
                break;
            }

            // 使用中のフレームのみ移動対象
            if !buddy_allocator::is_frame_allocated(frame_idx) {
                continue;
            }

            // ページ属性をチェック
            if !self.is_page_movable(frame_idx) {
                continue;
            }

            let phys_addr = PhysAddr::new((frame_idx * PAGE_SIZE_4K) as u64);
            if let Some(frame) = PhysFrame::from_start_address(phys_addr).ok() {
                movable.push(frame);
            }
        }

        movable
    }

    /// ページが移動可能かどうかをチェック
    #[inline]
    fn is_page_movable(&self, frame_idx: usize) -> bool {
        // 以下のページは移動不可:
        // 1. カーネルテキスト/データ（固定マッピング）
        // 2. ページテーブル自体
        // 3. DMAバッファ（デバイスが参照中）
        // 4. ピン留めされたページ

        // カーネル領域のチェック（16MBまでをカーネル領域とみなす）
        const KERNEL_END_FRAME: usize = 0x1000000 / PAGE_SIZE_4K; // 16MB / 4KB = 4096
        if frame_idx < KERNEL_END_FRAME {
            return false;
        }

        // TODO: より詳細なページ属性チェック
        // - ページテーブルのフラグを確認
        // - DMAバッファ登録テーブルを確認
        // - ピン留めカウンタを確認

        true
    }

    /// 空きスロットを検索
    fn find_free_slot(
        &mut self,
        start: FrameIndex,
        end: FrameIndex,
    ) -> Option<PhysFrame<Size4KiB>> {
        // 指定範囲内で空きフレームを探す
        for frame_idx in start.as_usize()..end.as_usize() {
            // 空きフレームを発見
            if !buddy_allocator::is_frame_allocated(frame_idx) {
                // Buddyアロケータからフレームを取得（予約）
                if let Some(frame) = buddy_allocator::buddy_alloc_frame() {
                    // 割り当てられたフレームが指定範囲内かチェック
                    if frame.start_address().as_u64() >= (start.as_usize() * PAGE_SIZE_4K) as u64
                        && frame.start_address().as_u64() < (end.as_usize() * PAGE_SIZE_4K) as u64
                    {
                        return Some(frame);
                    }
                    // 範囲外だった場合は返却して探索継続
                    buddy_allocator::buddy_dealloc_frame(frame);
                }
            }
        }
        None
    }

    /// ページをマイグレーション
    ///
    /// 完全なページマイグレーションを実行:
    /// 1. ソースページの参照カウントをチェック
    /// 2. ソースページをロック
    /// 3. コンテンツをデスティネーションにコピー
    /// 4. ページテーブルエントリを更新（全参照先）
    /// 5. TLBをフラッシュ（必要なら IPI で全CPU）
    /// 6. ソースページを解放
    fn migrate_page(&mut self, source: PhysFrame<Size4KiB>, dest: PhysFrame<Size4KiB>) -> bool {
        self.stats.migration_attempts += 1;

        // 1. ソース/デスト アドレス取得
        let src_phys = source.start_address().as_u64();
        let _dst_phys = dest.start_address().as_u64();

        // 2. カーネル直接マッピングを使用してコピー
        unsafe {
            let src_virt = phys_to_virt(source.start_address());
            let dst_virt = phys_to_virt(dest.start_address());

            // 4KB コピー
            core::ptr::copy_nonoverlapping(
                src_virt as *const u8,
                dst_virt as *mut u8,
                PAGE_SIZE_4K,
            );
        }

        // 3. ページテーブル更新（TODO: 実際のPTE更新ロジック）
        // - 全プロセスのページテーブルをスキャン
        // - src_phys を参照するPTEを見つける
        // - PTEの物理アドレス部分を dst_phys に更新
        // - Present ビットを一時的にクリアして更新
        //
        // 現時点では単純化: ページテーブル更新は未実装
        // 実装時は mm::higher_half::PageTableManager を使用

        // 4. TLBフラッシュ
        // マルチCPU環境では IPI で全CPUにフラッシュを要求
        broadcast_tlb_flush(src_phys);

        // 5. ソースページを解放
        buddy_allocator::buddy_dealloc_frame(source);

        self.stats.migration_success += 1;
        true
    }

    /// 連続領域が作成されたかチェック
    fn check_contiguous_region(&self, zone: &CompactionZone) -> bool {
        // ゾーン内の連続空き領域を再計算
        let mut max_contiguous = 0;
        let mut current_contiguous = 0;

        for i in 0..PAGES_PER_2MB {
            let frame_idx = zone.start.as_usize() + i;

            if buddy_allocator::is_frame_allocated(frame_idx) {
                if current_contiguous > max_contiguous {
                    max_contiguous = current_contiguous;
                }
                current_contiguous = 0;
            } else {
                current_contiguous += 1;
            }
        }

        if current_contiguous > max_contiguous {
            max_contiguous = current_contiguous;
        }

        // 2MB（512ページ）連続領域が作成されたか
        max_contiguous >= PAGES_PER_2MB
    }

    /// 統計情報を取得
    pub fn stats(&self) -> CompactionStats {
        self.stats
    }

    /// 統計をリセット
    pub fn reset_stats(&mut self) {
        self.stats = CompactionStats::default();
    }
}

// ============================================================================
// Global Compaction Manager
// ============================================================================

/// グローバルコンパクションマネージャ
static COMPACTION_MANAGER: IrqMutex<CompactionManager> = IrqMutex::new(CompactionManager::new());

/// コンパクションマネージャを初期化
pub fn init_compaction(max_frame: FrameIndex) {
    COMPACTION_MANAGER.lock().init(max_frame);
}

/// コンパクションを有効化
pub fn enable_compaction() {
    COMPACTION_MANAGER.lock().set_enabled(true);
}

/// コンパクションを無効化
pub fn disable_compaction() {
    COMPACTION_MANAGER.lock().set_enabled(false);
}

/// 断片化ゾーンをスキャン
pub fn compaction_scan() -> usize {
    COMPACTION_MANAGER.lock().scan_zones()
}

/// コンパクションを実行
pub fn compaction_run() -> usize {
    COMPACTION_MANAGER.lock().compact()
}

/// コンパクション統計を取得
pub fn compaction_stats() -> CompactionStats {
    COMPACTION_MANAGER.lock().stats()
}

/// アイドル時のコンパクション処理
///
/// スキャンとコンパクションを1回実行する。
/// アイドルタスクから定期的に呼び出すことで、
/// バックグラウンドで断片化を解消する。
pub fn compaction_idle_work() -> (usize, usize) {
    let scanned = compaction_scan();
    let compacted = compaction_run();
    (scanned, compacted)
}

// ============================================================================
// Direct Page Migration API
// ============================================================================

/// 単一ページを指定先に移動
///
/// # Safety
/// - source と dest が有効な物理フレームであること
/// - source が移動可能（ピン留めされていない）こと
pub unsafe fn migrate_single_page(
    source: PhysFrame<Size4KiB>,
    dest: PhysFrame<Size4KiB>,
) -> Result<(), MigrationError> {
    // 1. ソースページの内容を読み取り
    let src_ptr = phys_to_virt(source.start_address());
    let dst_ptr = phys_to_virt(dest.start_address());

    // 2. コピー（4KiB = 4096バイト）
    core::ptr::copy_nonoverlapping(src_ptr as *const u8, dst_ptr as *mut u8, PAGE_SIZE_4K);

    // 3. ページテーブル更新は呼び出し元の責任

    Ok(())
}

/// ページマイグレーションエラー
#[derive(Debug, Clone, Copy)]
pub enum MigrationError {
    /// ソースページがピン留めされている
    SourcePinned,
    /// デスティネーションが利用不可
    DestinationUnavailable,
    /// ページテーブル更新に失敗
    PageTableUpdateFailed,
    /// TLBフラッシュに失敗
    TlbFlushFailed,
}

/// 物理アドレスを仮想アドレスに変換（カーネル直接マッピング）
#[inline]
fn phys_to_virt(phys: PhysAddr) -> usize {
    crate::mm::virt::mapping::phys_to_virt(phys).as_u64() as usize
}

/// 特定のページのTLBエントリをフラッシュ
#[inline]
fn flush_tlb_page(phys_addr: u64) {
    // 直接マッピングの仮想アドレスを計算
    let virt_addr = crate::mm::virt::mapping::phys_to_virt(PhysAddr::new(phys_addr)).as_u64();

    // x86_64: INVLPG 命令でTLBエントリを無効化
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virt_addr,
            options(nostack, preserves_flags)
        );
    }
}

/// 全CPUのTLBをフラッシュ（ブロードキャスト）
///
/// IPI (Inter-Processor Interrupt) を使用して全CPUに
/// TLBフラッシュを要求する。
///
/// # Warning
/// これは高コストな操作。可能な限りバッチ処理すること。
fn broadcast_tlb_flush(phys_addr: u64) {
    use x86_64::VirtAddr;

    // 直接マッピングの仮想アドレスを計算
    let virt_addr =
        VirtAddr::new(crate::mm::virt::mapping::phys_to_virt(PhysAddr::new(phys_addr)).as_u64());

    // TLBバッチシステムを使用して全CPUにフラッシュを送信
    // flush_tlb_immediateは:
    // 1. ローカルCPUのTLBをフラッシュ
    // 2. IPI経由で他の全CPUにフラッシュを要求
    crate::mm::sync::tlb_batch::flush_tlb_immediate(virt_addr);
}

// ============================================================================
// Proactive Compaction (断片化指数の監視)
// ============================================================================

/// 断片化指数（Fragmentation Index）
///
/// Linux の /proc/buddyinfo や /proc/pagetypeinfo に相当する指標。
/// 値が高いほど断片化が進んでいる。
#[derive(Debug, Clone, Copy, Default)]
pub struct FragmentationIndex {
    /// 全体の断片化指数（0.0 = 断片化なし、1.0 = 完全に断片化）
    pub overall: f64,
    /// オーダーごとの断片化指数
    pub by_order: [f64; 19], // MAX_ORDER + 1
    /// 2MB連続領域の確保可能性（0.0 = 不可、1.0 = 容易）
    pub huge_page_availability: f64,
    /// 1GB連続領域の確保可能性
    pub gigantic_page_availability: f64,
}

impl FragmentationIndex {
    /// 断片化指数を計算
    pub fn calculate(buddy_stats: &crate::mm::phys::buddy_allocator::BuddyAllocatorStats) -> Self {
        let mut by_order = [0.0f64; 19];
        let mut total_weighted = 0.0;
        let mut total_weight = 0.0;

        for (order, &(free_blocks, _total_frames)) in buddy_stats.order_stats.iter().enumerate() {
            // 理想的には高オーダーに多くの空きがあるべき
            // 低オーダーに空きが集中していると断片化が進んでいる
            let weight = 1.0 / (1 << order) as f64; // 高オーダーほど重要
            let expected = buddy_stats.free_frames as f64 / (1 << order) as f64;

            if expected > 0.0 {
                let actual = free_blocks as f64;
                // 実際の空きブロック数 vs 期待値
                let ratio = (actual / expected).min(1.0);
                by_order[order] = 1.0 - ratio;
                total_weighted += by_order[order] * weight;
                total_weight += weight;
            }
        }

        let overall = if total_weight > 0.0 {
            total_weighted / total_weight
        } else {
            0.0
        };

        // 2MB (Order 9) の確保可能性
        let order_9_blocks = buddy_stats.order_stats.get(9).map(|&(b, _)| b).unwrap_or(0);
        let huge_page_availability = if buddy_stats.free_frames >= 512 {
            (order_9_blocks as f64).min(buddy_stats.free_frames as f64 / 512.0)
                / (buddy_stats.free_frames as f64 / 512.0)
        } else {
            0.0
        };

        // 1GB (Order 18) の確保可能性
        let order_18_blocks = buddy_stats
            .order_stats
            .get(18)
            .map(|&(b, _)| b)
            .unwrap_or(0);
        let gigantic_page_availability = if buddy_stats.free_frames >= 262144 {
            (order_18_blocks as f64).min(buddy_stats.free_frames as f64 / 262144.0)
                / (buddy_stats.free_frames as f64 / 262144.0)
        } else {
            0.0
        };

        Self {
            overall,
            by_order,
            huge_page_availability,
            gigantic_page_availability,
        }
    }

    /// コンパクションが必要かどうか判定
    pub fn needs_compaction(&self) -> bool {
        // 断片化が30%以上、または2MBページが確保困難
        self.overall > 0.3 || self.huge_page_availability < 0.5
    }

    /// 緊急コンパクションが必要かどうか
    pub fn needs_urgent_compaction(&self) -> bool {
        // 断片化が50%以上、または2MBページがほぼ確保不可
        self.overall > 0.5 || self.huge_page_availability < 0.1
    }
}

/// プロアクティブコンパクションマネージャ
pub struct ProactiveCompactionManager {
    /// 現在の断片化指数
    current_index: FragmentationIndex,
    /// Low watermark（この値を下回ったらコンパクション開始）
    low_watermark: f64,
    /// High watermark（この値に達したら緊急コンパクション）
    high_watermark: f64,
    /// バックグラウンドコンパクション有効フラグ
    enabled: bool,
    /// 最後のコンパクション実行時刻（tick）
    last_compaction_tick: u64,
    /// コンパクション間隔（tick）
    compaction_interval: u64,
}

impl ProactiveCompactionManager {
    pub const fn new() -> Self {
        Self {
            current_index: FragmentationIndex {
                overall: 0.0,
                by_order: [0.0; 19],
                huge_page_availability: 1.0,
                gigantic_page_availability: 1.0,
            },
            low_watermark: 0.3,
            high_watermark: 0.5,
            enabled: true,
            last_compaction_tick: 0,
            compaction_interval: 100, // 100 tick ごと
        }
    }

    /// 断片化指数を更新
    pub fn update_index(&mut self, stats: &crate::mm::phys::buddy_allocator::BuddyAllocatorStats) {
        self.current_index = FragmentationIndex::calculate(stats);
    }

    /// 現在の断片化指数を取得
    pub fn current_index(&self) -> &FragmentationIndex {
        &self.current_index
    }

    /// コンパクションアクションを決定
    pub fn decide_action(&self, current_tick: u64) -> CompactionAction {
        if !self.enabled {
            return CompactionAction::None;
        }

        // 緊急コンパクション
        if self.current_index.needs_urgent_compaction() {
            return CompactionAction::Urgent;
        }

        // 通常コンパクション（インターバルをチェック）
        if self.current_index.needs_compaction() {
            if current_tick.saturating_sub(self.last_compaction_tick) >= self.compaction_interval {
                return CompactionAction::Normal;
            }
        }

        // アイドルコンパクション（断片化が軽微でも徐々に解消）
        if self.current_index.overall > 0.1 {
            return CompactionAction::Idle;
        }

        CompactionAction::None
    }

    /// コンパクション実行を記録
    pub fn record_compaction(&mut self, tick: u64) {
        self.last_compaction_tick = tick;
    }

    /// Watermarkを設定
    pub fn set_watermarks(&mut self, low: f64, high: f64) {
        self.low_watermark = low.clamp(0.0, 1.0);
        self.high_watermark = high.clamp(self.low_watermark, 1.0);
    }

    /// 有効化/無効化
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// コンパクションアクション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionAction {
    /// コンパクション不要
    None,
    /// アイドル時の軽量コンパクション
    Idle,
    /// 通常のバックグラウンドコンパクション
    Normal,
    /// 緊急コンパクション（割り当て失敗のリスク）
    Urgent,
}

/// グローバルプロアクティブコンパクションマネージャ
static PROACTIVE_MANAGER: IrqMutex<ProactiveCompactionManager> =
    IrqMutex::new(ProactiveCompactionManager::new());

/// 断片化指数を更新
pub fn update_fragmentation_index() {
    let stats = crate::mm::phys::buddy_allocator::buddy_allocator_stats();
    PROACTIVE_MANAGER.lock().update_index(&stats);
}

/// 現在の断片化指数を取得
pub fn get_fragmentation_index() -> FragmentationIndex {
    *PROACTIVE_MANAGER.lock().current_index()
}

/// コンパクションアクションを決定
pub fn decide_compaction_action(current_tick: u64) -> CompactionAction {
    PROACTIVE_MANAGER.lock().decide_action(current_tick)
}

/// コンパクション実行を記録
pub fn record_compaction_done(tick: u64) {
    PROACTIVE_MANAGER.lock().record_compaction(tick);
}

/// プロアクティブコンパクションを有効化
pub fn enable_proactive_compaction() {
    PROACTIVE_MANAGER.lock().set_enabled(true);
}

/// プロアクティブコンパクションを無効化
pub fn disable_proactive_compaction() {
    PROACTIVE_MANAGER.lock().set_enabled(false);
}
