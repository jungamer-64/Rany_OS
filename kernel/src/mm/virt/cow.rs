// ============================================================================
// src/mm/cow.rs - Copy-on-Write Implementation
//
// # ⚠ 非推奨 (SAS違反)
//
// Copy-on-Writeはfork()を前提としたメカニズムですが、SAS (Single Address Space)
// アーキテクチャではfork()は存在せず、ドメイン生成により代替されます。
//
// ## 移行先
// - CoW fork → `domain_system::create_domain()` (Copy不要、独立ドメイン)
// - ページ共有 → `RRef<T>` ベースの明示的共有 (`crate::ipc::rref`)
// - 参照カウント → SASではドメイン境界での所有権移動が代替
//
// ## 概要 (Original)
//
// Copy-on-Write（CoW）機構の完全実装。fork()時のページ共有、
// 参照カウント管理、書き込み時の透過的なページ複製を提供する。
//
// ## 設計
//
// 1. **ページ参照カウント**: 各物理ページの共有数を追跡
// 2. **CoWマーキング**: PTEをRead-onlyに設定し、CoWフラグを管理
// 3. **フォルト時複製**: 書き込みフォルトでページを複製し、マッピングを更新
// 4. **最適化**: 参照カウント1のページは複製せずに権限変更のみ
//
// ## 使用例
//
// ```rust
// // fork時にCoWとしてマーク
// cow_mark_range(parent_vma.start, parent_vma.end)?;
//
// // 子プロセスのページテーブルを親と共有（read-only）
// cow_share_pages(parent_pt, child_pt, vma_range)?;
//
// // 書き込みフォルト時に複製
// cow_break(fault_addr)?;
// ```
//
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqPoisonLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use x86_64::structures::paging::PhysFrame;

use super::higher_half::{
    MapError, PageFlags, PageTableManager, PhysAddr, VirtAddr, get_current_pte, global_map_page,
    global_translate, global_unmap_page, global_update_flags, physical_memory_offset,
};
use crate::mm::phys::frame_allocator::{alloc_frame, dealloc_frame};
use crate::mm::reclaim::page_reclaim::{PageType as LruPageType, lru_add_page};
use crate::mm::sync::tlb_batch::flush_tlb_immediate;

// ============================================================================
// Page Reference Count
// ============================================================================

/// ページ参照カウントエントリ
struct PageRefCount {
    /// 参照カウント
    count: AtomicU32,
    /// CoWフラグ（このページがCoW共有されているか）
    is_cow: AtomicU32,
}

impl PageRefCount {
    fn new() -> Self {
        Self {
            count: AtomicU32::new(1),
            is_cow: AtomicU32::new(0),
        }
    }

    #[inline]
    fn get(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }

    #[inline]
    fn inc(&self) -> u32 {
        self.count.fetch_add(1, Ordering::AcqRel)
    }

    #[inline]
    fn dec(&self) -> u32 {
        self.count.fetch_sub(1, Ordering::AcqRel)
    }

    #[inline]
    fn is_cow(&self) -> bool {
        self.is_cow.load(Ordering::Acquire) != 0
    }

    #[inline]
    fn set_cow(&self, cow: bool) {
        self.is_cow
            .store(if cow { 1 } else { 0 }, Ordering::Release);
    }
}

// ============================================================================
// Global Page Reference Manager
// ============================================================================

/// グローバルページ参照カウントマネージャ
struct PageRefManager {
    /// 物理ページアドレス → 参照カウント
    refcounts: BTreeMap<u64, PageRefCount>,
}

impl PageRefManager {
    const fn new() -> Self {
        Self {
            refcounts: BTreeMap::new(),
        }
    }
}

static PAGE_REF_MANAGER: IrqPoisonLock<PageRefManager> = IrqPoisonLock::new(PageRefManager::new());

// ============================================================================
// CoW Statistics
// ============================================================================

/// CoW統計
pub struct CowStats {
    /// CoWとしてマークされたページ数
    pub marked: AtomicU64,
    /// CoW breakで複製されたページ数
    pub breaks: AtomicU64,
    /// 複製を省略したページ数（refcount == 1）
    pub skipped_copies: AtomicU64,
    /// 現在のCoW共有ページ数
    pub current_shared: AtomicU64,
}

impl CowStats {
    pub const fn new() -> Self {
        Self {
            marked: AtomicU64::new(0),
            breaks: AtomicU64::new(0),
            skipped_copies: AtomicU64::new(0),
            current_shared: AtomicU64::new(0),
        }
    }
}

static COW_STATS: CowStats = CowStats::new();

// ============================================================================
// CoW Result Types
// ============================================================================

/// CoW操作の結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowResult {
    /// 成功
    Ok,
    /// ページが見つからない
    PageNotFound,
    /// メモリ不足
    OutOfMemory,
    /// マッピングエラー
    MappingError,
    /// ページがCoWではない
    NotCow,
    /// 既にWritable
    AlreadyWritable,
}

// ============================================================================
// Page Reference Count API
// ============================================================================

/// ページの参照カウントを増加
///
/// fork()時に親子で同じ物理ページを共有する際に使用。
pub fn page_get(phys_addr: u64) {
    let page_addr = phys_addr & !0xFFF;

    let mut manager = match PAGE_REF_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(entry) = manager.refcounts.get(&page_addr) {
        entry.inc();
    } else {
        // 新規エントリ作成（参照カウント1で開始）
        manager.refcounts.insert(page_addr, PageRefCount::new());
    }
}

/// ページの参照カウントを減少
///
/// ページが不要になった際に呼び出す。
/// 参照カウントが0になった場合、ページを解放する。
///
/// # 戻り値
///
/// * `true` - ページを解放した
/// * `false` - まだ参照が残っている
pub fn page_put(phys_addr: u64) -> bool {
    let page_addr = phys_addr & !0xFFF;

    let mut manager = match PAGE_REF_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(entry) = manager.refcounts.get(&page_addr) {
        let old = entry.dec();
        if old == 1 {
            // 参照カウントが0になった
            manager.refcounts.remove(&page_addr);

            // 物理フレームを解放
            let frame = PhysFrame::containing_address(x86_64::PhysAddr::new(page_addr));
            dealloc_frame(frame);

            COW_STATS.current_shared.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

/// ページの参照カウントを取得
pub fn page_refcount(phys_addr: u64) -> u32 {
    let page_addr = phys_addr & !0xFFF;

    let manager = match PAGE_REF_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    manager
        .refcounts
        .get(&page_addr)
        .map(|e| e.get())
        .unwrap_or(1) // 追跡されていないページは単独参照と見なす
}

/// ページがCoWマークされているか
pub fn page_is_cow(phys_addr: u64) -> bool {
    let page_addr = phys_addr & !0xFFF;

    let manager = match PAGE_REF_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    manager
        .refcounts
        .get(&page_addr)
        .map(|e| e.is_cow())
        .unwrap_or(false)
}

// ============================================================================
// CoW Marking
// ============================================================================

/// ページをCoWとしてマーク
///
/// PTEをRead-onlyに設定し、参照カウントを管理する。
/// fork()時に親子両方のページテーブルに対して呼び出す。
pub fn cow_mark_page(virt_addr: VirtAddr) -> CowResult {
    let page_addr = VirtAddr::new(virt_addr.as_u64() & !0xFFF);

    // 現在の物理アドレスを取得
    let phys_addr = match global_translate(page_addr) {
        Some(phys) => phys,
        None => return CowResult::PageNotFound,
    };

    // 参照カウントを増加
    page_get(phys_addr.as_u64());

    // CoWフラグをセット
    {
        let manager = match PAGE_REF_MANAGER.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = manager.refcounts.get(&(phys_addr.as_u64() & !0xFFF)) {
            entry.set_cow(true);
        }
    }

    // PTEをRead-onlyに変更
    let flags = PageFlags::new(PageFlags::PRESENT | PageFlags::USER); // Writableを除去
    // Safety: ページテーブル操作
    match unsafe { global_update_flags(page_addr, flags) } {
        Ok(()) => {}
        Err(_) => return CowResult::MappingError,
    }

    // TLBフラッシュ（x86_64::VirtAddrに変換）
    flush_tlb_immediate(x86_64::VirtAddr::new(page_addr.as_u64()));

    COW_STATS.marked.fetch_add(1, Ordering::Relaxed);
    COW_STATS.current_shared.fetch_add(1, Ordering::Relaxed);

    CowResult::Ok
}

/// 仮想アドレス範囲をCoWとしてマーク
pub fn cow_mark_range(start: VirtAddr, end: VirtAddr) -> CowResult {
    let mut addr = start.as_u64() & !0xFFF;
    let end_addr = end.as_u64();

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while addr < end_addr {
        let result = cow_mark_page(VirtAddr::new(addr));
        if result != CowResult::Ok && result != CowResult::PageNotFound {
            return result;
        }
        addr += 4096;
    }

    CowResult::Ok
}

// ============================================================================
// CoW Break (Page Duplication)
// ============================================================================

/// CoWを解除してページを複製
///
/// 書き込みフォルト時に呼び出される。
/// 参照カウントが1の場合は複製せずに権限変更のみ行う。
pub fn cow_break(virt_addr: VirtAddr) -> CowResult {
    let page_addr = VirtAddr::new(virt_addr.as_u64() & !0xFFF);

    // 現在の物理アドレスを取得
    let old_phys = match global_translate(page_addr) {
        Some(phys) => phys,
        None => return CowResult::PageNotFound,
    };

    // 脆弱性修正: 参照カウントのチェックとPTEの更新をアトミックに行うためロックを保持
    let manager = match PAGE_REF_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let refcount = manager
        .refcounts
        .get(&(old_phys.as_u64() & !0xFFF))
        .map(|e| e.get())
        .unwrap_or(1);

    // 参照カウントが1なら複製不要
    if refcount <= 1 {
        // 単にWritableに変更
        let flags = PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER);
        // Safety: ページテーブル操作
        match unsafe { global_update_flags(page_addr, flags) } {
            Ok(()) => {}
            Err(_) => return CowResult::MappingError,
        }

        // CoWフラグをクリア
        if let Some(entry) = manager.refcounts.get(&(old_phys.as_u64() & !0xFFF)) {
            entry.set_cow(false);
        }

        // ロックを解放してからTLBフラッシュ
        drop(manager);

        flush_tlb_immediate(x86_64::VirtAddr::new(page_addr.as_u64()));

        COW_STATS.skipped_copies.fetch_add(1, Ordering::Relaxed);
        return CowResult::Ok;
    }

    // 参照カウント > 1 の場合

    // 参照カウントを先に減らすことで、他のプロセスがこのページを使い続けられるようにする
    // ただし、新しいページへのコピーが終わるまで物理ページが解放されないよう、
    // ここではまだ decrement しない。

    // 新しいフレームを割り当て（ロック保持中に割り当てるとデッドロックの可能性があるため一旦解放）
    drop(manager);

    let new_frame = match alloc_frame() {
        Some(f) => f,
        None => return CowResult::OutOfMemory,
    };

    // 物理アドレスをhigher_half型に変換
    let new_phys = PhysAddr::new(new_frame.start_address().as_u64());

    // ページ内容をコピー
    copy_page(old_phys, new_phys);

    // Memcgチャージ
    let memcg_id = crate::mm::meta::memcg::current_memcg_id();
    if crate::mm::meta::memcg::memcg_charge(memcg_id, 1, crate::mm::meta::memcg::ChargeType::Anon)
        .is_err()
    {
        dealloc_frame(new_frame);
        return CowResult::OutOfMemory;
    }

    // マッピングを更新（ここでもレースコンディションに注意）
    // 古いマッピングを削除し、新しいマッピングを作成
    let flags = PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER);

    unsafe {
        // global_unmap_page と global_map_page は内部でロックを取るはず
        let _ = global_unmap_page(page_addr);
        match global_map_page(page_addr, new_phys, flags) {
            Ok(()) => {}
            Err(MapError::AlreadyMapped) => {
                crate::mm::meta::memcg::memcg_uncharge(
                    memcg_id,
                    1,
                    crate::mm::meta::memcg::ChargeType::Anon,
                );
                dealloc_frame(new_frame);
                return CowResult::Ok;
            }
            Err(_) => {
                crate::mm::meta::memcg::memcg_uncharge(
                    memcg_id,
                    1,
                    crate::mm::meta::memcg::ChargeType::Anon,
                );
                dealloc_frame(new_frame);
                return CowResult::MappingError;
            }
        }
    }

    // TLBフラッシュ
    flush_tlb_immediate(x86_64::VirtAddr::new(page_addr.as_u64()));

    // 古いページの参照カウントを減少
    page_put(old_phys.as_u64());

    // LRUに追加
    lru_add_page(new_frame, LruPageType::Anonymous);

    // ページとmemcgを追跡
    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(new_phys.as_u64());
    crate::mm::meta::memcg::memcg_track_page(
        frame_idx,
        memcg_id,
        crate::mm::meta::memcg::ChargeType::Anon,
    );

    COW_STATS.breaks.fetch_add(1, Ordering::Relaxed);

    CowResult::Ok
}

/// ページ内容をコピー
fn copy_page(src_phys: PhysAddr, dst_phys: PhysAddr) {
    let src_x86 = x86_64::PhysAddr::new(src_phys.as_u64());
    let dst_x86 = x86_64::PhysAddr::new(dst_phys.as_u64());
    let src_virt = super::mapping::phys_to_virt(src_x86);
    let dst_virt = super::mapping::phys_to_virt(dst_x86);

    unsafe {
        core::ptr::copy_nonoverlapping(
            src_virt.as_u64() as *const u8,
            dst_virt.as_u64() as *mut u8,
            4096,
        );
    }
}

// ============================================================================
// Fork Support
// ============================================================================

/// fork()時のCoW設定
///
/// 親プロセスの仮想アドレス範囲を子プロセスにCoW共有する。
/// 両方のプロセスのPTEをRead-onlyに設定。
///
/// # 引数
///
/// * `ranges` - CoW共有する仮想アドレス範囲のリスト
///
/// # 注意
///
/// この関数は親プロセスのコンテキストで呼び出す。
/// 子プロセスのページテーブルは別途作成・設定する必要がある。
pub fn cow_fork_prepare(ranges: &[(VirtAddr, VirtAddr)]) -> CowResult {
    for (start, end) in ranges {
        // 親側のページをCoWマーク
        let result = cow_mark_range(*start, *end);
        if result != CowResult::Ok {
            return result;
        }
    }

    CowResult::Ok
}

/// fork()完了時のページテーブルエントリコピー
///
/// 親のPTEを子のページテーブルにコピーする。
/// 子側もRead-only+CoWフラグでマッピング。
///
/// # 引数
///
/// * `parent_virt` - 親の仮想アドレス
/// * `child_pt` - 子のページテーブル（将来の実装用）
///
pub fn cow_copy_pte(parent_virt: VirtAddr, child_pt: u64) -> CowResult {
    // 現在の物理アドレスを取得
    let phys = match global_translate(parent_virt) {
        Some(p) => p,
        None => return CowResult::PageNotFound,
    };

    // 参照カウントを増加（子も参照するため）
    page_get(phys.as_u64());

    let parent_pte = match get_current_pte(parent_virt) {
        Some(pte) => pte,
        None => return CowResult::PageNotFound,
    };

    if parent_pte.is_huge() {
        return CowResult::MappingError;
    }

    let flags = parent_pte
        .flags()
        .clear(PageFlags::WRITABLE)
        .set(PageFlags::PRESENT);

    let mut manager =
        unsafe { PageTableManager::new(PhysAddr::new(child_pt), physical_memory_offset()) };
    match unsafe { manager.map_page(parent_virt, phys, flags) } {
        Ok(()) => CowResult::Ok,
        Err(MapError::FrameAllocationFailed) => CowResult::OutOfMemory,
        Err(_) => CowResult::MappingError,
    }
}

// ============================================================================
// Zero Page Optimization
// ============================================================================

/// ゼロページの物理アドレス（共有用）
static mut ZERO_PAGE_PHYS: Option<u64> = None;

/// ゼロページを初期化
pub fn init_zero_page() {
    // ゼロページ用のフレームを割り当て
    if let Some(frame) = alloc_frame() {
        let phys = frame.start_address();

        // ゼロクリア
        let virt = super::mapping::phys_to_virt(phys);
        unsafe {
            core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, 4096);
        }

        unsafe {
            ZERO_PAGE_PHYS = Some(phys.as_u64());
        }

        // 参照カウントを大きな値に設定（解放されないように）
        {
            let mut manager = match PAGE_REF_MANAGER.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let entry = PageRefCount::new();
            entry.count.store(u32::MAX / 2, Ordering::Release);
            manager.refcounts.insert(phys.as_u64(), entry);
        }
    }
}

/// ゼロページの物理アドレスを取得
pub fn zero_page_phys() -> Option<u64> {
    unsafe { ZERO_PAGE_PHYS }
}

/// 新規匿名ページをゼロページへのCoWとしてマッピング
///
/// Demand Paging時にゼロクリアされたページが必要な場合、
/// 実際にページを割り当てずにゼロページへのCoWとしてマッピングする。
/// 書き込み時に初めて実ページが割り当てられる。
pub fn cow_map_zero_page(virt_addr: VirtAddr) -> CowResult {
    let page_addr = VirtAddr::new(virt_addr.as_u64() & !0xFFF);

    let zero_phys = match zero_page_phys() {
        Some(p) => p,
        None => return CowResult::PageNotFound,
    };

    // 参照カウントを増加
    page_get(zero_phys);

    // Read-onlyでマッピング
    let flags = PageFlags::new(PageFlags::PRESENT | PageFlags::USER);
    let phys_addr = PhysAddr::new(zero_phys);
    // Safety: ページテーブル操作
    match unsafe { global_map_page(page_addr, phys_addr, flags) } {
        Ok(()) => {}
        Err(MapError::AlreadyMapped) => {
            page_put(zero_phys);
            return CowResult::Ok;
        }
        Err(_) => {
            page_put(zero_phys);
            return CowResult::MappingError;
        }
    }

    CowResult::Ok
}

// ============================================================================
// Statistics
// ============================================================================

/// CoW統計スナップショット
#[derive(Debug, Clone, Copy)]
pub struct CowStatSnapshot {
    pub marked: u64,
    pub breaks: u64,
    pub skipped_copies: u64,
    pub current_shared: u64,
    pub tracked_pages: u64,
}

/// CoW統計を取得
pub fn cow_stats() -> CowStatSnapshot {
    let tracked = match PAGE_REF_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
    .refcounts
    .len() as u64;

    CowStatSnapshot {
        marked: COW_STATS.marked.load(Ordering::Relaxed),
        breaks: COW_STATS.breaks.load(Ordering::Relaxed),
        skipped_copies: COW_STATS.skipped_copies.load(Ordering::Relaxed),
        current_shared: COW_STATS.current_shared.load(Ordering::Relaxed),
        tracked_pages: tracked,
    }
}

// ============================================================================
// Debug
// ============================================================================

/// CoW状態のデバッグ出力
pub fn cow_debug_info() {
    let stats = cow_stats();

    log::debug!("=== CoW Debug Info ===");
    log::debug!("Marked pages: {}", stats.marked);
    log::debug!("Break operations: {}", stats.breaks);
    log::debug!("Skipped copies: {}", stats.skipped_copies);
    log::debug!("Current shared: {}", stats.current_shared);
    log::debug!("Tracked pages: {}", stats.tracked_pages);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_page_refcount_basic() {
        let phys = 0x100_000; // 1MB

        // 初回get
        page_get(phys);
        assert_eq!(page_refcount(phys), 1);

        // 2回目get
        page_get(phys);
        assert_eq!(page_refcount(phys), 2);

        // put
        page_put(phys);
        assert_eq!(page_refcount(phys), 1);
    }

    #[test_case]
    fn test_cow_stats() {
        let stats = cow_stats();
        // 統計が取得できることを確認
        let _ = stats.marked;
        let _ = stats.breaks;
    }
}
