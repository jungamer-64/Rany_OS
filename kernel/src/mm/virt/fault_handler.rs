// ============================================================================
// src/mm/fault_handler.rs - Advanced Page Fault Handler
//
// ## 概要
//
// 高度なページフォルト処理を提供する。demand paging, Copy-on-Write,
// スタック自動拡張、ファイルバックページのロードなどを統合的に処理する。
//
// ## 設計
//
// 1. **エラーコード解析**: x86_64のPageFaultErrorCodeからフォルト種別を判定
// 2. **VMA検索**: RCU保護されたVMAリストからフォルトアドレスのVMAを検索
// 3. **フォルト種別ごとの処理**:
//    - Demand Paging: 初回アクセス時にページ割り当て
//    - Copy-on-Write: 共有ページへの書き込みで複製
//    - Stack Growth: スタック下限近くのフォルトでスタック拡張
//    - File-backed: ファイルからページをロード
//
// ## 安全性
//
// - ユーザーモードフォルトとカーネルモードフォルトを区別
// - 不正アクセスは即座にSIGSEGV（または panic）
// - 再帰的フォルトの検出と防止
//
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::InterruptStackFrame;

use super::higher_half::{MapError, PageFlags, PhysAddr, VirtAddr, global_map_page};
use super::rcu_vma::{VmArea, VmaFlags};
use crate::mm::meta::memcg::{ChargeType, MemcgId, memcg_charge, memcg_track_page, memcg_uncharge};
use crate::mm::phys::frame_allocator::alloc_frame;
use crate::mm::reclaim::page_reclaim::{PageType as LruPageType, lru_add_page};
use crate::mm::sync::rcu::rcu_read_lock;
use crate::mm::types::FrameIndex;
use crate::per_cpu::PerCpuHot;

use x86_64::structures::paging::{PhysFrame, Size4KiB};
mod integration;

// ============================================================================
// Page Setup Helper
// ============================================================================

/// ページの割り当て→初期化→memcgチャージ→マッピング→LRU追跡
/// の共通パターンを統合するヘルパー。
///
/// `fault_handler`, `demand_paging`, `stack_growth`, `file_backed` の
/// 同一パターンを統合し、エラー時のロールバック（リーク防止）を確実にする。
pub struct PageSetup {
    pub frame: PhysFrame<Size4KiB>,
    pub frame_phys: PhysAddr,
    pub frame_idx: FrameIndex,
    pub charge_type: ChargeType,
    memcg_id: Option<MemcgId>,
}

impl PageSetup {
    /// 新しいフレームを割り当ててチャージする
    pub fn allocate(memcg_id: Option<MemcgId>, charge_type: ChargeType) -> Option<Self> {
        let frame = alloc_frame()?;
        let frame_phys = PhysAddr::new(frame.start_address().as_u64());

        // Memcgチャージ（有効な場合のみ）
        if let Some(id) = memcg_id {
            if memcg_charge(id, 1, charge_type).is_err() {
                crate::mm::phys::frame_allocator::dealloc_frame(frame);
                return None;
            }
        }

        let frame_idx = FrameIndex::from_phys_addr(frame_phys.as_u64());
        Some(Self {
            frame,
            frame_phys,
            frame_idx,
            charge_type,
            memcg_id,
        })
    }

    /// ページをマッピングし、LRU + memcg追跡を完了する。
    ///
    /// 成功時は `Ok(())` を返す。
    /// 失敗時はチャージ+フレームをロールバックし、`MapError` を返す。
    ///
    /// # Safety
    /// ページテーブル操作を行うため unsafe。
    pub unsafe fn map_and_track(
        self,
        page_addr: VirtAddr,
        flags: PageFlags,
        lru_type: LruPageType,
    ) -> Result<(), MapError> {
        match global_map_page(page_addr, self.frame_phys, flags) {
            Ok(()) => {
                lru_add_page(self.frame, lru_type);
                if let Some(id) = self.memcg_id {
                    memcg_track_page(self.frame_idx, id, self.charge_type);
                }
                Ok(())
            }
            Err(e) => {
                self.rollback_inner();
                Err(e)
            }
        }
    }

    /// マッピングせずにロールバック（チャージ解除 + フレーム解放）。
    pub fn rollback(self) {
        self.rollback_inner();
    }

    fn rollback_inner(&self) {
        if let Some(id) = self.memcg_id {
            memcg_uncharge(id, 1, self.charge_type);
        }
        crate::mm::phys::frame_allocator::dealloc_frame(self.frame);
    }
}

// ============================================================================
// Page Fault Error Code
// ============================================================================

/// x86_64 Page Fault Error Code bits
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PageFaultErrorCode {
    bits: u64,
}

impl PageFaultErrorCode {
    /// Create from raw bits
    #[inline]
    pub fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Present bit (P): fault caused by non-present page
    #[inline]
    pub fn is_present(&self) -> bool {
        self.bits & (1 << 0) != 0
    }

    /// Write bit (W/R): fault caused by write access
    #[inline]
    pub fn is_write(&self) -> bool {
        self.bits & (1 << 1) != 0
    }

    /// User bit (U/S): fault occurred in user mode
    #[inline]
    pub fn is_user(&self) -> bool {
        self.bits & (1 << 2) != 0
    }

    /// Reserved write (RSVD): fault caused by reserved bit set
    #[inline]
    pub fn is_reserved_write(&self) -> bool {
        self.bits & (1 << 3) != 0
    }

    /// Instruction fetch (I/D): fault caused by instruction fetch
    #[inline]
    pub fn is_instruction_fetch(&self) -> bool {
        self.bits & (1 << 4) != 0
    }

    /// Protection key violation (PK)
    #[inline]
    pub fn is_protection_key(&self) -> bool {
        self.bits & (1 << 5) != 0
    }

    /// Shadow stack (SS)
    #[inline]
    pub fn is_shadow_stack(&self) -> bool {
        self.bits & (1 << 6) != 0
    }

    /// Software Guard Extensions (SGX)
    #[inline]
    pub fn is_sgx(&self) -> bool {
        self.bits & (1 << 15) != 0
    }

    /// Raw bits
    #[inline]
    pub fn bits(&self) -> u64 {
        self.bits
    }
}

// ============================================================================
// Fault Result
// ============================================================================

/// ページフォルト処理の結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResult {
    /// フォルト解決成功
    Resolved,
    /// VMAが見つからない（SIGSEGV相当）
    NoVma,
    /// 権限違反（SIGSEGV相当）
    PermissionDenied,
    /// メモリ不足（SIGBUS相当）
    OutOfMemory,
    /// スタック拡張限界超過
    StackOverflow,
    /// カーネルバグ検出
    KernelBug,
    /// Copy-on-Writeフォルト処理
    CowHandled,
    /// Demand Pagingで新規ページ割り当て
    DemandPaged,
    /// スタック拡張成功
    StackGrown,
    /// ファイルバックページロード成功
    FilePageLoaded,
    /// ファイルバックページI/O失敗
    IoError,
}

// ============================================================================
// Fault Statistics
// ============================================================================

/// フォルト統計
pub struct FaultStats {
    /// 総フォルト数
    pub total: AtomicU64,
    /// Demand Pagingフォルト
    pub demand_paging: AtomicU64,
    /// Copy-on-Writeフォルト
    pub cow: AtomicU64,
    /// スタック拡張フォルト
    pub stack_growth: AtomicU64,
    /// ファイルバックフォルト
    pub file_backed: AtomicU64,
    /// 権限違反
    pub permission_denied: AtomicU64,
    /// VMA不在
    pub no_vma: AtomicU64,
    /// OOM
    pub oom: AtomicU64,
}

impl FaultStats {
    pub const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            demand_paging: AtomicU64::new(0),
            cow: AtomicU64::new(0),
            stack_growth: AtomicU64::new(0),
            file_backed: AtomicU64::new(0),
            permission_denied: AtomicU64::new(0),
            no_vma: AtomicU64::new(0),
            oom: AtomicU64::new(0),
        }
    }
}

static FAULT_STATS: FaultStats = FaultStats::new();

// ============================================================================
// Fault Handler Context
// ============================================================================

/// フォルトハンドラコンテキスト
pub struct FaultContext {
    /// フォルトアドレス
    pub fault_addr: VirtAddr,
    /// エラーコード
    pub error_code: PageFaultErrorCode,
    /// 現在のタスクID（将来のプロセス管理用）
    pub task_id: u64,
    /// 再帰フォルト検出フラグ
    pub recursive: bool,
}

// ============================================================================
// Main Fault Handler
// ============================================================================

/// メインのページフォルトハンドラ
///
/// 例外ハンドラから呼び出される。VMA検索とフォルト種別判定を行い、
/// 適切なサブハンドラに処理を委譲する。
///
/// # 引数
///
/// * `error_code` - x86_64 Page Fault Error Code
///
/// # 戻り値
///
/// * `FaultResult` - フォルト処理結果
///
/// # Safety
///
/// この関数は割り込みコンテキストから呼ばれる可能性があるため、
/// ブロッキング操作を行ってはならない。
pub fn handle_page_fault(error_code: u64, current_rsp: VirtAddr) -> FaultResult {
    // 統計更新
    FAULT_STATS.total.fetch_add(1, Ordering::Relaxed);

    // フォルトアドレス取得
    let fault_addr = match Cr2::read() {
        Ok(addr) => VirtAddr::new(addr.as_u64()),
        Err(_) => return FaultResult::KernelBug,
    };

    let error = PageFaultErrorCode::from_bits(error_code);

    // 再帰フォルト検出（Per-CPU）
    let recursive = crate::per_cpu::with_current_hot(PerCpuHot::enter_page_fault).unwrap_or(false);

    if recursive {
        // 再帰フォルト - 致命的エラー
        // カーネル内のバグやスタック破損の可能性
        return FaultResult::KernelBug;
    }

    let result = handle_fault_inner(fault_addr, error, current_rsp);

    let _ = crate::per_cpu::with_current_hot(PerCpuHot::exit_page_fault);

    result
}

/// 内部フォルト処理
fn handle_fault_inner(
    fault_addr: VirtAddr,
    error: PageFaultErrorCode,
    current_rsp: VirtAddr,
) -> FaultResult {
    // Reserved bit violation は常にバグ
    if error.is_reserved_write() {
        return FaultResult::KernelBug;
    }

    // VMA検索（RCU保護）
    let _guard = rcu_read_lock();

    // 現在のプロセスのVMAリストを取得
    let asid = super::address_space::current_asid();
    let manager = super::address_space::address_space_manager();

    let vma: Option<super::rcu_vma::VmaInfo> = {
        let spaces_guard = match manager.spaces().lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };
        if let Some(space) = spaces_guard.get(&asid) {
            space.vma_list().find(fault_addr)
        } else {
            None
        }
    };

    // VMAが見つからない場合
    if vma.is_none() {
        // 脆弱性修正: スタック拡張の判定に RSP を使用し、無制限なページ割り当てを防止
        if is_potential_stack_access(fault_addr, current_rsp) {
            return handle_stack_growth(fault_addr, error);
        }

        FAULT_STATS.no_vma.fetch_add(1, Ordering::Relaxed);
        return FaultResult::NoVma;
    }

    let vma = vma.unwrap();

    // 権限チェック
    if error.is_write() && (vma.flags & VmaFlags::Write as u32 == 0) {
        // 書き込み不可だが CoW フラグがある場合は CoW ハンドラへ
        if vma.flags & VmaFlags::CopyOnWrite as u32 != 0 {
            return handle_cow_fault(fault_addr, error);
        }
        FAULT_STATS
            .permission_denied
            .fetch_add(1, Ordering::Relaxed);
        return FaultResult::PermissionDenied;
    }

    if error.is_instruction_fetch() && (vma.flags & VmaFlags::Execute as u32 == 0) {
        FAULT_STATS
            .permission_denied
            .fetch_add(1, Ordering::Relaxed);
        return FaultResult::PermissionDenied;
    }

    // Present bit がない場合 = ページが割り当てられていない または NUMA Hint Fault
    if !error.is_present() {
        // NUMA Hint Fault チェック
        if let Some(res) = handle_numa_hint_fault(fault_addr) {
            return res;
        }

        // ファイルバックか匿名ページか
        if vma.flags & VmaFlags::FileBacked as u32 != 0 {
            // MemoryRegion相当の情報を渡す必要があるため、handle_file_fault を修正して VmaInfo を受け取るようにする
            return handle_file_fault_info(fault_addr, &vma);
        } else {
            return handle_demand_paging(fault_addr, error, vma.flags);
        }
    }

    // 書き込みフォルト + Present = Copy-on-Write の可能性
    if error.is_write() && error.is_present() {
        if vma.flags & VmaFlags::CopyOnWrite as u32 != 0 {
            return handle_cow_fault(fault_addr, error);
        }
    }

    FAULT_STATS
        .permission_denied
        .fetch_add(1, Ordering::Relaxed);
    FaultResult::PermissionDenied
}

/// ファイルバックページのフォルトハンドラ (VmaInfo版)
fn handle_file_fault_info(fault_addr: VirtAddr, vma: &super::rcu_vma::VmaInfo) -> FaultResult {
    FAULT_STATS.file_backed.fetch_add(1, Ordering::Relaxed);

    let page_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);
    let file_offset = vma.file_offset + (page_addr.as_u64() - vma.start.as_u64());

    let memcg_id = crate::mm::meta::memcg::current_memcg_id();

    // 脆弱性修正: PageSetupを使用して、不完全なマッピングやリークを防止
    let setup = match PageSetup::allocate(Some(memcg_id), ChargeType::Cache) {
        Some(s) => s,
        None => {
            FAULT_STATS.oom.fetch_add(1, Ordering::Relaxed);
            return FaultResult::OutOfMemory;
        }
    };

    // ファイルシステムからページを読み込む
    zero_page(setup.frame_phys);
    let virt = super::mapping::phys_to_virt(x86_64::PhysAddr::new(setup.frame_phys.as_u64()));
    let buf = unsafe {
        core::slice::from_raw_parts_mut(virt.as_u64() as *mut u8, crate::mm::types::PAGE_SIZE_4K)
    };

    if crate::fs::fs_abstraction::read_inode_by_number(
        vma.file_inode as crate::fs::InodeNum,
        file_offset,
        buf,
    )
    .is_err()
    {
        setup.rollback();
        return FaultResult::IoError;
    }

    // マッピング作成
    let mut base_flags = PageFlags::PRESENT | PageFlags::USER;
    if (vma.flags & VmaFlags::Write as u32) != 0 {
        base_flags |= PageFlags::WRITABLE;
    }
    let flags = PageFlags::new(base_flags);

    match unsafe { setup.map_and_track(page_addr, flags, LruPageType::FileBacked) } {
        Ok(()) => FaultResult::FilePageLoaded,
        Err(MapError::AlreadyMapped) => FaultResult::Resolved,
        Err(_) => FaultResult::KernelBug,
    }
}

/// NUMA Hint Fault ハンドラ
fn handle_numa_hint_fault(fault_addr: VirtAddr) -> Option<FaultResult> {
    use super::higher_half::{PageFlags, with_current_pte_mut};
    use crate::mm::numa::autonuma::{NumaFaultAction, get_page_numa_stats, handle_numa_fault};

    // PTEを確認し、NUMA_HINTが立っているかチェック
    // 立っていればクリアしてPresentを立てる
    with_current_pte_mut(fault_addr, |pte| {
        let flags = pte.flags();
        if flags.contains(PageFlags::NUMA_HINT) {
            // Hintフラグをクリアし、Presentを立てる
            let new_flags = flags.clear(PageFlags::NUMA_HINT).set(PageFlags::PRESENT);
            pte.set_flags(new_flags);

            // TLB無効化（現在のアドレスなのでinvlpgでOK）
            super::higher_half::invalidate_page(fault_addr);

            // アクセス情報を記録＆マイグレーション判断
            let frame = FrameIndex::from_phys_addr(pte.phys_addr().as_u64());
            let stats = get_page_numa_stats(frame);

            // 現在のCPUのNUMAノードを取得
            if let Some(_cpu_id) = crate::per_cpu::try_current_cpu_id() {
                // NUMAノードIDを取得 (Per-CPUデータから)
                let node_id =
                    crate::per_cpu::with_current_cold(|cold| cold.get_local_numa_node().as_u8())
                        .unwrap_or(0);

                let action = handle_numa_fault(&stats, node_id, crate::time::current_time_ns());

                if let NumaFaultAction::Migrate {
                    from_node: _,
                    to_node,
                } = action
                {
                    use crate::mm::numa::autonuma::{MIGRATION_ENGINE, MigrationRequest};
                    // マイグレーションキューに追加
                    MIGRATION_ENGINE.queue_migration(MigrationRequest {
                        src_frame: frame,
                        dest_node: to_node,
                        priority: 5,
                        timestamp: crate::time::current_time_ns(),
                    });
                }
            }

            Some(FaultResult::Resolved)
        } else {
            None
        }
    })
    .flatten()
}

#[allow(unused_assignments)]
#[allow(dead_code)]
pub extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let rsp = VirtAddr::new(stack_frame.stack_pointer.as_u64());
    handle_page_fault(error_code.bits(), rsp);
}

/// 権限チェックを実行し、拒否された場合は結果を返す
fn check_vma_permission(
    error: PageFaultErrorCode,
    vma: &VmArea,
    fault_addr: VirtAddr,
) -> Option<FaultResult> {
    if error.is_write() && !vma.is_writable() {
        if vma.flags & VmaFlags::CopyOnWrite as u32 != 0 {
            return Some(handle_cow_fault(fault_addr, error));
        }
        FAULT_STATS
            .permission_denied
            .fetch_add(1, Ordering::Relaxed);
        return Some(FaultResult::PermissionDenied);
    }

    if error.is_instruction_fetch() && !vma.is_executable() {
        FAULT_STATS
            .permission_denied
            .fetch_add(1, Ordering::Relaxed);
        return Some(FaultResult::PermissionDenied);
    }
    None
}

/// VMAに対するフォルト処理
#[allow(dead_code)]
fn handle_vma_fault(fault_addr: VirtAddr, error: PageFaultErrorCode, vma: &VmArea) -> FaultResult {
    // 権限チェック
    if let Some(result) = check_vma_permission(error, vma, fault_addr) {
        return result;
    }

    // Present bit なし = Demand Paging
    if !error.is_present() {
        if vma.is_file_backed() {
            return handle_file_fault(fault_addr, vma);
        } else {
            return handle_demand_paging(fault_addr, error, vma.flags);
        }
    }

    // Present + Write + CoW
    if error.is_write() && (vma.flags & VmaFlags::CopyOnWrite as u32 != 0) {
        return handle_cow_fault(fault_addr, error);
    }

    FAULT_STATS
        .permission_denied
        .fetch_add(1, Ordering::Relaxed);
    FaultResult::PermissionDenied
}

// ============================================================================
// Demand Paging Handler
// ============================================================================

/// Demand Paging フォルトハンドラ
///
/// 初回アクセス時にページを割り当て、ゼロクリアしてマッピングする。
fn handle_demand_paging(
    fault_addr: VirtAddr,
    _error: PageFaultErrorCode,
    vma_flags: u32,
) -> FaultResult {
    FAULT_STATS.demand_paging.fetch_add(1, Ordering::Relaxed);

    let page_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);
    let memcg_id = crate::mm::meta::memcg::current_memcg_id();

    let setup = match PageSetup::allocate(Some(memcg_id), ChargeType::Anon) {
        Some(s) => s,
        None => {
            FAULT_STATS.oom.fetch_add(1, Ordering::Relaxed);
            return FaultResult::OutOfMemory;
        }
    };

    // ゼロクリア
    zero_page(setup.frame_phys);

    let mut base_flags = PageFlags::PRESENT | PageFlags::USER;
    if (vma_flags & VmaFlags::Write as u32) != 0 {
        base_flags |= PageFlags::WRITABLE;
    }
    let flags = PageFlags::new(base_flags);

    match unsafe { setup.map_and_track(page_addr, flags, LruPageType::Anonymous) } {
        Ok(()) => FaultResult::DemandPaged,
        Err(MapError::AlreadyMapped) => FaultResult::Resolved,
        Err(_) => FaultResult::KernelBug,
    }
}

/// ページをゼロクリア
fn zero_page(phys_addr: PhysAddr) {
    // 物理アドレスを仮想アドレスに変換（higher_half::PhysAddr -> x86_64::PhysAddr -> VirtAddr）
    let x86_phys = x86_64::PhysAddr::new(phys_addr.as_u64());
    let virt = super::mapping::phys_to_virt(x86_phys);

    unsafe {
        core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, 4096);
    }
}

// ============================================================================
// Copy-on-Write Handler
// ============================================================================

/// Copy-on-Write フォルトハンドラ
///
/// 共有ページへの書き込み時に、ページを複製して新しいマッピングを作成する。
fn handle_cow_fault(fault_addr: VirtAddr, _error: PageFaultErrorCode) -> FaultResult {
    FAULT_STATS.cow.fetch_add(1, Ordering::Relaxed);

    // cow.rs の cow_break を使用して共通化
    match super::cow::cow_break(fault_addr) {
        super::cow::CowResult::Ok => FaultResult::CowHandled,
        super::cow::CowResult::PageNotFound => FaultResult::KernelBug,
        super::cow::CowResult::OutOfMemory => FaultResult::OutOfMemory,
        super::cow::CowResult::MappingError => FaultResult::KernelBug,
        super::cow::CowResult::NotCow => FaultResult::PermissionDenied,
        super::cow::CowResult::AlreadyWritable => FaultResult::Resolved,
    }
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
// Stack Growth Handler
// ============================================================================

/// スタック領域の最大サイズ（8MB）
const MAX_STACK_SIZE: u64 = 8 * 1024 * 1024;

/// スタック拡張のガード領域サイズ（64KB）
const STACK_GUARD_SIZE: u64 = 64 * 1024;

/// ユーザースタックの仮想アドレス範囲（仮の値）
const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;
const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - MAX_STACK_SIZE;

/// アドレスがスタック拡張の対象か判定
fn is_potential_stack_access(addr: VirtAddr, current_rsp: VirtAddr) -> bool {
    let addr_u64 = addr.as_u64();
    let rsp_u64 = current_rsp.as_u64();

    // ユーザースタック領域内かチェック
    if addr_u64 < USER_STACK_BOTTOM || addr_u64 >= USER_STACK_TOP {
        return false;
    }

    // RSPに近いかチェック（ガードページ超えを防止）
    // x86_64では128バイトのレッドゾーンを考慮し、かつ1ページ分の余裕を持たせる
    addr_u64 + 4096 + 128 >= rsp_u64
}

/// スタック拡張フォルトハンドラ
fn handle_stack_growth(fault_addr: VirtAddr, error: PageFaultErrorCode) -> FaultResult {
    FAULT_STATS.stack_growth.fetch_add(1, Ordering::Relaxed);

    let page_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);

    // 脆弱性修正: スタック限界チェックの厳格化
    // アドレスがガードページ領域に入っている場合は StackOverflow
    if page_addr.as_u64() < USER_STACK_BOTTOM + STACK_GUARD_SIZE {
        return FaultResult::StackOverflow;
    }

    // 後続処理は Demand Paging と共通化してリークや不整合を防止
    handle_demand_paging(
        fault_addr,
        error,
        VmaFlags::Read as u32 | VmaFlags::Write as u32,
    )
}

// ============================================================================
// File-backed Page Handler
// ============================================================================

/// ファイルバックページのフォルトハンドラ
#[allow(dead_code)]
fn handle_file_fault(fault_addr: VirtAddr, vma: &VmArea) -> FaultResult {
    FAULT_STATS.file_backed.fetch_add(1, Ordering::Relaxed);

    let page_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);

    // ファイルオフセットを計算
    let file_offset = vma.file_offset + (page_addr.as_u64() - vma.start.as_u64());

    // 新しいフレームを割り当て
    let frame = match alloc_frame() {
        Some(f) => f,
        None => {
            FAULT_STATS.oom.fetch_add(1, Ordering::Relaxed);
            return FaultResult::OutOfMemory;
        }
    };

    // 物理アドレスをhigher_half型に変換
    let frame_phys = PhysAddr::new(frame.start_address().as_u64());

    // ファイルシステムからページを読み込む
    zero_page(frame_phys);
    let virt = super::mapping::phys_to_virt(x86_64::PhysAddr::new(frame_phys.as_u64()));
    let buf = unsafe {
        core::slice::from_raw_parts_mut(virt.as_u64() as *mut u8, crate::mm::types::PAGE_SIZE_4K)
    };
    if crate::fs::fs_abstraction::read_inode_by_number(
        vma.file_inode as crate::fs::InodeNum,
        file_offset,
        buf,
    )
    .is_err()
    {
        crate::mm::phys::frame_allocator::dealloc_frame(frame);
        return FaultResult::IoError;
    }

    // Memcgチャージ（ファイルキャッシュ）
    let memcg_id = crate::mm::meta::memcg::current_memcg_id();
    if memcg_charge(memcg_id, 1, ChargeType::Cache).is_err() {
        crate::mm::phys::frame_allocator::dealloc_frame(frame);
        FAULT_STATS.oom.fetch_add(1, Ordering::Relaxed);
        return FaultResult::OutOfMemory;
    }

    // マッピング作成
    let mut base_flags = PageFlags::PRESENT | PageFlags::USER;
    if vma.is_writable() {
        // Private file mapping: CoWフラグ付きでマッピング
        base_flags |= PageFlags::WRITABLE;
    }
    let flags = PageFlags::new(base_flags);

    // Safety: ページテーブル操作
    match unsafe { global_map_page(page_addr, frame_phys, flags) } {
        Ok(()) => {}
        Err(MapError::AlreadyMapped) => {
            memcg_uncharge(memcg_id, 1, ChargeType::Cache);
            crate::mm::phys::frame_allocator::dealloc_frame(frame);
            return FaultResult::Resolved;
        }
        Err(_) => {
            memcg_uncharge(memcg_id, 1, ChargeType::Cache);
            crate::mm::phys::frame_allocator::dealloc_frame(frame);
            return FaultResult::KernelBug;
        }
    }

    // LRUに追加
    lru_add_page(frame, LruPageType::FileBacked);

    // ページとmemcgを追跡
    let frame_idx = FrameIndex::from_phys_addr(frame_phys.as_u64());
    memcg_track_page(frame_idx, memcg_id, ChargeType::Cache);

    FaultResult::FilePageLoaded
}

// ============================================================================
// Statistics and Debug
// ============================================================================

/// フォルト統計を取得
pub fn fault_stats() -> FaultStatSnapshot {
    FaultStatSnapshot {
        total: FAULT_STATS.total.load(Ordering::Relaxed),
        demand_paging: FAULT_STATS.demand_paging.load(Ordering::Relaxed),
        cow: FAULT_STATS.cow.load(Ordering::Relaxed),
        stack_growth: FAULT_STATS.stack_growth.load(Ordering::Relaxed),
        file_backed: FAULT_STATS.file_backed.load(Ordering::Relaxed),
        permission_denied: FAULT_STATS.permission_denied.load(Ordering::Relaxed),
        no_vma: FAULT_STATS.no_vma.load(Ordering::Relaxed),
        oom: FAULT_STATS.oom.load(Ordering::Relaxed),
    }
}

/// フォルト統計スナップショット
#[derive(Debug, Clone, Copy)]
pub struct FaultStatSnapshot {
    pub total: u64,
    pub demand_paging: u64,
    pub cow: u64,
    pub stack_growth: u64,
    pub file_backed: u64,
    pub permission_denied: u64,
    pub no_vma: u64,
    pub oom: u64,
}
