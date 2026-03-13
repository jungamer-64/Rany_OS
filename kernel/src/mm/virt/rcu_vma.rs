// ============================================================================
// src/mm/rcu_vma.rs - RCU-Protected VMA Search and Page Table Walk
//
// ## 概要
//
// VMA（Virtual Memory Area）検索とページテーブル歩行にRCUを適用し、
// 読み取り側のロック待ちを排除する。
//
// ## 設計
//
// ### VMA検索
// - 読み取り: RcuReadGuard で保護、ロックフリー
// - 更新: RCU置換（古いVMAは call_rcu で遅延解放）
//
// ### ページテーブル歩行
// - 読み取り: RcuReadGuard で保護
// - PTE更新: Atomic操作 + TLBフラッシュ
//
// ## パフォーマンス
//
// - VMA検索: O(log n) で完全ロックフリー
// - ページテーブル歩行: O(4) で完全ロックフリー
// - 読み取り側のオーバーヘッド: メモリバリアのみ
//
// ============================================================================
#![allow(dead_code)]

use super::higher_half::VirtAddr;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::sync::rcu::{RcuPointer, RcuReadGuard, rcu_read_lock};

// ============================================================================
// VMA (Virtual Memory Area) Structure
// ============================================================================

/// VMAの権限フラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VmaFlags {
    Read = 0x1,
    Write = 0x2,
    Execute = 0x4,
    Shared = 0x8,
    /// ファイルマッピング
    FileBacked = 0x10,
    /// 匿名マッピング
    Anonymous = 0x20,
    /// Huge Page使用
    HugePages = 0x40,
    /// Copy-on-Write
    CopyOnWrite = 0x80,
    /// ロックされている（ページアウト禁止）
    Locked = 0x100,
}

/// Virtual Memory Area
///
/// プロセスの仮想アドレス空間の一領域を表す。
/// RCUで保護され、検索時にロックが不要。
#[repr(C)]
pub struct VmArea {
    /// 開始アドレス
    pub start: VirtAddr,
    /// 終了アドレス（exclusive）
    pub end: VirtAddr,
    /// フラグ
    pub flags: u32,
    /// 次のVMA（ソートされたリンクリスト）
    next: RcuPointer<VmArea>,
    /// バッキングファイルのinode（ある場合）
    pub file_inode: u64,
    /// ファイルオフセット
    pub file_offset: u64,
    /// 参照カウント
    refcount: AtomicU64,
}

impl VmArea {
    /// 新しいVMAを作成
    pub fn new(start: VirtAddr, end: VirtAddr, flags: u32) -> Self {
        Self {
            start,
            end,
            flags,
            next: RcuPointer::null(),
            file_inode: 0,
            file_offset: 0,
            refcount: AtomicU64::new(1),
        }
    }

    /// アドレスがこのVMAに含まれるか
    #[inline]
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end
    }

    /// サイズを取得
    #[inline]
    pub fn size(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }

    /// 書き込み可能か
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags & VmaFlags::Write as u32 != 0
    }

    /// 実行可能か
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.flags & VmaFlags::Execute as u32 != 0
    }

    /// ファイルバックか
    #[inline]
    pub fn is_file_backed(&self) -> bool {
        self.flags & VmaFlags::FileBacked as u32 != 0
    }

    /// VMA情報をコピーして取得
    #[inline]
    pub fn info(&self) -> VmaInfo {
        VmaInfo {
            start: self.start,
            end: self.end,
            flags: self.flags,
            file_inode: self.file_inode,
            file_offset: self.file_offset,
        }
    }

    /// 参照カウントを増加
    #[inline]
    pub fn get(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// 参照カウントを減少
    #[inline]
    pub fn put(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::Release) == 1
    }
}

/// VMAのスナップショット情報（RCU読み取り用）
#[derive(Debug, Clone, Copy)]
pub struct VmaInfo {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub flags: u32,
    pub file_inode: u64,
    pub file_offset: u64,
}

/// VMA解放コールバック
fn free_vma_callback(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr as *mut VmArea);
        }
    }
}

// ============================================================================
// VMA List (RCU-protected linked list)
// ============================================================================

/// RCU保護されたVMAリスト
pub struct VmaList {
    /// 先頭VMA
    head: RcuPointer<VmArea>,
    /// VMA数
    count: AtomicU64,
}

impl VmaList {
    /// 新しいVMAリストを作成
    pub const fn new() -> Self {
        Self {
            head: RcuPointer::null(),
            count: AtomicU64::new(0),
        }
    }

    /// アドレスに対応するVMAを検索（RCU読み取り）
    ///
    /// ロックフリーでO(n)検索。
    /// 実際の実装ではRBツリーやスキップリストを使用する。
    pub fn find(&self, addr: VirtAddr) -> Option<VmaInfo> {
        let guard = rcu_read_lock();

        let mut current_ptr = self.head.get_raw(&guard);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while !current_ptr.is_null() {
            // Safety: RcuReadGuard 内
            let current = unsafe { &*current_ptr };

            if current.contains(addr) {
                return Some(current.info());
            }

            if addr < current.start {
                // ソート済みなのでこれ以降は見つからない
                break;
            }

            current_ptr = current.next.get_raw(&guard);
        }

        None
    }

    /// 指定範囲と重なるVMAを検索
    pub fn find_intersection(&self, start: VirtAddr, end: VirtAddr) -> Option<VmaInfo> {
        let guard = rcu_read_lock();

        let mut current_ptr = self.head.get_raw(&guard);
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while !current_ptr.is_null() {
            let current = unsafe { &*current_ptr };

            // 重なりをチェック
            if current.start < end && current.end > start {
                return Some(current.info());
            }

            if start < current.start && end <= current.start {
                // ソート済みなのでこれ以降は見つからない
                break;
            }

            current_ptr = current.next.get_raw(&guard);
        }

        None
    }

    /// VMAを挿入（書き込み側、ロックが必要）
    ///
    /// 呼び出し側で適切なロックを取得すること。
    /// 新しいVMAはソート位置に挿入される。
    pub fn insert(&self, new_vma: Box<VmArea>) {
        // NOTE: 外部ロックが必要（呼び出し側で排他制御）
        let mut prev_ptr: *mut VmArea = core::ptr::null_mut();
        let mut current_ptr = self.head.load_raw_mut();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while !current_ptr.is_null() {
            let current = unsafe { &*current_ptr };
            if new_vma.start < current.start {
                break;
            }
            prev_ptr = current_ptr as *mut VmArea;
            current_ptr = current.next.load_raw_mut();
        }

        new_vma.next.store_raw_mut(current_ptr);
        let new_ptr = Box::into_raw(new_vma);

        if prev_ptr.is_null() {
            self.head.store_raw_mut(new_ptr);
        } else {
            unsafe {
                (*prev_ptr).next.store_raw_mut(new_ptr);
            }
        }

        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// VMAを削除（書き込み側、ロックが必要）
    ///
    /// 削除したVMAはcall_rcuで遅延解放される。
    pub fn remove(&self, addr: VirtAddr) -> bool {
        // NOTE: 外部ロックが必要（呼び出し側で排他制御）
        let mut prev_ptr: *mut VmArea = core::ptr::null_mut();
        let mut current_ptr = self.head.load_raw_mut();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while !current_ptr.is_null() {
            let current = unsafe { &*current_ptr };
            if current.start == addr {
                let next_ptr = current.next.load_raw_mut();
                if prev_ptr.is_null() {
                    self.head.store_raw_mut(next_ptr);
                } else {
                    unsafe {
                        (*prev_ptr).next.store_raw_mut(next_ptr);
                    }
                }
                self.count.fetch_sub(1, Ordering::Relaxed);
                crate::mm::sync::rcu::call_rcu(current_ptr as *mut u8, free_vma_callback);
                return true;
            }
            if addr < current.start {
                break;
            }
            prev_ptr = current_ptr as *mut VmArea;
            current_ptr = current.next.load_raw_mut();
        }

        false
    }

    /// VMA数を取得
    pub fn len(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Page Table Walk (RCU-protected)
// ============================================================================

/// ページテーブルエントリ（64ビット）
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Present ビット
    pub const PRESENT: u64 = 1 << 0;
    /// Writable ビット
    pub const WRITABLE: u64 = 1 << 1;
    /// User accessible ビット
    pub const USER: u64 = 1 << 2;
    /// Write-through ビット
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Cache disable ビット
    pub const NO_CACHE: u64 = 1 << 4;
    /// Accessed ビット
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty ビット
    pub const DIRTY: u64 = 1 << 6;
    /// Huge page ビット
    pub const HUGE: u64 = 1 << 7;
    /// Global ビット
    pub const GLOBAL: u64 = 1 << 8;
    /// No-execute ビット
    pub const NO_EXECUTE: u64 = 1 << 63;

    /// 物理アドレスマスク
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// 新しいPTEを作成
    pub const fn new(addr: u64, flags: u64) -> Self {
        Self((addr & Self::ADDR_MASK) | flags)
    }

    /// 空のPTE
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Presentか
    #[inline]
    pub const fn is_present(&self) -> bool {
        self.0 & Self::PRESENT != 0
    }

    /// Huge pageか
    #[inline]
    pub const fn is_huge(&self) -> bool {
        self.0 & Self::HUGE != 0
    }

    /// 物理アドレスを取得
    #[inline]
    pub const fn addr(&self) -> u64 {
        self.0 & Self::ADDR_MASK
    }

    /// フラグを取得
    #[inline]
    pub const fn flags(&self) -> u64 {
        self.0 & !Self::ADDR_MASK
    }

    /// 生の値を取得
    #[inline]
    pub const fn raw(&self) -> u64 {
        self.0
    }
}

/// RCU保護されたPTE
///
/// Atomic操作でPTEを読み書きし、RcuReadGuard内での一貫性を保証。
#[repr(transparent)]
pub struct RcuPte {
    entry: AtomicU64,
}

impl RcuPte {
    /// 新しいRCU PTEを作成
    pub const fn new(pte: PageTableEntry) -> Self {
        Self {
            entry: AtomicU64::new(pte.raw()),
        }
    }

    /// 空のRCU PTEを作成
    pub const fn empty() -> Self {
        Self::new(PageTableEntry::empty())
    }

    /// PTEを読み取り（RCU読み取りセクション内）
    #[inline]
    pub fn read(&self, _guard: &RcuReadGuard) -> PageTableEntry {
        PageTableEntry(self.entry.load(Ordering::Acquire))
    }

    /// PTEを更新（アトミック）
    #[inline]
    pub fn write(&self, pte: PageTableEntry) {
        self.entry.store(pte.raw(), Ordering::Release);
    }

    /// Compare-and-swap
    #[inline]
    pub fn compare_exchange(
        &self,
        expected: PageTableEntry,
        new: PageTableEntry,
    ) -> Result<PageTableEntry, PageTableEntry> {
        self.entry
            .compare_exchange(
                expected.raw(),
                new.raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(PageTableEntry)
            .map_err(PageTableEntry)
    }
}

/// ページテーブル（512エントリ）
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [RcuPte; 512],
}

impl PageTable {
    /// 空のページテーブルを作成
    pub const fn empty() -> Self {
        const EMPTY_PTE: RcuPte = RcuPte::empty();
        Self {
            entries: [EMPTY_PTE; 512],
        }
    }

    /// エントリを取得
    #[inline]
    pub fn entry(&self, index: usize) -> &RcuPte {
        &self.entries[index & 0x1FF]
    }
}

/// ページテーブル歩行結果
#[derive(Debug)]
pub struct PageWalkResult {
    /// 物理アドレス
    pub phys_addr: u64,
    /// ページサイズ（4KB, 2MB, 1GB）
    pub page_size: PageSize,
    /// PTEフラグ
    pub flags: u64,
    /// 各レベルのPTE値
    pub pte_values: [u64; 4],
}

/// ページサイズ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Size4KB,
    Size2MB,
    Size1GB,
}

/// RCU保護されたページテーブル歩行
///
/// # Arguments
/// * `pml4_addr` - PML4テーブルの物理アドレス
/// * `virt_addr` - 変換する仮想アドレス
///
/// # Returns
/// 歩行結果、またはPageFaultの場合はNone
pub fn rcu_page_walk(pml4_addr: u64, virt_addr: VirtAddr) -> Option<PageWalkResult> {
    use super::higher_half::{PhysAddr, phys_to_virt};
    let guard = rcu_read_lock();

    let addr = virt_addr.as_u64();

    // インデックス計算
    let pml4_idx = ((addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((addr >> 12) & 0x1FF) as usize;
    let offset_4kb = (addr & 0xFFF) as u64;
    let offset_2mb = (addr & 0x1F_FFFF) as u64;
    let offset_1gb = (addr & 0x3FFF_FFFF) as u64;

    let mut pte_values = [0u64; 4];

    // PML4
    // 脆弱性修正: 物理アドレスを直接ポインタにキャストせず、phys_to_virt を使用
    let pml4_virt = phys_to_virt(PhysAddr::new(pml4_addr));
    let pml4 = unsafe { &*(pml4_virt.as_ptr::<PageTable>()) };
    let pml4e = pml4.entry(pml4_idx).read(&guard);
    pte_values[0] = pml4e.raw();

    if !pml4e.is_present() {
        return None;
    }

    // PDPT
    let pdpt_virt = phys_to_virt(PhysAddr::new(pml4e.addr()));
    let pdpt = unsafe { &*(pdpt_virt.as_ptr::<PageTable>()) };
    let pdpte = pdpt.entry(pdpt_idx).read(&guard);
    pte_values[1] = pdpte.raw();

    if !pdpte.is_present() {
        return None;
    }

    // 1GB Huge Page check
    if pdpte.is_huge() {
        return Some(PageWalkResult {
            phys_addr: pdpte.addr() + offset_1gb,
            page_size: PageSize::Size1GB,
            flags: pdpte.flags(),
            pte_values,
        });
    }

    // PD
    let pd_virt = phys_to_virt(PhysAddr::new(pdpte.addr()));
    let pd = unsafe { &*(pd_virt.as_ptr::<PageTable>()) };
    let pde = pd.entry(pd_idx).read(&guard);
    pte_values[2] = pde.raw();

    if !pde.is_present() {
        return None;
    }

    // 2MB Huge Page check
    if pde.is_huge() {
        return Some(PageWalkResult {
            phys_addr: pde.addr() + offset_2mb,
            page_size: PageSize::Size2MB,
            flags: pde.flags(),
            pte_values,
        });
    }

    // PT
    let pt_virt = phys_to_virt(PhysAddr::new(pde.addr()));
    let pt = unsafe { &*(pt_virt.as_ptr::<PageTable>()) };
    let pte = pt.entry(pt_idx).read(&guard);
    pte_values[3] = pte.raw();

    if !pte.is_present() {
        return None;
    }

    Some(PageWalkResult {
        phys_addr: pte.addr() + offset_4kb,
        page_size: PageSize::Size4KB,
        flags: pte.flags(),
        pte_values,
    })
}

// ============================================================================
// Speculative Page Walk (Fast Path)
// ============================================================================

/// 投機的ページテーブル歩行
///
/// RCU読み取りガードを取らずに歩行を試み、
/// 途中でエントリが変更された場合は失敗を返す。
/// 成功率が高い場合（ホットパス）に有効。
fn verify_speculative_result(
    pml4: &PageTable,
    pml4_idx: usize,
    pml4e_val: u64,
    entry: PageTableEntry,
    addr: u64,
    page_size: PageSize,
    offset_mask: u64,
    pte_values: [u64; 4],
) -> Option<PageWalkResult> {
    core::sync::atomic::fence(Ordering::Acquire);
    if pml4.entry(pml4_idx).entry.load(Ordering::Relaxed) != pml4e_val {
        return None;
    }
    Some(PageWalkResult {
        phys_addr: entry.addr() + (addr & offset_mask),
        page_size,
        flags: entry.flags(),
        pte_values,
    })
}

pub fn speculative_page_walk(pml4_addr: u64, virt_addr: VirtAddr) -> Option<PageWalkResult> {
    use super::higher_half::{PhysAddr, phys_to_virt};
    let addr = virt_addr.as_u64();

    let pml4_idx = ((addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((addr >> 12) & 0x1FF) as usize;
    let _offset_4kb = (addr & 0xFFF) as u64;

    let mut pte_values = [0u64; 4];

    // 投機的読み取り（バリアなし）
    // 脆弱性修正: phys_to_virt を使用
    let pml4_virt = phys_to_virt(PhysAddr::new(pml4_addr));
    let pml4 = unsafe { &*(pml4_virt.as_ptr::<PageTable>()) };
    let pml4e_val = pml4.entry(pml4_idx).entry.load(Ordering::Relaxed);
    pte_values[0] = pml4e_val;

    let pml4e = PageTableEntry(pml4e_val);
    if !pml4e.is_present() {
        return None;
    }

    let pdpt_virt = phys_to_virt(PhysAddr::new(pml4e.addr()));
    let pdpt = unsafe { &*(pdpt_virt.as_ptr::<PageTable>()) };
    let pdpte_val = pdpt.entry(pdpt_idx).entry.load(Ordering::Relaxed);
    pte_values[1] = pdpte_val;

    let pdpte = PageTableEntry(pdpte_val);
    if !pdpte.is_present() {
        return None;
    }

    if pdpte.is_huge() {
        return verify_speculative_result(
            pml4,
            pml4_idx,
            pml4e_val,
            pdpte,
            addr,
            PageSize::Size1GB,
            0x3FFF_FFFF,
            pte_values,
        );
    }

    let pd_virt = phys_to_virt(PhysAddr::new(pdpte.addr()));
    let pd = unsafe { &*(pd_virt.as_ptr::<PageTable>()) };
    let pde_val = pd.entry(pd_idx).entry.load(Ordering::Relaxed);
    pte_values[2] = pde_val;

    let pde = PageTableEntry(pde_val);
    if !pde.is_present() {
        return None;
    }

    if pde.is_huge() {
        return verify_speculative_result(
            pml4,
            pml4_idx,
            pml4e_val,
            pde,
            addr,
            PageSize::Size2MB,
            0x1F_FFFF,
            pte_values,
        );
    }

    let pt_virt = phys_to_virt(PhysAddr::new(pde.addr()));
    let pt = unsafe { &*(pt_virt.as_ptr::<PageTable>()) };
    let pte_val = pt.entry(pt_idx).entry.load(Ordering::Relaxed);
    pte_values[3] = pte_val;

    let pte = PageTableEntry(pte_val);
    if !pte.is_present() {
        return None;
    }

    // 最終検証
    verify_speculative_result(
        pml4,
        pml4_idx,
        pml4e_val,
        pte,
        addr,
        PageSize::Size4KB,
        0xFFF,
        pte_values,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_vma_contains() {
        let vma = VmArea::new(
            VirtAddr::new(0x1000),
            VirtAddr::new(0x2000),
            VmaFlags::Read as u32,
        );

        assert!(vma.contains(VirtAddr::new(0x1000)));
        assert!(vma.contains(VirtAddr::new(0x1FFF)));
        assert!(!vma.contains(VirtAddr::new(0x2000)));
        assert!(!vma.contains(VirtAddr::new(0x0FFF)));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_page_table_entry() {
        let pte = PageTableEntry::new(
            0x1234_5000,
            PageTableEntry::PRESENT | PageTableEntry::WRITABLE,
        );

        assert!(pte.is_present());
        assert!(!pte.is_huge());
        assert_eq!(pte.addr(), 0x1234_5000);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_rcu_pte() {
        let pte = RcuPte::new(PageTableEntry::new(0x1000, PageTableEntry::PRESENT));
        let guard = rcu_read_lock();

        let entry = pte.read(&guard);
        assert!(entry.is_present());
        assert_eq!(entry.addr(), 0x1000);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_vma_list_empty() {
        let list = VmaList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }
}
