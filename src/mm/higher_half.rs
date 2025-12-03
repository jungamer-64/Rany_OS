// ============================================================================
// src/mm/higher_half.rs - Higher Half Kernel Support
// ============================================================================
//!
//! # Higher Half Kernel サポート
//!
//! カーネルを仮想アドレス空間の上位半分にマップするための機能。
//!
//! ## アーキテクチャ
//! - カーネルは 0xFFFF_8000_0000_0000 以上にマップ
//! - 物理メモリは直接マップ（physical_memory_offset）
//! - ユーザースペースは下位半分を使用
//!
//! ## 型安全性
//! - VirtAddr / PhysAddr の明確な区別
//! - ページテーブル操作の安全な抽象化

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// Address Types
// ============================================================================

/// 仮想アドレス（型安全）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// カーネル空間の開始アドレス
    pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
    /// 物理メモリ直接マップの開始アドレス
    pub const PHYS_MAP_BASE: u64 = 0xFFFF_8880_0000_0000;
    /// カーネルヒープの開始アドレス
    pub const KERNEL_HEAP_BASE: u64 = 0xFFFF_C000_0000_0000;
    /// カーネルスタックの開始アドレス
    pub const KERNEL_STACK_BASE: u64 = 0xFFFF_E000_0000_0000;

    /// 新しい仮想アドレスを作成
    #[inline]
    pub const fn new(addr: u64) -> Self {
        // x86_64では47ビットアドレスを符号拡張
        let canonical = if addr & (1 << 47) != 0 {
            addr | 0xFFFF_0000_0000_0000
        } else {
            addr & 0x0000_FFFF_FFFF_FFFF
        };
        Self(canonical)
    }

    /// ゼロアドレス
    #[inline]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// ポインタとして取得
    #[inline]
    pub const fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    /// 可変ポインタとして取得
    #[inline]
    pub const fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// カーネル空間かどうか
    #[inline]
    pub const fn is_kernel_space(&self) -> bool {
        self.0 >= Self::KERNEL_BASE
    }

    /// ユーザー空間かどうか
    #[inline]
    pub const fn is_user_space(&self) -> bool {
        self.0 < Self::KERNEL_BASE
    }

    /// ページアラインされているか
    #[inline]
    pub const fn is_page_aligned(&self) -> bool {
        self.0 & 0xFFF == 0
    }

    /// ページ境界にアラインダウン
    #[inline]
    pub const fn align_down(&self) -> Self {
        Self(self.0 & !0xFFF)
    }

    /// ページ境界にアラインアップ
    #[inline]
    pub const fn align_up(&self) -> Self {
        Self((self.0 + 0xFFF) & !0xFFF)
    }

    /// オフセットを加算
    #[inline]
    pub const fn offset(&self, bytes: u64) -> Self {
        Self::new(self.0 + bytes)
    }

    /// ページテーブルインデックスを取得 (4レベル)
    #[inline]
    pub const fn page_table_indices(&self) -> [usize; 4] {
        [
            ((self.0 >> 39) & 0x1FF) as usize, // PML4
            ((self.0 >> 30) & 0x1FF) as usize, // PDPT
            ((self.0 >> 21) & 0x1FF) as usize, // PD
            ((self.0 >> 12) & 0x1FF) as usize, // PT
        ]
    }

    /// ページオフセットを取得
    #[inline]
    pub const fn page_offset(&self) -> u64 {
        self.0 & 0xFFF
    }
}

impl core::ops::Add<u64> for VirtAddr {
    type Output = VirtAddr;
    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        VirtAddr::new(self.0.wrapping_add(rhs))
    }
}

impl core::ops::Sub<VirtAddr> for VirtAddr {
    type Output = u64;
    #[inline]
    fn sub(self, rhs: VirtAddr) -> Self::Output {
        self.0.wrapping_sub(rhs.0)
    }
}

impl core::fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// 物理アドレス（型安全）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// 最大物理アドレス（52ビット）
    pub const MAX: u64 = (1 << 52) - 1;

    /// 新しい物理アドレスを作成
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr & Self::MAX)
    }

    /// ゼロアドレス
    #[inline]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// ページアラインされているか
    #[inline]
    pub const fn is_page_aligned(&self) -> bool {
        self.0 & 0xFFF == 0
    }

    /// ページ境界にアラインダウン
    #[inline]
    pub const fn align_down(&self) -> Self {
        Self(self.0 & !0xFFF)
    }

    /// ページ境界にアラインアップ
    #[inline]
    pub const fn align_up(&self) -> Self {
        Self((self.0 + 0xFFF) & !0xFFF)
    }

    /// フレーム番号を取得
    #[inline]
    pub const fn frame_number(&self) -> u64 {
        self.0 >> 12
    }

    /// フレーム番号から物理アドレスを作成
    #[inline]
    pub const fn from_frame_number(frame: u64) -> Self {
        Self(frame << 12)
    }
}

impl core::ops::Add<u64> for PhysAddr {
    type Output = PhysAddr;
    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        PhysAddr::new(self.0 + rhs)
    }
}

impl core::fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

// ============================================================================
// Page Size
// ============================================================================

/// ページサイズ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KiB (通常ページ)
    Size4KiB,
    /// 2 MiB (ラージページ)
    Size2MiB,
    /// 1 GiB (ギガページ)
    Size1GiB,
}

impl PageSize {
    /// サイズをバイトで取得
    pub const fn as_bytes(&self) -> u64 {
        match self {
            PageSize::Size4KiB => 4 * 1024,
            PageSize::Size2MiB => 2 * 1024 * 1024,
            PageSize::Size1GiB => 1024 * 1024 * 1024,
        }
    }

    /// ページテーブルレベルを取得 (0 = PT, 1 = PD, 2 = PDPT)
    pub const fn table_level(&self) -> usize {
        match self {
            PageSize::Size4KiB => 0,
            PageSize::Size2MiB => 1,
            PageSize::Size1GiB => 2,
        }
    }
}

// ============================================================================
// Page Table Entry
// ============================================================================

/// ページテーブルエントリのフラグ
#[derive(Debug, Clone, Copy)]
pub struct PageFlags(u64);

impl PageFlags {
    /// Present
    pub const PRESENT: u64 = 1 << 0;
    /// Writable
    pub const WRITABLE: u64 = 1 << 1;
    /// User accessible
    pub const USER: u64 = 1 << 2;
    /// Write-through caching
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Disable caching
    pub const NO_CACHE: u64 = 1 << 4;
    /// Accessed
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty
    pub const DIRTY: u64 = 1 << 6;
    /// Huge page (2MiB/1GiB)
    pub const HUGE_PAGE: u64 = 1 << 7;
    /// Global
    pub const GLOBAL: u64 = 1 << 8;
    /// No execute
    pub const NO_EXECUTE: u64 = 1 << 63;

    /// 新しいフラグを作成
    #[inline]
    pub const fn new(flags: u64) -> Self {
        Self(flags)
    }

    /// 空のフラグ
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// カーネルデータ用（読み書き可能、実行不可）
    #[inline]
    pub const fn kernel_data() -> Self {
        Self(Self::PRESENT | Self::WRITABLE | Self::NO_EXECUTE | Self::GLOBAL)
    }

    /// カーネルコード用（読み取り専用、実行可能）
    #[inline]
    pub const fn kernel_code() -> Self {
        Self(Self::PRESENT | Self::GLOBAL)
    }

    /// カーネル読み取り専用用
    #[inline]
    pub const fn kernel_rodata() -> Self {
        Self(Self::PRESENT | Self::NO_EXECUTE | Self::GLOBAL)
    }

    /// ユーザーデータ用
    #[inline]
    pub const fn user_data() -> Self {
        Self(Self::PRESENT | Self::WRITABLE | Self::USER | Self::NO_EXECUTE)
    }

    /// ユーザーコード用
    #[inline]
    pub const fn user_code() -> Self {
        Self(Self::PRESENT | Self::USER)
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// フラグを設定
    #[inline]
    pub const fn set(&self, flag: u64) -> Self {
        Self(self.0 | flag)
    }

    /// フラグをクリア
    #[inline]
    pub const fn clear(&self, flag: u64) -> Self {
        Self(self.0 & !flag)
    }

    /// フラグが設定されているか
    #[inline]
    pub const fn contains(&self, flag: u64) -> bool {
        (self.0 & flag) == flag
    }
}

/// ページテーブルエントリ
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// アドレスマスク (52ビット物理アドレス、4KB アライン)
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// 空のエントリ
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 新しいエントリを作成
    #[inline]
    pub const fn new(phys_addr: PhysAddr, flags: PageFlags) -> Self {
        Self((phys_addr.as_u64() & Self::ADDR_MASK) | flags.as_u64())
    }

    /// ヒュージページエントリを作成
    #[inline]
    pub const fn huge(phys_addr: PhysAddr, flags: PageFlags) -> Self {
        Self((phys_addr.as_u64() & Self::ADDR_MASK) | flags.as_u64() | PageFlags::HUGE_PAGE)
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Presentか
    #[inline]
    pub const fn is_present(&self) -> bool {
        (self.0 & PageFlags::PRESENT) != 0
    }

    /// ヒュージページか
    #[inline]
    pub const fn is_huge(&self) -> bool {
        (self.0 & PageFlags::HUGE_PAGE) != 0
    }

    /// 物理アドレスを取得
    #[inline]
    pub const fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & Self::ADDR_MASK)
    }

    /// フラグを取得
    #[inline]
    pub const fn flags(&self) -> PageFlags {
        PageFlags::new(self.0 & !Self::ADDR_MASK)
    }

    /// フラグを設定
    #[inline]
    pub fn set_flags(&mut self, flags: PageFlags) {
        self.0 = (self.0 & Self::ADDR_MASK) | flags.as_u64();
    }

    /// エントリをクリア
    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("present", &self.is_present())
            .field("phys_addr", &self.phys_addr())
            .field("huge", &self.is_huge())
            .finish()
    }
}

// ============================================================================
// Page Table
// ============================================================================

/// ページテーブル（512エントリ）
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; 512],
}

impl PageTable {
    /// 空のページテーブルを作成
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry::empty(); 512],
        }
    }

    /// エントリを取得
    #[inline]
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    /// エントリを可変参照で取得
    #[inline]
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }

    /// エントリのイテレータ
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &PageTableEntry> {
        self.entries.iter()
    }

    /// 全エントリをクリア
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.clear();
        }
    }
}

// ============================================================================
// Physical Memory Mapper
// ============================================================================

/// 物理メモリマッパー
/// 物理アドレスと仮想アドレス間の変換を提供
pub struct PhysicalMemoryMapper {
    /// 物理メモリオフセット
    offset: u64,
}

impl PhysicalMemoryMapper {
    /// 新しいマッパーを作成
    pub const fn new(physical_memory_offset: u64) -> Self {
        Self {
            offset: physical_memory_offset,
        }
    }

    /// 物理アドレスから仮想アドレスに変換
    #[inline]
    pub fn phys_to_virt(&self, phys: PhysAddr) -> VirtAddr {
        VirtAddr::new(phys.as_u64() + self.offset)
    }

    /// 仮想アドレスから物理アドレスに変換（直接マップ領域のみ）
    #[inline]
    pub fn virt_to_phys(&self, virt: VirtAddr) -> Option<PhysAddr> {
        if virt.as_u64() >= self.offset {
            Some(PhysAddr::new(virt.as_u64() - self.offset))
        } else {
            None
        }
    }

    /// 物理アドレスをポインタとして取得
    #[inline]
    pub fn phys_as_ptr<T>(&self, phys: PhysAddr) -> *const T {
        self.phys_to_virt(phys).as_ptr()
    }

    /// 物理アドレスを可変ポインタとして取得
    #[inline]
    pub fn phys_as_mut_ptr<T>(&self, phys: PhysAddr) -> *mut T {
        self.phys_to_virt(phys).as_mut_ptr()
    }
}

// ============================================================================
// Page Table Walker
// ============================================================================

/// ページテーブルウォーカー
pub struct PageTableWalker<'a> {
    /// PML4の物理アドレス
    pml4_phys: PhysAddr,
    /// 物理メモリマッパー
    mapper: &'a PhysicalMemoryMapper,
}

impl<'a> PageTableWalker<'a> {
    /// 新しいウォーカーを作成
    pub fn new(pml4_phys: PhysAddr, mapper: &'a PhysicalMemoryMapper) -> Self {
        Self { pml4_phys, mapper }
    }

    /// 現在のCR3からウォーカーを作成
    pub unsafe fn from_current_cr3(mapper: &'a PhysicalMemoryMapper) -> Self { unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        Self::new(PhysAddr::new(cr3 & !0xFFF), mapper)
    }}

    /// 仮想アドレスを物理アドレスに変換
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let indices = virt.page_table_indices();

        // PML4
        let pml4: &PageTable = unsafe { &*self.mapper.phys_as_ptr(self.pml4_phys) };
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() {
            return None;
        }

        // PDPT
        let pdpt: &PageTable = unsafe { &*self.mapper.phys_as_ptr(pml4e.phys_addr()) };
        let pdpte = pdpt.entry(indices[1]);
        if !pdpte.is_present() {
            return None;
        }
        if pdpte.is_huge() {
            // 1GiB page
            let base = pdpte.phys_addr().as_u64() & !(PageSize::Size1GiB.as_bytes() - 1);
            let offset = virt.as_u64() & (PageSize::Size1GiB.as_bytes() - 1);
            return Some(PhysAddr::new(base + offset));
        }

        // PD
        let pd: &PageTable = unsafe { &*self.mapper.phys_as_ptr(pdpte.phys_addr()) };
        let pde = pd.entry(indices[2]);
        if !pde.is_present() {
            return None;
        }
        if pde.is_huge() {
            // 2MiB page
            let base = pde.phys_addr().as_u64() & !(PageSize::Size2MiB.as_bytes() - 1);
            let offset = virt.as_u64() & (PageSize::Size2MiB.as_bytes() - 1);
            return Some(PhysAddr::new(base + offset));
        }

        // PT
        let pt: &PageTable = unsafe { &*self.mapper.phys_as_ptr(pde.phys_addr()) };
        let pte = pt.entry(indices[3]);
        if !pte.is_present() {
            return None;
        }

        // 4KiB page
        Some(PhysAddr::new(pte.phys_addr().as_u64() + virt.page_offset()))
    }
}

// ============================================================================
// Higher Half Kernel Manager
// ============================================================================

/// Higher Half Kernel マネージャー
pub struct HigherHalfManager {
    /// 物理メモリマッパー
    mapper: PhysicalMemoryMapper,
    /// カーネルの開始仮想アドレス
    kernel_start: VirtAddr,
    /// カーネルの終了仮想アドレス
    kernel_end: VirtAddr,
    /// 次に割り当て可能なカーネル仮想アドレス
    next_kernel_addr: AtomicU64,
}

impl HigherHalfManager {
    /// 新しいマネージャーを作成
    pub const fn new(physical_memory_offset: u64) -> Self {
        Self {
            mapper: PhysicalMemoryMapper::new(physical_memory_offset),
            kernel_start: VirtAddr::new(VirtAddr::KERNEL_BASE),
            kernel_end: VirtAddr::new(VirtAddr::KERNEL_BASE),
            next_kernel_addr: AtomicU64::new(VirtAddr::KERNEL_HEAP_BASE),
        }
    }

    /// 物理メモリマッパーを取得
    pub fn mapper(&self) -> &PhysicalMemoryMapper {
        &self.mapper
    }

    /// カーネル仮想アドレス領域を割り当て
    pub fn allocate_kernel_virt(&self, pages: usize) -> VirtAddr {
        let size = (pages as u64) * PageSize::Size4KiB.as_bytes();
        let addr = self.next_kernel_addr.fetch_add(size, Ordering::SeqCst);
        VirtAddr::new(addr)
    }

    /// カーネル空間内かどうか判定
    pub fn is_kernel_address(&self, addr: VirtAddr) -> bool {
        addr.is_kernel_space()
    }
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルHigher Halfマネージャー
static HIGHER_HALF_MANAGER: Mutex<Option<HigherHalfManager>> = Mutex::new(None);

/// Higher Halfカーネルを初期化
pub fn init(physical_memory_offset: u64) {
    let manager = HigherHalfManager::new(physical_memory_offset);
    *HIGHER_HALF_MANAGER.lock() = Some(manager);
    // log::info!("Higher half kernel initialized with offset {:#x}", physical_memory_offset);
}

/// 物理アドレスを仮想アドレスに変換
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    let guard = HIGHER_HALF_MANAGER.lock();
    let manager = guard.as_ref().expect("Higher half not initialized");
    manager.mapper().phys_to_virt(phys)
}

/// 仮想アドレスを物理アドレスに変換（直接マップ領域）
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    let guard = HIGHER_HALF_MANAGER.lock();
    let manager = guard.as_ref().expect("Higher half not initialized");
    manager.mapper().virt_to_phys(virt)
}

// ============================================================================
// TLB Operations
// ============================================================================

/// TLBを無効化（単一アドレス）
#[inline]
pub fn invalidate_page(addr: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
    }
}

/// TLBを全無効化
#[inline]
pub fn flush_tlb() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// CR3を設定
#[inline]
pub unsafe fn set_cr3(pml4_phys: PhysAddr) { unsafe {
    core::arch::asm!("mov cr3, {}", in(reg) pml4_phys.as_u64(), options(nostack, preserves_flags));
}}

/// CR3を取得
#[inline]
pub fn get_cr3() -> PhysAddr {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    PhysAddr::new(cr3 & !0xFFF)
}
