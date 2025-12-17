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

use crate::sync::PoisonLock;
use core::sync::atomic::{AtomicU64, Ordering};

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
///
/// 設計書 9.2.2: MPK (Memory Protection Keys) を第一級市民として追加
/// x86_64 ではビット 59-62 が Protection Key (PKEY) として使用される
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
    /// PAT (Page Attribute Table) bit for 4KB pages
    /// Combined with PWT and PCD to select memory type
    pub const PAT: u64 = 1 << 7;
    /// PAT bit for large pages (2MB/1GB) - bit 12 instead of bit 7
    pub const PAT_LARGE: u64 = 1 << 12;
    /// No execute
    pub const NO_EXECUTE: u64 = 1 << 63;

    // ========================================================================
    // MPK (Memory Protection Keys) Support - 設計書 9.2.2
    // ========================================================================

    /// Protection Key マスク (ビット 59-62)
    /// x86_64 では 16 個の Protection Key (0-15) をサポート
    pub const PROTECTION_KEY_MASK: u64 = 0xF << 59;

    /// Protection Key のビットシフト量
    const PKEY_SHIFT: u64 = 59;

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

    /// MMIO/VRAM用 Write-Combining (WC)
    ///
    /// Write-Combining enables efficient streaming writes to VRAM by
    /// combining multiple writes into larger bursts.
    /// Uses PAT=1, PWT=1, PCD=0 to select WC memory type (PAT entry 5).
    #[inline]
    pub const fn write_combining() -> Self {
        Self(
            Self::PRESENT
                | Self::WRITABLE
                | Self::PAT
                | Self::WRITE_THROUGH
                | Self::NO_EXECUTE
                | Self::GLOBAL,
        )
    }

    /// Large page (2MB/1GB) MMIO/VRAM用 Write-Combining
    #[inline]
    pub const fn write_combining_large() -> Self {
        Self(
            Self::PRESENT
                | Self::WRITABLE
                | Self::PAT_LARGE
                | Self::WRITE_THROUGH
                | Self::HUGE_PAGE
                | Self::NO_EXECUTE
                | Self::GLOBAL,
        )
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

    // ========================================================================
    // MPK API - 設計書 9.2.2.1
    // ========================================================================

    /// Protection Key を設定
    ///
    /// 設計書: 各ドメインの信頼レベルに応じた PKEY を自動的にページテーブルに適用
    ///
    /// # Arguments
    /// * `pkey` - Protection Key (0-15)
    ///
    /// # Panics
    /// `pkey` が 16 以上の場合
    #[inline]
    pub const fn set_pkey(self, pkey: u8) -> Self {
        assert!(pkey < 16, "Protection Key must be 0-15");
        // 既存の PKEY ビットをクリアしてから新しい値を設定
        let cleared = self.0 & !Self::PROTECTION_KEY_MASK;
        Self(cleared | ((pkey as u64) << Self::PKEY_SHIFT))
    }

    /// Protection Key を取得
    #[inline]
    pub const fn get_pkey(&self) -> u8 {
        ((self.0 & Self::PROTECTION_KEY_MASK) >> Self::PKEY_SHIFT) as u8
    }

    /// Protection Key が設定されているか
    #[inline]
    pub const fn has_pkey(&self) -> bool {
        (self.0 & Self::PROTECTION_KEY_MASK) != 0
    }

    /// 信頼レベルに基づいた Protection Key を設定
    ///
    /// 設計書 9.2.2.1: Protection Key の割り当て戦略
    /// - Key 0-7: 信頼レベル (0=最も信頼, 7=最も信頼されない)
    /// - Key 8-15: 機密性クラス (8=公開, 15=最高機密)
    #[inline]
    pub fn with_trust_level(self, trust_level: u8) -> Self {
        assert!(trust_level < 8, "Trust level must be 0-7");
        self.set_pkey(trust_level)
    }

    /// 機密性クラスに基づいた Protection Key を設定
    #[inline]
    pub fn with_confidentiality_class(self, class: u8) -> Self {
        assert!(class < 8, "Confidentiality class must be 0-7");
        self.set_pkey(8 + class)
    }

    /// ドメイン用フラグ（PKEY付き）
    #[inline]
    pub fn domain_data(trust_level: u8) -> Self {
        Self::user_data().with_trust_level(trust_level)
    }

    /// ドメインコード用フラグ（PKEY付き）
    #[inline]
    pub fn domain_code(trust_level: u8) -> Self {
        Self::user_code().with_trust_level(trust_level)
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
    pub unsafe fn from_current_cr3(mapper: &'a PhysicalMemoryMapper) -> Self {
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }
        Self::new(PhysAddr::new(cr3 & !0xFFF), mapper)
    }

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
static HIGHER_HALF_MANAGER: PoisonLock<Option<HigherHalfManager>> = PoisonLock::new(None);

/// Higher Halfカーネルを初期化
pub fn init(physical_memory_offset: u64) {
    let manager = HigherHalfManager::new(physical_memory_offset);
    // Initialization-time best-effort recovery: recovering a poisoned manager during init is
    // acceptable to allow boot to continue.
    let mut mgr_guard = HIGHER_HALF_MANAGER.lock_for_init("[MM] Higher Half init");
    *mgr_guard = Some(manager);
    // log::info!("Higher half kernel initialized with offset {:#x}", physical_memory_offset);
}

/// 物理アドレスを仮想アドレスに変換
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    let guard = match HIGHER_HALF_MANAGER.lock() {
        Ok(g) => g,
        Err(_) => panic!("[MM] Higher Half manager poisoned (phys_to_virt)"),
    };
    let manager = guard.as_ref().expect("Higher half not initialized");
    manager.mapper().phys_to_virt(phys)
}

/// 仮想アドレスを物理アドレスに変換（直接マップ領域）
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    match HIGHER_HALF_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref().expect("Higher half not initialized");
            manager.mapper().virt_to_phys(virt)
        }
        Err(_) => {
            log::error!("[MM] Higher Half manager poisoned (virt_to_phys) - returning None");
            None
        }
    }
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
pub unsafe fn set_cr3(pml4_phys: PhysAddr) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) pml4_phys.as_u64(), options(nostack, preserves_flags));
    }
}

/// CR3を取得
#[inline]
pub fn get_cr3() -> PhysAddr {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    PhysAddr::new(cr3 & !0xFFF)
}

// ============================================================================
// Page Table Manager
// 設計書 5.1: ページテーブル管理
// ============================================================================

/// マッピングエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// フレーム割り当て失敗
    FrameAllocationFailed,
    /// 既にマップ済み
    AlreadyMapped,
    /// マップされていない
    NotMapped,
    /// 無効なアドレス
    InvalidAddress,
    /// アラインメントエラー
    AlignmentError,
    /// 親エントリがHuge Page
    ParentEntryHugePage,
    /// ハードウェア／内部状態のエラー（PoisonLockが毒入れされているなど）
    HardwareError,
}

/// ページテーブルマネージャー
///
/// 仮想アドレスと物理アドレスのマッピングを管理する。
/// 4KiB, 2MiB, 1GiBページサイズをサポート。
pub struct PageTableManager {
    /// PML4（レベル4ページテーブル）の物理アドレス
    pml4_phys: PhysAddr,
    /// 物理メモリマッパー
    mapper: PhysicalMemoryMapper,
}

impl PageTableManager {
    /// 新しいPageTableManagerを作成
    ///
    /// # Safety
    /// - `pml4_phys` は有効なPML4ページテーブルを指している必要がある
    /// - `physical_memory_offset` は正しいオフセット値である必要がある
    pub unsafe fn new(pml4_phys: PhysAddr, physical_memory_offset: u64) -> Self {
        Self {
            pml4_phys,
            mapper: PhysicalMemoryMapper::new(physical_memory_offset),
        }
    }

    /// 現在のCR3からPageTableManagerを作成
    ///
    /// # Safety
    /// カーネルモードで呼び出す必要がある
    pub unsafe fn from_current_cr3(physical_memory_offset: u64) -> Self {
        let pml4_phys = get_cr3();
        unsafe { Self::new(pml4_phys, physical_memory_offset) }
    }

    /// PML4の物理アドレスを取得
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// 4KiBページをマップ
    ///
    /// # Safety
    /// - `virt` と `phys` は4KiBアラインされている必要がある
    /// - 物理フレームは有効なメモリを指している必要がある
    pub unsafe fn map_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        if !virt.is_page_aligned() || !phys.is_page_aligned() {
            return Err(MapError::AlignmentError);
        }

        let indices = virt.page_table_indices();

        // PML4 -> PDPT -> PD -> PT をウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pdpt_phys = self.ensure_table_entry(pml4, indices[0], flags)?;

        let pdpt = self.get_table_mut(pdpt_phys);
        if pdpt.entry(indices[1]).is_present() && pdpt.entry(indices[1]).is_huge() {
            return Err(MapError::ParentEntryHugePage);
        }
        let pd_phys = self.ensure_table_entry(pdpt, indices[1], flags)?;

        let pd = self.get_table_mut(pd_phys);
        if pd.entry(indices[2]).is_present() && pd.entry(indices[2]).is_huge() {
            return Err(MapError::ParentEntryHugePage);
        }
        let pt_phys = self.ensure_table_entry(pd, indices[2], flags)?;

        let pt = self.get_table_mut(pt_phys);
        let pte = pt.entry_mut(indices[3]);

        if pte.is_present() {
            return Err(MapError::AlreadyMapped);
        }

        *pte = PageTableEntry::new(phys, flags.set(PageFlags::PRESENT));

        // TLBを無効化
        invalidate_page(virt);

        Ok(())
    }

    /// 2MiBページをマップ（設計書5.1対応）
    ///
    /// # Safety
    /// - `virt` と `phys` は2MiBアラインされている必要がある
    pub unsafe fn map_2mb_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        const SIZE_2MB: u64 = PageSize::Size2MiB.as_bytes();

        if virt.as_u64() % SIZE_2MB != 0 || phys.as_u64() % SIZE_2MB != 0 {
            return Err(MapError::AlignmentError);
        }

        // PAT bit handling:
        // For 4KB pages, PAT is bit 7.
        // For Huge Pages (2MB/1GB), bit 7 is PS (Page Size), so PAT moves to bit 12.
        let mut actual_flags = flags;
        if actual_flags.contains(PageFlags::PAT) {
            actual_flags = actual_flags.clear(PageFlags::PAT).set(PageFlags::PAT_LARGE);
        }

        let indices = virt.page_table_indices();

        // PML4 -> PDPT -> PD をウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pdpt_phys = self.ensure_table_entry(pml4, indices[0], flags)?;

        let pdpt = self.get_table_mut(pdpt_phys);
        if pdpt.entry(indices[1]).is_present() && pdpt.entry(indices[1]).is_huge() {
            return Err(MapError::ParentEntryHugePage);
        }
        let pd_phys = self.ensure_table_entry(pdpt, indices[1], flags)?;

        let pd = self.get_table_mut(pd_phys);
        let pde = pd.entry_mut(indices[2]);

        if pde.is_present() {
            return Err(MapError::AlreadyMapped);
        }

        // Huge Page フラグを設定
        *pde = PageTableEntry::huge(phys, actual_flags.set(PageFlags::PRESENT));

        invalidate_page(virt);

        Ok(())
    }

    /// 1GiBページをマップ（設計書5.1対応）
    ///
    /// # Safety
    /// - `virt` と `phys` は1GiBアラインされている必要がある
    pub unsafe fn map_1gb_page(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        const SIZE_1GB: u64 = PageSize::Size1GiB.as_bytes();

        if virt.as_u64() % SIZE_1GB != 0 || phys.as_u64() % SIZE_1GB != 0 {
            return Err(MapError::AlignmentError);
        }

        // PAT bit handling (same as 2MB pages)
        let mut actual_flags = flags;
        if actual_flags.contains(PageFlags::PAT) {
            actual_flags = actual_flags.clear(PageFlags::PAT).set(PageFlags::PAT_LARGE);
        }

        let indices = virt.page_table_indices();

        // PML4 -> PDPT をウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pdpt_phys = self.ensure_table_entry(pml4, indices[0], flags)?;

        let pdpt = self.get_table_mut(pdpt_phys);
        let pdpte = pdpt.entry_mut(indices[1]);

        if pdpte.is_present() {
            return Err(MapError::AlreadyMapped);
        }

        // Huge Page フラグを設定（1GiBページ）
        *pdpte = PageTableEntry::huge(phys, actual_flags.set(PageFlags::PRESENT));

        invalidate_page(virt);

        Ok(())
    }

    /// ページをアンマップ
    ///
    /// 4KiB, 2MiB, 1GiBページを自動検出してアンマップする。
    pub unsafe fn unmap_page(&mut self, virt: VirtAddr) -> Result<PhysAddr, MapError> {
        if !virt.is_page_aligned() {
            return Err(MapError::AlignmentError);
        }

        let indices = virt.page_table_indices();

        // PML4
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() {
            return Err(MapError::NotMapped);
        }

        // PDPT
        let pdpt = self.get_table_mut(pml4e.phys_addr());
        let pdpte = pdpt.entry_mut(indices[1]);
        if !pdpte.is_present() {
            return Err(MapError::NotMapped);
        }
        if pdpte.is_huge() {
            // 1GiBページ
            let phys = pdpte.phys_addr();
            pdpte.clear();
            invalidate_page(virt);
            return Ok(phys);
        }

        // PD
        let pd = self.get_table_mut(pdpte.phys_addr());
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return Err(MapError::NotMapped);
        }
        if pde.is_huge() {
            // 2MiBページ
            let phys = pde.phys_addr();
            pde.clear();
            invalidate_page(virt);
            return Ok(phys);
        }

        // PT
        let pt = self.get_table_mut(pde.phys_addr());
        let pte = pt.entry_mut(indices[3]);
        if !pte.is_present() {
            return Err(MapError::NotMapped);
        }

        // 4KiBページ
        let phys = pte.phys_addr();
        pte.clear();
        invalidate_page(virt);

        Ok(phys)
    }

    /// 仮想アドレスを物理アドレスに変換
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let walker = PageTableWalker::new(self.pml4_phys, &self.mapper);
        walker.translate(virt)
    }

    /// ページテーブルの保護フラグを変更
    pub unsafe fn update_flags(
        &mut self,
        virt: VirtAddr,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        if !virt.is_page_aligned() {
            return Err(MapError::AlignmentError);
        }

        let indices = virt.page_table_indices();

        // テーブルをウォーク
        let pml4 = self.get_table_mut(self.pml4_phys);
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() {
            return Err(MapError::NotMapped);
        }

        let pdpt = self.get_table_mut(pml4e.phys_addr());
        let pdpte = pdpt.entry_mut(indices[1]);
        if !pdpte.is_present() {
            return Err(MapError::NotMapped);
        }
        if pdpte.is_huge() {
            pdpte.set_flags(flags.set(PageFlags::PRESENT).set(PageFlags::HUGE_PAGE));
            invalidate_page(virt);
            return Ok(());
        }

        let pd = self.get_table_mut(pdpte.phys_addr());
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() {
            return Err(MapError::NotMapped);
        }
        if pde.is_huge() {
            pde.set_flags(flags.set(PageFlags::PRESENT).set(PageFlags::HUGE_PAGE));
            invalidate_page(virt);
            return Ok(());
        }

        let pt = self.get_table_mut(pde.phys_addr());
        let pte = pt.entry_mut(indices[3]);
        if !pte.is_present() {
            return Err(MapError::NotMapped);
        }

        pte.set_flags(flags.set(PageFlags::PRESENT));
        invalidate_page(virt);

        Ok(())
    }

    /// 連続した仮想アドレス範囲をマップ
    ///
    /// 自動的に最適なページサイズを選択する。
    pub unsafe fn map_range(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: u64,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        let mut virt = virt_start.as_u64();
        let mut phys = phys_start.as_u64();
        let end = virt + size;

        while virt < end {
            let remaining = end - virt;

            // 1GiBページを使用可能かチェック
            const SIZE_1GB: u64 = PageSize::Size1GiB.as_bytes();
            if virt % SIZE_1GB == 0 && phys % SIZE_1GB == 0 && remaining >= SIZE_1GB {
                unsafe { self.map_1gb_page(VirtAddr::new(virt), PhysAddr::new(phys), flags)? };
                virt += SIZE_1GB;
                phys += SIZE_1GB;
                continue;
            }

            // 2MiBページを使用可能かチェック
            const SIZE_2MB: u64 = PageSize::Size2MiB.as_bytes();
            if virt % SIZE_2MB == 0 && phys % SIZE_2MB == 0 && remaining >= SIZE_2MB {
                unsafe { self.map_2mb_page(VirtAddr::new(virt), PhysAddr::new(phys), flags)? };
                virt += SIZE_2MB;
                phys += SIZE_2MB;
                continue;
            }

            // 4KiBページ
            const SIZE_4KB: u64 = PageSize::Size4KiB.as_bytes();
            unsafe { self.map_page(VirtAddr::new(virt), PhysAddr::new(phys), flags)? };
            virt += SIZE_4KB;
            phys += SIZE_4KB;
        }

        Ok(())
    }

    /// 連続した仮想アドレス範囲をアンマップ
    pub unsafe fn unmap_range(&mut self, virt_start: VirtAddr, size: u64) -> Result<(), MapError> {
        let mut virt = virt_start.as_u64();
        let end = virt + size;

        while virt < end {
            match unsafe { self.unmap_page(VirtAddr::new(virt)) } {
                Ok(_) => {
                    // ページサイズを検出してスキップ
                    // Note: unmap_pageは物理アドレスを返すが、ここではサイズ情報が必要
                    // 簡単のため4KiB単位で進める
                    virt += PageSize::Size4KiB.as_bytes();
                }
                Err(MapError::NotMapped) => {
                    // マップされていないページはスキップ
                    virt += PageSize::Size4KiB.as_bytes();
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    // --- ヘルパー関数 ---

    /// 物理アドレスからページテーブルの可変参照を取得
    fn get_table_mut(&self, phys: PhysAddr) -> &mut PageTable {
        let virt = self.mapper.phys_to_virt(phys);
        unsafe { &mut *virt.as_mut_ptr() }
    }

    /// テーブルエントリが存在しない場合は新しいテーブルを割り当て
    fn ensure_table_entry(
        &self,
        table: &mut PageTable,
        index: usize,
        _flags: PageFlags,
    ) -> Result<PhysAddr, MapError> {
        let entry = table.entry_mut(index);

        if entry.is_present() {
            if entry.is_huge() {
                return Err(MapError::ParentEntryHugePage);
            }
            return Ok(entry.phys_addr());
        }

        // 新しいページテーブルを割り当て
        let new_table_phys = self.alloc_page_table()?;

        // テーブルをゼロクリア
        let new_table = self.get_table_mut(new_table_phys);
        new_table.clear();

        // エントリを設定（常にWritableを設定して下位テーブルへのアクセスを許可）
        let entry_flags =
            PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER);
        *entry = PageTableEntry::new(new_table_phys, entry_flags);

        Ok(new_table_phys)
    }

    /// 新しいページテーブル用のフレームを割り当て
    fn alloc_page_table(&self) -> Result<PhysAddr, MapError> {
        // まず現在のCPUのローカルNUMAノードから割り当てを試みる（優先）
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            if let Some(frame) = crate::mm::alloc_frame_local(cpu_id as u8) {
                return Ok(PhysAddr::new(frame.start_address().as_u64()));
            }
        }

        // フォールバック: Buddy Allocatorを使用
        crate::mm::buddy_alloc_frame()
            .map(|frame| PhysAddr::new(frame.start_address().as_u64()))
            .ok_or(MapError::FrameAllocationFailed)
    }
}

/// グローバルなページテーブルマネージャー
static PAGE_TABLE_MANAGER: PoisonLock<Option<PageTableManager>> = PoisonLock::new(None);

/// ページテーブルマネージャーを初期化
pub fn init_page_table_manager(physical_memory_offset: u64) {
    let manager = unsafe { PageTableManager::from_current_cr3(physical_memory_offset) };
    // Initialization-time best-effort recovery for PageTableManager initialization.
    let mut mgr_guard = PAGE_TABLE_MANAGER.lock_for_init("[MM] Page Table Manager init");
    *mgr_guard = Some(manager);
}

/// グローバルページテーブルマネージャーでページをマップ
pub unsafe fn global_map_page(
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PageFlags,
) -> Result<(), MapError> {
    // If the global PageTableManager lock is poisoned, treat this as a
    // hardware/internal error and propagate it rather than attempting to
    // continue with potentially corrupted state.
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| {
            log::error!("[MM] Page Table Manager lock poisoned");
            MapError::HardwareError
        })?;

    let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;
    unsafe { manager.map_page(virt, phys, flags) }
}

/// グローバルページテーブルマネージャーでページをアンマップ
pub unsafe fn global_unmap_page(virt: VirtAddr) -> Result<PhysAddr, MapError> {
    let mut guard = PAGE_TABLE_MANAGER
        .lock()
        .map_err(|_| {
            log::error!("[MM] Page Table Manager lock poisoned");
            MapError::HardwareError
        })?;

    let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;
    unsafe { manager.unmap_page(virt) }
}

/// グローバルページテーブルマネージャーで仮想→物理変換
pub fn global_translate(virt: VirtAddr) -> Option<PhysAddr> {
    match PAGE_TABLE_MANAGER.lock() {
        Ok(guard) => {
            let manager = guard.as_ref();
            manager.and_then(|m| m.translate(virt))
        }
        Err(_) => {
            log::error!("[MM] Page Table Manager lock poisoned - returning None");
            None
        }
    }
}

/// グローバルページテーブルマネージャーでページのフラグを更新（MPK PKEY適用用）
pub unsafe fn global_update_flags(virt: VirtAddr, flags: PageFlags) -> Result<(), MapError> {
    match PAGE_TABLE_MANAGER.lock() {
        Ok(mut guard) => {
            let manager = guard.as_mut().ok_or(MapError::InvalidAddress)?;
            unsafe { manager.update_flags(virt, flags) }
        }
        Err(_) => {
            log::error!("[MM] Page Table Manager lock poisoned - returning HardwareError");
            Err(MapError::HardwareError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_page_table_prefers_numa_local_or_buddy() {
        // Verify alloc_page_table succeeds regardless of NUMA availability
        let manager = unsafe { PageTableManager::from_current_cr3(0) };
        let res = manager.alloc_page_table();
        assert!(res.is_ok());
    }

    #[test]
    fn test_global_map_page_poisoned_returns_hardware_error() {
        // Poison the PAGE_TABLE_MANAGER lock
        {
            let _guard = PAGE_TABLE_MANAGER.lock().unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);

        let res = unsafe {
            global_map_page(
                VirtAddr::new(0x1000),
                PhysAddr::new(0x2000),
                PageFlags::new(PageFlags::PRESENT),
            )
        };

        assert_eq!(res, Err(MapError::HardwareError));
    }

    #[test]
    fn test_global_unmap_page_poisoned_returns_hardware_error() {
        // Poison the PAGE_TABLE_MANAGER lock
        {
            let _guard = PAGE_TABLE_MANAGER.lock().unwrap();
            crate::sync::set_panicking(true);
        }
        crate::sync::set_panicking(false);

        let res = unsafe { global_unmap_page(VirtAddr::new(0x1000)) };
        assert_eq!(res, Err(MapError::HardwareError));
    }
}
