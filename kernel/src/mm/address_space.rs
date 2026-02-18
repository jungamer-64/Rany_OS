// ============================================================================
// src/mm/address_space.rs - Process Address Space Management
//
// ## 概要
//
// プロセスのアドレス空間を管理する統合レイヤー。
// VMA管理、ページテーブル、fork/exec、メモリマッピングAPIを統合。
//
// ## 設計
//
// 1. **ProcessAddressSpace**: プロセスごとのアドレス空間を表現
// 2. **VMA統合**: rcu_vma.rs と demand_paging.rs の VMA を統合
// 3. **CoW Fork**: fork()時のアドレス空間複製（CoWベース）
// 4. **Exec Reset**: exec()時のアドレス空間リセット
//
// ## ExoRust特有の設計
//
// - Single Address Space (SAS): 全プロセスが同一アドレス空間を共有
// - ドメイン境界でのセグメント分離
// - Exchange Heap経由のドメイン間通信
//
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::boxed::Box;
use spin::RwLock;

use super::higher_half::{VirtAddr, PhysAddr, PageFlags, global_unmap_page, global_translate};
use super::frame_allocator::alloc_frame;
use super::cow::{cow_mark_page, cow_copy_pte, page_get, page_put};
use super::rcu_vma::{VmaFlags, VmaList, VmArea};
use super::memcg::{memcg_charge, memcg_uncharge, ChargeType, MemcgId};
use super::stack_growth::{create_stack, StackResult};
use crate::mm::thp_promotion::ThpCandidate;
use super::buddy_allocator::{alloc_huge_frame, buddy_dealloc_frame, buddy_dealloc_frame_2m};
use x86_64::structures::paging::{PhysFrame, Size4KiB, Size2MiB};
use x86_64::PhysAddr as X64PhysAddr;

// ============================================================================
// Address Space Constants
// ============================================================================

/// ユーザー空間の開始アドレス
mod error;
pub use error::*;
mod impl_methods;
pub use impl_methods::*;
pub const USER_SPACE_START: u64 = 0x0000_0000_0010_0000; // 1MB

/// ユーザー空間の終了アドレス
pub const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_F000; // Lower half limit

/// カーネル空間の開始アドレス
pub const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;

/// デフォルトのヒープ開始アドレス
pub const DEFAULT_HEAP_START: u64 = 0x0000_1000_0000_0000;

/// デフォルトのスタックトップ
pub const DEFAULT_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;

/// デフォルトのmmap領域開始
pub const DEFAULT_MMAP_BASE: u64 = 0x0000_2000_0000_0000;

/// ページサイズ
const PAGE_SIZE: u64 = 4096;

// ============================================================================
// Address Space ID (ASID) Management
// ============================================================================

/// 次に割り当てるASID
static NEXT_ASID: AtomicU64 = AtomicU64::new(1);

/// ASIDを割り当て
fn allocate_asid() -> u64 {
    NEXT_ASID.fetch_add(1, Ordering::Relaxed)
}

// ============================================================================
// Memory Region Types
// ============================================================================

/// メモリ領域の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionType {
    /// コードセグメント
    Code,
    /// データセグメント
    Data,
    /// BSSセグメント
    Bss,
    /// ヒープ
    Heap,
    /// スタック
    Stack,
    /// mmap領域
    Mmap,
    /// 共有メモリ
    Shared,
    /// ファイルマッピング
    FileBacked,
    /// VDSO
    Vdso,
}

/// メモリ領域の権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Protection {
    pub const NONE: Self = Self { read: false, write: false, execute: false };
    pub const READ: Self = Self { read: true, write: false, execute: false };
    pub const READ_WRITE: Self = Self { read: true, write: true, execute: false };
    pub const READ_EXEC: Self = Self { read: true, write: false, execute: true };
    pub const READ_WRITE_EXEC: Self = Self { read: true, write: true, execute: true };

    #[inline]
    pub fn can_read(&self) -> bool {
        self.read
    }

    #[inline]
    pub fn can_write(&self) -> bool {
        self.write
    }

    #[inline]
    pub fn can_exec(&self) -> bool {
        self.execute
    }

    #[inline]
    pub fn union(&self, other: Self) -> Self {
        Self {
            read: self.read || other.read,
            write: self.write || other.write,
            execute: self.execute || other.execute,
        }
    }
    
    /// PageFlagsに変換
    pub fn to_page_flags(&self) -> PageFlags {
        let mut flags = PageFlags::new(PageFlags::PRESENT | PageFlags::USER);
        if self.write {
            flags = PageFlags::new(flags.as_u64() | PageFlags::WRITABLE);
        }
        if !self.execute {
            flags = PageFlags::new(flags.as_u64() | PageFlags::NO_EXECUTE);
        }
        flags
    }
    
    /// VmaFlagsから変換
    pub fn from_vma_flags(flags: u32) -> Self {
        Self {
            read: flags & VmaFlags::Read as u32 != 0,
            write: flags & VmaFlags::Write as u32 != 0,
            execute: flags & VmaFlags::Execute as u32 != 0,
        }
    }
}

// ============================================================================
// Virtual Memory Region
// ============================================================================

/// 仮想メモリ領域
#[derive(Debug)]
pub struct MemoryRegion {
    /// 開始アドレス
    pub start: VirtAddr,
    /// 終了アドレス（exclusive）
    pub end: VirtAddr,
    /// 領域タイプ
    pub region_type: RegionType,
    /// 権限
    pub protection: Protection,
    /// CoWフラグ
    pub cow: bool,
    /// ファイルバッキング情報
    pub file_info: Option<FileBackingInfo>,
    /// 参照カウント
    refcount: AtomicU64,
}

/// ファイルバッキング情報
#[derive(Debug, Clone)]
pub struct FileBackingInfo {
    /// ファイルのinode
    pub inode: u64,
    /// ファイル内オフセット
    pub offset: u64,
    /// サイズ
    pub size: u64,
}

impl MemoryRegion {
    /// 新しい領域を作成
    pub fn new(start: VirtAddr, end: VirtAddr, region_type: RegionType, protection: Protection) -> Self {
        Self {
            start,
            end,
            region_type,
            protection,
            cow: false,
            file_info: None,
            refcount: AtomicU64::new(1),
        }
    }
    
    /// サイズを取得
    pub fn size(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }
    
    /// ページ数を取得
    pub fn page_count(&self) -> u64 {
        (self.size() + PAGE_SIZE - 1) / PAGE_SIZE
    }
    
    /// アドレスが領域内か
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end
    }
    
    /// 領域が重なるか
    pub fn overlaps(&self, start: VirtAddr, end: VirtAddr) -> bool {
        self.start < end && self.end > start
    }
    
    /// 参照を取得
    pub fn get_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 参照を解放（trueなら解放が必要）
    pub fn put_ref(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::Release) == 1
    }

    /// VMAフラグへ変換
    fn vma_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.protection.read {
            flags |= VmaFlags::Read as u32;
        }
        if self.protection.write {
            flags |= VmaFlags::Write as u32;
        }
        if self.protection.execute {
            flags |= VmaFlags::Execute as u32;
        }
        if self.cow {
            flags |= VmaFlags::CopyOnWrite as u32;
        }
        if matches!(self.region_type, RegionType::Shared) {
            flags |= VmaFlags::Shared as u32;
        }
        if self.file_info.is_some() || matches!(self.region_type, RegionType::FileBacked) {
            flags |= VmaFlags::FileBacked as u32;
        } else {
            flags |= VmaFlags::Anonymous as u32;
        }
        flags
    }

    /// MemoryRegionからVmAreaを生成
    fn to_vma(&self) -> VmArea {
        let mut vma = VmArea::new(self.start, self.end, self.vma_flags());
        if let Some(info) = &self.file_info {
            vma.file_inode = info.inode;
            vma.file_offset = info.offset;
        }
        vma
    }
}

/// 既存リージョンから指定範囲のリージョンを複製
fn clone_region_with_range(
    base: &MemoryRegion,
    start: VirtAddr,
    end: VirtAddr,
    protection: Protection,
) -> MemoryRegion {
    let mut region = MemoryRegion::new(start, end, base.region_type, protection);
    region.cow = base.cow;
    region.file_info = base.file_info.clone();

    if let Some(info) = region.file_info.as_mut() {
        let delta = start.as_u64().saturating_sub(base.start.as_u64());
        let size = end.as_u64().saturating_sub(start.as_u64());
        info.offset = info.offset.saturating_add(delta);
        info.size = size;
    }

    region
}

// ============================================================================
// Process Address Space
// ============================================================================

/// プロセスのアドレス空間
pub struct ProcessAddressSpace {
    /// アドレス空間ID
    asid: u64,
    /// ページテーブルの物理アドレス（CR3に設定する値）
    page_table_root: AtomicU64,
    /// メモリ領域のマップ（start_addr -> region）
    regions: RwLock<BTreeMap<u64, Box<MemoryRegion>>>,
    /// RCU保護されたVMAリスト
    vma_list: VmaList,
    /// ヒープ境界（brk）
    heap_end: AtomicU64,
    /// mmap領域の次の割り当てアドレス
    mmap_hint: AtomicU64,
    /// スタック領域
    stack_top: AtomicU64,
    /// memcg ID
    memcg_id: MemcgId,
    /// 総マッピングページ数
    mapped_pages: AtomicU64,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}
