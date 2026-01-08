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
use super::rcu_vma::VmaFlags;
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

impl ProcessAddressSpace {
    /// 新しいアドレス空間を作成
    pub fn new() -> Self {
        Self {
            asid: allocate_asid(),
            page_table_root: AtomicU64::new(0),
            regions: RwLock::new(BTreeMap::new()),
            heap_end: AtomicU64::new(DEFAULT_HEAP_START),
            mmap_hint: AtomicU64::new(DEFAULT_MMAP_BASE),
            stack_top: AtomicU64::new(DEFAULT_STACK_TOP),
            memcg_id: MemcgId::ROOT,
            mapped_pages: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// ページテーブルを初期化
    pub fn init_page_table(&self) -> Result<(), AddressSpaceError> {
        // 新しいページテーブルを割り当て
        let frame = alloc_frame().ok_or(AddressSpaceError::OutOfMemory)?;
        let pt_phys = frame.start_address().as_u64();
        
        // ゼロクリア
        let virt = super::mapping::phys_to_virt(frame.start_address());
        unsafe {
            core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, PAGE_SIZE as usize);
        }
        
        // カーネル空間のマッピングをコピー（Higher Half）
        // TODO: 現在のページテーブルからカーネル部分をコピー
        
        self.page_table_root.store(pt_phys, Ordering::Release);
        self.initialized.store(true, Ordering::Release);
        
        Ok(())
    }
    
    /// ASIDを取得
    pub fn asid(&self) -> u64 {
        self.asid
    }
    
    /// ページテーブルルートを取得
    pub fn page_table_root(&self) -> u64 {
        self.page_table_root.load(Ordering::Acquire)
    }
    
    // ========================================================================
    // Memory Region Management
    // ========================================================================
    
    /// 領域を追加
    pub fn add_region(&self, region: MemoryRegion) -> Result<(), AddressSpaceError> {
        let start = region.start.as_u64();
        let end = region.end.as_u64();
        
        // 範囲チェック
        if start >= end {
            return Err(AddressSpaceError::InvalidRange);
        }
        
        let mut regions = self.regions.write();
        
        // 重複チェック
        for existing in regions.values() {
            if existing.overlaps(region.start, region.end) {
                return Err(AddressSpaceError::RegionOverlap);
            }
        }
        
        regions.insert(start, Box::new(region));
        Ok(())
    }
    
    /// アドレスに対応する領域を検索
    pub fn find_region(&self, addr: VirtAddr) -> Option<u64> {
        let regions = self.regions.read();
        
        // start <= addr となる最大のキーを探す
        for (&start, region) in regions.range(..=addr.as_u64()).rev() {
            if region.contains(addr) {
                return Some(start);
            }
            break;
        }
        None
    }
    
    /// 領域を取得
    pub fn get_region(&self, start_addr: u64) -> Option<Protection> {
        let regions = self.regions.read();
        regions.get(&start_addr).map(|r| r.protection)
    }
    
    /// 領域を削除
    pub fn remove_region(&self, start_addr: u64) -> Result<(), AddressSpaceError> {
        let mut regions = self.regions.write();
        
        if let Some(region) = regions.remove(&start_addr) {
            // マッピングを解除
            let page_count = region.page_count();
            for i in 0..page_count {
                let addr = VirtAddr::new(region.start.as_u64() + i * PAGE_SIZE);
                unsafe { let _ = global_unmap_page(addr); }
            }
            self.mapped_pages.fetch_sub(page_count, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AddressSpaceError::RegionNotFound)
        }
    }
    
    // ========================================================================
    // Memory Mapping API (mmap/munmap/mprotect)
    // ========================================================================
    
    /// メモリをマッピング（mmapの実装）
    pub fn mmap(
        &self,
        addr_hint: Option<VirtAddr>,
        size: u64,
        prot: Protection,
        region_type: RegionType,
    ) -> Result<VirtAddr, AddressSpaceError> {
        if size == 0 {
            return Err(AddressSpaceError::InvalidSize);
        }
        
        let size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1); // ページアラインメント
        
        // アドレスを決定
        let start_addr = if let Some(hint) = addr_hint {
            hint.as_u64()
        } else {
            // mmap領域から割り当て
            let hint = self.mmap_hint.fetch_add(size, Ordering::Relaxed);
            hint
        };
        
        let start = VirtAddr::new(start_addr);
        let end = VirtAddr::new(start_addr + size);
        
        // 領域を作成
        let region = MemoryRegion::new(start, end, region_type, prot);
        self.add_region(region)?;
        
        // Demand Pagingを使用するため、実際のページ割り当ては遅延
        // （ページフォルト時に割り当て）
        
        Ok(start)
    }
    
    /// メモリのマッピングを解除（munmapの実装）
    pub fn munmap(&self, addr: VirtAddr, size: u64) -> Result<(), AddressSpaceError> {
        if size == 0 {
            return Err(AddressSpaceError::InvalidSize);
        }
        
        let start_key = self.find_region(addr)
            .ok_or(AddressSpaceError::RegionNotFound)?;
        
        self.remove_region(start_key)
    }
    
    /// メモリ保護を変更（mprotectの実装）
    pub fn mprotect(&self, addr: VirtAddr, size: u64, prot: Protection) -> Result<(), AddressSpaceError> {
        let start_key = self.find_region(addr)
            .ok_or(AddressSpaceError::RegionNotFound)?;
        
        let mut regions = self.regions.write();
        
        if let Some(region) = regions.get_mut(&start_key) {
            // 範囲チェック
            let end = VirtAddr::new(addr.as_u64() + size);
            if end > region.end {
                return Err(AddressSpaceError::InvalidRange);
            }
            
            // 権限を更新
            // TODO: 部分的な範囲の場合は領域を分割
            region.protection = prot;
            
            // ページテーブルエントリを更新
            let page_count = size / PAGE_SIZE;
            for i in 0..page_count {
                let page_addr = VirtAddr::new(addr.as_u64() + i * PAGE_SIZE);
                let flags = prot.to_page_flags();
                unsafe { let _ = super::higher_half::global_update_flags(page_addr, flags); }
            }
            
            Ok(())
        } else {
            Err(AddressSpaceError::RegionNotFound)
        }
    }
    
    // ========================================================================
    // Heap Management (brk)
    // ========================================================================
    
    /// ヒープ境界を取得
    pub fn brk(&self) -> u64 {
        self.heap_end.load(Ordering::Acquire)
    }
    
    /// ヒープ境界を設定
    pub fn set_brk(&self, new_brk: u64) -> Result<u64, AddressSpaceError> {
        let current = self.heap_end.load(Ordering::Acquire);
        
        if new_brk < DEFAULT_HEAP_START {
            return Err(AddressSpaceError::InvalidRange);
        }
        
        if new_brk > current {
            // ヒープ拡張
            let size = new_brk - current;
            let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            
            // Memcgチャージ
            let pages = aligned_size / PAGE_SIZE;
            if memcg_charge(self.memcg_id, pages, ChargeType::Anon).is_err() {
                return Err(AddressSpaceError::OutOfMemory);
            }
            
            // 実際のページ割り当てはDemand Paging
        } else if new_brk < current {
            // ヒープ縮小
            let size = current - new_brk;
            let pages = size / PAGE_SIZE;
            
            // ページを解放
            for i in 0..pages {
                let addr = VirtAddr::new(new_brk + i * PAGE_SIZE);
                if let Some(phys) = global_translate(addr) {
                    unsafe { let _ = global_unmap_page(addr); }
                    page_put(phys.as_u64());
                }
            }
            
            memcg_uncharge(self.memcg_id, pages, ChargeType::Anon);
        }
        
        self.heap_end.store(new_brk, Ordering::Release);
        Ok(new_brk)
    }
    
    // ========================================================================
    // Fork Support (Copy-on-Write)
    // ========================================================================
    
    /// アドレス空間を複製（fork用）
    ///
    /// Copy-on-Writeを使用して効率的に複製する。
    /// 全ての書き込み可能ページをRead-onlyに変更し、
    /// フォルト時に実際のコピーを行う。
    pub fn fork(&self) -> Result<Box<ProcessAddressSpace>, AddressSpaceError> {
        let child = Box::new(ProcessAddressSpace::new());
        
        // ページテーブルを初期化
        child.init_page_table()?;
        
        let regions = self.regions.read();
        
        for (&start, region) in regions.iter() {
            // 子プロセス用の新しい領域を作成
            let mut child_region = MemoryRegion::new(
                region.start,
                region.end,
                region.region_type,
                region.protection,
            );
            child_region.cow = true;
            child_region.file_info = region.file_info.clone();
            
            // 親のページをCoWとしてマーク
            if region.protection.write {
                let page_count = region.page_count();
                for i in 0..page_count {
                    let addr = VirtAddr::new(region.start.as_u64() + i * PAGE_SIZE);
                    
                    // ページが存在する場合のみ処理
                    if let Some(phys) = global_translate(addr) {
                        // 親をRead-onlyに変更（CoWマーク）
                        let _ = cow_mark_page(addr);
                        
                        // 参照カウントを増加
                        page_get(phys.as_u64());
                        
                        // 子のページテーブルにエントリをコピー
                        let _ = cow_copy_pte(addr, child.page_table_root());
                    }
                }
            }
            
            // 子に領域を追加
            let mut child_regions = child.regions.write();
            child_regions.insert(start, Box::new(child_region));
        }
        
        // ヒープとスタック境界をコピー
        child.heap_end.store(self.heap_end.load(Ordering::Acquire), Ordering::Release);
        child.stack_top.store(self.stack_top.load(Ordering::Acquire), Ordering::Release);
        child.mmap_hint.store(self.mmap_hint.load(Ordering::Acquire), Ordering::Release);
        
        Ok(child)
    }
    
    // ========================================================================
    // Exec Support
    // ========================================================================
    
    /// アドレス空間をリセット（exec用）
    ///
    /// 全てのユーザー空間マッピングを解除し、
    /// 新しいプログラムのロード準備をする。
    pub fn exec_reset(&self) -> Result<(), AddressSpaceError> {
        let mut regions = self.regions.write();
        
        // 全領域を削除
        let keys: Vec<u64> = regions.keys().copied().collect();
        for start in keys {
            if let Some(region) = regions.remove(&start) {
                // ユーザー空間のみ解除
                if region.start.as_u64() < KERNEL_SPACE_START {
                    let page_count = region.page_count();
                    for i in 0..page_count {
                        let addr = VirtAddr::new(region.start.as_u64() + i * PAGE_SIZE);
                        if let Some(phys) = global_translate(addr) {
                            unsafe { let _ = global_unmap_page(addr); }
                            page_put(phys.as_u64());
                        }
                    }
                }
            }
        }
        
        // 境界をリセット
        self.heap_end.store(DEFAULT_HEAP_START, Ordering::Release);
        self.mmap_hint.store(DEFAULT_MMAP_BASE, Ordering::Release);
        self.stack_top.store(DEFAULT_STACK_TOP, Ordering::Release);
        self.mapped_pages.store(0, Ordering::Release);
        
        Ok(())
    }
    
    /// 新しいプログラムセグメントをロード
    pub fn load_segment(
        &self,
        vaddr: VirtAddr,
        size: u64,
        prot: Protection,
        region_type: RegionType,
    ) -> Result<(), AddressSpaceError> {
        let region = MemoryRegion::new(
            vaddr,
            VirtAddr::new(vaddr.as_u64() + size),
            region_type,
            prot,
        );
        self.add_region(region)
    }
    
    // ========================================================================
    // Stack Management
    // ========================================================================
    
    /// スタックをセットアップ
    pub fn setup_stack(&self, stack_top: VirtAddr, initial_size: u64, max_size: u64) -> Result<VirtAddr, AddressSpaceError> {
        // スタック領域を作成
        let stack_bottom = VirtAddr::new(stack_top.as_u64() - initial_size);
        
        let region = MemoryRegion::new(
            stack_bottom,
            stack_top,
            RegionType::Stack,
            Protection::READ_WRITE,
        );
        self.add_region(region)?;
        
        // スタック管理に登録
        match create_stack(self.asid, stack_top, initial_size, max_size) {
            StackResult::Ok => {
                self.stack_top.store(stack_top.as_u64(), Ordering::Release);
                Ok(stack_top)
            }
            _ => Err(AddressSpaceError::OutOfMemory),
        }
    }
    
    // ========================================================================
    // Statistics
    // ========================================================================
    
    /// 統計情報を取得
    pub fn stats(&self) -> AddressSpaceStats {
        let regions = self.regions.read();
        
        let mut total_virtual = 0u64;
        let mut region_count = 0usize;
        
        for region in regions.values() {
            total_virtual += region.size();
            region_count += 1;
        }
        
        AddressSpaceStats {
            asid: self.asid,
            total_virtual,
            mapped_pages: self.mapped_pages.load(Ordering::Relaxed),
            region_count,
            heap_size: self.heap_end.load(Ordering::Relaxed) - DEFAULT_HEAP_START,
        }
    }
    /// NUMAヒントスキャンを実行
    ///
    /// 指定されたアドレスからスキャンを開始し、PresentなページのPresentフラグを落とし、
    /// NUMA_HINTフラグを立てる。
    ///
    /// # Returns
    /// (scanned_pages, faults_set, next_scan_addr)
    pub fn scan_numa_hints(&self, start_addr: VirtAddr, batch_size: usize) -> (usize, usize, VirtAddr) {
        let mut scanned = 0;
        let mut faults = 0;
        let mut current_addr = start_addr;
        let regions = self.regions.read();

        // 指定アドレス以降の領域を検索
        // Note: BTreeMap::range works on keys. start_addr might be in the middle of a region.
        // We find the first region that ends after start_addr.
        for (&r_start, region) in regions.range(..).filter(|&(&_s, ref r)| r.end > start_addr) {
            if scanned >= batch_size {
                break;
            }

            // スキャン対象外の領域（カーネル、デバイスなど）はスキップ
            // Anon / Shared / FileBacked のみを対象とする
            match region.region_type {
                RegionType::Data | RegionType::Stack | RegionType::Heap | RegionType::Bss | RegionType::Mmap => {} // OK
                _ => {
                    // Skip this region, move current_addr to end
                    if current_addr < region.end {
                        current_addr = region.end;
                    }
                    continue;
                }
            }
            
            // 権限チェック (Read/Write access requires Present)
            // If not present (e.g. pure guard page), skip.
            // But we check PTEs.
            
            // 領域内のスキャン開始位置
            let region_scan_start = if current_addr < region.start {
                region.start
            } else {
                current_addr
            };

            let mut page_addr = region_scan_start;
            while page_addr < region.end && scanned < batch_size {
                // ページテーブル設定
                // Note: walking page tables recursively. 
                // Using a helper to update PTE directly.
                if self.update_pte_for_numa_hint(page_addr) {
                    faults += 1;
                }
                
                scanned += 1;
                page_addr = VirtAddr::new(page_addr.as_u64() + PAGE_SIZE);
            }
            current_addr = page_addr;
        }

        // If we ran out of regions, wrap around? 
        // Caller handles wrap around.
        
        (scanned, faults, current_addr)
    }

    /// PTEを更新してNUMAヒントを設定
    fn update_pte_for_numa_hint(&self, addr: VirtAddr) -> bool {
        // ページテーブルをウォークしてPTEを取得
        let pt_root = self.page_table_root.load(Ordering::Acquire);
        if pt_root == 0 {
            return false;
        }

        let indices = addr.page_table_indices();
        
        // Manual four-level walk using phys_to_virt
        // Level 4 (PML4)
        let pml4_phys = PhysAddr::new(pt_root);
        let pml4_ptr = super::higher_half::phys_to_virt(pml4_phys).as_mut_ptr::<super::higher_half::PageTable>();
        let pml4 = unsafe { &mut *pml4_ptr };
        let pml4e = pml4.entry_mut(indices[0]);
        if !pml4e.is_present() { return false; }

        // Level 3 (PDPT)
        let pdpt_phys = pml4e.phys_addr();
        let pdpt_ptr = super::higher_half::phys_to_virt(pdpt_phys).as_mut_ptr::<super::higher_half::PageTable>();
        let pdpt = unsafe { &mut *pdpt_ptr };
        let pdpte = pdpt.entry_mut(indices[1]);
        if !pdpte.is_present() { return false; }
        if pdpte.is_huge() { return false; } // 1GB pages not supported for auto numa yet

        // Level 2 (PD)
        let pd_phys = pdpte.phys_addr();
        let pd_ptr = super::higher_half::phys_to_virt(pd_phys).as_mut_ptr::<super::higher_half::PageTable>();
        let pd = unsafe { &mut *pd_ptr };
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() { return false; }
        if pde.is_huge() { return false; } // 2MB pages not supported for auto numa yet

        // Level 1 (PT)
        let pt_phys = pde.phys_addr();
        let pt_ptr = super::higher_half::phys_to_virt(pt_phys).as_mut_ptr::<super::higher_half::PageTable>();
        let pt = unsafe { &mut *pt_ptr };
        let pte = pt.entry_mut(indices[3]);

        // Hint設定
        if pte.is_present() {
            let mut flags = pte.flags();
            // 既にHintが立っている場合はスキップ
            if flags.contains(PageFlags::NUMA_HINT) {
                return false;
            }
            // Presentを落とし、Hintを立てる
            flags = flags.clear(PageFlags::PRESENT).set(PageFlags::NUMA_HINT);
            pte.set_flags(flags);
            
            // TLB Invalidation handled by caller (usually flush_tlb_local if current, or ignored until next context switch)
            return true;
        }

        false
    }

    /// THP昇格候補を検索
    ///
    /// 指定されたアドレスからスキャンを開始し、昇格可能な2MB領域を探す。
    pub fn find_thp_candidates(&self, start_addr: VirtAddr, limit: usize) -> (Vec<ThpCandidate>, VirtAddr) {
        let mut candidates = Vec::new();
        let mut current_addr = start_addr;
        let regions = self.regions.read();
        
        // Iterate regions starting from start_addr
        for (&_r_start, region) in regions.range(..).filter(|&(&_s, ref r)| r.end > start_addr) {
            if candidates.len() >= limit {
                break;
            }

            // Skip unsuitable regions (e.g. non-Anon, non-aligned size check?)
            match region.region_type {
                 RegionType::Heap | RegionType::Bss | RegionType::Data => {}
                 _ => {
                     // Determine skip
                     if current_addr < region.end { current_addr = region.end; }
                     continue;
                 }
            }
            
            // Adjust scan start within this region
            let region_scan_start = if current_addr < region.start { region.start } else { current_addr };
            
            // Align to 2MB
            let mut scan_cursor = VirtAddr::new((region_scan_start.as_u64() + 0x1FFFFF) & !0x1FFFFF);
            
            while scan_cursor.as_u64() + 0x200000 <= region.end.as_u64() && candidates.len() < limit {
                if let Some(candidate) = self.check_if_thp_candidate(scan_cursor) {
                    candidates.push(candidate);
                }
                scan_cursor = VirtAddr::new(scan_cursor.as_u64() + 0x200000);
            }
            
            current_addr = scan_cursor;
        }
        
        (candidates, current_addr)
    }

    /// Check if a 2MB range is a candidate
    fn check_if_thp_candidate(&self, start: VirtAddr) -> Option<ThpCandidate> {
        // Here we need to check if pages are mapped and present
        let mut used_pages = 0;
        
        // This is a simplified check. In reality we'd walk the PT.
        for i in 0..512 {
            let addr = VirtAddr::new(start.as_u64() + i * 4096);
            if let Some(_phys) = global_translate(addr) {
                used_pages += 1;
            }
        }

        // Threshold: 50%
        if used_pages > 256 {
            Some(ThpCandidate {
                start_addr: start,
                used_pages: used_pages as u16,
                flags: 0, // Fill later or get from first page
                priority: ((used_pages * 100 / 512).min(255)) as u8,
            })
        } else {
            None
        }
    }

    /// Promote a 2MB range to a Huge Page
    pub fn promote_huge_page(&self, start_addr: VirtAddr) -> bool {
        // 1. alignment check
        if !start_addr.is_page_aligned() || start_addr.as_u64() & 0x1FFFFF != 0 {
            return false;
        }

        // 2. Get protection flags from region
        let protection = match self.get_region(start_addr.as_u64()) {
            Some(p) => p,
            None => return false,
        };

        // 3. Allocate Huge Frame
        let huge_frame = match alloc_huge_frame() {
            Some(f) => f,
            None => return false,
        };
        let huge_phys = huge_frame.start_address();
        let huge_virt = super::mapping::phys_to_virt(huge_phys);

        // 4. Zero the huge page (safety)
        unsafe {
            core::ptr::write_bytes(huge_virt.as_mut_ptr::<u8>(), 0, 0x200000);
        }

        // 5. Copy data and prepare for switch
        let pt_root = self.page_table_root.load(Ordering::Acquire);
        if pt_root == 0 {
            let idx = super::types::FrameIndex::new(huge_phys.frame_number() as usize);
            super::buddy_allocator::dealloc_frame(idx, 9);
            return false; 
        }

        // Walk to PDE
        let indices = start_addr.page_table_indices();
        
        // Scope for unsafe PT walk and updates
        let result = unsafe { self.perform_promotion(pt_root, indices, huge_phys, protection) };
        
        if !result {
             let idx = super::types::FrameIndex::new(huge_phys.frame_number() as usize);
             super::buddy_allocator::dealloc_frame(idx, 9);
        }
        
        result
    }

    /// Internal unsafe helper for promotion
    unsafe fn perform_promotion(
        &self, 
        pt_root: u64, 
        indices: [usize; 4], 
        huge_phys: PhysAddr,
        protection: Protection
    ) -> bool {
        use super::higher_half::{PageTable, PageFlags, PageTableEntry};
        
        // Level 4 (PML4)
        let pml4_phys = PhysAddr::new(pt_root);
        let pml4 = &*super::higher_half::phys_to_virt(pml4_phys).as_ptr::<PageTable>();
        let pml4e = pml4.entry(indices[0]);
        if !pml4e.is_present() { return false; }

        // Level 3 (PDPT)
        let pdpt_phys = pml4e.phys_addr();
        let pdpt = &*super::higher_half::phys_to_virt(pdpt_phys).as_ptr::<PageTable>();
        let pdpte = pdpt.entry(indices[1]);
        if !pdpte.is_present() { return false; }
        if pdpte.is_huge() { return false; } 

        // Level 2 (PD) - This is where we modify
        let pd_phys = pdpte.phys_addr();
        let pd = &mut *super::higher_half::phys_to_virt(pd_phys).as_mut_ptr::<PageTable>();
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() { return false; }
        if pde.is_huge() { return false; } // Already huge

        // Level 1 (PT) - The table we are replacing
        let pt_phys = pde.phys_addr();
        let pt = &*super::higher_half::phys_to_virt(pt_phys).as_ptr::<PageTable>();
        
        let huge_base_virt = super::mapping::phys_to_virt(huge_phys);
        
        let mut frames_to_free = Vec::new();
        
        for i in 0..512 {
            let pte = pt.entry(i);
            if pte.is_present() {
                let src_phys = pte.phys_addr();
                let src_virt = super::mapping::phys_to_virt(src_phys);
                let dst_virt = huge_base_virt.offset(i as u64 * 4096);
                
                // Copy 4KB
                core::ptr::copy_nonoverlapping(src_virt.as_ptr::<u8>(), dst_virt.as_mut_ptr::<u8>(), 4096);
                
                frames_to_free.push(src_phys);
            }
        }
        
        // Update PDE to point to Huge Page
        let mut flags = protection.to_page_flags();
        flags = flags.set(PageFlags::PRESENT | PageFlags::HUGE_PAGE);
        if protection.write { flags = flags.set(PageFlags::DIRTY); }
        
        let new_pde = PageTableEntry::huge(huge_phys, flags);
        
        *pde = new_pde;
        
        // TLB Flush
        let vaddr = (indices[0] as u64) << 39 | (indices[1] as u64) << 30 | (indices[2] as u64) << 21;
        let _vaddr_canon = if vaddr & (1 << 47) != 0 { vaddr | 0xFFFF000000000000 } else { vaddr };
        core::arch::asm!("invlpg [{}]", in(reg) _vaddr_canon);

        // Free old frames
        for frame in frames_to_free {
             let idx = super::types::FrameIndex::new(frame.frame_number() as usize);
             super::buddy_allocator::dealloc_frame(idx, 0);
        }
        
        // Free the PT frame
        let pt_idx = super::types::FrameIndex::new(pt_phys.frame_number() as usize);
        super::buddy_allocator::dealloc_frame(pt_idx, 0);
        
        true
    }
}

impl Default for ProcessAddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        // 全領域を解放
        let _ = self.exec_reset();
        
        // ページテーブルを解放
        let pt_root = self.page_table_root.load(Ordering::Acquire);
        if pt_root != 0 {
            // TODO: ページテーブル階層を再帰的に解放
        }
    }
}

// ============================================================================
// Address Space Error
// ============================================================================

/// アドレス空間操作のエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// メモリ不足
    OutOfMemory,
    /// 無効な範囲
    InvalidRange,
    /// 無効なサイズ
    InvalidSize,
    /// 領域が重複
    RegionOverlap,
    /// 領域が見つからない
    RegionNotFound,
    /// 権限エラー
    PermissionDenied,
    /// 既にマッピング済み
    AlreadyMapped,
    /// マッピングエラー
    MapFailed,
}

// ============================================================================
// Statistics
// ============================================================================

/// アドレス空間の統計情報
#[derive(Debug, Clone)]
pub struct AddressSpaceStats {
    /// ASID
    pub asid: u64,
    /// 仮想アドレス空間の合計サイズ
    pub total_virtual: u64,
    /// マッピングされたページ数
    pub mapped_pages: u64,
    /// 領域数
    pub region_count: usize,
    /// ヒープサイズ
    pub heap_size: u64,
}

// ============================================================================
// Global Address Space Manager
// ============================================================================

/// グローバルアドレス空間マネージャ
pub struct AddressSpaceManager {
    /// アドレス空間のマップ (asid -> address_space)
    spaces: RwLock<BTreeMap<u64, Box<ProcessAddressSpace>>>,
    /// 現在アクティブなASID
    current_asid: AtomicU64,
}

impl AddressSpaceManager {
    /// 新しいマネージャを作成
    pub const fn new() -> Self {
        Self {
            spaces: RwLock::new(BTreeMap::new()),
            current_asid: AtomicU64::new(0),
        }
    }
    
    /// アドレス空間を作成
    pub fn create(&self) -> Result<u64, AddressSpaceError> {
        let space = Box::new(ProcessAddressSpace::new());
        let asid = space.asid();
        
        space.init_page_table()?;
        
        let mut spaces = self.spaces.write();
        spaces.insert(asid, space);
        
        Ok(asid)
    }
    
    /// アドレス空間を取得
    pub fn get(&self, asid: u64) -> Option<u64> {
        let spaces = self.spaces.read();
        spaces.get(&asid).map(|s| s.page_table_root())
    }
    
    /// アドレス空間を削除
    pub fn destroy(&self, asid: u64) {
        let mut spaces = self.spaces.write();
        spaces.remove(&asid);
    }
    
    /// 現在のASIDを取得
    pub fn current_asid(&self) -> u64 {
        self.current_asid.load(Ordering::Acquire)
    }
    
    /// アドレス空間を切り替え
    pub fn switch_to(&self, asid: u64) -> Result<(), AddressSpaceError> {
        let spaces = self.spaces.read();
        
        if let Some(space) = spaces.get(&asid) {
            let cr3 = space.page_table_root();
            
            // CR3を設定
            unsafe {
                super::higher_half::set_cr3(PhysAddr::new(cr3));
            }
            
            self.current_asid.store(asid, Ordering::Release);
            Ok(())
        } else {
            Err(AddressSpaceError::RegionNotFound)
        }
    }

    /// 現在のアドレス空間をスキャン（NUMA Hint）
    pub fn scan_current_address_space(&self, start_addr: VirtAddr, batch_size: usize) -> Option<(usize, usize, VirtAddr)> {
        let asid = self.current_asid.load(Ordering::Acquire);
        if asid == 0 { return None; }

        let spaces = self.spaces.read();
        if let Some(space) = spaces.get(&asid) {
            Some(space.scan_numa_hints(start_addr, batch_size))
        } else {
            None
        }
    }
}

/// グローバルアドレス空間マネージャ
static ADDRESS_SPACE_MANAGER: AddressSpaceManager = AddressSpaceManager::new();

// ============================================================================
// Public API
// ============================================================================

/// アドレス空間マネージャを取得
pub fn address_space_manager() -> &'static AddressSpaceManager {
    &ADDRESS_SPACE_MANAGER
}

/// 新しいアドレス空間を作成
pub fn create_address_space() -> Result<u64, AddressSpaceError> {
    ADDRESS_SPACE_MANAGER.create()
}

/// アドレス空間を削除
pub fn destroy_address_space(asid: u64) {
    ADDRESS_SPACE_MANAGER.destroy(asid);
}

/// アドレス空間を切り替え
pub fn switch_address_space(asid: u64) -> Result<(), AddressSpaceError> {
    ADDRESS_SPACE_MANAGER.switch_to(asid)
}

/// 現在のASIDを取得
pub fn current_asid() -> u64 {
    ADDRESS_SPACE_MANAGER.current_asid()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protection_conversion() {
        let prot = Protection::READ_WRITE;
        let flags = prot.to_page_flags();
        assert!(flags.bits() & PageFlags::PRESENT != 0);
        assert!(flags.bits() & PageFlags::WRITABLE != 0);
    }
    
    #[test]
    fn test_region_contains() {
        let region = MemoryRegion::new(
            VirtAddr::new(0x1000),
            VirtAddr::new(0x2000),
            RegionType::Data,
            Protection::READ_WRITE,
        );
        
        assert!(region.contains(VirtAddr::new(0x1000)));
        assert!(region.contains(VirtAddr::new(0x1500)));
        assert!(!region.contains(VirtAddr::new(0x2000)));
        assert!(!region.contains(VirtAddr::new(0x0FFF)));
    }
}
