// ============================================================================
// src/sas/mod.rs - Single Address Space Manager
// 設計書 1.1: Single Address Space (SAS) の完全実装
//
// 全セルが単一の仮想アドレス空間を共有し、CR3切り替えなしで
// セル間通信を実現する。メモリ保護はコンパイラ（Rust型システム）が保証。
// ============================================================================
#![allow(dead_code)]

pub mod memory_region;
pub mod heap_registry;
pub mod ownership;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::domain_system::DomainId;

pub use memory_region::{MemoryRegion, RegionPermissions};
pub use heap_registry::{HeapRegistry, RegistryError};
pub use ownership::{OwnershipError, OwnershipToken, Transferable, ZeroCopyTransfer};

// ============================================================================
// SAS Manager
// ============================================================================

/// Single Address Space Manager
/// 
/// 設計書 1.1: CR3切り替えなしで全セルが同一アドレス空間を共有
/// メモリ保護はRustの型システムとHeap Registryが提供
pub struct SingleAddressSpaceManager {
    /// セルごとのメモリ領域管理
    cell_regions: BTreeMap<DomainId, Vec<MemoryRegion>>,
    /// ヒープオブジェクトの所有者追跡
    heap_registry: HeapRegistry,
    /// 次の領域割り当てアドレス
    next_alloc_addr: AtomicU64,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl SingleAddressSpaceManager {
    /// SAS Managerを作成
    pub const fn new() -> Self {
        Self {
            cell_regions: BTreeMap::new(),
            heap_registry: HeapRegistry::new(),
            next_alloc_addr: AtomicU64::new(SAS_BASE_ADDRESS),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// SASを初期化
    pub fn init(&mut self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return; // 既に初期化済み
        }
        
        // カーネル領域を登録
        let kernel_region = MemoryRegion::new(
            KERNEL_BASE,
            KERNEL_SIZE,
            RegionPermissions::KERNEL,
        );
        self.cell_regions.insert(DomainId::KERNEL, alloc::vec![kernel_region]);
        
        crate::log!("[SAS] Single Address Space Manager initialized\n");
        crate::log!("[SAS] Base address: {:#x}\n", SAS_BASE_ADDRESS);
    }
    
    /// セル用のメモリ領域を割り当て
    pub fn allocate_region(
        &mut self,
        domain_id: DomainId,
        size: usize,
        permissions: RegionPermissions,
    ) -> Result<MemoryRegion, SasError> {
        // アドレスを割り当て
        let addr = self.next_alloc_addr.fetch_add(
            align_up(size as u64, PAGE_SIZE),
            Ordering::SeqCst,
        );
        
        // 上限チェック
        if addr + size as u64 > SAS_MAX_ADDRESS {
            return Err(SasError::OutOfAddressSpace);
        }
        
        let region = MemoryRegion::new(addr as usize, size, permissions);
        
        // セルの領域リストに追加
        self.cell_regions
            .entry(domain_id)
            .or_insert_with(Vec::new)
            .push(region.clone());
        
        crate::log!("[SAS] Allocated region for {}: {:#x} - {:#x}\n",
            domain_id, region.start, region.end());
        
        Ok(region)
    }
    
    /// 所有権をゼロコピーで移動
    /// 
    /// 設計書 7.1: CR3の切り替えなしでポインタの有効性を維持
    /// アドレス変換なしで即座に完了
    pub fn transfer_ownership(
        &mut self,
        ptr: usize,
        from: DomainId,
        to: DomainId,
    ) -> Result<(), OwnershipError> {
        // ポインタはそのまま有効（SASなのでアドレス変換不要）
        // Heap Registryで所有者のみ変更
        self.heap_registry.change_owner(ptr, from, to)?;
        
        crate::log!("[SAS] Transferred ownership: {:#x} from {} to {}\n",
            ptr, from, to);
        
        Ok(())
    }
    
    /// オブジェクトを登録
    pub fn register_object(
        &mut self,
        ptr: usize,
        size: usize,
        owner: DomainId,
    ) {
        self.heap_registry.register_simple(ptr, size, owner);
    }
    
    /// オブジェクトを解除
    pub fn unregister_object(&mut self, ptr: usize) -> Option<DomainId> {
        let owner = self.heap_registry.get_owner(ptr)?;
        // 注意: 完全な解除ではなく所有者を返すのみ
        // 実際の解除は reclaim_domain_resources で行う
        Some(owner)
    }
    
    /// アドレスの所有者を取得
    pub fn get_owner(&self, ptr: usize) -> Option<DomainId> {
        self.heap_registry.get_owner(ptr)
    }
    
    /// アクセス権限をチェック
    pub fn check_access(
        &self,
        ptr: usize,
        accessor: DomainId,
    ) -> Result<(), OwnershipError> {
        // カーネルドメインは全アクセス可能
        if accessor == DomainId::KERNEL {
            return Ok(());
        }
        
        // 所有者チェック
        match self.heap_registry.get_owner(ptr) {
            Some(owner) if owner == accessor => Ok(()),
            Some(owner) => Err(OwnershipError::AccessDenied {
                ptr,
                owner,
                accessor,
            }),
            None => Err(OwnershipError::UnregisteredPointer(ptr)),
        }
    }
    
    /// セルのリソースを全て回収
    pub fn reclaim_domain_resources(&mut self, domain_id: DomainId) -> usize {
        let count = self.heap_registry.reclaim_all(domain_id);
        self.cell_regions.remove(&domain_id);
        
        crate::log!("[SAS] Reclaimed {} objects from {}\n", count, domain_id);
        count
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> SasStats {
        SasStats {
            total_regions: self.cell_regions.values().map(|v| v.len()).sum(),
            total_objects: self.heap_registry.object_count(),
            domains: self.cell_regions.len(),
            next_addr: self.next_alloc_addr.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// 定数
// ============================================================================

/// SASベースアドレス（ヒープの後ろから開始）
const SAS_BASE_ADDRESS: u64 = 0x_6666_6666_0000;

/// SAS最大アドレス
const SAS_MAX_ADDRESS: u64 = 0x_FFFF_FFFF_0000;

/// カーネルベースアドレス
const KERNEL_BASE: usize = 0x0;

/// カーネルサイズ（16MB）
const KERNEL_SIZE: usize = 16 * 1024 * 1024;

/// ページサイズ
const PAGE_SIZE: u64 = 4096;

/// アドレスをアラインメント
const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

// ============================================================================
// エラー型
// ============================================================================

/// SASエラー
#[derive(Debug, Clone)]
pub enum SasError {
    /// アドレス空間不足
    OutOfAddressSpace,
    /// 所有権エラー
    Ownership(OwnershipError),
    /// 無効な領域
    InvalidRegion,
}

impl From<OwnershipError> for SasError {
    fn from(e: OwnershipError) -> Self {
        SasError::Ownership(e)
    }
}

impl core::fmt::Display for SasError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SasError::OutOfAddressSpace => write!(f, "Out of address space"),
            SasError::Ownership(e) => write!(f, "Ownership error: {}", e),
            SasError::InvalidRegion => write!(f, "Invalid region"),
        }
    }
}

// ============================================================================
// 統計
// ============================================================================

/// SAS統計
#[derive(Debug, Clone)]
pub struct SasStats {
    /// 総領域数
    pub total_regions: usize,
    /// 総オブジェクト数
    pub total_objects: usize,
    /// ドメイン数
    pub domains: usize,
    /// 次の割り当てアドレス
    pub next_addr: u64,
}

// ============================================================================
// グローバルインスタンス
// ============================================================================

/// グローバルSAS Manager
static SAS_MANAGER: Mutex<SingleAddressSpaceManager> = 
    Mutex::new(SingleAddressSpaceManager::new());

/// SAS Managerにアクセス
pub fn with_sas_manager<F, R>(f: F) -> R
where
    F: FnOnce(&SingleAddressSpaceManager) -> R,
{
    f(&SAS_MANAGER.lock())
}

/// SAS Managerを変更
pub fn with_sas_manager_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut SingleAddressSpaceManager) -> R,
{
    f(&mut SAS_MANAGER.lock())
}

/// SASを初期化
pub fn init() {
    with_sas_manager_mut(|m| m.init());
}

/// 所有権を移動（公開API）
pub fn transfer_ownership(
    ptr: usize,
    from: DomainId,
    to: DomainId,
) -> Result<(), OwnershipError> {
    with_sas_manager_mut(|m| m.transfer_ownership(ptr, from, to))
}

/// オブジェクトを登録
pub fn register_object(ptr: usize, size: usize, owner: DomainId) {
    with_sas_manager_mut(|m| m.register_object(ptr, size, owner));
}

/// オブジェクトを解除
pub fn unregister_object(ptr: usize) -> Option<DomainId> {
    with_sas_manager_mut(|m| m.unregister_object(ptr))
}

/// アクセス権限をチェック
pub fn check_access(ptr: usize, accessor: DomainId) -> Result<(), OwnershipError> {
    with_sas_manager(|m| m.check_access(ptr, accessor))
}

/// 統計を取得
pub fn stats() -> SasStats {
    with_sas_manager(|m| m.stats())
}
