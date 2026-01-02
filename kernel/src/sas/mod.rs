// ============================================================================
// src/sas/mod.rs - Single Address Space Manager
// ============================================================================
// 設計書 1.1: Single Address Space (SAS) の完全実装
//
// 全セルが単一の仮想アドレス空間を共有し、CR3切り替えなしで
// セル間通信を実現する。メモリ保護はコンパイラ（Rust型システム）が保証。
// ============================================================================
#![allow(dead_code)]

pub mod heap_registry;
pub mod memory_region;
pub mod ownership;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

// Use the canonical DomainId when building the full kernel binary, but provide a
// lightweight test-only shim when running `cargo test --lib` so the `sas` module
// can be tested in isolation without pulling in the entire `domain_system`.
#[cfg(not(any(test, feature = "bench")))]
pub use crate::domain_system::DomainId;

#[cfg(any(test, feature = "bench"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

#[cfg(any(test, feature = "bench"))]
impl DomainId {
    pub const fn new(id: u64) -> Self { Self(id) }
    pub const fn as_u64(&self) -> u64 { self.0 }
    pub const KERNEL: DomainId = DomainId(0);
}

#[cfg(any(test, feature = "bench"))]
impl core::fmt::Display for DomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

// Note: SAS relies on the canonical `DomainId` from `domain_system` so a single
// type is used consistently across the kernel. If you need to run isolated
// `sas` lib tests, adapt the test harness accordingly.

// Display impl is provided by `domain_system::DomainId` to keep a single
// canonical implementation; tests should use that type when available.

pub use heap_registry::HeapRegistry;
pub use memory_region::{MemoryRegion, RegionPermissions};
pub use ownership::OwnershipError;

// ============================================================================
// Global Heap Registry
// ============================================================================

lazy_static! {
    /// グローバルヒープオブジェクトレジストリ
    /// Sharded + ThreadSafe structure
    static ref HEAP_REGISTRY: HeapRegistry = HeapRegistry::default();
}

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
    // heap_registry: HeapRegistry, // Removed: Use global HEAP_REGISTRY
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
        let kernel_region = MemoryRegion::new(KERNEL_BASE, KERNEL_SIZE, RegionPermissions::KERNEL);
        self.cell_regions
            .insert(DomainId::KERNEL, alloc::vec![kernel_region]);

        log::info!("[SAS] Single Address Space Manager initialized\n");
        log::info!("[SAS] Base address: {:#x}\n", SAS_BASE_ADDRESS);

        // Initialize Exchange Heap (32MB)
        // Allocate from Global Allocator to ensure backed memory
            // Exchange heap is only initialized in non-test/bench builds where the
            // `mm` module (and the global allocator) is available. Tests run under
            // `cargo test --lib` do not link the full kernel binary and should not
            // perform global memory allocations here.
            #[cfg(not(any(test, feature = "bench")))]
            unsafe {
                use alloc::alloc::{Layout, alloc};
                let size = 32 * 1024 * 1024; // 32MB
                let layout = Layout::from_size_align(size, 4096).unwrap();
                let ptr = alloc(layout);
                if !ptr.is_null() {
                    crate::mm::exchange_heap::init_exchange_heap(ptr as usize, size);
                    log::info!(
                        "[SAS] Exchange Heap initialized (32MB) at {:#x}\n",
                        ptr as usize
                    );
                } else {
                    log::error!("[SAS] Failed to allocate memory for Exchange Heap\n");
                }
            }
    }

    /// セル用のメモリ領域を割り当て
    pub fn allocate_region(
        &mut self,
        domain_id: DomainId,
        size: usize,
        permissions: RegionPermissions,
    ) -> Result<MemoryRegion, SasError> {
        // アドレスを割り当て
        let addr = self
            .next_alloc_addr
            .fetch_add(align_up(size as u64, PAGE_SIZE), Ordering::SeqCst);

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

        log::info!(
            "[SAS] Allocated region for {}: {:#x} - {:#x}\n",
            domain_id,
            region.start,
            region.end()
        );

        Ok(region)
    }

    // NOTE: transfer/check methods removed from struct to encourage using global methods
    // bypassing the manager lock.

    /// セルのリソースを全て回収
    pub fn reclaim_domain_resources(&mut self, domain_id: DomainId) -> usize {
        // 回収はグローバルレジストリに対して行う
        let count = HEAP_REGISTRY.reclaim_all(domain_id);
        self.cell_regions.remove(&domain_id);

        log::info!("[SAS] Reclaimed {} objects from {}\n", count, domain_id);
        count
    }

    /// 統計情報を取得
    pub fn stats(&self) -> SasStats {
        SasStats {
            total_regions: self.cell_regions.values().map(|v: &Vec<MemoryRegion>| v.len()).sum::<usize>(),
            total_objects: HEAP_REGISTRY.object_count(),
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
static SAS_MANAGER: Mutex<SingleAddressSpaceManager> = Mutex::new(SingleAddressSpaceManager::new());

/// SAS Managerにアクセス
/// Note: 基本的な操作（所有権転送など）はこれを使わず、直接以下の関数を使用すること。
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

// ============================================================================
// High-Performance Access Methods (Bypass SAS_MANAGER lock)
// ============================================================================

/// 所有権を移動（公開API）
pub fn transfer_ownership(ptr: usize, from: DomainId, to: DomainId) -> Result<(), OwnershipError> {
    HEAP_REGISTRY.change_owner(ptr, from, to).map_err(|e| {
        // Logging moved here since it was inside manager method
        // But logging might be expensive, maybe log only on error or debug
        e
    })?;

    // Log success?
    // log::info!("[SAS] Transferred ownership: {:#x} from {} to {}\n", ptr, from, to);
    Ok(())
}

/// オブジェクトを登録
pub fn register_object(ptr: usize, size: usize, owner: DomainId) {
    HEAP_REGISTRY.register_simple(ptr, size, owner);
}

/// オブジェクトを解除
pub fn unregister_object(ptr: usize) -> Option<DomainId> {
    // get_owner and unregister?
    // unregister_object logic in original was: get_owner -> return owner.
    // IT DID NOT UNREGISTER.
    // "注意: 完全な解除ではなく所有者を返すのみ"
    // "実際の解除は reclaim_domain_resources で行う"
    //
    // However, heap_registry.unregister exists.
    // If the intention of `unregister_object` API was just "I am done with this, please free it",
    // then we should unregister.
    // But original code said: "Note: Not full unregister...".
    // Wait, `heap_registry.unregister_simple` existed in previous `heap_registry.rs`.
    // I need to implement `unregister_simple` in my new `heap_registry.rs` or just use `unregister`?
    // In my new `heap_registry.rs`, `unregister` requires `owner`.
    //
    // The original `unregister_object` implementation called `self.heap_registry.get_owner(ptr)`.
    // It didn't call `unregister`.
    //
    // If I want to match original behavior:
    HEAP_REGISTRY.get_owner(ptr)
}

/// オブジェクトを無条件に登録解除し、情報を返す
pub fn unregister_any(ptr: usize) -> Option<(DomainId, usize)> {
    HEAP_REGISTRY.unregister_any(ptr)
}

/// アクセス権限をチェック
pub fn check_access(ptr: usize, accessor: DomainId) -> Result<(), OwnershipError> {
    // カーネルドメインは全アクセス可能
    if accessor == DomainId::KERNEL {
        return Ok(());
    }

    if HEAP_REGISTRY.check_access(ptr, accessor) {
        Ok(())
    } else {
        // Find owner to report detailed error, if possible
        let owner = HEAP_REGISTRY.get_owner(ptr);
        match owner {
            Some(o) => Err(OwnershipError::AccessDenied {
                ptr,
                owner: o,
                accessor,
            }),
            None => Err(OwnershipError::UnregisteredPointer(ptr)),
        }
    }
}

/// 所有者を取得
pub fn get_owner(ptr: usize) -> Option<DomainId> {
    HEAP_REGISTRY.get_owner(ptr)
}

/// ドメインのリソースを回収
pub fn reclaim_domain_resources(domain: DomainId) -> usize {
    HEAP_REGISTRY.reclaim_all(domain)
}

/// 統計を取得
pub fn stats() -> SasStats {
    // Must lock global manager for region stats
    let regions = with_sas_manager(|m| {
        (
            m.cell_regions.len(),
            m.next_alloc_addr.load(Ordering::Relaxed),
            m.cell_regions.values().map(|v: &Vec<MemoryRegion>| v.len()).sum::<usize>(),
        )
    });

    SasStats {
        total_regions: regions.2,
        total_objects: HEAP_REGISTRY.object_count(),
        domains: regions.0,
        next_addr: regions.1,
    }
}
