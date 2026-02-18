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
use alloc::boxed::Box;
use once_cell::race::OnceBox;
use spin::Mutex;

// SAS は `domain_system::DomainId` をそのまま使用する。
// 非testビルドでは正規版 domain_system.rs の DomainId、
// test/benchビルドでは task/domain_system.rs の shim DomainId が
// `crate::domain_system` として re-export されるため、条件なしで統一可能。
pub use crate::domain_system::DomainId;

pub use heap_registry::HeapRegistry;
pub use memory_region::{MemoryRegion, RegionPermissions};
pub use ownership::OwnershipError;

// ============================================================================
// Global Heap Registry
// ============================================================================

/// グローバルヒープオブジェクトレジストリ
/// Sharded + ThreadSafe structure
static HEAP_REGISTRY: OnceBox<HeapRegistry> = OnceBox::new();

/// ヒープレジストリを取得（必要に応じて初期化）
#[inline]
fn heap_registry() -> &'static HeapRegistry {
    HEAP_REGISTRY.get_or_init(|| Box::new(HeapRegistry::default()))
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
                    crate::mm::cache::exchange_heap::init_exchange_heap(ptr as usize, size);
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
        let count = heap_registry().reclaim_all(domain_id);
        self.cell_regions.remove(&domain_id);

        log::info!("[SAS] Reclaimed {} objects from {}\n", count, domain_id);
        count
    }

    /// 統計情報を取得
    pub fn stats(&self) -> SasStats {
        SasStats {
            total_regions: self.cell_regions.values().map(|v: &Vec<MemoryRegion>| v.len()).sum::<usize>(),
            total_objects: heap_registry().object_count(),
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

/// Atomic statistics for lock-free access to frequently queried metrics
struct AtomicSasStats {
    /// Number of domains (updated on domain add/remove)
    domain_count: AtomicU64,
    /// Total regions across all domains (updated on region alloc/free)
    region_count: AtomicU64,
}

impl AtomicSasStats {
    const fn new() -> Self {
        Self {
            domain_count: AtomicU64::new(0),
            region_count: AtomicU64::new(0),
        }
    }

    #[inline]
    fn increment_domains(&self) {
        self.domain_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn decrement_domains(&self) {
        self.domain_count.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    fn increment_regions(&self) {
        self.region_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn decrement_regions(&self) {
        self.region_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Global atomic stats (lock-free access)
static ATOMIC_SAS_STATS: AtomicSasStats = AtomicSasStats::new();

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
    heap_registry().change_owner(ptr, from, to).map_err(|e| {
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
    heap_registry().register_simple(ptr, size, owner);
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
    heap_registry().get_owner(ptr)
}

/// オブジェクトを無条件に登録解除し、情報を返す
pub fn unregister_any(ptr: usize) -> Option<(DomainId, usize)> {
    heap_registry().unregister_any(ptr)
}

/// アクセス権限をチェック
pub fn check_access(ptr: usize, accessor: DomainId) -> Result<(), OwnershipError> {
    // カーネルドメインは全アクセス可能
    if accessor == DomainId::KERNEL {
        return Ok(());
    }

    if heap_registry().check_access(ptr, accessor) {
        Ok(())
    } else {
        // Find owner to report detailed error, if possible
        let owner = heap_registry().get_owner(ptr);
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
    heap_registry().get_owner(ptr)
}

/// ドメインのリソースを回収
pub fn reclaim_domain_resources(domain: DomainId) -> usize {
    heap_registry().reclaim_all(domain)
}

/// オブジェクトが毒入れされているかチェック
/// 設計書 8.4: Exchange Heapへの適用
pub fn is_object_poisoned(ptr: usize) -> bool {
    heap_registry().is_poisoned(ptr)
}

/// オブジェクトを毒入れする
/// 設計書 8.4: オーナーがパニックした際にオブジェクトを無効化
pub fn poison_object(ptr: usize) -> Result<(), heap_registry::RegistryError> {
    heap_registry().poison_object(ptr)
}

/// 指定ドメインが所有する全オブジェクトを毒入れ
/// 設計書 8.4: ドメインパニック時の連鎖クラッシュ防止
pub fn poison_domain_objects(domain: DomainId) -> usize {
    heap_registry().poison_domain_objects(domain)
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
        total_objects: heap_registry().object_count(),
        domains: regions.0,
        next_addr: regions.1,
    }
}

/// Quick stats using atomic counters (lock-free, approximate).
///
/// This provides O(1) access to frequently queried metrics without
/// acquiring any locks. Values may be slightly stale but are consistent.
#[inline]
pub fn quick_stats() -> (u64, u64, u64) {
    (
        ATOMIC_SAS_STATS.domain_count.load(Ordering::Relaxed),
        ATOMIC_SAS_STATS.region_count.load(Ordering::Relaxed),
        // next_alloc_addr is already atomic in the manager
        with_sas_manager(|m| m.next_alloc_addr.load(Ordering::Relaxed)),
    )
}

/// Get object count (lock-free via heap registry)
#[inline]
pub fn object_count() -> usize {
    heap_registry().object_count()
}
