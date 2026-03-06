// ============================================================================
// kernel/src/mm/domain_ownership.rs - Domain Ownership Tracking for Exchange Heap
// ============================================================================
//!
//! # ドメインオーナーシップ追跡
//!
//! 設計書 5.4 および 8.1 に基づく実装
//!
//! SAS（単一アドレス空間）ではプロセス終了による自動メモリ解放がないため、
//! ドメインがクラッシュした際に Exchange Heap 上のメモリがリークする可能性があります。
//!
//! このモジュールは、各割り当てにドメインIDをタグ付けし、
//! クラッシュハンドラやOOMキラーが特定ドメインのメモリを一括回収できる
//! 仕組みを提供します。
//!
//! ## 使用例
//!
//! ```rust
//! // ドメインIDを指定してアロケーション
//! let ptr = allocate_for_domain(domain_id, layout)?;
//!
//! // ドメインクラッシュ時の一括回収
//! let freed_bytes = reclaim_domain_allocations(domain_id);
//! ```
#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;

use crate::domain_system::DomainId;

/// アロケーション情報
#[derive(Debug, Clone, Copy)]
pub struct AllocationInfo {
    /// アロケーションのアドレス
    pub address: usize,
    /// アロケーションのサイズ
    pub size: usize,
    /// アロケーション時のタイムスタンプ（tick）
    pub timestamp: u64,
}

/// ドメインごとのアロケーション追跡
struct DomainAllocations {
    /// ドメインID -> アロケーションリスト
    allocations: BTreeMap<DomainId, Vec<AllocationInfo>>,
    /// アドレス -> ドメインID（逆引き用）
    address_to_domain: BTreeMap<usize, DomainId>,
    /// 総追跡アロケーション数
    total_allocations: usize,
    /// ドメインごとの総割り当てバイト数
    domain_bytes: BTreeMap<DomainId, usize>,
}

impl DomainAllocations {
    const fn new() -> Self {
        Self {
            allocations: BTreeMap::new(),
            address_to_domain: BTreeMap::new(),
            total_allocations: 0,
            domain_bytes: BTreeMap::new(),
        }
    }

    /// アロケーションを登録
    fn register(&mut self, domain_id: DomainId, address: usize, size: usize) {
        let info = AllocationInfo {
            address,
            size,
            timestamp: crate::task::timer::current_tick(),
        };

        self.allocations
            .entry(domain_id)
            .or_insert_with(Vec::new)
            .push(info);

        self.address_to_domain.insert(address, domain_id);
        self.total_allocations += 1;

        *self.domain_bytes.entry(domain_id).or_insert(0) += size;
    }

    /// アロケーションの登録を解除
    fn unregister(&mut self, address: usize) -> Option<(DomainId, usize)> {
        let domain_id = self.address_to_domain.remove(&address)?;

        if let Some(allocs) = self.allocations.get_mut(&domain_id) {
            if let Some(pos) = allocs.iter().position(|a| a.address == address) {
                let info = allocs.remove(pos);
                self.total_allocations = self.total_allocations.saturating_sub(1);

                if let Some(bytes) = self.domain_bytes.get_mut(&domain_id) {
                    *bytes = bytes.saturating_sub(info.size);
                }

                // 空になったドメインエントリを削除
                if allocs.is_empty() {
                    self.allocations.remove(&domain_id);
                    self.domain_bytes.remove(&domain_id);
                }

                return Some((domain_id, info.size));
            }
        }

        None
    }

    /// ドメインの全アロケーションを取得
    fn get_domain_allocations(&self, domain_id: DomainId) -> Vec<AllocationInfo> {
        self.allocations
            .get(&domain_id)
            .cloned()
            .unwrap_or_default()
    }

    /// ドメインの全アロケーションを削除（リストを返す）
    fn remove_domain_allocations(&mut self, domain_id: DomainId) -> Vec<AllocationInfo> {
        // アドレス逆引きテーブルからも削除
        if let Some(allocs) = self.allocations.get(&domain_id) {
            for info in allocs {
                self.address_to_domain.remove(&info.address);
                self.total_allocations = self.total_allocations.saturating_sub(1);
            }
        }

        self.domain_bytes.remove(&domain_id);
        self.allocations.remove(&domain_id).unwrap_or_default()
    }

    /// ドメインの総割り当てバイト数を取得
    fn domain_total_bytes(&self, domain_id: DomainId) -> usize {
        self.domain_bytes.get(&domain_id).copied().unwrap_or(0)
    }

    /// 統計を取得
    fn stats(&self) -> OwnershipStats {
        OwnershipStats {
            total_allocations: self.total_allocations,
            total_domains: self.allocations.len(),
            total_tracked_bytes: self.domain_bytes.values().sum(),
        }
    }
}

/// グローバルドメインアロケーション追跡
static DOMAIN_ALLOCATIONS: PoisonLock<DomainAllocations> =
    PoisonLock::new(DomainAllocations::new());

// ============================================================================
// Public API
// ============================================================================

/// アロケーションをドメインに登録
///
/// Exchange Heap 上のアロケーション後に呼び出す
pub fn register_allocation(domain_id: DomainId, address: usize, size: usize) {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(mut guard) => {
            guard.register(domain_id, address, size);
        }
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - register skipped");
        }
    }
}

/// アロケーションの登録を解除
///
/// Exchange Heap 上のデアロケーション時に呼び出す
pub fn unregister_allocation(address: usize) -> Option<(DomainId, usize)> {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(mut guard) => guard.unregister(address),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - unregister skipped");
            None
        }
    }
}

/// ドメインの全アロケーションを取得
pub fn get_domain_allocations(domain_id: DomainId) -> Vec<AllocationInfo> {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(guard) => guard.get_domain_allocations(domain_id),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - returning empty list");
            Vec::new()
        }
    }
}

/// ドメインの総割り当てバイト数を取得
pub fn domain_total_bytes(domain_id: DomainId) -> usize {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(guard) => guard.domain_total_bytes(domain_id),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - returning 0");
            0
        }
    }
}

/// ドメインの全アロケーションを回収
///
/// ドメインクラッシュ時やOOM時に呼び出す
///
/// # Returns
/// 解放したバイト数
pub fn reclaim_domain_allocations(domain_id: DomainId) -> usize {
    let allocations = match DOMAIN_ALLOCATIONS.lock() {
        Ok(mut guard) => guard.remove_domain_allocations(domain_id),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - reclaim skipped");
            Vec::new()
        }
    };

    let mut freed_bytes = 0;

    for info in allocations {
        // Exchange Heap から解放
        // 注意: Layout は正確でなくてもサイズが一致していれば問題ない
        if let Ok(layout) = Layout::from_size_align(info.size, 8) {
            if let Some(ptr) = NonNull::new(info.address as *mut u8) {
                unsafe {
                    crate::mm::cache::exchange_heap::deallocate_raw(ptr, layout);
                }
                freed_bytes += info.size;
            }
        }
    }

    if freed_bytes > 0 {
        log::info!(
            "[OWNERSHIP] Reclaimed {} bytes from domain {}\n",
            freed_bytes,
            domain_id
        );
    }

    freed_bytes
}

/// 統計を取得
pub fn stats() -> OwnershipStats {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(guard) => guard.stats(),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - returning zero stats");
            OwnershipStats {
                total_allocations: 0,
                total_domains: 0,
                total_tracked_bytes: 0,
            }
        }
    }
}

/// オーナーシップ統計
#[derive(Debug, Clone, Copy)]
pub struct OwnershipStats {
    /// 総追跡アロケーション数
    pub total_allocations: usize,
    /// 追跡中のドメイン数
    pub total_domains: usize,
    /// 総追跡バイト数
    pub total_tracked_bytes: usize,
}

// ============================================================================
// Exchange Heap 統合 API
// ============================================================================

/// ドメイン用にExchange Heap上にメモリを割り当て（オーナーシップ追跡付き）
///
/// 標準の `allocate_on_exchange` の代わりに使用
pub fn allocate_for_domain<T>(domain_id: DomainId, value: T) -> Option<NonNull<T>> {
    use crate::mm::cache::exchange_heap::allocate_on_exchange;

    let ptr = allocate_on_exchange(value)?;
    let layout = Layout::new::<T>();

    register_allocation(domain_id, ptr.as_ptr() as usize, layout.size());

    Some(ptr)
}

/// ドメイン用のExchange Heap上のメモリを解放（オーナーシップ追跡解除付き）
///
/// # Safety
/// - `ptr` は `allocate_for_domain` で取得したポインタである必要がある
pub unsafe fn deallocate_for_domain<T>(ptr: NonNull<T>) {
    use crate::mm::cache::exchange_heap::deallocate_on_exchange;

    let address = ptr.as_ptr() as usize;
    unregister_allocation(address);

    unsafe {
        deallocate_on_exchange(ptr);
    }
}

/// ドメイン用にゼロ初期化されたスライスを割り当て（オーナーシップ追跡付き）
pub fn allocate_slice_for_domain<T: Sized>(
    domain_id: DomainId,
    len: usize,
) -> Option<(NonNull<T>, Layout)> {
    use crate::mm::cache::exchange_heap::allocate_zeroed_slice;

    let (ptr, layout) = allocate_zeroed_slice::<T>(len)?;

    register_allocation(domain_id, ptr.as_ptr() as usize, layout.size());

    Some((ptr, layout))
}

/// ドメイン用スライスを解放（オーナーシップ追跡解除付き）
///
/// # Safety
/// - `ptr` は `allocate_slice_for_domain` で取得したポインタである必要がある
pub unsafe fn deallocate_slice_for_domain<T>(ptr: NonNull<T>, len: usize) {
    use crate::mm::cache::exchange_heap::deallocate_slice;

    let address = ptr.as_ptr() as usize;
    unregister_allocation(address);

    unsafe {
        deallocate_slice(ptr, len);
    }
}

// ============================================================================
// OOM Killer 統合
// ============================================================================

/// 全ドメインの割り当てサマリを取得（OOMキラー用）
pub fn get_domain_memory_summary() -> Vec<(DomainId, usize)> {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(allocs) => allocs
            .domain_bytes
            .iter()
            .map(|(id, bytes)| (*id, *bytes))
            .collect(),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - returning empty summary");
            Vec::new()
        }
    }
}

/// 最大メモリ使用ドメインを取得（OOMキラー用）
pub fn get_largest_domain() -> Option<(DomainId, usize)> {
    match DOMAIN_ALLOCATIONS.lock() {
        Ok(allocs) => allocs
            .domain_bytes
            .iter()
            .max_by_key(|(_, bytes)| *bytes)
            .map(|(id, bytes)| (*id, *bytes)),
        Err(_) => {
            log::error!("[OWNERSHIP] Global Map poisoned - returning None");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_register_unregister() {
        let domain_id = DomainId::new(100);
        let address = 0x1000;
        let size = 256;

        register_allocation(domain_id, address, size);

        assert_eq!(domain_total_bytes(domain_id), size);

        let result = unregister_allocation(address);
        assert_eq!(result, Some((domain_id, size)));

        assert_eq!(domain_total_bytes(domain_id), 0);
    }

    #[test_case]
    fn test_reclaim_domain() {
        let domain_id = DomainId::new(200);

        // 複数のアロケーションを登録
        register_allocation(domain_id, 0x2000, 100);
        register_allocation(domain_id, 0x3000, 200);
        register_allocation(domain_id, 0x4000, 300);

        assert_eq!(domain_total_bytes(domain_id), 600);

        // 全アロケーションを取得
        let allocs = get_domain_allocations(domain_id);
        assert_eq!(allocs.len(), 3);
    }

    #[test_case]
    fn test_stats() {
        let stats = stats();
        // 基本的な統計が取得できることを確認
        // assert!(stats.total_allocations >= 0); // usize is always >= 0
        // assert!(stats.total_domains >= 0);
    }

    #[test_case]
    fn test_poisoned_register_skips() {
        use crate::sync::set_panicking;
        set_panicking(true);
        register_allocation(DomainId::new(1), 0x1234, 512);
        set_panicking(false);
        assert_eq!(get_domain_allocations(DomainId::new(1)).len(), 0);
    }

    #[test_case]
    fn test_poisoned_getters_return_defaults() {
        use crate::sync::set_panicking;
        set_panicking(true);
        assert!(get_domain_memory_summary().is_empty());
        assert_eq!(get_largest_domain(), None);
        set_panicking(false);
    }
}
