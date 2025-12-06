// ============================================================================
// src/ipc/rref.rs - Zero-Copy Remote Reference (based on RedLeaf OS)
// 設計書 5.3: 線形型（Linear Types）と交換ヒープ（Exchange Heap）
// ============================================================================
#![allow(dead_code)]

use core::alloc::Layout;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use spin::Mutex;

// DomainIdはdomain_system.rsから使用（P3: 重複定義の排除）
pub use crate::domain_system::DomainId;

// ============================================================================
// Heap Registry - sas/heap_registry.rs の統合実装を使用
// P3完了: 重複実装を削除し、統一されたHeapRegistryを使用
// ============================================================================

use crate::sas::heap_registry::HeapRegistry;

/// グローバルなHeap Registry
/// ドメインクラッシュ時のメモリ回収に使用
/// sas/heap_registry.rs の完全実装を使用
static HEAP_REGISTRY: Mutex<HeapRegistry> = Mutex::new(HeapRegistry::new());

/// 特定のドメインが所有する全オブジェクトを回収
/// 設計書 8.1: パニック時のリソース回収
pub fn reclaim_domain_resources(domain: DomainId) {
    let mut registry = HEAP_REGISTRY.lock();
    
    // HeapRegistryの統合されたreclaim_allを使用
    let reclaimed_count = registry.reclaim_all(domain);
    
    if reclaimed_count > 0 {
        crate::log!("[RRef] Reclaimed {} objects from domain {}\n", reclaimed_count, domain.as_u64());
    }
}

// ============================================================================
// RRef - Remote Reference with Exchange Heap
// ============================================================================

/// Remote Reference: ゼロコピー通信のためのヒープラッパー
/// 所有権を持つドメインを追跡可能にする
///
/// # ゼロコピーの仕組み
/// 1. データはExchange Heap上に一度だけ配置される
/// 2. RRefの所有権がMove semanticsで移動する
/// 3. Rustの型システムが旧所有者からのアクセスを防止
/// 4. ドメインクラッシュ時: Heap Registryが所有オブジェクトを回収
pub struct RRef<T: ?Sized> {
    /// Exchange Heap上のポインタ
    ptr: NonNull<T>,
    /// 現在の所有者
    owner: DomainId,
}

impl<T> RRef<T> {
    /// 新しいRRefを作成
    /// データはExchange Heap上に配置される
    pub fn new(owner: DomainId, val: T) -> Self {
        let layout = Layout::new::<T>();

        // Exchange Heapに割り当て
        let ptr = crate::mm::exchange_heap::allocate_on_exchange(val)
            .expect("Exchange heap allocation failed");

        // Heap Registryに登録（統合されたAPIを使用）
        HEAP_REGISTRY
            .lock()
            .register_simple(ptr.as_ptr() as usize, layout.size(), owner);

        RRef { ptr, owner }
    }

    /// 所有権の移動 (Move)
    /// 設計書 5.3: データコピーなしで所有権のみ移動
    pub fn move_to(mut self, new_owner: DomainId) -> Self {
        // Heap Registryの所有者を更新（統合されたAPIを使用）
        let _ = HEAP_REGISTRY
            .lock()
            .change_owner(self.ptr.as_ptr() as usize, self.owner, new_owner);
        self.owner = new_owner;
        self
    }

    /// 現在の所有者を取得
    pub fn owner(&self) -> DomainId {
        self.owner
    }

    /// 内部データへの参照を取得（所有権チェック付き）
    pub fn as_ref_checked(&self, requester: DomainId) -> Result<&T, AccessError> {
        if self.owner == requester {
            Ok(unsafe { self.ptr.as_ref() })
        } else {
            Err(AccessError::NotOwner)
        }
    }

    /// 内部データへの可変参照を取得（所有権チェック付き）
    pub fn as_mut_checked(&mut self, requester: DomainId) -> Result<&mut T, AccessError> {
        if self.owner == requester {
            Ok(unsafe { self.ptr.as_mut() })
        } else {
            Err(AccessError::NotOwner)
        }
    }

    /// RRefを消費して内部の値を取り出す
    pub fn into_inner(self) -> T {
        let ptr = self.ptr;
        let layout = Layout::new::<T>();

        // Heap Registryから登録解除（統合されたAPIを使用）
        HEAP_REGISTRY.lock().unregister_simple(ptr.as_ptr() as usize);

        // 値を読み出し
        let value = unsafe { ptr.as_ptr().read() };

        // Exchange Heapから解放（Dropトレイトがすでに呼ばれないようにする）
        core::mem::forget(self);

        // メモリを解放
        unsafe {
            crate::mm::exchange_heap::deallocate_raw(ptr.cast(), layout);
        }

        value
    }
}

impl<T: ?Sized> Deref for RRef<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for RRef<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: ?Sized> Drop for RRef<T> {
    fn drop(&mut self) {
        // Heap Registryから登録解除（統合されたAPIを使用）
        HEAP_REGISTRY
            .lock()
            .unregister_simple(self.ptr.as_ptr() as *const () as usize);

        // Exchange Heapから解放
        unsafe {
            let layout = Layout::for_value(self.ptr.as_ref());
            core::ptr::drop_in_place(self.ptr.as_ptr());
            crate::mm::exchange_heap::deallocate_raw(self.ptr.cast(), layout);
        }
    }
}

// Send/Sync の実装（SAS環境では安全）
unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

/// アクセスエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    NotOwner,
}

impl core::fmt::Display for AccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AccessError::NotOwner => write!(f, "Access denied: not the owner of this RRef"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rref_ownership() {
        let domain1 = DomainId::new(1);
        let domain2 = DomainId::new(2);

        let rref = RRef::new(domain1, 42u32);
        assert_eq!(rref.owner(), domain1);

        // Move ownership
        let rref = rref.move_to(domain2);
        assert_eq!(rref.owner(), domain2);

        // Access check
        assert!(rref.as_ref_checked(domain2).is_ok());
        assert!(rref.as_ref_checked(domain1).is_err());
    }
}
