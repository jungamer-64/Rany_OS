// ============================================================================
// src/ipc/rref.rs - Zero-Copy Remote Reference (based on RedLeaf OS)
// 設計書 5.3: 線形型（Linear Types）と交換ヒープ（Exchange Heap）
// 設計書 8.4: PoisonLockによるパニック時の毒入れ対応
// ============================================================================
#![allow(dead_code)]

use core::alloc::Layout;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
// 【設計書 8.4】跨ドメインアクセスにはPoisonLockを使用
use crate::sync::PoisonLock;

// DomainIdはdomain_system.rsから使用（P3: 重複定義の排除）
pub use crate::domain_system::DomainId;

// ============================================================================
// Heap Registry - sas/heap_registry.rs の統合実装を使用
// P3完了: 重複実装を削除し、統一されたHeapRegistryを使用
// 【設計書 8.4】PoisonLock使用 - 跨ドメインアクセス対応
// ============================================================================

use crate::sas::heap_registry::HeapRegistry;

/// グローバルなHeap Registry
/// ドメインクラッシュ時のメモリ回収に使用
/// sas/heap_registry.rs の完全実装を使用
/// 【設計書 8.4】パニック時に毒入れされ、回復可能
static HEAP_REGISTRY: PoisonLock<HeapRegistry> = PoisonLock::new(HeapRegistry::new());

/// 特定のドメインが所有する全オブジェクトを回収
/// 設計書 8.1: パニック時のリソース回収
pub fn reclaim_domain_resources(domain: DomainId) {
    // 【設計書 8.4】毒入れされていても回復して回収を実行
    let mut registry = HEAP_REGISTRY.lock().unwrap_or_else(|e| {
        log::info!("[RRef] Warning: HEAP_REGISTRY poisoned, recovering for reclaim\n");
        e.into_inner()
    });

    // HeapRegistryの統合されたreclaim_allを使用
    let reclaimed_count = registry.reclaim_all(domain);

    if reclaimed_count > 0 {
        log::info!(
            "[RRef] Reclaimed {} objects from domain {}\n",
            reclaimed_count,
            domain.as_u64()
        );
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
        // 【設計書 8.4】PoisonLockの毒入れ対応
        HEAP_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .register_simple(ptr.as_ptr() as usize, layout.size(), owner);

        RRef { ptr, owner }
    }

    /// 所有権の移動 (Move)
    /// 設計書 5.3: データコピーなしで所有権のみ移動
    pub fn move_to(mut self, new_owner: DomainId) -> Self {
        // Heap Registryの所有者を更新（統合されたAPIを使用）
        // 【設計書 8.4】PoisonLockの毒入れ対応
        let _ = HEAP_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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
        // 【設計書 8.4】PoisonLockの毒入れ対応
        HEAP_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unregister_simple(ptr.as_ptr() as usize);

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
        // 【設計書 8.4】PoisonLockの毒入れ対応
        HEAP_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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

// ============================================================================
// TypeIdHash - ABI互換性検証のための型ハッシュ
// 設計書 3.4: ABIの安定性とType ID Check
// ============================================================================

/// 型定義ハッシュ値
///
/// 動的リンク環境でのABI互換性を保証するため、
/// 構造体のレイアウト情報からハッシュ値を計算する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TypeHash(u64);

impl TypeHash {
    /// 新しいTypeHashを作成
    pub const fn new(hash: u64) -> Self {
        Self(hash)
    }

    /// ハッシュ値を取得
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// 2つのTypeHashが互換性があるか検証
    pub const fn is_compatible(&self, other: &TypeHash) -> bool {
        self.0 == other.0
    }
}

/// 型定義ハッシュを提供するトレイト
///
/// 【設計書 3.4】ABIの安定性とType ID Check
///
/// セル間で共有される構造体に実装する。
/// コンパイル時に型の名前、フィールドの順序・型・オフセット、
/// 関数の引数・戻り値の型からハッシュを計算する。
///
/// # 実装方法
///
/// 1. `#[derive(TypeIdHash)]`マクロを使用（将来実装）
/// 2. 手動で`const TYPE_HASH`を定義
///
/// # 例
///
/// ```ignore
/// struct MyMessage {
///     id: u64,
///     data: [u8; 32],
/// }
///
/// impl TypeIdHash for MyMessage {
///     const TYPE_HASH: TypeHash = TypeHash::new(
///         // FNV-1aハッシュを使用して計算
///         compute_type_hash!(MyMessage, id: u64, data: [u8; 32])
///     );
/// }
/// ```
pub trait TypeIdHash {
    /// この型のコンパイル時ハッシュ値
    const TYPE_HASH: TypeHash;

    /// 型名（デバッグ用）
    fn type_name() -> &'static str {
        core::any::type_name::<Self>()
    }

    /// ハッシュ値を取得（インスタンスメソッド版）
    fn type_hash(&self) -> TypeHash {
        Self::TYPE_HASH
    }
}

/// TypeIdHashの検証エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeHashError {
    /// ハッシュ値が一致しない（ABI非互換）
    HashMismatch {
        expected: TypeHash,
        actual: TypeHash,
    },
    /// バージョンが非互換
    VersionMismatch,
}

impl core::fmt::Display for TypeHashError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            TypeHashError::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "Type hash mismatch: expected 0x{:016X}, got 0x{:016X}",
                    expected.value(),
                    actual.value()
                )
            }
            TypeHashError::VersionMismatch => {
                write!(f, "Type version mismatch")
            }
        }
    }
}

/// 2つの型のハッシュ値を検証
///
/// ロード時検証に使用。ハッシュ値が一致しない場合はエラーを返す。
pub fn verify_type_hash<T: TypeIdHash>(expected: TypeHash) -> Result<(), TypeHashError> {
    let actual = T::TYPE_HASH;
    if expected.is_compatible(&actual) {
        Ok(())
    } else {
        Err(TypeHashError::HashMismatch { expected, actual })
    }
}

/// FNV-1aハッシュ計算のヘルパー
///
/// コンパイル時にconst fnで計算可能
pub const fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < data.len() {
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// 型名とサイズからハッシュを計算
///
/// 簡易実装。本格的な実装ではフィールド情報も含める。
pub const fn compute_simple_type_hash(type_name: &str, size: usize, align: usize) -> TypeHash {
    let name_hash = fnv1a_hash(type_name.as_bytes());
    let size_bits = (size as u64) << 32;
    let align_bits = (align as u64) << 48;
    TypeHash::new(name_hash ^ size_bits ^ align_bits)
}

// ============================================================================
// 基本型へのTypeIdHash実装
// ============================================================================

impl TypeIdHash for u8 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u8", 1, 1);
}

impl TypeIdHash for u16 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u16", 2, 2);
}

impl TypeIdHash for u32 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u32", 4, 4);
}

impl TypeIdHash for u64 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("u64", 8, 8);
}

impl TypeIdHash for i8 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i8", 1, 1);
}

impl TypeIdHash for i16 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i16", 2, 2);
}

impl TypeIdHash for i32 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i32", 4, 4);
}

impl TypeIdHash for i64 {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("i64", 8, 8);
}

impl TypeIdHash for bool {
    const TYPE_HASH: TypeHash = compute_simple_type_hash("bool", 1, 1);
}

impl<T: TypeIdHash, const N: usize> TypeIdHash for [T; N] {
    const TYPE_HASH: TypeHash =
        TypeHash::new(T::TYPE_HASH.value() ^ fnv1a_hash(b"array") ^ (N as u64));
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
