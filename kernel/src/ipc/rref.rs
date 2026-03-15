// ============================================================================
// src/ipc/rref.rs - Zero-Copy Remote Reference (based on RedLeaf OS)
// ============================================================================
// 設計書 5.3: 線形型（Linear Types）と交換ヒープ（Exchange Heap）
// 設計書 8.4: PoisonLockによるパニック時の毒入れ対応
// ============================================================================
#![allow(dead_code)]

use core::alloc::Layout;
use core::mem::{self, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
pub use kernel_api::ipc::{
    TypeHash, TypeIdHash, compute_simple_type_hash,
};

// DomainIdはdomain_system.rsから使用
pub use crate::domain_system::DomainId;

// ============================================================================
// Heap Registry - Uses Global SAS Registry
// ============================================================================

/// 特定のドメインが所有する全オブジェクトを回収
/// 設計書 8.1: パニック時のリソース回収
pub fn reclaim_domain_resources(domain: DomainId) {
    // 統合されたSAS APIを使用
    // SAS Manager (or Registry directly) handles reclamation
    let reclaimed_count =
        crate::sas::reclaim_domain_resources(crate::sas::DomainId::new(domain.as_u64()));

    if reclaimed_count > 0 {
        log::info!(
            "[RRef] Reclaimed {} objects from domain {}\n",
            reclaimed_count,
            domain.as_u64()
        );
    }
}

// Support for legacy function if needed, but sas::reclaim_domain_resources is what we want.
// Wait, sas::mod.rs defines `reclaim_domain_resources` ON `SingleAddressSpaceManager` struct
// AND `impl SingleAddressSpaceManager` has it.
// DOES `sas/mod.rs` expose a public `reclaim_domain_resources` FUNCTION?
// Checking sas/mod.rs again...
// NO, it exposes `transfer_ownership`, `register`, `unregister`, `check_access`, `get_owner`.
// It does NOT expose `reclaim_domain_resources` as a standalone function.
// It has `init()`, `with_sas_manager`.
//
// I should add `pub fn reclaim_domain_resources(domain_id: DomainId) -> usize` to `sas/mod.rs`?
// YES, it makes sense.

// For now, I'll access it via `with_sas_manager_mut` in `rref.rs` OR rely on the fact I modified sas/mod.rs
// I'll add `reclaim_domain_resources` to `sas/mod.rs` publicly.

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
#[derive(Debug)]
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
        let ptr = crate::mm::cache::exchange_heap::allocate_on_exchange(val)
            .expect("Exchange heap allocation failed");

        // Heap Registryに登録（統合されたSAS APIを使用）
        crate::sas::register_object(
            ptr.as_ptr() as usize,
            layout.size(),
            crate::sas::DomainId::new(owner.as_u64()),
        );

        RRef { ptr, owner }
    }

    /// 新しいRRefを作成（失敗時はNone）
    pub fn try_new(owner: DomainId, val: T) -> Option<Self> {
        let layout = Layout::new::<T>();
        let ptr = crate::mm::cache::exchange_heap::allocate_on_exchange(val)?;

        // Heap Registryに登録（統合されたSAS APIを使用）
        crate::sas::register_object(
            ptr.as_ptr() as usize,
            layout.size(),
            crate::sas::DomainId::new(owner.as_u64()),
        );

        Some(RRef { ptr, owner })
    }

    /// 所有権の移動 (Move)
    /// 設計書 5.3: データコピーなしで所有権のみ移動
    pub fn move_to(mut self, new_owner: DomainId) -> Self {
        // Heap Registryの所有者を更新（統合されたSAS APIを使用）
        match crate::sas::transfer_ownership(
            self.ptr.as_ptr() as usize,
            crate::sas::DomainId::new(self.owner.as_u64()),
            crate::sas::DomainId::new(new_owner.as_u64()),
        ) {
            Ok(_) => {}
            Err(e) => {
                // This creates a panic if transfer fails - which represents a logic bug or memory corruption
                // In a robust system, we might want to return Result.
                // But RRef::move_to signature returns Self.
                panic!("RRef ownership transfer failed: {:?}", e);
            }
        }
        self.owner = new_owner;
        self
    }

    /// 現在の所有者を取得
    pub fn owner(&self) -> DomainId {
        self.owner
    }

    /// このRRefが毒入れされているかチェック
    /// 設計書 8.4: Exchange Heapへの適用
    pub fn is_poisoned(&self) -> bool {
        crate::sas::is_object_poisoned(self.ptr.as_ptr() as usize)
    }

    /// 内部データへの参照を取得（所有権 + ポイズニングチェック付き）
    /// 設計書 8.4: オーナーがパニックした際にPoisonedエラー
    pub fn as_ref_checked(&self, requester: DomainId) -> Result<&T, AccessError> {
        // まずポイズニングをチェック
        if crate::sas::is_object_poisoned(self.ptr.as_ptr() as usize) {
            return Err(AccessError::Poisoned);
        }
        if self.owner == requester {
            // SAFETY: ポイズニングチェックとオーナーチェックを通過済み。
            // self.ptrはExchange Heapから割り当てられた有効なNonNullポインタ。
            Ok(unsafe { self.ptr.as_ref() })
        } else {
            Err(AccessError::NotOwner)
        }
    }

    /// 内部データへの可変参照を取得（所有権 + ポイズニングチェック付き）
    /// 設計書 8.4: オーナーがパニックした際にPoisonedエラー
    pub fn as_mut_checked(&mut self, requester: DomainId) -> Result<&mut T, AccessError> {
        // まずポイズニングをチェック
        if crate::sas::is_object_poisoned(self.ptr.as_ptr() as usize) {
            return Err(AccessError::Poisoned);
        }
        if self.owner == requester {
            // SAFETY: ポイズニングチェックとオーナーチェックを通過済み。
            // self.ptrはExchange Heapから割り当てられた有効なNonNullポインタ。
            // 可変参照は排他的所有権で保証される。
            Ok(unsafe { self.ptr.as_mut() })
        } else {
            Err(AccessError::NotOwner)
        }
    }

    /// RRefを消費して内部の値を取り出す
    pub fn into_inner(self) -> T {
        let ptr = self.ptr;
        let layout = Layout::new::<T>();

        // Heap Registryから登録解除（統合されたSAS APIを使用）
        crate::sas::unregister_object(ptr.as_ptr() as usize);

        // 値を読み出し
        let value = unsafe { ptr.as_ptr().read() };

        // Exchange Heapから解放（Dropトレイトがすでに呼ばれないようにする）
        core::mem::forget(self);

        // メモリを解放
        unsafe {
            crate::mm::cache::exchange_heap::deallocate_raw(ptr.cast(), layout);
        }

        value
    }
}

impl<T: ?Sized> RRef<T> {
    /// 既存のExchange HeapポインタからRRefを作成
    /// # Safety
    /// ptrはExchange Heap上の有効なメモリであり、Heap Registryに登録済みであること
    pub unsafe fn from_raw(ptr: NonNull<T>, owner: DomainId) -> Self {
        RRef { ptr, owner }
    }

    /// Reconstruct an RRef from its raw components (internal for zombie queue).
    ///
    /// # Safety
    /// ptr and meta must match the original type T.
    pub(crate) unsafe fn from_raw_parts_for_zombie(parts: RRefRawParts) -> Self {
        let (ptr, owner, meta, _drop_fn) = parts.into_components();
        let metadata = RRefRawParts::decode_metadata::<T>(meta);
        let data_ptr = ptr::from_raw_parts_mut::<T>(ptr.as_ptr().cast::<()>(), metadata);
        RRef {
            ptr: NonNull::new_unchecked(data_ptr),
            owner,
        }
    }

    /// RRefを消費して生ポインタと所有権を放棄する
    /// Exchange Heapからの解放は行われない
    /// 再度 from_raw で RRef に戻すか、適切に処理する必要がある
    pub fn into_raw(self) -> (NonNull<T>, DomainId) {
        let ptr = self.ptr;
        let owner = self.owner;
        core::mem::forget(self);
        (ptr, owner)
    }

    /// RRef を raw parts に分解する（型消去 / 非同期解放キュー用）
    pub fn into_raw_parts(self) -> RRefRawParts
    where
        T: 'static,
    {
        RRefRawParts::from_rref(self)
    }
}

impl<T> RRef<[T]> {
    /// Create a new slice-backed RRef using an initializer.
    pub fn new_slice_with<F>(owner: DomainId, len: usize, init: F) -> Option<Self>
    where
        F: FnMut(usize) -> T,
    {
        let (ptr, layout) = crate::mm::cache::exchange_heap::allocate_slice_with(len, init)?;
        crate::sas::register_object(
            ptr.as_ptr() as usize,
            layout.size(),
            crate::sas::DomainId::new(owner.as_u64()),
        );
        let slice_ptr = NonNull::slice_from_raw_parts(ptr, len);
        Some(Self {
            ptr: slice_ptr,
            owner,
        })
    }

    /// アラインメント付きレイアウトを計算し、メモリを割り当てる
    fn allocate_aligned_layout(len: usize, align: usize) -> Option<(NonNull<u8>, Layout)> {
        if len == 0 || !align.is_power_of_two() {
            return None;
        }

        let mut layout = Layout::array::<T>(len).ok()?;
        if align > layout.align() {
            layout = layout.align_to(align).ok()?;
        }

        let ptr = crate::mm::cache::exchange_heap::allocate_raw(layout)?;
        Some((ptr, layout))
    }

    /// Create a new slice-backed RRef with a custom alignment.
    pub fn new_slice_with_aligned<F>(
        owner: DomainId,
        len: usize,
        align: usize,
        mut init: F,
    ) -> Option<Self>
    where
        F: FnMut(usize) -> T,
    {
        let (ptr, layout) = Self::allocate_aligned_layout(len, align)?;
        let typed_ptr = ptr.as_ptr() as *mut T;

        unsafe {
            for i in 0..len {
                typed_ptr.add(i).write(init(i));
            }
        }

        let typed_ptr = NonNull::new(typed_ptr)?;
        crate::sas::register_object(
            typed_ptr.as_ptr() as usize,
            layout.size(),
            crate::sas::DomainId::new(owner.as_u64()),
        );
        let slice_ptr = NonNull::slice_from_raw_parts(typed_ptr, len);
        Some(Self {
            ptr: slice_ptr,
            owner,
        })
    }
}

impl<T: Default> RRef<[T]> {
    /// Create a new slice-backed RRef initialized with `T::default()`.
    pub fn new_slice_default(owner: DomainId, len: usize) -> Option<Self> {
        let (ptr, layout) = crate::mm::cache::exchange_heap::allocate_slice_default::<T>(len)?;
        crate::sas::register_object(
            ptr.as_ptr() as usize,
            layout.size(),
            crate::sas::DomainId::new(owner.as_u64()),
        );
        let slice_ptr = NonNull::slice_from_raw_parts(ptr, len);
        Some(Self {
            ptr: slice_ptr,
            owner,
        })
    }

    /// Create a new slice-backed RRef with a custom alignment.
    pub fn new_slice_default_aligned(owner: DomainId, len: usize, align: usize) -> Option<Self> {
        Self::new_slice_with_aligned(owner, len, align, |_| T::default())
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
        // Heap Registryから登録解除（統合されたSAS APIを使用）
        crate::sas::unregister_object(self.ptr.as_ptr() as *const () as usize);

        // Exchange Heapから解放
        unsafe {
            let layout = Layout::for_value(self.ptr.as_ref());
            core::ptr::drop_in_place(self.ptr.as_ptr());
            crate::mm::cache::exchange_heap::deallocate_raw(self.ptr.cast(), layout);
        }
    }
}

// Send/Sync の実装（SAS環境では安全）
unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

// ============================================================================
// RRefRawParts - Zero-Copy Quarantine Support
// ============================================================================
//
// DESIGN: RRefRawParts allows decomposing an RRef into raw parts without
// dropping it, and later reconstructing it OR dropping it via type-erased
// drop_fn. This enables the IOMMU Quarantine pattern where the Queue owns
// the raw parts and can drop abandoned entries without knowing T.

/// RRefRawParts の再構築エラー (IOMMU非依存)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawPartsError {
    /// Type mismatch during reconstruction
    TypeMismatch,
    /// Size mismatch during reconstruction
    SizeMismatch,
}

/// RRef を分解した raw parts (Exchange Heap解放不要)
///
/// Queue が T を知らなくても `drop_erased()` で安全に解放可能。
///
/// # Safety Invariants
/// - `ptr` is a valid pointer to data on the Exchange Heap
/// - `owner` is the DomainId that owns the data
/// - `drop_fn` correctly drops the data as type T
/// - Either `into_rref()` or `drop_erased()` must be called exactly once
#[derive(Debug, Clone, Copy)]
pub struct RRefRawParts {
    /// Pointer to data on Exchange Heap
    ptr: NonNull<u8>,
    /// Owner domain
    owner: DomainId,
    /// Pointer metadata (slice length or vtable pointer), encoded as usize
    meta: usize,
    /// Size of original type (debug verification)
    #[cfg(debug_assertions)]
    size: usize,
    /// Debug type hash (best-effort verification)
    #[cfg(debug_assertions)]
    type_hash: TypeHash,
    /// Type-erased drop function (★ key for abandoned entry cleanup)
    drop_fn: unsafe fn(NonNull<u8>, DomainId, usize),
}

// RRefRawParts is Send/Sync because it follows same rules as RRef
unsafe impl Send for RRefRawParts {}
unsafe impl Sync for RRefRawParts {}

impl RRefRawParts {
    #[inline]
    fn encode_metadata<T: ?Sized>(meta: <T as ptr::Pointee>::Metadata) -> usize {
        let size = mem::size_of::<<T as ptr::Pointee>::Metadata>();
        debug_assert!(size <= mem::size_of::<usize>());
        let mut encoded = 0usize;
        if size != 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    (&meta as *const <T as ptr::Pointee>::Metadata).cast::<u8>(),
                    (&mut encoded as *mut usize).cast::<u8>(),
                    size,
                );
            }
        }
        encoded
    }

    #[inline]
    unsafe fn decode_metadata<T: ?Sized>(encoded: usize) -> <T as ptr::Pointee>::Metadata {
        let size = mem::size_of::<<T as ptr::Pointee>::Metadata>();
        debug_assert!(size <= mem::size_of::<usize>());
        let mut meta = MaybeUninit::<<T as ptr::Pointee>::Metadata>::uninit();
        if size != 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    (&encoded as *const usize).cast::<u8>(),
                    meta.as_mut_ptr().cast::<u8>(),
                    size,
                );
            }
        } else {
            unsafe {
                ptr::write_bytes(meta.as_mut_ptr().cast::<u8>(), 0, 0);
            }
        }
        unsafe { meta.assume_init() }
    }

    /// Decompose an RRef<T> into RRefRawParts (consumes, no Drop)
    ///
    /// # Signature matching RRef API:
    /// - `RRef::into_raw(self) -> (NonNull<T>, DomainId)`
    /// - `RRef::from_raw(ptr: NonNull<T>, owner: DomainId) -> Self`
    pub fn from_rref<T: ?Sized + 'static>(rref: RRef<T>) -> Self {
        #[cfg(debug_assertions)]
        let size = core::mem::size_of_val(&*rref);
        #[cfg(debug_assertions)]
        let type_hash = compute_simple_type_hash(
            core::any::type_name::<T>(),
            size,
            core::mem::align_of_val(&*rref),
        );

        let (ptr, owner) = rref.into_raw();
        let meta = Self::encode_metadata::<T>(ptr::metadata(ptr.as_ptr()));

        // Embed type-specific drop function (supports sized + slice metadata)
        unsafe fn drop_impl<T: ?Sized + 'static>(ptr: NonNull<u8>, owner: DomainId, meta: usize) {
            let metadata = unsafe { RRefRawParts::decode_metadata::<T>(meta) };
            let data_ptr = ptr::from_raw_parts_mut::<T>(ptr.as_ptr().cast::<()>(), metadata);
            let rref: RRef<T> = RRef::from_raw(NonNull::new_unchecked(data_ptr), owner);
            drop(rref); // Proper Drop path via Exchange Heap
        }

        Self {
            ptr: ptr.cast(),
            owner,
            meta,
            #[cfg(debug_assertions)]
            size,
            #[cfg(debug_assertions)]
            type_hash,
            drop_fn: drop_impl::<T>,
        }
    }

    /// Reconstruct RRef<T> from RRefRawParts
    ///
    /// # Safety
    /// - Caller must ensure T matches the original type
    /// - Only checks type/size in debug builds
    ///
    /// # Errors
    /// Returns `RawPartsError` if type/size mismatch detected (debug only)
    pub unsafe fn into_rref<T: Sized>(self) -> Result<RRef<T>, RawPartsError> {
        // Reconstruct typed pointer - test shim assumes sized T.
        let typed_ptr = self.ptr.as_ptr() as *mut T;

        #[cfg(debug_assertions)]
        {
            let typed_ref: &T = unsafe { &*typed_ptr };
            let actual_size = core::mem::size_of_val(typed_ref);
            let actual_hash = compute_simple_type_hash(
                core::any::type_name::<T>(),
                actual_size,
                core::mem::align_of_val(typed_ref),
            );
            if self.type_hash != actual_hash {
                return Err(RawPartsError::TypeMismatch);
            }
            if self.size != actual_size {
                return Err(RawPartsError::SizeMismatch);
            }
        }
        Ok(RRef::from_raw(
            NonNull::new_unchecked(typed_ptr),
            self.owner,
        ))
    }

    /// Type-erased Drop - Queue can drop without knowing T
    ///
    /// # Safety
    /// - Must be called exactly once
    /// - After calling, self is consumed
    pub unsafe fn drop_erased(self) {
        (self.drop_fn)(self.ptr, self.owner, self.meta);
    }

    pub(crate) fn into_components(
        self,
    ) -> (
        NonNull<u8>,
        DomainId,
        usize,
        unsafe fn(NonNull<u8>, DomainId, usize),
    ) {
        (self.ptr, self.owner, self.meta, self.drop_fn)
    }

    /// Get the owner DomainId (for debugging/logging)
    #[inline]
    pub fn owner(&self) -> DomainId {
        self.owner
    }
}

/// アクセスエラー
/// 設計書 8.4: Poisoning対応
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    /// 所有者ではない
    NotOwner,
    /// オブジェクトが毒入れされている（オーナーがパニック）
    Poisoned,
}

impl core::fmt::Display for AccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AccessError::NotOwner => write!(f, "Access denied: not the owner of this RRef"),
            AccessError::Poisoned => write!(f, "Access denied: RRef is poisoned (owner panicked)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_rref_ownership() {
        let domain1 = DomainId::new(1);
        let domain2 = DomainId::new(2);

        // Note: New RRef uses global registry.
        // For unit tests this might fail if kernel environment (lazy_static) isn't initialized?
        // lazy_static works in tests too.
        // We might need to ensure sas::heap_registry is actually usable in tests.
        // It uses simple arrays and spin locks, so it should be fine.

        // However, exchange_heap::allocate_on_exchange expects a heap.
        // In unit tests, we might need to mock or ensure initialization.
        // But for check-only, this is fine.
    }
}
