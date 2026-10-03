// ============================================================================
// src/ipc/rref.rs - Zero-Copy Remote Reference (based on RedLeaf OS)
// ============================================================================
// 設計書 5.3: 線形型（Linear Types）と交換ヒープ（Exchange Heap）
// 設計書 8.4: PoisonLockによるパニック時の毒入れ対応
// ============================================================================
use core::alloc::Layout;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
pub use kernel_api::ipc::{TypeHash, TypeIdHash, compute_simple_type_hash};

// DomainId は canonical domain module から使用
pub use crate::domain::DomainId;
#[path = "rref/raw_parts.rs"]
mod raw_parts;
pub use raw_parts::{RRefRawParts, RawPartsError, RawPartsFailure};

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
    layout: Layout,
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

        RRef { ptr, owner, layout }
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

        Some(RRef { ptr, owner, layout })
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
        let layout = self.layout;

        // Heap Registryから登録解除（統合されたSAS APIを使用）
        crate::sas::unregister_any(ptr.as_ptr() as usize);

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
    /// Observe the owned allocation without creating a reference to its contents.
    /// DMA boundaries use this to preserve provenance while device access is live.
    pub(crate) fn allocation_ptr(&self) -> NonNull<T> {
        self.ptr
    }

    /// RRef を raw parts に分解する（型消去 / 非同期解放キュー用）
    pub fn into_raw_parts(self) -> RRefRawParts
    where
        T: Send + 'static,
    {
        RRefRawParts::from_rref(self)
    }
}

/// Before registry publication, this owner tracks exactly the constructed
/// prefix and the allocation's original alignment. Interruption drops that
/// prefix and returns the block; successful publication consumes this owner.
struct InitializingSlice<T> {
    pointer: NonNull<T>,
    layout: Layout,
    initialized: usize,
}
impl<T> Drop for InitializingSlice<T> {
    fn drop(&mut self) {
        // SAFETY: only this prefix holds initialized T values. No registry,
        // device or other borrower can access this unpublished allocation.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.pointer.as_ptr(),
                self.initialized,
            ));
            crate::mm::cache::exchange_heap::deallocate_raw(self.pointer.cast(), self.layout);
        }
    }
}

impl<T> RRef<[T]> {
    /// Construct initialized values with the element's natural alignment.
    pub fn new_slice_with<F>(owner: DomainId, len: usize, init: F) -> Option<Self>
    where
        F: FnMut(usize) -> T,
    {
        Self::new_slice_with_aligned(owner, len, core::mem::align_of::<T>(), init)
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
        let mut prefix = InitializingSlice::<T> {
            pointer: ptr.cast(),
            layout,
            initialized: 0,
        };
        for index in 0..len {
            let value = init(index);
            // SAFETY: checked array layout covers this previously uninitialized
            // element; the prefix owner records every completed construction.
            unsafe { prefix.pointer.as_ptr().add(index).write(value) };
            prefix.initialized += 1;
        }
        crate::sas::register_object(
            prefix.pointer.as_ptr() as usize,
            layout.size(),
            crate::sas::DomainId::new(owner.as_u64()),
        );
        let prefix = core::mem::ManuallyDrop::new(prefix);
        Some(Self {
            ptr: NonNull::slice_from_raw_parts(prefix.pointer, len),
            owner,
            layout,
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
            layout,
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
        crate::sas::unregister_any(self.ptr.as_ptr() as *const () as usize);

        // Exchange Heapから解放
        unsafe {
            let layout = self.layout;
            core::ptr::drop_in_place(self.ptr.as_ptr());
            crate::mm::cache::exchange_heap::deallocate_raw(self.ptr.cast(), layout);
        }
    }
}

// SAFETY: moving the unique owner transfers its exact stable allocation and
// destructor obligation; payload movement is allowed by T: Send.
unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
// SAFETY: shared access creates only shared payload references. Mutation and
// destruction require exclusive ownership, and T: Sync admits those observers.
unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}

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
