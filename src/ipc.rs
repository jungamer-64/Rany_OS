// ============================================================================
// src/ipc.rs - Zero-Copy IPC with RRef (Remote Reference)
// ============================================================================
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

/// ドメインID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainId(u64);

impl DomainId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const KERNEL: DomainId = DomainId(0);
}

/// Remote Reference: ゼロコピー通信のためのヒープラッパー
/// 
/// # ゼロコピーの仕組み
/// 1. データはExchange Heap上に一度だけ配置される
/// 2. RRefの所有権がMove semanticsで移動する
/// 3. Rustの型システムが旧所有者からのアクセスを防止
/// 4. ドメインクラッシュ時: Heap Registryが所有オブジェクトを回収
pub struct RRef<T: ?Sized> {
    data: Box<T>,
    owner: DomainId,
}

impl<T> RRef<T> {
    /// 新しいRRefを作成
    pub fn new(owner: DomainId, val: T) -> Self {
        RRef {
            data: Box::new(val),
            owner,
        }
    }

    /// 所有権の移動 (Move) - ゼロコピー
    pub fn move_to(mut self, new_owner: DomainId) -> Self {
        self.owner = new_owner;
        self
    }

    /// 現在の所有者を取得
    pub fn owner(&self) -> DomainId {
        self.owner
    }
}

impl<T: ?Sized> Deref for RRef<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.data
    }
}

impl<T: ?Sized> DerefMut for RRef<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

// Send/Sync の実装（SAS環境では安全）
unsafe impl<T: ?Sized + Send> Send for RRef<T> {}
unsafe impl<T: ?Sized + Sync> Sync for RRef<T> {}
