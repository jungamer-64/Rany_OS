// ============================================================================
// src/ipc/rref.rs - Zero-Copy Remote Reference (based on RedLeaf OS)
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

    pub const KERNEL: DomainId = DomainId(0);
}

/// Remote Reference: ゼロコピー通信のためのヒープラッパー
/// 所有権を持つドメインを追跡可能にする
/// 
/// # ゼロコピーの仕組み
/// 1. データはExchange Heap上に一度だけ配置される
/// 2. RRefの所有権がMove semanticsで移動する
/// 3. Rustの型システムが旧所有者からのアクセスを防止
/// 4. ドメインクラッシュ時: Heap Registryが所有オブジェクトを回収
pub struct RRef<T: ?Sized> {
    data: Box<T>,      // グローバルな「交換ヒープ」上のポインタ
    owner: DomainId,   // 現在の所有者
}

impl<T> RRef<T> {
    /// 新しいRRefを作成
    /// データはExchange Heap（カスタムアロケータ）に配置される
    pub fn new(owner: DomainId, val: T) -> Self {
        RRef {
            data: Box::new(val), // TODO: カスタムアロケータを使用する場合は変更が必要
            owner,
        }
    }

    /// 所有権の移動 (Move)
    /// 設計書 5.3: データコピーなしで所有権のみ移動
    pub fn move_to(mut self, new_owner: DomainId) -> Self {
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
            Ok(&self.data)
        } else {
            Err(AccessError::NotOwner)
        }
    }

    /// 内部データへの可変参照を取得（所有権チェック付き）
    pub fn as_mut_checked(&mut self, requester: DomainId) -> Result<&mut T, AccessError> {
        if self.owner == requester {
            Ok(&mut self.data)
        } else {
            Err(AccessError::NotOwner)
        }
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
