// ============================================================================
// src/sas/ownership.rs - 型安全な所有権転送
// ============================================================================
//! Rustの型システムを活用した所有権転送メカニズム。
//! ゼロコピーでのセル間オブジェクト転送を安全に実現。
#![allow(dead_code)]

use crate::domain_system::DomainId;
use core::marker::PhantomData;

/// 所有権転送エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipError {
    /// 所有者が一致しない
    NotOwner,
    /// 無効な転送先
    InvalidDestination,
    /// 既に転送済み
    AlreadyTransferred,
    /// 登録されていない
    NotRegistered,
    /// 型が一致しない
    TypeMismatch,
    /// アクセス拒否
    AccessDenied {
        ptr: usize,
        owner: crate::domain_system::DomainId,
        accessor: crate::domain_system::DomainId,
    },
    /// 未登録のポインタ
    UnregisteredPointer(usize),
}

impl core::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OwnershipError::NotOwner => write!(f, "Not the owner"),
            OwnershipError::InvalidDestination => write!(f, "Invalid destination"),
            OwnershipError::AlreadyTransferred => write!(f, "Already transferred"),
            OwnershipError::NotRegistered => write!(f, "Not registered"),
            OwnershipError::TypeMismatch => write!(f, "Type mismatch"),
            OwnershipError::AccessDenied {
                ptr,
                owner,
                accessor,
            } => {
                write!(
                    f,
                    "Access denied: ptr={:#x}, owner={}, accessor={}",
                    ptr, owner, accessor
                )
            }
            OwnershipError::UnregisteredPointer(ptr) => {
                write!(f, "Unregistered pointer: {:#x}", ptr)
            }
        }
    }
}

/// 所有権転送トークン
///
/// 所有権の転送を型レベルで追跡する。
/// このトークンはムーブのみ可能で、コピー/クローン不可。
#[derive(Debug)]
pub struct OwnershipToken<T> {
    /// 転送元ドメイン
    pub from: DomainId,
    /// 転送先ドメイン
    pub to: DomainId,
    /// 転送されるアドレス
    pub address: usize,
    /// サイズ
    pub size: usize,
    /// 型のPhantomData
    _marker: PhantomData<T>,
}

impl<T> OwnershipToken<T> {
    /// 新しい転送トークンを作成
    pub fn new(from: DomainId, to: DomainId, address: usize, size: usize) -> Self {
        Self {
            from,
            to,
            address,
            size,
            _marker: PhantomData,
        }
    }

    /// 転送を完了してアドレスを取得
    ///
    /// この関数はトークンを消費し、転送先でのみ呼び出し可能。
    pub fn complete(self, current_domain: DomainId) -> Result<usize, OwnershipError> {
        if current_domain != self.to {
            return Err(OwnershipError::NotOwner);
        }
        Ok(self.address)
    }
}

/// 転送可能なオブジェクトラッパー
///
/// SAS環境でセル間転送可能なオブジェクトを表す。
/// 所有権追跡と型安全性を保証。
#[repr(C)]
pub struct Transferable<T: Sized + Send> {
    /// 内部データ
    data: T,
    /// 所有者ドメイン
    owner: DomainId,
    /// 転送状態
    state: TransferState,
}

/// 転送状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// 所有中
    Owned,
    /// 転送中
    InTransfer,
    /// 転送済み（無効）
    Transferred,
}

impl<T: Sized + Send> Transferable<T> {
    /// 新しいTransferableを作成
    pub fn new(data: T, owner: DomainId) -> Self {
        Self {
            data,
            owner,
            state: TransferState::Owned,
        }
    }

    /// 転送を開始
    pub fn begin_transfer(
        &mut self,
        current_domain: DomainId,
        target: DomainId,
    ) -> Result<OwnershipToken<T>, OwnershipError> {
        // 所有者チェック
        if self.owner != current_domain {
            return Err(OwnershipError::NotOwner);
        }

        // 状態チェック
        if self.state != TransferState::Owned {
            return Err(OwnershipError::AlreadyTransferred);
        }

        // 転送状態に移行
        self.state = TransferState::InTransfer;

        let address = &self.data as *const T as usize;
        let size = core::mem::size_of::<T>();

        Ok(OwnershipToken::new(current_domain, target, address, size))
    }

    /// 転送を完了（受信側）
    pub fn complete_transfer(&mut self, _token: OwnershipToken<T>, new_owner: DomainId) {
        self.owner = new_owner;
        self.state = TransferState::Owned;
    }

    /// データへの参照を取得（所有者のみ）
    pub fn get(&self, accessor: DomainId) -> Result<&T, OwnershipError> {
        if self.owner != accessor {
            return Err(OwnershipError::NotOwner);
        }
        if self.state != TransferState::Owned {
            return Err(OwnershipError::AlreadyTransferred);
        }
        Ok(&self.data)
    }

    /// データへの可変参照を取得（所有者のみ）
    pub fn get_mut(&mut self, accessor: DomainId) -> Result<&mut T, OwnershipError> {
        if self.owner != accessor {
            return Err(OwnershipError::NotOwner);
        }
        if self.state != TransferState::Owned {
            return Err(OwnershipError::AlreadyTransferred);
        }
        Ok(&mut self.data)
    }

    /// 所有者を取得
    pub fn owner(&self) -> DomainId {
        self.owner
    }

    /// 状態を取得
    pub fn state(&self) -> TransferState {
        self.state
    }
}

/// ゼロコピー転送用のポインタラッパー
///
/// 実際のデータをムーブせずに、ポインタの所有権のみを転送する。
pub struct ZeroCopyTransfer<T: Sized + Send> {
    /// データへのポインタ
    ptr: *mut T,
    /// サイズ
    size: usize,
    /// 元の所有者
    original_owner: DomainId,
    /// 現在の所有者
    current_owner: DomainId,
    /// 有効フラグ
    valid: bool,
}

impl<T: Sized + Send> ZeroCopyTransfer<T> {
    /// 既存のポインタから作成
    ///
    /// # Safety
    /// - ptrは有効なT型データを指している必要がある
    /// - 呼び出し元がメモリの所有権を持っている必要がある
    pub unsafe fn from_ptr(ptr: *mut T, owner: DomainId) -> Self {
        Self {
            ptr,
            size: core::mem::size_of::<T>(),
            original_owner: owner,
            current_owner: owner,
            valid: true,
        }
    }

    /// 所有権を転送
    pub fn transfer(&mut self, from: DomainId, to: DomainId) -> Result<(), OwnershipError> {
        if !self.valid {
            return Err(OwnershipError::AlreadyTransferred);
        }
        if self.current_owner != from {
            return Err(OwnershipError::NotOwner);
        }

        self.current_owner = to;
        Ok(())
    }

    /// ポインタを取得（所有者のみ）
    pub fn as_ptr(&self, accessor: DomainId) -> Result<*const T, OwnershipError> {
        if !self.valid {
            return Err(OwnershipError::AlreadyTransferred);
        }
        if self.current_owner != accessor {
            return Err(OwnershipError::NotOwner);
        }
        Ok(self.ptr as *const T)
    }

    /// 可変ポインタを取得（所有者のみ）
    pub fn as_mut_ptr(&mut self, accessor: DomainId) -> Result<*mut T, OwnershipError> {
        if !self.valid {
            return Err(OwnershipError::AlreadyTransferred);
        }
        if self.current_owner != accessor {
            return Err(OwnershipError::NotOwner);
        }
        Ok(self.ptr)
    }

    /// 転送を無効化
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// アドレスを取得
    pub fn address(&self) -> usize {
        self.ptr as usize
    }

    /// サイズを取得
    pub fn size(&self) -> usize {
        self.size
    }
}

// Send/Sync実装
unsafe impl<T: Sized + Send> Send for ZeroCopyTransfer<T> {}
// Note: Syncは実装しない - 並行アクセスは所有権チェックで防止
