// ============================================================================
// src/sas/heap_registry.rs - ヒープオブジェクト所有権レジストリ
// ============================================================================
//! SAS環境でのメモリ保護を実現するため、ヒープオブジェクトの所有者を追跡する。
//! コンパイラベースの保護と実行時チェックを組み合わせて安全性を確保。
#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::domain_system::DomainId;

/// ヒープオブジェクトのメタデータ
#[derive(Debug, Clone)]
pub struct HeapObject {
    /// オブジェクトの開始アドレス
    pub address: usize,
    /// オブジェクトのサイズ
    pub size: usize,
    /// 所有者のドメインID
    pub owner: DomainId,
    /// 型識別子（型安全な転送のため）
    pub type_id: u64,
    /// アロケーション世代（UAF検出用）
    pub generation: u64,
    /// 参照カウント
    pub ref_count: u32,
}

/// ヒープレジストリ
/// 
/// 全てのヒープオブジェクトの所有権を追跡し、
/// SAS環境でのメモリ安全性を保証する。
pub struct HeapRegistry {
    /// アドレス → オブジェクトのマッピング
    objects: BTreeMap<usize, HeapObject>,
    /// ドメイン → 所有オブジェクトアドレスのマッピング
    owner_index: BTreeMap<DomainId, Vec<usize>>,
    /// 次のオブジェクト世代
    next_generation: AtomicU64,
    /// 統計情報
    stats: RegistryStats,
}

/// レジストリ統計
#[derive(Debug, Default)]
struct RegistryStats {
    total_registered: u64,
    total_transferred: u64,
    total_freed: u64,
    access_checks: u64,
    access_denials: u64,
}

impl HeapRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            owner_index: BTreeMap::new(),
            next_generation: AtomicU64::new(1),
            stats: RegistryStats {
                total_registered: 0,
                total_transferred: 0,
                total_freed: 0,
                access_checks: 0,
                access_denials: 0,
            },
        }
    }
    
    /// オブジェクトを登録
    pub fn register(
        &mut self,
        address: usize,
        size: usize,
        owner: DomainId,
        type_id: u64,
    ) -> Result<u64, RegistryError> {
        // 重複チェック
        if self.objects.contains_key(&address) {
            return Err(RegistryError::AlreadyRegistered);
        }
        
        // 重なり検出
        if self.check_overlap(address, size) {
            return Err(RegistryError::Overlapping);
        }
        
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        
        let object = HeapObject {
            address,
            size,
            owner,
            type_id,
            generation,
            ref_count: 1,
        };
        
        self.objects.insert(address, object);
        
        // オーナーインデックスを更新
        self.owner_index
            .entry(owner)
            .or_insert_with(Vec::new)
            .push(address);
        
        self.stats.total_registered += 1;
        
        Ok(generation)
    }
    
    /// オブジェクトの登録を解除
    pub fn unregister(&mut self, address: usize, owner: DomainId) -> Result<(), RegistryError> {
        // オブジェクトを検索
        let object = self.objects.get(&address)
            .ok_or(RegistryError::NotFound)?;
        
        // 所有者チェック
        if object.owner != owner {
            return Err(RegistryError::PermissionDenied);
        }
        
        // 参照カウントチェック
        if object.ref_count > 1 {
            return Err(RegistryError::StillReferenced);
        }
        
        // 削除
        self.objects.remove(&address);
        
        // オーナーインデックスから削除
        if let Some(addrs) = self.owner_index.get_mut(&owner) {
            addrs.retain(|&a| a != address);
        }
        
        self.stats.total_freed += 1;
        
        Ok(())
    }
    
    /// 所有権を転送
    pub fn transfer_ownership(
        &mut self,
        address: usize,
        from: DomainId,
        to: DomainId,
    ) -> Result<(), RegistryError> {
        // オブジェクトを検索
        let object = self.objects.get_mut(&address)
            .ok_or(RegistryError::NotFound)?;
        
        // 所有者チェック
        if object.owner != from {
            return Err(RegistryError::PermissionDenied);
        }
        
        // 参照カウントチェック（転送は唯一の参照時のみ）
        if object.ref_count != 1 {
            return Err(RegistryError::StillReferenced);
        }
        
        // 所有者を更新
        object.owner = to;
        
        // インデックスを更新
        if let Some(addrs) = self.owner_index.get_mut(&from) {
            addrs.retain(|&a| a != address);
        }
        self.owner_index
            .entry(to)
            .or_insert_with(Vec::new)
            .push(address);
        
        self.stats.total_transferred += 1;
        
        Ok(())
    }
    
    /// アクセス権をチェック
    pub fn check_access(&mut self, address: usize, accessor: DomainId) -> bool {
        self.stats.access_checks += 1;
        
        // 直接マッチを試行
        if let Some(object) = self.objects.get(&address) {
            return object.owner == accessor;
        }
        
        // 範囲検索（アドレスがオブジェクト内にあるか）
        for (_, object) in self.objects.range(..=address).rev().take(1) {
            if address < object.address + object.size {
                if object.owner == accessor {
                    return true;
                }
            }
        }
        
        self.stats.access_denials += 1;
        false
    }
    
    /// オブジェクト情報を取得
    pub fn get_object(&self, address: usize) -> Option<&HeapObject> {
        self.objects.get(&address)
    }
    
    /// ドメインの全オブジェクトを取得
    pub fn get_domain_objects(&self, domain: DomainId) -> Option<&Vec<usize>> {
        self.owner_index.get(&domain)
    }
    
    /// 参照カウントを増加
    pub fn add_ref(&mut self, address: usize) -> Result<(), RegistryError> {
        let object = self.objects.get_mut(&address)
            .ok_or(RegistryError::NotFound)?;
        object.ref_count = object.ref_count.checked_add(1)
            .ok_or(RegistryError::RefCountOverflow)?;
        Ok(())
    }
    
    /// 参照カウントを減少
    pub fn release_ref(&mut self, address: usize) -> Result<u32, RegistryError> {
        let object = self.objects.get_mut(&address)
            .ok_or(RegistryError::NotFound)?;
        object.ref_count = object.ref_count.checked_sub(1)
            .ok_or(RegistryError::RefCountUnderflow)?;
        Ok(object.ref_count)
    }
    
    /// 重なりをチェック
    fn check_overlap(&self, address: usize, size: usize) -> bool {
        // 前後の範囲をチェック
        let end = address + size;
        
        for (_, obj) in self.objects.range(..end) {
            let obj_end = obj.address + obj.size;
            if obj.address < end && address < obj_end {
                return true;
            }
        }
        
        false
    }
    
    // ========================================================================
    // SAS Manager用の追加メソッド
    // ========================================================================
    
    /// 所有者を変更（SAS Manager用簡易版）
    pub fn change_owner(
        &mut self, 
        ptr: usize, 
        from: DomainId, 
        to: DomainId
    ) -> Result<(), super::OwnershipError> {
        self.transfer_ownership(ptr, from, to)
            .map_err(|e| match e {
                RegistryError::NotFound => super::OwnershipError::NotRegistered,
                RegistryError::PermissionDenied => super::OwnershipError::NotOwner,
                _ => super::OwnershipError::AlreadyTransferred,
            })
    }
    
    /// 所有者を取得
    pub fn get_owner(&self, ptr: usize) -> Option<DomainId> {
        // 直接マッチ
        if let Some(obj) = self.objects.get(&ptr) {
            return Some(obj.owner);
        }
        
        // 範囲検索
        for (_, object) in self.objects.range(..=ptr).rev().take(1) {
            if ptr < object.address + object.size {
                return Some(object.owner);
            }
        }
        
        None
    }
    
    /// オブジェクトを登録（簡易版、type_id = 0）
    pub fn register_simple(&mut self, ptr: usize, size: usize, owner: DomainId) {
        let _ = self.register(ptr, size, owner, 0);
    }
    
    /// ドメインの全オブジェクトを回収
    pub fn reclaim_all(&mut self, domain: DomainId) -> usize {
        let addrs: Vec<usize> = self.owner_index
            .remove(&domain)
            .unwrap_or_default();
        
        let count = addrs.len();
        
        for addr in addrs {
            self.objects.remove(&addr);
            self.stats.total_freed += 1;
        }
        
        count
    }
    
    /// 登録オブジェクト数を取得
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
}

/// レジストリエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// 既に登録済み
    AlreadyRegistered,
    /// 見つからない
    NotFound,
    /// 権限なし
    PermissionDenied,
    /// まだ参照されている
    StillReferenced,
    /// 領域が重なっている
    Overlapping,
    /// 参照カウントオーバーフロー
    RefCountOverflow,
    /// 参照カウントアンダーフロー
    RefCountUnderflow,
}
