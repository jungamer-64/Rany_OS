//! 共有メモリ (Shared Memory) - ゼロコピープロセス間通信
//!
//! ExoRust SAS (Single Address Space) アーキテクチャにおける
//! 高速プロセス間通信の実装

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// 共有メモリID (Newtype)
mod shm_info;
pub use shm_info::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ShmId(u64);

impl ShmId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// 共有メモリキー (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ShmKey(i32);

impl ShmKey {
    pub const IPC_PRIVATE: Self = Self(0);

    pub const fn new(key: i32) -> Self {
        Self(key)
    }

    pub const fn as_i32(&self) -> i32 {
        self.0
    }
}

/// 共有メモリサイズ (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmSize(usize);

impl ShmSize {
    /// Page size constant (re-exported from mm/types)
    pub const PAGE_SIZE: usize = crate::mm::types::PAGE_SIZE_4K;

    pub const fn new(size: usize) -> Self {
        Self(size)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }

    /// ページ境界に切り上げ
    pub fn page_aligned(&self) -> Self {
        let pages = (self.0 + Self::PAGE_SIZE - 1) / Self::PAGE_SIZE;
        Self(pages * Self::PAGE_SIZE)
    }
}

/// 共有メモリ権限
#[derive(Debug, Clone, Copy)]
pub struct ShmPermissions {
    /// 読み取り可能
    pub read: bool,
    /// 書き込み可能
    pub write: bool,
    /// 実行可能 (通常は無効)
    pub execute: bool,
    /// モード (Unix風権限ビット)
    pub mode: u16,
}

impl Default for ShmPermissions {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            mode: 0o600, // owner r/w
        }
    }
}

impl ShmPermissions {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
        mode: 0o400,
    };

    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
        mode: 0o600,
    };
}

/// 共有メモリフラグ
#[derive(Debug, Clone, Copy)]
pub struct ShmFlags {
    /// 存在しない場合は作成
    pub create: bool,
    /// 存在する場合はエラー
    pub exclusive: bool,
    /// 削除マーク
    pub remove_on_last_detach: bool,
    /// Huge Page使用
    pub huge_pages: bool,
    /// ロック (スワップアウト禁止)
    pub locked: bool,
}

impl Default for ShmFlags {
    fn default() -> Self {
        Self {
            create: false,
            exclusive: false,
            remove_on_last_detach: false,
            huge_pages: false,
            locked: false,
        }
    }
}

/// 共有メモリエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmError {
    /// 存在しない
    NotFound,
    /// すでに存在する
    AlreadyExists,
    /// 権限エラー
    PermissionDenied,
    /// サイズエラー
    InvalidSize,
    /// メモリ不足
    OutOfMemory,
    /// 無効なアドレス
    InvalidAddress,
    /// アタッチ済み
    AlreadyAttached,
    /// デタッチエラー
    NotAttached,
    /// 使用中
    InUse,
    /// 無効なID
    InvalidId,
    /// システムリソース不足
    NoResources,
}

/// 共有メモリ統計
#[derive(Debug)]
pub struct ShmStats {
    /// 現在のアタッチ数
    pub attach_count: AtomicUsize,
    /// 総アタッチ回数
    pub total_attaches: AtomicU64,
    /// 総デタッチ回数
    pub total_detaches: AtomicU64,
    /// 作成時刻
    pub created_at: u64,
    /// 最終アクセス時刻
    pub last_access: AtomicU64,
    /// 最終変更時刻
    pub last_modify: AtomicU64,
}

impl ShmStats {
    pub fn new() -> Self {
        let now = crate::time::current_time_ns();
        Self {
            attach_count: AtomicUsize::new(0),
            total_attaches: AtomicU64::new(0),
            total_detaches: AtomicU64::new(0),
            created_at: now,
            last_access: AtomicU64::new(now),
            last_modify: AtomicU64::new(now),
        }
    }
}

/// 共有メモリ領域
pub struct SharedMemoryRegion {
    /// ID
    id: ShmId,
    /// キー
    key: ShmKey,
    /// サイズ
    size: ShmSize,
    /// 実際のメモリ
    memory: Vec<u8>,
    /// 権限
    permissions: ShmPermissions,
    /// フラグ
    flags: ShmFlags,
    /// 統計
    stats: ShmStats,
    /// 削除マーク
    marked_for_removal: AtomicBool,
    /// 名前 (オプション)
    name: Option<String>,
}

impl SharedMemoryRegion {
    /// 新しい共有メモリ領域を作成
    pub fn new(
        id: ShmId,
        key: ShmKey,
        size: ShmSize,
        permissions: ShmPermissions,
        flags: ShmFlags,
    ) -> Result<Self, ShmError> {
        let aligned_size = size.page_aligned();

        let mut memory = Vec::new();
        memory
            .try_reserve(aligned_size.as_usize())
            .map_err(|_| ShmError::OutOfMemory)?;
        memory.resize(aligned_size.as_usize(), 0);

        Ok(Self {
            id,
            key,
            size: aligned_size,
            memory,
            permissions,
            flags,
            stats: ShmStats::new(),
            marked_for_removal: AtomicBool::new(false),
            name: None,
        })
    }

    /// 名前付きで作成
    pub fn with_name(
        id: ShmId,
        name: &str,
        size: ShmSize,
        permissions: ShmPermissions,
        flags: ShmFlags,
    ) -> Result<Self, ShmError> {
        let mut region = Self::new(id, ShmKey::IPC_PRIVATE, size, permissions, flags)?;
        region.name = Some(String::from(name));
        Ok(region)
    }

    /// IDを取得
    pub fn id(&self) -> ShmId {
        self.id
    }

    /// キーを取得
    pub fn key(&self) -> ShmKey {
        self.key
    }

    /// サイズを取得
    pub fn size(&self) -> ShmSize {
        self.size
    }

    /// 名前を取得
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// メモリのポインタを取得 (読み取り)
    pub fn as_ptr(&self) -> *const u8 {
        self.memory.as_ptr()
    }

    /// メモリのポインタを取得 (読み書き)
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.memory.as_mut_ptr()
    }

    /// スライスとして取得
    pub fn as_slice(&self) -> &[u8] {
        &self.memory
    }

    /// ミュータブルスライスとして取得
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.memory
    }

    /// 現在のアタッチ数
    pub fn attach_count(&self) -> usize {
        self.stats.attach_count.load(Ordering::Acquire)
    }

    /// アタッチ
    fn attach(&self) -> Result<(), ShmError> {
        self.stats.attach_count.fetch_add(1, Ordering::AcqRel);
        self.stats.total_attaches.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// デタッチ
    fn detach(&self) -> Result<bool, ShmError> {
        let prev = self.stats.attach_count.fetch_sub(1, Ordering::AcqRel);
        self.stats.total_detaches.fetch_add(1, Ordering::Relaxed);

        // 最後のデタッチで削除マークがあれば削除可能
        if prev == 1 && self.marked_for_removal.load(Ordering::Acquire) {
            return Ok(true); // 削除可能
        }
        Ok(false)
    }

    /// 削除マークを設定
    pub fn mark_for_removal(&self) {
        self.marked_for_removal.store(true, Ordering::Release);
    }

    /// 削除可能かどうか
    pub fn can_be_removed(&self) -> bool {
        self.marked_for_removal.load(Ordering::Acquire) && self.attach_count() == 0
    }
}

/// 共有メモリハンドル (アタッチ済み)
pub struct ShmHandle {
    region: Arc<spin::RwLock<SharedMemoryRegion>>,
    base_addr: usize,
    attached: AtomicBool,
    /// Optional capability token associated with this handle (in-flight accounting)
    token: Option<u64>,
}

impl ShmHandle {
    /// 新しいハンドルを作成 (トークンなし)
    fn new(region: Arc<spin::RwLock<SharedMemoryRegion>>) -> Result<Self, ShmError> {
        Self::new_with_token(region, None)
    }

    /// 新しいハンドルを作成し、オプションのトークンを関連付ける。
    /// トークンが指定された場合、in-flight カウンタをインクリメントし、
    /// 失敗したらエラーを返す。
    fn new_with_token(
        region: Arc<spin::RwLock<SharedMemoryRegion>>,
        token: Option<u64>,
    ) -> Result<Self, ShmError> {
        // If a token is provided, attempt to increment in-flight. On failure, deny.
        if let Some(t) = token {
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(ShmError::PermissionDenied);
            }
        }

        // Attach to the region; if attach fails, roll back in-flight increment.
        let base_addr = {
            let r = region.read();
            if let Err(e) = r.attach() {
                if let Some(t) = token {
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                return Err(e);
            }
            r.as_ptr() as usize
        };

        Ok(Self {
            region,
            base_addr,
            attached: AtomicBool::new(true),
            token,
        })
    }

    /// ベースアドレスを取得
    pub fn base_addr(&self) -> usize {
        self.base_addr
    }

    /// サイズを取得
    pub fn size(&self) -> usize {
        self.region.read().size().as_usize()
    }

    /// 読み取り用スライスを取得
    pub fn read(&self) -> Option<&[u8]> {
        if !self.attached.load(Ordering::Acquire) {
            return None;
        }
        // Safety: アタッチ中はメモリは有効
        unsafe {
            let ptr = self.base_addr as *const u8;
            let size = self.size();
            Some(crate::util::raw_ptr_as_slice(ptr, size))
        }
    }

    /// 書き込み用スライスを取得
    pub fn write(&self) -> Option<&mut [u8]> {
        if !self.attached.load(Ordering::Acquire) {
            return None;
        }
        // Safety: アタッチ中はメモリは有効
        unsafe {
            let ptr = self.base_addr as *mut u8;
            let size = self.size();
            Some(crate::util::raw_ptr_as_slice_mut(ptr, size))
        }
    }

    /// 指定オフセットに書き込み
    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), ShmError> {
        let mem = self.write().ok_or(ShmError::NotAttached)?;

        if offset + data.len() > mem.len() {
            return Err(ShmError::InvalidAddress);
        }

        mem[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// 指定オフセットから読み取り
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, ShmError> {
        let mem = self.read().ok_or(ShmError::NotAttached)?;

        if offset >= mem.len() {
            return Err(ShmError::InvalidAddress);
        }

        let to_read = buf.len().min(mem.len() - offset);
        buf[..to_read].copy_from_slice(&mem[offset..offset + to_read]);
        Ok(to_read)
    }

    /// デタッチ
    pub fn detach(&self) -> Result<(), ShmError> {
        if !self.attached.swap(false, Ordering::AcqRel) {
            return Err(ShmError::NotAttached);
        }

        let r = self.region.read();
        r.detach()?;

        // If a token was associated with this handle, decrement its in-flight counter.
        if let Some(t) = self.token {
            let _ = crate::security::capability::manager().decrement_in_flight(t);
        }

        Ok(())
    }

    /// アタッチ済みかどうか
    pub fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire)
    }
}

impl Drop for ShmHandle {
    fn drop(&mut self) {
        if self.attached.load(Ordering::Acquire) {
            let _ = self.detach();
        }
    }
}

/// 共有メモリマネージャー
pub struct SharedMemoryManager {
    /// 次のID
    next_id: AtomicU64,
    /// ID別の領域
    regions_by_id: spin::RwLock<BTreeMap<ShmId, Arc<spin::RwLock<SharedMemoryRegion>>>>,
    /// キー別の領域
    regions_by_key: spin::RwLock<BTreeMap<ShmKey, ShmId>>,
    /// 名前別の領域
    regions_by_name: spin::RwLock<BTreeMap<String, ShmId>>,
    /// 統計
    total_created: AtomicU64,
    total_destroyed: AtomicU64,
    total_bytes: AtomicUsize,
}

impl SharedMemoryManager {
    /// 新しいマネージャーを作成
    pub const fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            regions_by_id: spin::RwLock::new(BTreeMap::new()),
            regions_by_key: spin::RwLock::new(BTreeMap::new()),
            regions_by_name: spin::RwLock::new(BTreeMap::new()),
            total_created: AtomicU64::new(0),
            total_destroyed: AtomicU64::new(0),
            total_bytes: AtomicUsize::new(0),
        }
    }

    /// 新しいIDを生成
    fn generate_id(&self) -> ShmId {
        ShmId::new(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// 共有メモリを作成
    pub fn create(
        &self,
        key: ShmKey,
        size: ShmSize,
        permissions: ShmPermissions,
        flags: ShmFlags,
    ) -> Result<ShmId, ShmError> {
        // キーが既に存在するかチェック
        if key != ShmKey::IPC_PRIVATE {
            let key_map = self.regions_by_key.read();
            if key_map.contains_key(&key) {
                if flags.exclusive {
                    return Err(ShmError::AlreadyExists);
                }
                // contains_key() で確認済みなので get() は必ず Some
                // get() の結果を安全に unwrap します
                return Ok(*key_map.get(&key).unwrap());
            }
        }

        let id = self.generate_id();
        let region = SharedMemoryRegion::new(id, key, size, permissions, flags)?;
        let region_size = region.size().as_usize();
        let region = Arc::new(spin::RwLock::new(region));

        // 登録
        {
            let mut id_map = self.regions_by_id.write();
            id_map.insert(id, region);
        }

        if key != ShmKey::IPC_PRIVATE {
            let mut key_map = self.regions_by_key.write();
            key_map.insert(key, id);
        }

        self.total_created.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(region_size, Ordering::Relaxed);

        Ok(id)
    }

    /// 名前付き共有メモリを作成
    pub fn create_named(
        &self,
        name: &str,
        size: ShmSize,
        permissions: ShmPermissions,
        flags: ShmFlags,
    ) -> Result<ShmId, ShmError> {
        // 名前が既に存在するかチェック
        {
            let name_map = self.regions_by_name.read();
            if name_map.contains_key(name) {
                if flags.exclusive {
                    return Err(ShmError::AlreadyExists);
                }
                // get() の結果を安全に unwrap します
                return Ok(*name_map.get(name).unwrap());
            }
        }

        let id = self.generate_id();
        let region = SharedMemoryRegion::with_name(id, name, size, permissions, flags)?;
        let region_size = region.size().as_usize();
        let region = Arc::new(spin::RwLock::new(region));

        // 登録
        {
            let mut id_map = self.regions_by_id.write();
            id_map.insert(id, region);
        }

        {
            let mut name_map = self.regions_by_name.write();
            name_map.insert(String::from(name), id);
        }

        self.total_created.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(region_size, Ordering::Relaxed);

        Ok(id)
    }

    /// 共有メモリを取得 (キーで)
    pub fn get_by_key(&self, key: ShmKey) -> Option<ShmId> {
        let key_map = self.regions_by_key.read();
        key_map.get(&key).copied()
    }

    /// 共有メモリを取得 (名前で)
    pub fn get_by_name(&self, name: &str) -> Option<ShmId> {
        let name_map = self.regions_by_name.read();
        name_map.get(name).copied()
    }

    /// 共有メモリにアタッチ (従来互換: トークンなし)
    pub fn attach(&self, id: ShmId) -> Result<ShmHandle, ShmError> {
        self.attach_with_token(id, None)
    }

    /// 共有メモリにアタッチし、オプションでトークンを紐付ける。
    /// トークンが与えられた場合、in-flight カウンタがインクリメントされる。
    pub fn attach_with_token(&self, id: ShmId, token: Option<u64>) -> Result<ShmHandle, ShmError> {
        let id_map = self.regions_by_id.read();
        let region = id_map.get(&id).ok_or(ShmError::NotFound)?;
        ShmHandle::new_with_token(region.clone(), token)
    }

    /// 共有メモリを削除
    pub fn remove(&self, id: ShmId) -> Result<(), ShmError> {
        let region = {
            let id_map = self.regions_by_id.read();
            id_map.get(&id).cloned().ok_or(ShmError::NotFound)?
        };

        // 削除マークを設定
        {
            let r = region.read();
            r.mark_for_removal();

            // アタッチがある場合は実際の削除を延期
            if r.attach_count() > 0 {
                return Ok(());
            }
        }

        // 実際の削除
        self.do_remove(id, &region)
    }

    /// 実際の削除処理
    fn do_remove(
        &self,
        id: ShmId,
        region: &Arc<spin::RwLock<SharedMemoryRegion>>,
    ) -> Result<(), ShmError> {
        let (key, name, size) = {
            let r = region.read();
            (r.key(), r.name().map(String::from), r.size())
        };

        // マップから削除
        {
            let mut id_map = self.regions_by_id.write();
            id_map.remove(&id);
        }

        if key != ShmKey::IPC_PRIVATE {
            let mut key_map = self.regions_by_key.write();
            key_map.remove(&key);
        }

        if let Some(n) = name {
            let mut name_map = self.regions_by_name.write();
            name_map.remove(&n);
        }

        self.total_destroyed.fetch_add(1, Ordering::Relaxed);
        self.total_bytes
            .fetch_sub(size.as_usize(), Ordering::Relaxed);

        Ok(())
    }

    /// 情報を取得
    pub fn info(&self, id: ShmId) -> Option<ShmInfo> {
        let id_map = self.regions_by_id.read();
        let region = id_map.get(&id)?;
        let r = region.read();

        Some(ShmInfo {
            id,
            key: r.key(),
            size: r.size(),
            attach_count: r.attach_count(),
            permissions: r.permissions,
            name: r.name().map(String::from),
        })
    }

    /// 統計を取得
    pub fn stats(&self) -> ShmManagerStats {
        ShmManagerStats {
            total_created: self.total_created.load(Ordering::Relaxed),
            total_destroyed: self.total_destroyed.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            active_regions: self.regions_by_id.read().len(),
        }
    }
}
