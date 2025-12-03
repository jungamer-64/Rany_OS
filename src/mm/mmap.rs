//! メモリマップ (mmap) - メモリマップドI/O
//!
//! ExoRust SAS アーキテクチャにおけるメモリマッピング
//! ファイルやデバイスを直接メモリにマップ

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// マッピングアドレス (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MappedAddress(usize);

impl MappedAddress {
    pub const NULL: Self = Self(0);

    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }

    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// ページアライメントされているか
    pub fn is_page_aligned(&self) -> bool {
        self.0 % MappingSize::PAGE_SIZE == 0
    }
}

/// マッピングサイズ (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingSize(usize);

impl MappingSize {
    pub const PAGE_SIZE: usize = 4096;
    pub const HUGE_PAGE_2M: usize = 2 * 1024 * 1024;
    pub const HUGE_PAGE_1G: usize = 1024 * 1024 * 1024;

    pub const fn new(size: usize) -> Self {
        Self(size)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }

    /// ページ数を計算
    pub fn page_count(&self) -> usize {
        (self.0 + Self::PAGE_SIZE - 1) / Self::PAGE_SIZE
    }

    /// ページ境界に切り上げ
    pub fn page_aligned(&self) -> Self {
        Self(self.page_count() * Self::PAGE_SIZE)
    }
}

/// マッピングオフセット (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingOffset(u64);

impl MappingOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// ページアライメントされているか
    pub fn is_page_aligned(&self) -> bool {
        self.0 as usize % MappingSize::PAGE_SIZE == 0
    }
}

/// メモリ保護フラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection {
    bits: u32,
}

impl Protection {
    pub const NONE: Self = Self { bits: 0 };
    pub const READ: Self = Self { bits: 1 };
    pub const WRITE: Self = Self { bits: 2 };
    pub const EXEC: Self = Self { bits: 4 };

    pub const READ_WRITE: Self = Self { bits: 1 | 2 };
    pub const READ_EXEC: Self = Self { bits: 1 | 4 };
    pub const READ_WRITE_EXEC: Self = Self { bits: 1 | 2 | 4 };

    pub const fn new(bits: u32) -> Self {
        Self { bits }
    }

    pub fn can_read(&self) -> bool {
        (self.bits & 1) != 0
    }

    pub fn can_write(&self) -> bool {
        (self.bits & 2) != 0
    }

    pub fn can_exec(&self) -> bool {
        (self.bits & 4) != 0
    }

    pub fn union(&self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}

/// マッピングフラグ
#[derive(Debug, Clone, Copy)]
pub struct MappingFlags {
    /// 共有マッピング
    pub shared: bool,
    /// プライベートマッピング (COW)
    pub private: bool,
    /// 固定アドレス
    pub fixed: bool,
    /// 匿名マッピング
    pub anonymous: bool,
    /// スタック
    pub stack: bool,
    /// ロック (スワップ禁止)
    pub locked: bool,
    /// Huge Pages
    pub huge_pages: bool,
    /// 予約のみ (物理メモリ割り当てなし)
    pub no_reserve: bool,
    /// ゼロ初期化
    pub zero_init: bool,
}

impl Default for MappingFlags {
    fn default() -> Self {
        Self {
            shared: false,
            private: true,
            fixed: false,
            anonymous: false,
            stack: false,
            locked: false,
            huge_pages: false,
            no_reserve: false,
            zero_init: true,
        }
    }
}

impl MappingFlags {
    /// 匿名プライベートマッピング
    pub fn anonymous_private() -> Self {
        Self {
            anonymous: true,
            private: true,
            ..Default::default()
        }
    }

    /// 共有マッピング
    pub fn shared_mapping() -> Self {
        Self {
            shared: true,
            private: false,
            ..Default::default()
        }
    }
}

/// マッピングエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmapError {
    /// 無効なアドレス
    InvalidAddress,
    /// 無効なサイズ
    InvalidSize,
    /// 無効なオフセット
    InvalidOffset,
    /// メモリ不足
    OutOfMemory,
    /// 領域が重複
    Overlapping,
    /// 権限エラー
    PermissionDenied,
    /// アライメントエラー
    AlignmentError,
    /// ファイルが見つからない
    FileNotFound,
    /// マッピングが見つからない
    NotMapped,
    /// サポートされていない操作
    NotSupported,
    /// リソース不足
    NoResources,
}

/// マッピングタイプ
#[derive(Debug, Clone)]
pub enum MappingType {
    /// 匿名マッピング
    Anonymous,
    /// ファイルマッピング
    File {
        /// ファイルパス (またはFD)
        path: alloc::string::String,
        /// ファイル内オフセット
        offset: MappingOffset,
    },
    /// デバイスマッピング
    Device {
        /// デバイス名
        device: alloc::string::String,
        /// 物理アドレス
        phys_addr: usize,
    },
    /// 共有メモリマッピング
    SharedMemory {
        /// 共有メモリID
        shm_id: u64,
    },
}

/// メモリマッピング
pub struct MemoryMapping {
    /// 開始アドレス
    address: MappedAddress,
    /// サイズ
    size: MappingSize,
    /// 保護
    protection: Protection,
    /// フラグ
    flags: MappingFlags,
    /// タイプ
    mapping_type: MappingType,
    /// 実際のメモリ (匿名マッピングの場合)
    memory: Option<Vec<u8>>,
    /// 参照カウント
    ref_count: AtomicUsize,
    /// アクセスカウント
    access_count: AtomicU64,
    /// ダーティフラグ
    dirty: AtomicBool,
}

impl MemoryMapping {
    /// 新しい匿名マッピングを作成
    pub fn anonymous(
        address: MappedAddress,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
    ) -> Result<Self, MmapError> {
        let aligned_size = size.page_aligned();

        let mut memory = Vec::new();
        memory
            .try_reserve(aligned_size.as_usize())
            .map_err(|_| MmapError::OutOfMemory)?;

        if flags.zero_init {
            memory.resize(aligned_size.as_usize(), 0);
        } else {
            unsafe {
                memory.set_len(aligned_size.as_usize());
            }
        }

        Ok(Self {
            address,
            size: aligned_size,
            protection,
            flags,
            mapping_type: MappingType::Anonymous,
            memory: Some(memory),
            ref_count: AtomicUsize::new(1),
            access_count: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        })
    }

    /// ファイルマッピングを作成
    pub fn file(
        address: MappedAddress,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
        path: &str,
        offset: MappingOffset,
    ) -> Result<Self, MmapError> {
        if !offset.is_page_aligned() {
            return Err(MmapError::AlignmentError);
        }

        let aligned_size = size.page_aligned();

        // TODO: 実際のファイル読み込み
        let mut memory = Vec::new();
        memory
            .try_reserve(aligned_size.as_usize())
            .map_err(|_| MmapError::OutOfMemory)?;
        memory.resize(aligned_size.as_usize(), 0);

        Ok(Self {
            address,
            size: aligned_size,
            protection,
            flags,
            mapping_type: MappingType::File {
                path: alloc::string::String::from(path),
                offset,
            },
            memory: Some(memory),
            ref_count: AtomicUsize::new(1),
            access_count: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        })
    }

    /// デバイスマッピングを作成
    pub fn device(
        address: MappedAddress,
        size: MappingSize,
        protection: Protection,
        device: &str,
        phys_addr: usize,
    ) -> Result<Self, MmapError> {
        Ok(Self {
            address,
            size: size.page_aligned(),
            protection,
            flags: MappingFlags {
                shared: true,
                private: false,
                locked: true, // デバイスメモリはロック
                ..Default::default()
            },
            mapping_type: MappingType::Device {
                device: alloc::string::String::from(device),
                phys_addr,
            },
            memory: None, // デバイスメモリは直接アクセス
            ref_count: AtomicUsize::new(1),
            access_count: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        })
    }

    /// アドレスを取得
    pub fn address(&self) -> MappedAddress {
        self.address
    }

    /// サイズを取得
    pub fn size(&self) -> MappingSize {
        self.size
    }

    /// 終了アドレスを取得
    pub fn end_address(&self) -> MappedAddress {
        MappedAddress::new(self.address.as_usize() + self.size.as_usize())
    }

    /// アドレスが範囲内かチェック
    pub fn contains(&self, addr: MappedAddress) -> bool {
        addr.as_usize() >= self.address.as_usize()
            && addr.as_usize() < self.end_address().as_usize()
    }

    /// 保護を取得
    pub fn protection(&self) -> Protection {
        self.protection
    }

    /// 保護を変更
    pub fn set_protection(&mut self, prot: Protection) -> Result<(), MmapError> {
        // W^X チェック
        if prot.can_write() && prot.can_exec() {
            return Err(MmapError::PermissionDenied);
        }
        self.protection = prot;
        Ok(())
    }

    /// メモリスライスを取得 (読み取り)
    pub fn as_slice(&self) -> Option<&[u8]> {
        self.memory.as_ref().map(|m| m.as_slice())
    }

    /// メモリスライスを取得 (書き込み)
    pub fn as_mut_slice(&mut self) -> Option<&mut [u8]> {
        self.dirty.store(true, Ordering::Release);
        self.memory.as_mut().map(|m| m.as_mut_slice())
    }

    /// 指定オフセットを読み取り
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, MmapError> {
        if !self.protection.can_read() {
            return Err(MmapError::PermissionDenied);
        }

        let mem = self.memory.as_ref().ok_or(MmapError::NotSupported)?;

        if offset >= mem.len() {
            return Ok(0);
        }

        let to_read = buf.len().min(mem.len() - offset);
        buf[..to_read].copy_from_slice(&mem[offset..offset + to_read]);

        self.access_count.fetch_add(1, Ordering::Relaxed);
        Ok(to_read)
    }

    /// 指定オフセットに書き込み
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize, MmapError> {
        if !self.protection.can_write() {
            return Err(MmapError::PermissionDenied);
        }

        let mem = self.memory.as_mut().ok_or(MmapError::NotSupported)?;

        if offset >= mem.len() {
            return Ok(0);
        }

        let to_write = data.len().min(mem.len() - offset);
        mem[offset..offset + to_write].copy_from_slice(&data[..to_write]);

        self.dirty.store(true, Ordering::Release);
        self.access_count.fetch_add(1, Ordering::Relaxed);
        Ok(to_write)
    }

    /// ダーティかどうか
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// ダーティフラグをクリア
    pub fn clear_dirty(&self) {
        self.dirty.store(false, Ordering::Release);
    }

    /// 同期 (ファイルマッピングの場合)
    pub fn sync(&mut self) -> Result<(), MmapError> {
        if !self.is_dirty() {
            return Ok(());
        }

        match &self.mapping_type {
            MappingType::File { path: _, offset: _ } => {
                // TODO: ファイルに書き戻し
                self.clear_dirty();
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// マッピング情報
#[derive(Debug)]
pub struct MappingInfo {
    pub address: MappedAddress,
    pub size: MappingSize,
    pub protection: Protection,
    pub is_shared: bool,
    pub is_anonymous: bool,
    pub is_dirty: bool,
}

/// メモリマップマネージャー
pub struct MmapManager {
    /// マッピング (アドレス順)
    mappings: spin::RwLock<BTreeMap<usize, Arc<spin::RwLock<MemoryMapping>>>>,
    /// 次の空きアドレス
    next_addr: AtomicUsize,
    /// ベースアドレス
    base_addr: usize,
    /// 最大アドレス
    max_addr: usize,
    /// 統計
    total_mapped: AtomicUsize,
    total_unmapped: AtomicUsize,
}

impl MmapManager {
    /// デフォルトのマッピング領域
    pub const DEFAULT_BASE: usize = 0x0000_7000_0000_0000;
    pub const DEFAULT_MAX: usize = 0x0000_7fff_ffff_ffff;

    pub const fn new() -> Self {
        Self {
            mappings: spin::RwLock::new(BTreeMap::new()),
            next_addr: AtomicUsize::new(Self::DEFAULT_BASE),
            base_addr: Self::DEFAULT_BASE,
            max_addr: Self::DEFAULT_MAX,
            total_mapped: AtomicUsize::new(0),
            total_unmapped: AtomicUsize::new(0),
        }
    }

    /// 空きアドレスを探す
    fn find_free_address(&self, size: MappingSize) -> Option<MappedAddress> {
        let aligned_size = size.page_aligned().as_usize();
        let mappings = self.mappings.read();

        let mut current = self.next_addr.load(Ordering::Acquire);

        loop {
            if current + aligned_size > self.max_addr {
                return None;
            }

            // 既存のマッピングと重複チェック
            let overlaps = mappings.iter().any(|(_addr, mapping)| {
                let m = mapping.read();
                let m_start = m.address().as_usize();
                let m_end = m.end_address().as_usize();

                // 重複チェック
                !(current + aligned_size <= m_start || current >= m_end)
            });

            if !overlaps {
                // 次回のための更新
                self.next_addr
                    .store(current + aligned_size, Ordering::Release);
                return Some(MappedAddress::new(current));
            }

            // 次の候補
            current += MappingSize::PAGE_SIZE;
        }
    }

    /// 匿名マッピングを作成
    pub fn mmap_anonymous(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
    ) -> Result<MappedAddress, MmapError> {
        if size.as_usize() == 0 {
            return Err(MmapError::InvalidSize);
        }

        let address = if let Some(a) = addr {
            if flags.fixed {
                if !a.is_page_aligned() {
                    return Err(MmapError::AlignmentError);
                }
                a
            } else {
                self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
            }
        } else {
            self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
        };

        let mapping = MemoryMapping::anonymous(address, size, protection, flags)?;
        let mapping_size = mapping.size().as_usize();

        {
            let mut mappings = self.mappings.write();
            mappings.insert(address.as_usize(), Arc::new(spin::RwLock::new(mapping)));
        }

        self.total_mapped.fetch_add(mapping_size, Ordering::Relaxed);
        Ok(address)
    }

    /// ファイルマッピングを作成
    pub fn mmap_file(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
        path: &str,
        offset: MappingOffset,
    ) -> Result<MappedAddress, MmapError> {
        if size.as_usize() == 0 {
            return Err(MmapError::InvalidSize);
        }

        let address = if let Some(a) = addr {
            if flags.fixed {
                if !a.is_page_aligned() {
                    return Err(MmapError::AlignmentError);
                }
                a
            } else {
                self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
            }
        } else {
            self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
        };

        let mapping = MemoryMapping::file(address, size, protection, flags, path, offset)?;
        let mapping_size = mapping.size().as_usize();

        {
            let mut mappings = self.mappings.write();
            mappings.insert(address.as_usize(), Arc::new(spin::RwLock::new(mapping)));
        }

        self.total_mapped.fetch_add(mapping_size, Ordering::Relaxed);
        Ok(address)
    }

    /// マッピングを解除
    pub fn munmap(&self, addr: MappedAddress, _size: MappingSize) -> Result<(), MmapError> {
        let mut mappings = self.mappings.write();

        // 該当するマッピングを探す
        let mapping = mappings
            .remove(&addr.as_usize())
            .ok_or(MmapError::NotMapped)?;

        let mapping_size = mapping.read().size().as_usize();
        self.total_unmapped
            .fetch_add(mapping_size, Ordering::Relaxed);

        Ok(())
    }

    /// 保護を変更
    pub fn mprotect(
        &self,
        addr: MappedAddress,
        _size: MappingSize,
        protection: Protection,
    ) -> Result<(), MmapError> {
        let mappings = self.mappings.read();

        let mapping = mappings.get(&addr.as_usize()).ok_or(MmapError::NotMapped)?;

        let mut m = mapping.write();
        m.set_protection(protection)
    }

    /// 同期
    pub fn msync(&self, addr: MappedAddress, _size: MappingSize) -> Result<(), MmapError> {
        let mappings = self.mappings.read();

        let mapping = mappings.get(&addr.as_usize()).ok_or(MmapError::NotMapped)?;

        let mut m = mapping.write();
        m.sync()
    }

    /// マッピングを取得
    pub fn get_mapping(&self, addr: MappedAddress) -> Option<Arc<spin::RwLock<MemoryMapping>>> {
        let mappings = self.mappings.read();

        // 完全一致
        if let Some(m) = mappings.get(&addr.as_usize()) {
            return Some(m.clone());
        }

        // 範囲内のマッピングを探す
        for (_, mapping) in mappings.iter() {
            let m = mapping.read();
            if m.contains(addr) {
                return Some(mapping.clone());
            }
        }

        None
    }

    /// マッピング情報を取得
    pub fn info(&self, addr: MappedAddress) -> Option<MappingInfo> {
        let mapping = self.get_mapping(addr)?;
        let m = mapping.read();

        Some(MappingInfo {
            address: m.address(),
            size: m.size(),
            protection: m.protection(),
            is_shared: m.flags.shared,
            is_anonymous: matches!(m.mapping_type, MappingType::Anonymous),
            is_dirty: m.is_dirty(),
        })
    }

    /// 全マッピング情報を取得
    pub fn list_mappings(&self) -> Vec<MappingInfo> {
        let mappings = self.mappings.read();
        let mut result = Vec::new();

        for (_, mapping) in mappings.iter() {
            let m = mapping.read();
            result.push(MappingInfo {
                address: m.address(),
                size: m.size(),
                protection: m.protection(),
                is_shared: m.flags.shared,
                is_anonymous: matches!(m.mapping_type, MappingType::Anonymous),
                is_dirty: m.is_dirty(),
            });
        }

        result
    }

    /// 統計を取得
    pub fn stats(&self) -> MmapStats {
        MmapStats {
            total_mapped: self.total_mapped.load(Ordering::Relaxed),
            total_unmapped: self.total_unmapped.load(Ordering::Relaxed),
            active_mappings: self.mappings.read().len(),
        }
    }
}

/// mmap統計
#[derive(Debug)]
pub struct MmapStats {
    pub total_mapped: usize,
    pub total_unmapped: usize,
    pub active_mappings: usize,
}

/// グローバルmmapマネージャー
static MMAP_MANAGER: MmapManager = MmapManager::new();

/// mmapマネージャーを取得
pub fn mmap_manager() -> &'static MmapManager {
    &MMAP_MANAGER
}

// --- POSIX風 API ---

/// mmap() 相当
pub fn mmap(
    addr: Option<MappedAddress>,
    size: MappingSize,
    protection: Protection,
    flags: MappingFlags,
) -> Result<MappedAddress, MmapError> {
    MMAP_MANAGER.mmap_anonymous(addr, size, protection, flags)
}

/// mmap() ファイル版
pub fn mmap_file(
    addr: Option<MappedAddress>,
    size: MappingSize,
    protection: Protection,
    flags: MappingFlags,
    path: &str,
    offset: MappingOffset,
) -> Result<MappedAddress, MmapError> {
    MMAP_MANAGER.mmap_file(addr, size, protection, flags, path, offset)
}

/// munmap() 相当
pub fn munmap(addr: MappedAddress, size: MappingSize) -> Result<(), MmapError> {
    MMAP_MANAGER.munmap(addr, size)
}

/// mprotect() 相当
pub fn mprotect(
    addr: MappedAddress,
    size: MappingSize,
    protection: Protection,
) -> Result<(), MmapError> {
    MMAP_MANAGER.mprotect(addr, size, protection)
}

/// msync() 相当
pub fn msync(addr: MappedAddress, size: MappingSize) -> Result<(), MmapError> {
    MMAP_MANAGER.msync(addr, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymous_mmap() {
        let addr = mmap(
            None,
            MappingSize::new(4096),
            Protection::READ_WRITE,
            MappingFlags::anonymous_private(),
        )
        .unwrap();

        assert!(addr.is_page_aligned());

        munmap(addr, MappingSize::new(4096)).unwrap();
    }

    #[test]
    fn test_mapping_read_write() {
        let addr = mmap(
            None,
            MappingSize::new(8192),
            Protection::READ_WRITE,
            MappingFlags::anonymous_private(),
        )
        .unwrap();

        let mapping = MMAP_MANAGER.get_mapping(addr).unwrap();
        {
            let mut m = mapping.write();
            m.write(0, b"Hello, mmap!").unwrap();
        }

        {
            let m = mapping.read();
            let mut buf = [0u8; 12];
            m.read(0, &mut buf).unwrap();
            assert_eq!(&buf, b"Hello, mmap!");
        }
    }
}
