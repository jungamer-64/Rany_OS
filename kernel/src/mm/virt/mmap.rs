//! メモリマップ (mmap) - メモリマップドI/O
//!
//! ExoRust SAS アーキテクチャにおけるメモリマッピング
//! ファイルやデバイスを直接メモリにマップ

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use super::address_space::Protection;
use crate::mm::types::{MappedAddress, MappingOffset, MappingSize};

/// マッピングフラグ
mod api;
pub use api::*;
mod manager_impl;
pub use manager_impl::*;
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

        // メモリを確保
        let mut memory = Vec::new();
        memory
            .try_reserve(aligned_size.as_usize())
            .map_err(|_| MmapError::OutOfMemory)?;
        memory.resize(aligned_size.as_usize(), 0);

        // ファイルからデータを読み込み
        match crate::fs::memfs::read_file_content(path, "/") {
            Ok(file_data) => {
                let file_offset = offset.as_usize();
                if file_offset < file_data.len() {
                    let copy_len =
                        core::cmp::min(file_data.len() - file_offset, aligned_size.as_usize());
                    memory[..copy_len]
                        .copy_from_slice(&file_data[file_offset..file_offset + copy_len]);
                }
            }
            Err(_) => {
                // ファイルが見つからない場合はゼロ初期化のままにする
                // (MAP_ANONYMOUS的な動作)
            }
        }

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
            MappingType::File { path, offset } => {
                // ファイルに書き戻し
                if let Some(ref memory) = self.memory {
                    let file_offset = offset.as_usize();
                    // ファイルへ書き込み
                    // 注: offsetを考慮した部分書き込みは将来対応
                    if file_offset == 0 {
                        let _ = crate::fs::memfs::write_file_content(path, "/", memory);
                    }
                }
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
