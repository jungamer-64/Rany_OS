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
use super::types::{MappedAddress, MappingOffset, MappingSize};

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

    /// 物理メモリを割り当てて仮想アドレスにマップ (SAS統合版)
    ///
    /// Buddy Allocatorから物理フレームを割り当て、ページテーブルにマップする。
    /// これにより、mmap()が実際のページテーブル操作と統合される。
    pub fn mmap_with_physical_alloc(
        &self,
        addr: Option<MappedAddress>,
        size: MappingSize,
        protection: Protection,
        flags: MappingFlags,
    ) -> Result<MappedAddress, MmapError> {
        use crate::mm::{PageFlags, alloc_frame};
        use x86_64::PhysAddr;

        if size.as_usize() == 0 {
            return Err(MmapError::InvalidSize);
        }

        let address = if let Some(a) = addr {
            if flags.fixed && !a.is_page_aligned() {
                return Err(MmapError::AlignmentError);
            }
            if flags.fixed {
                a
            } else {
                self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
            }
        } else {
            self.find_free_address(size).ok_or(MmapError::OutOfMemory)?
        };

        let aligned_size = size.page_aligned();
        let page_count = aligned_size.page_count();

        // ページテーブルフラグを設定
        let mut pt_flags = PageFlags::new(PageFlags::PRESENT);
        if protection.can_write() {
            pt_flags = pt_flags.set(PageFlags::WRITABLE);
        }
        if !protection.can_exec() {
            pt_flags = pt_flags.set(PageFlags::NO_EXECUTE);
        }
        // ユーザー空間のマッピングの場合
        if address.as_usize() < crate::mm::higher_half::VirtAddr::KERNEL_BASE as usize {
            pt_flags = pt_flags.set(PageFlags::USER);
        }

        // 各ページに物理フレームを割り当ててマップ
        let mut allocated_frames = Vec::new();
        for i in 0..page_count {
            let frame = alloc_frame().ok_or(MmapError::OutOfMemory)?;
            let phys_addr = PhysAddr::new(frame.start_address().as_u64());
            let virt_addr = crate::mm::higher_half::VirtAddr::new(
                (address.as_usize() + i * MappingSize::PAGE_SIZE) as u64,
            );

            // ページテーブルにマップ
            let map_result = unsafe {
                crate::mm::global_map_page(
                    virt_addr,
                    crate::mm::higher_half::PhysAddr::new(phys_addr.as_u64()),
                    pt_flags,
                )
            };

            if map_result.is_err() {
                // 失敗した場合、これまでに割り当てたフレームを解放
                for prev_frame in allocated_frames {
                    crate::mm::dealloc_frame(prev_frame);
                }
                return Err(MmapError::NoResources);
            }

            allocated_frames.push(frame);

            // ゼロ初期化（フラグが設定されている場合）
            if flags.zero_init {
                unsafe {
                    let ptr = virt_addr.as_u64() as *mut u8;
                    core::ptr::write_bytes(ptr, 0, MappingSize::PAGE_SIZE);
                }
            }
        }

        // 内部マッピング情報を作成（物理フレームはページテーブルで管理）
        let mapping = MemoryMapping::anonymous(address, size, protection, flags)?;
        let mapping_size = mapping.size().as_usize();

        {
            let mut mappings = self.mappings.write();
            mappings.insert(address.as_usize(), Arc::new(spin::RwLock::new(mapping)));
        }

        self.total_mapped.fetch_add(mapping_size, Ordering::Relaxed);
        Ok(address)
    }

    /// SASリニアマッピング領域から仮想アドレスを取得
    ///
    /// 物理アドレスを直接マップしている領域（Higher Half）の仮想アドレスを返す。
    /// これはゼロコピー操作に最適。
    pub fn get_sas_linear_mapping(&self, phys_addr: u64, size: usize) -> Option<MappedAddress> {
        // SAS: 物理メモリは physical_memory_offset + phys_addr でアクセス可能
        let offset = crate::mm::mapping::physical_memory_offset();
        let virt_addr = offset + phys_addr;

        // 範囲チェック
        if size == 0 {
            return None;
        }

        Some(MappedAddress::new(virt_addr as usize))
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

    /// マッピングを解除し、物理フレームも解放する（SAS統合版）
    ///
    /// `mmap_with_physical_alloc`で作成したマッピングを解除する際に使用。
    /// ページテーブルのマッピングを解除し、物理フレームをBuddy Allocatorに返却する。
    pub fn munmap_with_physical_dealloc(
        &self,
        addr: MappedAddress,
        size: MappingSize,
    ) -> Result<(), MmapError> {
        use x86_64::structures::paging::PageSize;

        // マッピング情報を取得・削除
        let mapping = {
            let mut mappings = self.mappings.write();
            mappings
                .remove(&addr.as_usize())
                .ok_or(MmapError::NotMapped)?
        };

        let mapping_guard = mapping.read();
        let aligned_size = size.page_aligned();
        let page_count = aligned_size.page_count();

        // 各ページをアンマップして物理フレームを解放
        for i in 0..page_count {
            let virt_addr = crate::mm::higher_half::VirtAddr::new(
                (addr.as_usize() + i * MappingSize::PAGE_SIZE) as u64,
            );

            // ページテーブルから仮想アドレスを物理アドレスに変換
            if let Some(phys_addr) = crate::mm::global_translate(virt_addr) {
                // ページテーブルからアンマップ
                let _ = unsafe { crate::mm::global_unmap_page(virt_addr) };

                // 物理フレームをPMMに返却
                let frame = x86_64::structures::paging::PhysFrame::<
                    x86_64::structures::paging::Size4KiB,
                >::containing_address(x86_64::PhysAddr::new(
                    phys_addr.as_u64(),
                ));
                crate::mm::dealloc_frame(frame);
            }
        }

        let mapping_size = mapping_guard.size().as_usize();
        drop(mapping_guard);

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
