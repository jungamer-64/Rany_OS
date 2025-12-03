// ============================================================================
// src/fs/ext2.rs - Ext2 Filesystem Implementation
// ============================================================================
//!
//! # Ext2ファイルシステム
//!
//! Linux ext2形式のファイルシステム実装。
//!
//! ## 機能
//! - スーパーブロック解析
//! - ブロックグループ管理
//! - inode読み取り
//! - ディレクトリ/ファイル操作

#![allow(dead_code)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use super::block::BlockDevice;
use super::vfs::{
    DirEntry, FileAttr, FileMode, FileSystem, FileType, FsError, FsResult, FsStats, Inode,
    InodeNum, OpenFlags,
};

// ============================================================================
// Ext2 Constants
// ============================================================================

/// 基本ブロックサイズ（バイト）
const BASE_BLOCK_SIZE: usize = 512;

/// Ext2マジックナンバー
const EXT2_MAGIC: u16 = 0xEF53;

/// スーパーブロックのオフセット（バイト）
const SUPERBLOCK_OFFSET: u64 = 1024;

/// ルートディレクトリのinode番号
const ROOT_INODE: u32 = 2;

/// ファイルタイプマスク
const S_IFMT: u16 = 0xF000;
/// 通常ファイル
const S_IFREG: u16 = 0x8000;
/// ディレクトリ
const S_IFDIR: u16 = 0x4000;
/// キャラクタデバイス
const S_IFCHR: u16 = 0x2000;
/// ブロックデバイス
const S_IFBLK: u16 = 0x6000;
/// FIFO
const S_IFIFO: u16 = 0x1000;
/// ソケット
const S_IFSOCK: u16 = 0xC000;
/// シンボリックリンク
const S_IFLNK: u16 = 0xA000;

/// 直接ブロック数
const DIRECT_BLOCKS: usize = 12;
/// 間接ブロックインデックス
const INDIRECT_BLOCK: usize = 12;
/// 二重間接ブロックインデックス
const DOUBLE_INDIRECT_BLOCK: usize = 13;
/// 三重間接ブロックインデックス
const TRIPLE_INDIRECT_BLOCK: usize = 14;

// ============================================================================
// Superblock
// ============================================================================

/// Ext2スーパーブロック
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Superblock {
    /// inode総数
    pub inodes_count: u32,
    /// ブロック総数
    pub blocks_count: u32,
    /// 予約ブロック数
    pub reserved_blocks_count: u32,
    /// 空きブロック数
    pub free_blocks_count: u32,
    /// 空きinode数
    pub free_inodes_count: u32,
    /// 最初のデータブロック
    pub first_data_block: u32,
    /// ブロックサイズ（log2 - 10）
    pub log_block_size: u32,
    /// フラグメントサイズ（log2 - 10）
    pub log_frag_size: u32,
    /// グループあたりのブロック数
    pub blocks_per_group: u32,
    /// グループあたりのフラグメント数
    pub frags_per_group: u32,
    /// グループあたりのinode数
    pub inodes_per_group: u32,
    /// 最終マウント時刻
    pub mtime: u32,
    /// 最終書き込み時刻
    pub wtime: u32,
    /// マウント回数
    pub mnt_count: u16,
    /// 最大マウント回数
    pub max_mnt_count: u16,
    /// マジックナンバー
    pub magic: u16,
    /// ファイルシステム状態
    pub state: u16,
    /// エラー時の動作
    pub errors: u16,
    /// マイナーリビジョン
    pub minor_rev_level: u16,
    /// 最終チェック時刻
    pub lastcheck: u32,
    /// チェック間隔
    pub checkinterval: u32,
    /// 作成OS
    pub creator_os: u32,
    /// リビジョンレベル
    pub rev_level: u32,
    /// デフォルトUID（予約ブロック用）
    pub def_resuid: u16,
    /// デフォルトGID（予約ブロック用）
    pub def_resgid: u16,
    // EXT2_DYNAMIC_REV 用の拡張フィールド
    /// 最初の非予約inode
    pub first_ino: u32,
    /// inodeサイズ
    pub inode_size: u16,
    /// このスーパーブロックのグループ番号
    pub block_group_nr: u16,
    /// 互換機能フラグ
    pub feature_compat: u32,
    /// 非互換機能フラグ
    pub feature_incompat: u32,
    /// 読み取り専用互換機能フラグ
    pub feature_ro_compat: u32,
    /// UUID
    pub uuid: [u8; 16],
    /// ボリューム名
    pub volume_name: [u8; 16],
    /// 最終マウントパス
    pub last_mounted: [u8; 64],
    /// 圧縮アルゴリズム
    pub algo_bitmap: u32,
    /// プリアロケートブロック数（ファイル）
    pub prealloc_blocks: u8,
    /// プリアロケートブロック数（ディレクトリ）
    pub prealloc_dir_blocks: u8,
    /// パディング
    _padding: u16,
    /// ジャーナルUUID
    pub journal_uuid: [u8; 16],
    /// ジャーナルinode
    pub journal_inum: u32,
    /// ジャーナルデバイス
    pub journal_dev: u32,
    /// 孤児inodeリストの先頭
    pub last_orphan: u32,
    /// HTREEハッシュシード
    pub hash_seed: [u32; 4],
    /// デフォルトハッシュバージョン
    pub def_hash_version: u8,
    /// パディング
    _reserved: [u8; 3],
    /// デフォルトマウントオプション
    pub default_mount_options: u32,
    /// 最初のメタブロックグループ
    pub first_meta_bg: u32,
}

impl Superblock {
    /// ブロックサイズを取得（バイト）
    pub fn block_size(&self) -> u32 {
        1024 << self.log_block_size
    }

    /// ブロックグループ数を計算
    pub fn block_group_count(&self) -> u32 {
        (self.blocks_count + self.blocks_per_group - 1) / self.blocks_per_group
    }

    /// inodeサイズを取得
    pub fn inode_size(&self) -> u32 {
        if self.rev_level >= 1 {
            self.inode_size as u32
        } else {
            128
        }
    }
}

// ============================================================================
// Block Group Descriptor
// ============================================================================

/// ブロックグループ記述子
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BlockGroupDescriptor {
    /// ブロックビットマップのブロック番号
    pub block_bitmap: u32,
    /// inodeビットマップのブロック番号
    pub inode_bitmap: u32,
    /// inodeテーブルの開始ブロック番号
    pub inode_table: u32,
    /// 空きブロック数
    pub free_blocks_count: u16,
    /// 空きinode数
    pub free_inodes_count: u16,
    /// ディレクトリ数
    pub used_dirs_count: u16,
    /// パディング
    pub pad: u16,
    /// 予約
    pub reserved: [u8; 12],
}

// ============================================================================
// Inode
// ============================================================================

/// Ext2 inode
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext2Inode {
    /// ファイルモード
    pub mode: u16,
    /// 所有者UID
    pub uid: u16,
    /// ファイルサイズ（下位32ビット）
    pub size: u32,
    /// 最終アクセス時刻
    pub atime: u32,
    /// 作成時刻
    pub ctime: u32,
    /// 最終変更時刻
    pub mtime: u32,
    /// 削除時刻
    pub dtime: u32,
    /// 所有者GID
    pub gid: u16,
    /// リンク数
    pub links_count: u16,
    /// 512バイトブロック数
    pub blocks: u32,
    /// フラグ
    pub flags: u32,
    /// OS固有値1
    pub osd1: u32,
    /// ブロックポインタ
    pub block: [u32; 15],
    /// ファイルバージョン
    pub generation: u32,
    /// ファイルACL
    pub file_acl: u32,
    /// ディレクトリACL / サイズ上位32ビット
    pub dir_acl: u32,
    /// フラグメントアドレス
    pub faddr: u32,
    /// OS固有値2
    pub osd2: [u8; 12],
}

impl Ext2Inode {
    /// ファイルタイプを取得
    pub fn file_type(&self) -> FileType {
        match self.mode & S_IFMT {
            S_IFREG => FileType::Regular,
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            S_IFCHR => FileType::CharDevice,
            S_IFBLK => FileType::BlockDevice,
            S_IFIFO => FileType::Fifo,
            S_IFSOCK => FileType::Socket,
            _ => FileType::Regular,
        }
    }

    /// ファイルサイズを取得
    pub fn file_size(&self) -> u64 {
        // 通常ファイルの場合、dir_aclは上位32ビット
        if self.file_type() == FileType::Regular {
            ((self.dir_acl as u64) << 32) | (self.size as u64)
        } else {
            self.size as u64
        }
    }

    /// ディレクトリかどうか
    pub fn is_directory(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

/// Ext2ディレクトリエントリ
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext2DirEntry {
    /// inode番号
    pub inode: u32,
    /// エントリサイズ
    pub rec_len: u16,
    /// 名前の長さ
    pub name_len: u8,
    /// ファイルタイプ（ext2 rev >= 0.5）
    pub file_type: u8,
    // 名前がここに続く（可変長）
}

/// ディレクトリエントリのファイルタイプ
const EXT2_FT_UNKNOWN: u8 = 0;
const EXT2_FT_REG_FILE: u8 = 1;
const EXT2_FT_DIR: u8 = 2;
const EXT2_FT_CHRDEV: u8 = 3;
const EXT2_FT_BLKDEV: u8 = 4;
const EXT2_FT_FIFO: u8 = 5;
const EXT2_FT_SOCK: u8 = 6;
const EXT2_FT_SYMLINK: u8 = 7;

impl Ext2DirEntry {
    /// ファイルタイプを取得
    pub fn get_file_type(&self) -> FileType {
        match self.file_type {
            EXT2_FT_REG_FILE => FileType::Regular,
            EXT2_FT_DIR => FileType::Directory,
            EXT2_FT_SYMLINK => FileType::Symlink,
            EXT2_FT_CHRDEV => FileType::CharDevice,
            EXT2_FT_BLKDEV => FileType::BlockDevice,
            EXT2_FT_FIFO => FileType::Fifo,
            EXT2_FT_SOCK => FileType::Socket,
            _ => FileType::Regular,
        }
    }
}

// ============================================================================
// Ext2 Filesystem
// ============================================================================

/// Ext2ファイルシステム
pub struct Ext2FileSystem {
    /// ブロックデバイス
    device: Arc<dyn BlockDevice>,
    /// スーパーブロック
    superblock: Superblock,
    /// ブロックグループ記述子
    block_groups: Vec<BlockGroupDescriptor>,
    /// ブロックサイズ
    block_size: u32,
}

impl Ext2FileSystem {
    /// Ext2ファイルシステムをマウント
    pub fn mount(device: Arc<dyn BlockDevice>) -> FsResult<Arc<Self>> {
        // スーパーブロックを読み取り（オフセット1024バイト）
        // 512バイトセクタでセクタ2から読み取り
        let mut buffer = [0u8; BASE_BLOCK_SIZE];
        device
            .read_sync(2, &mut buffer) // セクタ2 = オフセット1024
            .map_err(|_| FsError::IoError)?;

        let superblock: Superblock =
            unsafe { core::ptr::read(buffer.as_ptr() as *const Superblock) };

        // マジックナンバーを確認
        if superblock.magic != EXT2_MAGIC {
            return Err(FsError::InvalidArgument);
        }

        let block_size = superblock.block_size();
        let bg_count = superblock.block_group_count();

        // ブロックグループ記述子を読み取り
        let bgdt_block = if block_size == 1024 { 2 } else { 1 };
        let bgdt_size = (bg_count as usize) * mem::size_of::<BlockGroupDescriptor>();
        let bgdt_blocks = (bgdt_size + block_size as usize - 1) / block_size as usize;

        let mut block_groups = Vec::with_capacity(bg_count as usize);
        let mut bgdt_buffer = vec![0u8; bgdt_blocks * block_size as usize];

        // 512バイトセクタ単位で読み取り
        let sectors_per_fs_block = block_size as u64 / BASE_BLOCK_SIZE as u64;
        for i in 0..bgdt_blocks {
            let start_sector =
                bgdt_block as u64 * sectors_per_fs_block + i as u64 * sectors_per_fs_block;
            for j in 0..sectors_per_fs_block as usize {
                device
                    .read_sync(start_sector + j as u64, &mut buffer)
                    .map_err(|_| FsError::IoError)?;
                let offset = i * block_size as usize + j * BASE_BLOCK_SIZE;
                let end = offset + BASE_BLOCK_SIZE;
                if end <= bgdt_buffer.len() {
                    bgdt_buffer[offset..end].copy_from_slice(&buffer);
                }
            }
        }

        for i in 0..bg_count as usize {
            let offset = i * mem::size_of::<BlockGroupDescriptor>();
            let bgd: BlockGroupDescriptor = unsafe {
                core::ptr::read(bgdt_buffer[offset..].as_ptr() as *const BlockGroupDescriptor)
            };
            block_groups.push(bgd);
        }

        Ok(Arc::new(Self {
            device,
            superblock,
            block_groups,
            block_size,
        }))
    }

    /// inodeを読み取り
    pub fn read_inode(&self, inode_num: u32) -> FsResult<Ext2Inode> {
        if inode_num == 0 || inode_num > self.superblock.inodes_count {
            return Err(FsError::InvalidArgument);
        }

        let group = (inode_num - 1) / self.superblock.inodes_per_group;
        let index = (inode_num - 1) % self.superblock.inodes_per_group;

        let bgd = &self.block_groups[group as usize];
        let inode_size = self.superblock.inode_size();
        let inodes_per_block = self.block_size / inode_size;

        let block = bgd.inode_table + index / inodes_per_block;
        let offset = (index % inodes_per_block) * inode_size;

        // ブロックを読み取り
        let mut buffer = vec![0u8; self.block_size as usize];
        self.read_block(block, &mut buffer)?;

        let inode: Ext2Inode =
            unsafe { core::ptr::read(buffer[offset as usize..].as_ptr() as *const Ext2Inode) };

        Ok(inode)
    }

    /// ブロックを読み取り
    fn read_block(&self, block_num: u32, buffer: &mut [u8]) -> FsResult<()> {
        let sectors_per_block = self.block_size as u64 / BASE_BLOCK_SIZE as u64;
        let start_sector = block_num as u64 * sectors_per_block;

        let mut temp = [0u8; BASE_BLOCK_SIZE];
        for i in 0..sectors_per_block as usize {
            self.device
                .read_sync(start_sector + i as u64, &mut temp)
                .map_err(|_| FsError::IoError)?;
            let offset = i * BASE_BLOCK_SIZE;
            let end = offset + BASE_BLOCK_SIZE;
            if end <= buffer.len() {
                buffer[offset..end].copy_from_slice(&temp);
            }
        }

        Ok(())
    }

    /// データブロック番号を取得（論理→物理）
    fn get_block_num(&self, inode: &Ext2Inode, logical_block: u32) -> FsResult<u32> {
        let ptrs_per_block = self.block_size / 4;

        if logical_block < DIRECT_BLOCKS as u32 {
            // 直接ブロック
            return Ok(inode.block[logical_block as usize]);
        }

        let logical_block = logical_block - DIRECT_BLOCKS as u32;

        if logical_block < ptrs_per_block {
            // 間接ブロック
            let indirect_block = inode.block[INDIRECT_BLOCK];
            if indirect_block == 0 {
                return Ok(0);
            }

            let mut buffer = vec![0u8; self.block_size as usize];
            self.read_block(indirect_block, &mut buffer)?;

            let ptr_offset = (logical_block * 4) as usize;
            let block_num = u32::from_le_bytes([
                buffer[ptr_offset],
                buffer[ptr_offset + 1],
                buffer[ptr_offset + 2],
                buffer[ptr_offset + 3],
            ]);

            return Ok(block_num);
        }

        let logical_block = logical_block - ptrs_per_block;

        if logical_block < ptrs_per_block * ptrs_per_block {
            // 二重間接ブロック
            let double_indirect_block = inode.block[DOUBLE_INDIRECT_BLOCK];
            if double_indirect_block == 0 {
                return Ok(0);
            }

            let mut buffer = vec![0u8; self.block_size as usize];
            self.read_block(double_indirect_block, &mut buffer)?;

            let first_index = logical_block / ptrs_per_block;
            let second_index = logical_block % ptrs_per_block;

            let ptr_offset = (first_index * 4) as usize;
            let indirect_block = u32::from_le_bytes([
                buffer[ptr_offset],
                buffer[ptr_offset + 1],
                buffer[ptr_offset + 2],
                buffer[ptr_offset + 3],
            ]);

            if indirect_block == 0 {
                return Ok(0);
            }

            self.read_block(indirect_block, &mut buffer)?;

            let ptr_offset = (second_index * 4) as usize;
            let block_num = u32::from_le_bytes([
                buffer[ptr_offset],
                buffer[ptr_offset + 1],
                buffer[ptr_offset + 2],
                buffer[ptr_offset + 3],
            ]);

            return Ok(block_num);
        }

        // 三重間接ブロック（非常に大きなファイル用）
        Err(FsError::NotSupported)
    }
}

impl FileSystem for Ext2FileSystem {
    fn name(&self) -> &str {
        "ext2"
    }

    fn root(&self) -> FsResult<Arc<dyn Inode>> {
        let inode = self.read_inode(ROOT_INODE)?;
        Ok(Arc::new(Ext2InodeWrapper {
            fs: Arc::new(self.clone()),
            inode_num: ROOT_INODE,
            inode,
        }))
    }

    fn statfs(&self) -> FsResult<FsStats> {
        Ok(FsStats {
            blocks: self.superblock.blocks_count as u64,
            bfree: self.superblock.free_blocks_count as u64,
            bavail: self.superblock.free_blocks_count as u64
                - self.superblock.reserved_blocks_count as u64,
            files: self.superblock.inodes_count as u64,
            ffree: self.superblock.free_inodes_count as u64,
            bsize: self.block_size,
            namelen: 255,
            frsize: self.block_size,
        })
    }

    fn sync(&self) -> FsResult<()> {
        // TODO: キャッシュをフラッシュ
        Ok(())
    }

    fn unmount(&self) -> FsResult<()> {
        self.sync()
    }
}

impl Clone for Ext2FileSystem {
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            superblock: self.superblock,
            block_groups: self.block_groups.clone(),
            block_size: self.block_size,
        }
    }
}

// ============================================================================
// Ext2 Inode Wrapper
// ============================================================================

/// Ext2 inodeのラッパー
pub struct Ext2InodeWrapper {
    fs: Arc<Ext2FileSystem>,
    inode_num: u32,
    inode: Ext2Inode,
}

impl Ext2InodeWrapper {
    /// ディレクトリエントリを読み取り
    fn read_dir_entries(&self) -> FsResult<Vec<(String, u32, FileType)>> {
        if !self.inode.is_directory() {
            return Err(FsError::NotDirectory);
        }

        let mut entries = Vec::new();
        let mut offset = 0u64;
        let size = self.inode.file_size();
        let block_size = self.fs.block_size as u64;

        while offset < size {
            let logical_block = (offset / block_size) as u32;
            let block_offset = (offset % block_size) as usize;

            let physical_block = self.fs.get_block_num(&self.inode, logical_block)?;
            if physical_block == 0 {
                break;
            }

            let mut buffer = vec![0u8; self.fs.block_size as usize];
            self.fs.read_block(physical_block, &mut buffer)?;

            let mut pos = block_offset;
            while pos < buffer.len() && (offset + (pos - block_offset) as u64) < size {
                let entry: Ext2DirEntry =
                    unsafe { core::ptr::read(buffer[pos..].as_ptr() as *const Ext2DirEntry) };

                if entry.inode != 0 && entry.rec_len > 0 {
                    let name_start = pos + 8;
                    let name_end = name_start + entry.name_len as usize;

                    if name_end <= buffer.len() {
                        let name =
                            String::from_utf8_lossy(&buffer[name_start..name_end]).into_owned();

                        if name != "." && name != ".." {
                            entries.push((name, entry.inode, entry.get_file_type()));
                        }
                    }
                }

                if entry.rec_len == 0 {
                    break;
                }

                pos += entry.rec_len as usize;
            }

            offset = (logical_block as u64 + 1) * block_size;
        }

        Ok(entries)
    }
}

impl Inode for Ext2InodeWrapper {
    fn getattr(&self) -> FsResult<FileAttr> {
        Ok(FileAttr {
            ino: self.inode_num as InodeNum,
            size: self.inode.file_size(),
            blocks: self.inode.blocks as u64,
            file_type: self.inode.file_type(),
            mode: FileMode(self.inode.mode & 0x0FFF),
            nlink: self.inode.links_count as u32,
            uid: self.inode.uid as u32,
            gid: self.inode.gid as u32,
            rdev: 0,
            blksize: self.fs.block_size,
            atime: self.inode.atime as u64 * 1_000_000_000,
            mtime: self.inode.mtime as u64 * 1_000_000_000,
            ctime: self.inode.ctime as u64 * 1_000_000_000,
        })
    }

    fn setattr(&self, _attr: &FileAttr) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        let entries = self.read_dir_entries()?;

        for (entry_name, inode_num, _) in entries {
            if entry_name == name {
                let inode = self.fs.read_inode(inode_num)?;
                return Ok(Arc::new(Ext2InodeWrapper {
                    fs: self.fs.clone(),
                    inode_num,
                    inode,
                }));
            }
        }

        Err(FsError::NotFound)
    }

    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        let entries = self.read_dir_entries()?;

        Ok(entries
            .into_iter()
            .map(|(name, ino, file_type)| DirEntry {
                name,
                ino: ino as InodeNum,
                file_type,
            })
            .collect())
    }

    fn create(&self, _name: &str, _mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn mkdir(&self, _name: &str, _mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn unlink(&self, _name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn rmdir(&self, _name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn rename(&self, _old_name: &str, _new_dir: &Arc<dyn Inode>, _new_name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn symlink(&self, _name: &str, _target: &str) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn readlink(&self) -> FsResult<String> {
        if self.inode.file_type() != FileType::Symlink {
            return Err(FsError::InvalidArgument);
        }

        // 小さなシンボリックリンクはinodeに直接格納される
        let size = self.inode.file_size();
        if size <= 60 {
            // packed structのフィールドを安全に読み取り
            let block: [u32; 15] = unsafe {
                let ptr = core::ptr::addr_of!(self.inode.block);
                core::ptr::read_unaligned(ptr)
            };
            let bytes: &[u8] =
                unsafe { core::slice::from_raw_parts(block.as_ptr() as *const u8, size as usize) };
            return Ok(String::from_utf8_lossy(bytes).into_owned());
        }

        // 大きなシンボリックリンクはデータブロックに格納
        let mut buffer = vec![0u8; size as usize];
        let bytes_read = self.read(0, &mut buffer)?;
        buffer.truncate(bytes_read);

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let size = self.inode.file_size();
        if offset >= size {
            return Ok(0);
        }

        let to_read = buf.len().min((size - offset) as usize);
        let block_size = self.fs.block_size as u64;
        let mut bytes_read = 0usize;
        let mut current_offset = offset;

        while bytes_read < to_read {
            let logical_block = (current_offset / block_size) as u32;
            let block_offset = (current_offset % block_size) as usize;

            let physical_block = self.fs.get_block_num(&self.inode, logical_block)?;
            if physical_block == 0 {
                // スパースファイル：ゼロで埋める
                let available = (block_size as usize - block_offset).min(to_read - bytes_read);
                for i in 0..available {
                    buf[bytes_read + i] = 0;
                }
                bytes_read += available;
                current_offset += available as u64;
                continue;
            }

            let mut block_buffer = vec![0u8; self.fs.block_size as usize];
            self.fs.read_block(physical_block, &mut block_buffer)?;

            let available = (block_size as usize - block_offset).min(to_read - bytes_read);
            buf[bytes_read..bytes_read + available]
                .copy_from_slice(&block_buffer[block_offset..block_offset + available]);

            bytes_read += available;
            current_offset += available as u64;
        }

        Ok(bytes_read)
    }

    fn write(&self, _offset: u64, _buf: &[u8]) -> FsResult<usize> {
        Err(FsError::NotSupported)
    }

    fn truncate(&self, _size: u64) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblock_block_size() {
        // block_size = 1024 << 0 = 1024
        let mut sb: Superblock = unsafe { core::mem::zeroed() };
        sb.log_block_size = 0;
        assert_eq!(sb.block_size(), 1024);

        // block_size = 1024 << 2 = 4096
        sb.log_block_size = 2;
        assert_eq!(sb.block_size(), 4096);
    }

    #[test]
    fn test_inode_file_type() {
        let mut inode: Ext2Inode = unsafe { core::mem::zeroed() };

        inode.mode = S_IFREG;
        assert_eq!(inode.file_type(), FileType::Regular);

        inode.mode = S_IFDIR;
        assert_eq!(inode.file_type(), FileType::Directory);

        inode.mode = S_IFLNK;
        assert_eq!(inode.file_type(), FileType::Symlink);
    }
}
