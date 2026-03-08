// ============================================================================
// filesystems/nvme_ns/src/fs.rs - NVMe Namespace Filesystem
// ============================================================================
//!
//! `NvmeNamespaceFs` — NVMe Namespace ファイルシステムのメイン構造体。
//!
//! VFS の `ExtendedFileSystem` トレイトおよび `NsInodeOps` トレイトを実装し、
//! ブロックデバイス I/O を介してオンディスク構造にアクセスする。
//!
//! ## 使い方
//! ```ignore
//! // フォーマット
//! NvmeNamespaceFs::mkfs(&block_dev, 4096, "myvolume")?;
//!
//! // マウント
//! let fs = NvmeNamespaceFs::mount(block_dev)?;
//! let root = fs.root()?; // Arc<dyn Inode>
//! ```

use alloc::sync::Arc;
use alloc::vec;

use exorust_sync::PoisonLock;
use vfs::{FsStats, VfsError, VfsResult};

use crate::bitmap::Bitmap;
use crate::error::NsError;
use crate::inode::{NsInode, NsInodeOps};
use crate::layout::{NsLayout, SUPERBLOCK_MAGIC, SuperBlock};
use crate::ondisk::{DiskInode, INODE_SIZE, InodeKind, ROOT_INODE_NUM};

// ============================================================================
// BlockIo トレイト
// ============================================================================

/// `NvmeNamespaceFs` が使用するブロック I/O 抽象。
///
/// NVMe ドライバの同期パス（ポーリングモード）に対応する最小インターフェース。
/// VFS の `ZeroCopyBlockDevice` はバッファ型が関連型で汎用化しにくいため、
/// ここでは簡素なバイトスライス I/O を定義して柔軟性を確保する。
pub trait BlockIo: Send + Sync {
    /// ブロックサイズ（バイト）
    fn block_size(&self) -> u32;

    /// 総ブロック数
    fn total_blocks(&self) -> u64;

    /// 指定 LBA のブロックを読む。`buf.len() >= block_size` であること。
    fn read_block(&self, lba: u64, buf: &mut [u8]) -> Result<(), NsError>;

    /// 指定 LBA にブロックを書く。`buf.len() >= block_size` であること。
    fn write_block(&self, lba: u64, buf: &[u8]) -> Result<(), NsError>;

    /// キャッシュをフラッシュ
    fn flush(&self) -> Result<(), NsError>;
}

// ============================================================================
// NvmeNamespaceFs
// ============================================================================

/// NVMe Namespace ファイルシステム
pub struct NvmeNamespaceFs {
    /// ブロック I/O バックエンド
    dev: Arc<dyn BlockIo>,
    /// キャッシュされたスーパーブロック
    sb: PoisonLock<SuperBlock>,
    /// ブロックビットマップ
    block_bm: PoisonLock<Bitmap>,
    /// Inode ビットマップ
    inode_bm: PoisonLock<Bitmap>,
    /// 自己参照（root() で Arc<Self> を復元するため）
    self_ref: PoisonLock<Option<alloc::sync::Weak<Self>>>,
}

impl NvmeNamespaceFs {
    // ========================================================================
    // mkfs - フォーマット
    // ========================================================================

    /// Namespace をフォーマットして新しいファイルシステムを書き込む。
    ///
    /// # 引数
    /// - `dev`: ブロック I/O バックエンド
    /// - `inode_ratio`: データブロック何個あたりに inode 1 つを割り当てるか (例: 4)
    /// - `label`: ボリュームラベル（最大 63 バイト）
    pub fn mkfs(dev: &dyn BlockIo, inode_ratio: u64, label: &str) -> Result<(), NsError> {
        let bs = dev.block_size() as u64;
        let total = dev.total_blocks();

        let layout = NsLayout::compute(bs, total, inode_ratio);
        let mut sb = layout.to_superblock();

        // ラベル設定
        let label_bytes = label.as_bytes();
        let copy_len = label_bytes.len().min(sb.label.len() - 1);
        sb.label[..copy_len].copy_from_slice(&label_bytes[..copy_len]);

        // スーパーブロック書き込み
        let mut buf = vec![0u8; bs as usize];
        let sb_bytes = unsafe {
            core::slice::from_raw_parts(
                &sb as *const SuperBlock as *const u8,
                core::mem::size_of::<SuperBlock>(),
            )
        };
        buf[..sb_bytes.len()].copy_from_slice(sb_bytes);
        dev.write_block(0, &buf)?;

        // ブロックビットマップ初期化（メタデータ領域を使用中にマーク）
        let mut block_bm = Bitmap::new(total);
        for i in 0..layout.data_start_lba {
            block_bm.mark_used(i);
        }
        Self::write_bitmap(dev, &block_bm, layout.block_bitmap_start, bs)?;

        // Inode ビットマップ初期化（root inode を使用中にマーク）
        let mut inode_bm = Bitmap::new(layout.max_inodes);
        inode_bm.mark_used(ROOT_INODE_NUM);
        Self::write_bitmap(dev, &inode_bm, layout.inode_bitmap_start, bs)?;

        // Root inode 作成（ディレクトリ）
        let root_disk = DiskInode::new(InodeKind::Directory, 0o755);
        Self::write_disk_inode(dev, &layout, ROOT_INODE_NUM, &root_disk, bs)?;

        // フラッシュ
        dev.flush()?;

        Ok(())
    }

    // ========================================================================
    // mount - マウント
    // ========================================================================

    /// マウント: スーパーブロックを読み取り、ビットマップをキャッシュする。
    pub fn mount(dev: Arc<dyn BlockIo>) -> Result<Arc<Self>, NsError> {
        let bs = dev.block_size() as u64;

        // スーパーブロック読み取り
        let mut buf = vec![0u8; bs as usize];
        dev.read_block(0, &mut buf)?;

        let sb = unsafe {
            let ptr = buf.as_ptr() as *const SuperBlock;
            *ptr
        };

        if sb.magic != SUPERBLOCK_MAGIC {
            return Err(NsError::InvalidSuperblock);
        }

        // ブロックビットマップ読み取り
        let block_bm = Self::read_bitmap(
            &*dev,
            sb.block_bitmap_start,
            sb.block_bitmap_blocks,
            sb.total_blocks,
            bs,
        )?;

        // Inode ビットマップ読み取り
        let inode_bm = Self::read_bitmap(
            &*dev,
            sb.inode_bitmap_start,
            sb.inode_bitmap_blocks,
            sb.max_inodes,
            bs,
        )?;

        let fs = Arc::new(Self {
            dev,
            sb: PoisonLock::new(sb),
            block_bm: PoisonLock::new(block_bm),
            inode_bm: PoisonLock::new(inode_bm),
            self_ref: PoisonLock::new(None),
        });

        // 自己参照を設定（Weak で循環参照を回避）
        {
            let mut sr = fs.self_ref.lock().map_err(|_| NsError::IoError)?;
            *sr = Some(Arc::downgrade(&fs));
        }

        Ok(fs)
    }

    // ========================================================================
    // Bitmap I/O helpers
    // ========================================================================

    fn write_bitmap(
        dev: &dyn BlockIo,
        bm: &Bitmap,
        start_lba: u64,
        bs: u64,
    ) -> Result<(), NsError> {
        let data = bm.as_bytes();
        let bs_usize = bs as usize;
        let mut lba = start_lba;
        let mut offset = 0;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < data.len() {
            let end = (offset + bs_usize).min(data.len());
            let mut buf = vec![0u8; bs_usize];
            buf[..end - offset].copy_from_slice(&data[offset..end]);
            dev.write_block(lba, &buf)?;
            lba += 1;
            offset += bs_usize;
        }
        Ok(())
    }

    fn read_bitmap(
        dev: &dyn BlockIo,
        start_lba: u64,
        block_count: u64,
        total_bits: u64,
        bs: u64,
    ) -> Result<Bitmap, NsError> {
        let bs_usize = bs as usize;
        let mut raw = alloc::vec::Vec::new();
        for i in 0..block_count {
            let mut buf = vec![0u8; bs_usize];
            dev.read_block(start_lba + i, &mut buf)?;
            raw.extend_from_slice(&buf);
        }
        // 余分なバイトをトリミング
        let needed = ((total_bits + 7) / 8) as usize;
        raw.truncate(needed);
        Ok(Bitmap::from_raw(raw, total_bits))
    }

    // ========================================================================
    // Inode Table I/O helpers
    // ========================================================================

    fn inode_location(sb: &SuperBlock, ino: u64, bs: u64) -> (u64, usize) {
        let inodes_per_block = bs as usize / INODE_SIZE;
        let block_index = ino as usize / inodes_per_block;
        let offset_in_block = (ino as usize % inodes_per_block) * INODE_SIZE;
        (sb.inode_table_start + block_index as u64, offset_in_block)
    }

    fn write_disk_inode(
        dev: &dyn BlockIo,
        layout: &NsLayout,
        ino: u64,
        disk: &DiskInode,
        bs: u64,
    ) -> Result<(), NsError> {
        let inodes_per_block = bs as usize / INODE_SIZE;
        let block_index = ino as usize / inodes_per_block;
        let offset_in_block = (ino as usize % inodes_per_block) * INODE_SIZE;

        let lba = layout.inode_table_start + block_index as u64;
        let mut buf = vec![0u8; bs as usize];
        dev.read_block(lba, &mut buf)?;
        buf[offset_in_block..offset_in_block + INODE_SIZE].copy_from_slice(disk.as_bytes());
        dev.write_block(lba, &buf)?;
        Ok(())
    }

    // ========================================================================
    // 外部公開ヘルパー
    // ========================================================================

    /// スーパーブロック情報を取得
    pub fn superblock(&self) -> Result<SuperBlock, NsError> {
        let sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        Ok(*sb)
    }

    /// ブロックサイズを取得
    pub fn blk_size(&self) -> u64 {
        self.dev.block_size() as u64
    }
}

// ============================================================================
// NsInodeOps 実装
// ============================================================================

impl NsInodeOps for NvmeNamespaceFs {
    fn read_inode(&self, ino: u64) -> Result<DiskInode, NsError> {
        let sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        if ino >= sb.max_inodes {
            return Err(NsError::InvalidInode(ino));
        }
        let bs = sb.block_size as u64;
        let (lba, offset) = Self::inode_location(&sb, ino, bs);
        drop(sb);

        let mut buf = vec![0u8; bs as usize];
        self.dev.read_block(lba, &mut buf)?;
        let disk = unsafe { DiskInode::from_bytes(&buf[offset..offset + INODE_SIZE]) };
        Ok(*disk)
    }

    fn write_inode(&self, ino: u64, disk: &DiskInode) -> Result<(), NsError> {
        let sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        if ino >= sb.max_inodes {
            return Err(NsError::InvalidInode(ino));
        }
        let bs = sb.block_size as u64;
        let (lba, offset) = Self::inode_location(&sb, ino, bs);
        drop(sb);

        let mut buf = vec![0u8; bs as usize];
        self.dev.read_block(lba, &mut buf)?;
        buf[offset..offset + INODE_SIZE].copy_from_slice(disk.as_bytes());
        self.dev.write_block(lba, &buf)?;
        Ok(())
    }

    fn read_block(&self, lba: u64, buf: &mut [u8]) -> Result<(), NsError> {
        self.dev.read_block(lba, buf)
    }

    fn write_block(&self, lba: u64, buf: &[u8]) -> Result<(), NsError> {
        self.dev.write_block(lba, buf)
    }

    fn alloc_block(&self) -> Result<u64, NsError> {
        let sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        let data_start = sb.data_start_lba;
        drop(sb);

        let mut bm = self.block_bm.lock().map_err(|_| NsError::IoError)?;
        match bm.alloc() {
            Some(bit) => {
                // ブロックビットマップのビットはグローバル LBA に対応
                // data_start 以降のブロックのみ返す
                if bit < data_start {
                    // メタデータ領域はすでに mark_used 済みだが念のため
                    // 再帰的に探す
                    drop(bm);
                    self.alloc_block()
                } else {
                    let mut sb = self.sb.lock().map_err(|_| NsError::IoError)?;
                    sb.free_blocks = sb.free_blocks.saturating_sub(1);
                    Ok(bit)
                }
            }
            None => Err(NsError::NoSpace),
        }
    }

    fn free_block(&self, lba: u64) -> Result<(), NsError> {
        let mut bm = self.block_bm.lock().map_err(|_| NsError::IoError)?;
        bm.free(lba);
        let mut sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        sb.free_blocks += 1;
        Ok(())
    }

    fn alloc_inode(&self) -> Result<u64, NsError> {
        let mut bm = self.inode_bm.lock().map_err(|_| NsError::IoError)?;
        match bm.alloc() {
            Some(ino) => {
                let mut sb = self.sb.lock().map_err(|_| NsError::IoError)?;
                sb.free_inodes = sb.free_inodes.saturating_sub(1);
                Ok(ino)
            }
            None => Err(NsError::NoSpace),
        }
    }

    fn free_inode(&self, ino: u64) -> Result<(), NsError> {
        let mut bm = self.inode_bm.lock().map_err(|_| NsError::IoError)?;
        bm.free(ino);
        let mut sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        sb.free_inodes += 1;
        Ok(())
    }

    fn block_size(&self) -> u64 {
        self.dev.block_size() as u64
    }

    fn fs_stats(&self) -> Result<FsStats, NsError> {
        let sb = self.sb.lock().map_err(|_| NsError::IoError)?;
        Ok(FsStats {
            blocks: sb.total_blocks,
            bfree: sb.free_blocks,
            bavail: sb.free_blocks,
            files: sb.max_inodes,
            ffree: sb.free_inodes,
            bsize: sb.block_size,
            namelen: crate::dir::MAX_NAME_LEN as u32,
            frsize: sb.block_size,
        })
    }
}

// ============================================================================
// VFS ExtendedFileSystem 実装
// ============================================================================

impl vfs::ExtendedFileSystem for NvmeNamespaceFs {
    fn name(&self) -> &str {
        "nvme_ns"
    }

    fn root(&self) -> VfsResult<Arc<dyn vfs::Inode>> {
        let disk = self.read_inode(ROOT_INODE_NUM).map_err(VfsError::from)?;

        // Weak 参照から Arc<Self> を復元
        let sr = self.self_ref.lock().map_err(|_| VfsError::IoError)?;
        let weak = sr.as_ref().ok_or(VfsError::IoError)?;
        let fs_arc = weak.upgrade().ok_or(VfsError::IoError)?;

        // NvmeNamespaceFs は NsInodeOps を実装しているため、
        // Arc<NvmeNamespaceFs> を Arc<dyn NsInodeOps> にアップキャスト
        let ops: Arc<dyn NsInodeOps> = fs_arc;
        let inode = NsInode::new(ROOT_INODE_NUM, disk, ops);
        Ok(Arc::new(inode))
    }

    fn statfs(&self) -> VfsResult<vfs::FsStats> {
        let sb = self.sb.lock().map_err(|_| VfsError::IoError)?;
        Ok(vfs::FsStats {
            blocks: sb.total_blocks,
            bfree: sb.free_blocks,
            bavail: sb.free_blocks,
            files: sb.max_inodes,
            ffree: sb.free_inodes,
            bsize: sb.block_size,
            namelen: crate::dir::MAX_NAME_LEN as u32,
            frsize: sb.block_size,
        })
    }

    fn sync(&self) -> VfsResult<()> {
        // ビットマップをディスクに書き戻し
        let sb = self.sb.lock().map_err(|_| VfsError::IoError)?;
        let bs = sb.block_size as u64;

        // ブロックビットマップ
        {
            let bm = self.block_bm.lock().map_err(|_| VfsError::IoError)?;
            if bm.is_dirty() {
                Self::write_bitmap(&*self.dev, &bm, sb.block_bitmap_start, bs)
                    .map_err(|_| VfsError::IoError)?;
            }
        }

        // Inode ビットマップ
        {
            let bm = self.inode_bm.lock().map_err(|_| VfsError::IoError)?;
            if bm.is_dirty() {
                Self::write_bitmap(&*self.dev, &bm, sb.inode_bitmap_start, bs)
                    .map_err(|_| VfsError::IoError)?;
            }
        }

        // スーパーブロック書き戻し
        {
            let mut buf = vec![0u8; bs as usize];
            let sb_bytes = unsafe {
                core::slice::from_raw_parts(
                    &*sb as *const SuperBlock as *const u8,
                    core::mem::size_of::<SuperBlock>(),
                )
            };
            buf[..sb_bytes.len()].copy_from_slice(sb_bytes);
            self.dev
                .write_block(0, &buf)
                .map_err(|_| VfsError::IoError)?;
        }
        drop(sb);

        self.dev.flush().map_err(|_| VfsError::IoError)?;
        Ok(())
    }

    fn unmount(&self) -> VfsResult<()> {
        // sync してクリーン状態にマーク
        self.sync()?;
        let mut sb = self.sb.lock().map_err(|_| VfsError::IoError)?;
        sb.state = 0; // clean
        Ok(())
    }
}
