// ============================================================================
// filesystems/nvme_ns/src/layout.rs - Disk Layout & Superblock
// ============================================================================
//!
//! NVMe Namespace FS のディスクレイアウトとスーパーブロック定義。
//!
//! ## レイアウト概要
//! | 領域            | 開始 LBA                    | サイズ                      |
//! |-----------------|-----------------------------|-----------------------------|
//! | Superblock      | 0                           | 1 ブロック                   |
//! | Block Bitmap    | 1                           | ceil(total_blocks / (8*bs)) |
//! | Inode Bitmap    | 1 + bb_blocks               | ceil(max_inodes / (8*bs))   |
//! | Inode Table     | 1 + bb_blocks + ib_blocks   | ceil(max_inodes * 256 / bs) |
//! | Data Blocks     | data_start_lba              | 残り全て                     |

use core::mem;

/// スーパーブロックマジックナンバー: "EXNS" (ExoRust NVMe namespace)
pub const SUPERBLOCK_MAGIC: u64 = 0x45584E_5346_530001; // EXNSFS\x00\x01

/// スーパーブロックバージョン
pub const SUPERBLOCK_VERSION: u32 = 1;

/// オンディスクスーパーブロック (先頭 LBA に配置)
///
/// `#[repr(C)]` で安定したバイナリレイアウトを保証。512B / 4KiB いずれの
/// ブロックサイズでも先頭ブロックに収まるよう 256B に設計。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SuperBlock {
    /// マジックナンバー
    pub magic: u64,
    /// レイアウトバージョン
    pub version: u32,
    /// ブロックサイズ (バイト, 通常 512 or 4096)
    pub block_size: u32,
    /// Namespace 全ブロック数
    pub total_blocks: u64,
    /// 最大 inode 数
    pub max_inodes: u64,
    /// 空きブロック数
    pub free_blocks: u64,
    /// 空き inode 数
    pub free_inodes: u64,
    /// ブロックビットマップ開始 LBA
    pub block_bitmap_start: u64,
    /// ブロックビットマップ用ブロック数
    pub block_bitmap_blocks: u64,
    /// Inode ビットマップ開始 LBA
    pub inode_bitmap_start: u64,
    /// Inode ビットマップ用ブロック数
    pub inode_bitmap_blocks: u64,
    /// Inode テーブル開始 LBA
    pub inode_table_start: u64,
    /// Inode テーブル用ブロック数
    pub inode_table_blocks: u64,
    /// データ領域開始 LBA
    pub data_start_lba: u64,
    /// マウント回数
    pub mount_count: u32,
    /// 最終マウント時刻 (Unix epoch)
    pub last_mount_time: u64,
    /// 最終書き込み時刻 (Unix epoch)
    pub last_write_time: u64,
    /// FS 状態フラグ (0=clean, 1=dirty)
    pub state: u32,
    /// UUID (128-bit)
    pub uuid: [u8; 16],
    /// ボリュームラベル (UTF-8, null終端)
    pub label: [u8; 64],
    /// 予約領域
    _reserved: [u8; 16],
}

const _: () = assert!(mem::size_of::<SuperBlock>() <= 256);

impl SuperBlock {
    /// マジックナンバーの検証
    pub fn is_valid(&self) -> bool {
        self.magic == SUPERBLOCK_MAGIC && self.version == SUPERBLOCK_VERSION
    }

    /// ボリュームラベルを文字列として取得
    pub fn label_str(&self) -> &str {
        let end = self.label.iter().position(|&b| b == 0).unwrap_or(self.label.len());
        core::str::from_utf8(&self.label[..end]).unwrap_or("")
    }
}

impl Default for SuperBlock {
    fn default() -> Self {
        // Safety: ゼロ初期化されたスーパーブロックは無効（magic == 0）
        unsafe { mem::zeroed() }
    }
}

/// NVMe Namespace FS のレイアウト計算ヘルパー
#[derive(Debug, Clone)]
pub struct NsLayout {
    pub block_size: u64,
    pub total_blocks: u64,
    pub max_inodes: u64,
    pub block_bitmap_start: u64,
    pub block_bitmap_blocks: u64,
    pub inode_bitmap_start: u64,
    pub inode_bitmap_blocks: u64,
    pub inode_table_start: u64,
    pub inode_table_blocks: u64,
    pub data_start_lba: u64,
    pub data_blocks: u64,
}

impl NsLayout {
    /// Namespace のパラメータからレイアウトを計算する。
    ///
    /// # 引数
    /// - `block_size`: 論理ブロックサイズ（バイト）
    /// - `total_blocks`: Namespace の全ブロック数
    /// - `inode_ratio`: data ブロックあたりの inode 比率（例: 4 = 4ブロックに1 inode）
    pub fn compute(block_size: u64, total_blocks: u64, inode_ratio: u64) -> Self {
        let bits_per_block = block_size * 8;
        let inode_size = super::ondisk::INODE_SIZE as u64;
        let inodes_per_block = block_size / inode_size;

        // Superblock は LBA 0 の 1 ブロック
        let superblock_blocks: u64 = 1;

        // 最大 inode 数の概算（全データ領域に対する比率）
        // 正確な計算は反復が必要だが、ここでは上限を概算で設定
        let estimated_data = total_blocks.saturating_sub(superblock_blocks + 2);
        let max_inodes = if inode_ratio == 0 {
            estimated_data / 4
        } else {
            estimated_data / inode_ratio
        }
        .max(16); // 最低16 inode

        // Block Bitmap: ceil(total_blocks / bits_per_block) ブロック
        let block_bitmap_blocks = (total_blocks + bits_per_block - 1) / bits_per_block;
        let block_bitmap_start = superblock_blocks;

        // Inode Bitmap: ceil(max_inodes / bits_per_block) ブロック
        let inode_bitmap_blocks = (max_inodes + bits_per_block - 1) / bits_per_block;
        let inode_bitmap_start = block_bitmap_start + block_bitmap_blocks;

        // Inode Table: ceil(max_inodes / inodes_per_block) ブロック
        let inode_table_blocks = if inodes_per_block == 0 {
            max_inodes
        } else {
            (max_inodes + inodes_per_block - 1) / inodes_per_block
        };
        let inode_table_start = inode_bitmap_start + inode_bitmap_blocks;

        // Data Blocks: 残り
        let metadata_end = inode_table_start + inode_table_blocks;
        let data_start_lba = metadata_end;
        let data_blocks = total_blocks.saturating_sub(metadata_end);

        Self {
            block_size,
            total_blocks,
            max_inodes,
            block_bitmap_start,
            block_bitmap_blocks,
            inode_bitmap_start,
            inode_bitmap_blocks,
            inode_table_start,
            inode_table_blocks,
            data_start_lba,
            data_blocks,
        }
    }

    /// レイアウトからスーパーブロックを生成する
    pub fn to_superblock(&self) -> SuperBlock {
        SuperBlock {
            magic: SUPERBLOCK_MAGIC,
            version: SUPERBLOCK_VERSION,
            block_size: self.block_size as u32,
            total_blocks: self.total_blocks,
            max_inodes: self.max_inodes,
            free_blocks: self.data_blocks,
            free_inodes: self.max_inodes.saturating_sub(1), // root inode は予約済み
            block_bitmap_start: self.block_bitmap_start,
            block_bitmap_blocks: self.block_bitmap_blocks,
            inode_bitmap_start: self.inode_bitmap_start,
            inode_bitmap_blocks: self.inode_bitmap_blocks,
            inode_table_start: self.inode_table_start,
            inode_table_blocks: self.inode_table_blocks,
            data_start_lba: self.data_start_lba,
            mount_count: 0,
            last_mount_time: 0,
            last_write_time: 0,
            state: 0,
            uuid: [0; 16],
            label: [0; 64],
            _reserved: [0; 16],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_basic() {
        // 512B blocks, 1024 blocks total, 1 inode per 4 data blocks
        let layout = NsLayout::compute(512, 1024, 4);
        assert!(layout.data_start_lba > 0);
        assert!(layout.data_blocks > 0);
        assert!(layout.data_start_lba + layout.data_blocks <= layout.total_blocks);
    }

    #[test]
    fn superblock_roundtrip() {
        let layout = NsLayout::compute(4096, 65536, 4);
        let sb = layout.to_superblock();
        assert!(sb.is_valid());
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.total_blocks, 65536);
    }

    #[test]
    fn superblock_size() {
        assert!(core::mem::size_of::<SuperBlock>() <= 256);
    }
}
