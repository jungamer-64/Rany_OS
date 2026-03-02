// ============================================================================
// filesystems/nvme_ns/src/ondisk.rs - On-Disk Inode Structure
// ============================================================================
//!
//! NVMe Namespace FS のオンディスク inode 定義。
//!
//! 1 inode = 256 バイト。4KiB ブロックには 16 inode が格納される。
//! ダイレクトブロックポインタ × 12 + 間接ブロックポインタ × 3 で
//! 大容量ファイルに対応。

use core::mem;

/// inode のオンディスクサイズ（バイト）
pub const INODE_SIZE: usize = 256;

/// ルートディレクトリの inode 番号
pub const ROOT_INODE_NUM: u64 = 0;

/// ダイレクトブロックポインタ数
pub const DIRECT_BLOCKS: usize = 12;

/// inode の種別
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    /// 未使用
    Free = 0,
    /// 通常ファイル
    Regular = 1,
    /// ディレクトリ
    Directory = 2,
    /// シンボリックリンク
    Symlink = 3,
}

impl InodeKind {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => InodeKind::Regular,
            2 => InodeKind::Directory,
            3 => InodeKind::Symlink,
            _ => InodeKind::Free,
        }
    }
}

/// オンディスク inode 構造 (256 バイト)
///
/// ダイレクト 12 + 単間接 + 二重間接 + 三重間接 でブロックを管理。
/// 4KiB ブロックの場合:
///   - ダイレクト: 12 × 4KiB = 48KiB
///   - 単間接: 512 × 4KiB = 2MiB
///   - 二重間接: 512² × 4KiB = 1GiB
///   - 三重間接: 512³ × 4KiB = 512GiB
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DiskInode {
    /// inode 種別
    pub kind: u16,
    /// パーミッション (rwxrwxrwx)
    pub mode: u16,
    /// UID
    pub uid: u32,
    /// GID
    pub gid: u32,
    /// ハードリンク数
    pub nlink: u32,
    /// ファイルサイズ（バイト）
    pub size: u64,
    /// 使用ブロック数
    pub blocks: u64,
    /// 作成時刻 (Unix epoch, ナノ秒)
    pub ctime: u64,
    /// 変更時刻 (Unix epoch, ナノ秒)
    pub mtime: u64,
    /// アクセス時刻 (Unix epoch, ナノ秒)
    pub atime: u64,
    /// ダイレクトブロックポインタ (LBA)
    pub direct: [u64; DIRECT_BLOCKS],
    /// 単間接ブロックポインタ (LBA)
    pub indirect: u64,
    /// 二重間接ブロックポインタ (LBA)
    pub double_indirect: u64,
    /// 三重間接ブロックポインタ (LBA)
    pub triple_indirect: u64,
    /// フラグ (追記専用, 不変等)
    pub flags: u32,
    /// 拡張属性ブロック (将来用)
    pub xattr_block: u64,
    /// 予約領域
    _reserved: [u8; 64],
}

const _: () = assert!(mem::size_of::<DiskInode>() == INODE_SIZE);

impl DiskInode {
    /// 新しい空の inode を作成
    pub fn new(kind: InodeKind, mode: u16) -> Self {
        let mut inode: Self = unsafe { mem::zeroed() };
        inode.kind = kind as u16;
        inode.mode = mode;
        inode.nlink = 1;
        inode
    }

    /// inode の種別を取得
    pub fn inode_kind(&self) -> InodeKind {
        InodeKind::from_u16(self.kind)
    }

    /// ファイルか判定
    pub fn is_file(&self) -> bool {
        self.inode_kind() == InodeKind::Regular
    }

    /// ディレクトリか判定
    pub fn is_dir(&self) -> bool {
        self.inode_kind() == InodeKind::Directory
    }

    /// シンボリックリンクか判定
    pub fn is_symlink(&self) -> bool {
        self.inode_kind() == InodeKind::Symlink
    }

    /// 使用中か判定
    pub fn is_allocated(&self) -> bool {
        self.inode_kind() != InodeKind::Free
    }

    /// ブロックポインタのスロット数（ダイレクトのみ、間接は別管理）
    pub fn direct_block_count(&self) -> usize {
        let mut count = 0;
        for &b in &self.direct {
            if b != 0 {
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// inode が参照するデータブロックの最大数（ダイレクトのみ）
    pub fn max_direct_bytes(&self, block_size: u64) -> u64 {
        DIRECT_BLOCKS as u64 * block_size
    }

    /// バイト配列として読み出し
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, INODE_SIZE) }
    }

    /// バイト配列から復元
    ///
    /// # Safety
    /// `bytes` は少なくとも INODE_SIZE バイト長でなければならない。
    pub unsafe fn from_bytes(bytes: &[u8]) -> &Self {
        assert!(bytes.len() >= INODE_SIZE);
        unsafe { &*(bytes.as_ptr() as *const Self) }
    }

    /// 可変バイト配列から復元
    ///
    /// # Safety
    /// `bytes` は少なくとも INODE_SIZE バイト長でなければならない。
    pub unsafe fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        assert!(bytes.len() >= INODE_SIZE);
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_size() {
        assert_eq!(core::mem::size_of::<DiskInode>(), INODE_SIZE);
    }

    #[test]
    fn inode_new() {
        let inode = DiskInode::new(InodeKind::Regular, 0o644);
        assert!(inode.is_file());
        assert!(!inode.is_dir());
        assert_eq!(inode.nlink, 1);
        assert_eq!(inode.size, 0);
    }

    #[test]
    fn inode_roundtrip() {
        let inode = DiskInode::new(InodeKind::Directory, 0o755);
        let bytes = inode.as_bytes();
        let recovered = unsafe { DiskInode::from_bytes(bytes) };
        assert!(recovered.is_dir());
        assert_eq!(recovered.mode, 0o755);
    }
}
