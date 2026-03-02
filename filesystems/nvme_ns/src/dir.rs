// ============================================================================
// filesystems/nvme_ns/src/dir.rs - Directory Entry
// ============================================================================
//!
//! NVMe Namespace FS のディレクトリエントリ管理。
//!
//! ## オンディスクフォーマット
//! ```text
//! ┌──────────┬──────────┬────────┬──────┬───────────────────┐
//! │ ino (8B) │ entry_len│name_len│ kind │ name (可変長)      │
//! │ u64 LE   │ u16 LE   │ u16 LE │ u8   │ UTF-8, パディング  │
//! └──────────┴──────────┴────────┴──────┴───────────────────┘
//! ```
//!
//! - `ino == 0` は削除済みエントリを示す
//! - `entry_len` はパディング込みの全体長（8 バイト境界アラインメント）
//! - 最大ファイル名長: 255 バイト

use alloc::vec::Vec;

use crate::ondisk::InodeKind;

/// ディレクトリエントリヘッダサイズ（ino + entry_len + name_len + kind + padding）
pub const DIR_ENTRY_HEADER_SIZE: usize = 8 + 2 + 2 + 1 + 3; // 16 bytes

/// 最大ファイル名長（バイト）
pub const MAX_NAME_LEN: usize = 255;

/// ディレクトリエントリ（メモリ表現）
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Inode 番号（0 = 削除済み）
    pub ino: u64,
    /// エントリ全体のバイト長（ヘッダ + 名前 + パディング）
    pub entry_len: u16,
    /// 名前のバイト長
    pub name_len: u16,
    /// エントリ種別
    pub kind: u8,
    /// ファイル名 (UTF-8)
    pub name: Vec<u8>,
}

impl DirEntry {
    /// バイト配列からディレクトリエントリを読み取る
    ///
    /// 残りバッファが不足している場合は `None` を返す。
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < DIR_ENTRY_HEADER_SIZE {
            return None;
        }

        let ino = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let entry_len = u16::from_le_bytes(buf[8..10].try_into().ok()?);
        let name_len = u16::from_le_bytes(buf[10..12].try_into().ok()?);
        let kind = buf[12];

        if entry_len == 0 {
            return Some(Self {
                ino,
                entry_len: 0,
                name_len: 0,
                kind,
                name: Vec::new(),
            });
        }

        let name_start = DIR_ENTRY_HEADER_SIZE;
        let name_end = name_start + name_len as usize;
        if name_end > buf.len() || name_end > entry_len as usize {
            return None;
        }

        Some(Self {
            ino,
            entry_len,
            name_len,
            kind,
            name: buf[name_start..name_end].to_vec(),
        })
    }

    /// ディレクトリエントリをバイト配列にシリアライズ
    pub fn to_bytes(ino: u64, name: &str, kind: InodeKind) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(MAX_NAME_LEN);
        let raw_len = DIR_ENTRY_HEADER_SIZE + name_len;
        // 8 バイト境界にアラインメント
        let entry_len = (raw_len + 7) & !7;

        let mut buf = alloc::vec![0u8; entry_len];
        buf[0..8].copy_from_slice(&ino.to_le_bytes());
        buf[8..10].copy_from_slice(&(entry_len as u16).to_le_bytes());
        buf[10..12].copy_from_slice(&(name_len as u16).to_le_bytes());
        buf[12] = kind as u8;
        // buf[13..16] はパディング（ゼロ）
        buf[DIR_ENTRY_HEADER_SIZE..DIR_ENTRY_HEADER_SIZE + name_len]
            .copy_from_slice(&name_bytes[..name_len]);

        buf
    }

    /// ファイル名を文字列として取得
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name).unwrap_or("")
    }

    /// 削除済みか判定
    pub fn is_deleted(&self) -> bool {
        self.ino == 0
    }
}

/// InodeKind → vfs::FileType 変換ヘルパー
pub fn kind_to_file_type(kind: u8) -> vfs::FileType {
    match InodeKind::from_u16(kind as u16) {
        InodeKind::Regular => vfs::FileType::File,
        InodeKind::Directory => vfs::FileType::Directory,
        InodeKind::Symlink => vfs::FileType::Symlink,
        InodeKind::Free => vfs::FileType::File,
    }
}

// ============================================================================
// DirEntryIter
// ============================================================================

/// ディレクトリブロック内のエントリイテレータ
pub struct DirEntryIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DirEntryIter<'a> {
    /// ブロックバッファからイテレータを作成
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for DirEntryIter<'a> {
    type Item = DirEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + DIR_ENTRY_HEADER_SIZE > self.buf.len() {
            return None;
        }
        let entry = DirEntry::from_bytes(&self.buf[self.pos..])?;
        if entry.entry_len == 0 {
            return None;
        }
        self.pos += entry.entry_len as usize;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = DirEntry::to_bytes(42, "hello.txt", InodeKind::Regular);
        let entry = DirEntry::from_bytes(&bytes).unwrap();
        assert_eq!(entry.ino, 42);
        assert_eq!(entry.name_str(), "hello.txt");
        assert_eq!(entry.kind, InodeKind::Regular as u8);
        // entry_len は 8 バイト境界
        assert_eq!(entry.entry_len as usize % 8, 0);
    }

    #[test]
    fn deleted_entry() {
        let bytes = DirEntry::to_bytes(0, "removed", InodeKind::Free);
        let entry = DirEntry::from_bytes(&bytes).unwrap();
        assert!(entry.is_deleted());
    }

    #[test]
    fn iterator() {
        let mut block = Vec::new();
        block.extend_from_slice(&DirEntry::to_bytes(1, "a", InodeKind::Regular));
        block.extend_from_slice(&DirEntry::to_bytes(2, "bb", InodeKind::Directory));
        block.extend_from_slice(&DirEntry::to_bytes(3, "ccc", InodeKind::Symlink));

        let entries: Vec<_> = DirEntryIter::new(&block).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name_str(), "a");
        assert_eq!(entries[1].name_str(), "bb");
        assert_eq!(entries[2].name_str(), "ccc");
    }
}
