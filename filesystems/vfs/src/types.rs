// ============================================================================
// libs/vfs/src/types.rs - VFS Types
// ============================================================================
//!
//! ファイルシステムで使用される基本型定義。
//!
//! このモジュールはカーネルとファイルシステム実装で共通して使用される
//! ファイル属性、メタデータ、フラグなどの型を提供します。

use bitflags::bitflags;

/// Inode番号型
pub type InodeNum = u64;

// ============================================================================
// File Types
// ============================================================================

/// ファイルタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileType {
    /// 通常ファイル
    #[default]
    File,
    /// ディレクトリ
    Directory,
    /// シンボリックリンク
    Symlink,
    /// ブロックデバイス
    BlockDevice,
    /// キャラクタデバイス
    CharDevice,
    /// 名前付きパイプ（FIFO）
    Pipe,
    /// ソケット
    Socket,
}

// ============================================================================
// File Metadata
// ============================================================================

/// 基本ファイルメタデータ
#[derive(Debug, Clone, Copy, Default)]
pub struct Metadata {
    pub file_type: Option<FileType>,
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub readonly: bool,
}

/// 詳細ファイル属性（UNIX-style）
///
/// Inodeの詳細な属性情報を保持します。
#[derive(Clone, Debug)]
pub struct FileAttr {
    /// Inode番号
    pub ino: InodeNum,
    /// ファイルサイズ（バイト）
    pub size: u64,
    /// ブロック数
    pub blocks: u64,
    /// ファイルタイプ
    pub file_type: FileType,
    /// ファイルモード（パーミッション）
    pub mode: UnixFileMode,
    /// ハードリンク数
    pub nlink: u32,
    /// オーナーユーザーID
    pub uid: u32,
    /// オーナーグループID
    pub gid: u32,
    /// デバイスID（特殊ファイル用）
    pub rdev: u64,
    /// ファイルシステムI/Oのブロックサイズ
    pub blksize: u32,
    /// 最終アクセス時刻（エポックからのナノ秒）
    pub atime: u64,
    /// 最終更新時刻
    pub mtime: u64,
    /// 最終状態変更時刻
    pub ctime: u64,
}

impl Default for FileAttr {
    fn default() -> Self {
        Self {
            ino: 0,
            size: 0,
            blocks: 0,
            file_type: FileType::File,
            mode: UnixFileMode::default(),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            atime: 0,
            mtime: 0,
            ctime: 0,
        }
    }
}

impl From<&FileAttr> for Metadata {
    fn from(attr: &FileAttr) -> Self {
        Self {
            file_type: Some(attr.file_type),
            size: attr.size,
            created: attr.ctime,
            modified: attr.mtime,
            accessed: attr.atime,
            readonly: !attr.mode.owner_write(),
        }
    }
}

// ============================================================================
// Filesystem Statistics
// ============================================================================

/// ファイルシステム統計情報
#[derive(Clone, Debug, Default)]
pub struct FsStats {
    /// 総ブロック数
    pub blocks: u64,
    /// 空きブロック数
    pub bfree: u64,
    /// 利用可能ブロック数（非スーパーユーザー向け）
    pub bavail: u64,
    /// 総Inode数
    pub files: u64,
    /// 空きInode数
    pub ffree: u64,
    /// ブロックサイズ
    pub bsize: u32,
    /// 最大ファイル名長
    pub namelen: u32,
    /// フラグメントサイズ
    pub frsize: u32,
}

// ============================================================================
// Seek Position
// ============================================================================

/// シーク位置
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFrom {
    /// ファイル先頭からのオフセット
    Start(u64),
    /// ファイル末尾からのオフセット
    End(i64),
    /// 現在位置からのオフセット
    Current(i64),
}

// ============================================================================
// Open Flags
// ============================================================================

bitflags! {
    /// ファイルオープンフラグ
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub struct OpenFlags: u32 {
        /// 読み取り専用
        const READ = 0x0001;
        /// 書き込み専用
        const WRITE = 0x0002;
        /// 読み書き両用
        const RDWR = Self::READ.bits() | Self::WRITE.bits();
        /// ファイルが存在しない場合は作成
        const CREATE = 0x0004;
        /// ファイルを切り詰める
        const TRUNCATE = 0x0008;
        /// 末尾に追記
        const APPEND = 0x0010;
        /// ファイルが存在する場合はエラー（CREATEと併用）
        const EXCLUSIVE = 0x0020;
        /// ディレクトリとして開く
        const DIRECTORY = 0x0040;
        /// ノンブロッキングモード
        const NONBLOCK = 0x0080;
        /// 同期I/O
        const SYNC = 0x0100;
    }
}

impl OpenFlags {
    /// 読み取りアクセスが要求されているか
    #[inline]
    #[must_use]
    pub const fn can_read(&self) -> bool {
        self.contains(Self::READ)
    }

    /// 書き込みアクセスが要求されているか
    #[inline]
    #[must_use]
    pub const fn can_write(&self) -> bool {
        self.contains(Self::WRITE)
    }

    /// 作成フラグが設定されているか
    #[inline]
    #[must_use]
    pub const fn should_create(&self) -> bool {
        self.contains(Self::CREATE)
    }

    /// 切り詰めフラグが設定されているか
    #[inline]
    #[must_use]
    pub const fn should_truncate(&self) -> bool {
        self.contains(Self::TRUNCATE)
    }

    /// 追記フラグが設定されているか
    #[inline]
    #[must_use]
    pub const fn should_append(&self) -> bool {
        self.contains(Self::APPEND)
    }
}

// ============================================================================
// File Mode (Simple)
// ============================================================================

bitflags! {
    /// シンプルなファイルモード（パーミッション）
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub struct FileMode: u32 {
        const READ = 0x04;
        const WRITE = 0x02;
        const EXECUTE = 0x01;
    }
}

// ============================================================================
// Unix File Mode (Full POSIX)
// ============================================================================

/// UNIX形式のファイルモード（パーミッション）
///
/// POSIX互換のファイルパーミッションを表現します。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnixFileMode(pub u16);

impl UnixFileMode {
    // Owner permissions
    /// オーナー読み取り許可
    pub const S_IRUSR: u16 = 0o400;
    /// オーナー書き込み許可
    pub const S_IWUSR: u16 = 0o200;
    /// オーナー実行許可
    pub const S_IXUSR: u16 = 0o100;

    // Group permissions
    /// グループ読み取り許可
    pub const S_IRGRP: u16 = 0o040;
    /// グループ書き込み許可
    pub const S_IWGRP: u16 = 0o020;
    /// グループ実行許可
    pub const S_IXGRP: u16 = 0o010;

    // Other permissions
    /// その他読み取り許可
    pub const S_IROTH: u16 = 0o004;
    /// その他書き込み許可
    pub const S_IWOTH: u16 = 0o002;
    /// その他実行許可
    pub const S_IXOTH: u16 = 0o001;

    // Common defaults
    /// デフォルトファイルモード（rw-r--r--）
    pub const DEFAULT_FILE: UnixFileMode = UnixFileMode(0o644);
    /// デフォルトディレクトリモード（rwxr-xr-x）
    pub const DEFAULT_DIR: UnixFileMode = UnixFileMode(0o755);
    /// デフォルトシンボリックリンクモード（rwxrwxrwx）
    pub const DEFAULT_LINK: UnixFileMode = UnixFileMode(0o777);

    /// 新しいファイルモードを作成
    #[inline]
    #[must_use]
    pub const fn new(mode: u16) -> Self {
        Self(mode)
    }

    /// 生の値を取得
    #[inline]
    #[must_use]
    pub const fn bits(&self) -> u16 {
        self.0
    }

    /// オーナーが読み取り可能か
    #[inline]
    #[must_use]
    pub const fn owner_read(&self) -> bool {
        self.0 & Self::S_IRUSR != 0
    }

    /// オーナーが書き込み可能か
    #[inline]
    #[must_use]
    pub const fn owner_write(&self) -> bool {
        self.0 & Self::S_IWUSR != 0
    }

    /// オーナーが実行可能か
    #[inline]
    #[must_use]
    pub const fn owner_execute(&self) -> bool {
        self.0 & Self::S_IXUSR != 0
    }

    /// グループが読み取り可能か
    #[inline]
    #[must_use]
    pub const fn group_read(&self) -> bool {
        self.0 & Self::S_IRGRP != 0
    }

    /// グループが書き込み可能か
    #[inline]
    #[must_use]
    pub const fn group_write(&self) -> bool {
        self.0 & Self::S_IWGRP != 0
    }

    /// グループが実行可能か
    #[inline]
    #[must_use]
    pub const fn group_execute(&self) -> bool {
        self.0 & Self::S_IXGRP != 0
    }

    /// その他が読み取り可能か
    #[inline]
    #[must_use]
    pub const fn other_read(&self) -> bool {
        self.0 & Self::S_IROTH != 0
    }

    /// その他が書き込み可能か
    #[inline]
    #[must_use]
    pub const fn other_write(&self) -> bool {
        self.0 & Self::S_IWOTH != 0
    }

    /// その他が実行可能か
    #[inline]
    #[must_use]
    pub const fn other_execute(&self) -> bool {
        self.0 & Self::S_IXOTH != 0
    }
}

impl Default for UnixFileMode {
    fn default() -> Self {
        Self::DEFAULT_FILE
    }
}

impl From<u16> for UnixFileMode {
    fn from(mode: u16) -> Self {
        Self(mode)
    }
}

impl From<UnixFileMode> for u16 {
    fn from(mode: UnixFileMode) -> Self {
        mode.0
    }
}

// ============================================================================
// Directory Entry (for Inode-based operations)
// ============================================================================

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// ディレクトリエントリ（Inode操作用）
///
/// ディレクトリ内の1つのエントリを表します。
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// エントリ名
    pub name: String,
    /// Inode番号
    pub ino: InodeNum,
    /// ファイルタイプ
    pub file_type: FileType,
}

#[cfg(feature = "alloc")]
impl DirEntry {
    /// 新しいディレクトリエントリを作成
    #[must_use]
    pub fn new(name: String, ino: InodeNum, file_type: FileType) -> Self {
        Self {
            name,
            ino,
            file_type,
        }
    }
}
