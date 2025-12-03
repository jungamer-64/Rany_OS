//! devfs - Device Filesystem
//!
//! /dev ファイルシステムの実装
//! デバイスノードを仮想ファイルとして公開

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// デバイス番号 (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DeviceNumber {
    major: u16,
    minor: u16,
}

impl DeviceNumber {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub const fn major(&self) -> u16 {
        self.major
    }

    pub const fn minor(&self) -> u16 {
        self.minor
    }

    pub const fn to_dev_t(&self) -> u32 {
        ((self.major as u32) << 16) | (self.minor as u32)
    }

    pub const fn from_dev_t(dev: u32) -> Self {
        Self {
            major: (dev >> 16) as u16,
            minor: dev as u16,
        }
    }

    // 標準デバイス番号
    pub const NULL: Self = Self::new(1, 3);
    pub const ZERO: Self = Self::new(1, 5);
    pub const FULL: Self = Self::new(1, 7);
    pub const RANDOM: Self = Self::new(1, 8);
    pub const URANDOM: Self = Self::new(1, 9);
    pub const TTY: Self = Self::new(5, 0);
    pub const CONSOLE: Self = Self::new(5, 1);
}

/// デバイスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// キャラクタデバイス
    Character,
    /// ブロックデバイス
    Block,
}

/// inode番号 (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DevInode(u64);

impl DevInode {
    pub const ROOT: Self = Self(1);

    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// デバイス操作トレイト
pub trait DeviceOps: Send + Sync {
    /// デバイスを開く
    fn open(&self) -> Result<(), DevError>;

    /// デバイスを閉じる
    fn close(&self) -> Result<(), DevError>;

    /// 読み取り
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, DevError>;

    /// 書き込み
    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize, DevError>;

    /// ioctl
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<usize, DevError>;
}

/// デバイスエントリ
pub struct DevEntry {
    /// inode
    pub inode: DevInode,
    /// 名前
    pub name: String,
    /// デバイスタイプ
    pub device_type: Option<DeviceType>,
    /// デバイス番号
    pub device_number: Option<DeviceNumber>,
    /// デバイス操作
    pub ops: Option<Arc<dyn DeviceOps>>,
    /// 子エントリ (ディレクトリの場合)
    pub children: BTreeMap<String, DevEntry>,
    /// シンボリックリンク先
    pub symlink_target: Option<String>,
}

impl DevEntry {
    /// ディレクトリエントリを作成
    pub fn directory(inode: DevInode, name: &str) -> Self {
        Self {
            inode,
            name: String::from(name),
            device_type: None,
            device_number: None,
            ops: None,
            children: BTreeMap::new(),
            symlink_target: None,
        }
    }

    /// キャラクタデバイスエントリを作成
    pub fn character_device(
        inode: DevInode,
        name: &str,
        device_number: DeviceNumber,
        ops: Arc<dyn DeviceOps>,
    ) -> Self {
        Self {
            inode,
            name: String::from(name),
            device_type: Some(DeviceType::Character),
            device_number: Some(device_number),
            ops: Some(ops),
            children: BTreeMap::new(),
            symlink_target: None,
        }
    }

    /// ブロックデバイスエントリを作成
    pub fn block_device(
        inode: DevInode,
        name: &str,
        device_number: DeviceNumber,
        ops: Arc<dyn DeviceOps>,
    ) -> Self {
        Self {
            inode,
            name: String::from(name),
            device_type: Some(DeviceType::Block),
            device_number: Some(device_number),
            ops: Some(ops),
            children: BTreeMap::new(),
            symlink_target: None,
        }
    }

    /// シンボリックリンクを作成
    pub fn symlink(inode: DevInode, name: &str, target: &str) -> Self {
        Self {
            inode,
            name: String::from(name),
            device_type: None,
            device_number: None,
            ops: None,
            children: BTreeMap::new(),
            symlink_target: Some(String::from(target)),
        }
    }

    /// 子エントリを追加
    pub fn add_child(&mut self, entry: DevEntry) {
        self.children.insert(entry.name.clone(), entry);
    }

    /// ディレクトリかどうか
    pub fn is_directory(&self) -> bool {
        self.device_type.is_none() && self.symlink_target.is_none()
    }
}

/// devfs エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevError {
    /// エントリが見つからない
    NotFound,
    /// ディレクトリではない
    NotDirectory,
    /// デバイスではない
    NotDevice,
    /// 既に存在する
    AlreadyExists,
    /// 操作不可
    NotSupported,
    /// 読み取り不可
    NotReadable,
    /// 書き込み不可
    NotWritable,
    /// IO エラー
    IoError,
    /// 権限なし
    PermissionDenied,
}

// --- 標準デバイス実装 ---

/// /dev/null デバイス
pub struct NullDevice;

impl DeviceOps for NullDevice {
    fn open(&self) -> Result<(), DevError> {
        Ok(())
    }
    fn close(&self) -> Result<(), DevError> {
        Ok(())
    }

    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize, DevError> {
        Ok(0) // EOF
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, DevError> {
        Ok(buf.len()) // 全て捨てる
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> {
        Ok(0)
    }
}

/// /dev/zero デバイス
pub struct ZeroDevice;

impl DeviceOps for ZeroDevice {
    fn open(&self) -> Result<(), DevError> {
        Ok(())
    }
    fn close(&self) -> Result<(), DevError> {
        Ok(())
    }

    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, DevError> {
        for byte in buf.iter_mut() {
            *byte = 0;
        }
        Ok(buf.len())
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, DevError> {
        Ok(buf.len())
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> {
        Ok(0)
    }
}

/// /dev/full デバイス
pub struct FullDevice;

impl DeviceOps for FullDevice {
    fn open(&self) -> Result<(), DevError> {
        Ok(())
    }
    fn close(&self) -> Result<(), DevError> {
        Ok(())
    }

    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, DevError> {
        for byte in buf.iter_mut() {
            *byte = 0;
        }
        Ok(buf.len())
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize, DevError> {
        Err(DevError::NotWritable) // ENOSPC
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> {
        Ok(0)
    }
}

/// /dev/random, /dev/urandom デバイス
pub struct RandomDevice {
    /// エントロピープール (簡易実装)
    state: AtomicU64,
}

impl RandomDevice {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0x5DEECE66D_u64),
        }
    }

    /// 簡易乱数生成
    fn next_random(&self) -> u64 {
        let mut state = self.state.load(Ordering::Relaxed);
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state.store(state, Ordering::Relaxed);
        state
    }
}

impl DeviceOps for RandomDevice {
    fn open(&self) -> Result<(), DevError> {
        Ok(())
    }
    fn close(&self) -> Result<(), DevError> {
        Ok(())
    }

    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, DevError> {
        for chunk in buf.chunks_mut(8) {
            let random = self.next_random();
            let bytes = random.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(buf.len())
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, DevError> {
        // エントロピーを追加
        for chunk in buf.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let entropy = u64::from_le_bytes(bytes);
            let _ = self.state.fetch_xor(entropy, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> {
        Ok(0)
    }
}

/// /dev/tty, /dev/console デバイス (VGA出力)
pub struct ConsoleDevice;

impl DeviceOps for ConsoleDevice {
    fn open(&self) -> Result<(), DevError> {
        Ok(())
    }
    fn close(&self) -> Result<(), DevError> {
        Ok(())
    }

    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize, DevError> {
        // TODO: キーボード入力
        Ok(0)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, DevError> {
        // VGAに出力 (簡易実装 - 実際はVGAドライバを呼び出す)
        // シリアル出力の代替としてバッファに保存するか、無視
        let _ = core::str::from_utf8(buf);
        Ok(buf.len())
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> {
        Ok(0)
    }
}

/// devfs ファイルシステム
pub struct DevFs {
    /// ルートエントリ
    root: spin::RwLock<DevEntry>,
    /// 次のinode番号
    next_inode: AtomicU64,
}

impl DevFs {
    /// 新しいdevfsを作成
    pub fn new() -> Self {
        let root = DevEntry::directory(DevInode::ROOT, "");

        let fs = Self {
            root: spin::RwLock::new(root),
            next_inode: AtomicU64::new(2),
        };

        fs.init_standard_devices();
        fs
    }

    /// 標準デバイスを初期化
    fn init_standard_devices(&self) {
        // /dev/null
        self.register_char_device("null", DeviceNumber::NULL, Arc::new(NullDevice));

        // /dev/zero
        self.register_char_device("zero", DeviceNumber::ZERO, Arc::new(ZeroDevice));

        // /dev/full
        self.register_char_device("full", DeviceNumber::FULL, Arc::new(FullDevice));

        // /dev/random
        self.register_char_device(
            "random",
            DeviceNumber::RANDOM,
            Arc::new(RandomDevice::new()),
        );

        // /dev/urandom
        self.register_char_device(
            "urandom",
            DeviceNumber::URANDOM,
            Arc::new(RandomDevice::new()),
        );

        // /dev/tty
        self.register_char_device("tty", DeviceNumber::TTY, Arc::new(ConsoleDevice));

        // /dev/console
        self.register_char_device("console", DeviceNumber::CONSOLE, Arc::new(ConsoleDevice));

        // /dev/stdin -> /proc/self/fd/0 (シンボリックリンク)
        self.create_symlink("stdin", "/proc/self/fd/0");
        self.create_symlink("stdout", "/proc/self/fd/1");
        self.create_symlink("stderr", "/proc/self/fd/2");

        // /dev/fd ディレクトリ
        self.create_directory("fd");

        // /dev/pts ディレクトリ (疑似端末)
        self.create_directory("pts");

        // /dev/shm ディレクトリ (共有メモリ)
        self.create_directory("shm");

        // /dev/disk ディレクトリ
        self.create_directory("disk");
        self.create_directory("disk/by-id");
        self.create_directory("disk/by-uuid");
    }

    /// 次のinode番号を取得
    fn allocate_inode(&self) -> DevInode {
        DevInode::new(self.next_inode.fetch_add(1, Ordering::AcqRel))
    }

    /// ディレクトリを作成
    pub fn create_directory(&self, path: &str) {
        let inode = self.allocate_inode();

        // パスを分解
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return;
        }

        let mut root = self.root.write();
        let mut current = &mut *root;

        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // 最後の要素: ディレクトリを作成
                let entry = DevEntry::directory(inode, part);
                current.add_child(entry);
            } else {
                // 中間要素: 既存ディレクトリに移動
                if !current.children.contains_key(*part) {
                    let intermediate = DevEntry::directory(self.allocate_inode(), part);
                    current.add_child(intermediate);
                }
                // contains_key チェック後なので必ず存在
                // expect で明示的に理由を文書化（デバッグ時に有用）
                current = current
                    .children
                    .get_mut(*part)
                    .expect("child must exist after contains_key check or add_child");
            }
        }
    }

    /// シンボリックリンクを作成
    pub fn create_symlink(&self, name: &str, target: &str) {
        let inode = self.allocate_inode();
        let entry = DevEntry::symlink(inode, name, target);

        let mut root = self.root.write();
        root.add_child(entry);
    }

    /// キャラクタデバイスを登録
    pub fn register_char_device(
        &self,
        name: &str,
        device_number: DeviceNumber,
        ops: Arc<dyn DeviceOps>,
    ) {
        let inode = self.allocate_inode();
        let entry = DevEntry::character_device(inode, name, device_number, ops);

        let mut root = self.root.write();
        root.add_child(entry);
    }

    /// ブロックデバイスを登録
    pub fn register_block_device(
        &self,
        name: &str,
        device_number: DeviceNumber,
        ops: Arc<dyn DeviceOps>,
    ) {
        let inode = self.allocate_inode();
        let entry = DevEntry::block_device(inode, name, device_number, ops);

        let mut root = self.root.write();
        root.add_child(entry);
    }

    /// デバイスを登録解除
    pub fn unregister_device(&self, name: &str) -> Result<(), DevError> {
        let mut root = self.root.write();
        root.children.remove(name).ok_or(DevError::NotFound)?;
        Ok(())
    }

    /// パスからエントリを検索
    fn lookup_entry<'a>(entry: &'a DevEntry, path: &str) -> Option<&'a DevEntry> {
        let mut current = entry;

        for component in path.split('/').filter(|s| !s.is_empty()) {
            match current.children.get(component) {
                Some(child) => current = child,
                None => return None,
            }
        }

        Some(current)
    }

    /// エントリを検索
    pub fn lookup(&self, path: &str) -> Result<DevInode, DevError> {
        let root = self.root.read();
        Self::lookup_entry(&root, path)
            .map(|e| e.inode)
            .ok_or(DevError::NotFound)
    }

    /// ディレクトリ一覧を取得
    pub fn readdir(&self, path: &str) -> Result<Vec<String>, DevError> {
        let root = self.root.read();

        let entry = if path.is_empty() || path == "/" {
            &*root
        } else {
            Self::lookup_entry(&root, path).ok_or(DevError::NotFound)?
        };

        if !entry.is_directory() {
            return Err(DevError::NotDirectory);
        }

        Ok(entry.children.keys().cloned().collect())
    }

    /// デバイスを開く
    pub fn open(&self, path: &str) -> Result<Arc<dyn DeviceOps>, DevError> {
        let root = self.root.read();
        let entry = Self::lookup_entry(&root, path).ok_or(DevError::NotFound)?;

        entry.ops.clone().ok_or(DevError::NotDevice)
    }
}

/// グローバル devfs インスタンス
static DEVFS: spin::Once<DevFs> = spin::Once::new();

/// devfs を取得
pub fn devfs() -> &'static DevFs {
    DEVFS.call_once(DevFs::new)
}

/// 初期化
pub fn init() {
    let _ = devfs();
}

/// デバイスファイルハンドル
pub struct DevFileHandle {
    ops: Arc<dyn DeviceOps>,
    position: AtomicUsize,
}

impl DevFileHandle {
    pub fn open(path: &str) -> Result<Self, DevError> {
        let ops = devfs().open(path)?;
        ops.open()?;

        Ok(Self {
            ops,
            position: AtomicUsize::new(0),
        })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, DevError> {
        let pos = self.position.load(Ordering::Acquire);
        let bytes_read = self.ops.read(pos, buf)?;
        self.position.fetch_add(bytes_read, Ordering::AcqRel);
        Ok(bytes_read)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, DevError> {
        let pos = self.position.load(Ordering::Acquire);
        let bytes_written = self.ops.write(pos, buf)?;
        self.position.fetch_add(bytes_written, Ordering::AcqRel);
        Ok(bytes_written)
    }

    pub fn ioctl(&self, cmd: u32, arg: usize) -> Result<usize, DevError> {
        self.ops.ioctl(cmd, arg)
    }

    pub fn seek(&self, pos: usize) {
        self.position.store(pos, Ordering::Release);
    }
}

impl Drop for DevFileHandle {
    fn drop(&mut self) {
        let _ = self.ops.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_device() {
        let null = NullDevice;

        let mut buf = [0u8; 10];
        assert_eq!(null.read(0, &mut buf).unwrap(), 0);

        let data = b"test";
        assert_eq!(null.write(0, data).unwrap(), 4);
    }

    #[test]
    fn test_zero_device() {
        let zero = ZeroDevice;

        let mut buf = [1u8; 10];
        assert_eq!(zero.read(0, &mut buf).unwrap(), 10);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_device() {
        let random = RandomDevice::new();

        let mut buf1 = [0u8; 8];
        let mut buf2 = [0u8; 8];

        random.read(0, &mut buf1).unwrap();
        random.read(0, &mut buf2).unwrap();

        // 異なる値が生成される(ほぼ確実)
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_devfs_structure() {
        let fs = DevFs::new();

        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("null")));
        assert!(entries.contains(&String::from("zero")));
        assert!(entries.contains(&String::from("random")));
    }
}
