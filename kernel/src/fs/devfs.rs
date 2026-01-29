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
        // コンソールデバイスの読み取り
        // キーボード入力は非同期ストリーム経由で取得する必要がある
        // (KeyboardStreamを使用)
        // ここでは同期読み取りをサポートしないため0を返す
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

        // /dev/stdin -> /proc/self/fd/0 (POSIX互換時のみ)
        #[cfg(feature = "posix-compat")]
        {
            self.create_symlink("stdin", "/proc/self/fd/0");
            self.create_symlink("stdout", "/proc/self/fd/1");
            self.create_symlink("stderr", "/proc/self/fd/2");
        }

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

    /// デバイス番号からブロックデバイスを探す
    pub fn find_block_device_by_number(&self, device_number: DeviceNumber) -> Result<Arc<dyn DeviceOps>, DevError> {
        let root = self.root.read();

        fn search(entry: &DevEntry, device_number: DeviceNumber) -> Option<Arc<dyn DeviceOps>> {
            if entry.device_type == Some(DeviceType::Block) {
                if let Some(dn) = entry.device_number {
                    if dn == device_number {
                        return entry.ops.clone();
                    }
                }
            }

            for child in entry.children.values() {
                if let Some(ops) = search(child, device_number) {
                    return Some(ops);
                }
            }

            None
        }

        search(&*root, device_number).ok_or(DevError::NotFound)
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
    token: Option<u64>,
}

impl DevFileHandle {
    pub fn open(path: &str) -> Result<Self, DevError> {
        // Backward-compatible: open without token
        Self::open_with_token(path, None)
    }

    pub fn open_with_token(path: &str, token: Option<u64>) -> Result<Self, DevError> {
        use crate::task::context;

        let caller = context::current_subject().domain.as_u64();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_FOWNER) {
                return Err(DevError::NotSupported);
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(DevError::NotSupported);
            }
        }

        let ops = devfs().open(path)?;
        if let Err(e) = ops.open() {
            // Rollback in-flight on failure to open
            if let Some(t) = token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            return Err(e);
        }

        Ok(Self {
            ops,
            position: AtomicUsize::new(0),
            token,
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
        if let Some(t) = self.token {
            let _ = crate::security::capability::manager().decrement_in_flight(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use crate::domain_system::{DomainCredentials, DomainId, DomainSecurity};
    use crate::task::context::{get_current_task, set_current_task, TaskControlBlock};
    use crate::security::capability::{manager, CapabilitySet, CAP_FOWNER};

    fn idle_entry(_: u64) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    struct CurrentTaskGuard {
        prev: Option<*mut TaskControlBlock>,
        current: *mut TaskControlBlock,
    }

    impl Drop for CurrentTaskGuard {
        fn drop(&mut self) {
            let cpu_id = crate::smp::current_cpu() as usize;
            let prev_ptr = self.prev.unwrap_or(core::ptr::null_mut());
            unsafe {
                set_current_task(cpu_id, prev_ptr);
                drop(Box::from_raw(self.current));
            }
        }
    }

    fn set_current_subject(domain_id: DomainId) -> CurrentTaskGuard {
        let cpu_id = crate::smp::current_cpu() as usize;
        let prev = get_current_task(cpu_id);
        let mut tcb = TaskControlBlock::new(idle_entry, 0, 0, domain_id)
            .expect("failed to create test TCB");
        let caps = manager().get_capabilities(domain_id.as_u64());
        tcb.security = Arc::new(DomainSecurity {
            credentials: DomainCredentials::ROOT,
            caps,
        });
        let boxed = Box::new(tcb);
        let current = Box::into_raw(boxed);
        unsafe {
            set_current_task(cpu_id, current);
        }
        CurrentTaskGuard { prev, current }
    }

    #[test_case]
    fn test_null_device() {
        let null = NullDevice;

        let mut buf = [0u8; 10];
        assert_eq!(null.read(0, &mut buf).unwrap(), 0);

        let data = b"test";
        assert_eq!(null.write(0, data).unwrap(), 4);
    }

    #[test_case]
    fn test_zero_device() {
        let zero = ZeroDevice;

        let mut buf = [1u8; 10];
        assert_eq!(zero.read(0, &mut buf).unwrap(), 10);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test_case]
    fn test_random_device() {
        let random = RandomDevice::new();

        let mut buf1 = [0u8; 8];
        let mut buf2 = [0u8; 8];

        random.read(0, &mut buf1).unwrap();
        random.read(0, &mut buf2).unwrap();

        // 異なる値が生成される(ほぼ確実)
        assert_ne!(buf1, buf2);
    }

    #[test_case]
    fn test_dev_open_with_token_reclaim() {
        // Setup: create caller and target domains
        let caller = DomainId::new(500);
        let target = DomainId::new(501);

        // Caller gets permission to grant CAP_FOWNER
        manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_FOWNER));
        let _caller_guard = set_current_subject(caller);

        // Grant token to target
        let token = manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), CAP_FOWNER, None, false)
            .unwrap();

        // Target opens using token
        let handle = {
            let _target_guard = set_current_subject(target);
            DevFileHandle::open_with_token("null", Some(token)).expect("open should succeed")
        };
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        assert!(manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        {
            let _target_guard = set_current_subject(target);
            drop(handle);
        }

        assert_eq!(manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        assert!(manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_devfs_structure() {
        let fs = DevFs::new();

        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("null")));
        assert!(entries.contains(&String::from("zero")));
        assert!(entries.contains(&String::from("random")));
    }

    #[test_case]
    fn test_find_block_device_by_number() {
        struct TestBlockDevice;
        impl DeviceOps for TestBlockDevice {
            fn open(&self) -> Result<(), DevError> { Ok(()) }
            fn close(&self) -> Result<(), DevError> { Ok(()) }
            fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize, DevError> { Ok(0) }
            fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize, DevError> { Ok(0) }
            fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, DevError> { Ok(0) }
        }

        let fs = DevFs::new();
        let devnum = DeviceNumber::new(8, 9);
        fs.register_block_device("testblk", devnum, Arc::new(TestBlockDevice));

        let ops = fs.find_block_device_by_number(devnum).expect("block device should be found by number");
        ops.open().unwrap();
        ops.close().unwrap();
    }
}

