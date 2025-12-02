//! procfs - Process Filesystem
//!
//! /proc ファイルシステムの実装
//! プロセス情報やカーネル状態を仮想ファイルとして公開

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

/// inode番号 (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ProcInode(u64);

impl ProcInode {
    pub const ROOT: Self = Self(1);
    
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// プロセスID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Pid(u32);

impl Pid {
    pub const KERNEL: Self = Self(0);
    pub const INIT: Self = Self(1);

    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// ファイルタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcFileType {
    /// ディレクトリ
    Directory,
    /// 通常ファイル
    File,
    /// シンボリックリンク
    Symlink,
}

/// procfs エントリ
pub struct ProcEntry {
    /// inode
    pub inode: ProcInode,
    /// ファイル名
    pub name: String,
    /// ファイルタイプ
    pub file_type: ProcFileType,
    /// 読み取りハンドラ
    pub read_fn: Option<Box<dyn Fn() -> String + Send + Sync>>,
    /// 書き込みハンドラ
    pub write_fn: Option<Box<dyn Fn(&str) -> Result<(), ProcError> + Send + Sync>>,
    /// 子エントリ (ディレクトリの場合)
    pub children: BTreeMap<String, ProcEntry>,
}

impl ProcEntry {
    /// 新しいディレクトリエントリ
    pub fn directory(inode: ProcInode, name: &str) -> Self {
        Self {
            inode,
            name: String::from(name),
            file_type: ProcFileType::Directory,
            read_fn: None,
            write_fn: None,
            children: BTreeMap::new(),
        }
    }

    /// 新しいファイルエントリ
    pub fn file<F>(inode: ProcInode, name: &str, read_fn: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        Self {
            inode,
            name: String::from(name),
            file_type: ProcFileType::File,
            read_fn: Some(Box::new(read_fn)),
            write_fn: None,
            children: BTreeMap::new(),
        }
    }

    /// 書き込み可能ファイルエントリ
    pub fn writable_file<R, W>(inode: ProcInode, name: &str, read_fn: R, write_fn: W) -> Self
    where
        R: Fn() -> String + Send + Sync + 'static,
        W: Fn(&str) -> Result<(), ProcError> + Send + Sync + 'static,
    {
        Self {
            inode,
            name: String::from(name),
            file_type: ProcFileType::File,
            read_fn: Some(Box::new(read_fn)),
            write_fn: Some(Box::new(write_fn)),
            children: BTreeMap::new(),
        }
    }

    /// シンボリックリンクエントリ
    pub fn symlink(inode: ProcInode, name: &str, target: String) -> Self {
        Self {
            inode,
            name: String::from(name),
            file_type: ProcFileType::Symlink,
            read_fn: Some(Box::new(move || target.clone())),
            write_fn: None,
            children: BTreeMap::new(),
        }
    }

    /// 子エントリを追加
    pub fn add_child(&mut self, entry: ProcEntry) {
        self.children.insert(entry.name.clone(), entry);
    }
}

/// procfs エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    /// エントリが見つからない
    NotFound,
    /// ディレクトリではない
    NotDirectory,
    /// 読み取り不可
    NotReadable,
    /// 書き込み不可
    NotWritable,
    /// 権限なし
    PermissionDenied,
    /// 無効な引数
    InvalidArgument,
}

/// procfs ファイルシステム
pub struct ProcFs {
    /// ルートエントリ
    root: spin::RwLock<ProcEntry>,
    /// 次のinode番号
    next_inode: AtomicU64,
}

impl ProcFs {
    /// 新しいprocfsを作成
    pub fn new() -> Self {
        let mut root = ProcEntry::directory(ProcInode::ROOT, "");
        
        let fs = Self {
            root: spin::RwLock::new(root),
            next_inode: AtomicU64::new(2),
        };

        fs.init_static_entries();
        fs
    }

    /// 静的エントリを初期化
    fn init_static_entries(&self) {
        // /proc/version
        self.add_file("version", || {
            alloc::format!(
                "ExoRust Kernel {} ({}) (gcc version 12.0.0)\n",
                env!("CARGO_PKG_VERSION"),
                "x86_64"
            )
        });

        // /proc/uptime
        self.add_file("uptime", || {
            // TODO: 実際のuptime計算
            alloc::format!("{}.{} {}.{}\n", 0, 0, 0, 0)
        });

        // /proc/meminfo
        self.add_file("meminfo", Self::generate_meminfo);

        // /proc/cpuinfo
        self.add_file("cpuinfo", Self::generate_cpuinfo);

        // /proc/stat
        self.add_file("stat", Self::generate_stat);

        // /proc/loadavg
        self.add_file("loadavg", || {
            alloc::format!("0.00 0.00 0.00 1/1 1\n")
        });

        // /proc/filesystems
        self.add_file("filesystems", || {
            alloc::format!(
                "nodev\tproc\n\
                 nodev\tdevfs\n\
                 \text2\n\
                 nodev\ttmpfs\n"
            )
        });

        // /proc/mounts
        self.add_file("mounts", || {
            alloc::format!(
                "proc /proc proc rw,nosuid,nodev,noexec 0 0\n\
                 devfs /dev devfs rw,nosuid 0 0\n"
            )
        });

        // /proc/cmdline
        self.add_file("cmdline", || {
            alloc::format!("console=ttyS0\n")
        });

        // /proc/sys ディレクトリ
        self.add_directory("sys");
        self.add_sys_entries();

        // /proc/net ディレクトリ
        self.add_directory("net");
        self.add_net_entries();
    }

    /// sys エントリを追加
    fn add_sys_entries(&self) {
        // TODO: sysctl 変数
    }

    /// net エントリを追加
    fn add_net_entries(&self) {
        // TODO: ネットワーク統計
    }

    /// 次のinode番号を取得
    fn allocate_inode(&self) -> ProcInode {
        ProcInode::new(self.next_inode.fetch_add(1, Ordering::AcqRel))
    }

    /// ファイルを追加
    pub fn add_file<F>(&self, name: &str, read_fn: F)
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        let inode = self.allocate_inode();
        let entry = ProcEntry::file(inode, name, read_fn);
        
        let mut root = self.root.write();
        root.add_child(entry);
    }

    /// ディレクトリを追加
    pub fn add_directory(&self, name: &str) {
        let inode = self.allocate_inode();
        let entry = ProcEntry::directory(inode, name);
        
        let mut root = self.root.write();
        root.add_child(entry);
    }

    /// プロセスエントリを追加
    pub fn add_process(&self, pid: Pid) {
        let pid_str = alloc::format!("{}", pid.as_u32());
        
        let mut proc_dir = ProcEntry::directory(self.allocate_inode(), &pid_str);
        
        // /proc/[pid]/status
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "status",
            move || Self::generate_process_status(pid_copy),
        ));

        // /proc/[pid]/stat
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "stat",
            move || Self::generate_process_stat(pid_copy),
        ));

        // /proc/[pid]/maps
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "maps",
            move || Self::generate_process_maps(pid_copy),
        ));

        // /proc/[pid]/cmdline
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "cmdline",
            move || Self::generate_process_cmdline(pid_copy),
        ));

        // /proc/[pid]/exe (symlink)
        proc_dir.add_child(ProcEntry::symlink(
            self.allocate_inode(),
            "exe",
            String::from("/bin/process"),
        ));

        // /proc/[pid]/cwd (symlink)
        proc_dir.add_child(ProcEntry::symlink(
            self.allocate_inode(),
            "cwd",
            String::from("/"),
        ));

        // /proc/[pid]/fd ディレクトリ
        proc_dir.add_child(ProcEntry::directory(self.allocate_inode(), "fd"));

        let mut root = self.root.write();
        root.add_child(proc_dir);
    }

    /// プロセスエントリを削除
    pub fn remove_process(&self, pid: Pid) {
        let pid_str = alloc::format!("{}", pid.as_u32());
        let mut root = self.root.write();
        root.children.remove(&pid_str);
    }

    /// パスからエントリを検索
    pub fn lookup(&self, path: &str) -> Result<ProcInode, ProcError> {
        let root = self.root.read();
        let mut current = &*root;
        
        for component in path.split('/').filter(|s| !s.is_empty()) {
            match current.children.get(component) {
                Some(entry) => current = entry,
                None => return Err(ProcError::NotFound),
            }
        }
        
        Ok(current.inode)
    }

    /// ファイルを読み取り
    pub fn read(&self, path: &str) -> Result<String, ProcError> {
        let root = self.root.read();
        let mut current = &*root;
        
        for component in path.split('/').filter(|s| !s.is_empty()) {
            match current.children.get(component) {
                Some(entry) => current = entry,
                None => return Err(ProcError::NotFound),
            }
        }
        
        match &current.read_fn {
            Some(read_fn) => Ok(read_fn()),
            None => Err(ProcError::NotReadable),
        }
    }

    /// ディレクトリ一覧を取得
    pub fn readdir(&self, path: &str) -> Result<Vec<String>, ProcError> {
        let root = self.root.read();
        let mut current = &*root;
        
        if !path.is_empty() && path != "/" {
            for component in path.split('/').filter(|s| !s.is_empty()) {
                match current.children.get(component) {
                    Some(entry) => current = entry,
                    None => return Err(ProcError::NotFound),
                }
            }
        }
        
        if current.file_type != ProcFileType::Directory {
            return Err(ProcError::NotDirectory);
        }
        
        Ok(current.children.keys().cloned().collect())
    }

    // --- 情報生成関数 ---

    fn generate_meminfo() -> String {
        // TODO: 実際のメモリ情報
        alloc::format!(
            "MemTotal:       16777216 kB\n\
             MemFree:         8388608 kB\n\
             MemAvailable:   12582912 kB\n\
             Buffers:          524288 kB\n\
             Cached:          2097152 kB\n\
             SwapCached:            0 kB\n\
             Active:          4194304 kB\n\
             Inactive:        2097152 kB\n\
             SwapTotal:             0 kB\n\
             SwapFree:              0 kB\n"
        )
    }

    fn generate_cpuinfo() -> String {
        // TODO: 実際のCPU情報
        alloc::format!(
            "processor\t: 0\n\
             vendor_id\t: GenuineIntel\n\
             cpu family\t: 6\n\
             model\t\t: 142\n\
             model name\t: Intel(R) Core(TM) i7\n\
             stepping\t: 10\n\
             cpu MHz\t\t: 3000.000\n\
             cache size\t: 8192 KB\n\
             physical id\t: 0\n\
             siblings\t: 8\n\
             core id\t\t: 0\n\
             cpu cores\t: 4\n\
             flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic\n\
             bugs\t\t:\n\
             bogomips\t: 6000.00\n\n"
        )
    }

    fn generate_stat() -> String {
        // TODO: 実際の統計情報
        alloc::format!(
            "cpu  0 0 0 0 0 0 0 0 0 0\n\
             cpu0 0 0 0 0 0 0 0 0 0 0\n\
             intr 0\n\
             ctxt 0\n\
             btime 0\n\
             processes 1\n\
             procs_running 1\n\
             procs_blocked 0\n\
             softirq 0 0 0 0 0 0 0 0 0 0 0\n"
        )
    }

    fn generate_process_status(pid: Pid) -> String {
        // TODO: 実際のプロセス状態
        alloc::format!(
            "Name:\tunknown\n\
             Umask:\t0022\n\
             State:\tS (sleeping)\n\
             Tgid:\t{}\n\
             Ngid:\t0\n\
             Pid:\t{}\n\
             PPid:\t1\n\
             TracerPid:\t0\n\
             Uid:\t0\t0\t0\t0\n\
             Gid:\t0\t0\t0\t0\n\
             FDSize:\t64\n\
             VmPeak:\t    4096 kB\n\
             VmSize:\t    4096 kB\n\
             VmRSS:\t    1024 kB\n\
             Threads:\t1\n",
            pid.as_u32(),
            pid.as_u32()
        )
    }

    fn generate_process_stat(pid: Pid) -> String {
        // TODO: 実際のプロセス統計
        alloc::format!(
            "{} (unknown) S 1 {} {} 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            pid.as_u32(),
            pid.as_u32(),
            pid.as_u32()
        )
    }

    fn generate_process_maps(pid: Pid) -> String {
        // TODO: 実際のメモリマップ
        alloc::format!(
            "00400000-00401000 r-xp 00000000 00:00 0          /bin/process\n\
             00600000-00601000 r--p 00000000 00:00 0          /bin/process\n\
             00601000-00602000 rw-p 00001000 00:00 0          /bin/process\n\
             7ffff7ff8000-7ffff7ffa000 r-xp 00000000 00:00 0  [vdso]\n\
             7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0  [stack]\n"
        )
    }

    fn generate_process_cmdline(_pid: Pid) -> String {
        // TODO: 実際のコマンドライン
        String::from("/bin/process\0")
    }
}

/// グローバル procfs インスタンス
static PROCFS: spin::Once<ProcFs> = spin::Once::new();

/// procfs を取得
pub fn procfs() -> &'static ProcFs {
    PROCFS.call_once(ProcFs::new)
}

/// 初期化
pub fn init() {
    let _ = procfs();
}

// --- VFS統合用トレイト ---

/// procfs ファイル操作
pub trait ProcFileOps {
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, ProcError>;
    fn write(&self, offset: usize, buf: &[u8]) -> Result<usize, ProcError>;
}

/// procfs ファイルハンドル
pub struct ProcFileHandle {
    path: String,
    content: String,
    position: AtomicUsize,
}

impl ProcFileHandle {
    pub fn open(path: &str) -> Result<Self, ProcError> {
        let content = procfs().read(path)?;
        Ok(Self {
            path: String::from(path),
            content,
            position: AtomicUsize::new(0),
        })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ProcError> {
        let pos = self.position.load(Ordering::Acquire);
        let bytes = self.content.as_bytes();
        
        if pos >= bytes.len() {
            return Ok(0);
        }
        
        let remaining = &bytes[pos..];
        let to_read = buf.len().min(remaining.len());
        buf[..to_read].copy_from_slice(&remaining[..to_read]);
        
        self.position.fetch_add(to_read, Ordering::AcqRel);
        Ok(to_read)
    }

    pub fn seek(&self, pos: usize) {
        self.position.store(pos, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_procfs_read() {
        let fs = ProcFs::new();
        
        let version = fs.read("version").unwrap();
        assert!(version.contains("ExoRust"));
    }

    #[test]
    fn test_procfs_directory() {
        let fs = ProcFs::new();
        
        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("version")));
        assert!(entries.contains(&String::from("meminfo")));
    }

    #[test]
    fn test_process_entries() {
        let fs = ProcFs::new();
        
        fs.add_process(Pid::new(1234));
        
        let status = fs.read("1234/status").unwrap();
        assert!(status.contains("Pid:\t1234"));
        
        fs.remove_process(Pid::new(1234));
        assert!(fs.lookup("1234").is_err());
    }
}
