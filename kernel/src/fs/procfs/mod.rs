//! procfs - Process Filesystem
//!
//! /proc ファイルシステムの実装
//! プロセス情報やカーネル状態を仮想ファイルとして公開

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::domain_system::DomainId;
use crate::task::process::{ProcessId, process_manager};

#[path = "../../compat/posix/procfs_pid.rs"]
mod pid;
pub use pid::Pid;

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
    /// 読み取りハンドラ (権限チェックのため Result を返す)
    pub read_fn: Option<Box<dyn Fn() -> Result<String, ProcError> + Send + Sync>>,
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
        F: Fn() -> Result<String, ProcError> + Send + Sync + 'static,
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
        R: Fn() -> Result<String, ProcError> + Send + Sync + 'static,
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
            read_fn: Some(Box::new(move || Ok(target.clone()))),
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

fn read_sysfs_text(path: &str) -> Result<String, ProcError> {
    match crate::fs::sysfs::read_file(path) {
        Some(Ok(bytes)) => String::from_utf8(bytes).map_err(|_| ProcError::NotReadable),
        Some(Err(_)) => Err(ProcError::NotFound),
        None => Err(ProcError::NotFound),
    }
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
        let root = ProcEntry::directory(ProcInode::ROOT, "");

        let fs = Self {
            root: spin::RwLock::new(root),
            next_inode: AtomicU64::new(2),
        };

        fs.init_static_entries();
        fs
    }

    /// /proc 直下のシステムファイルを登録する
    fn add_system_files(&self) {
        self.add_file("version", || read_sysfs_text("/sys/system/version"));
        self.add_file("uptime", || read_sysfs_text("/sys/system/uptime"));
        self.add_file("meminfo", || read_sysfs_text("/sys/system/meminfo"));
        self.add_file("cpuinfo", || read_sysfs_text("/sys/system/cpuinfo"));
        self.add_file("stat", || read_sysfs_text("/sys/system/stat"));
        self.add_file("loadavg", || read_sysfs_text("/sys/system/loadavg"));
        self.add_file("filesystems", || read_sysfs_text("/sys/system/filesystems"));
        self.add_file("mounts", || read_sysfs_text("/sys/system/mounts"));
        self.add_file("cmdline", || read_sysfs_text("/sys/system/cmdline"));
    }

    /// 静的エントリを初期化
    fn init_static_entries(&self) {
        // /proc/* system surface delegates to /sys/system
        self.add_system_files();

        // /proc/sys ディレクトリ
        self.add_directory("sys");
        self.add_sys_entries();

        // /proc/net ディレクトリ
        self.add_directory("net");
        self.add_net_entries();
    }

    /// sys エントリを追加
    fn add_sys_entries(&self) {
        // sysctl-style entries under /proc/sys/kernel
        let kernel_inode = self.allocate_inode();
        let mut kernel_entry = ProcEntry::directory(kernel_inode, "kernel");

        let hostname_inode = self.allocate_inode();
        let hostname_entry =
            ProcEntry::file(hostname_inode, "hostname", || read_sysfs_text("/sys/system/kernel/hostname"));
        kernel_entry.add_child(hostname_entry);

        let ostype_inode = self.allocate_inode();
        let ostype_entry =
            ProcEntry::file(ostype_inode, "ostype", || read_sysfs_text("/sys/system/kernel/ostype"));
        kernel_entry.add_child(ostype_entry);

        let version_inode = self.allocate_inode();
        let version_entry =
            ProcEntry::file(version_inode, "version", || read_sysfs_text("/sys/system/kernel/version"));
        kernel_entry.add_child(version_entry);

        let mut root = self.root.write();
        if let Some(sys_dir) = root.children.get_mut("sys") {
            sys_dir.add_child(kernel_entry);
        }
    }

    /// net エントリを追加
    fn add_net_entries(&self) {
        // /proc/net/dev - ネットワークデバイス統計
        let dev_inode = self.allocate_inode();
        let dev_entry = ProcEntry::file(dev_inode, "dev", || read_sysfs_text("/sys/system/net/dev"));
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(dev_entry);
        }
        drop(root);

        // /proc/net/tcp - TCP接続情報
        let tcp_inode = self.allocate_inode();
        let tcp_entry = ProcEntry::file(tcp_inode, "tcp", || read_sysfs_text("/sys/system/net/tcp"));
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(tcp_entry);
        }
        drop(root);

        // /proc/net/udp - UDP接続情報
        let udp_inode = self.allocate_inode();
        let udp_entry = ProcEntry::file(udp_inode, "udp", || read_sysfs_text("/sys/system/net/udp"));
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(udp_entry);
        }
        drop(root);

        // /proc/net/arp - ARPテーブル
        let arp_inode = self.allocate_inode();
        let arp_entry = ProcEntry::file(arp_inode, "arp", || read_sysfs_text("/sys/system/net/arp"));
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(arp_entry);
        }
    }

    /// 次のinode番号を取得
    fn allocate_inode(&self) -> ProcInode {
        ProcInode::new(self.next_inode.fetch_add(1, Ordering::AcqRel))
    }

    /// ファイルを追加
    pub fn add_file<F>(&self, name: &str, read_fn: F)
    where
        F: Fn() -> Result<String, ProcError> + Send + Sync + 'static,
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
            Some(read_fn) => read_fn(),
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

    /// Read with an optional token for permissioned dynamic entries (e.g., `/proc/<pid>/fd/<n>`).
    pub fn read_with_token(&self, path: &str, token: Option<u64>) -> Result<String, ProcError> {
        use crate::task::context;
        let caller = context::current_subject().domain;
        let comps: alloc::vec::Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if comps.len() >= 3 && comps[comps.len() - 2] == "fd" {
            return resolve_fd_entry(&comps, caller, token);
        }
        self.read(path)
    }

}

/// fdアクセス権限を検証する
fn check_fd_access_permission(
    caller: DomainId,
    proc_domain: DomainId,
    token: Option<u64>,
) -> bool {
    if caller == proc_domain {
        return true;
    }
    let mgr = crate::security::capability::manager();
    let id = caller.as_u64();
    if mgr.has_capability(id, crate::security::capability::CAP_FOWNER)
        || mgr.has_capability(id, crate::security::capability::CAP_SYS_PTRACE)
        || mgr.has_capability(id, crate::security::capability::CAP_SYS_ADMIN)
    {
        return true;
    }
    token.is_some_and(|t| mgr.validate_token(id, t, crate::security::capability::CAP_FOWNER))
}

/// fdパスエントリを解決する
fn resolve_fd_entry(
    comps: &[&str],
    caller: DomainId,
    token: Option<u64>,
) -> Result<String, ProcError> {
    let pid_num = comps[comps.len() - 3]
        .parse::<u32>()
        .map_err(|_| ProcError::InvalidArgument)?;
    let pid = Pid::new(pid_num);
    let proc_id = ProcessId::new(pid.as_u32() as u64);
    let proc_domain: DomainId = proc_id.into();
    if process_manager().get(proc_id).is_none() {
        return Err(ProcError::NotFound);
    }
    if !check_fd_access_permission(caller, proc_domain, token) {
        return Err(ProcError::PermissionDenied);
    }
    let handle_id = comps
        .last()
        .unwrap()
        .parse::<u64>()
        .map_err(|_| ProcError::InvalidArgument)?;
    crate::service_impl::file_handle_path(handle_id).ok_or(ProcError::NotFound)
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
    token: Option<u64>,
}

impl ProcFileHandle {
    pub fn open(path: &str) -> Result<Self, ProcError> {
        // Backward-compatible: open without token
        Self::open_with_token(path, None)
    }

    /// パスに応じた必要ケーパビリティを判定
    fn determine_required_capability(comps: &[&str]) -> u64 {
        let last = match comps.last() {
            Some(l) => *l,
            None => return crate::security::capability::CAP_SYS_PTRACE,
        };
        match last {
            "mem" | "maps" | "cmdline" => crate::security::capability::CAP_SYS_PTRACE,
            "exe" | "fd" => crate::security::capability::CAP_FOWNER,
            _ if comps.len() >= 2 && comps[comps.len()-2] == "fd" => {
                crate::security::capability::CAP_FOWNER
            }
            _ => crate::security::capability::CAP_SYS_PTRACE,
        }
    }

    pub fn open_with_token(path: &str, token: Option<u64>) -> Result<Self, ProcError> {
        use crate::task::context;

        let caller = context::current_subject().domain;
        let comps: alloc::vec::Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let required_cap = Self::determine_required_capability(&comps);

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller.as_u64(), t, required_cap) {
                return Err(ProcError::PermissionDenied);
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(ProcError::PermissionDenied);
            }
        }

        let content = match procfs().read_with_token(path, token) {
            Ok(c) => c,
            Err(e) => {
                // Rollback in-flight on failure
                if let Some(t) = token {
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                return Err(e);
            }
        };

        Ok(Self {
            path: String::from(path),
            content,
            position: AtomicUsize::new(0),
            token,
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

impl Drop for ProcFileHandle {
    fn drop(&mut self) {
        if let Some(t) = self.token {
            let _ = crate::security::capability::manager().decrement_in_flight(t);
        }
    }
}

/// Directory handle that may hold a token (in-flight counted)
pub struct ProcDirHandle {
    path: String,
    token: Option<u64>,
}

impl ProcDirHandle {
    /// Read directory entries. For `/proc/<pid>/fd` this enforces permission checks
    /// using caller identity, capabilities, or an associated token.
    pub fn readdir(&self) -> Result<Vec<String>, ProcError> {
        use crate::task::context;
        let caller = context::current_subject().domain;

        // If this is a per-process fd directory, do permission checks
        let comps: alloc::vec::Vec<&str> = self.path.split('/').filter(|s| !s.is_empty()).collect();
        if comps.len() >= 2 && comps[comps.len() - 1] == "fd" {
            return self.readdir_fd(&comps, caller);
        }

        // Fallback to regular readdir for other directories
        procfs().readdir(&self.path)
    }

    /// /proc/<pid>/fd の読み取りと権限チェック
    fn readdir_fd(
        &self,
        comps: &[&str],
        caller: DomainId,
    ) -> Result<Vec<String>, ProcError> {
        let pid_comp = comps[comps.len() - 2];
        let pid_num = pid_comp.parse::<u32>().map_err(|_| ProcError::InvalidArgument)?;
        let pid = Pid::new(pid_num);
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        let proc_domain: DomainId = proc_id.into();
        if process_manager().get(proc_id).is_none() {
            return Err(ProcError::NotFound);
        }

        if !self.is_fd_access_allowed(caller, proc_domain) {
            return Err(ProcError::PermissionDenied);
        }

        let owner_id = proc_domain.as_u64();
        let handles = crate::service_impl::file_handles_for_owner(owner_id);
        let mut entries: alloc::vec::Vec<String> = handles.iter().map(|id| id.to_string()).collect();
        entries.sort();
        Ok(entries)
    }

    /// fd ディレクトリへのアクセス権限を判定
    fn is_fd_access_allowed(&self, caller: DomainId, proc_domain: DomainId) -> bool {
        if caller == proc_domain {
            return true;
        }
        if crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_FOWNER)
            || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
            || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
        {
            return true;
        }
        if let Some(t) = self.token {
            if crate::security::capability::manager().validate_token(caller.as_u64(), t, crate::security::capability::CAP_FOWNER) {
                return true;
            }
        }
        false
    }
}

impl Drop for ProcDirHandle {
    fn drop(&mut self) {
        if let Some(t) = self.token {
            let _ = crate::security::capability::manager().decrement_in_flight(t);
        }
    }
}

impl ProcFs {
    /// Validate and increment in-flight for a capability token.
    fn validate_and_acquire_token(
        caller_domain: u64,
        token: Option<u64>,
        required_cap: u64,
    ) -> Result<(), ProcError> {
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller_domain, t, required_cap) {
                return Err(ProcError::PermissionDenied);
            }
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(ProcError::PermissionDenied);
            }
        }
        Ok(())
    }

    /// Release in-flight tracking for a token and return an error.
    fn release_token_and_fail(token: Option<u64>, err: ProcError) -> Result<ProcDirHandle, ProcError> {
        if let Some(t) = token {
            let _ = crate::security::capability::manager().decrement_in_flight(t);
        }
        Err(err)
    }

    /// Open a directory and optionally bind it to a token (increment in-flight).
    pub fn opendir_with_token(&self, path: &str, token: Option<u64>) -> Result<ProcDirHandle, ProcError> {
        use crate::task::context;
        let caller = context::current_subject().domain;

        // Required capability for fd directory is CAP_FOWNER
        let required_cap = crate::security::capability::CAP_FOWNER;

        Self::validate_and_acquire_token(caller.as_u64(), token, required_cap)?;

        // Verify path exists and is directory
        let root = self.root.read();
        let mut current = &*root;
        if !path.is_empty() && path != "/" {
            for component in path.split('/').filter(|s| !s.is_empty()) {
                match current.children.get(component) {
                    Some(entry) => current = entry,
                    None => return Self::release_token_and_fail(token, ProcError::NotFound),
                }
            }
        }

        if current.file_type != ProcFileType::Directory {
            return Self::release_token_and_fail(token, ProcError::NotDirectory);
        }

        Ok(ProcDirHandle { path: String::from(path), token })
    }
}
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test_case]
    fn test_procfs_read() {
        let fs = ProcFs::new();

        let version = fs.read("version").unwrap();
        assert!(version.contains("ExoRust"));
    }

    #[test_case]
    fn test_procfs_directory() {
        let fs = ProcFs::new();

        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("version")));
        assert!(entries.contains(&String::from("meminfo")));
    }

    #[test_case]
    fn test_process_entries() {
        let fs = ProcFs::new();

        fs.add_process(Pid::new(1234));

        let status = fs.read("1234/status").unwrap();
        assert!(status.contains("Pid:\t1234"));

        fs.remove_process(Pid::new(1234));
        assert!(fs.lookup("1234").is_err());
    }

    #[test_case]
    fn test_proc_mem_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_proc").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_proc").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/mem", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_mem_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_proc_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_proc_stress").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/mem", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_maps_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_maps").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_maps").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/maps", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_maps_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_maps_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_maps_stress").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/maps", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_cmdline_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_cmdline").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_cmdline").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/cmdline", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_cmdline_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_cmdline_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_cmdline_stress").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/cmdline", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_fd_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_fd").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens fd directory using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/fd", target.as_u64());
        let handle = procfs().opendir_with_token(&path, Some(token)).expect("opendir should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_fd_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_fd_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd_stress").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/fd", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = procfs().opendir_with_token(&path, Some(tok)).expect("opendir should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_exe_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_exe").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_exe").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens exe using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/exe", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_exe_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_exe_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_exe_stress").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/exe", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    fn test_proc_fd_listing_shows_open_handles() {
        // Create target process
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd_list").unwrap();

        // Make sure procfs entry exists
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Set current process to target and open a file
        crate::task::process::set_current_process(target);
        let handle = crate::service_impl::EXOKERNEL
            .fs_open_with_token("test_proc_fd_file", crate::OpenMode::Write, None)
            .expect("open should succeed");

        // Read fd dir
        let entries = procfs().readdir(&alloc::format!("{}/fd", target.as_u64())).expect("readdir should succeed");
        assert!(entries.contains(&handle.id().to_string()));

        // Close handle
        crate::service_impl::EXOKERNEL.fs_close(handle).expect("close should succeed");
    }
}


