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

/// Process-like identifier for procfs path compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Pid(u32);

impl Pid {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

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

fn read_sysinfo_str(f: fn() -> alloc::string::String) -> Result<String, ProcError> {
    Ok(f())
}

fn read_sysinfo_static(val: &'static str) -> Result<String, ProcError> {
    Ok(alloc::format!("{}\n", val))
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
        use crate::system_info as si;
        self.add_file("version", || {
            Ok(alloc::format!(
                "ExoRust Kernel {} ({}) (gcc version 12.0.0)\n",
                si::kernel_version(),
                si::arch_name()
            ))
        });
        self.add_file("uptime", || {
            let ticks = si::uptime_ticks();
            let secs = ticks / 1000;
            let frac = (ticks % 1000) / 10;
            let idle_secs = secs * 9 / 10;
            let idle_frac = frac * 9 / 10;
            Ok(alloc::format!("{}.{:02} {}.{:02}\n", secs, frac, idle_secs, idle_frac))
        });
        self.add_file("meminfo", || {
            let total_kb = si::memory_total_kb();
            let free_kb = si::memory_free_kb();
            let available_kb = free_kb + (free_kb / 4);
            let used_kb = total_kb.saturating_sub(free_kb);
            Ok(alloc::format!(
                "MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\nBuffers:        {:8} kB\nCached:         {:8} kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n",
                total_kb, free_kb, available_kb, used_kb / 8, used_kb / 4
            ))
        });
        self.add_file("cpuinfo", || {
            let count = si::cpu_count();
            let vendor = si::cpu_vendor();
            let model = si::cpu_model();
            let mut info = String::new();
            for id in 0..count {
                use core::fmt::Write;
                let _ = write!(info,
                    "processor\t: {}\nvendor_id\t: {}\ncpu family\t: 6\nmodel name\t: {}\ncpu MHz\t\t: 3000.000\ncache size\t: 8192 KB\nsiblings\t: {}\ncore id\t\t: {}\ncpu cores\t: {}\n\n",
                    id, vendor, model, count, id, count
                );
            }
            Ok(info)
        });
        self.add_file("stat", || {
            let timer = si::timer_ticks();
            let ctx = si::context_switch_count();
            let boot = si::boot_time_secs();
            let domains = crate::domain_system::list_domain_snapshots().len() as u64;
            let cpu_count = si::cpu_count();
            let mut out = String::new();
            use core::fmt::Write;
            let _ = write!(out, "cpu  {} 0 {} 0 0 0 {} 0 0 0\n", timer / 10, timer / 5, timer / 20);
            for i in 0..cpu_count {
                let _ = write!(out, "cpu{} {} 0 {} 0 0 0 {} 0 0 0\n",
                    i, timer / (10 * cpu_count as u64), timer / (5 * cpu_count as u64), timer / (20 * cpu_count as u64));
            }
            let _ = write!(out, "intr {}\nctxt {}\nbtime {}\nprocesses {}\nprocs_running 1\nprocs_blocked 0\n",
                timer, ctx, boot, domains);
            Ok(out)
        });
        self.add_file("loadavg", || Ok(String::from("0.00 0.00 0.00 1/1 1\n")));
        self.add_file("filesystems", || Ok(String::from("nodev\ttmpfs\n")));
        self.add_file("mounts", || Ok(String::from("")));
        self.add_file("cmdline", || Ok(String::from("console=ttyS0\n")));
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
            ProcEntry::file(hostname_inode, "hostname", || Ok(String::from("exorust\n")));
        kernel_entry.add_child(hostname_entry);

        let ostype_inode = self.allocate_inode();
        let ostype_entry =
            ProcEntry::file(ostype_inode, "ostype", || {
                Ok(alloc::format!("{}\n", crate::system_info::kernel_name()))
            });
        kernel_entry.add_child(ostype_entry);

        let version_inode = self.allocate_inode();
        let version_entry =
            ProcEntry::file(version_inode, "version", || {
                Ok(alloc::format!("#1 SMP ExoRust {}\n", crate::system_info::kernel_version()))
            });
        kernel_entry.add_child(version_entry);

        let mut root = self.root.write();
        if let Some(sys_dir) = root.children.get_mut("sys") {
            sys_dir.add_child(kernel_entry);
        }
    }

    /// net エントリを追加
    fn add_net_entries(&self) {
        let net_generators: &[(&str, fn() -> Result<String, ProcError>)] = &[
            ("dev", || {
                let mut out = String::from(
                    "Inter-|   Receive                                                |  Transmit\n\
                     face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
                out.push_str("    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
                out.push_str("  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
                Ok(out)
            }),
            ("tcp", || Ok(String::from(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"))),
            ("udp", || Ok(String::from(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"))),
            ("arp", || Ok(String::from(
                "IP address       HW type     Flags       HW address            Mask     Device\n"))),
        ];

        for &(name, gen_fn) in net_generators {
            let inode = self.allocate_inode();
            let entry = ProcEntry::file(inode, name, gen_fn);
            let mut root = self.root.write();
            if let Some(net_dir) = root.children.get_mut("net") {
                net_dir.add_child(entry);
            }
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
    let proc_domain = DomainId::new(pid.as_u32() as u64);
    if crate::domain_system::get_domain_snapshot(proc_domain).is_none() {
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
        let proc_domain = DomainId::new(pid.as_u32() as u64);
        if crate::domain_system::get_domain_snapshot(proc_domain).is_none() {
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
