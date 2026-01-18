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
use crate::task::process::{ProcessState, ProcessId, process_manager};

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

    /// 静的エントリを初期化
    fn init_static_entries(&self) {
        // /proc/version
        self.add_file("version", || {
            Ok(alloc::format!(
                "ExoRust Kernel {} ({}) (gcc version 12.0.0)\n",
                env!("CARGO_PKG_VERSION"),
                "x86_64"
            ))
        });

        // /proc/uptime
        self.add_file("uptime", || {
            // システム稼働時間を計算（ミリ秒から秒に変換）
            let uptime_ms = crate::time::current_tick();
            let uptime_secs = uptime_ms / 1000;
            let uptime_frac = (uptime_ms % 1000) / 10; // 小数点2桁
            // アイドル時間（簡易実装：稼働時間の90%と仮定）
            let idle_secs = uptime_secs * 9 / 10;
            let idle_frac = uptime_frac * 9 / 10;
            Ok(alloc::format!(
                "{}.{:02} {}.{:02}\n",
                uptime_secs,
                uptime_frac,
                idle_secs,
                idle_frac
            ))
        });

        // /proc/meminfo
        self.add_file("meminfo", || Ok(Self::generate_meminfo()));

        // /proc/cpuinfo
        self.add_file("cpuinfo", || Ok(Self::generate_cpuinfo()));

        // /proc/stat
        self.add_file("stat", || Ok(Self::generate_stat()));

        // /proc/loadavg
        self.add_file("loadavg", || Ok(alloc::format!("0.00 0.00 0.00 1/1 1\n")));

        // /proc/filesystems
        self.add_file("filesystems", || {
            Ok(alloc::format!(
                "nodev\tproc\n\
                 nodev\tdevfs\n\
                 \text2\n\
                 nodev\ttmpfs\n"
            ))
        });

        // /proc/mounts
        self.add_file("mounts", || {
            Ok(alloc::format!(
                "proc /proc proc rw,nosuid,nodev,noexec 0 0\n\
                 devfs /dev devfs rw,nosuid 0 0\n"
            ))
        });

        // /proc/cmdline
        self.add_file("cmdline", || Ok(alloc::format!("console=ttyS0\n")));

        // /proc/sys ディレクトリ
        self.add_directory("sys");
        self.add_sys_entries();

        // /proc/net ディレクトリ
        self.add_directory("net");
        self.add_net_entries();
    }

    /// sys エントリを追加
    fn add_sys_entries(&self) {
        // sysctlスタイルの設定エントリを追加
        // /proc/sys/kernel/hostname
        let hostname_inode = self.allocate_inode();
        let hostname_entry = ProcEntry::file(hostname_inode, "kernel/hostname", || {
            Ok(alloc::string::String::from("exorust\n"))
        });
        let mut root = self.root.write();
        if let Some(sys_dir) = root.children.get_mut("sys") {
            sys_dir.add_child(hostname_entry);
        }
        drop(root);

        // /proc/sys/kernel/ostype
        let ostype_inode = self.allocate_inode();
        let ostype_entry = ProcEntry::file(ostype_inode, "kernel/ostype", || {
            Ok(alloc::string::String::from("ExoRust\n"))
        });
        let mut root = self.root.write();
        if let Some(sys_dir) = root.children.get_mut("sys") {
            sys_dir.add_child(ostype_entry);
        }
        drop(root);

        // /proc/sys/kernel/version
        let version_inode = self.allocate_inode();
        let version_entry = ProcEntry::file(version_inode, "kernel/version", || {
            Ok(alloc::format!("#1 SMP {}\n", "ExoRust 0.1.0"))
        });
        let mut root = self.root.write();
        if let Some(sys_dir) = root.children.get_mut("sys") {
            sys_dir.add_child(version_entry);
        }
    }

    /// net エントリを追加
    fn add_net_entries(&self) {
        // /proc/net/dev - ネットワークデバイス統計
        let dev_inode = self.allocate_inode();
        let dev_entry = ProcEntry::file(dev_inode, "dev", || {
            let mut output = alloc::string::String::from(
                "Inter-|   Receive                                                |  Transmit\n\
                 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
            );
            // 仮想ネットワーク統計（将来的にはNetworkStackから取得）
            output.push_str("    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
            output.push_str("  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n");
            Ok(output)
        });
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(dev_entry);
        }
        drop(root);

        // /proc/net/tcp - TCP接続情報
        let tcp_inode = self.allocate_inode();
        let tcp_entry = ProcEntry::file(tcp_inode, "tcp", || {
            let output = alloc::string::String::from(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
            );
            // 将来的にはTcpProcessorから取得
            Ok(output)
        });
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(tcp_entry);
        }
        drop(root);

        // /proc/net/udp - UDP接続情報
        let udp_inode = self.allocate_inode();
        let udp_entry = ProcEntry::file(udp_inode, "udp", || {
            Ok(alloc::string::String::from(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
            ))
        });
        let mut root = self.root.write();
        if let Some(net_dir) = root.children.get_mut("net") {
            net_dir.add_child(udp_entry);
        }
        drop(root);

        // /proc/net/arp - ARPテーブル
        let arp_inode = self.allocate_inode();
        let arp_entry = ProcEntry::file(arp_inode, "arp", || {
            Ok(alloc::string::String::from(
                "IP address       HW type     Flags       HW address            Mask     Device\n",
            ))
        });
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

    /// プロセスエントリを追加
    pub fn add_process(&self, pid: Pid) {
        let pid_str = alloc::format!("{}", pid.as_u32());

        let mut proc_dir = ProcEntry::directory(self.allocate_inode(), &pid_str);

        // /proc/[pid]/status
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "status",
            move || Ok(Self::generate_process_status(pid_copy)),
        ));

        // /proc/[pid]/stat
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(self.allocate_inode(), "stat", move || {
            Ok(Self::generate_process_stat(pid_copy))
        }));

        // /proc/[pid]/maps
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(self.allocate_inode(), "maps", move || {
            Self::generate_process_maps(pid_copy)
        }));

        // /proc/[pid]/cmdline
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "cmdline",
            move || Self::generate_process_cmdline(pid_copy),
        ));

        // /proc/[pid]/exe (permission-checked entry)
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(self.allocate_inode(), "exe", move || {
            let proc_id = ProcessId::new(pid_copy.as_u32() as u64);
            let caller = crate::task::context::current_subject().domain;
            let proc_domain: DomainId = proc_id.into();
            if let Some(_process) = process_manager().get(proc_id) {
                if caller == proc_domain
                    || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_FOWNER)
                    || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                    || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
                {
                    Ok(String::from("/bin/process"))
                } else {
                    Err(ProcError::PermissionDenied)
                }
            } else {
                Err(ProcError::NotFound)
            }
        }));

        // /proc/[pid]/cwd (symlink)
        proc_dir.add_child(ProcEntry::symlink(
            self.allocate_inode(),
            "cwd",
            String::from("/"),
        ));

        // /proc/[pid]/mem
        /*
        let pid_copy = pid;
        proc_dir.add_child(ProcEntry::file(
            self.allocate_inode(),
            "mem",
            move || Self::generate_process_mem(pid_copy),
        ));
        */

        // /proc/[pid]/fd ディレクトリ
        proc_dir.add_child(ProcEntry::directory(self.allocate_inode(), "fd")); // permission-checked via ProcDirHandle::readdir()

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

        // Special-case: per-process fd entries like `<pid>/fd/<n>`
        let comps: alloc::vec::Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if comps.len() >= 3 && comps[comps.len() - 2] == "fd" {
            let pid_comp = comps[comps.len() - 3];
            if let Ok(pid_num) = pid_comp.parse::<u32>() {
                let pid = Pid::new(pid_num);
                let proc_id = ProcessId::new(pid.as_u32() as u64);
                let proc_domain: DomainId = proc_id.into();
                if process_manager().get(proc_id).is_none() {
                    return Err(ProcError::NotFound);
                }

                // permission: same domain/process, CAP_FOWNER, CAP_SYS_PTRACE, CAP_SYS_ADMIN, or valid token
                let mut allowed = false;
                if caller == proc_domain {
                    allowed = true;
                }
                if !allowed {
                    if crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_FOWNER)
                        || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                        || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
                    {
                        allowed = true;
                    }
                }
                if !allowed {
                    if let Some(t) = token {
                        if crate::security::capability::manager().validate_token(caller.as_u64(), t, crate::security::capability::CAP_FOWNER) {
                            allowed = true;
                        }
                    }
                }
                if !allowed {
                    return Err(ProcError::PermissionDenied);
                }

                // Last component is handle id
                let handle_comp = comps.last().unwrap();
                if let Ok(handle_id) = handle_comp.parse::<u64>() {
                    if let Some(p) = crate::service_impl::file_handle_path(handle_id) {
                        return Ok(p);
                    } else {
                        return Err(ProcError::NotFound);
                    }
                } else {
                    return Err(ProcError::InvalidArgument);
                }
            } else {
                return Err(ProcError::InvalidArgument);
            }
        }

        // Fallback to regular read for static entries
        self.read(path)
    }

    // --- 情報生成関数 ---

    fn generate_meminfo() -> String {
        // 実際のメモリ情報を取得
        let total_kb = crate::memory::total_memory_kb();
        let free_kb = crate::memory::free_memory_kb();
        let available_kb = free_kb + (free_kb / 4); // 利用可能メモリの推定
        let used_kb = total_kb.saturating_sub(free_kb);
        let cached_kb = used_kb / 4; // キャッシュの推定
        let buffers_kb = used_kb / 8; // バッファの推定
        let active_kb = used_kb / 2;
        let inactive_kb = used_kb / 4;

        alloc::format!(
            "MemTotal:       {:8} kB\n\
             MemFree:        {:8} kB\n\
             MemAvailable:   {:8} kB\n\
             Buffers:        {:8} kB\n\
             Cached:         {:8} kB\n\
             SwapCached:            0 kB\n\
             Active:         {:8} kB\n\
             Inactive:       {:8} kB\n\
             SwapTotal:             0 kB\n\
             SwapFree:              0 kB\n",
            total_kb,
            free_kb,
            available_kb,
            buffers_kb,
            cached_kb,
            active_kb,
            inactive_kb
        )
    }

    fn generate_cpuinfo() -> String {
        // 実際のCPU情報を取得
        let cpu_count = crate::smp::cpu_count();
        let mut info = String::new();

        for cpu_id in 0..cpu_count {
            use core::fmt::Write;
            let _ = write!(
                info,
                "processor\t: {}\n\
                 vendor_id\t: {}\n\
                 cpu family\t: 6\n\
                 model\t\t: 142\n\
                 model name\t: {}\n\
                 stepping\t: 10\n\
                 cpu MHz\t\t: {:.3}\n\
                 cache size\t: {} KB\n\
                 physical id\t: 0\n\
                 siblings\t: {}\n\
                 core id\t\t: {}\n\
                 cpu cores\t: {}\n\
                 flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 sse sse2 ss ht syscall nx lm constant_tsc\n\
                 bugs\t\t:\n\
                 bogomips\t: {:.2}\n\n",
                cpu_id,
                get_cpu_vendor(),
                get_cpu_model_name(),
                3000.0, // MHz - 実際にはTSC周波数から計算可能
                8192,   // キャッシュサイズ（KB）
                cpu_count,
                cpu_id,
                cpu_count,
                6000.0 // bogomips
            );
        }

        info
    }

    fn generate_stat() -> String {
        // 実際の統計情報を取得
        let timer_ticks = crate::interrupts::get_timer_ticks();
        let ctx_switches = crate::task::context::CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed);
        let boot_time = crate::time::now().saturating_sub(crate::time::current_tick() / 1000);
        let cpu_count = crate::smp::cpu_count();
        let process_count = process_manager().count();

        use core::fmt::Write;
        let mut output = String::new();

        // 総CPU時間
        let _ = write!(
            output,
            "cpu  {} 0 {} 0 0 0 {} 0 0 0\n",
            timer_ticks / 10,
            timer_ticks / 5,
            timer_ticks / 20
        );

        // 各CPUの時間
        for i in 0..cpu_count {
            let _ = write!(
                output,
                "cpu{} {} 0 {} 0 0 0 {} 0 0 0\n",
                i,
                timer_ticks / (10 * cpu_count as u64),
                timer_ticks / (5 * cpu_count as u64),
                timer_ticks / (20 * cpu_count as u64)
            );
        }

        let _ = write!(output, "intr {}\n", timer_ticks);
        let _ = write!(output, "ctxt {}\n", ctx_switches);
        let _ = write!(output, "btime {}\n", boot_time);
        let _ = write!(output, "processes {}\n", process_count);
        let _ = write!(output, "procs_running 1\n");
        let _ = write!(output, "procs_blocked 0\n");
        let _ = write!(output, "softirq 0 0 0 0 0 0 0 0 0 0 0\n");

        output
    }

    fn generate_process_status(pid: Pid) -> String {
        // プロセスマネージャーから情報を取得
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        if let Some(process) = process_manager().get(proc_id) {
            let p = process.read();
            let state_char = match p.state {
                ProcessState::Running => 'R',
                ProcessState::Blocked => 'S',
                ProcessState::Ready => 'R',
                ProcessState::Stopped => 'T',
                ProcessState::Zombie => 'Z',
                ProcessState::Dead => 'X',
                ProcessState::Creating => 'D',
            };
            alloc::format!(
                "Name:\t{}\n\
                 Umask:\t0022\n\
                 State:\t{} ({})\n\
                 Tgid:\t{}\n\
                 Ngid:\t0\n\
                 Pid:\t{}\n\
                 PPid:\t{}\n\
                 TracerPid:\t0\n\
                 Uid:\t{}\t{}\t{}\t{}\n\
                 Gid:\t{}\t{}\t{}\t{}\n\
                 FDSize:\t64\n\
                 VmPeak:\t    4096 kB\n\
                 VmSize:\t    4096 kB\n\
                 VmRSS:\t    1024 kB\n\
                 Threads:\t{}\n",
                p.name,
                state_char,
                match state_char {
                    'R' => "running",
                    'S' => "sleeping",
                    'T' => "stopped",
                    'Z' => "zombie",
                    'X' => "dead",
                    _ => "unknown",
                },
                pid.as_u32(),
                pid.as_u32(),
                p.ppid.as_u64(),
                p.credentials.uid.as_u32(),
                p.credentials.uid.as_u32(),
                p.credentials.uid.as_u32(),
                p.credentials.uid.as_u32(),
                p.credentials.gid.as_u32(),
                p.credentials.gid.as_u32(),
                p.credentials.gid.as_u32(),
                p.credentials.gid.as_u32(),
                p.threads().len().max(1)
            )
        } else {
            // プロセスが見つからない場合はデフォルト値
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
    }

    fn generate_process_stat(pid: Pid) -> String {
        // プロセスマネージャーから情報を取得
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        if let Some(process) = process_manager().get(proc_id) {
            let p = process.read();
            let state_char = match p.state {
                ProcessState::Running => 'R',
                ProcessState::Blocked => 'S',
                ProcessState::Ready => 'R',
                ProcessState::Stopped => 'T',
                ProcessState::Zombie => 'Z',
                ProcessState::Dead => 'X',
                ProcessState::Creating => 'D',
            };
            alloc::format!(
                "{} ({}) {} {} {} {} 0 0 0 0 0 0 0 0 0 {} 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                pid.as_u32(),
                p.name,
                state_char,
                p.ppid.as_u64(),
                pid.as_u32(),                   // pgid
                pid.as_u32(),                   // sid
                p.priority.as_i8() as i32 + 20, // nice value
                p.threads().len().max(1)
            )
        } else {
            alloc::format!(
                "{} (unknown) S 1 {} {} 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                pid.as_u32(),
                pid.as_u32(),
                pid.as_u32()
            )
        }
    }

    fn generate_process_maps(pid: Pid) -> Result<String, ProcError> {
        // プロセスのメモリマップ（簡易実装）
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        let caller = crate::task::context::current_subject().domain;
        let proc_domain: DomainId = proc_id.into();

        if let Some(_process) = process_manager().get(proc_id) {
            if caller == proc_domain
                || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
            {
                Ok(alloc::format!(
                    "00400000-00401000 r-xp 00000000 00:00 0          /bin/process{}\n\
                     00600000-00601000 r--p 00000000 00:00 0          /bin/process{}\n\
                     00601000-00602000 rw-p 00001000 00:00 0          /bin/process{}\n\
                     7ffff7ff8000-7ffff7ffa000 r-xp 00000000 00:00 0  [vdso]\n\
                     7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0  [stack]\n",
                    pid.as_u32(),
                    pid.as_u32(),
                    pid.as_u32()
                ))
            } else {
                Err(ProcError::PermissionDenied)
            }
        } else {
            Err(ProcError::NotFound)
        }
    }

    fn generate_process_cmdline(pid: Pid) -> Result<String, ProcError> {
        // プロセスマネージャーから情報を取得
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        let caller = crate::task::context::current_subject().domain;
        let proc_domain: DomainId = proc_id.into();

        if let Some(process) = process_manager().get(proc_id) {
            if caller == proc_domain
                || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
            {
                let p = process.read();
                if p.cmdline.is_empty() {
                    Ok(alloc::format!("{}\0", p.name))
                } else {
                    Ok(p.cmdline.join("\0") + "\0")
                }
            } else {
                Err(ProcError::PermissionDenied)
            }
        } else {
            Err(ProcError::NotFound)
        }
    }

    fn generate_process_mem(pid: Pid) -> Result<String, ProcError> {
        // プロセスのメモリへのアクセスは、通常自身か CAP_SYS_PTRACE/CAP_SYS_ADMIN を要求します
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        let caller = crate::task::context::current_subject().domain;
        let proc_domain: DomainId = proc_id.into();

        if let Some(_process) = process_manager().get(proc_id) {
            if caller == proc_domain
                || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
            {
                // 実際の /proc/[pid]/mem 実装は未完（ここではプレースホルダを返す）
                Ok(alloc::format!("Process {} memory (placeholder)\n", pid.as_u32()))
            } else {
                Err(ProcError::PermissionDenied)
            }
        } else {
            Err(ProcError::NotFound)
        }
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
    token: Option<u64>,
}

impl ProcFileHandle {
    pub fn open(path: &str) -> Result<Self, ProcError> {
        // Backward-compatible: open without token
        Self::open_with_token(path, None)
    }

    pub fn open_with_token(path: &str, token: Option<u64>) -> Result<Self, ProcError> {
        use crate::task::context;

        let caller = context::current_subject().domain;

        // Determine required capability for tokens based on path
        let comps: alloc::vec::Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let required_cap = if let Some(last) = comps.last() {
            if *last == "mem" || *last == "maps" || *last == "cmdline" {
                crate::security::capability::CAP_SYS_PTRACE
            } else if *last == "exe" || *last == "fd" {
                crate::security::capability::CAP_FOWNER
            } else if comps.len() >= 2 && comps[comps.len()-2] == "fd" {
                crate::security::capability::CAP_FOWNER
            } else {
                crate::security::capability::CAP_SYS_PTRACE
            }
        } else {
            crate::security::capability::CAP_SYS_PTRACE
        };

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
            let pid_comp = comps[comps.len() - 2];
            if let Ok(pid_num) = pid_comp.parse::<u32>() {
                let pid = Pid::new(pid_num);
                let proc_id = ProcessId::new(pid.as_u32() as u64);
                let proc_domain: DomainId = proc_id.into();
                if process_manager().get(proc_id).is_none() {
                    return Err(ProcError::NotFound);
                }

                // permission: same domain/process, CAP_FOWNER, CAP_SYS_PTRACE, CAP_SYS_ADMIN, or valid token
                let mut allowed = false;
                if caller == proc_domain {
                    allowed = true;
                }
                if !allowed {
                    if crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_FOWNER)
                        || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                        || crate::security::capability::manager().has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
                    {
                        allowed = true;
                    }
                }
                if !allowed {
                    if let Some(t) = self.token {
                        if crate::security::capability::manager().validate_token(caller.as_u64(), t, crate::security::capability::CAP_FOWNER) {
                            allowed = true;
                        }
                    }
                }
                if !allowed {
                    return Err(ProcError::PermissionDenied);
                }

                // Enumerate real file handles owned by this process
                let owner_id = proc_domain.as_u64();
                let handles = crate::service_impl::file_handles_for_owner(owner_id);
                let mut entries: alloc::vec::Vec<String> = handles.iter().map(|id| id.to_string()).collect();
                entries.sort();
                return Ok(entries);
            } else {
                return Err(ProcError::InvalidArgument);
            }
        }

        // Fallback to regular readdir for other directories
        procfs().readdir(&self.path)
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
    /// Open a directory and optionally bind it to a token (increment in-flight).
    pub fn opendir_with_token(&self, path: &str, token: Option<u64>) -> Result<ProcDirHandle, ProcError> {
        use crate::task::context;
        let caller = context::current_subject().domain;

        // Required capability for fd directory is CAP_FOWNER
        let comps: alloc::vec::Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let required_cap = if comps.len() >= 1 && comps[comps.len() - 1] == "fd" {
            crate::security::capability::CAP_FOWNER
        } else {
            crate::security::capability::CAP_FOWNER
        };

        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller.as_u64(), t, required_cap) {
                return Err(ProcError::PermissionDenied);
            }
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(ProcError::PermissionDenied);
            }
        }

        // Verify path exists and is directory
        let root = self.root.read();
        let mut current = &*root;
        if !path.is_empty() && path != "/" {
            for component in path.split('/').filter(|s| !s.is_empty()) {
                match current.children.get(component) {
                    Some(entry) => current = entry,
                    None => {
                        if let Some(t) = token {
                            let _ = crate::security::capability::manager().decrement_in_flight(t);
                        }
                        return Err(ProcError::NotFound);
                    }
                }
            }
        }

        if current.file_type != ProcFileType::Directory {
            if let Some(t) = token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            return Err(ProcError::NotDirectory);
        }

        Ok(ProcDirHandle { path: String::from(path), token })
    }
}
// ============================================================================
// CPU情報取得ヘルパー
// ============================================================================

/// CPUベンダーIDを取得
fn get_cpu_vendor() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        // CPUID is safe to call directly
        let result = __cpuid(0);
        let vendor_bytes = [
            (result.ebx as u8),
            ((result.ebx >> 8) as u8),
            ((result.ebx >> 16) as u8),
            ((result.ebx >> 24) as u8),
            (result.edx as u8),
            ((result.edx >> 8) as u8),
            ((result.edx >> 16) as u8),
            ((result.edx >> 24) as u8),
            (result.ecx as u8),
            ((result.ecx >> 8) as u8),
            ((result.ecx >> 16) as u8),
            ((result.ecx >> 24) as u8),
        ];
        // 一般的なベンダーIDをチェック
        if &vendor_bytes[..12] == b"GenuineIntel" {
            "GenuineIntel"
        } else if &vendor_bytes[..12] == b"AuthenticAMD" {
            "AuthenticAMD"
        } else {
            "Unknown"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "Unknown"
    }
}

/// CPUモデル名を取得
fn get_cpu_model_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        // CPUID拡張機能チェック
        let result = __cpuid(0x80000000);
        if result.eax >= 0x80000004 {
            // モデル名はCPUID 0x80000002-0x80000004で取得可能だが、
            // 静的文字列を返すためベンダーに基づく推定を使用
            let vendor = get_cpu_vendor();
            if vendor == "GenuineIntel" {
                "Intel(R) Core(TM) Processor"
            } else if vendor == "AuthenticAMD" {
                "AMD Processor"
            } else {
                "Unknown Processor"
            }
        } else {
            "Unknown Processor"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "Unknown Processor"
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


