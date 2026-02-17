use alloc::string::String;

use crate::domain_system::DomainId;
use crate::task::process::{process_manager, ProcessId, ProcessState};

use super::{ProcEntry, ProcError, ProcFs};

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

impl ProcFs {
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
            Self::check_exe_access(pid_copy)
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

    /// /proc/[pid]/exe パーミッションチェック
    fn check_exe_access(pid: Pid) -> Result<String, ProcError> {
        let proc_id = ProcessId::new(pid.as_u32() as u64);
        let caller = crate::task::context::current_subject().domain;
        let proc_domain: DomainId = proc_id.into();
        if let Some(_process) = process_manager().get(proc_id) {
            if caller == proc_domain
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_FOWNER)
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
            {
                Ok(String::from("/bin/process"))
            } else {
                Err(ProcError::PermissionDenied)
            }
        } else {
            Err(ProcError::NotFound)
        }
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
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
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
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
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
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_PTRACE)
                || crate::security::capability::manager()
                    .has_capability(caller.as_u64(), crate::security::capability::CAP_SYS_ADMIN)
            {
                // 実際の /proc/[pid]/mem 実装は未完（ここではプレースホルダを返す）
                Ok(alloc::format!(
                    "Process {} memory (placeholder)\n",
                    pid.as_u32()
                ))
            } else {
                Err(ProcError::PermissionDenied)
            }
        } else {
            Err(ProcError::NotFound)
        }
    }
}
