//! プロセス管理 (Process Management)
//!
//! ExoRust のタスク/プロセスライフサイクル管理
//! ドメインベースのプロセスモデル

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::mm::memcg::MemcgId;

// ============================================================================
// Per-CPU 現在プロセスID追跡
// ============================================================================

/// 各CPUの現在プロセスID (最大64コア対応)
mod cap_validation;
pub use cap_validation::*;
static CURRENT_PROCESS: [AtomicU64; 64] = {
    const INIT: AtomicU64 = AtomicU64::new(1); // 初期値はINITプロセス
    [INIT; 64]
};

/// 現在のプロセスIDを設定
pub fn set_current_process(pid: ProcessId) {
    let cpu_id = crate::smp::current_cpu() as usize;
    if cpu_id < 64 {
        CURRENT_PROCESS[cpu_id].store(pid.as_u64(), Ordering::Release);
    }
}

/// 現在のプロセスIDを取得
pub fn get_current_process() -> ProcessId {
    let cpu_id = crate::smp::current_cpu() as usize;
    if cpu_id < 64 {
        ProcessId::new(CURRENT_PROCESS[cpu_id].load(Ordering::Acquire))
    } else {
        ProcessId::INIT
    }
}

/// プロセスID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ProcessId(u64);

impl ProcessId {
    pub const KERNEL: Self = Self(0);
    pub const INIT: Self = Self(1);

    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<ProcessId> for crate::domain_system::DomainId {
    fn from(pid: ProcessId) -> Self {
        crate::domain_system::DomainId::new(pid.as_u64())
    }
}

/// スレッドID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ThreadId(u64);

impl ThreadId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// プロセスグループID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ProcessGroupId(u64);

impl ProcessGroupId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// セッションID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SessionId(u64);

impl SessionId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// プロセス状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// 作成中
    Creating,
    /// 実行可能
    Ready,
    /// 実行中
    Running,
    /// ブロック中 (I/O待ち等)
    Blocked,
    /// 停止中 (SIGSTOP)
    Stopped,
    /// ゾンビ (終了済み、待機中)
    Zombie,
    /// 完全終了
    Dead,
}

/// 終了コード (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitCode(i32);

impl ExitCode {
    pub const SUCCESS: Self = Self(0);
    pub const FAILURE: Self = Self(1);

    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    pub const fn as_i32(&self) -> i32 {
        self.0
    }

    pub fn is_success(&self) -> bool {
        self.0 == 0
    }
}

/// プロセス優先度 (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct Priority(i8);

impl Priority {
    pub const LOWEST: Self = Self(-20);
    pub const LOW: Self = Self(-10);
    pub const NORMAL: Self = Self(0);
    pub const HIGH: Self = Self(10);
    pub const HIGHEST: Self = Self(19);
    pub const REALTIME: Self = Self(20);

    pub const fn new(prio: i8) -> Self {
        // clamp を const fn 内で使えないため手動で実装
        let clamped = if prio < -20 {
            -20
        } else if prio > 20 {
            20
        } else {
            prio
        };
        Self(clamped)
    }

    pub const fn as_i8(&self) -> i8 {
        self.0
    }
}

/// ユーザーID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(u32);

impl UserId {
    pub const ROOT: Self = Self(0);

    pub const fn new(uid: u32) -> Self {
        Self(uid)
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn is_root(&self) -> bool {
        self.0 == 0
    }
}

/// グループID (Newtype)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(u32);

impl GroupId {
    pub const ROOT: Self = Self(0);

    pub const fn new(gid: u32) -> Self {
        Self(gid)
    }

    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

/// プロセス資格情報
#[derive(Debug, Clone)]
pub struct Credentials {
    /// 実UID
    pub uid: UserId,
    /// 有効UID
    pub euid: UserId,
    /// 保存UID
    pub suid: UserId,
    /// 実GID
    pub gid: GroupId,
    /// 有効GID
    pub egid: GroupId,
    /// 保存GID
    pub sgid: GroupId,
    /// 補助グループ
    pub groups: Vec<GroupId>,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            uid: UserId::ROOT,
            euid: UserId::ROOT,
            suid: UserId::ROOT,
            gid: GroupId::ROOT,
            egid: GroupId::ROOT,
            sgid: GroupId::ROOT,
            groups: Vec::new(),
        }
    }
}

impl Credentials {
    /// root権限があるか
    pub fn is_privileged(&self) -> bool {
        self.euid.is_root()
    }
}

/// リソース制限
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimit {
    /// 現在の制限
    pub soft: u64,
    /// 最大制限
    pub hard: u64,
}

impl ResourceLimit {
    pub const UNLIMITED: u64 = u64::MAX;

    pub const fn new(soft: u64, hard: u64) -> Self {
        Self { soft, hard }
    }

    pub const fn unlimited() -> Self {
        Self {
            soft: Self::UNLIMITED,
            hard: Self::UNLIMITED,
        }
    }
}

/// リソース制限種別
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum ResourceType {
    /// CPU時間 (秒)
    CpuTime,
    /// ファイルサイズ (バイト)
    FileSize,
    /// データセグメント (バイト)
    DataSize,
    /// スタックサイズ (バイト)
    StackSize,
    /// コアダンプサイズ (バイト)
    CoreSize,
    /// 常駐メモリ (バイト)
    ResidentSet,
    /// プロセス数
    NumProcesses,
    /// ファイルディスクリプタ数
    NumFiles,
    /// メモリロック (バイト)
    MemLock,
    /// アドレス空間 (バイト)
    AddressSpace,
    /// ファイルロック数
    FileLocks,
    /// ペンディングシグナル数
    SignalsPending,
    /// メッセージキューサイズ (バイト)
    MsgQueueSize,
}

/// リソース制限セット
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    limits: BTreeMap<ResourceType, ResourceLimit>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        let mut limits = BTreeMap::new();

        // デフォルト制限
        limits.insert(ResourceType::CpuTime, ResourceLimit::unlimited());
        limits.insert(ResourceType::FileSize, ResourceLimit::unlimited());
        limits.insert(ResourceType::DataSize, ResourceLimit::unlimited());
        limits.insert(
            ResourceType::StackSize,
            ResourceLimit::new(8 * 1024 * 1024, ResourceLimit::UNLIMITED),
        );
        limits.insert(
            ResourceType::CoreSize,
            ResourceLimit::new(0, ResourceLimit::UNLIMITED),
        );
        limits.insert(ResourceType::ResidentSet, ResourceLimit::unlimited());
        limits.insert(ResourceType::NumProcesses, ResourceLimit::new(4096, 65536));
        limits.insert(ResourceType::NumFiles, ResourceLimit::new(1024, 65536));
        limits.insert(
            ResourceType::MemLock,
            ResourceLimit::new(64 * 1024, 64 * 1024),
        );
        limits.insert(ResourceType::AddressSpace, ResourceLimit::unlimited());

        Self { limits }
    }
}

impl ResourceLimits {
    pub fn get(&self, resource: ResourceType) -> ResourceLimit {
        self.limits
            .get(&resource)
            .copied()
            .unwrap_or(ResourceLimit::unlimited())
    }

    pub fn set(&mut self, resource: ResourceType, limit: ResourceLimit) {
        self.limits.insert(resource, limit);
    }
}

/// プロセス統計
#[derive(Debug, Default)]
pub struct ProcessStats {
    /// ユーザーモードCPU時間 (ナノ秒)
    pub user_time: AtomicU64,
    /// システムモードCPU時間 (ナノ秒)
    pub system_time: AtomicU64,
    /// 任意コンテキストスイッチ回数
    pub voluntary_switches: AtomicU64,
    /// 強制コンテキストスイッチ回数
    pub involuntary_switches: AtomicU64,
    /// ページフォルト (マイナー)
    pub minor_faults: AtomicU64,
    /// ページフォルト (メジャー)
    pub major_faults: AtomicU64,
    /// 読み取りバイト数
    pub bytes_read: AtomicU64,
    /// 書き込みバイト数
    pub bytes_written: AtomicU64,
}

/// プロセス情報
pub struct ProcessInfo {
    /// プロセスID
    pub pid: ProcessId,
    /// 親プロセスID
    pub ppid: ProcessId,
    /// プロセスグループID
    pub pgid: ProcessGroupId,
    /// セッションID
    pub sid: SessionId,
    /// 状態
    pub state: ProcessState,
    /// プロセス名
    pub name: String,
    /// コマンドライン
    pub cmdline: Vec<String>,
    /// 作業ディレクトリ
    pub cwd: String,
    /// 資格情報
    pub credentials: Credentials,
    /// 優先度
    pub priority: Priority,
    /// 統計
    pub stats: ProcessStats,
    /// リソース制限
    pub limits: ResourceLimits,
    /// memcg ID
    pub memcg_id: MemcgId,
    /// 作成時刻
    pub created_at: u64,
    /// 終了コード (終了時のみ)
    pub exit_code: Option<ExitCode>,
    /// 子プロセス
    children: Vec<ProcessId>,
    /// スレッド
    threads: Vec<ThreadId>,
    /// AutoNUMA スキャン用の現在アドレス
    pub numa_scan_addr: AtomicU64,
}

impl ProcessInfo {
    /// 新しいプロセス情報を作成
    pub fn new(pid: ProcessId, ppid: ProcessId, name: &str) -> Self {
        Self {
            pid,
            ppid,
            pgid: ProcessGroupId::new(pid.as_u64()),
            sid: SessionId::new(pid.as_u64()),
            state: ProcessState::Creating,
            name: String::from(name),
            cmdline: Vec::new(),
            cwd: String::from("/"),
            credentials: Credentials::default(),
            priority: Priority::NORMAL,
            stats: ProcessStats::default(),
            limits: ResourceLimits::default(),
            memcg_id: MemcgId::ROOT,
            created_at: crate::time::current_time_ns(),
            exit_code: None,
            children: Vec::new(),
            threads: Vec::new(),
            numa_scan_addr: AtomicU64::new(crate::mm::address_space::USER_SPACE_START),
        }
    }

    /// 子プロセスを追加
    pub fn add_child(&mut self, child: ProcessId) {
        self.children.push(child);
    }

    /// 子プロセスを削除
    pub fn remove_child(&mut self, child: ProcessId) {
        self.children.retain(|&c| c != child);
    }

    /// スレッドを追加
    pub fn add_thread(&mut self, thread: ThreadId) {
        self.threads.push(thread);
    }

    /// スレッドを削除
    pub fn remove_thread(&mut self, thread: ThreadId) {
        self.threads.retain(|&t| t != thread);
    }

    /// 子プロセス一覧
    pub fn children(&self) -> &[ProcessId] {
        &self.children
    }

    /// スレッド一覧
    pub fn threads(&self) -> &[ThreadId] {
        &self.threads
    }
}

/// プロセスエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    /// プロセスが見つからない
    NotFound,
    /// 権限エラー
    PermissionDenied,
    /// リソース不足
    OutOfResources,
    /// 無効な操作
    InvalidOperation,
    /// 子プロセスがない
    NoChild,
    /// すでに終了している
    AlreadyExited,
    /// ゾンビ状態
    IsZombie,
}

/// プロセスマネージャー
pub struct ProcessManager {
    /// プロセステーブル
    processes: spin::RwLock<BTreeMap<ProcessId, Arc<spin::RwLock<ProcessInfo>>>>,
    /// 次のPID
    next_pid: AtomicU64,
    /// 次のTID
    next_tid: AtomicU64,
    /// 統計
    total_created: AtomicU64,
    total_exited: AtomicU64,
}

impl ProcessManager {
    pub const fn new() -> Self {
        Self {
            processes: spin::RwLock::new(BTreeMap::new()),
            next_pid: AtomicU64::new(2), // 0=kernel, 1=init
            next_tid: AtomicU64::new(1),
            total_created: AtomicU64::new(0),
            total_exited: AtomicU64::new(0),
        }
    }

    /// 新しいPIDを生成
    fn allocate_pid(&self) -> ProcessId {
        ProcessId::new(self.next_pid.fetch_add(1, Ordering::Relaxed))
    }

    /// 新しいTIDを生成
    fn allocate_tid(&self) -> ThreadId {
        ThreadId::new(self.next_tid.fetch_add(1, Ordering::Relaxed))
    }

    /// プロセスを作成
    pub fn create(&self, ppid: ProcessId, name: &str) -> Result<ProcessId, ProcessError> {
        let pid = self.allocate_pid();
        let info = ProcessInfo::new(pid, ppid, name);

        {
            let mut processes = self.processes.write();
            processes.insert(pid, Arc::new(spin::RwLock::new(info)));
        }

        // 親プロセスの子リストに追加
        if ppid != ProcessId::KERNEL {
            if let Some(parent) = self.get(ppid) {
                let mut p = parent.write();
                p.add_child(pid);
            }
        }

        self.total_created.fetch_add(1, Ordering::Relaxed);
        Ok(pid)
    }

    /// プロセスを取得
    pub fn get(&self, pid: ProcessId) -> Option<Arc<spin::RwLock<ProcessInfo>>> {
        let processes = self.processes.read();
        processes.get(&pid).cloned()
    }

    /// プロセス状態を更新
    pub fn set_state(&self, pid: ProcessId, state: ProcessState) -> Result<(), ProcessError> {
        let process = self.get(pid).ok_or(ProcessError::NotFound)?;
        let mut p = process.write();
        p.state = state;
        Ok(())
    }

    /// プロセスを終了
    pub fn exit(&self, pid: ProcessId, code: ExitCode) -> Result<(), ProcessError> {
        let process = self.get(pid).ok_or(ProcessError::NotFound)?;

        {
            let mut p = process.write();
            if p.state == ProcessState::Dead {
                return Err(ProcessError::AlreadyExited);
            }

            p.state = ProcessState::Zombie;
            p.exit_code = Some(code);
        }

        self.total_exited.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// ゾンビプロセスを回収 (wait)
    pub fn wait(
        &self,
        ppid: ProcessId,
        pid: Option<ProcessId>,
    ) -> Result<(ProcessId, ExitCode), ProcessError> {
        let parent = self.get(ppid).ok_or(ProcessError::NotFound)?;
        let children = {
            let p = parent.read();
            p.children().to_vec()
        };

        if children.is_empty() {
            return Err(ProcessError::NoChild);
        }

        let target = self.validate_wait_target(pid, &children)?;

        if let Some((child_pid, code)) = self.find_zombie_child(&children, target) {
            self.reap(child_pid)?;
            let mut p = parent.write();
            p.remove_child(child_pid);
            return Ok((child_pid, code));
        }

        // 待機する子がいない
        // 注: 実際のブロッキング待機はタスクスケジューラとの統合が必要
        // 現在はポーリングベースまたはNoChildエラーを返す
        // 完全な実装には以下が必要:
        // 1. 現在のタスクを待機状態にする
        // 2. 子プロセスがexitしたときにwakeupする
        // 3. シグナル(SIGCHLD)との統合
        Err(ProcessError::NoChild)
    }

    /// Validate the `pid` argument for `wait`, returning the resolved target.
    fn validate_wait_target(
        &self,
        pid: Option<ProcessId>,
        children: &[ProcessId],
    ) -> Result<Option<ProcessId>, ProcessError> {
        if let Some(target_pid) = pid {
            if !children.contains(&target_pid) {
                return Err(ProcessError::NoChild);
            }
            Ok(Some(target_pid))
        } else {
            Ok(None)
        }
    }

    /// Search `children` for the first zombie matching `target`, returning its pid and exit code.
    fn find_zombie_child(
        &self,
        children: &[ProcessId],
        target: Option<ProcessId>,
    ) -> Option<(ProcessId, ExitCode)> {
        for &child_pid in children {
            if target.is_some() && target != Some(child_pid) {
                continue;
            }
            if let Some(child) = self.get(child_pid) {
                let c = child.read();
                if c.state == ProcessState::Zombie {
                    if let Some(code) = c.exit_code {
                        return Some((child_pid, code));
                    }
                }
            }
        }
        None
    }

    /// ゾンビを回収
    fn reap(&self, pid: ProcessId) -> Result<(), ProcessError> {
        // Decrement in-flight counters for any grants held by this process.
        let grants = crate::security::capability::manager().list_grants(pid.as_u64());
        for g in grants {
            // Best-effort decrement (ignore errors if not incremented)
            let _ = crate::security::capability::manager().decrement_in_flight(g.id);
        }

        let mut processes = self.processes.write();
        processes.remove(&pid).ok_or(ProcessError::NotFound)?;
        Ok(())
    }

    /// プロセス一覧を取得
    pub fn list(&self) -> Vec<ProcessId> {
        let processes = self.processes.read();
        processes.keys().copied().collect()
    }

    /// プロセス数を取得
    pub fn count(&self) -> usize {
        self.processes.read().len()
    }

    /// 統計を取得
    pub fn stats(&self) -> (u64, u64) {
        (
            self.total_created.load(Ordering::Relaxed),
            self.total_exited.load(Ordering::Relaxed),
        )
    }
}

/// グローバルプロセスマネージャー
static PROCESS_MANAGER: ProcessManager = ProcessManager::new();

/// プロセスマネージャーを取得
pub fn process_manager() -> &'static ProcessManager {
    &PROCESS_MANAGER
}

// --- システムコール風 API ---

/// fork() 相当 (ExoRustでは spawn に近い)
pub fn spawn(name: &str) -> Result<ProcessId, ProcessError> {
    let ppid = get_current_process();
    PROCESS_MANAGER.create(ppid, name)
}
