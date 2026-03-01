// ============================================================================
// src/domain_system.rs - 統合ドメイン管理システム
// ============================================================================
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
//
// domain/ と ipc/ の機能を統合し、一貫したドメイン管理を提供
// ============================================================================
#![allow(dead_code)]

// use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};
// 【設計書 8.1】PoisonLock使用 - パニック時自動毒入れ
use crate::domain::quota::{DomainPriority, DomainQuota, IoQuota, MemoryQuota, quota_manager};
use crate::error::{DomainErrorKind, KernelError};
use crate::security::CapabilitySet;
use crate::sync::PoisonLock;
use spin::Once;

pub const CPU_QUOTA_SUSPEND_STREAK: u8 = 3;
pub const CPU_QUOTA_SUSPEND_WINDOW_NS: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuotaAction {
    None,
    YieldDemote,
    Suspend { until_ns: u64 },
}

// ============================================================================
// ドメインID
// ============================================================================

/// ドメインを一意に識別するID
mod public_api;
pub use public_api::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

impl DomainId {
    /// 新しいドメインIDを作成
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// IDを数値として取得
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// カーネルドメイン（常にID=0）
    pub const KERNEL: DomainId = DomainId(0);
}

impl core::fmt::Display for DomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

// ============================================================================
// ドメイン状態
// ============================================================================

/// ドメインのライフサイクル状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// 初期化中
    Initializing,
    /// 実行中
    Running,
    /// 一時停止
    Suspended,
    /// 停止（エラーで）
    Stopped,
    /// 終了済み（リソース回収完了）
    Terminated,
}

impl DomainState {
    /// 実行可能な状態かどうか
    pub fn is_runnable(&self) -> bool {
        matches!(self, DomainState::Running | DomainState::Initializing)
    }

    /// アクティブな状態かどうか（リソースを保持）
    pub fn is_active(&self) -> bool {
        !matches!(self, DomainState::Terminated)
    }
}

// ============================================================================
// ドメインセキュリティ
// ============================================================================

/// ドメイン主体の資格情報
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCredentials {
    pub uid: u32,
    pub gid: u32,
}

impl DomainCredentials {
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    pub const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// ドメイン主体の権限情報
#[derive(Debug, Clone)]
pub struct DomainSecurity {
    pub credentials: DomainCredentials,
    pub caps: CapabilitySet,
}

impl DomainSecurity {
    pub fn kernel() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::full(),
        }
    }
}

impl Default for DomainSecurity {
    fn default() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::empty(),
        }
    }
}

fn kernel_security_handle() -> Arc<DomainSecurity> {
    static KERNEL_SECURITY: Once<Arc<DomainSecurity>> = Once::new();
    KERNEL_SECURITY
        .call_once(|| Arc::new(DomainSecurity::kernel()))
        .clone()
}

/// Requested capability descriptor used by `spawn_domain_with_caps`.
#[derive(Debug, Clone, Copy)]
pub struct RequestedCap {
    pub cap: u64,
    pub expires: Option<u64>,
    pub delegatable: bool,
}

// ============================================================================
// ドメイン構造体
// ============================================================================

/// ドメイン: 隔離された実行環境
#[derive(Debug)]
pub struct Domain {
    /// ドメインID
    pub id: DomainId,
    /// ドメイン名
    pub name: String,
    /// 現在の状態
    pub state: DomainState,
    /// セキュリティ主体（資格情報/ケイパビリティ）
    pub security: Arc<DomainSecurity>,

    // タスク管理
    /// このドメインに属するタスクID
    pub tasks: Vec<u64>,

    // 依存関係
    /// このドメインが依存するドメイン
    pub dependencies: Vec<DomainId>,
    /// このドメインに依存するドメイン
    pub dependents: Vec<DomainId>,

    // リソース追跡
    /// 所有するRRefの数
    pub rref_count: u64,
    /// 割り当て済みメモリ量（バイト）
    pub allocated_memory: u64,

    // 統計情報
    /// 総実行時間（ティック）
    pub runtime_ticks: u64,
    /// コンテキストスイッチ回数
    pub context_switches: u64,
    /// 作成時刻（ティック）
    pub created_at: u64,

    // エラー情報
    /// パニックメッセージ（クラッシュ時）
    pub panic_message: Option<String>,
    /// 最後のエラーメッセージ
    pub last_error: Option<String>,
    /// NUMAノードアフィニティ（任意）
    pub numa_node: Option<usize>,
    /// スケジューリング/回収優先度（メタデータ）
    pub priority: DomainPriority,
    /// CPU使用率上限（%）
    pub cpu_limit_percent: u64,
    /// メモリ使用量上限（バイト）
    pub memory_limit_bytes: u64,
    /// I/O帯域上限（バイト/秒、0=無制限）
    pub io_bandwidth_limit: u64,
    /// CPUクォータ連続違反回数
    pub cpu_violation_streak: u8,
    /// クォータ制御での一時Suspend期限（ns, 0=未設定）
    pub quota_suspend_until_ns: u64,
}

/// Domain summary snapshot for external queries
#[derive(Debug, Clone)]
pub struct DomainSnapshot {
    pub id: DomainId,
    pub name: String,
    pub state: DomainState,
    pub tasks: usize,
    pub task_ids: Vec<u64>,
    pub memory_bytes: u64,
    pub rrefs: u64,
    pub runtime_ticks: u64,
    pub context_switches: u64,
    pub created_at: u64,
    pub dependencies: Vec<DomainId>,
    pub dependents: Vec<DomainId>,
    pub numa_node: Option<usize>,
    pub priority: DomainPriority,
    pub cpu_limit_percent: u64,
    pub memory_limit_bytes: u64,
    pub io_bandwidth_limit: u64,
    pub panic_message: Option<String>,
    pub last_error: Option<String>,
}

impl Domain {
    /// 新しいドメインを作成
    pub fn new(id: DomainId, name: String) -> Self {
        let security = if id == DomainId::KERNEL {
            kernel_security_handle()
        } else {
            Arc::new(DomainSecurity::default())
        };

        Self {
            id,
            name,
            state: DomainState::Initializing,
            security,
            tasks: Vec::new(),
            dependencies: Vec::new(),
            dependents: Vec::new(),
            rref_count: 0,
            allocated_memory: 0,
            runtime_ticks: 0,
            context_switches: 0,
            created_at: crate::task::timer::current_tick(),
            panic_message: None,
            last_error: None,
            numa_node: None,
            priority: DomainPriority::Normal,
            cpu_limit_percent: 100,
            memory_limit_bytes: u64::MAX,
            io_bandwidth_limit: 0,
            cpu_violation_streak: 0,
            quota_suspend_until_ns: 0,
        }
    }

    /// 実行可能かどうか
    pub fn is_runnable(&self) -> bool {
        self.state.is_runnable()
    }

    /// タスクを追加
    pub fn add_task(&mut self, task_id: u64) {
        if !self.tasks.contains(&task_id) {
            self.tasks.push(task_id);
        }
    }

    /// タスクを削除
    pub fn remove_task(&mut self, task_id: u64) {
        self.tasks.retain(|&id| id != task_id);
    }

    /// 依存関係を追加
    pub fn add_dependency(&mut self, dep: DomainId) {
        if !self.dependencies.contains(&dep) {
            self.dependencies.push(dep);
        }
    }

    /// 被依存関係を追加（他のドメインがこのドメインに依存）
    pub fn add_dependent(&mut self, dep_id: DomainId) {
        if !self.dependents.contains(&dep_id) {
            self.dependents.push(dep_id);
        }
    }

    /// 依存関係を削除
    pub fn remove_dependency(&mut self, dep: DomainId) {
        self.dependencies.retain(|&id| id != dep);
    }

    /// 被依存関係を削除
    pub fn remove_dependent(&mut self, dep_id: DomainId) {
        self.dependents.retain(|&id| id != dep_id);
    }

    /// RRef数をインクリメント
    pub fn increment_rref(&mut self) {
        self.rref_count += 1;
    }

    /// RRef数をデクリメント
    pub fn decrement_rref(&mut self) {
        if self.rref_count > 0 {
            self.rref_count -= 1;
        }
    }

    /// メモリ使用量を追加
    pub fn add_memory(&mut self, size: u64) {
        self.allocated_memory = self.allocated_memory.saturating_add(size);
    }

    /// NUMAノードを設定
    pub fn set_numa_node(&mut self, node: usize) {
        self.numa_node = Some(node);
    }

    /// NUMAノードを取得
    pub fn get_numa_node(&self) -> Option<usize> {
        self.numa_node
    }

    /// ケイパビリティセットを設定（メタデータ + ポリシー入力）
    pub fn set_capabilities(&mut self, caps: CapabilitySet) {
        Arc::make_mut(&mut self.security).caps = caps;
    }

    /// 優先度を設定
    pub fn set_priority(&mut self, priority: DomainPriority) {
        self.priority = priority;
    }

    /// リソース上限メタデータを設定
    pub fn set_resource_limits(
        &mut self,
        cpu_limit_percent: u64,
        memory_limit_bytes: u64,
        io_bandwidth_limit: u64,
    ) {
        self.cpu_limit_percent = cpu_limit_percent;
        self.memory_limit_bytes = memory_limit_bytes;
        self.io_bandwidth_limit = io_bandwidth_limit;
    }

    /// メモリ使用量を減少
    pub fn free_memory(&mut self, size: u64) {
        self.allocated_memory = self.allocated_memory.saturating_sub(size);
    }
}

const BYTES_PER_MB: u64 = 1024 * 1024;

#[inline]
fn bytes_to_mb_ceil(bytes: u64) -> u64 {
    bytes.div_ceil(BYTES_PER_MB).max(1)
}

fn sync_domain_quota(
    id: DomainId,
    priority: DomainPriority,
    cpu_limit_percent: u64,
    memory_limit_bytes: u64,
    io_bandwidth_limit: u64,
) {
    if id == DomainId::KERNEL {
        quota_manager().register(DomainQuota::kernel());
        return;
    }

    let mut quota = DomainQuota::new(id, priority).with_cpu_limit(cpu_limit_percent.min(100), 100);

    quota.memory = if memory_limit_bytes == 0 || memory_limit_bytes == u64::MAX {
        MemoryQuota::unlimited()
    } else {
        MemoryQuota::new(bytes_to_mb_ceil(memory_limit_bytes))
    };

    if io_bandwidth_limit == 0 || io_bandwidth_limit == u64::MAX {
        quota.network_io = IoQuota::unlimited();
        quota.storage_io = IoQuota::unlimited();
    } else {
        let mbps = bytes_to_mb_ceil(io_bandwidth_limit);
        quota.network_io = IoQuota::new(mbps, mbps);
        quota.storage_io = IoQuota::new(mbps, mbps);
    }

    quota_manager().register(quota);
}

fn unregister_domain_quota(id: DomainId) {
    if id != DomainId::KERNEL {
        quota_manager().unregister(id);
    }
}

// ============================================================================
// ドメインレジストリ
// ============================================================================

/// ドメインレジストリ
#[derive(Debug)]
struct DomainRegistry {
    /// 全ドメインのリスト
    domains: Vec<Domain>,
    /// 次のドメインID
    next_id: AtomicU64,
}

impl DomainRegistry {
    /// 新しいレジストリを作成
    const fn new() -> Self {
        Self {
            domains: Vec::new(),
            next_id: AtomicU64::new(1), // 0はカーネル用
        }
    }

    /// 新しいドメインIDを生成
    fn generate_id(&self) -> DomainId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        DomainId::new(id)
    }
}

/// グローバルなドメインレジストリ
/// 【設計書 8.1】PoisonLockを使用してパニック時の毒入れを保証
static REGISTRY: PoisonLock<DomainRegistry> = PoisonLock::new(DomainRegistry::new());

// ============================================================================
// ヒープレジストリ統合
// ============================================================================
// 以前はここに static HEAP_REGISTRY がありましたが、
// 拡張性のため crate::sas（Global Sharded Registry）に統合されました。
// ============================================================================

// ============================================================================
// 公開API - ドメイン管理
// ============================================================================

/// ドメインシステムを初期化（カーネルドメインを作成）
pub fn init() {
    // Ensure quota manager is initialized before any non-kernel domain is created.
    crate::domain::quota::init();

    crate::io::log::early_print("[DOM] lock\n");
    // 初期化時は毒入れされていないはず
    let mut registry = REGISTRY
        .lock()
        .expect("domain registry poisoned during init");
    crate::io::log::early_print("[DOM] locked\n");

    // カーネルドメインを作成
    let mut kernel = Domain::new(DomainId::KERNEL, "kernel".into());
    crate::io::log::early_print("[DOM] new done\n");
    kernel.state = DomainState::Running;
    crate::io::log::early_print("[DOM] insert\n");
    registry.domains.push(kernel);
    sync_domain_quota(
        DomainId::KERNEL,
        DomainPriority::Critical,
        100,
        u64::MAX,
        u64::MAX,
    );
    crate::io::log::early_print("[DOM] done\n");
}

/// 新しいドメインを作成
///
/// # パフォーマンス注意
/// `name.clone()` は `crate::log!` マクロで使用するために必要。
/// ドメイン作成は頻繁に呼ばれないため、このコストは許容される。
/// 代替案: log を先に行い、name を消費するパターン
pub fn create_domain(name: String) -> Result<DomainId, KernelError> {
    // Runtime path: do not attempt best-effort recovery from a poisoned registry.
    // If the registry lock is poisoned, return a conservative error so callers can
    // decide how to proceed (e.g., abort, retry, or propagate the error).
    match REGISTRY.lock() {
        Ok(mut registry) => {
            let id = registry.generate_id();
            // Log before consuming `name` to avoid an extra clone
            log::info!("[DOMAIN] Created domain {} ({})\n", id.as_u64(), &name);
            let domain = Domain::new(id, name);
            sync_domain_quota(
                id,
                domain.priority,
                domain.cpu_limit_percent,
                domain.memory_limit_bytes,
                domain.io_bandwidth_limit,
            );
            registry.domains.push(domain);
            Ok(id)
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned during create_domain");
            Err(KernelError::Domain(DomainErrorKind::RegistryPoisoned))
        }
    }
}

/// Spawn a new domain and apply requested capability grants atomically.
///
/// This is the Domain/Cell equivalent of the legacy `spawn_with_caps`.
pub fn spawn_domain_with_caps(
    name: String,
    requested: &[RequestedCap],
) -> Result<(DomainId, Vec<u64>), KernelError> {
    let parent = crate::task::context::current_subject().domain.as_u64();
    let cap_mgr = crate::security::capability::manager();

    for req in requested {
        let allowed = cap_mgr.has_capability(parent, crate::security::capability::CAP_SYS_ADMIN)
            || cap_mgr.get_capabilities(parent).is_permitted(req.cap)
            || cap_mgr
                .list_grants(parent)
                .iter()
                .any(|t| t.cap == req.cap && t.delegatable);
        if !allowed {
            return Err(KernelError::Domain(DomainErrorKind::OwnershipViolation));
        }
    }

    let domain_id = create_domain(name)?;
    let _ = with_domain_mut(domain_id, |d| d.state = DomainState::Running);

    let mut created_tokens: Vec<u64> = Vec::new();
    for req in requested {
        match cap_mgr.grant_capability_with_opts(
            parent,
            domain_id.as_u64(),
            req.cap,
            req.expires,
            req.delegatable,
        ) {
            Ok(token_id) => {
                created_tokens.push(token_id);
                let _ = cap_mgr.increment_in_flight(token_id);
            }
            Err(_) => {
                for token_id in created_tokens.iter().copied() {
                    let _ = cap_mgr.revoke_grant(parent, token_id, true);
                }
                let _ = with_domain_mut(domain_id, |d| d.state = DomainState::Terminated);
                return Err(KernelError::Domain(DomainErrorKind::LifecycleError));
            }
        }
    }

    Ok((domain_id, created_tokens))
}

/// ドメインのセキュリティハンドルを取得
pub fn domain_security_handle(id: DomainId) -> Arc<DomainSecurity> {
    match REGISTRY.lock() {
        Ok(guard) => guard
            .domains
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.security.clone())
            .unwrap_or_else(kernel_security_handle),
        Err(_) => kernel_security_handle(),
    }
}

/// ドメインの状態を取得
pub fn get_domain_state(id: DomainId) -> Option<DomainState> {
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(|d| d.state),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_state)");
            None
        }
    }
}

/// ドメインに対して読み取り操作を実行
/// domain/registry.rs からの互換性維持のために追加
pub fn with_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&Domain) -> R,
{
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(f),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (with_domain)");
            None
        }
    }
}

/// ドメインに対して更新操作を実行
/// domain/registry.rs からの互換性維持のために追加
pub fn with_domain_mut<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&mut Domain) -> R,
{
    match REGISTRY.lock() {
        Ok(mut guard) => guard.domains.iter_mut().find(|d| d.id == id).map(f),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (with_domain_mut)");
            None
        }
    }
}

/// Create a lightweight snapshot of a domain for external queries.
fn to_snapshot(domain: &Domain) -> DomainSnapshot {
    DomainSnapshot {
        id: domain.id,
        name: domain.name.clone(),
        state: domain.state,
        tasks: domain.tasks.len(),
        task_ids: domain.tasks.clone(),
        memory_bytes: domain.allocated_memory,
        rrefs: domain.rref_count,
        runtime_ticks: domain.runtime_ticks,
        context_switches: domain.context_switches,
        created_at: domain.created_at,
        dependencies: domain.dependencies.clone(),
        dependents: domain.dependents.clone(),
        numa_node: domain.numa_node,
        priority: domain.priority,
        cpu_limit_percent: domain.cpu_limit_percent,
        memory_limit_bytes: domain.memory_limit_bytes,
        io_bandwidth_limit: domain.io_bandwidth_limit,
        panic_message: domain.panic_message.clone(),
        last_error: domain.last_error.clone(),
    }
}

/// List all domain snapshots.
pub fn list_domain_snapshots() -> Vec<DomainSnapshot> {
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().map(to_snapshot).collect(),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (list_domain_snapshots)");
            Vec::new()
        }
    }
}

/// Get a single domain snapshot by ID.
pub fn get_domain_snapshot(id: DomainId) -> Option<DomainSnapshot> {
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(to_snapshot),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_snapshot)");
            None
        }
    }
}

/// ドメインの状態を変更
pub fn set_domain_state(id: DomainId, state: DomainState) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                let old_state = domain.state;
                domain.state = state;
                log::info!("[DOMAIN] {} state: {:?} -> {:?}\n", id, old_state, state);
                if state == DomainState::Terminated {
                    unregister_domain_quota(id);
                } else {
                    sync_domain_quota(
                        id,
                        domain.priority,
                        domain.cpu_limit_percent,
                        domain.memory_limit_bytes,
                        domain.io_bandwidth_limit,
                    );
                }
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (set_domain_state) - no-op"),
    }
}

/// ドメインを開始
pub fn start_domain(id: DomainId) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut registry) => {
            if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                if domain.state != DomainState::Initializing {
                    return Err("Domain is not in initializing state");
                }
                domain.state = DomainState::Running;
                log::info!("[DOMAIN] Started {}\n", id);
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (start_domain)");
            Err("Domain registry poisoned")
        }
    }
}

/// Set NUMA node for a domain
pub fn set_domain_numa(id: DomainId, node: usize) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                domain.set_numa_node(node);
                log::info!("[DOMAIN] {} NUMA node set to {}\n", id, node);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (set_domain_numa) - no-op"),
    }
}

/// Set capability set for a domain (DriverCell metadata integration hook)
pub fn set_domain_capabilities(id: DomainId, caps: CapabilitySet) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                domain.set_capabilities(caps);
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (set_domain_capabilities)");
            Err("Domain registry poisoned")
        }
    }
}

/// Set scheduling priority metadata for a domain
pub fn set_domain_priority(id: DomainId, priority: DomainPriority) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                domain.set_priority(priority);
                sync_domain_quota(
                    id,
                    domain.priority,
                    domain.cpu_limit_percent,
                    domain.memory_limit_bytes,
                    domain.io_bandwidth_limit,
                );
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (set_domain_priority)");
            Err("Domain registry poisoned")
        }
    }
}

/// Set quota metadata for a domain
pub fn set_domain_resource_limits(
    id: DomainId,
    cpu_limit_percent: u64,
    memory_limit_bytes: u64,
    io_bandwidth_limit: u64,
) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                domain.set_resource_limits(
                    cpu_limit_percent,
                    memory_limit_bytes,
                    io_bandwidth_limit,
                );
                sync_domain_quota(
                    id,
                    domain.priority,
                    domain.cpu_limit_percent,
                    domain.memory_limit_bytes,
                    domain.io_bandwidth_limit,
                );
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (set_domain_resource_limits)");
            Err("Domain registry poisoned")
        }
    }
}

#[inline]
fn demote_priority(priority: DomainPriority) -> DomainPriority {
    match priority {
        DomainPriority::Critical => DomainPriority::Critical,
        DomainPriority::High => DomainPriority::Normal,
        DomainPriority::Normal | DomainPriority::Low => DomainPriority::Low,
    }
}

pub fn report_cpu_quota_exceeded(id: DomainId, now_ns: u64) -> CpuQuotaAction {
    if id == DomainId::KERNEL {
        return CpuQuotaAction::None;
    }

    match REGISTRY.lock() {
        Ok(mut guard) => {
            let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) else {
                return CpuQuotaAction::None;
            };

            if matches!(domain.state, DomainState::Terminated | DomainState::Stopped) {
                return CpuQuotaAction::None;
            }

            domain.cpu_violation_streak = domain.cpu_violation_streak.saturating_add(1);
            let next_priority = demote_priority(domain.priority);
            if next_priority != domain.priority {
                domain.priority = next_priority;
            }

            sync_domain_quota(
                id,
                domain.priority,
                domain.cpu_limit_percent,
                domain.memory_limit_bytes,
                domain.io_bandwidth_limit,
            );

            if domain.cpu_violation_streak >= CPU_QUOTA_SUSPEND_STREAK {
                let until_ns = now_ns.saturating_add(CPU_QUOTA_SUSPEND_WINDOW_NS);
                domain.quota_suspend_until_ns = until_ns;
                domain.state = DomainState::Suspended;
                return CpuQuotaAction::Suspend { until_ns };
            }

            CpuQuotaAction::YieldDemote
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (report_cpu_quota_exceeded)");
            CpuQuotaAction::None
        }
    }
}

pub fn report_cpu_quota_ok(id: DomainId) {
    if id == DomainId::KERNEL {
        return;
    }
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                domain.cpu_violation_streak = 0;
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (report_cpu_quota_ok)"),
    }
}

pub fn quota_suspend_deadline_ns(id: DomainId) -> Option<u64> {
    match REGISTRY.lock() {
        Ok(guard) => guard
            .domains
            .iter()
            .find(|d| d.id == id && d.quota_suspend_until_ns > 0)
            .map(|d| d.quota_suspend_until_ns),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (quota_suspend_deadline_ns)");
            None
        }
    }
}

pub fn is_domain_runnable_now(id: DomainId, now_ns: u64) -> bool {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) else {
                return false;
            };

            if domain.state == DomainState::Suspended {
                if domain.quota_suspend_until_ns > 0 && now_ns >= domain.quota_suspend_until_ns {
                    domain.state = DomainState::Running;
                    domain.quota_suspend_until_ns = 0;
                    domain.cpu_violation_streak = 0;
                    return true;
                }
                return false;
            }

            domain.state.is_runnable()
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (is_domain_runnable_now)");
            false
        }
    }
}

/// Get NUMA node for a domain
pub fn get_domain_numa(id: DomainId) -> Option<usize> {
    match REGISTRY.lock() {
        Ok(guard) => guard
            .domains
            .iter()
            .find(|d| d.id == id)
            .and_then(|d| d.get_numa_node()),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_numa)");
            None
        }
    }
}

#[cfg(test)]
mod tests;

/// Stop a domain
pub fn stop_domain(id: DomainId) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut registry) => {
            if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                domain.state = DomainState::Stopped;
                log::info!("[DOMAIN] Stopped {}\n", id);
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (stop_domain)");
            Err("Domain registry poisoned")
        }
    }
}

/// Resume a stopped or suspended domain
pub fn resume_domain(id: DomainId) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut registry) => {
            if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                match domain.state {
                    DomainState::Stopped | DomainState::Suspended => {
                        domain.state = DomainState::Running;
                        log::info!("[DOMAIN] Resumed {}\n", id);
                        Ok(())
                    }
                    DomainState::Running | DomainState::Initializing => Ok(()),
                    DomainState::Terminated => Err("Domain is terminated"),
                }
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (resume_domain)");
            Err("Domain registry poisoned")
        }
    }
}

/// ドメインを終了しリソースを回収
pub fn terminate_domain(id: DomainId) -> Result<(), &'static str> {
    if id == DomainId::KERNEL {
        return Err("Cannot terminate kernel domain");
    }

    // dependents をロック外で使うため clone() が必要
    // Note: Vec<DomainId> の clone は DomainId が Copy なら
    // 単純な memcpy に展開される（Vecヘッダーのみアロケート）
    let dependents: Vec<DomainId>;

    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                    domain.state = DomainState::Terminated;
                    // clone() はロックを保持したままの処理を避けるため
                    // デッドロック回避が clone のコストより重要
                    dependents = domain.dependents.clone();
                } else {
                    return Err("Domain not found");
                }
            }
            Err(_) => {
                log::error!("[DOMAIN] Registry poisoned (terminate_domain)");
                return Err("Domain registry poisoned");
            }
        }
    }

    // リソース回収（ロックを解放してから）
    reclaim_domain_resources(id);
    unregister_domain_quota(id);

    // 依存するドメインに通知
    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                for dep_id in dependents {
                    if let Some(dep) = registry.domains.iter_mut().find(|d| d.id == dep_id) {
                        dep.last_error = Some(format!("Dependency {} terminated", id.as_u64()));
                    }
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (terminate_domain notify) - skipping dependent updates"
            ),
        }
    }

    log::info!("[DOMAIN] Terminated {} and reclaimed resources\n", id);
    Ok(())
}

/// ドメインがパニックした場合の処理
pub fn handle_domain_panic(id: DomainId, message: String) {
    log::info!("[PANIC] {} crashed: {}\n", id, message);

    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                    domain.state = DomainState::Stopped;
                    domain.panic_message = Some(message);
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (handle_domain_panic) - could not record panic message"
            ),
        }
    }

    // リソース回収
    reclaim_domain_resources(id);
}

/// ドメインにタスクを追加
pub fn add_task_to_domain(domain_id: DomainId, task_id: u64) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == domain_id) {
                domain.add_task(task_id);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (add_task_to_domain) - no-op"),
    }
}
