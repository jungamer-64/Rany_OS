//! Domain registry and lifecycle internals.
use super::{
    DomainId, DomainLifecycleError, DomainPolicyError, DomainSecurity, DomainSecurityLookupError,
    DomainSnapshot, DomainState, DomainStopOutcome, RequestedCap,
    api::reclaim_domain_resources,
    kernel_security_handle,
    quota::{DomainPriority, DomainQuota, IoQuota, MemoryQuota, QuotaError, quota_manager},
};
use crate::error::{DomainErrorKind, KernelError};
use crate::security::CapabilitySet;
use crate::sync::PoisonLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

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
    pub(super) state: DomainState,
    /// セキュリティ主体（資格情報/ケイパビリティ）
    pub security: Arc<DomainSecurity>,
    pub(crate) code: Arc<super::DomainCodeState>,
    generation: Option<(
        crate::loader::CellId,
        Arc<crate::loader::code::CodeGeneration>,
    )>,

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
    /// Most recent terminated dependency, recorded without allocating during recovery.
    pub terminated_dependency: Option<DomainId>,
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
}

impl Domain {
    /// Prepare metadata before publication. Allocation failure publishes no
    /// domain or security handle; metadata prepared so far is dropped.
    pub fn new(id: DomainId, name: String) -> Result<Self, KernelError> {
        let security = if id == DomainId::KERNEL {
            kernel_security_handle()
        } else {
            Arc::try_new(DomainSecurity::default())
                .map_err(|_| KernelError::Memory(crate::error::MemoryError::OutOfMemory))?
        };

        Ok(Self {
            id,
            name,
            state: DomainState::Initializing,
            security,
            code: Arc::try_new(super::DomainCodeState::default())
                .map_err(|_| KernelError::Memory(crate::error::MemoryError::OutOfMemory))?,
            generation: None,
            dependencies: Vec::new(),
            dependents: Vec::new(),
            rref_count: 0,
            allocated_memory: 0,
            runtime_ticks: 0,
            context_switches: 0,
            created_at: crate::task::current_tick(),
            panic_message: None,
            terminated_dependency: None,
            numa_node: None,
            priority: DomainPriority::Normal,
            cpu_limit_percent: 100,
            memory_limit_bytes: u64::MAX,
            io_bandwidth_limit: 0,
        })
    }

    /// 実行可能かどうか
    pub fn is_runnable(&self) -> bool {
        self.state.is_runnable()
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

pub(crate) fn domain_quota_policy(
    id: DomainId,
    priority: DomainPriority,
    cpu_limit_percent: u64,
    memory_limit_bytes: u64,
    io_bandwidth_limit: u64,
) -> DomainQuota {
    if id == DomainId::KERNEL {
        return DomainQuota::kernel();
    }

    let mut quota = DomainQuota::new(id, priority).with_cpu_limit(cpu_limit_percent.min(100), 100);

    quota.memory = if memory_limit_bytes == 0 || memory_limit_bytes == u64::MAX {
        MemoryQuota::unlimited()
    } else {
        MemoryQuota::from_bytes(memory_limit_bytes)
    };

    if io_bandwidth_limit == 0 || io_bandwidth_limit == u64::MAX {
        quota.network_io = IoQuota::unlimited();
        quota.storage_io = IoQuota::unlimited();
    } else {
        let mbps = bytes_to_mb_ceil(io_bandwidth_limit);
        quota.network_io = IoQuota::new(mbps, mbps);
        quota.storage_io = IoQuota::new(mbps, mbps);
    }

    quota
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
pub(crate) struct DomainRegistry {
    /// 全ドメインのリスト
    pub(crate) domains: Vec<Domain>,
    /// 次のドメインID
    pub(crate) next_id: AtomicU64,
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
pub(crate) static REGISTRY: PoisonLock<DomainRegistry> = PoisonLock::new(DomainRegistry::new());

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

    // 初期化時は毒入れされていないはず
    let mut registry = REGISTRY
        .lock()
        .expect("domain registry poisoned during init");

    // カーネルドメインを作成
    let mut kernel = Domain::new(DomainId::KERNEL, "kernel".into())
        .expect("kernel domain metadata required at startup");
    kernel.state = DomainState::Running;
    registry.domains.push(kernel);
    quota_manager()
        .register(domain_quota_policy(
            DomainId::KERNEL,
            DomainPriority::Critical,
            100,
            u64::MAX,
            u64::MAX,
        ))
        .expect("kernel quota policy required at startup");
}

/// Prepare security/account metadata outside the registries, then publish the
/// domain without allocation. Rejection consumes an ID but publishes no domain.
pub fn create_domain(name: String) -> Result<DomainId, KernelError> {
    let (id, needed) = {
        let registry = REGISTRY
            .lock()
            .map_err(|_| KernelError::Domain(DomainErrorKind::RegistryPoisoned))?;
        let needed = registry
            .domains
            .len()
            .checked_add(1)
            .ok_or(KernelError::Domain(DomainErrorKind::RegistryFull))?;
        (registry.generate_id(), needed)
    };
    // Metadata allocation can enter OOM/domain lookup; it must run without either
    // registry lock. The final locked publication below performs no allocation.
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(needed)
        .map_err(|_| KernelError::Memory(crate::error::MemoryError::OutOfMemory))?;
    let domain = Domain::new(id, name)?;
    quota_manager()
        .register(domain_quota_policy(
            id,
            domain.priority,
            domain.cpu_limit_percent,
            domain.memory_limit_bytes,
            domain.io_bandwidth_limit,
        ))
        .map_err(|error| match error {
            QuotaError::MetadataAllocationFailed => {
                KernelError::Memory(crate::error::MemoryError::OutOfMemory)
            }
            QuotaError::RegistryUnavailable => {
                KernelError::Domain(DomainErrorKind::RegistryPoisoned)
            }
            error => KernelError::Domain(DomainErrorKind::Policy(DomainPolicyError::Quota(error))),
        })?;
    let result = {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                let required = registry.domains.len().checked_add(1);
                if required.is_none_or(|required| {
                    registry.domains.capacity() < required && prepared.capacity() < required
                }) {
                    Err(KernelError::Domain(DomainErrorKind::RegistryFull))
                } else {
                    if registry.domains.len() == registry.domains.capacity() {
                        prepared.extend(registry.domains.drain(..));
                        core::mem::swap(&mut registry.domains, &mut prepared);
                    }
                    registry.domains.push(domain);
                    Ok(id)
                }
            }
            Err(_) => Err(KernelError::Domain(DomainErrorKind::RegistryPoisoned)),
        }
    };
    // Rejection has consumed the ID but publishes no domain. Account rollback
    // and metadata destruction occur after releasing the registry lock.
    if result.is_err() {
        unregister_domain_quota(id);
    }
    drop(prepared);
    result
}

/// Spawn a new domain and apply requested capability grants atomically.
///
/// This is the Domain/Cell equivalent of the legacy `spawn_with_caps`.
pub fn spawn_domain_with_caps(
    name: String,
    requested: &[RequestedCap],
) -> Result<(DomainId, Vec<u64>), KernelError> {
    let parent = crate::task::current_subject().domain.as_u64();
    let cap_mgr = crate::security::capability::manager();

    for req in requested {
        let allowed = cap_mgr.has_capability(parent, crate::security::capability::CAP_SYS_ADMIN)
            || cap_mgr.get_capabilities(parent).is_permitted(req.cap)
            || cap_mgr
                .list_grants(parent, parent)
                .iter()
                .any(|t| t.cap == req.cap && t.delegatable);
        if !allowed {
            return Err(KernelError::Domain(DomainErrorKind::OwnershipViolation));
        }
    }

    let domain_id = create_domain(name)?;
    start_domain(domain_id).map_err(|_| KernelError::Domain(DomainErrorKind::LifecycleError))?;

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
                if let Err(error) = terminate_domain(domain_id) {
                    log::error!(
                        "[DOMAIN] Failed grant rollback retained domain {}: {}",
                        domain_id,
                        error
                    );
                }
                return Err(KernelError::Domain(DomainErrorKind::LifecycleError));
            }
        }
    }

    Ok((domain_id, created_tokens))
}

/// Observe immutable security metadata for a live domain. This snapshot grants
/// no quota or resource-publication admission; those owners check separately.
pub fn domain_security_handle(
    id: DomainId,
) -> Result<Arc<DomainSecurity>, DomainSecurityLookupError> {
    let registry = REGISTRY
        .lock()
        .map_err(|_| DomainSecurityLookupError::RegistryUnavailable)?;
    let domain = registry
        .domains
        .iter()
        .find(|domain| domain.id == id)
        .ok_or(DomainSecurityLookupError::UnknownDomain(id))?;
    if !domain.state.is_active() {
        return Err(DomainSecurityLookupError::Terminated(id));
    }
    Ok(Arc::clone(&domain.security))
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

/// Commit prepared resource metadata while owner termination is excluded.
/// The callback must perform only its allocation-free publication. Prepare
/// fallible metadata and device authorization before entering this scope, and
/// finalize payloads after leaving it. Rejection returns the prepared owner
/// unchanged after unlocking. No admission can escape with the result.
pub(crate) fn with_resource_admission<T, R>(
    owner: DomainId,
    prepared: T,
    publish: impl FnOnce(super::DomainResourceAdmission<'_>, T) -> R,
) -> Result<R, (super::DomainResourceAdmissionError, T)> {
    use super::{DomainResourceAdmission, DomainResourceAdmissionError};
    let registry = match REGISTRY.lock() {
        Ok(registry) => registry,
        Err(_) => return Err((DomainResourceAdmissionError::RegistryUnavailable, prepared)),
    };
    let admission = registry
        .domains
        .iter()
        .find(|domain| domain.id == owner)
        .ok_or(DomainResourceAdmissionError::UnknownOwner)
        .and_then(|domain| DomainResourceAdmission::checked(&domain.id, &domain.state));
    match admission {
        Ok(admission) => Ok(publish(admission, prepared)),
        Err(cause) => {
            drop(registry);
            Err((cause, prepared))
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
        tasks: 0,
        task_ids: Vec::new(),
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
        terminated_dependency: domain.terminated_dependency,
    }
}

/// List all domain snapshots.
pub fn list_domain_snapshots() -> Vec<DomainSnapshot> {
    let mut snapshots = match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().map(to_snapshot).collect(),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (list_domain_snapshots)");
            Vec::new()
        }
    };
    for snapshot in &mut snapshots {
        snapshot.task_ids = crate::task::domain_task_ids(snapshot.id);
        snapshot.tasks = snapshot.task_ids.len();
    }
    snapshots
}

/// Get a single domain snapshot by ID.
pub fn get_domain_snapshot(id: DomainId) -> Option<DomainSnapshot> {
    let mut snapshot = match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(to_snapshot),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_snapshot)");
            None
        }
    }?;
    snapshot.task_ids = crate::task::domain_task_ids(id);
    snapshot.tasks = snapshot.task_ids.len();
    Some(snapshot)
}

/// ドメインを開始
pub fn start_domain(id: DomainId) -> Result<(), DomainLifecycleError> {
    let mut registry = REGISTRY
        .lock()
        .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
    let domain = registry
        .domains
        .iter_mut()
        .find(|domain| domain.id == id)
        .ok_or(DomainLifecycleError::NotFound)?;
    if domain.state != DomainState::Initializing {
        return Err(DomainLifecycleError::InvalidState(domain.state));
    }
    domain.state = DomainState::Running;
    Ok(())
}

/// Clear diagnostics and reopen only a completed stop, atomically with admission.
pub(super) fn restart_stopped_domain(id: DomainId) -> Result<(), DomainLifecycleError> {
    let mut registry = REGISTRY
        .lock()
        .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
    let domain = registry
        .domains
        .iter_mut()
        .find(|domain| domain.id == id)
        .ok_or(DomainLifecycleError::NotFound)?;
    if domain.state != DomainState::Stopped {
        return Err(DomainLifecycleError::InvalidState(domain.state));
    }
    domain.panic_message = None;
    domain.terminated_dependency = None;
    domain.state = DomainState::Running;
    Ok(())
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

/// Prepare replacement security outside the registry lock. Existing handles
/// retain their snapshot; allocation failure or a concurrent security update
/// publishes nothing. The caller may retry `SecurityChanged` with fresh policy.
pub fn set_domain_capabilities(id: DomainId, caps: CapabilitySet) -> Result<(), DomainPolicyError> {
    let observed = {
        let guard = REGISTRY
            .lock()
            .map_err(|_| DomainPolicyError::RegistryUnavailable)?;
        guard
            .domains
            .iter()
            .find(|domain| domain.id == id)
            .ok_or(DomainPolicyError::NotFound)?
            .security
            .clone()
    };
    let replacement = Arc::try_new(DomainSecurity {
        credentials: observed.credentials,
        caps,
    })
    .map_err(|_| DomainPolicyError::MetadataAllocationFailed)?;
    let retired = {
        let mut guard = REGISTRY
            .lock()
            .map_err(|_| DomainPolicyError::RegistryUnavailable)?;
        let domain = guard
            .domains
            .iter_mut()
            .find(|domain| domain.id == id)
            .ok_or(DomainPolicyError::NotFound)?;
        if !Arc::ptr_eq(&domain.security, &observed) {
            return Err(DomainPolicyError::SecurityChanged);
        }
        core::mem::replace(&mut domain.security, replacement)
    };
    // The last snapshot may return heap RAM; release it after unlocking too.
    drop(retired);
    Ok(())
}

/// Set scheduling priority metadata for a domain
pub fn set_domain_priority(
    id: DomainId,
    priority: DomainPriority,
) -> Result<(), DomainPolicyError> {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                quota_manager()
                    .update_policy(domain_quota_policy(
                        id,
                        priority,
                        domain.cpu_limit_percent,
                        domain.memory_limit_bytes,
                        domain.io_bandwidth_limit,
                    ))
                    .map_err(DomainPolicyError::Quota)?;
                domain.set_priority(priority);
                Ok(())
            } else {
                Err(DomainPolicyError::NotFound)
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (set_domain_priority)");
            Err(DomainPolicyError::RegistryUnavailable)
        }
    }
}

/// Set quota metadata for a domain
pub fn set_domain_resource_limits(
    id: DomainId,
    cpu_limit_percent: u64,
    memory_limit_bytes: u64,
    io_bandwidth_limit: u64,
) -> Result<(), DomainPolicyError> {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                quota_manager()
                    .update_policy(domain_quota_policy(
                        id,
                        domain.priority,
                        cpu_limit_percent,
                        memory_limit_bytes,
                        io_bandwidth_limit,
                    ))
                    .map_err(DomainPolicyError::Quota)?;
                domain.set_resource_limits(
                    cpu_limit_percent,
                    memory_limit_bytes,
                    io_bandwidth_limit,
                );
                Ok(())
            } else {
                Err(DomainPolicyError::NotFound)
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (set_domain_resource_limits)");
            Err(DomainPolicyError::RegistryUnavailable)
        }
    }
}

pub fn is_domain_runnable_now(id: DomainId, _now_ns: u64) -> bool {
    if id == DomainId::KERNEL {
        return true;
    }

    match REGISTRY.lock() {
        Ok(guard) => {
            let Some(domain) = guard.domains.iter().find(|d| d.id == id) else {
                return false;
            };

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

/// Requests stop before testing completion. Suspended polls retain their
/// stack and may resume to reach a poll boundary; new polls are denied.
pub fn stop_domain(id: DomainId) -> Result<DomainStopOutcome, DomainLifecycleError> {
    if id == DomainId::KERNEL {
        return Err(DomainLifecycleError::KernelDomain);
    }
    crate::task::domain_stop_boundary(id, |outcome| {
        let mut registry = REGISTRY
            .lock()
            .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
        let domain = registry
            .domains
            .iter_mut()
            .find(|domain| domain.id == id)
            .ok_or(DomainLifecycleError::NotFound)?;
        if domain.state == DomainState::Terminated {
            return Ok(DomainStopOutcome::Complete);
        }
        let outcome = match outcome {
            DomainStopOutcome::Complete if domain.code.executing() != 0 => {
                DomainStopOutcome::InProgress {
                    active_polls: domain.code.executing(),
                    interrupted_polls: 0,
                }
            }
            other => other,
        };
        if domain.state != DomainState::Terminating {
            domain.state = match outcome {
                DomainStopOutcome::Complete => DomainState::Stopped,
                DomainStopOutcome::InProgress { .. } => DomainState::Stopping,
            };
        }
        Ok(outcome)
    })
}

/// Resume a stopped or suspended domain
pub fn resume_domain(id: DomainId) -> Result<(), DomainLifecycleError> {
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
                    state @ (DomainState::Terminating
                    | DomainState::Terminated
                    | DomainState::Stopping) => Err(DomainLifecycleError::InvalidState(state)),
                }
            } else {
                Err(DomainLifecycleError::NotFound)
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (resume_domain)");
            Err(DomainLifecycleError::RegistryPoisoned)
        }
    }
}

/// ドメインを終了しリソースを回収
pub fn terminate_domain(id: DomainId) -> Result<(), DomainLifecycleError> {
    if id == DomainId::KERNEL {
        return Err(DomainLifecycleError::KernelDomain);
    }

    let admission = {
        let registry = REGISTRY
            .lock()
            .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
        let domain = registry
            .domains
            .iter()
            .find(|domain| domain.id == id)
            .ok_or(DomainLifecycleError::NotFound)?;
        if domain.state == DomainState::Terminated {
            return Ok(());
        }
        quota_manager()
            .bind_memory(id)
            .map_err(DomainLifecycleError::Quota)?
    };
    let reclamation = crate::task::domain_stop_boundary(id, |outcome| {
        let mut registry = REGISTRY
            .lock()
            .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
        let domain = registry
            .domains
            .iter_mut()
            .find(|domain| domain.id == id)
            .ok_or(DomainLifecycleError::NotFound)?;
        if domain.state == DomainState::Terminated {
            return Ok(None);
        }
        if outcome != DomainStopOutcome::Complete {
            if domain.state != DomainState::Terminating {
                domain.state = DomainState::Stopping;
            }
            return Err(DomainLifecycleError::Busy(outcome));
        }
        let executions = domain.code.executing();
        if executions != 0 {
            if domain.state != DomainState::Terminating {
                domain.state = DomainState::Stopping;
            }
            return Err(DomainLifecycleError::CodeBusy { leases: executions });
        }
        let reclamation = domain
            .code
            .claim_reclamation()
            .ok_or(DomainLifecycleError::ReclamationInProgress)?;
        domain.state = DomainState::Terminating;
        Ok(Some(reclamation))
    })?;
    let Some(_reclamation) = reclamation else {
        return Ok(());
    };
    // Destruct Future objects while their code and domain resources remain
    // mapped. Only poll-boundary states can be retired here.
    crate::task::retire_domain_tasks(id);
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    let cleanup = crate::resource_registry::cleanup_owner_domain(id)?;
    #[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
    let cleanup = crate::resource_registry::OwnerCleanupStats::default();
    let leases = domain_code_leases(id);
    if leases != 0 {
        return Err(DomainLifecycleError::CodeBusy { leases });
    }

    // The bound generation is still owned while the domain is Terminating.
    // Module teardown may admit finalization work, whose tasks and resources
    // must finish before the domain becomes Terminated or its memory is freed.
    let bound_cell = with_domain(id, |domain| {
        domain.generation.as_ref().map(|(cell, _)| *cell)
    })
    .flatten();
    if let Some(cell) = bound_cell {
        // Successful loader removal has already acknowledged module teardown.
        if crate::loader::with_registry(|registry| registry.get(cell).is_some()) {
            crate::loader::cell_runtime::finalize(cell).map_err(|cause| {
                DomainLifecycleError::CodeFinalization {
                    cell_id: cell.as_u64(),
                    cause,
                }
            })?;
        }
    }
    let leases = domain_code_leases(id);
    if leases != 0 {
        return Err(DomainLifecycleError::CodeBusy { leases });
    }

    reclaim_domain_resources(id, cleanup);
    {
        let mut registry = REGISTRY
            .lock()
            .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
        let index = registry
            .domains
            .iter()
            .position(|domain| domain.id == id)
            .ok_or(DomainLifecycleError::NotFound)?;
        let (before, rest) = registry.domains.split_at_mut(index);
        let (domain, after) = rest.split_first_mut().expect("selected existing domain");
        unregister_domain_quota(id);
        domain.state = DomainState::Terminated;
        if domain.dependents.contains(&id) {
            domain.terminated_dependency = Some(id);
        }
        for dependent in before.iter_mut().chain(after.iter_mut()) {
            if domain.dependents.contains(&dependent.id) {
                dependent.terminated_dependency = Some(id);
            }
        }
    }
    drop(admission);
    log::info!("[DOMAIN] Terminated {} and initiated resource return", id);
    Ok(())
}

/// Recovery requests stop without consuming the domain's ability to restart.
pub(crate) fn request_fault_stop(
    id: DomainId,
    message: String,
) -> Result<DomainStopOutcome, DomainLifecycleError> {
    {
        let mut registry = REGISTRY
            .lock()
            .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
        let domain = registry
            .domains
            .iter_mut()
            .find(|domain| domain.id == id)
            .ok_or(DomainLifecycleError::NotFound)?;
        domain.panic_message = Some(message);
    }
    stop_domain(id)
}

/// ドメインがパニックした場合の処理
pub fn handle_domain_panic(id: DomainId, message: String) {
    log::info!("[PANIC] {} crashed: {}\n", id, message);

    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                    domain.panic_message = Some(message);
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (handle_domain_panic) - could not record panic message"
            ),
        }
    }

    // A panic report does not prove that every interrupted stack is gone.
    // Retain resources until the ordinary stop/termination boundary succeeds.
    if let Err(error) = terminate_domain(id) {
        log::warn!("[DOMAIN] Panic cleanup remains incomplete for {id}: {error}");
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod security_tests {
    use super::*;

    #[test]
    fn capability_publication_keeps_existing_security_snapshots_immutable() {
        let id = create_domain(String::from("security_publication")).expect("domain admission");
        let original = domain_security_handle(id).expect("live security snapshot");
        assert_eq!(original.caps, CapabilitySet::empty());
        set_domain_capabilities(id, CapabilitySet::full()).expect("security publication");
        let granted = domain_security_handle(id).expect("live security snapshot");
        assert_eq!(granted.caps, CapabilitySet::full());
        assert_eq!(granted.credentials, original.credentials);
        assert_eq!(original.caps, CapabilitySet::empty());
        set_domain_capabilities(id, CapabilitySet::empty()).expect("security replacement");
        assert_eq!(
            domain_security_handle(id)
                .expect("live security snapshot")
                .caps,
            CapabilitySet::empty()
        );
        assert_eq!(granted.caps, CapabilitySet::full());
        terminate_domain(id).expect("domain cleanup");
    }

    #[test]
    fn capability_publication_rejects_a_missing_domain() {
        assert_eq!(
            set_domain_capabilities(DomainId::new(u64::MAX), CapabilitySet::empty()),
            Err(DomainPolicyError::NotFound)
        );
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod termination_tests {
    use super::*;

    #[test]
    fn termination_notifies_only_dependents_and_retains_live_return_targets() {
        let before = create_domain(String::from("dependent_before")).expect("domain admission");
        let source = create_domain(String::from("dependency")).expect("domain admission");
        let after = create_domain(String::from("dependent_after")).expect("domain admission");
        let unrelated = create_domain(String::from("unrelated")).expect("domain admission");
        crate::domain::lifecycle::add_domain_dependency(before, source).expect("dependency");
        crate::domain::lifecycle::add_domain_dependency(after, source).expect("dependency");
        let binding = quota_manager()
            .bind_memory(source)
            .expect("execution admission");
        let credit = binding.reserve(37).expect("payload admission");
        terminate_domain(source).expect("termination publication");
        assert_eq!(get_domain_state(source), Some(DomainState::Terminated));
        assert_eq!(
            with_domain(before, |d| d.terminated_dependency),
            Some(Some(source))
        );
        assert_eq!(
            with_domain(after, |d| d.terminated_dependency),
            Some(Some(source))
        );
        assert_eq!(
            with_domain(unrelated, |d| d.terminated_dependency),
            Some(None)
        );
        assert_eq!(quota_manager().get_stats(source).unwrap().memory_used, 37);
        assert!(
            matches!(binding.reserve(1), Err(QuotaError::Retired { domain_id }) if domain_id == source)
        );
        assert!(matches!(
            crate::domain::lifecycle::restart_domain(source),
            Err(crate::domain::lifecycle::DomainError::Lifecycle(
                DomainLifecycleError::InvalidState(DomainState::Terminated)
            ))
        ));
        terminate_domain(source).expect("idempotent termination");
        drop(credit);
        drop(binding);
        assert!(quota_manager().get_stats(source).is_none());
        for id in [before, after, unrelated] {
            terminate_domain(id).expect("fixture cleanup");
        }
    }

    #[test]
    fn termination_rejections_leave_the_domain_and_admission_unchanged() {
        assert_eq!(
            terminate_domain(DomainId::KERNEL),
            Err(DomainLifecycleError::KernelDomain)
        );
        assert_eq!(
            terminate_domain(DomainId::new(u64::MAX)),
            Err(DomainLifecycleError::NotFound)
        );
        let id = create_domain(String::from("termination_admission")).expect("domain admission");
        quota_manager().unregister(id);
        assert!(matches!(
            terminate_domain(id),
            Err(DomainLifecycleError::Quota(_))
        ));
        assert_eq!(get_domain_state(id), Some(DomainState::Initializing));
        assert_eq!(with_domain(id, |d| d.terminated_dependency), Some(None));
        // Prepare a new account only after the rejected, zero-progress attempt.
        quota_manager()
            .register(DomainQuota::new(id, DomainPriority::Normal))
            .expect("re-admission");
        terminate_domain(id).expect("fixture cleanup");
    }
}

pub(crate) fn acquire_future_code_lease(id: DomainId) -> Option<super::DomainCodeLease> {
    let active = crate::cpu::CurrentCpu::acquire().and_then(|cpu| {
        cpu.execution()
            .filter(|subject| subject.domain == id)
            .and_then(|_| cpu.execution_cell())
    });
    let inherited = match active {
        Some(cell) => Some(crate::loader::acquire_code_lease(cell)?),
        None => None,
    };
    let registry = REGISTRY.lock().ok()?;
    let domain = registry
        .domains
        .iter()
        .find(|domain| domain.id == id && domain.state.is_runnable())?;
    let generation = match inherited {
        Some(lease) => Some(lease),
        None => match &domain.generation {
            Some((cell, generation)) => Some(generation.acquire(*cell)?),
            None => None,
        },
    };
    Some(super::DomainCodeLease::future(
        domain.code.clone(),
        generation,
    ))
}

/// Capture the registering invocation's exact generation before storing callbacks.
pub(crate) fn acquire_resource_code_lease(id: DomainId) -> Option<super::DomainCodeLease> {
    let active = crate::cpu::CurrentCpu::acquire().and_then(|cpu| {
        cpu.execution()
            .filter(|subject| subject.domain == id)
            .and_then(|_| cpu.execution_cell())
    });
    let inherited = match active {
        Some(cell) => Some(crate::loader::acquire_code_lease(cell)?),
        None => None,
    };
    let registry = REGISTRY.lock().ok()?;
    let domain = registry
        .domains
        .iter()
        .find(|domain| domain.id == id && domain.state.is_runnable())?;
    let generation = match inherited {
        Some(lease) => Some(lease),
        None => match &domain.generation {
            Some((cell, generation)) => Some(generation.acquire(*cell)?),
            None => None,
        },
    };
    Some(super::DomainCodeLease::resource(
        domain.code.clone(),
        generation,
    ))
}

#[derive(Clone, Copy)]
pub(crate) enum ResourceInvocation {
    Operation,
    Finalize,
}

/// Invocation derives only from the registered owner's retained lease. Closing
/// loader admission cannot prevent that owner from finishing its finalizer.
pub(crate) fn acquire_resource_execution_lease(
    id: DomainId,
    resource: &super::DomainCodeLease,
    invocation: ResourceInvocation,
) -> Option<super::DomainCodeLease> {
    let registry = REGISTRY.lock().ok()?;
    let domain = registry.domains.iter().find(|domain| domain.id == id)?;
    let admitted = match invocation {
        ResourceInvocation::Operation => domain.state.is_runnable(),
        ResourceInvocation::Finalize => domain.state != DomainState::Terminated,
    };
    if !admitted {
        return None;
    }
    resource.execution_from_resource(&domain.code)
}

/// Retains a specific invocation generation instead of the domain's current dispatch.
pub(crate) fn acquire_cell_execution_lease(
    id: DomainId,
    cell: crate::loader::CellId,
) -> Option<super::DomainCodeLease> {
    let generation = crate::loader::acquire_code_lease(cell)?;
    let registry = REGISTRY.lock().ok()?;
    let domain = registry
        .domains
        .iter()
        .find(|domain| domain.id == id && domain.state.is_runnable())?;
    Some(super::DomainCodeLease::execution(
        domain.code.clone(),
        Some(generation),
    ))
}

pub(crate) fn acquire_execution_code_lease(id: DomainId) -> Option<super::DomainCodeLease> {
    let registry = REGISTRY.lock().ok()?;
    let domain = registry
        .domains
        .iter()
        .find(|domain| domain.id == id && domain.state.is_runnable())?;
    let generation = match &domain.generation {
        Some((cell, generation)) => Some(generation.acquire(*cell)?),
        None => None,
    };
    Some(super::DomainCodeLease::execution(
        domain.code.clone(),
        generation,
    ))
}

pub(crate) fn domain_code_leases(id: DomainId) -> usize {
    let registry = REGISTRY.lock().unwrap_or_else(|error| error.into_inner());
    registry
        .domains
        .iter()
        .find(|domain| domain.id == id)
        .map_or(0, |domain| domain.code.total())
}

/// A domain delegates fresh entries to this exact loaded code generation.
/// Existing Futures retain the old generation across publication and rollback.
pub(crate) fn bind_code_generation(
    id: DomainId,
    cell: crate::loader::CellId,
) -> Result<(), DomainLifecycleError> {
    let generation =
        crate::loader::with_registry(|registry| registry.get(cell).map(|cell| cell.code.clone()))
            .ok_or(DomainLifecycleError::NotFound)?;
    let mut registry = REGISTRY
        .lock()
        .map_err(|_| DomainLifecycleError::RegistryPoisoned)?;
    let domain = registry
        .domains
        .iter_mut()
        .find(|domain| domain.id == id)
        .ok_or(DomainLifecycleError::NotFound)?;
    if !matches!(
        domain.state,
        DomainState::Initializing | DomainState::Running
    ) {
        return Err(DomainLifecycleError::InvalidState(domain.state));
    }
    domain.generation = Some((cell, generation));
    Ok(())
}

pub(crate) fn acquire_teardown_code_lease(
    id: DomainId,
    source: Option<&crate::loader::code::CodeLease>,
) -> Option<super::DomainCodeLease> {
    let generation = match source {
        Some(source) => Some(source.retain()?),
        None => None,
    };
    let registry = REGISTRY.lock().ok()?;
    let domain = registry.domains.iter().find(|domain| {
        domain.id == id
            && matches!(
                domain.state,
                DomainState::Initializing
                    | DomainState::Running
                    | DomainState::Stopping
                    | DomainState::Stopped
                    | DomainState::Terminating
            )
    })?;
    Some(super::DomainCodeLease::execution(
        domain.code.clone(),
        generation,
    ))
}

/// Cleanup may continue without reopening ordinary task or code admission.
/// This check grants no authority: the task already owns its finalization lease.
pub(crate) fn can_finalize(id: DomainId) -> bool {
    let registry = REGISTRY.lock().unwrap_or_else(|error| error.into_inner());
    registry.domains.iter().any(|domain| {
        domain.id == id
            && matches!(
                domain.state,
                DomainState::Initializing
                    | DomainState::Running
                    | DomainState::Stopping
                    | DomainState::Stopped
                    | DomainState::Terminating
            )
    })
}

/// Acquire only from an already retained finalizer generation. Callers hold
/// the execution authority established by the registered owner, not a cell ID.
pub(crate) fn acquire_finalization_future_lease(
    id: DomainId,
    source: Option<&crate::loader::code::CodeLease>,
) -> Option<super::DomainCodeLease> {
    let generation = match source {
        Some(source) => Some(source.retain()?),
        None => None,
    };
    let registry = REGISTRY.lock().ok()?;
    let domain = registry.domains.iter().find(|domain| {
        domain.id == id
            && matches!(
                domain.state,
                DomainState::Initializing
                    | DomainState::Running
                    | DomainState::Stopping
                    | DomainState::Stopped
                    | DomainState::Terminating
            )
    })?;
    Some(super::DomainCodeLease::future(
        domain.code.clone(),
        generation,
    ))
}
