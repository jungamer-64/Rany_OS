//! Domain registry and lifecycle internals.
use super::{
    DomainId, DomainLifecycleError, DomainPolicyError, DomainSecurity, DomainSecurityLookupError,
    DomainSnapshot, DomainState, DomainStopOutcome,
    api::reclaim_domain_resources,
    kernel_security_handle,
    quota::{
        CpuQuota, DomainPriority, DomainQuota, IoQuota, MemoryQuota, QuotaError, quota_manager,
    },
};
use crate::error::{DomainErrorKind, KernelError};
use crate::security::CapabilitySet;
use crate::sync::PoisonLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

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
    dependencies: Arc<[DomainId]>,

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
            dependencies: Arc::try_clone_from_ref(&[] as &[DomainId])
                .map_err(|_| KernelError::Memory(crate::error::MemoryError::OutOfMemory))?,
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
) -> Result<DomainQuota, QuotaError> {
    if id == DomainId::KERNEL {
        return Ok(DomainQuota::kernel());
    }

    let mut quota = DomainQuota::new(id, priority).with_cpu_limit(CpuQuota::new(
        cpu_limit_percent,
        Duration::from_millis(100),
    )?);

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

    Ok(quota)
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

/// Dependency publication failure; no edge from this attempt is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainDependencyError {
    RegistryPoisoned,
    NotFound {
        domain: DomainId,
    },
    Unavailable {
        domain: DomainId,
        state: DomainState,
    },
    MetadataAllocationFailed,
    DependenciesChanged {
        domain: DomainId,
    },
}

impl core::fmt::Display for DomainDependencyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RegistryPoisoned => formatter.write_str("domain registry poisoned"),
            Self::NotFound { domain } => {
                write!(formatter, "dependency endpoint {domain} not found")
            }
            Self::Unavailable { domain, state } => {
                write!(formatter, "dependency endpoint {domain} is {state:?}")
            }
            Self::MetadataAllocationFailed => {
                formatter.write_str("dependency metadata allocation failed")
            }
            Self::DependenciesChanged { domain } => {
                write!(
                    formatter,
                    "dependencies of {domain} changed before publication"
                )
            }
        }
    }
}

struct PreparedDependency {
    dependent: DomainId,
    dependency: DomainId,
    observed: Arc<[DomainId]>,
    replacement: Arc<[DomainId]>,
}

impl PreparedDependency {
    fn new(
        dependent: DomainId,
        dependency: DomainId,
        observed: Arc<[DomainId]>,
    ) -> Result<Self, DomainDependencyError> {
        let needed = observed
            .len()
            .checked_add(1)
            .ok_or(DomainDependencyError::MetadataAllocationFailed)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(needed)
            .map_err(|_| DomainDependencyError::MetadataAllocationFailed)?;
        entries.extend_from_slice(&observed);
        entries.push(dependency);
        let replacement = Arc::try_clone_from_ref(entries.as_slice())
            .map_err(|_| DomainDependencyError::MetadataAllocationFailed)?;
        Ok(Self {
            dependent,
            dependency,
            observed,
            replacement,
        })
    }
}

impl DomainRegistry {
    fn dependency_endpoint(&self, id: DomainId) -> Result<&Domain, DomainDependencyError> {
        let domain = self
            .domains
            .iter()
            .find(|domain| domain.id == id)
            .ok_or(DomainDependencyError::NotFound { domain: id })?;
        if matches!(
            domain.state,
            DomainState::Stopping | DomainState::Terminating | DomainState::Terminated
        ) {
            return Err(DomainDependencyError::Unavailable {
                domain: id,
                state: domain.state,
            });
        }
        Ok(domain)
    }

    fn observe_dependency(
        &self,
        dependent: DomainId,
        dependency: DomainId,
    ) -> Result<Arc<[DomainId]>, DomainDependencyError> {
        self.dependency_endpoint(dependency)?;
        Ok(Arc::clone(
            &self.dependency_endpoint(dependent)?.dependencies,
        ))
    }

    fn publish_dependency(
        &mut self,
        prepared: &PreparedDependency,
    ) -> Result<Option<Arc<[DomainId]>>, DomainDependencyError> {
        self.dependency_endpoint(prepared.dependency)?;
        self.dependency_endpoint(prepared.dependent)?;
        let domain = self
            .domains
            .iter_mut()
            .find(|domain| domain.id == prepared.dependent)
            .ok_or(DomainDependencyError::NotFound {
                domain: prepared.dependent,
            })?;
        if domain.dependencies.contains(&prepared.dependency) {
            return Ok(None);
        }
        if !Arc::ptr_eq(&domain.dependencies, &prepared.observed) {
            return Err(DomainDependencyError::DependenciesChanged {
                domain: prepared.dependent,
            });
        }
        Ok(Some(core::mem::replace(
            &mut domain.dependencies,
            Arc::clone(&prepared.replacement),
        )))
    }
}

/// Publish an edge while both endpoints still accept dependency registration.
/// Allocation and disposal of replaced metadata occur outside the registry lock.
///
/// # Errors
/// Missing or stopping/reclaimed endpoints reject the edge. Allocation failure
/// publishes nothing. `DependenciesChanged` requires a fresh retry; another
/// publisher may have updated the dependency set meanwhile.
pub fn add_domain_dependency(
    dependent: DomainId,
    dependency: DomainId,
) -> Result<(), DomainDependencyError> {
    let observed = REGISTRY
        .lock()
        .map_err(|_| DomainDependencyError::RegistryPoisoned)?
        .observe_dependency(dependent, dependency)?;
    if observed.contains(&dependency) {
        return Ok(());
    }
    let prepared = PreparedDependency::new(dependent, dependency, observed)?;
    let replaced = {
        let mut registry = REGISTRY
            .lock()
            .map_err(|_| DomainDependencyError::RegistryPoisoned)?;
        registry.publish_dependency(&prepared)?
    };
    drop(replaced);
    Ok(())
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
    domain_quota_policy(
        id,
        domain.priority,
        domain.cpu_limit_percent,
        domain.memory_limit_bytes,
        domain.io_bandwidth_limit,
    )
    .and_then(|quota| quota_manager().register(quota))
    .map_err(|error| match error {
        QuotaError::MetadataAllocationFailed => {
            KernelError::Memory(crate::error::MemoryError::OutOfMemory)
        }
        QuotaError::RegistryUnavailable => KernelError::Domain(DomainErrorKind::RegistryPoisoned),
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
fn to_snapshot(domain: &Domain, domains: &[Domain]) -> DomainSnapshot {
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
        dependencies: domain.dependencies.to_vec(),
        dependents: domains
            .iter()
            .filter(|candidate| candidate.dependencies.contains(&domain.id))
            .map(|candidate| candidate.id)
            .collect(),
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
        Ok(guard) => guard
            .domains
            .iter()
            .map(|domain| to_snapshot(domain, &guard.domains))
            .collect(),
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
        Ok(guard) => guard
            .domains
            .iter()
            .find(|d| d.id == id)
            .map(|domain| to_snapshot(domain, &guard.domains)),
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
/// Retained Futures and their memory account remain registered.
///
/// # Errors
/// Registry failure, a missing domain, or an incomplete/reclaimed stop rejects
/// the restart without clearing diagnostics or reopening admission.
pub fn restart_domain(id: DomainId) -> Result<(), DomainLifecycleError> {
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
                let quota = domain_quota_policy(
                    id,
                    priority,
                    domain.cpu_limit_percent,
                    domain.memory_limit_bytes,
                    domain.io_bandwidth_limit,
                )
                .map_err(DomainPolicyError::Quota)?;
                quota_manager()
                    .update_policy(quota)
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
                let quota = domain_quota_policy(
                    id,
                    domain.priority,
                    cpu_limit_percent,
                    memory_limit_bytes,
                    io_bandwidth_limit,
                )
                .map_err(DomainPolicyError::Quota)?;
                quota_manager()
                    .update_policy(quota)
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
        unregister_domain_quota(id);
        registry.domains[index].state = DomainState::Terminated;
        for dependent in &mut registry.domains {
            if dependent.dependencies.contains(&id) {
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

    fn dependency_registry() -> DomainRegistry {
        let mut registry = DomainRegistry::new();
        for id in 1..=3 {
            registry
                .domains
                .push(Domain::new(DomainId::new(id), String::from("endpoint")).unwrap());
        }
        registry
    }

    fn prepare_dependency(registry: &DomainRegistry, source: u64) -> PreparedDependency {
        let dependent = DomainId::new(1);
        let dependency = DomainId::new(source);
        PreparedDependency::new(
            dependent,
            dependency,
            registry.observe_dependency(dependent, dependency).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn dependency_publication_is_idempotent_and_projects_reverse_edges() {
        let mut registry = dependency_registry();
        let prepared = prepare_dependency(&registry, 2);
        drop(registry.publish_dependency(&prepared).unwrap());
        assert!(registry.publish_dependency(&prepared).unwrap().is_none());
        let consumer = to_snapshot(&registry.domains[0], &registry.domains);
        let source = to_snapshot(&registry.domains[1], &registry.domains);
        assert_eq!(consumer.dependencies, [DomainId::new(2)]);
        assert_eq!(source.dependents, [DomainId::new(1)]);
    }

    #[test]
    fn prepared_dependency_revalidates_endpoint_admission() {
        let mut registry = dependency_registry();
        let prepared = prepare_dependency(&registry, 2);
        registry.domains[1].state = DomainState::Terminated;
        assert_eq!(
            registry.publish_dependency(&prepared),
            Err(DomainDependencyError::Unavailable {
                domain: DomainId::new(2),
                state: DomainState::Terminated,
            })
        );
        assert!(registry.domains[0].dependencies.is_empty());
        assert!(
            to_snapshot(&registry.domains[1], &registry.domains)
                .dependents
                .is_empty()
        );
        let mut stopped_consumer = dependency_registry();
        let prepared = prepare_dependency(&stopped_consumer, 2);
        stopped_consumer.domains[0].state = DomainState::Stopping;
        assert_eq!(
            stopped_consumer.publish_dependency(&prepared),
            Err(DomainDependencyError::Unavailable {
                domain: DomainId::new(1),
                state: DomainState::Stopping,
            })
        );
        assert!(stopped_consumer.domains[0].dependencies.is_empty());
    }

    #[test]
    fn competing_dependency_publications_preserve_the_committed_edge() {
        let mut registry = dependency_registry();
        let first = prepare_dependency(&registry, 2);
        let stale = prepare_dependency(&registry, 3);
        drop(registry.publish_dependency(&first).unwrap());
        assert_eq!(
            registry.publish_dependency(&stale),
            Err(DomainDependencyError::DependenciesChanged {
                domain: DomainId::new(1),
            })
        );
        assert_eq!(&*registry.domains[0].dependencies, &[DomainId::new(2)]);
        assert!(
            to_snapshot(&registry.domains[2], &registry.domains)
                .dependents
                .is_empty()
        );
        let retry = prepare_dependency(&registry, 3);
        drop(registry.publish_dependency(&retry).unwrap());
        assert_eq!(
            &*registry.domains[0].dependencies,
            &[DomainId::new(2), DomainId::new(3)]
        );
    }

    #[test]
    fn dependency_registration_rejects_missing_endpoints_without_publication() {
        let live = create_domain(String::from("dependency_missing_peer")).unwrap();
        let missing = DomainId::new(u64::MAX);
        for (dependent, dependency) in [(live, missing), (missing, live)] {
            assert_eq!(
                add_domain_dependency(dependent, dependency),
                Err(DomainDependencyError::NotFound { domain: missing })
            );
        }
        let snapshot = get_domain_snapshot(live).unwrap();
        assert!(snapshot.dependencies.is_empty());
        assert!(snapshot.dependents.is_empty());
        terminate_domain(live).unwrap();
    }

    #[test]
    fn dependency_registration_racing_termination_keeps_notification_coherent() {
        for _ in 0..16 {
            let source = create_domain(String::from("dependency_race_source")).unwrap();
            let consumer = create_domain(String::from("dependency_race_consumer")).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let registration_barrier = Arc::clone(&barrier);
            let registration = std::thread::spawn(move || {
                registration_barrier.wait();
                add_domain_dependency(consumer, source)
            });
            let termination = std::thread::spawn(move || {
                barrier.wait();
                terminate_domain(source)
            });
            let registration = registration.join().unwrap();
            termination.join().unwrap().unwrap();
            let snapshot = get_domain_snapshot(consumer).unwrap();
            match registration {
                Ok(()) => assert_eq!(snapshot.terminated_dependency, Some(source)),
                Err(DomainDependencyError::Unavailable { domain, .. }) => {
                    assert_eq!(domain, source);
                    assert_eq!(snapshot.terminated_dependency, None);
                    assert!(snapshot.dependencies.is_empty());
                }
                cause => panic!("unexpected dependency race result: {cause:?}"),
            }
            terminate_domain(consumer).unwrap();
        }
    }

    #[test]
    fn termination_notifies_only_dependents_and_retains_live_return_targets() {
        let before = create_domain(String::from("dependent_before")).expect("domain admission");
        let source = create_domain(String::from("dependency")).expect("domain admission");
        let after = create_domain(String::from("dependent_after")).expect("domain admission");
        let unrelated = create_domain(String::from("unrelated")).expect("domain admission");
        add_domain_dependency(before, source).expect("dependency");
        add_domain_dependency(after, source).expect("dependency");
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
            restart_domain(source),
            Err(DomainLifecycleError::InvalidState(DomainState::Terminated))
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
