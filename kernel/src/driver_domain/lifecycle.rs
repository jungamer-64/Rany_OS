// ============================================================================
// kernel/src/driver_domain/lifecycle.rs - DriverDomain ライフサイクル管理
// ============================================================================
//! DriverCellのライフサイクル管理
//!
//! 設計書 3.1: セル(Cell)モデルのライフサイクル
//! 設計書 8: フォールトアイソレーション
//!
//! ## ライフサイクルフロー
//!
//! 1. `create()` - DriverCellを作成し設定
//! 2. `load()` - ELFバイナリをロードしCellとDomainを紐付け
//! 3. `start()` - ドライバをprobe + startし、DomainProxyで隔離実行
//! 4. `stop()` - ドライバを停止しリソースを解放
//! 5. `unload()` - セルをアンロードしDomainを終了
//!
//! 障害発生時は `fault::handle_fault()` 経由で自動復旧を試みる。
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::domain::DomainId;
use crate::domain::quota::DomainPriority;
use crate::driver_registry::DriverHandle;
use crate::loader::CellId;
use crate::security::CapabilitySet;
use kernel_api::abi::driver::DriverContext as AbiDriverContext;

use super::fault::RestartPolicy;
use super::{
    DriverDomain, DriverDomainError, DriverDomainId, DriverDomainState, driver_domain_manager,
};

// ============================================================================
// Configuration
// ============================================================================

/// DriverCell作成時の設定
#[derive(Debug, Clone)]
pub struct DriverDomainConfig {
    /// ドライバドメイン名
    pub name: String,
    /// 再起動ポリシー
    pub restart_policy: RestartPolicy,
    /// 優先度
    pub priority: DomainPriority,
    /// ケイパビリティ
    pub capabilities: CapabilitySet,
    /// unsafeを許可するか
    pub allow_unsafe: bool,
    /// CPU使用率上限（%）
    pub cpu_limit_percent: u64,
    /// メモリ使用量上限（バイト）
    pub memory_limit_bytes: u64,
    /// I/O帯域上限（バイト/秒、0=無制限）
    pub io_bandwidth_limit: u64,
    /// NUMAノード（任意）
    pub numa_node: Option<usize>,
    /// ABIドライバに渡すデバイスコンテキスト
    pub abi_driver_context: AbiDriverContext,
}

impl DriverDomainConfig {
    /// デフォルト設定で作成
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            restart_policy: RestartPolicy::default(),
            priority: DomainPriority::Normal,
            capabilities: CapabilitySet::empty(),
            allow_unsafe: false,
            cpu_limit_percent: 100,
            memory_limit_bytes: 64 * 1024 * 1024,
            io_bandwidth_limit: 0,
            numa_node: None,
            abi_driver_context: AbiDriverContext::new(),
        }
    }

    /// 再起動ポリシーを設定
    pub fn with_restart_policy(mut self, policy: RestartPolicy) -> Self {
        self.restart_policy = policy;
        self
    }

    /// 優先度を設定
    pub fn with_priority(mut self, priority: DomainPriority) -> Self {
        self.priority = priority;
        self
    }

    /// ケイパビリティを設定
    pub fn with_capabilities(mut self, caps: CapabilitySet) -> Self {
        self.capabilities = caps;
        self
    }

    /// unsafeを許可
    pub fn with_unsafe_allowed(mut self) -> Self {
        self.allow_unsafe = true;
        self
    }

    /// CPUクォータを設定
    pub fn with_cpu_limit(mut self, percent: u64) -> Self {
        self.cpu_limit_percent = percent;
        self
    }

    /// メモリ上限を設定
    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = bytes;
        self
    }

    /// NUMAノードを設定
    pub fn with_numa_node(mut self, node: usize) -> Self {
        self.numa_node = Some(node);
        self
    }

    /// ABIドライバに渡すコンテキストを設定
    pub fn with_abi_driver_context(mut self, ctx: AbiDriverContext) -> Self {
        self.abi_driver_context = ctx;
        self
    }
}

// ============================================================================
// Lifecycle Operations
// ============================================================================

/// DriverCellを作成（設定から）
///
/// まだコードはロードされない。load()を呼ぶ必要がある。
pub fn create(config: &DriverDomainConfig) -> Result<DriverDomainId, DriverDomainError> {
    let manager = driver_domain_manager();
    let id = manager.allocate_id();

    let cell = DriverDomain::from_config(id, config);
    manager.register(cell)?;
    super::stats::global_stats().on_created();

    log::info!(
        "[DriverDomain] Created: {} (id={}, priority={:?}, restart={:?})\n",
        config.name,
        id,
        config.priority,
        config.restart_policy
    );

    Ok(id)
}

/// DriverCellにドライバartifact（raw ELF / driver pack）をロード
///
/// 1. ドライバartifactをCellとしてロード（署名検証 + Type ID Check）
/// 2. 対応するDomainを作成
/// 3. リソースクォータを設定
/// 4. NUMAアフィニティを設定
pub fn load(
    id: DriverDomainId,
    artifact_data: &[u8],
) -> Result<(CellId, DomainId), DriverDomainError> {
    let manager = driver_domain_manager();

    // 状態チェック
    let (name, allow_unsafe) = manager.with_cell(id, |cell| {
        if cell.state != DriverDomainState::Created && cell.state != DriverDomainState::Stopped {
            return Err(DriverDomainError::InvalidStateTransition {
                from: cell.state,
                to: DriverDomainState::Loading,
            });
        }
        Ok((cell.name.clone(), cell.allow_unsafe))
    })??;

    // Loading状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverDomainState::Loading);
    })?;

    // 1. ドライバartifactをCellとしてロード
    let cell_id = match crate::loader::load_driver_artifact_cell(&name, artifact_data, allow_unsafe)
    {
        Ok(cid) => cid,
        Err(e) => {
            let msg = format!("{}", e);
            manager
                .with_cell_mut(id, |cell| {
                    cell.transition_to(DriverDomainState::Faulted);
                })
                .ok();
            return Err(DriverDomainError::LoadFailed(msg));
        }
    };

    // 2. 対応するDomainを作成
    let domain_name = format!("drv:{}", name);
    let domain_id = match crate::domain::create_domain(domain_name) {
        Ok(did) => did,
        Err(e) => {
            // ロールバック: セルをアンロード
            let _ = crate::loader::unload_cell(cell_id);
            let msg = format!("{}", e);
            manager
                .with_cell_mut(id, |cell| {
                    cell.transition_to(DriverDomainState::Faulted);
                })
                .ok();
            return Err(DriverDomainError::DomainCreationFailed(msg));
        }
    };

    crate::domain::registry::bind_code_generation(domain_id, cell_id)
        .map_err(|error| DriverDomainError::DomainCreationFailed(format!("{error}")))?;

    // 3. DriverCell設定をDomainへ反映（メタデータ + セキュリティ）
    let (numa_node, caps, priority, cpu_limit, mem_limit, io_limit) =
        manager.with_cell(id, |cell| {
            (
                cell.numa_node,
                cell.capabilities,
                cell.priority,
                cell.cpu_limit_percent,
                cell.memory_limit_bytes,
                cell.io_bandwidth_limit,
            )
        })?;

    // Publish the resource owners before fallible policy admission. Failure
    // leaves a tracked faulted cell instead of an apparently loaded domain.
    manager
        .with_cell_mut(id, |cell| {
            cell.set_cell_id(cell_id);
            cell.set_domain_id(domain_id);
        })
        .map_err(|_| DriverDomainError::PolicyAdmissionFailed {
            cause: crate::domain::DomainPolicyError::RegistryUnavailable,
            cell: cell_id,
            domain: domain_id,
        })?;
    let policy = crate::domain::set_domain_capabilities(domain_id, caps)
        .and_then(|()| crate::domain::set_domain_priority(domain_id, priority))
        .and_then(|()| {
            crate::domain::set_domain_resource_limits(domain_id, cpu_limit, mem_limit, io_limit)
        });
    if let Err(cause) = policy {
        if let Err(error) = manager.with_cell_mut(id, |cell| {
            cell.transition_to(DriverDomainState::Faulted);
        }) {
            log::error!("Driver cell {} fault publication failed: {}", id, error);
        }
        return Err(DriverDomainError::PolicyAdmissionFailed {
            cause,
            cell: cell_id,
            domain: domain_id,
        });
    }

    // 4. NUMAアフィニティを設定
    if let Some(node) = numa_node {
        crate::domain::set_domain_numa(domain_id, node);
    }

    // 5. DriverCellに紐付け
    manager.with_cell_mut(id, |cell| {
        cell.set_cell_id(cell_id);
        cell.set_domain_id(domain_id);
        cell.transition_to(DriverDomainState::Loaded);
        cell.stats.record_load();
    })?;

    log::info!(
        "[DriverDomain] Loaded: {} (cell={:?}, domain={})\n",
        name,
        cell_id.as_u64(),
        domain_id
    );

    Ok((cell_id, domain_id))
}

/// DriverCellのドライバを登録・開始
///
/// 1. CellからドライバエントリをDriverRegistryに登録
/// 2. ドライバをprobe
/// 3. ドライバをstart
/// 4. DomainをRunning状態に遷移
///
/// 全ての操作はDomainProxyを経由し、パニック時は安全に捕捉される。
/// DriverCellを停止
///
/// 1. 全ドライバをstop
/// 2. DomainをStopped状態に
/// 3. DriverCellをStopped状態に
pub fn stop(id: DriverDomainId) -> Result<(), DriverDomainError> {
    let manager = driver_domain_manager();

    // 状態チェック
    let (driver_handles, domain_id) = manager.with_cell(id, |cell| {
        if !cell.state.can_stop() {
            return Err(DriverDomainError::InvalidStateTransition {
                from: cell.state,
                to: DriverDomainState::Stopping,
            });
        }
        Ok((cell.driver_handles.clone(), cell.domain_id))
    })??;

    // Stopping状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverDomainState::Stopping);
    })?;

    if let Some(domain) = domain_id {
        match crate::domain::stop_domain(domain).map_err(DriverDomainError::DomainLifecycle)? {
            crate::domain::DomainStopOutcome::Complete => {}
            pending => {
                return Err(DriverDomainError::DomainLifecycle(
                    crate::domain::DomainLifecycleError::Busy(pending),
                ));
            }
        }
    }
    let registry = crate::driver_registry::driver_registry();
    for handle in &driver_handles {
        if !matches!(
            registry.state(*handle),
            Some(
                kernel_api::driver::DriverState::Stopped | kernel_api::driver::DriverState::Removed
            )
        ) {
            registry
                .stop(*handle)
                .map_err(DriverDomainError::DriverOperation)?;
        }
    }

    // Stopped状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverDomainState::Stopped);
        cell.stats.record_stop();
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!("[DriverDomain] Stopped: {}\n", name);

    Ok(())
}

/// DriverCellを完全にアンロード
///
/// 1. ドライバをstop（必要なら）
/// 2. ドライバをunregister
/// 3. Cellをアンロード（Epoch-based Reclamation）
/// 4. Domainを終了
/// 5. DriverDomainManagerから削除
pub fn unload(id: DriverDomainId) -> Result<(), DriverDomainError> {
    let manager = driver_domain_manager();

    // まず停止（Running/Starting/Faultedなら）
    let state = manager.with_cell(id, |cell| cell.state)?;
    if state.can_stop() {
        stop(id)?;
    }

    let (driver_handles, cell_id, domain_id, name) = manager.with_cell(id, |cell| {
        (
            cell.driver_handles.clone(),
            cell.cell_id,
            cell.domain_id,
            cell.name.clone(),
        )
    })?;

    // Remove each successfully retired handle from the owner before retry.
    for handle in &driver_handles {
        crate::loader::unload_driver(*handle).map_err(DriverDomainError::CodeReclamation)?;
        manager.with_cell_mut(id, |cell| {
            cell.driver_handles.retain(|current| current != handle)
        })?;
    }
    // Future destruction runs while the old code remains mapped.
    if let Some(domain) = domain_id {
        crate::domain::terminate_domain(domain).map_err(DriverDomainError::DomainLifecycle)?;
    }
    if let Some(cell) = cell_id {
        crate::loader::unload_cell(cell).map_err(DriverDomainError::CodeReclamation)?;
    }

    // ManagerからDriverCellを削除
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverDomainState::Unloaded);
    })?;
    manager.remove(id)?;
    super::stats::global_stats().on_unloaded();

    log::info!("[DriverDomain] Unloaded: {} (id={})\n", name, id);

    Ok(())
}

/// ELFデータからDriverCellを作成し、ロード→開始まで一括で行う
///
/// 最も一般的な使用パターン。設定に基づいてドライバドメインを
/// 完全にセットアップする。
pub fn create_and_start(
    config: &DriverDomainConfig,
    artifact_data: &[u8],
) -> Result<(DriverDomainId, Vec<DriverHandle>), DriverDomainError> {
    // 1. 作成
    let id = create(config)?;

    // 2. ロード
    if let Err(e) = load(id, artifact_data) {
        // ロールバック
        let _ = driver_domain_manager().remove(id);
        return Err(e);
    }

    // 3. 開始
    match start(id) {
        Ok(handles) => Ok((id, handles)),
        Err(error @ DriverDomainError::StartupPending { .. }) => Err(error),
        Err(error) => {
            // Startup may already have published hardware state. Its owner and
            // claim remain registered until explicit shutdown acknowledges it.
            Err(error)
        }
    }
}

/// よく使うデフォルト設定で DriverDomain を作成して開始する簡易API
pub fn create_and_start_default(
    name: &str,
    artifact_data: &[u8],
    allow_unsafe: bool,
) -> Result<(DriverDomainId, Vec<DriverHandle>), DriverDomainError> {
    let mut config = DriverDomainConfig::new(name)
        .with_restart_policy(RestartPolicy::on_panic(3, 100))
        .with_capabilities(CapabilitySet::empty());
    if allow_unsafe {
        config = config.with_unsafe_allowed();
    }
    create_and_start(&config, artifact_data)
}

/// 全DriverCellを停止
pub fn stop_all() {
    let manager = driver_domain_manager();
    let running = manager.cells_by_state(DriverDomainState::Running);

    for id in running {
        if let Err(e) = stop(id) {
            log::warn!("[DriverDomain] Failed to stop {}: {}\n", id, e);
        }
    }
}

/// 全DriverCellをアンロード
pub fn unload_all() {
    let manager = driver_domain_manager();
    let snapshots = manager.list_snapshots();

    for snap in snapshots {
        if snap.state != DriverDomainState::Unloaded {
            if let Err(e) = unload(snap.id) {
                log::warn!("[DriverDomain] Failed to unload {}: {}\n", snap.id, e);
            }
        }
    }
}

/// Collect lifecycle completions in ordinary service-host execution. Callback
/// work runs outside the DriverDomain registry; Busy preserves its owner.
pub(crate) fn progress_startups() {
    let manager = driver_domain_manager();
    for snapshot in manager.list_snapshots() {
        if snapshot.state != DriverDomainState::Starting {
            continue;
        }
        match start(snapshot.id) {
            Ok(_) | Err(DriverDomainError::StartupPending { .. }) => {}
            Err(cause) => log::error!(
                "driver startup {} failed with its owner retained: {cause}",
                snapshot.id
            ),
        }
    }
}
