// ============================================================================
// kernel/src/driver_cell/lifecycle.rs - DriverCell ライフサイクル管理
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

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::domain::quota::DomainPriority;
use crate::domain_system::DomainId;
use crate::driver_registry::DriverHandle;
use crate::loader::CellId;
use crate::security::CapabilitySet;

use super::fault::RestartPolicy;
use super::{
    DriverCell, DriverCellError, DriverCellId, DriverCellState, driver_cell_manager,
};

// ============================================================================
// Configuration
// ============================================================================

/// DriverCell作成時の設定
#[derive(Debug, Clone)]
pub struct DriverCellConfig {
    /// ドライバセル名
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
}

impl DriverCellConfig {
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
}

// ============================================================================
// Lifecycle Operations
// ============================================================================

/// DriverCellを作成（設定から）
///
/// まだコードはロードされない。load()を呼ぶ必要がある。
pub fn create(config: &DriverCellConfig) -> Result<DriverCellId, DriverCellError> {
    let manager = driver_cell_manager();
    let id = manager.allocate_id();

    let cell = DriverCell::from_config(id, config);
    manager.register(cell)?;

    log::info!(
        "[DriverCell] Created: {} (id={}, priority={:?}, restart={:?})\n",
        config.name,
        id,
        config.priority,
        config.restart_policy
    );

    Ok(id)
}

/// DriverCellにELFバイナリをロード
///
/// 1. ELFをCellとしてロード（署名検証 + Type ID Check）
/// 2. 対応するDomainを作成
/// 3. リソースクォータを設定
/// 4. NUMAアフィニティを設定
pub fn load(
    id: DriverCellId,
    elf_data: &[u8],
) -> Result<(CellId, DomainId), DriverCellError> {
    let manager = driver_cell_manager();

    // 状態チェック
    let (name, allow_unsafe) = manager.with_cell(id, |cell| {
        if cell.state != DriverCellState::Created && cell.state != DriverCellState::Stopped {
            return Err(DriverCellError::InvalidStateTransition {
                from: cell.state,
                to: DriverCellState::Loading,
            });
        }
        Ok((cell.name.clone(), cell.allow_unsafe))
    })??;

    // Loading状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Loading);
    })?;

    // 1. ELFをCellとしてロード
    let cell_id = match crate::loader::load_cell(&name, elf_data, allow_unsafe) {
        Ok(cid) => cid,
        Err(e) => {
            let msg = format!("{}", e);
            manager.with_cell_mut(id, |cell| {
                cell.transition_to(DriverCellState::Faulted);
            }).ok();
            return Err(DriverCellError::LoadFailed(msg));
        }
    };

    // 2. 対応するDomainを作成
    let domain_name = format!("drv:{}", name);
    let domain_id = match crate::domain_system::create_domain(domain_name) {
        Ok(did) => did,
        Err(e) => {
            // ロールバック: セルをアンロード
            let _ = crate::loader::unload_cell(cell_id);
            let msg = format!("{}", e);
            manager.with_cell_mut(id, |cell| {
                cell.transition_to(DriverCellState::Faulted);
            }).ok();
            return Err(DriverCellError::DomainCreationFailed(msg));
        }
    };

    // 3. NUMAアフィニティを設定
    let numa_node = manager.with_cell(id, |cell| cell.numa_node)?;
    if let Some(node) = numa_node {
        crate::domain_system::set_domain_numa(domain_id, node);
    }

    // 4. DriverCellに紐付け
    manager.with_cell_mut(id, |cell| {
        cell.set_cell_id(cell_id);
        cell.set_domain_id(domain_id);
        cell.transition_to(DriverCellState::Loaded);
        cell.stats.record_load();
    })?;

    log::info!(
        "[DriverCell] Loaded: {} (cell={:?}, domain={})\n",
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
pub fn start(id: DriverCellId) -> Result<Vec<DriverHandle>, DriverCellError> {
    let manager = driver_cell_manager();

    // 状態チェック
    let cell_id = manager.with_cell(id, |cell| {
        if cell.state != DriverCellState::Loaded && cell.state != DriverCellState::Stopped {
            return Err(DriverCellError::InvalidStateTransition {
                from: cell.state,
                to: DriverCellState::Starting,
            });
        }
        cell.cell_id.ok_or(DriverCellError::LoadFailed(
            "Cell not loaded".into(),
        ))
    })??;

    // Starting状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Starting);
    })?;

    // ドライバをCellから登録
    let handle = match crate::loader::register_driver_from_cell(cell_id) {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{}", e);
            manager.with_cell_mut(id, |cell| {
                cell.transition_to(DriverCellState::Faulted);
            }).ok();
            return Err(DriverCellError::DriverInitFailed(msg));
        }
    };

    // ドライバをprobe + start
    let registry = crate::driver_registry::driver_registry();
    if let Err(e) = registry.probe_and_start(handle) {
        let msg = format!("{}", e);
        manager.with_cell_mut(id, |cell| {
            cell.transition_to(DriverCellState::Faulted);
        }).ok();
        return Err(DriverCellError::DriverInitFailed(msg));
    }

    // DomainをRunning状態に
    let domain_id = manager.with_cell(id, |cell| cell.domain_id)?;
    if let Some(did) = domain_id {
        crate::domain_system::start_domain(did).ok();
    }

    // DriverCellをRunning状態に
    manager.with_cell_mut(id, |cell| {
        cell.add_driver_handle(handle);
        cell.transition_to(DriverCellState::Running);
        cell.reset_fault_count();
        cell.stats.record_start();
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!(
        "[DriverCell] Started: {} (driver={:?})\n",
        name,
        handle.index()
    );

    Ok(alloc::vec![handle])
}

/// DriverCellを停止
///
/// 1. 全ドライバをstop
/// 2. DomainをStopped状態に
/// 3. DriverCellをStopped状態に
pub fn stop(id: DriverCellId) -> Result<(), DriverCellError> {
    let manager = driver_cell_manager();

    // 状態チェック
    let (driver_handles, domain_id) = manager.with_cell(id, |cell| {
        if !cell.state.can_stop() {
            return Err(DriverCellError::InvalidStateTransition {
                from: cell.state,
                to: DriverCellState::Stopping,
            });
        }
        Ok((cell.driver_handles.clone(), cell.domain_id))
    })??;

    // Stopping状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Stopping);
    })?;

    // 全ドライバを停止
    let registry = crate::driver_registry::driver_registry();
    for handle in &driver_handles {
        if let Err(e) = registry.stop(*handle) {
            log::warn!(
                "[DriverCell] Failed to stop driver {:?}: {}\n",
                handle.index(),
                e
            );
        }
    }

    // Domainを停止
    if let Some(did) = domain_id {
        crate::domain_system::stop_domain(did).ok();
    }

    // Stopped状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Stopped);
        cell.stats.record_stop();
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!("[DriverCell] Stopped: {}\n", name);

    Ok(())
}

/// DriverCellを完全にアンロード
///
/// 1. ドライバをstop（必要なら）
/// 2. ドライバをunregister
/// 3. Cellをアンロード（Epoch-based Reclamation）
/// 4. Domainを終了
/// 5. DriverCellManagerから削除
pub fn unload(id: DriverCellId) -> Result<(), DriverCellError> {
    let manager = driver_cell_manager();

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

    // ドライバをunregister
    for handle in &driver_handles {
        if let Err(e) = crate::loader::unload_driver(*handle) {
            log::warn!(
                "[DriverCell] Failed to unload driver {:?}: {}\n",
                handle.index(),
                e
            );
        }
    }

    // Cellをアンロード
    if let Some(cid) = cell_id {
        if let Err(e) = crate::loader::unload_cell(cid) {
            log::warn!(
                "[DriverCell] Failed to unload cell {:?}: {}\n",
                cid.as_u64(),
                e
            );
        }
    }

    // Domainを終了
    if let Some(did) = domain_id {
        if let Err(e) = crate::domain_system::terminate_domain(did) {
            log::warn!(
                "[DriverCell] Failed to terminate domain {}: {}\n",
                did,
                e
            );
        }
    }

    // ManagerからDriverCellを削除
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Unloaded);
    })?;
    manager.remove(id)?;

    log::info!(
        "[DriverCell] Unloaded: {} (id={})\n",
        name,
        id
    );

    Ok(())
}

/// ELFデータからDriverCellを作成し、ロード→開始まで一括で行う
///
/// 最も一般的な使用パターン。設定に基づいてドライバセルを
/// 完全にセットアップする。
pub fn create_and_start(
    config: &DriverCellConfig,
    elf_data: &[u8],
) -> Result<(DriverCellId, Vec<DriverHandle>), DriverCellError> {
    // 1. 作成
    let id = create(config)?;

    // 2. ロード
    if let Err(e) = load(id, elf_data) {
        // ロールバック
        let _ = driver_cell_manager().remove(id);
        return Err(e);
    }

    // 3. 開始
    match start(id) {
        Ok(handles) => Ok((id, handles)),
        Err(e) => {
            // ロールバック
            let _ = unload(id);
            Err(e)
        }
    }
}

/// 全DriverCellを停止
pub fn stop_all() {
    let manager = driver_cell_manager();
    let running = manager.cells_by_state(DriverCellState::Running);

    for id in running {
        if let Err(e) = stop(id) {
            log::warn!("[DriverCell] Failed to stop {}: {}\n", id, e);
        }
    }
}

/// 全DriverCellをアンロード
pub fn unload_all() {
    let manager = driver_cell_manager();
    let snapshots = manager.list_snapshots();

    for snap in snapshots {
        if snap.state != DriverCellState::Unloaded {
            if let Err(e) = unload(snap.id) {
                log::warn!("[DriverCell] Failed to unload {}: {}\n", snap.id, e);
            }
        }
    }
}
