// ============================================================================
// kernel/src/driver_cell/mod.rs - Driver Cell: 統一ドライバ隔離モデル
// ============================================================================
//! # Driver Cell (ドライバセル)
//!
//! 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
//! 設計書 8: フォールトアイソレーションと回復メカニズム
//!
//! ## 概要
//!
//! `DriverCell` は、以下の3つの概念を統合する実行時抽象です:
//!
//! 1. **Cell** (ローダーレベル) - ELFバイナリとしてロードされたコード
//! 2. **Domain** (実行時管理) - リソースクォータ、ケイパビリティ、状態追跡
//! 3. **Driver** (デバイスインターフェース) - ドライバライフサイクル管理
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    DriverCell                           │
//! │                                                         │
//! │  ┌──────────────┐  ┌───────────┐  ┌────────────────┐   │
//! │  │ Cell (ELF)   │  │  Domain   │  │  Driver(s)     │   │
//! │  │  - コード     │  │ - クォータ │  │ - probe/start  │   │
//! │  │  - シンボル   │  │ - 状態    │  │ - stop/remove  │   │
//! │  │  - 署名検証   │  │ - タスク  │  │ - hot-swap     │   │
//! │  └──────────────┘  └───────────┘  └────────────────┘   │
//! │                                                         │
//! │  ┌──────────────────────────────────────────────────┐   │
//! │  │              Isolation Layer                      │   │
//! │  │  - DomainProxy (パニック捕捉)                     │   │
//! │  │  - PoisonLock (毒入れ対応)                        │   │
//! │  │  - Exchange Heap (ゼロコピーIPC)                   │   │
//! │  │  - MPK/PKU (ハードウェア保護)                     │   │
//! │  └──────────────────────────────────────────────────┘   │
//! │                                                         │
//! │  ┌──────────────────────────────────────────────────┐   │
//! │  │              Recovery & Policy                    │   │
//! │  │  - RestartPolicy (自動再起動)                     │   │
//! │  │  - FaultHistory (障害履歴)                        │   │
//! │  │  - LiveUpdate (ホットスワップ)                    │   │
//! │  └──────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## ライフサイクル
//!
//! ```text
//! Created → Loading → Loaded → Starting → Running → Stopping → Stopped → Unloaded
//!                                  │                    ↑
//!                                  │   (panic)          │
//!                                  ▼                    │
//!                               Faulted ──(restart)─────┘
//! ```
//!
//! ## 設計原則
//!
//! - **障害分離**: ドライバのパニックがカーネルに波及しない
//! - **リソース制限**: CPU/メモリ/I/Oクォータでリソース独占を防止
//! - **自動回復**: 設定可能な再起動ポリシーで障害から自動復旧
//! - **ホットスワップ**: StateTransfer + Epoch-based Reclamationでゼロダウンタイム更新
//! - **Safe Rust**: Framework API以外でunsafeを使用しない

#![allow(dead_code)]

pub mod fault;
pub mod hot_swap;
pub mod lifecycle;
pub mod stats;

#[cfg(test)]
mod tests;

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::domain::quota::DomainPriority;
#[allow(unused_imports)]
use crate::domain::quota::DomainQuota;
use crate::domain_system::DomainId;
use crate::driver_registry::DriverHandle;
use crate::loader::CellId;
use crate::security::CapabilitySet;
use crate::sync::PoisonLock;

pub use fault::{FaultRecord, RestartPolicy};
pub use hot_swap::HotSwapState;
pub use lifecycle::DriverCellConfig;
pub use stats::DriverCellStats;

// ============================================================================
// DriverCell ID
// ============================================================================

/// DriverCellを一意に識別するID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DriverCellId(u64);

impl DriverCellId {
    /// 新しいIDを作成
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// IDを数値として取得
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for DriverCellId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DriverCell({})", self.0)
    }
}

// ============================================================================
// DriverCell State
// ============================================================================

/// DriverCellのライフサイクル状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverCellState {
    /// 作成済み（未ロード）
    Created,
    /// コードをロード中
    Loading,
    /// ロード完了、ドライバ初期化待ち
    Loaded,
    /// ドライバを開始中（probe/start）
    Starting,
    /// 正常動作中
    Running,
    /// 停止処理中
    Stopping,
    /// 停止済み（再起動可能）
    Stopped,
    /// 障害発生（パニック/エラー）
    Faulted,
    /// 再起動中
    Restarting,
    /// ホットスワップ中
    Updating,
    /// アンロード済み（終了）
    Unloaded,
}

impl DriverCellState {
    /// 実行中かどうか
    pub fn is_running(&self) -> bool {
        matches!(self, DriverCellState::Running)
    }

    /// アクティブ（リソースを保持）かどうか
    pub fn is_active(&self) -> bool {
        !matches!(
            self,
            DriverCellState::Created | DriverCellState::Unloaded
        )
    }

    /// 停止可能かどうか
    pub fn can_stop(&self) -> bool {
        matches!(
            self,
            DriverCellState::Running
                | DriverCellState::Starting
                | DriverCellState::Faulted
        )
    }

    /// 再起動可能かどうか
    pub fn can_restart(&self) -> bool {
        matches!(
            self,
            DriverCellState::Stopped | DriverCellState::Faulted
        )
    }
}

impl core::fmt::Display for DriverCellState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Loading => write!(f, "Loading"),
            Self::Loaded => write!(f, "Loaded"),
            Self::Starting => write!(f, "Starting"),
            Self::Running => write!(f, "Running"),
            Self::Stopping => write!(f, "Stopping"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Faulted => write!(f, "Faulted"),
            Self::Restarting => write!(f, "Restarting"),
            Self::Updating => write!(f, "Updating"),
            Self::Unloaded => write!(f, "Unloaded"),
        }
    }
}

// ============================================================================
// DriverCell - 統合ドライバ隔離モデル
// ============================================================================

/// DriverCell: Cell + Domain + Driver の統合抽象
///
/// 設計書 3.1: セル(Cell)モデルの完全な実装
/// - コードの分離（Cell/ELFロード）
/// - 実行時の分離（Domain/リソース管理）
/// - デバイスインターフェース（Driver/ライフサイクル）
/// - 障害分離（Proxy/PoisonLock/Exchange Heap）
pub struct DriverCell {
    // === 識別情報 ===
    /// DriverCellの一意なID
    pub id: DriverCellId,
    /// ドライバセル名
    pub name: String,

    // === コンポーネントID ===
    /// ロード済みセルID（ELFコード）
    pub cell_id: Option<CellId>,
    /// 実行時ドメインID（リソース管理）
    pub domain_id: Option<DomainId>,
    /// 登録されたドライバハンドル
    pub driver_handles: Vec<DriverHandle>,

    // === 状態管理 ===
    /// 現在の状態
    pub state: DriverCellState,
    /// 前回の状態（遷移追跡用）
    previous_state: Option<DriverCellState>,

    // === ポリシー・設定 ===
    /// 再起動ポリシー
    pub restart_policy: RestartPolicy,
    /// ドメイン優先度
    pub priority: DomainPriority,
    /// 要求ケイパビリティ
    pub capabilities: CapabilitySet,
    /// unsafeコードを許可するか
    pub allow_unsafe: bool,

    // === リソース管理 ===
    /// CPU使用率上限（%）
    pub cpu_limit_percent: u64,
    /// メモリ使用量上限（バイト）
    pub memory_limit_bytes: u64,
    /// I/O帯域上限（バイト/秒）
    pub io_bandwidth_limit: u64,

    // === 障害追跡 ===
    /// 障害履歴
    pub fault_history: Vec<FaultRecord>,
    /// 連続障害回数
    pub consecutive_faults: u32,

    // === ホットスワップ ===
    /// ホットスワップ状態
    pub hot_swap_state: HotSwapState,

    // === 統計情報 ===
    /// 統計データ
    pub stats: DriverCellStats,

    // === NUMAアフィニティ ===
    /// NUMAノード（任意）
    pub numa_node: Option<usize>,

    /// 作成時刻（TSCティック）
    pub created_at: u64,
}

impl DriverCell {
    /// 新しいDriverCellを作成
    pub fn new(id: DriverCellId, name: String) -> Self {
        Self {
            id,
            name,
            cell_id: None,
            domain_id: None,
            driver_handles: Vec::new(),
            state: DriverCellState::Created,
            previous_state: None,
            restart_policy: RestartPolicy::default(),
            priority: DomainPriority::Normal,
            capabilities: CapabilitySet::empty(),
            allow_unsafe: false,
            cpu_limit_percent: 100,
            memory_limit_bytes: 64 * 1024 * 1024, // 64MB デフォルト
            io_bandwidth_limit: 0,                 // 0 = 制限なし
            fault_history: Vec::new(),
            consecutive_faults: 0,
            hot_swap_state: HotSwapState::Idle,
            stats: DriverCellStats::new(),
            numa_node: None,
            created_at: crate::task::timer::current_tick(),
        }
    }

    /// 設定から作成
    pub fn from_config(id: DriverCellId, config: &DriverCellConfig) -> Self {
        let mut cell = Self::new(id, config.name.clone());
        cell.restart_policy = config.restart_policy;
        cell.priority = config.priority;
        cell.capabilities = config.capabilities;
        cell.allow_unsafe = config.allow_unsafe;
        cell.cpu_limit_percent = config.cpu_limit_percent;
        cell.memory_limit_bytes = config.memory_limit_bytes;
        cell.io_bandwidth_limit = config.io_bandwidth_limit;
        cell.numa_node = config.numa_node;
        cell
    }

    /// 状態を遷移
    fn transition_to(&mut self, new_state: DriverCellState) {
        self.previous_state = Some(self.state);
        let old = self.state;
        self.state = new_state;
        log::info!(
            "[DriverCell] {} state: {} -> {}\n",
            self.name,
            old,
            new_state
        );
    }

    /// CellIDを設定
    pub fn set_cell_id(&mut self, cell_id: CellId) {
        self.cell_id = Some(cell_id);
    }

    /// DomainIDを設定
    pub fn set_domain_id(&mut self, domain_id: DomainId) {
        self.domain_id = Some(domain_id);
    }

    /// DriverHandleを追加
    pub fn add_driver_handle(&mut self, handle: DriverHandle) {
        if !self.driver_handles.contains(&handle) {
            self.driver_handles.push(handle);
        }
    }

    /// DriverHandleを削除
    pub fn remove_driver_handle(&mut self, handle: DriverHandle) {
        self.driver_handles.retain(|h| *h != handle);
    }

    /// 障害回数をリセット（正常動作に復帰した場合）
    pub fn reset_fault_count(&mut self) {
        self.consecutive_faults = 0;
    }

    /// スナップショットを取得（軽量コピー）
    pub fn snapshot(&self) -> DriverCellSnapshot {
        DriverCellSnapshot {
            id: self.id,
            name: self.name.clone(),
            state: self.state,
            cell_id: self.cell_id,
            domain_id: self.domain_id,
            driver_count: self.driver_handles.len(),
            priority: self.priority,
            consecutive_faults: self.consecutive_faults,
            total_faults: self.fault_history.len(),
            restart_policy: self.restart_policy,
            cpu_limit_percent: self.cpu_limit_percent,
            memory_limit_bytes: self.memory_limit_bytes,
            numa_node: self.numa_node,
            created_at: self.created_at,
            stats: self.stats.clone(),
        }
    }
}

impl core::fmt::Debug for DriverCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DriverCell")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state)
            .field("cell_id", &self.cell_id)
            .field("domain_id", &self.domain_id)
            .field("driver_handles", &self.driver_handles.len())
            .field("priority", &self.priority)
            .field("faults", &self.consecutive_faults)
            .finish()
    }
}

// ============================================================================
// DriverCell Snapshot
// ============================================================================

/// DriverCellの軽量スナップショット（外部公開用）
#[derive(Debug, Clone)]
pub struct DriverCellSnapshot {
    pub id: DriverCellId,
    pub name: String,
    pub state: DriverCellState,
    pub cell_id: Option<CellId>,
    pub domain_id: Option<DomainId>,
    pub driver_count: usize,
    pub priority: DomainPriority,
    pub consecutive_faults: u32,
    pub total_faults: usize,
    pub restart_policy: RestartPolicy,
    pub cpu_limit_percent: u64,
    pub memory_limit_bytes: u64,
    pub numa_node: Option<usize>,
    pub created_at: u64,
    pub stats: DriverCellStats,
}

// ============================================================================
// DriverCellManager - グローバル管理
// ============================================================================

/// DriverCell管理システム
///
/// 全てのドライバセルのライフサイクルを一元管理する。
/// PoisonLockにより、パニック時の安全性を保証する。
pub struct DriverCellManager {
    /// 全DriverCellのマップ
    cells: PoisonLock<BTreeMap<DriverCellId, DriverCell>>,
    /// 次のID
    next_id: AtomicU64,
}

impl DriverCellManager {
    /// 新しいManagerを作成
    pub const fn new() -> Self {
        Self {
            cells: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 新しいIDを生成
    pub fn allocate_id(&self) -> DriverCellId {
        DriverCellId::new(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// DriverCellを登録
    pub fn register(&self, cell: DriverCell) -> Result<DriverCellId, DriverCellError> {
        let id = cell.id;
        let mut cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverCellManager] Registry poisoned during register");
            DriverCellError::RegistryPoisoned
        })?;

        if cells.contains_key(&id) {
            return Err(DriverCellError::AlreadyExists(id));
        }

        log::info!(
            "[DriverCellManager] Registered: {} ({})\n",
            cell.name,
            id
        );
        cells.insert(id, cell);
        Ok(id)
    }

    /// DriverCellを取得（読み取り）
    pub fn with_cell<F, R>(&self, id: DriverCellId, f: F) -> Result<R, DriverCellError>
    where
        F: FnOnce(&DriverCell) -> R,
    {
        let cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverCellManager] Registry poisoned during read");
            DriverCellError::RegistryPoisoned
        })?;

        cells.get(&id).map(f).ok_or(DriverCellError::NotFound(id))
    }

    /// DriverCellを変更
    pub fn with_cell_mut<F, R>(&self, id: DriverCellId, f: F) -> Result<R, DriverCellError>
    where
        F: FnOnce(&mut DriverCell) -> R,
    {
        let mut cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverCellManager] Registry poisoned during write");
            DriverCellError::RegistryPoisoned
        })?;

        cells
            .get_mut(&id)
            .map(f)
            .ok_or(DriverCellError::NotFound(id))
    }

    /// DriverCellを削除
    pub fn remove(&self, id: DriverCellId) -> Result<DriverCell, DriverCellError> {
        let mut cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverCellManager] Registry poisoned during remove");
            DriverCellError::RegistryPoisoned
        })?;

        cells.remove(&id).ok_or(DriverCellError::NotFound(id))
    }

    /// 全DriverCellのスナップショットを取得
    pub fn list_snapshots(&self) -> Vec<DriverCellSnapshot> {
        match self.cells.lock() {
            Ok(cells) => cells.values().map(|c| c.snapshot()).collect(),
            Err(_) => {
                log::error!("[DriverCellManager] Registry poisoned (list_snapshots)");
                Vec::new()
            }
        }
    }

    /// 特定の状態のDriverCellを列挙
    pub fn cells_by_state(&self, state: DriverCellState) -> Vec<DriverCellId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .filter(|(_, c)| c.state == state)
                .map(|(id, _)| *id)
                .collect(),
            Err(_) => {
                log::error!("[DriverCellManager] Registry poisoned (cells_by_state)");
                Vec::new()
            }
        }
    }

    /// DomainIDからDriverCellを検索
    pub fn find_by_domain(&self, domain_id: DomainId) -> Option<DriverCellId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.domain_id == Some(domain_id))
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// CellIDからDriverCellを検索
    pub fn find_by_cell(&self, cell_id: CellId) -> Option<DriverCellId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.cell_id == Some(cell_id))
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// DriverHandleからDriverCellを検索
    pub fn find_by_driver_handle(&self, handle: DriverHandle) -> Option<DriverCellId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.driver_handles.contains(&handle))
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// 名前からDriverCellを検索
    pub fn find_by_name(&self, name: &str) -> Option<DriverCellId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.name == name)
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// 登録数を取得
    pub fn count(&self) -> usize {
        match self.cells.lock() {
            Ok(cells) => cells.len(),
            Err(_) => 0,
        }
    }

    /// 実行中のDriverCell数
    pub fn running_count(&self) -> usize {
        match self.cells.lock() {
            Ok(cells) => cells.values().filter(|c| c.state.is_running()).count(),
            Err(_) => 0,
        }
    }

    /// 障害発生中のDriverCell数
    pub fn faulted_count(&self) -> usize {
        match self.cells.lock() {
            Ok(cells) => {
                cells
                    .values()
                    .filter(|c| c.state == DriverCellState::Faulted)
                    .count()
            }
            Err(_) => 0,
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// DriverCell操作のエラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverCellError {
    /// DriverCellが見つからない
    NotFound(DriverCellId),
    /// 既に存在する
    AlreadyExists(DriverCellId),
    /// 無効な状態遷移
    InvalidStateTransition {
        from: DriverCellState,
        to: DriverCellState,
    },
    /// レジストリが毒入れされた
    RegistryPoisoned,
    /// セルのロードに失敗
    LoadFailed(String),
    /// ドメインの作成に失敗
    DomainCreationFailed(String),
    /// ドライバの初期化に失敗
    DriverInitFailed(String),
    /// ドライバの停止に失敗
    DriverStopFailed(String),
    /// 再起動ポリシーで再起動回数を超過
    RestartLimitExceeded {
        max_retries: u32,
        current: u32,
    },
    /// ホットスワップ失敗
    HotSwapFailed(String),
    /// リソースクォータ超過
    QuotaExceeded(String),
    /// ケイパビリティ不足
    InsufficientCapabilities,
    /// アンロード時に依存関係がある
    HasDependents,
}

impl core::fmt::Display for DriverCellError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "DriverCell not found: {}", id),
            Self::AlreadyExists(id) => write!(f, "DriverCell already exists: {}", id),
            Self::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition: {} -> {}", from, to)
            }
            Self::RegistryPoisoned => write!(f, "DriverCell registry poisoned"),
            Self::LoadFailed(msg) => write!(f, "Cell load failed: {}", msg),
            Self::DomainCreationFailed(msg) => write!(f, "Domain creation failed: {}", msg),
            Self::DriverInitFailed(msg) => write!(f, "Driver init failed: {}", msg),
            Self::DriverStopFailed(msg) => write!(f, "Driver stop failed: {}", msg),
            Self::RestartLimitExceeded { max_retries, current } => {
                write!(
                    f,
                    "Restart limit exceeded: {}/{} retries",
                    current, max_retries
                )
            }
            Self::HotSwapFailed(msg) => write!(f, "Hot-swap failed: {}", msg),
            Self::QuotaExceeded(msg) => write!(f, "Quota exceeded: {}", msg),
            Self::InsufficientCapabilities => write!(f, "Insufficient capabilities"),
            Self::HasDependents => write!(f, "Cell has active dependents"),
        }
    }
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルDriverCellマネージャ
static DRIVER_CELL_MANAGER: DriverCellManager = DriverCellManager::new();

/// グローバルマネージャへのアクセス
pub fn driver_cell_manager() -> &'static DriverCellManager {
    &DRIVER_CELL_MANAGER
}

/// DriverCellサブシステムを初期化
pub fn init() {
    log::info!("[DriverCell] Subsystem initialized\n");
}
