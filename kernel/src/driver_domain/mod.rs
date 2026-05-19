// ============================================================================
// kernel/src/driver_domain/mod.rs - Driver Domain: 統一ドライバ隔離モデル
// ============================================================================
//! # Driver Domain (ドライバドメイン)
//!
//! 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
//! 設計書 8: フォールトアイソレーションと回復メカニズム
//!
//! ## 概要
//!
//! `DriverDomain` は、以下の3つの概念を統合する実行時抽象です:
//!
//! 1. **Cell** (ローダーレベル) - ELFバイナリとしてロードされたコード
//! 2. **Domain** (実行時管理) - リソースクォータ、ケイパビリティ、状態追跡
//! 3. **Driver** (デバイスインターフェース) - ドライバライフサイクル管理
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    DriverDomain                           │
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
pub mod fault;
pub mod hot_swap;
pub mod lifecycle;
pub mod stats;

#[cfg(feature = "qemu-test-export")]
#[path = "tests.rs"]
pub mod qemu_tests;

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::domain::DomainId;
use crate::domain::quota::DomainPriority;
use crate::driver_registry::DriverHandle;
use crate::loader::CellId;
use crate::security::CapabilitySet;
use crate::sync::PoisonLock;
use kernel_api::abi::driver::DriverContext as AbiDriverContext;

pub use fault::{FaultRecord, RestartPolicy};
pub use hot_swap::HotSwapState;
pub use lifecycle::DriverDomainConfig;
pub use stats::DriverDomainStats;

// ============================================================================
// DriverDomain ID
// ============================================================================

/// DriverCellを一意に識別するID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DriverDomainId(u64);

impl DriverDomainId {
    /// 新しいIDを作成
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// IDを数値として取得
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for DriverDomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DriverDomain({})", self.0)
    }
}

// ============================================================================
// DriverDomain State
// ============================================================================

/// DriverCellのライフサイクル状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverDomainState {
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

impl DriverDomainState {
    /// 実行中かどうか
    pub fn is_running(&self) -> bool {
        matches!(self, DriverDomainState::Running)
    }

    /// アクティブ（リソースを保持）かどうか
    pub fn is_active(&self) -> bool {
        !matches!(
            self,
            DriverDomainState::Created | DriverDomainState::Unloaded
        )
    }

    /// 停止可能かどうか
    pub fn can_stop(&self) -> bool {
        matches!(
            self,
            DriverDomainState::Running | DriverDomainState::Starting | DriverDomainState::Faulted
        )
    }

    /// 再起動可能かどうか
    pub fn can_restart(&self) -> bool {
        matches!(
            self,
            DriverDomainState::Stopped | DriverDomainState::Faulted
        )
    }
}

impl core::fmt::Display for DriverDomainState {
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
// DriverDomain - 統合ドライバ隔離モデル
// ============================================================================

/// DriverDomain: Cell + Domain + Driver の統合抽象
///
/// 設計書 3.1: セル(Cell)モデルの完全な実装
/// - コードの分離（Cell/ELFロード）
/// - 実行時の分離（Domain/リソース管理）
/// - デバイスインターフェース（Driver/ライフサイクル）
/// - 障害分離（Proxy/PoisonLock/Exchange Heap）
pub struct DriverDomain {
    // === 識別情報 ===
    /// DriverCellの一意なID
    pub id: DriverDomainId,
    /// ドライバドメイン名
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
    pub state: DriverDomainState,
    /// 前回の状態（遷移追跡用）
    previous_state: Option<DriverDomainState>,

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
    /// 検証猶予の期限（ティック）
    pub validation_deadline_tick: Option<u64>,
    /// 直近のヘルス失敗理由
    pub last_health_failure: Option<String>,

    // === 統計情報 ===
    /// 統計データ
    pub stats: DriverDomainStats,

    // === NUMAアフィニティ ===
    /// NUMAノード（任意）
    pub numa_node: Option<usize>,
    /// ABIドライバに渡すデバイスコンテキスト
    pub abi_driver_context: AbiDriverContext,

    /// 作成時刻（TSCティック）
    pub created_at: u64,
}

impl DriverDomain {
    /// 新しいDriverCellを作成
    pub fn new(id: DriverDomainId, name: String) -> Self {
        Self {
            id,
            name,
            cell_id: None,
            domain_id: None,
            driver_handles: Vec::new(),
            state: DriverDomainState::Created,
            previous_state: None,
            restart_policy: RestartPolicy::default(),
            priority: DomainPriority::Normal,
            capabilities: CapabilitySet::empty(),
            allow_unsafe: false,
            cpu_limit_percent: 100,
            memory_limit_bytes: 64 * 1024 * 1024, // 64MB デフォルト
            io_bandwidth_limit: 0,                // 0 = 制限なし
            fault_history: Vec::new(),
            consecutive_faults: 0,
            hot_swap_state: HotSwapState::Idle,
            validation_deadline_tick: None,
            last_health_failure: None,
            stats: DriverDomainStats::new(),
            numa_node: None,
            abi_driver_context: AbiDriverContext::new(),
            created_at: crate::task::current_tick(),
        }
    }

    /// 設定から作成
    pub fn from_config(id: DriverDomainId, config: &DriverDomainConfig) -> Self {
        let mut cell = Self::new(id, config.name.clone());
        cell.restart_policy = config.restart_policy;
        cell.priority = config.priority;
        cell.capabilities = config.capabilities;
        cell.allow_unsafe = config.allow_unsafe;
        cell.cpu_limit_percent = config.cpu_limit_percent;
        cell.memory_limit_bytes = config.memory_limit_bytes;
        cell.io_bandwidth_limit = config.io_bandwidth_limit;
        cell.numa_node = config.numa_node;
        cell.abi_driver_context = config.abi_driver_context;
        cell
    }

    /// 状態を遷移
    fn transition_to(&mut self, new_state: DriverDomainState) {
        self.previous_state = Some(self.state);
        let old = self.state;
        self.state = new_state;
        log::info!(
            "[DriverDomain] {} state: {} -> {}\n",
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
    pub fn snapshot(&self) -> DriverDomainSnapshot {
        DriverDomainSnapshot {
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
            hot_swap_state: self.hot_swap_state,
            validation_deadline_tick: self.validation_deadline_tick,
            last_health_failure: self.last_health_failure.clone(),
        }
    }
}

impl core::fmt::Debug for DriverDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DriverDomain")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state)
            .field("cell_id", &self.cell_id)
            .field("domain_id", &self.domain_id)
            .field("driver_handles", &self.driver_handles.len())
            .field("priority", &self.priority)
            .field("faults", &self.consecutive_faults)
            .field("pci_locator", &self.abi_driver_context.pci_locator)
            .finish()
    }
}

// ============================================================================
// DriverDomain Snapshot
// ============================================================================

/// DriverCellの軽量スナップショット（外部公開用）
#[derive(Debug, Clone)]
pub struct DriverDomainSnapshot {
    pub id: DriverDomainId,
    pub name: String,
    pub state: DriverDomainState,
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
    pub stats: DriverDomainStats,
    pub hot_swap_state: HotSwapState,
    pub validation_deadline_tick: Option<u64>,
    pub last_health_failure: Option<String>,
}

// ============================================================================
// DriverDomainManager - グローバル管理
// ============================================================================

/// DriverCell管理システム
///
/// 全てのドライバドメインのライフサイクルを一元管理する。
/// PoisonLockにより、パニック時の安全性を保証する。
pub struct DriverDomainManager {
    /// 全DriverCellのマップ
    cells: PoisonLock<BTreeMap<DriverDomainId, DriverDomain>>,
    /// 次のID
    next_id: AtomicU64,
}

impl DriverDomainManager {
    /// 新しいManagerを作成
    pub const fn new() -> Self {
        Self {
            cells: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 新しいIDを生成
    pub fn allocate_id(&self) -> DriverDomainId {
        DriverDomainId::new(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// DriverCellを登録
    pub fn register(&self, cell: DriverDomain) -> Result<DriverDomainId, DriverDomainError> {
        let id = cell.id;
        let mut cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverDomainManager] Registry poisoned during register");
            DriverDomainError::RegistryPoisoned
        })?;

        if cells.contains_key(&id) {
            return Err(DriverDomainError::AlreadyExists(id));
        }

        log::info!("[DriverDomainManager] Registered: {} ({})\n", cell.name, id);
        cells.insert(id, cell);
        Ok(id)
    }

    /// DriverCellを取得（読み取り）
    pub fn with_cell<F, R>(&self, id: DriverDomainId, f: F) -> Result<R, DriverDomainError>
    where
        F: FnOnce(&DriverDomain) -> R,
    {
        let cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverDomainManager] Registry poisoned during read");
            DriverDomainError::RegistryPoisoned
        })?;

        cells.get(&id).map(f).ok_or(DriverDomainError::NotFound(id))
    }

    /// DriverCellを変更
    pub fn with_cell_mut<F, R>(&self, id: DriverDomainId, f: F) -> Result<R, DriverDomainError>
    where
        F: FnOnce(&mut DriverDomain) -> R,
    {
        let mut cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverDomainManager] Registry poisoned during write");
            DriverDomainError::RegistryPoisoned
        })?;

        cells
            .get_mut(&id)
            .map(f)
            .ok_or(DriverDomainError::NotFound(id))
    }

    /// DriverCellを削除
    pub fn remove(&self, id: DriverDomainId) -> Result<DriverDomain, DriverDomainError> {
        let mut cells = self.cells.lock().map_err(|_| {
            log::error!("[DriverDomainManager] Registry poisoned during remove");
            DriverDomainError::RegistryPoisoned
        })?;

        cells.remove(&id).ok_or(DriverDomainError::NotFound(id))
    }

    /// 全DriverCellのスナップショットを取得
    pub fn list_snapshots(&self) -> Vec<DriverDomainSnapshot> {
        match self.cells.lock() {
            Ok(cells) => cells.values().map(|c| c.snapshot()).collect(),
            Err(_) => {
                log::error!("[DriverDomainManager] Registry poisoned (list_snapshots)");
                Vec::new()
            }
        }
    }

    /// 特定の状態のDriverCellを列挙
    pub fn cells_by_state(&self, state: DriverDomainState) -> Vec<DriverDomainId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .filter(|(_, c)| c.state == state)
                .map(|(id, _)| *id)
                .collect(),
            Err(_) => {
                log::error!("[DriverDomainManager] Registry poisoned (cells_by_state)");
                Vec::new()
            }
        }
    }

    /// DomainIDからDriverCellを検索
    pub fn find_by_domain(&self, domain_id: DomainId) -> Option<DriverDomainId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.domain_id == Some(domain_id))
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// CellIDからDriverCellを検索
    pub fn find_by_cell(&self, cell_id: CellId) -> Option<DriverDomainId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.cell_id == Some(cell_id))
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// DriverHandleからDriverCellを検索
    pub fn find_by_driver_handle(&self, handle: DriverHandle) -> Option<DriverDomainId> {
        match self.cells.lock() {
            Ok(cells) => cells
                .iter()
                .find(|(_, c)| c.driver_handles.contains(&handle))
                .map(|(id, _)| *id),
            Err(_) => None,
        }
    }

    /// 名前からDriverCellを検索
    pub fn find_by_name(&self, name: &str) -> Option<DriverDomainId> {
        crate::io::log::early_print("[DCELL-MGR] find_by_name enter locked=");
        crate::io::log::early_print(if self.cells.is_locked() { "1" } else { "0" });
        crate::io::log::early_print("\n");
        match self.cells.lock() {
            Ok(cells) => {
                crate::io::log::early_print("[DCELL-MGR] find_by_name lock ok\n");
                for (id, c) in cells.iter() {
                    crate::io::log::early_print("[DCELL-MGR] candidate id=");
                    crate::io::log::early_print_hex(id.as_u64());
                    crate::io::log::early_print(" name_ptr=");
                    crate::io::log::early_print_hex(c.name.as_ptr() as usize as u64);
                    crate::io::log::early_print(" name_len=");
                    crate::io::log::early_print_hex(c.name.len() as u64);
                    crate::io::log::early_print("\n");
                    if c.name == name {
                        crate::io::log::early_print("[DCELL-MGR] find_by_name hit\n");
                        return Some(*id);
                    }
                }
                crate::io::log::early_print("[DCELL-MGR] find_by_name miss\n");
                None
            }
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
            Ok(cells) => cells
                .values()
                .filter(|c| c.state == DriverDomainState::Faulted)
                .count(),
            Err(_) => 0,
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// DriverCell操作のエラー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverDomainError {
    /// DriverCellが見つからない
    NotFound(DriverDomainId),
    /// 既に存在する
    AlreadyExists(DriverDomainId),
    /// 無効な状態遷移
    InvalidStateTransition {
        from: DriverDomainState,
        to: DriverDomainState,
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
    RestartLimitExceeded { max_retries: u32, current: u32 },
    /// ホットスワップ失敗
    HotSwapFailed(String),
    /// リソースクォータ超過
    QuotaExceeded(String),
    /// ケイパビリティ不足
    InsufficientCapabilities,
    /// アンロード時に依存関係がある
    HasDependents,
}

impl core::fmt::Display for DriverDomainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "DriverDomain not found: {}", id),
            Self::AlreadyExists(id) => write!(f, "DriverDomain already exists: {}", id),
            Self::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition: {} -> {}", from, to)
            }
            Self::RegistryPoisoned => write!(f, "DriverDomain registry poisoned"),
            Self::LoadFailed(msg) => write!(f, "Cell load failed: {}", msg),
            Self::DomainCreationFailed(msg) => write!(f, "Domain creation failed: {}", msg),
            Self::DriverInitFailed(msg) => write!(f, "Driver init failed: {}", msg),
            Self::DriverStopFailed(msg) => write!(f, "Driver stop failed: {}", msg),
            Self::RestartLimitExceeded {
                max_retries,
                current,
            } => {
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
static DRIVER_DOMAIN_MANAGER: DriverDomainManager = DriverDomainManager::new();

/// グローバルマネージャへのアクセス
pub fn driver_domain_manager() -> &'static DriverDomainManager {
    &DRIVER_DOMAIN_MANAGER
}

/// DriverCellサブシステムを初期化
pub fn init() {
    log::info!("[DriverDomain] Subsystem initialized\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::abi::driver::{DriverContext as AbiDriverContext, PackedPciLocation};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn from_config_preserves_abi_driver_context() {
        let locator = PackedPciLocation::new(0x1234, 0x56, 0x07, 0x01);
        let ctx = AbiDriverContext::for_pci(0xfeed_0000, 9, 0x8086, 0x100e, 0x0200_00, locator);
        let config = DriverDomainConfig::new("test-driver").with_abi_driver_context(ctx);

        let domain = DriverDomain::from_config(DriverDomainId::new(1), &config);

        assert_eq!(domain.abi_driver_context.device_address, 0xfeed_0000);
        assert_eq!(domain.abi_driver_context.irq, 9);
        assert_eq!(domain.abi_driver_context.pci_location(), locator);
    }
}
