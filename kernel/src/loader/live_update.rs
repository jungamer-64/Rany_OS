// ============================================================================
// src/loader/live_update.rs - Epoch-based Reclamation for Live Updates
// 設計書 3.5.3: クォーラムと一貫性: Epoch-based Reclamation
// ============================================================================
//!
//! # ライブアップデートとEpoch-based Reclamation
//!
//! 高可用性環境でカーネル/ドライバの無停止更新を実現する。
//! RCU (Read-Copy-Update) に類似したEpoch-basedメモリ回収を採用。
//!
//! ## 設計書準拠
//!
//! - セクション 3.5.1: セルのホットスワップ
//! - セクション 3.5.2: 状態移行プロトコル
//! - セクション 3.5.3: Epoch-based Reclamation
//! - セクション 3.5.4: ロールバックと障害回復
//!
//! ## プロトコル概要
//!
//! ```text
//! 1. 新セルをメモリにロード（旧セルは維持）
//! 2. グローバルエポックをインクリメント
//! 3. 新セルへのポインタをGOTに書き込み（アトミックスワップ）
//! 4. Quiescent State Detection で全コアの離脱を確認
//! 5. 旧セルのメモリを解放
//! ```

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel_api::driver_abi::{DriverEntryFn, DriverExportsV1, DRIVER_ENTRY_SYMBOL, DRIVER_EXPORTS_SYMBOL};
use spin::Mutex;

// ============================================================================
// Epoch Management
// ============================================================================

/// 最大CPUコア数
const MAX_CORES: usize = 64;

/// グローバルエポックカウンタ
pub static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 各CPUコアのローカルエポック
pub struct PerCoreEpoch {
    /// 現在このコアが参照しているエポック
    pub local_epoch: AtomicU64,
    /// クリティカルセクション内かどうか
    pub in_critical_section: AtomicBool,
}

impl PerCoreEpoch {
    /// 新しいPerCoreEpochを作成
    pub const fn new() -> Self {
        Self {
            local_epoch: AtomicU64::new(0),
            in_critical_section: AtomicBool::new(false),
        }
    }
}

/// 全コアのエポック状態
static PER_CORE_EPOCHS: [PerCoreEpoch; MAX_CORES] = {
    const INIT: PerCoreEpoch = PerCoreEpoch::new();
    [INIT; MAX_CORES]
};

/// アクティブなコア数
static ACTIVE_CORES: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// Quiescent State API
// ============================================================================

/// クリティカルセクションに入る
///
/// セルのコードを使用する前に呼び出す。
/// 現在のグローバルエポックをローカルに記録する。
#[inline]
pub fn enter_critical_section() {
    let core_id = get_current_core_id();
    if core_id >= MAX_CORES {
        return;
    }

    let epoch = &PER_CORE_EPOCHS[core_id];
    let global = GLOBAL_EPOCH.load(Ordering::Acquire);

    epoch.local_epoch.store(global, Ordering::Release);
    epoch.in_critical_section.store(true, Ordering::Release);
}

/// クリティカルセクションから出る
///
/// セルのコードの使用が完了したら呼び出す。
#[inline]
pub fn leave_critical_section() {
    let core_id = get_current_core_id();
    if core_id >= MAX_CORES {
        return;
    }

    let epoch = &PER_CORE_EPOCHS[core_id];
    epoch.in_critical_section.store(false, Ordering::Release);
}

/// Quiescent State（安全な状態）に入る
///
/// Executorのメインループで周期的に呼び出す。
/// これにより、ライブアップデートの安全な切り替えポイントを提供する。
#[inline]
pub fn enter_quiescent_state() {
    let core_id = get_current_core_id();
    if core_id >= MAX_CORES {
        return;
    }

    let epoch = &PER_CORE_EPOCHS[core_id];

    // ローカルエポックをグローバルに同期
    let global = GLOBAL_EPOCH.load(Ordering::Acquire);
    epoch.local_epoch.store(global, Ordering::Release);

    // クリティカルセクション外であることを示す
    epoch.in_critical_section.store(false, Ordering::Release);
}

/// 全コアがQuiescent Stateに到達するのを待つ
///
/// 指定されたエポック以降に全コアが安全な状態に移行するまでブロック。
pub fn wait_for_quiescent_state(old_epoch: u64) {
    let active_cores = ACTIVE_CORES.load(Ordering::Acquire) as usize;

    loop {
        let all_departed = (0..active_cores.min(MAX_CORES)).all(|cpu| {
            let core_epoch = PER_CORE_EPOCHS[cpu].local_epoch.load(Ordering::Acquire);
            let in_cs = PER_CORE_EPOCHS[cpu]
                .in_critical_section
                .load(Ordering::Acquire);

            // コアがクリティカルセクション外か、新エポックに移行済み
            !in_cs || core_epoch > old_epoch
        });

        if all_departed {
            break;
        }

        // 短いスピンウェイト後、再チェック
        core::hint::spin_loop();
    }
}

// ============================================================================
// Request Tracker
// ============================================================================

/// ドメインへのアクティブリクエスト数を追跡
pub struct RequestTracker {
    /// アクティブなリクエスト数
    active_count: AtomicU64,
    /// ドレイン（排出）シグナル
    drain_signal: AtomicBool,
}

impl RequestTracker {
    /// 新しいRequestTrackerを作成
    pub const fn new() -> Self {
        Self {
            active_count: AtomicU64::new(0),
            drain_signal: AtomicBool::new(false),
        }
    }

    /// リクエストの開始を記録
    ///
    /// ドレイン中は false を返す（新規リクエスト拒否）。
    pub fn begin_request(&self) -> bool {
        if self.drain_signal.load(Ordering::Acquire) {
            return false; // ドレイン中は新規リクエストを拒否
        }
        self.active_count.fetch_add(1, Ordering::Acquire);
        true
    }

    /// リクエストの終了を記録
    pub fn end_request(&self) {
        self.active_count.fetch_sub(1, Ordering::Release);
    }

    /// アクティブリクエスト数を取得
    pub fn active_count(&self) -> u64 {
        self.active_count.load(Ordering::Acquire)
    }

    /// ドレインを開始し、全リクエストの完了を待機
    pub fn wait_for_drain(&self) {
        self.drain_signal.store(true, Ordering::Release);
        while self.active_count.load(Ordering::Acquire) > 0 {
            core::hint::spin_loop();
        }
    }

    /// ドレインをリセット
    pub fn reset_drain(&self) {
        self.drain_signal.store(false, Ordering::Release);
    }
}

// ============================================================================
// Live Update Protocol
// ============================================================================

/// ライブアップデートの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUpdateState {
    /// 準備完了
    Ready,
    /// 新セルロード中
    Loading,
    /// 切り替え中
    Switching,
    /// 旧セル解放待ち
    WaitingQuiescent,
    /// 完了
    Complete,
    /// エラー
    Error,
}

/// ライブアップデートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUpdateError {
    /// 更新中に別の更新が開始された
    UpdateInProgress,
    /// 新セルのロード失敗
    LoadFailed,
    /// Quiescent待機タイムアウト
    QuiescentTimeout,
    /// セルが見つからない
    CellNotFound,
    /// 状態移行失敗
    StateMigrationFailed,
}

impl core::fmt::Display for LiveUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UpdateInProgress => write!(f, "Another update is in progress"),
            Self::LoadFailed => write!(f, "Failed to load new cell"),
            Self::QuiescentTimeout => write!(f, "Timeout waiting for quiescent state"),
            Self::CellNotFound => write!(f, "Cell not found"),
            Self::StateMigrationFailed => write!(f, "State migration failed"),
        }
    }
}

/// ライブアップデートマネージャ
pub struct LiveUpdateManager {
    /// 現在の状態
    state: Mutex<LiveUpdateState>,
    /// 更新中フラグ
    updating: AtomicBool,
    /// ロールバック猶予期間のエポック
    rollback_epoch: AtomicU64,
    /// デフォルトロールバック猶予期間（ティック）
    rollback_grace_period: u64,
}

impl LiveUpdateManager {
    /// 新しいLiveUpdateManagerを作成
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(LiveUpdateState::Ready),
            updating: AtomicBool::new(false),
            rollback_epoch: AtomicU64::new(0),
            rollback_grace_period: 60 * 1000, // 60秒（ミリ秒）
        }
    }

    /// 現在の状態を取得
    pub fn state(&self) -> LiveUpdateState {
        *self.state.lock()
    }

    /// ライブアップデートを実行
    ///
    /// # Arguments
    /// - `cell_id`: 更新対象のセルID
    /// - `new_elf_data`: 新しいセルのELFデータ
    ///
    /// # Returns
    /// 成功時は新しいセルIDを返す
    pub fn perform_update(
        &self,
        _cell_id: u64,
        _new_elf_data: &[u8],
    ) -> Result<u64, LiveUpdateError> {
        // 排他制御
        if self.updating.swap(true, Ordering::Acquire) {
            return Err(LiveUpdateError::UpdateInProgress);
        }

        let result = self.perform_update_inner(_cell_id, _new_elf_data);

        self.updating.store(false, Ordering::Release);
        result
    }

    fn perform_update_inner(
        &self,
        old_id_u64: u64,
        new_elf_data: &[u8],
    ) -> Result<u64, LiveUpdateError> {
        let old_cell_id = crate::loader::CellId::from_u64(old_id_u64);

        // Step 0: Identify target driver(s) from old cell
        let old_drivers = crate::loader::with_registry(|r| {
            r.get(old_cell_id).map(|c| c.registered_drivers.clone())
        });

        let old_drivers = match old_drivers {
            Some(d) => d,
            None => return Err(LiveUpdateError::CellNotFound),
        };

        if old_drivers.is_empty() {
            return Err(LiveUpdateError::CellNotFound); // Or invalid state
        }

        // Step 1: Load new cell
        *self.state.lock() = LiveUpdateState::Loading;
        log::info!("[LIVE_UPDATE] Loading new cell version...\n");

        // Generate a name for the new cell based on old cell?
        // For now, use "update-<epoch>"
        let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
        let name = alloc::format!("update-{}", epoch);

        // Load the cell (unsafe allowed for updates)
        let new_cell_id = match crate::loader::load_cell(&name, new_elf_data, true) {
            Ok(id) => id,
            Err(_) => return Err(LiveUpdateError::LoadFailed),
        };

        // Step 2: Global Epoch Increment (Pre-swap)
        let old_epoch = GLOBAL_EPOCH.fetch_add(1, Ordering::SeqCst);
        log::info!(
            "[LIVE_UPDATE] Epoch incremented: {} -> {}\n",
            old_epoch,
            old_epoch + 1
        );

        // Step 3: Swap (Update Driver Registry)
        *self.state.lock() = LiveUpdateState::Switching;

        let resolve_entry = |cell_id, call_init| -> Result<(DriverEntryFn, Option<extern "C" fn() -> i32>), LiveUpdateError> {
            let exports_addr = crate::loader::with_registry(|r| {
                let cell = r.get(cell_id)?;
                cell.exports
                    .iter()
                    .find(|(n, _)| n == DRIVER_EXPORTS_SYMBOL)
                    .map(|(_, addr)| *addr)
            });

            if let Some(addr) = exports_addr {
                let exports_ptr = addr as *const DriverExportsV1;
                let prepared = crate::driver_registry::prepare_driver_exports(exports_ptr, call_init)
                    .map_err(|_| LiveUpdateError::LoadFailed)?;
                return Ok((prepared.entry, prepared.fini));
            }

            let entry_addr = crate::loader::with_registry(|r| {
                let cell = r.get(cell_id)?;
                cell.exports
                    .iter()
                    .find(|(n, _)| n == DRIVER_ENTRY_SYMBOL)
                    .map(|(_, addr)| *addr)
            });

            let entry_addr = match entry_addr {
                Some(a) => a,
                None => return Err(LiveUpdateError::LoadFailed),
            };

            let entry_fn: DriverEntryFn = unsafe { core::mem::transmute(entry_addr) };
            Ok((entry_fn, None))
        };

        // Resolve entry symbol in NEW cell
        let (entry_fn, entry_fini) = match resolve_entry(new_cell_id, true) {
            Ok(v) => v,
            Err(_) => {
                let _ = crate::loader::with_registry_mut(|r| r.unload(new_cell_id));
                return Err(LiveUpdateError::LoadFailed);
            }
        };

        // Resolve entry symbol in OLD cell (for rollback)
        let old_entry = resolve_entry(old_cell_id, false).ok();

        // Update all drivers registered to the old cell
        let mut updated_handles = Vec::new();
        let mut update_failed = false;

        for handle in &old_drivers {
            match crate::driver_registry::update_abi_driver_with_fini(*handle, entry_fn, entry_fini) {
                Ok(_) => updated_handles.push(*handle),
                Err(_) => {
                    update_failed = true;
                    break;
                }
            }
        }

        if update_failed {
            log::error!("[LIVE_UPDATE] Update failed, rolling back {} drivers...\n", updated_handles.len());
            // Rollback successful updates
            if let Some((old_entry_fn, old_entry_fini)) = old_entry {
                for handle in updated_handles {
                    if let Err(e) =
                        crate::driver_registry::update_abi_driver_with_fini(handle, old_entry_fn, old_entry_fini)
                    {
                        log::error!(
                            "[LIVE_UPDATE] CRITICAL: Rollback failed for driver {:?}: {:?}\n",
                            handle,
                            e
                        );
                    }
                }
            } else {
                 log::error!("[LIVE_UPDATE] CRITICAL: Cannot rollback, old entry point not found\n");
            }

            // Cleanup new cell
            let _ = crate::loader::with_registry_mut(|r| r.unload(new_cell_id));
            return Err(LiveUpdateError::StateMigrationFailed);
        }

        // Step 3.5: Migrate ownership in Cell Registry
        crate::loader::with_registry_mut(|r| {
            if let Some(old_c) = r.get_mut(old_cell_id) {
                old_c.registered_drivers.clear();
            }
            if let Some(new_c) = r.get_mut(new_cell_id) {
                for h in &old_drivers {
                    new_c.registered_drivers.push(*h);
                }
            }
        });

        // Step 4: Wait for Quiescent State
        *self.state.lock() = LiveUpdateState::WaitingQuiescent;
        log::info!("[LIVE_UPDATE] Waiting for quiescent state...\n");
        wait_for_quiescent_state(old_epoch);
        log::info!("[LIVE_UPDATE] All cores reached quiescent state\n");

        // Step 5: Complete & Free Old Cell
        *self.state.lock() = LiveUpdateState::Complete;
        self.rollback_epoch.store(old_epoch + 1, Ordering::Release);

        // Unload old cell
        match crate::loader::unload_cell(old_cell_id) {
            Ok(_) => log::info!("[LIVE_UPDATE] Old cell unloaded\n"),
            Err(e) => log::info!(
                "[LIVE_UPDATE] Warning: Failed to unload old cell: {:?}\n",
                e
            ),
        }

        Ok(new_cell_id.as_u64())
    }

    /// ロールバックを実行
    pub fn rollback(&self) -> Result<(), LiveUpdateError> {
        log::info!("[LIVE_UPDATE] Rollback requested\n");
        // TODO: ロールバック実装
        Ok(())
    }
}

impl Default for LiveUpdateManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Instance & Initialization
// ============================================================================

/// グローバルライブアップデートマネージャ
static LIVE_UPDATE_MANAGER: LiveUpdateManager = LiveUpdateManager::new();

/// ライブアップデートマネージャを取得
pub fn live_update_manager() -> &'static LiveUpdateManager {
    &LIVE_UPDATE_MANAGER
}

/// アクティブコア数を設定
pub fn set_active_cores(count: u64) {
    ACTIVE_CORES.store(count, Ordering::Release);
}

/// 現在のグローバルエポックを取得
pub fn current_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// ライブアップデートサブシステムを初期化
pub fn init() {
    // 初期エポックを1に設定
    GLOBAL_EPOCH.store(1, Ordering::Release);
    log::info!("[LIVE_UPDATE] Epoch-based reclamation initialized\n");
}

// ============================================================================
// Helper Functions
// ============================================================================

/// 現在のCPUコアIDを取得
fn get_current_core_id() -> usize {
    // LAPICからコアIDを取得（簡易版）
    // 実際にはLAPIC IDをコアインデックスに変換する必要がある
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID経由でLAPIC IDを取得
        use core::arch::x86_64::__cpuid;
        let result = __cpuid(0x01);
        ((result.ebx >> 24) & 0xFF) as usize
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// StateTransfer Trait - 設計書 3.5.2: 状態移行プロトコル
// ============================================================================

use alloc::vec::Vec;

/// ライブアップデート時の状態エクスポートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateExportError {
    /// シリアライズに失敗
    SerializationFailed,
    /// バッファ不足
    BufferTooSmall,
    /// 状態が不整合
    InconsistentState,
    /// サポートされていない
    NotSupported,
}

/// ライブアップデート時の状態インポートエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateImportError {
    /// デシリアライズに失敗
    DeserializationFailed,
    /// バージョン非互換
    VersionMismatch,
    /// 破損したデータ
    CorruptedData,
    /// 状態復元に失敗
    RestoreFailed,
    /// サポートされていない
    NotSupported,
}

/// エクスポートされた状態のメタデータ
#[derive(Debug, Clone)]
pub struct ExportedStateMetadata {
    /// 状態のバージョン番号
    pub version: u32,
    /// エクスポート元のセルID
    pub source_cell_id: u64,
    /// エクスポート時刻（ティック）
    pub export_time: u64,
    /// 状態データのサイズ
    pub data_size: usize,
    /// チェックサム（簡易整合性検証用）
    pub checksum: u32,
}

/// エクスポートされた状態
/// 設計書 3.5.2: 内部状態を交換ヒープ上のシリアライズ可能な形式にエクスポート
#[derive(Debug, Clone)]
pub struct ExportedState {
    /// メタデータ
    pub metadata: ExportedStateMetadata,
    /// シリアライズされた状態データ
    pub data: Vec<u8>,
}

impl ExportedState {
    /// 新しいExportedStateを作成
    pub fn new(version: u32, source_cell_id: u64, data: Vec<u8>) -> Self {
        let checksum = Self::compute_checksum(&data);
        Self {
            metadata: ExportedStateMetadata {
                version,
                source_cell_id,
                export_time: crate::task::timer::current_tick(),
                data_size: data.len(),
                checksum,
            },
            data,
        }
    }

    /// チェックサムを計算（簡易版：バイト合計）
    fn compute_checksum(data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
    }

    /// データの整合性を検証
    pub fn verify(&self) -> bool {
        self.metadata.data_size == self.data.len()
            && self.metadata.checksum == Self::compute_checksum(&self.data)
    }
}

/// 状態移行トレイト
/// 設計書 3.5.2: セルが内部状態を持つ場合、ライブアップデート時に状態を新バージョンに移行
///
/// # 使用例
/// ```rust
/// impl StateTransfer for NetworkDriver {
///     const STATE_VERSION: u32 = 1;
///     
///     fn export_state(&self) -> Result<ExportedState, StateExportError> {
///         // 内部状態をシリアライズ
///         let mut data = Vec::new();
///         // ... シリアライズ処理 ...
///         Ok(ExportedState::new(Self::STATE_VERSION, self.cell_id(), data))
///     }
///     
///     fn import_state(state: ExportedState) -> Result<Self, StateImportError> {
///         if state.metadata.version != Self::STATE_VERSION {
///             return Err(StateImportError::VersionMismatch);
///         }
///         // 状態を復元
///         // ... デシリアライズ処理 ...
///         Ok(Self::new_from_state(...))
///     }
/// }
/// ```
pub trait StateTransfer: Sized {
    /// 状態のバージョン番号
    /// 新バージョンが旧フォーマットを理解できない場合はロールバック
    const STATE_VERSION: u32;

    /// 内部状態をエクスポート（シリアライズ）
    /// 設計書 3.5.2: 旧セルが内部状態を交換ヒープ上の形式にエクスポート
    fn export_state(&self) -> Result<ExportedState, StateExportError>;

    /// 状態をインポート（デシリアライズ）して新インスタンスを構築
    /// 設計書 3.5.2: 新セルがエクスポートされた状態をインポートして復元
    fn import_state(state: ExportedState) -> Result<Self, StateImportError>;

    /// バージョン互換性をチェック
    /// デフォルトでは完全一致のみ許可
    fn is_version_compatible(exported_version: u32) -> bool {
        exported_version == Self::STATE_VERSION
    }

    /// セルIDを取得（オプショナル）
    fn cell_id(&self) -> u64 {
        0
    }

    /// 状態移行を試行
    /// バージョン互換性チェック + インポートを一括で行う
    fn try_migrate(state: ExportedState) -> Result<Self, StateImportError> {
        // データ整合性検証
        if !state.verify() {
            return Err(StateImportError::CorruptedData);
        }

        // バージョン互換性チェック
        if !Self::is_version_compatible(state.metadata.version) {
            return Err(StateImportError::VersionMismatch);
        }

        // 状態をインポート
        Self::import_state(state)
    }
}

/// StateTransferを実装しないセル用のダミー実装
/// 状態を持たないセルはこれを使用可能
pub struct StatelessCell;

impl StateTransfer for StatelessCell {
    const STATE_VERSION: u32 = 0;

    fn export_state(&self) -> Result<ExportedState, StateExportError> {
        // 状態なし - 空のデータをエクスポート
        Ok(ExportedState::new(Self::STATE_VERSION, 0, Vec::new()))
    }

    fn import_state(state: ExportedState) -> Result<Self, StateImportError> {
        if !state.data.is_empty() {
            return Err(StateImportError::CorruptedData);
        }
        Ok(StatelessCell)
    }
}


