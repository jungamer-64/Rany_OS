// ============================================================================
// kernel/src/driver_cell/hot_swap.rs - DriverCell ホットスワップ
// ============================================================================
//! # ドライバセルのホットスワップ（ライブアップデート）
//!
//! 設計書 3.5: リアルタイムアップデート
//! 設計書 3.5.1: セルのホットスワップ
//! 設計書 3.5.3: Epoch-based Reclamation
//!
//! ## ホットスワップフロー
//!
//! ```text
//! 1. 新ELFをロード（旧セルは維持）
//! 2. LiveUpdateManager経由でアップデート実行
//!    a. グローバルエポックをインクリメント
//!    b. 新ドライバを旧ドライバのハンドルに差し替え
//!    c. Quiescent State Detection で全コアの離脱を確認
//! 3. 旧セルのメモリを安全に解放
//! 4. DriverCellのメタデータを更新
//! ```

#![allow(dead_code)]

use alloc::format;

use crate::loader::CellId;

use super::{DriverCellError, DriverCellId, DriverCellState, driver_cell_manager};

// ============================================================================
// Hot Swap State
// ============================================================================

/// ホットスワップの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotSwapState {
    /// アイドル（スワップ中ではない）
    Idle,
    /// 新バージョンのロード中
    Loading,
    /// 切り替え中
    Switching,
    /// 検証中（新バージョンの動作確認）
    Validating,
    /// 完了
    Complete,
    /// エラー（ロールバック済みまたは要ロールバック）
    Error,
}

impl core::fmt::Display for HotSwapState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Loading => write!(f, "Loading"),
            Self::Switching => write!(f, "Switching"),
            Self::Validating => write!(f, "Validating"),
            Self::Complete => write!(f, "Complete"),
            Self::Error => write!(f, "Error"),
        }
    }
}

// ============================================================================
// Hot Swap Result
// ============================================================================

/// ホットスワップの結果
#[derive(Debug, Clone)]
pub struct HotSwapResult {
    /// 旧CellID
    pub old_cell_id: CellId,
    /// 新CellID
    pub new_cell_id: CellId,
    /// スワップにかかった時間（ティック）
    pub duration_ticks: u64,
    /// ロールバックが必要かどうか
    pub needs_rollback: bool,
}

// ============================================================================
// Hot Swap Operations
// ============================================================================

/// DriverCellのホットスワップを実行
///
/// 新しいELFバイナリでドライバを置換する。
/// Epoch-based Reclamationにより、旧コードへの参照が安全に消えるまで
/// メモリは解放されない。
///
/// # Arguments
/// - `id`: DriverCellのID
/// - `new_elf_data`: 新しいELFバイナリ
///
/// # Returns
/// 成功時は `HotSwapResult` を返す
pub fn hot_swap(
    id: DriverCellId,
    new_elf_data: &[u8],
) -> Result<HotSwapResult, DriverCellError> {
    let manager = driver_cell_manager();
    let start_tick = crate::task::timer::current_tick();

    // 状態チェック: Runningのみホットスワップ可能
    let old_cell_id = manager.with_cell(id, |cell| {
        if cell.state != DriverCellState::Running {
            return Err(DriverCellError::InvalidStateTransition {
                from: cell.state,
                to: DriverCellState::Updating,
            });
        }
        cell.cell_id.ok_or(DriverCellError::LoadFailed(
            "No cell loaded".into(),
        ))
    })??;

    // Updating状態に遷移
    manager.with_cell_mut(id, |cell| {
        cell.transition_to(DriverCellState::Updating);
        cell.hot_swap_state = HotSwapState::Loading;
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!(
        "[DriverCell] Hot-swap starting for '{}' (old cell={:?})\n",
        name,
        old_cell_id.as_u64()
    );

    // LiveUpdateManagerを使用してアップデート実行
    let live_update = crate::loader::live_update_manager();

    manager.with_cell_mut(id, |cell| {
        cell.hot_swap_state = HotSwapState::Switching;
    })?;

    match live_update.perform_update(old_cell_id.as_u64(), new_elf_data) {
        Ok(new_cell_id_u64) => {
            let new_cell_id = CellId::from_u64(new_cell_id_u64);
            let duration = crate::task::timer::current_tick().saturating_sub(start_tick);

            // DriverCellのメタデータを更新
            manager.with_cell_mut(id, |cell| {
                cell.cell_id = Some(new_cell_id);
                cell.hot_swap_state = HotSwapState::Validating;
            })?;

            // 新ドライバのハンドルを更新
            // LiveUpdateManagerが内部的にDriverRegistryを更新しているため、
            // DriverCellのdriver_handlesは旧ハンドルを維持（replace_driver済み）
            update_driver_handles_after_swap(id, new_cell_id)?;

            // Running状態に復帰
            manager.with_cell_mut(id, |cell| {
                cell.transition_to(DriverCellState::Running);
                cell.hot_swap_state = HotSwapState::Complete;
                cell.stats.record_hot_swap();
            })?;

            log::info!(
                "[DriverCell] Hot-swap completed for '{}': cell {:?} -> {:?} ({}ms)\n",
                name,
                old_cell_id.as_u64(),
                new_cell_id_u64,
                duration / 1000 // rough tick→ms (depends on timer)
            );

            Ok(HotSwapResult {
                old_cell_id,
                new_cell_id,
                duration_ticks: duration,
                needs_rollback: false,
            })
        }
        Err(e) => {
            let msg = format!("LiveUpdate failed: {}", e);
            log::error!(
                "[DriverCell] Hot-swap failed for '{}': {}\n",
                name,
                msg
            );

            // ロールバック: 元のRunning状態に復帰
            manager.with_cell_mut(id, |cell| {
                cell.hot_swap_state = HotSwapState::Error;
                cell.transition_to(DriverCellState::Running);
            })?;

            Err(DriverCellError::HotSwapFailed(msg))
        }
    }
}

/// ホットスワップ後のドライバハンドル更新
///
/// LiveUpdateManagerがDriverRegistryのreplace_driverを呼んでいるため、
/// 既存のDriverHandleは有効なまま（vtableが新コードを指している）。
/// CellEntryのregistered_driversを新セルに付け替える。
fn update_driver_handles_after_swap(
    id: DriverCellId,
    new_cell_id: CellId,
) -> Result<(), DriverCellError> {
    let manager = driver_cell_manager();

    let handles = manager.with_cell(id, |cell| cell.driver_handles.clone())?;

    // 新セルのregistered_driversを更新
    crate::loader::with_registry_mut(|r| {
        if let Some(entry) = r.get_mut(new_cell_id) {
            for handle in &handles {
                if !entry.registered_drivers.contains(handle) {
                    entry.registered_drivers.push(*handle);
                }
            }
        }
    });

    Ok(())
}

/// ホットスワップをロールバック
///
/// 検証フェーズで問題が発見された場合に呼び出す。
/// LiveUpdateManagerのrollback()を使用して旧バージョンに復帰する。
pub fn rollback(id: DriverCellId) -> Result<(), DriverCellError> {
    let manager = driver_cell_manager();

    let hot_swap_state = manager.with_cell(id, |cell| cell.hot_swap_state)?;

    if hot_swap_state != HotSwapState::Validating && hot_swap_state != HotSwapState::Error {
        return Err(DriverCellError::HotSwapFailed(
            "No active hot-swap to rollback".into(),
        ));
    }

    let live_update = crate::loader::live_update_manager();
    if let Err(e) = live_update.rollback() {
        return Err(DriverCellError::HotSwapFailed(format!(
            "Rollback failed: {}",
            e
        )));
    }

    manager.with_cell_mut(id, |cell| {
        cell.hot_swap_state = HotSwapState::Idle;
        cell.transition_to(DriverCellState::Running);
    })?;

    let name = manager.with_cell(id, |cell| cell.name.clone())?;
    log::info!("[DriverCell] Hot-swap rolled back for '{}'\n", name);

    Ok(())
}

/// ホットスワップの状態を確認
pub fn hot_swap_status(id: DriverCellId) -> Result<HotSwapState, DriverCellError> {
    driver_cell_manager().with_cell(id, |cell| cell.hot_swap_state)
}
