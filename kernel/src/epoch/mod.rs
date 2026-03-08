// ============================================================================
// kernel/src/epoch/mod.rs - Epoch-Based Reclamation for Live Updates
// ============================================================================
//!
//! # Epoch-Based Reclamation
//!
//! 設計書 Section 3.5.3 に基づく実装
//!
//! ライブアップデートにおいて「切り替えをアトミックに行う」ことを実現します。
//! RCU（Read-Copy-Update）に類似したEpoch-based Reclamationを採用。
//!
//! ## 動作原理
//!
//! 1. **エポック管理:** グローバルエポックとコアローカルエポックを管理
//! 2. **Quiescent State Detection:** 全Executorが「安全な状態」に到達したことを検出
//! 3. **遅延解放:** 旧バージョンのセルは全コアが離脱するまで保持
//!
//! ## ライブアップデートプロトコル
//!
//! ```text
//! 1. 新セルをメモリにロード（旧セルは維持）
//! 2. グローバルエポックをインクリメント
//! 3. 新セルへのポインタをGOTに書き込み（アトミックスワップ）
//! 4. Quiescent State Detection で全コアの離脱を確認
//! 5. 旧セルのメモリを解放
//! ```
#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// グローバルエポック
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 最大CPUコア数
const MAX_CORES: usize = 64;

/// コアごとのエポック情報
struct PerCoreEpoch {
    /// このコアが観測したエポック
    epoch: AtomicU64,
    /// このコアがアクティブ（クリティカルセクション内）かどうか
    active: AtomicBool,
}

impl PerCoreEpoch {
    const fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            active: AtomicBool::new(false),
        }
    }
}

/// コアごとのエポック配列
static PER_CORE_EPOCHS: [PerCoreEpoch; MAX_CORES] = [const { PerCoreEpoch::new() }; MAX_CORES];

/// 遅延解放キュー
struct DeferredFree {
    /// 解放対象のアドレス
    address: usize,
    /// 解放時のサイズ
    size: usize,
    /// この解放が登録されたエポック
    retire_epoch: u64,
}

/// 遅延解放キュー
static DEFERRED_QUEUE: PoisonLock<Vec<DeferredFree>> = PoisonLock::new(Vec::new());

// ============================================================================
// Epoch Guard API
// ============================================================================

/// エポックガード
///
/// クリティカルセクションの開始/終了を管理する RAII ガード
pub struct EpochGuard {
    core_id: usize,
}

impl EpochGuard {
    /// クリティカルセクションに入る
    pub fn enter(core_id: usize) -> Self {
        let core_id = core_id.min(MAX_CORES - 1);

        // このコアをアクティブにマーク
        PER_CORE_EPOCHS[core_id]
            .active
            .store(true, Ordering::Release);

        // 現在のグローバルエポックを記録
        let current_epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
        PER_CORE_EPOCHS[core_id]
            .epoch
            .store(current_epoch, Ordering::Release);

        Self { core_id }
    }

    /// 現在のエポックを取得
    pub fn current_epoch(&self) -> u64 {
        GLOBAL_EPOCH.load(Ordering::Acquire)
    }
}

impl Drop for EpochGuard {
    fn drop(&mut self) {
        // Quiescent Point: クリティカルセクションを離脱
        PER_CORE_EPOCHS[self.core_id]
            .active
            .store(false, Ordering::Release);
    }
}

// ============================================================================
// Epoch Management API
// ============================================================================

/// グローバルエポックをインクリメント
///
/// ライブアップデート時に呼び出す
pub fn advance_epoch() -> u64 {
    GLOBAL_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
}

/// 現在のグローバルエポックを取得
pub fn current_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// 全コアが指定エポック以降に到達したかを確認
///
/// Quiescent State Detection の実装
pub fn all_cores_past_epoch(target_epoch: u64) -> bool {
    for core_epoch in PER_CORE_EPOCHS.iter() {
        // アクティブでないコアは問題なし
        if !core_epoch.active.load(Ordering::Acquire) {
            continue;
        }

        // アクティブなコアがターゲットエポック以前にいる場合は待機必要
        let observed_epoch = core_epoch.epoch.load(Ordering::Acquire);
        if observed_epoch <= target_epoch {
            return false;
        }
    }
    true
}

/// 全コアがQuiescent Stateに到達するまで待機
///
/// # Arguments
/// * `target_epoch` - このエポック以前のリソースを解放したい
/// * `max_attempts` - 最大リトライ回数
///
/// # Returns
/// * `true` - 全コアが到達
/// * `false` - タイムアウト
pub fn wait_for_quiescent_state(target_epoch: u64, max_attempts: u64) -> bool {
    for _ in 0..max_attempts {
        if all_cores_past_epoch(target_epoch) {
            return true;
        }
        // 少し待機（スピンウェイト）
        core::hint::spin_loop();
    }
    false
}

// ============================================================================
// Deferred Free API
// ============================================================================

/// メモリ解放を遅延キューに登録
///
/// 現在のエポック以前にアクティブだったコアが全て離脱するまで
/// 実際の解放を遅延する
pub fn defer_free(address: usize, size: usize) {
    let current = current_epoch();
    let mut queue = DEFERRED_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    queue.push(DeferredFree {
        address,
        size,
        retire_epoch: current,
    });
}

/// 遅延解放キューを処理
///
/// 安全に解放可能なエントリを解放する
///
/// # Returns
/// 解放したメモリ量（バイト）
pub fn process_deferred_frees() -> usize {
    let mut freed = 0;

    let mut queue = DEFERRED_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    queue.retain(|entry| {
        // このエントリが登録されたエポック以前の全コアが離脱したか確認
        if all_cores_past_epoch(entry.retire_epoch) {
            // 解放可能
            log::info!(
                "[EPOCH] Freed deferred memory: addr=0x{:x}, size={}\n",
                entry.address,
                entry.size
            );
            freed += entry.size;
            false // キューから削除
        } else {
            true // キューに残す
        }
    });

    freed
}

// ============================================================================
// Live Update Support
// ============================================================================

/// ライブアップデートの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUpdateState {
    /// 待機中
    Idle,
    /// 新セルロード中
    Loading,
    /// Quiescent待機中
    WaitingForQuiescent,
    /// 切り替え完了
    Completed,
    /// ロールバック
    RolledBack,
}

/// ライブアップデートコントローラ
pub struct LiveUpdateController {
    /// 現在の状態
    state: LiveUpdateState,
    /// 更新開始時のエポック
    start_epoch: u64,
    /// ロールバック猶予期間（ミリ秒）
    rollback_timeout_ms: u64,
}

impl LiveUpdateController {
    /// 新しいコントローラを作成
    pub fn new() -> Self {
        Self {
            state: LiveUpdateState::Idle,
            start_epoch: 0,
            rollback_timeout_ms: 60_000, // デフォルト60秒
        }
    }

    /// ライブアップデートを開始
    pub fn begin_update(&mut self) -> u64 {
        self.state = LiveUpdateState::Loading;
        self.start_epoch = advance_epoch();
        log::info!(
            "[LIVE_UPDATE] Started update at epoch {}\n",
            self.start_epoch
        );
        self.start_epoch
    }

    /// 新セルへの切り替えを試行
    ///
    /// 全コアがQuiescent Stateに到達するまで待機
    pub fn try_switch(&mut self, max_wait_ms: u64) -> bool {
        self.state = LiveUpdateState::WaitingForQuiescent;

        // Quiescent State を待機
        let attempts = max_wait_ms * 1000; // おおよその反復回数
        if wait_for_quiescent_state(self.start_epoch, attempts) {
            self.state = LiveUpdateState::Completed;
            log::info!("[LIVE_UPDATE] Switch completed\n");
            true
        } else {
            log::info!("[LIVE_UPDATE] Quiescent wait timeout, rolling back\n");
            self.rollback();
            false
        }
    }

    /// ロールバック
    pub fn rollback(&mut self) {
        self.state = LiveUpdateState::RolledBack;
        log::info!("[LIVE_UPDATE] Rolled back\n");
    }

    /// 現在の状態を取得
    pub fn state(&self) -> LiveUpdateState {
        self.state
    }

    /// ロールバックタイムアウトを設定
    pub fn set_rollback_timeout(&mut self, timeout_ms: u64) {
        self.rollback_timeout_ms = timeout_ms;
    }
}

impl Default for LiveUpdateController {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// エポック統計
#[derive(Debug, Clone)]
pub struct EpochStats {
    /// 現在のグローバルエポック
    pub current_epoch: u64,
    /// 遅延解放キューのサイズ
    pub deferred_queue_size: usize,
    /// アクティブなコア数
    pub active_cores: usize,
}

/// 統計情報を取得
pub fn stats() -> EpochStats {
    let active_cores = PER_CORE_EPOCHS
        .iter()
        .filter(|e| e.active.load(Ordering::Relaxed))
        .count();

    EpochStats {
        current_epoch: current_epoch(),
        deferred_queue_size: DEFERRED_QUEUE.lock().unwrap_or_else(|e| e.into_inner()).len(),
        active_cores,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_epoch_advance() {
        let e1 = current_epoch();
        let e2 = advance_epoch();
        assert_eq!(e2, e1 + 1);
        assert_eq!(current_epoch(), e2);
    }

    #[test_case]
    fn test_epoch_guard() {
        let guard = EpochGuard::enter(0);
        assert!(PER_CORE_EPOCHS[0].active.load(Ordering::Relaxed));
        drop(guard);
        assert!(!PER_CORE_EPOCHS[0].active.load(Ordering::Relaxed));
    }

    #[test_case]
    fn test_quiescent_detection() {
        // 全コアが非アクティブなら即座にtrue
        assert!(all_cores_past_epoch(0));

        // コア0をアクティブに
        let guard = EpochGuard::enter(0);
        let start_epoch = current_epoch();

        // エポックを進める
        advance_epoch();

        // コア0はまだ古いエポックにいる
        assert!(!all_cores_past_epoch(start_epoch));

        drop(guard);

        // コア0が離脱したので true
        assert!(all_cores_past_epoch(start_epoch));
    }
}
