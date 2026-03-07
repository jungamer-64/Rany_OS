// ============================================================================
// src/task/timer.rs - Timer Delegation Layer
// ============================================================================
//!
//! # Timer Delegation Layer
//!
//! 後方互換のための薄い委譲レイヤー。
//! 実装は `time_driver` クレート（ドライバ/セル）に移動済み。
//!
//! ## ExoRust アーキテクチャ
//!
//! - **Framework (kernel)**: PIT/TSC/APIC ハードウェア制御
//! - **Cell (time_driver)**: スリープ管理、タイマー登録、CPU時間統計
//!
//! 既存の呼び出し元はこのモジュール経由で引き続き動作する。
// ============================================================================

/// タイマー割り込みハンドラから呼ばれる
///
/// 【設計書 4.2】2段階Wake方式:
/// ISRコンテキストでは直接wake()を呼ばず、ロックフリーキューに追加
#[inline]
pub fn handle_timer_interrupt() {
    crate::drivers::time::handle_timer_interrupt();
}

/// 保留中のタイマーWakerを処理（Executorから呼び出す）
///
/// 【設計書 4.2】2段階Wake方式: 非ISRコンテキストで呼び出す
#[inline]
pub fn process_pending_timer_wakers() {
    crate::drivers::time::process_pending_timer_wakers();
}

/// 保留中のタイマーWaker数を取得（おおよそ）
#[inline]
pub fn pending_timer_waker_count() -> usize {
    crate::drivers::time::pending_timer_waker_count()
}

/// ペンディングキューの統計を取得 (enqueued, dropped)
#[inline]
pub fn pending_waker_stats() -> (usize, usize) {
    crate::drivers::time::pending_waker_stats()
}

/// 現在のティック数を取得
#[inline]
pub fn current_tick() -> u64 {
    crate::drivers::time::current_tick()
}

/// 指定ミリ秒スリープする非同期関数
#[inline]
pub async fn sleep_ms(duration_ms: u64) {
    crate::drivers::time::sleep_ms(duration_ms).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_delegation_current_tick() {
        // ティックはtime_driver::TIME_MANAGERのアトミック値を参照
        let _tick = current_tick();
    }

    #[test_case]
    fn test_delegation_pending_stats() {
        let (enq, drop) = pending_waker_stats();
        // 初期状態ではどちらも0または低い値
        let _ = (enq, drop);
    }
}
