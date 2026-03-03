// ============================================================================
// src/sync/lockfree/backoff.rs - 指数バックオフ戦略
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// ============================================================================

/// 指数バックオフのための定数
const BACKOFF_SPIN_LIMIT: u32 = 6;
const BACKOFF_YIELD_LIMIT: u32 = 10;

/// 指数バックオフ
///
/// スピンループでの競合を緩和するための戦略。
/// 最初は高速なスピン、次にCPUヒント、最後にyieldを使用。
#[derive(Debug)]
pub struct Backoff {
    step: u32,
}

impl Backoff {
    /// 新しいバックオフを作成
    #[inline]
    pub const fn new() -> Self {
        Self { step: 0 }
    }

    /// リセット
    #[inline]
    pub fn reset(&mut self) {
        self.step = 0;
    }

    /// スピンして待機
    ///
    /// 呼び出すたびにバックオフ時間が指数的に増加
    #[inline]
    pub fn spin(&mut self) {
        if self.step <= BACKOFF_SPIN_LIMIT {
            // 高速スピン: 2^step 回のspin_loop_hint
            for _ in 0..(1 << self.step) {
                core::hint::spin_loop();
            }
        } else if self.step <= BACKOFF_YIELD_LIMIT {
            // CPUヒントによる待機
            for _ in 0..(1 << BACKOFF_SPIN_LIMIT) {
                core::hint::spin_loop();
            }
            // yieldポイント（将来のスケジューラ統合用）
            #[cfg(all(feature = "std", not(target_os = "none")))]
            std::thread::yield_now();
        } else {
            // 最大バックオフに達した場合
            for _ in 0..(1 << BACKOFF_SPIN_LIMIT) {
                core::hint::spin_loop();
            }
        }

        // 境界値 (BACKOFF_YIELD_LIMIT) に達した場合も次回のspinで
        // 完了状態に移行するため、<= を使用して1つ上げる
        if self.step <= BACKOFF_YIELD_LIMIT {
            self.step += 1;
        }
    }

    /// 軽量なスナップ（短いスピンのみ）
    #[inline]
    pub fn snooze(&mut self) {
        if self.step <= BACKOFF_SPIN_LIMIT {
            for _ in 0..(1 << self.step) {
                core::hint::spin_loop();
            }
            self.step += 1;
        } else {
            core::hint::spin_loop();
        }
    }

    /// 完了したか（最大バックオフに達したか）
    #[inline]
    pub fn is_completed(&self) -> bool {
        self.step > BACKOFF_YIELD_LIMIT
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}
