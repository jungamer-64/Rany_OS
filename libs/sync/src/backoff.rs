// ============================================================================
// libs/sync/src/backoff.rs - Exponential Backoff
// ============================================================================
//!
//! 指数バックオフアルゴリズム

use core::sync::atomic::{spin_loop_hint, AtomicU32, Ordering};

/// 指数バックオフ
///
/// スピンロックの競合時に、徐々にスリープ時間を増やすことで
/// CPUリソースの無駄遣いを防ぎます。
pub struct Backoff {
    step: u32,
}

impl Backoff {
    /// 最大バックオフステップ数
    const MAX_STEP: u32 = 6;

    /// 新しいBackoffを作成
    #[inline]
    pub const fn new() -> Self {
        Self { step: 0 }
    }

    /// スピン待機を実行
    ///
    /// 呼び出すたびにスピン回数が指数関数的に増加します。
    #[inline]
    pub fn spin(&mut self) {
        let spins = 1 << self.step.min(Self::MAX_STEP);
        for _ in 0..spins {
            core::hint::spin_loop();
        }
        if self.step < Self::MAX_STEP {
            self.step += 1;
        }
    }

    /// バックオフ状態をリセット
    #[inline]
    pub fn reset(&mut self) {
        self.step = 0;
    }

    /// 現在のステップ数を取得
    #[inline]
    pub fn step(&self) -> u32 {
        self.step
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}
