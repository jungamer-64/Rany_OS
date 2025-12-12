//! リクエスト追跡
//!
//! 設計書セクション 3.5.3 参照

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering::{Acquire, Release}};

/// ドメインへのアクティブリクエスト数を追跡
pub struct RequestTracker {
    /// アクティブなリクエスト数
    active_count: AtomicU64,
    /// ドレイン（排出）シグナル
    drain_signal: AtomicBool,
}

impl RequestTracker {
    pub const fn new() -> Self {
        Self {
            active_count: AtomicU64::new(0),
            drain_signal: AtomicBool::new(false),
        }
    }

    /// リクエストの開始を記録
    pub fn begin_request(&self) -> bool {
        if self.drain_signal.load(Acquire) {
            return false; // ドレイン中は新規リクエストを拒否
        }
        self.active_count.fetch_add(1, Acquire);
        true
    }

    /// リクエストの終了を記録
    pub fn end_request(&self) {
        self.active_count.fetch_sub(1, Release);
    }

    /// 全リクエストの完了を待機
    pub fn wait_for_drain(&self) {
        self.drain_signal.store(true, Release);
        while self.active_count.load(Acquire) > 0 {
            core::hint::spin_loop();
        }
    }
}

// 順序保証:
// - GOT更新前に到着したリクエスト → 旧セルで完了
// - GOT更新後に到着したリクエスト → 新セルで処理
// - 同一リクエストが両方で処理されることは原理的に不可能
