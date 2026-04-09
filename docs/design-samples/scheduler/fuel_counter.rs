//! 燃料ベース実行（Fuel-based Execution）
//!
//! 設計書セクション 4.4.1 参照

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// タスクごとの燃料カウンタ
pub struct FuelCounter {
    /// 残り燃料
    remaining: AtomicU64,
    /// 1回のスケジューリングで補充される燃料量
    refill_amount: u64,
}

/// 燃料切れエラー
pub struct FuelExhausted;

impl FuelCounter {
    pub const fn new(refill_amount: u64) -> Self {
        Self {
            remaining: AtomicU64::new(refill_amount),
            refill_amount,
        }
    }

    /// 燃料を消費（ループ反復、関数呼び出しで呼ばれる）
    pub fn consume(&self, amount: u64) -> Result<(), FuelExhausted> {
        let prev = self.remaining.fetch_sub(amount, Relaxed);
        if prev < amount {
            // 燃料切れ：強制yield
            self.remaining.store(0, Relaxed);
            Err(FuelExhausted)
        } else {
            Ok(())
        }
    }

    /// 次のスケジューリング時に燃料を補充
    pub fn refill(&self) {
        self.remaining.store(self.refill_amount, Relaxed);
    }

    /// 残り燃料を取得
    pub fn remaining(&self) -> u64 {
        self.remaining.load(Relaxed)
    }
}

// 燃料消費ポイント（コンパイラが自動挿入）:
// - ループのバックエッジ（各反復で消費）
// - 関数呼び出し（呼び出し深度に応じて消費）
// - 長時間計算が予想される操作

// 燃料クォータの設定:
// - デフォルト: 10,000単位/スケジュール
// - リアルタイムタスク: 無制限（手動設定）
// - 低優先度タスク: 1,000単位/スケジュール

pub const DEFAULT_FUEL: u64 = 10_000;
pub const REALTIME_FUEL: u64 = u64::MAX;
pub const LOW_PRIORITY_FUEL: u64 = 1_000;
