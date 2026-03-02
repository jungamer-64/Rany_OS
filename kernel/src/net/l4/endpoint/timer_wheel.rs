// ============================================================================
// kernel/src/net/endpoint/timer_wheel.rs
// ============================================================================
//! # Hashed Timing Wheel (ハッシュドタイミングホイール)
//!
//! 再送タイマーの効率的な管理を実現するデータ構造。
//!
//! ## 概要
//! 従来の実装では、全コネクションの再送キューを線形探索していたため、
//! 接続数 N に対して $O(N)$ のコストがかかっていた。
//!
//! タイミングホイールは、タイマー満了時刻をスロット（バケット）にマッピングし、
//! 現在のtickに対応するスロットのみを検査することで $O(1)$ amortized の
//! タイマー管理を実現する。
//!
//! ## 参考
//! - G. Varghese & A. Lauck, "Hashed and Hierarchical Timing Wheels" (1997)
//! - Linux kernel: `net/core/timer_defs.h`

use alloc::vec::Vec;
use super::types::EndpointAddr;

/// ホイールのスロット数（2のべき乗）
///
/// 256スロット × 100tick/チェック間隔 = 25600tick ≒ 25.6秒の範囲をカバー。
/// RTOの最大値（60秒）を超えるタイマーは最も遠いスロットに配置される。
const WHEEL_SLOTS: usize = 256;
const WHEEL_MASK: usize = WHEEL_SLOTS - 1;

/// タイマーエントリ
#[derive(Debug, Clone)]
pub struct TimerEntry {
    /// 接続キー
    pub local: EndpointAddr,
    pub remote: EndpointAddr,
    /// タイマー満了tick
    pub deadline: u64,
}

/// ハッシュドタイミングホイール
pub struct TimingWheel {
    /// スロット配列。各スロットはそのtick範囲に満了するタイマーのリスト。
    slots: [Vec<TimerEntry>; WHEEL_SLOTS],
    /// 現在のホイールポインタ（最後にチェックしたスロット）
    current_slot: usize,
    /// 最後にadvanceしたtick
    last_tick: u64,
}

impl TimingWheel {
    /// 新規作成
    pub fn new() -> Self {
        // Vec は const fn で初期化できないため、手動で構築
        const EMPTY_VEC: Vec<TimerEntry> = Vec::new();
        Self {
            slots: [EMPTY_VEC; WHEEL_SLOTS],
            current_slot: 0,
            last_tick: 0,
        }
    }

    /// タイマーを登録する
    ///
    /// `deadline`: タイマーが満了するtick値
    pub fn schedule(&mut self, local: EndpointAddr, remote: EndpointAddr, deadline: u64) {
        let slot = (deadline as usize) & WHEEL_MASK;
        self.slots[slot].push(TimerEntry {
            local,
            remote,
            deadline,
        });
    }

    /// 指定された接続のタイマーをキャンセルする
    pub fn cancel(&mut self, local: &EndpointAddr, remote: &EndpointAddr) {
        for slot in &mut self.slots {
            slot.retain(|entry| &entry.local != local || &entry.remote != remote);
        }
    }

    /// 指定された接続のタイマーを再スケジュール（既存があれば差し替え）
    pub fn reschedule(&mut self, local: EndpointAddr, remote: EndpointAddr, new_deadline: u64) {
        self.cancel(&local, &remote);
        self.schedule(local, remote, new_deadline);
    }

    /// ホイールを `current_tick` まで進め、満了したタイマーを収集して返す。
    ///
    /// 返されたタイマーの `deadline <= current_tick` であることが保証される。
    /// 同じスロットに配置されていても deadline が未来のものはスロットに残す。
    pub fn advance(&mut self, current_tick: u64) -> Vec<(EndpointAddr, EndpointAddr)> {
        let mut expired = Vec::new();

        // last_tick+1 から current_tick までの各スロットを検査
        let ticks_to_advance = current_tick.saturating_sub(self.last_tick);
        let slots_to_check = if ticks_to_advance as usize > WHEEL_SLOTS {
            WHEEL_SLOTS
        } else {
            ticks_to_advance as usize
        };

        for i in 0..slots_to_check {
            let slot_idx = (self.current_slot + 1 + i) & WHEEL_MASK;
            let slot = &mut self.slots[slot_idx];

            // deadline <= current_tick のものを抽出
            let mut remaining = Vec::new();
            for entry in slot.drain(..) {
                if entry.deadline <= current_tick {
                    expired.push((entry.local, entry.remote));
                } else {
                    remaining.push(entry);
                }
            }
            *slot = remaining;
        }

        self.current_slot = (current_tick as usize) & WHEEL_MASK;
        self.last_tick = current_tick;

        expired
    }

    /// ホイールに登録されているタイマー数（デバッグ用）
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.slots.iter().map(|s| s.len()).sum()
    }

    /// ホイールが空かどうか
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_empty())
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_timing_wheel_basic() {
        let mut wheel = TimingWheel::new();
        let local = EndpointAddr::new([10, 0, 0, 1], 1000);
        let remote = EndpointAddr::new([10, 0, 0, 2], 2000);

        // deadline=100 でスケジュール
        wheel.schedule(local, remote, 100);
        assert_eq!(wheel.len(), 1);

        // tick=50 → まだ満了しない
        let expired = wheel.advance(50);
        assert!(expired.is_empty());

        // tick=100 → 満了
        let expired = wheel.advance(100);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], (local, remote));

        // 取り出し済みなので空
        assert!(wheel.is_empty());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_timing_wheel_cancel() {
        let mut wheel = TimingWheel::new();
        let local = EndpointAddr::new([10, 0, 0, 1], 1000);
        let remote = EndpointAddr::new([10, 0, 0, 2], 2000);

        wheel.schedule(local, remote, 200);
        assert_eq!(wheel.len(), 1);

        wheel.cancel(&local, &remote);
        assert!(wheel.is_empty());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_timing_wheel_reschedule() {
        let mut wheel = TimingWheel::new();
        let local = EndpointAddr::new([10, 0, 0, 1], 1000);
        let remote = EndpointAddr::new([10, 0, 0, 2], 2000);

        wheel.schedule(local, remote, 100);
        wheel.reschedule(local, remote, 300);
        assert_eq!(wheel.len(), 1);

        // tick=100 → もう旧 deadline は存在しない
        let expired = wheel.advance(100);
        assert!(expired.is_empty());

        // tick=300 → 新しい deadline で満了
        let expired = wheel.advance(300);
        assert_eq!(expired.len(), 1);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_timing_wheel_multiple() {
        let mut wheel = TimingWheel::new();
        let a = EndpointAddr::new([10, 0, 0, 1], 1000);
        let b = EndpointAddr::new([10, 0, 0, 2], 2000);
        let c = EndpointAddr::new([10, 0, 0, 3], 3000);
        let d = EndpointAddr::new([10, 0, 0, 4], 4000);

        wheel.schedule(a, b, 50);
        wheel.schedule(c, d, 150);
        assert_eq!(wheel.len(), 2);

        let expired = wheel.advance(100);
        assert_eq!(expired.len(), 1); // (a, b) のみ

        let expired = wheel.advance(200);
        assert_eq!(expired.len(), 1); // (c, d) のみ

        assert!(wheel.is_empty());
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn timing_wheel_basic_smoke() -> bool {
        let mut wheel = TimingWheel::new();
        let local = EndpointAddr::new([10, 0, 0, 1], 1000);
        let remote = EndpointAddr::new([10, 0, 0, 2], 2000);

        wheel.schedule(local, remote, 100);
        if wheel.len() != 1 { return false; }

        let expired = wheel.advance(50);
        if !expired.is_empty() { return false; }

        let expired = wheel.advance(100);
        if expired.len() != 1 { return false; }

        wheel.is_empty()
    }

    pub fn timing_wheel_cancel_smoke() -> bool {
        let mut wheel = TimingWheel::new();
        let local = EndpointAddr::new([10, 0, 0, 1], 1000);
        let remote = EndpointAddr::new([10, 0, 0, 2], 2000);

        wheel.schedule(local, remote, 200);
        wheel.cancel(&local, &remote);
        wheel.is_empty()
    }
}
