// ============================================================================
// kernel/src/net/l4/tcp/timer_wheel.rs - Hashed Timing Wheel (ハッシュドタイミングホイール)
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

use crate::net::l4::types::EndpointAddr;
use alloc::vec::Vec;

/// ホイールのスロット数（2のべき乗）
///
/// 256スロット × 100tick/チェック間隔 = 25600tick ≒ 25.6秒の範囲をカバー。
/// RTOの最大値（60秒）を超えるタイマーは最も遠いスロットに配置される。
const WHEEL_SLOTS: usize = 256;
const WHEEL_MASK: usize = WHEEL_SLOTS - 1;

/// タイマーエントリ
#[derive(Debug)]
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
}
