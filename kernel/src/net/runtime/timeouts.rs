// ============================================================================
// kernel/src/net/runtime/timeouts.rs - Network Stack Timeout Helpers
// ============================================================================
//! # Network Stack Timeout Helpers
//!
//! タイムアウト駆動のネットワーク処理を管理するユーティリティ群。
//!
//! ## 主要コンポーネント
//! - `TimeoutWheel`: 階層型タイマーホイール (O(1)挿入/O(1)期限切れポーリング)
//! - `RetransmitTimer`: RFC 6298準拠のTCP再送タイマー
//! - `KeepaliveTimer`: TCPキープアライブタイマー
//! - `TimeWaitTimer`: TIME_WAIT (2MSL) タイマー

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

// ============================================================================
// Timer Wheel
// ============================================================================

/// タイマーホイールのスロット数 (2のべき乗)
const WHEEL_SLOTS: usize = 256;
const WHEEL_MASK: usize = WHEEL_SLOTS - 1;

/// タイマーイベントID
pub type TimerId = u64;

/// タイマーイベント情報
#[derive(Debug)]
pub struct TimerEntry {
    /// ユニークID
    pub id: TimerId,
    /// 期限切れ時刻 (ms)
    pub deadline: u64,
    /// タイマー種別
    pub kind: TimerKind,
}

/// タイマー種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    /// TCP再送タイムアウト
    TcpRetransmit,
    /// TCPキープアライブ
    TcpKeepalive,
    /// TCP TIME_WAIT (2MSL)
    TcpTimeWait,
    /// NDP Neighbor Solicitation再送
    NdpRetransmit,
    /// NDP解決待ちパケットの期限切れ
    NdpPendingExpire,
    /// ARPエントリの期限切れ
    ArpExpire,
    /// IGMPレポートタイマー
    IgmpReport,
    /// 汎用タイマー
    Generic,
}

/// 簡易タイマーホイール
///
/// O(1)でタイマーを挿入し、O(slot_size)で期限切れをポーリングする。
/// ネットワークスタックの定期的なタイムアウト処理に使用。
pub struct TimeoutWheel {
    /// スロット配列 (各スロットはTimerEntryのリスト)
    slots: [Vec<TimerEntry>; WHEEL_SLOTS],
    /// 現在のスロットインデックス
    current_slot: usize,
    /// 最後にtickした時刻
    last_tick: u64,
    /// 1スロットあたりの時間間隔 (ms)
    resolution_ms: u64,
    /// 次のタイマーID
    next_id: AtomicU64,
}

impl TimeoutWheel {
    /// 新しいタイマーホイールを作成
    ///
    /// `resolution_ms`: 1スロットあたりの時間間隔 (推奨: 10-100ms)
    pub fn new(resolution_ms: u64) -> Self {
        const EMPTY_VEC: Vec<TimerEntry> = Vec::new();
        Self {
            slots: [EMPTY_VEC; WHEEL_SLOTS],
            current_slot: 0,
            last_tick: 0,
            resolution_ms: if resolution_ms == 0 {
                10
            } else {
                resolution_ms
            },
            next_id: AtomicU64::new(1),
        }
    }

    /// タイマーを追加
    ///
    /// `delay_ms`: 現在からの遅延時間 (ms)
    /// `kind`: タイマー種別
    /// 戻り値: タイマーID (キャンセル用)
    pub fn schedule(&mut self, delay_ms: u64, kind: TimerKind, current_time: u64) -> TimerId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let deadline = current_time + delay_ms;
        let ticks_ahead = delay_ms / self.resolution_ms;
        let slot = (self.current_slot + ticks_ahead as usize) & WHEEL_MASK;

        self.slots[slot].push(TimerEntry { id, deadline, kind });

        id
    }

    /// タイマーをキャンセル
    pub fn cancel(&mut self, id: TimerId) -> bool {
        for slot in self.slots.iter_mut() {
            if let Some(pos) = slot.iter().position(|e| e.id == id) {
                slot.swap_remove(pos);
                return true;
            }
        }
        false
    }

    /// 時計を進めて期限切れタイマーを収集
    ///
    /// `current_time`: 現在時刻 (ms)
    /// 戻り値: 期限切れとなったタイマーエントリのリスト
    pub fn tick(&mut self, current_time: u64) -> Vec<TimerEntry> {
        let mut expired = Vec::new();

        // 前回tickからの経過スロット数を計算
        let elapsed_ms = current_time.saturating_sub(self.last_tick);
        let slots_to_advance = (elapsed_ms / self.resolution_ms) as usize;

        if slots_to_advance == 0 {
            return expired;
        }

        let slots_to_check = slots_to_advance.min(WHEEL_SLOTS);

        for _ in 0..slots_to_check {
            self.current_slot = (self.current_slot + 1) & WHEEL_MASK;

            let slot = &mut self.slots[self.current_slot];
            let mut remaining = Vec::new();

            for entry in slot.drain(..) {
                if entry.deadline <= current_time {
                    expired.push(entry);
                } else {
                    remaining.push(entry);
                }
            }

            *slot = remaining;
        }

        self.last_tick = current_time;
        expired
    }

    /// 登録されたタイマー数
    pub fn count(&self) -> usize {
        self.slots.iter().map(|s| s.len()).sum()
    }
}

// ============================================================================
// TCP Retransmit Timer (RFC 6298)
// ============================================================================

/// RFC 6298準拠RTO (Retransmission Timeout) 計算器
///
/// SRTT (Smoothed Round-Trip Time) と RTTVAR (RTT Variance) から
/// RTO = SRTT + max(G, K * RTTVAR) を計算。
#[derive(Debug)]
pub struct RetransmitTimer {
    /// SRTT in microseconds
    srtt: u64,
    /// RTTVAR in microseconds
    rttvar: u64,
    /// Current RTO in milliseconds
    rto_ms: u64,
    /// Minimum RTO (ms) — RFC 6298: 1秒を推奨
    min_rto_ms: u64,
    /// Maximum RTO (ms) — 通常60秒
    max_rto_ms: u64,
    /// Clock granularity (ms)
    granularity_ms: u64,
    /// RTTサンプルを受信済みか
    has_measurement: bool,
    /// 指数バックオフ回数
    backoff_count: u32,
}

impl RetransmitTimer {
    /// デフォルト: min 200ms, max 60s, granularity 10ms
    pub fn new() -> Self {
        Self {
            srtt: 0,
            rttvar: 0,
            rto_ms: 1000, // Initial RTO: 1秒 (RFC 6298)
            min_rto_ms: 200,
            max_rto_ms: 60_000,
            granularity_ms: 10,
            has_measurement: false,
            backoff_count: 0,
        }
    }

    /// カスタムパラメータで作成
    pub fn with_params(min_rto_ms: u64, max_rto_ms: u64, granularity_ms: u64) -> Self {
        Self {
            min_rto_ms,
            max_rto_ms,
            granularity_ms,
            ..Self::new()
        }
    }

    /// RTTサンプルから RTO を更新 (RFC 6298 Section 2)
    pub fn update_rtt(&mut self, rtt_us: u64) {
        if !self.has_measurement {
            // 最初の測定: SRTT = R, RTTVAR = R/2
            self.srtt = rtt_us;
            self.rttvar = rtt_us / 2;
            self.has_measurement = true;
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
            //   beta = 1/4
            let diff = if self.srtt > rtt_us {
                self.srtt - rtt_us
            } else {
                rtt_us - self.srtt
            };
            self.rttvar = (3 * self.rttvar + diff) / 4;

            // SRTT = (1 - alpha) * SRTT + alpha * R
            //   alpha = 1/8
            self.srtt = (7 * self.srtt + rtt_us) / 8;
        }

        // RTO = SRTT + max(G, K * RTTVAR), K = 4
        let rtt_var_term = (4 * self.rttvar) / 1000; // convert to ms
        let g = self.granularity_ms;
        let rto = (self.srtt / 1000) + rtt_var_term.max(g);

        self.rto_ms = rto.clamp(self.min_rto_ms, self.max_rto_ms);
        self.backoff_count = 0;
    }

    /// タイムアウト発生 — 指数バックオフ
    pub fn backoff(&mut self) {
        self.backoff_count += 1;
        self.rto_ms = (self.rto_ms * 2).min(self.max_rto_ms);
    }

    /// 現在のRTO (ms)
    #[inline]
    pub fn rto(&self) -> u64 {
        self.rto_ms
    }

    /// SRTT (us)
    #[inline]
    pub fn srtt_us(&self) -> u64 {
        self.srtt
    }

    /// バックオフ回数
    #[inline]
    pub fn backoff_count(&self) -> u32 {
        self.backoff_count
    }

    /// リセット
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for RetransmitTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Keepalive Timer
// ============================================================================

/// TCPキープアライブタイマー
///
/// RFC 1122: アイドル接続を検出して自動切断。
#[derive(Debug)]
pub struct KeepaliveTimer {
    /// アイドルしきい値 (ms) — デフォルト 7200秒 (2時間)
    pub idle_timeout_ms: u64,
    /// プローブ間隔 (ms) — デフォルト 75秒
    pub probe_interval_ms: u64,
    /// 最大プローブ回数
    pub max_probes: u32,
    /// 最後のデータ受信時刻
    last_data_time: u64,
    /// 送信済みプローブ数
    probes_sent: u32,
    /// 有効か
    enabled: bool,
}

impl KeepaliveTimer {
    pub fn new() -> Self {
        Self {
            idle_timeout_ms: 7_200_000, // 2 hours
            probe_interval_ms: 75_000,  // 75 seconds
            max_probes: 9,
            last_data_time: 0,
            probes_sent: 0,
            enabled: false,
        }
    }

    /// キープアライブを有効化
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// データ受信時に呼び出し — タイマーをリセット
    pub fn on_data_received(&mut self, current_time: u64) {
        self.last_data_time = current_time;
        self.probes_sent = 0;
    }

    /// プローブが必要か判定
    pub fn should_probe(&self, current_time: u64) -> bool {
        if !self.enabled {
            return false;
        }

        let idle_time = current_time.saturating_sub(self.last_data_time);

        if self.probes_sent == 0 {
            // 最初のプローブ: idleしきい値を超えたら
            idle_time >= self.idle_timeout_ms
        } else {
            // 後続のプローブ: probe_interval 経過ごと
            idle_time >= self.idle_timeout_ms + (self.probes_sent as u64) * self.probe_interval_ms
        }
    }

    /// プローブ送信を記録
    pub fn on_probe_sent(&mut self) {
        self.probes_sent += 1;
    }

    /// 接続を切断すべきか (最大プローブ数超過)
    pub fn should_abort(&self) -> bool {
        self.enabled && self.probes_sent >= self.max_probes
    }

    /// 送信済みプローブ数
    #[inline]
    pub fn probes_sent(&self) -> u32 {
        self.probes_sent
    }
}

impl Default for KeepaliveTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TIME_WAIT Timer
// ============================================================================

/// MSL (Maximum Segment Lifetime)
const MSL_MS: u64 = 120_000; // 120秒 (RFC 793)

/// TIME_WAIT (2MSL) タイマー
///
/// TCP接続のFIN-ACK完了後、遅延パケットの安全な破棄を保証する。
#[derive(Debug)]
pub struct TimeWaitTimer {
    /// TIME_WAIT開始時刻
    start_time: u64,
    /// 2MSL期間 (ms)
    duration_ms: u64,
}

impl TimeWaitTimer {
    /// TIME_WAIT開始
    pub fn start(current_time: u64) -> Self {
        Self {
            start_time: current_time,
            duration_ms: 2 * MSL_MS,
        }
    }

    /// カスタムMSLで開始
    pub fn start_with_msl(current_time: u64, msl_ms: u64) -> Self {
        Self {
            start_time: current_time,
            duration_ms: 2 * msl_ms,
        }
    }

    /// 期限切れか
    #[inline]
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.start_time) >= self.duration_ms
    }

    /// 残り時間 (ms)
    pub fn remaining_ms(&self, current_time: u64) -> u64 {
        let elapsed = current_time.saturating_sub(self.start_time);
        self.duration_ms.saturating_sub(elapsed)
    }
}

// ============================================================================
// Tests
// ============================================================================

// Export the test helpers when building QEMU full-boot runtime tests so wrapper functions can
// call them from `kernel/src/net/qemu_tests.rs`.  Other modules already use the
// `qemu-test-export` feature flag.
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_timeout_wheel_basic() {
        let mut wheel = TimeoutWheel::new(10);
        let id = wheel.schedule(100, TimerKind::TcpRetransmit, 0);
        assert!(id > 0);
        assert_eq!(wheel.count(), 1);

        // Advance past deadline
        let expired = wheel.tick(110);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].kind, TimerKind::TcpRetransmit);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_timeout_wheel_cancel() {
        let mut wheel = TimeoutWheel::new(10);
        let id = wheel.schedule(100, TimerKind::NdpRetransmit, 0);
        assert!(wheel.cancel(id));
        assert_eq!(wheel.count(), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_timer_initial() {
        let timer = RetransmitTimer::new();
        assert_eq!(timer.rto(), 1000); // 1秒
    }

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_timer_update() {
        let mut timer = RetransmitTimer::new();
        // First measurement: 100ms RTT
        timer.update_rtt(100_000); // 100ms in us
        assert!(timer.rto() >= 200); // min_rto
        assert!(timer.rto() <= 60_000); // max_rto
    }

    #[cfg_attr(test, test_case)]
    pub fn test_retransmit_timer_backoff() {
        let mut timer = RetransmitTimer::new();
        assert_eq!(timer.rto(), 1000);
        timer.backoff();
        assert_eq!(timer.rto(), 2000);
        timer.backoff();
        assert_eq!(timer.rto(), 4000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_keepalive_timer() {
        let mut ka = KeepaliveTimer::new();
        ka.enable();
        ka.on_data_received(0);

        // Not yet idle
        assert!(!ka.should_probe(1000));

        // After 2 hours idle
        assert!(ka.should_probe(7_200_001));

        ka.on_probe_sent();
        assert!(!ka.should_abort());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_time_wait_timer() {
        let tw = TimeWaitTimer::start(1000);
        assert!(!tw.is_expired(1000));
        assert!(!tw.is_expired(60_000));
        // After 2 MSL (120 seconds)
        assert!(tw.is_expired(121_001));
    }
}
