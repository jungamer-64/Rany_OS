// ============================================================================
// kernel/src/net/l4/tcp/congestion/mod.rs - TCP Congestion Control - 輻輳制御
// ============================================================================

// 輻輳制御の内部統計フィールドはデバッグ及びチューニング用に保持。
//! # TCP Congestion Control - 輻輳制御
//!
//! RFC 5681 (TCP Congestion Control) 準拠実装
//! - Slow Start
//! - Congestion Avoidance  
//! - Fast Retransmit / Fast Recovery (NewReno)

use core::cmp::{max, min};
pub const DEFAULT_MSS: u32 = 536;

/// 初期ウィンドウサイズ (RFC 6928: 10 MSS)
pub const INITIAL_WINDOW: u32 = 10;

/// 最小輻輳ウィンドウ
pub const MIN_CWND: u32 = 2;

/// 輻輳制御状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// スロースタート
    SlowStart,
    /// 輻輳回避
    CongestionAvoidance,
    /// 高速回復
    FastRecovery,
}

impl Default for CongestionState {
    fn default() -> Self {
        CongestionState::SlowStart
    }
}

/// 輻輳制御コントローラ (NewReno)
#[derive(Debug)]
pub struct CongestionController {
    /// 現在の状態
    state: CongestionState,
    /// 輻輳ウィンドウ (cwnd) - バイト単位
    cwnd: u32,
    /// スロースタート閾値 (ssthresh) - バイト単位
    ssthresh: u32,
    /// Maximum Segment Size
    mss: u32,
    /// 重複ACKカウンタ (Fast Retransmit用)
    dup_ack_count: u8,
    /// 回復ポイント (Fast Recovery用)
    recover: u32,
    /// Congestion Avoidance用のバイトカウンタ
    bytes_acked: u32,
    /// 送信中 (in-flight) のバイト数
    bytes_in_flight: u32,
}

impl CongestionController {
    /// 新規作成
    pub fn new() -> Self {
        let mss = DEFAULT_MSS;
        Self {
            state: CongestionState::SlowStart,
            cwnd: INITIAL_WINDOW * mss,
            ssthresh: u32::MAX, // 初期値は無限大（最初のロスまで）
            mss,
            dup_ack_count: 0,
            recover: 0,
            bytes_acked: 0,
            bytes_in_flight: 0,
        }
    }

    /// MSS更新時の処理 (RFC 6928: 初期ウィンドウを新MSSに合わせる)
    pub fn update_mss(&mut self, new_mss: u32) {
        let old_mss = self.mss;
        self.mss = new_mss;

        // 接続開始直後（まだデータ送信前）であれば、初期ウィンドウを再計算
        if self.state == CongestionState::SlowStart && self.cwnd == INITIAL_WINDOW * old_mss {
            self.cwnd = INITIAL_WINDOW * new_mss;
        }
    }

    /// 送信可能なバイト数を計算
    /// effective_window = min(cwnd, rwnd) - bytes_in_flight
    pub fn available_window(&self, rwnd: u32) -> u32 {
        let effective = min(self.cwnd, rwnd);
        effective.saturating_sub(self.bytes_in_flight)
    }

    /// データ送信を記録
    pub fn on_send(&mut self, bytes: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// ACK受信時の処理 (RFC 5681 Section 3.1)
    ///
    /// - bytes_acked: 今回ACKされたバイト数（新規ACK）
    /// - is_dup_ack: 重複ACKかどうか
    /// - snd_una: 未確認の最古シーケンス番号
    pub fn on_ack(&mut self, bytes_acked: u32, is_dup_ack: bool, snd_una: u32) {
        // in-flight更新
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if is_dup_ack {
            self.on_dup_ack(snd_una);
            return;
        }

        // 新規ACK - 重複カウンタリセット
        self.dup_ack_count = 0;

        match self.state {
            CongestionState::SlowStart => {
                // Slow Start: cwnd += min(N, SMSS) for each ACK
                // 簡略化: cwnd += bytes_acked (1 MSS per ACK in practice)
                self.cwnd = self.cwnd.saturating_add(min(bytes_acked, self.mss));

                // ssthreshに達したらCongestion Avoidanceへ
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                    self.bytes_acked = 0;
                }
            }
            CongestionState::CongestionAvoidance => {
                // Congestion Avoidance: cwnd += SMSS * SMSS / cwnd for each ACK
                // RFC 5681の推奨: cwnd += SMSS per RTT (approximately)
                self.bytes_acked = self.bytes_acked.saturating_add(bytes_acked);

                // cwnd分のバイトがACKされたら1 MSS増加
                if self.bytes_acked >= self.cwnd {
                    self.cwnd = self.cwnd.saturating_add(self.mss);
                    self.bytes_acked = 0;
                }
            }
            CongestionState::FastRecovery => {
                // Fast Recovery: 新規ACKで回復完了
                if snd_una > self.recover {
                    // 回復完了 - Congestion Avoidanceへ
                    self.cwnd = self.ssthresh;
                    self.state = CongestionState::CongestionAvoidance;
                    self.bytes_acked = 0;
                } else {
                    // 部分ACK - cwndをデフレート
                    self.cwnd = self.cwnd.saturating_sub(bytes_acked);
                    self.cwnd = self.cwnd.saturating_add(self.mss);
                }
            }
        }
    }

    /// 重複ACK処理 (Fast Retransmit / Fast Recovery)
    fn on_dup_ack(&mut self, snd_una: u32) {
        self.dup_ack_count = self.dup_ack_count.saturating_add(1);

        match self.state {
            CongestionState::SlowStart | CongestionState::CongestionAvoidance => {
                if self.dup_ack_count >= 3 {
                    // 3重複ACK - Fast Retransmitトリガー
                    self.enter_fast_recovery(snd_una);
                }
            }
            CongestionState::FastRecovery => {
                // 追加の重複ACK - cwndをインフレート
                self.cwnd = self.cwnd.saturating_add(self.mss);
            }
        }
    }

    /// Fast Recovery開始
    fn enter_fast_recovery(&mut self, snd_una: u32) {
        // ssthresh = max(FlightSize / 2, 2*SMSS)
        let flight_size = self.bytes_in_flight;
        self.ssthresh = max(flight_size / 2, MIN_CWND * self.mss);

        // cwnd = ssthresh + 3*SMSS (既受信の3重複ACK分)
        self.cwnd = self.ssthresh + 3 * self.mss;

        // 回復ポイント設定
        self.recover = snd_una;

        self.state = CongestionState::FastRecovery;
    }

    /// タイムアウト時の処理 (RFC 5681 Section 3.1)
    pub fn on_timeout(&mut self) {
        // ssthresh = max(FlightSize / 2, 2*SMSS)
        let flight_size = self.bytes_in_flight;
        self.ssthresh = max(flight_size / 2, MIN_CWND * self.mss);

        // cwnd = 1 MSS (または loss window)
        self.cwnd = self.mss;

        // Slow Startに戻る
        self.state = CongestionState::SlowStart;
        self.dup_ack_count = 0;
        self.bytes_acked = 0;
    }
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct TcpCongestionController {
    controller: CongestionController,
}

impl TcpCongestionController {
    pub fn new() -> Self {
        Self {
            controller: CongestionController::new(),
        }
    }

    pub fn update_mss(&mut self, mss: u32) {
        self.controller.update_mss(mss);
    }

    pub fn available_window(&self, rwnd: u32) -> u32 {
        self.controller.available_window(rwnd)
    }

    pub fn on_send(&mut self, bytes: u32, _current_time_ms: u64) {
        self.controller.on_send(bytes);
    }

    pub fn on_ack(
        &mut self,
        bytes_acked: u32,
        is_dup_ack: bool,
        snd_una: u32,
        _current_time_ms: u64,
        _rtt_sample_ms: u64,
    ) {
        self.controller.on_ack(bytes_acked, is_dup_ack, snd_una);
    }

    pub fn on_timeout(&mut self, _current_time_ms: u64) {
        self.controller.on_timeout();
    }
}

impl Default for TcpCongestionController {
    fn default() -> Self {
        Self::new()
    }
}
