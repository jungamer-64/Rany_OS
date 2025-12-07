//! # TCP Congestion Control - 輻輳制御
//!
//! RFC 5681 (TCP Congestion Control) 準拠実装
//! - Slow Start
//! - Congestion Avoidance  
//! - Fast Retransmit / Fast Recovery (NewReno)

use core::cmp::{max, min};

/// Maximum Segment Size (デフォルト)
pub const DEFAULT_MSS: u32 = 1460;

/// 初期ウィンドウサイズ (RFC 6928: 10 MSS)
pub const INITIAL_WINDOW: u32 = 10;

/// 最小輻輳ウィンドウ
pub const MIN_CWND: u32 = 2;

/// 輻輳制御アルゴリズムの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// RFC 5681 NewReno
    NewReno,
    /// RFC 8312 CUBIC (将来実装)
    Cubic,
    /// RFC 9002 BBR (将来実装)
    Bbr,
}

impl Default for CongestionAlgorithm {
    fn default() -> Self {
        CongestionAlgorithm::NewReno
    }
}

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
#[derive(Debug, Clone)]
pub struct CongestionController {
    /// アルゴリズム
    algorithm: CongestionAlgorithm,
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
            algorithm: CongestionAlgorithm::NewReno,
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

    /// MSSを指定して作成
    pub fn with_mss(mss: u32) -> Self {
        Self {
            algorithm: CongestionAlgorithm::NewReno,
            state: CongestionState::SlowStart,
            cwnd: INITIAL_WINDOW * mss,
            ssthresh: u32::MAX,
            mss,
            dup_ack_count: 0,
            recover: 0,
            bytes_acked: 0,
            bytes_in_flight: 0,
        }
    }

    /// 現在の輻輳ウィンドウ取得
    #[inline]
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// ssthresh取得
    #[inline]
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// 現在の状態取得
    #[inline]
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// MSS取得
    #[inline]
    pub fn mss(&self) -> u32 {
        self.mss
    }

    /// 送信可能なバイト数を計算
    /// effective_window = min(cwnd, rwnd) - bytes_in_flight
    pub fn available_window(&self, rwnd: u32) -> u32 {
        let effective = min(self.cwnd, rwnd);
        effective.saturating_sub(self.bytes_in_flight)
    }

    /// 送信可能かどうか
    pub fn can_send(&self, rwnd: u32, bytes: u32) -> bool {
        self.available_window(rwnd) >= bytes
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

    /// パケットロス検出時（一般）
    pub fn on_packet_loss(&mut self) {
        self.on_timeout();
    }

    /// 接続リセット
    pub fn reset(&mut self) {
        self.state = CongestionState::SlowStart;
        self.cwnd = INITIAL_WINDOW * self.mss;
        self.ssthresh = u32::MAX;
        self.dup_ack_count = 0;
        self.recover = 0;
        self.bytes_acked = 0;
        self.bytes_in_flight = 0;
    }

    /// デバッグ情報
    pub fn debug_info(&self) -> CongestionDebugInfo {
        CongestionDebugInfo {
            algorithm: self.algorithm,
            state: self.state,
            cwnd: self.cwnd,
            ssthresh: self.ssthresh,
            mss: self.mss,
            bytes_in_flight: self.bytes_in_flight,
            dup_ack_count: self.dup_ack_count,
        }
    }
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}

/// デバッグ情報構造体
#[derive(Debug, Clone)]
pub struct CongestionDebugInfo {
    pub algorithm: CongestionAlgorithm,
    pub state: CongestionState,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub mss: u32,
    pub bytes_in_flight: u32,
    pub dup_ack_count: u8,
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cc = CongestionController::new();
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
        assert_eq!(cc.ssthresh(), u32::MAX);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::with_mss(1000);
        let initial_cwnd = cc.cwnd();

        // ACK受信でcwnd増加
        cc.on_ack(1000, false, 1000);
        assert!(cc.cwnd() > initial_cwnd);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_transition_to_congestion_avoidance() {
        let mut cc = CongestionController::with_mss(1000);
        cc.ssthresh = 5000; // 強制的に低く設定

        // Slow Start で ssthresh を超えるまでACK
        for _ in 0..10 {
            cc.on_ack(1000, false, 0);
        }

        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_fast_retransmit() {
        let mut cc = CongestionController::with_mss(1000);
        cc.bytes_in_flight = 10000;

        // 3重複ACKでFast Recovery
        cc.on_ack(0, true, 1000);
        cc.on_ack(0, true, 1000);
        cc.on_ack(0, true, 1000);

        assert_eq!(cc.state(), CongestionState::FastRecovery);
        assert!(cc.ssthresh() < u32::MAX);
    }

    #[test]
    fn test_timeout() {
        let mut cc = CongestionController::with_mss(1000);
        cc.cwnd = 50000;
        cc.bytes_in_flight = 30000;

        cc.on_timeout();

        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.cwnd(), 1000); // 1 MSS
        assert_eq!(cc.ssthresh(), 15000); // FlightSize / 2
    }

    #[test]
    fn test_available_window() {
        let mut cc = CongestionController::with_mss(1000);
        cc.cwnd = 10000;
        cc.bytes_in_flight = 3000;

        // cwnd制限
        assert_eq!(cc.available_window(20000), 7000);

        // rwnd制限
        assert_eq!(cc.available_window(5000), 2000);
    }
}
