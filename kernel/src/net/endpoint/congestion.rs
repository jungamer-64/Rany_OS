// ============================================================================
// kernel/src/net/endpoint/congestion.rs
// ============================================================================
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

    #[test_case]
    fn test_initial_state() {
        let cc = CongestionController::new();
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
        assert_eq!(cc.ssthresh(), u32::MAX);
    }

    #[test_case]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::with_mss(1000);
        let initial_cwnd = cc.cwnd();

        // ACK受信でcwnd増加
        cc.on_ack(1000, false, 1000);
        assert!(cc.cwnd() > initial_cwnd);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test_case]
    fn test_transition_to_congestion_avoidance() {
        let mut cc = CongestionController::with_mss(1000);
        cc.ssthresh = 5000; // 強制的に低く設定

        // Slow Start で ssthresh を超えるまでACK
        for _ in 0..10 {
            cc.on_ack(1000, false, 0);
        }

        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }

    #[test_case]
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

    #[test_case]
    fn test_timeout() {
        let mut cc = CongestionController::with_mss(1000);
        cc.cwnd = 50000;
        cc.bytes_in_flight = 30000;

        cc.on_timeout();

        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.cwnd(), 1000); // 1 MSS
        assert_eq!(cc.ssthresh(), 15000); // FlightSize / 2
    }

    #[test_case]
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

// =====================================================
// CUBIC 輻輳制御 (RFC 8312)
// =====================================================

/// CUBIC constants (RFC 8312 Section 5)
mod cubic_constants {
    /// CUBIC scaling factor β (beta) = 0.7
    pub const BETA: u32 = 70; // Represented as percentage (70%)
    /// CUBIC scaling constant C = 0.4
    /// We use fixed-point: C = 410 / 1024 ≈ 0.4
    pub const C_NUMERATOR: u64 = 410;
    pub const C_DENOMINATOR: u64 = 1024;
    /// Fast convergence factor (1 + β) / 2 ≈ 0.85
    pub const FAST_CONVERGENCE: u32 = 85;
}

/// CUBIC congestion controller state
#[derive(Debug, Clone)]
pub struct CubicController {
    /// Base congestion controller (inherits from NewReno for slow start)
    base: CongestionController,
    /// W_max: window size before last reduction (in bytes)
    w_max: u32,
    /// Epoch start time (milliseconds since connection start)
    epoch_start: u64,
    /// K: time period to reach W_max (in ms)
    k: u64,
    /// Origin point of cubic function
    origin_point: u32,
    /// TCP-friendly window for fairness
    w_tcp: u32,
    /// ACK count for TCP-friendly mode
    ack_cnt: u32,
    /// Last congestion event time
    last_congestion: u64,
}

impl CubicController {
    /// Create a new CUBIC controller
    pub fn new() -> Self {
        Self {
            base: CongestionController::new(),
            w_max: 0,
            epoch_start: 0,
            k: 0,
            origin_point: 0,
            w_tcp: 0,
            ack_cnt: 0,
            last_congestion: 0,
        }
    }

    /// Create with custom MSS
    pub fn with_mss(mss: u32) -> Self {
        Self {
            base: CongestionController::with_mss(mss),
            w_max: 0,
            epoch_start: 0,
            k: 0,
            origin_point: 0,
            w_tcp: 0,
            ack_cnt: 0,
            last_congestion: 0,
        }
    }

    /// Get current cwnd
    #[inline]
    pub fn cwnd(&self) -> u32 {
        self.base.cwnd()
    }

    /// Get current state
    #[inline]
    pub fn state(&self) -> CongestionState {
        self.base.state()
    }

    /// Get MSS
    #[inline]
    pub fn mss(&self) -> u32 {
        self.base.mss()
    }

    /// Available send window
    pub fn available_window(&self, rwnd: u32) -> u32 {
        self.base.available_window(rwnd)
    }

    /// Record data send
    pub fn on_send(&mut self, bytes: u32) {
        self.base.on_send(bytes);
    }

    /// Calculate cubic root using Newton-Raphson method
    /// Returns cube root of x (integer approximation)
    fn cubic_root(x: u64) -> u64 {
        if x == 0 {
            return 0;
        }
        
        // Initial guess: x^(1/3) ≈ 2^(log2(x)/3)
        let mut y = 1u64 << ((64 - x.leading_zeros() + 2) / 3);
        
        // Newton-Raphson iterations: y = (2*y + x/y²) / 3
        for _ in 0..6 {
            let y_squared = y.saturating_mul(y);
            if y_squared == 0 {
                break;
            }
            let new_y = (2 * y + x / y_squared) / 3;
            if new_y >= y {
                break;
            }
            y = new_y;
        }
        y
    }

    /// Calculate CUBIC window target W_cubic(t)
    /// W_cubic(t) = C * (t - K)^3 + W_max
    fn cubic_update(&mut self, current_time_ms: u64) -> u32 {
        let mss = self.base.mss as u64;
        
        // Calculate time since epoch start
        let t = current_time_ms.saturating_sub(self.epoch_start);
        
        // Calculate (t - K)^3 in segments (not bytes)
        let t_k_diff = if t > self.k {
            t - self.k
        } else {
            self.k - t
        };
        
        // Cube of difference
        let t_k_cubed = t_k_diff.saturating_mul(t_k_diff).saturating_mul(t_k_diff);
        
        // W_cubic = C * (t - K)^3 + W_max (in segments)
        // Using fixed-point: C * x = (C_NUMERATOR * x) / C_DENOMINATOR
        let delta = (cubic_constants::C_NUMERATOR * t_k_cubed) / cubic_constants::C_DENOMINATOR / 1000 / 1000 / 1000;
        
        let origin_segments = self.origin_point as u64 / mss;
        
        let target_segments = if t > self.k {
            origin_segments.saturating_add(delta)
        } else {
            origin_segments.saturating_sub(delta)
        };
        
        // Convert back to bytes
        (target_segments * mss) as u32
    }

    /// ACK received - CUBIC window update
    pub fn on_ack(&mut self, bytes_acked: u32, is_dup_ack: bool, snd_una: u32, current_time_ms: u64) {
        self.base.bytes_in_flight = self.base.bytes_in_flight.saturating_sub(bytes_acked);
        
        if is_dup_ack {
            self.on_dup_ack(snd_una, current_time_ms);
            return;
        }
        
        self.base.dup_ack_count = 0;
        
        match self.base.state {
            CongestionState::SlowStart => {
                // Use standard slow start from base
                self.base.cwnd = self.base.cwnd.saturating_add(min(bytes_acked, self.base.mss));
                
                if self.base.cwnd >= self.base.ssthresh {
                    self.base.state = CongestionState::CongestionAvoidance;
                    self.epoch_start = current_time_ms;
                    self.reset_epoch();
                }
            }
            CongestionState::CongestionAvoidance => {
                // CUBIC congestion avoidance
                if self.epoch_start == 0 {
                    self.epoch_start = current_time_ms;
                    self.reset_epoch();
                }
                
                let w_cubic = self.cubic_update(current_time_ms);
                
                // TCP-friendly region: linear increase
                let mss = self.base.mss;
                self.ack_cnt = self.ack_cnt.saturating_add(bytes_acked);
                if self.ack_cnt >= self.base.cwnd {
                    self.w_tcp = self.w_tcp.saturating_add(mss);
                    self.ack_cnt = 0;
                }
                
                // Use max of CUBIC and TCP-friendly window
                let target = max(w_cubic, self.w_tcp);
                
                if target > self.base.cwnd {
                    // Increase by at most 1 MSS per RTT
                    let increase = min(target - self.base.cwnd, mss);
                    self.base.cwnd = self.base.cwnd.saturating_add(increase);
                }
            }
            CongestionState::FastRecovery => {
                // Fast recovery from base
                if snd_una > self.base.recover {
                    self.base.cwnd = self.base.ssthresh;
                    self.base.state = CongestionState::CongestionAvoidance;
                    self.epoch_start = current_time_ms;
                    self.reset_epoch();
                } else {
                    self.base.cwnd = self.base.cwnd.saturating_sub(bytes_acked);
                    self.base.cwnd = self.base.cwnd.saturating_add(self.base.mss);
                }
            }
        }
    }

    /// Reset epoch parameters
    fn reset_epoch(&mut self) {
        let mss = self.base.mss as u64;
        
        // Set origin point
        if self.w_max > self.base.cwnd {
            // Fast convergence: use reduced W_max
            self.origin_point = (self.w_max as u64 * cubic_constants::FAST_CONVERGENCE as u64 / 100) as u32;
        } else {
            self.origin_point = self.base.cwnd;
        }
        
        // Calculate K = cubic_root(W_max * (1 - β) / C)
        // K in milliseconds
        let w_max_segments = self.origin_point as u64 / mss;
        let beta_factor = 100 - cubic_constants::BETA as u64; // 30%
        let numerator = w_max_segments * beta_factor * cubic_constants::C_DENOMINATOR;
        let denominator = cubic_constants::C_NUMERATOR * 100;
        
        if denominator > 0 {
            self.k = Self::cubic_root(numerator * 1000 * 1000 * 1000 / denominator);
        } else {
            self.k = 0;
        }
        
        // Initialize TCP-friendly window
        self.w_tcp = self.base.cwnd;
        self.ack_cnt = 0;
    }

    /// Duplicate ACK handling
    fn on_dup_ack(&mut self, snd_una: u32, current_time_ms: u64) {
        self.base.dup_ack_count = self.base.dup_ack_count.saturating_add(1);
        
        match self.base.state {
            CongestionState::SlowStart | CongestionState::CongestionAvoidance => {
                if self.base.dup_ack_count >= 3 {
                    self.enter_fast_recovery(snd_una, current_time_ms);
                }
            }
            CongestionState::FastRecovery => {
                self.base.cwnd = self.base.cwnd.saturating_add(self.base.mss);
            }
        }
    }

    /// Enter fast recovery with CUBIC-specific ssthresh calculation
    fn enter_fast_recovery(&mut self, snd_una: u32, current_time_ms: u64) {
        // Save W_max before reduction
        self.w_max = self.base.cwnd;
        
        // ssthresh = cwnd * β
        self.base.ssthresh = (self.base.cwnd as u64 * cubic_constants::BETA as u64 / 100) as u32;
        self.base.ssthresh = max(self.base.ssthresh, MIN_CWND * self.base.mss);
        
        // cwnd = ssthresh + 3*MSS
        self.base.cwnd = self.base.ssthresh + 3 * self.base.mss;
        self.base.recover = snd_una;
        self.base.state = CongestionState::FastRecovery;
        
        // Reset epoch
        self.epoch_start = current_time_ms;
        self.last_congestion = current_time_ms;
    }

    /// Timeout handling
    pub fn on_timeout(&mut self, current_time_ms: u64) {
        // Save W_max
        self.w_max = self.base.cwnd;
        
        // Reset to slow start
        self.base.on_timeout();
        
        // Reset epoch
        self.epoch_start = 0;
        self.last_congestion = current_time_ms;
    }

    /// Reset controller
    pub fn reset(&mut self) {
        self.base.reset();
        self.w_max = 0;
        self.epoch_start = 0;
        self.k = 0;
        self.origin_point = 0;
        self.w_tcp = 0;
        self.ack_cnt = 0;
        self.last_congestion = 0;
    }
}

impl Default for CubicController {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================
// CUBIC テスト
// =====================================================

#[cfg(test)]
mod cubic_tests {
    use super::*;

    #[test_case]
    fn test_cubic_initial_state() {
        let cc = CubicController::new();
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
    }

    #[test_case]
    fn test_cubic_slow_start() {
        let mut cc = CubicController::with_mss(1000);
        let initial = cc.cwnd();
        
        cc.on_ack(1000, false, 1000, 0);
        assert!(cc.cwnd() > initial);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test_case]
    fn test_cubic_root() {
        assert_eq!(CubicController::cubic_root(0), 0);
        assert_eq!(CubicController::cubic_root(1), 1);
        assert_eq!(CubicController::cubic_root(8), 2);
        assert_eq!(CubicController::cubic_root(27), 3);
        assert_eq!(CubicController::cubic_root(1000), 10);
    }

    #[test_case]
    fn test_cubic_fast_recovery() {
        let mut cc = CubicController::with_mss(1000);
        cc.base.cwnd = 50000;
        cc.base.bytes_in_flight = 40000;
        
        // Trigger fast retransmit
        cc.on_ack(0, true, 1000, 100);
        cc.on_ack(0, true, 1000, 100);
        cc.on_ack(0, true, 1000, 100);
        
        assert_eq!(cc.state(), CongestionState::FastRecovery);
        // ssthresh = cwnd * 0.7 = 35000
        assert_eq!(cc.base.ssthresh, 35000);
        assert_eq!(cc.w_max, 50000);
    }
}

// =====================================================
// BBR 輻輳制御 (Bottleneck Bandwidth and RTT)
// =====================================================
//
// BBRv1 implementation based on:
// - Google's BBR paper: "BBR: Congestion-Based Congestion Control"
// - Linux kernel BBR implementation
// - IETF draft-cardwell-iccrg-bbr-congestion-control
//
// Key concepts:
// - BtlBw: Bottleneck Bandwidth (maximum delivery rate)
// - RTprop: Round-trip propagation time (minimum RTT)
// - pacing_rate = BtlBw * pacing_gain
// - cwnd = BtlBw * RTprop * cwnd_gain

/// BBR state machine phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    /// Exponential bandwidth probing (like slow start)
    Startup,
    /// Drain queues after startup
    Drain,
    /// Steady-state bandwidth probing
    ProbeBW,
    /// Probe for minimum RTT
    ProbeRTT,
}

impl Default for BbrState {
    fn default() -> Self {
        BbrState::Startup
    }
}

/// BBR constants
mod bbr_constants {
    /// High gain for startup phase (2/ln(2) ≈ 2.89)
    /// We use 289/100 for fixed-point
    pub const STARTUP_GAIN: u32 = 289;
    pub const GAIN_SCALE: u32 = 100;
    
    /// Drain gain (inverse of startup: ln(2)/2 ≈ 0.35)
    pub const DRAIN_GAIN: u32 = 35;
    
    /// Steady-state gain
    pub const STEADY_GAIN: u32 = 100;
    
    /// Probe bandwidth gains (cycle through these)
    /// 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
    pub const PROBE_BW_GAINS: [u32; 8] = [125, 75, 100, 100, 100, 100, 100, 100];
    
    /// Probe RTT cwnd (4 segments)
    pub const PROBE_RTT_CWND_SEGMENTS: u32 = 4;
    
    /// RTprop filter window (10 seconds in ms)
    pub const RTPROP_FILTER_LEN_MS: u64 = 10_000;
    
    /// BtlBw filter window (10 RTTs, we approximate as samples)
    pub const BTLBW_FILTER_LEN: usize = 10;
    
    /// Probe RTT duration (200ms)
    pub const PROBE_RTT_DURATION_MS: u64 = 200;
    
    /// Minimum cwnd (4 segments)
    pub const MIN_CWND_SEGMENTS: u32 = 4;
    
    /// Full bandwidth threshold (1.25x growth)
    pub const FULL_BW_THRESHOLD: u32 = 125; // 125%
    
    /// Full bandwidth count before exiting startup
    pub const FULL_BW_COUNT: u8 = 3;
}

/// Bandwidth sample for max-filter
#[derive(Debug, Clone, Copy, Default)]
struct BwSample {
    /// Delivery rate in bytes per millisecond
    bw: u64,
    /// Timestamp when this sample was taken
    timestamp: u64,
}

/// RTT sample for min-filter
#[derive(Debug, Clone, Copy, Default)]
struct RttSample {
    /// RTT in milliseconds
    rtt: u64,
    /// Timestamp when this sample was taken
    timestamp: u64,
}

/// BBR Congestion Controller
#[derive(Debug, Clone)]
pub struct BbrController {
    /// Current BBR state
    state: BbrState,
    /// Maximum Segment Size
    mss: u32,
    /// Congestion window (bytes)
    cwnd: u32,
    /// Pacing rate (bytes per millisecond)
    pacing_rate: u64,
    
    // === Bandwidth estimation ===
    /// Bottleneck bandwidth filter (max of last N samples)
    btl_bw_filter: [BwSample; bbr_constants::BTLBW_FILTER_LEN],
    /// Current filter index
    bw_filter_idx: usize,
    /// Current estimated bottleneck bandwidth
    btl_bw: u64,
    
    // === RTT estimation ===
    /// Minimum RTT (RTprop)
    rt_prop: u64,
    /// RTprop timestamp
    rt_prop_stamp: u64,
    /// RTprop expired flag
    rt_prop_expired: bool,
    
    // === Delivery rate tracking ===
    /// Bytes delivered so far
    delivered: u64,
    /// Delivery timestamp
    delivered_time: u64,
    /// First sent time (for rate calculation)
    first_sent_time: u64,
    /// Bytes in flight
    bytes_in_flight: u32,
    
    // === Pacing and gains ===
    /// Current pacing gain (scaled by GAIN_SCALE)
    pacing_gain: u32,
    /// Current cwnd gain (scaled by GAIN_SCALE)
    cwnd_gain: u32,
    
    // === ProbeBW state ===
    /// Current cycle index (0-7)
    cycle_idx: usize,
    /// Cycle start time
    cycle_start: u64,
    
    // === Startup state ===
    /// Full bandwidth reached flag
    full_bw_reached: bool,
    /// Full bandwidth value
    full_bw: u64,
    /// Count of rounds without bandwidth growth
    full_bw_count: u8,
    /// Round-trip counter
    round_count: u64,
    /// Round start flag
    round_start: bool,
    /// Next round delivered bytes
    next_round_delivered: u64,
    
    // === ProbeRTT state ===
    /// ProbeRTT start time
    probe_rtt_done_stamp: u64,
    /// ProbeRTT round done flag
    probe_rtt_round_done: bool,
    /// Saved cwnd before ProbeRTT
    prior_cwnd: u32,
    
    // === Packet tracking ===
    /// Round-trip time for latest ACK
    last_rtt: u64,
}

impl BbrController {
    /// Create a new BBR controller
    pub fn new() -> Self {
        Self::with_mss(DEFAULT_MSS)
    }
    
    /// Create with custom MSS
    pub fn with_mss(mss: u32) -> Self {
        let initial_cwnd = INITIAL_WINDOW * mss;
        Self {
            state: BbrState::Startup,
            mss,
            cwnd: initial_cwnd,
            pacing_rate: 0,
            
            btl_bw_filter: [BwSample::default(); bbr_constants::BTLBW_FILTER_LEN],
            bw_filter_idx: 0,
            btl_bw: 0,
            
            rt_prop: u64::MAX,
            rt_prop_stamp: 0,
            rt_prop_expired: false,
            
            delivered: 0,
            delivered_time: 0,
            first_sent_time: 0,
            bytes_in_flight: 0,
            
            pacing_gain: bbr_constants::STARTUP_GAIN,
            cwnd_gain: bbr_constants::STARTUP_GAIN,
            
            cycle_idx: 0,
            cycle_start: 0,
            
            full_bw_reached: false,
            full_bw: 0,
            full_bw_count: 0,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            
            probe_rtt_done_stamp: 0,
            probe_rtt_round_done: false,
            prior_cwnd: 0,
            
            last_rtt: 0,
        }
    }
    
    /// Get current cwnd
    #[inline]
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }
    
    /// Get current pacing rate (bytes/ms)
    #[inline]
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }
    
    /// Get current state
    #[inline]
    pub fn state(&self) -> BbrState {
        self.state
    }
    
    /// Get MSS
    #[inline]
    pub fn mss(&self) -> u32 {
        self.mss
    }
    
    /// Get estimated bottleneck bandwidth
    #[inline]
    pub fn btl_bw(&self) -> u64 {
        self.btl_bw
    }
    
    /// Get minimum RTT (RTprop)
    #[inline]
    pub fn rt_prop(&self) -> u64 {
        if self.rt_prop == u64::MAX { 0 } else { self.rt_prop }
    }
    
    /// Get bytes in flight
    #[inline]
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }
    
    /// Calculate BDP (Bandwidth-Delay Product)
    fn bdp(&self) -> u64 {
        if self.rt_prop == u64::MAX {
            return (INITIAL_WINDOW * self.mss) as u64;
        }
        // BDP = BtlBw * RTprop (bytes/ms * ms = bytes)
        self.btl_bw.saturating_mul(self.rt_prop)
    }
    
    /// Calculate target cwnd
    fn target_cwnd(&self) -> u32 {
        let bdp = self.bdp();
        let target = (bdp * self.cwnd_gain as u64) / bbr_constants::GAIN_SCALE as u64;
        max(target as u32, bbr_constants::MIN_CWND_SEGMENTS * self.mss)
    }
    
    /// Update pacing rate based on current BtlBw and gain
    fn update_pacing_rate(&mut self) {
        if self.btl_bw == 0 {
            // Initial pacing: use cwnd / RTprop estimate
            let rtt = if self.rt_prop == u64::MAX { 100 } else { self.rt_prop };
            if rtt > 0 {
                self.pacing_rate = self.cwnd as u64 / rtt;
            }
            return;
        }
        
        // pacing_rate = BtlBw * pacing_gain
        self.pacing_rate = (self.btl_bw * self.pacing_gain as u64) / bbr_constants::GAIN_SCALE as u64;
    }
    
    /// Update cwnd
    fn update_cwnd(&mut self) {
        let target = self.target_cwnd();
        
        match self.state {
            BbrState::ProbeRTT => {
                // Minimum cwnd during ProbeRTT
                self.cwnd = bbr_constants::PROBE_RTT_CWND_SEGMENTS * self.mss;
            }
            BbrState::Startup | BbrState::Drain => {
                // Allow cwnd to grow/shrink towards target
                if self.cwnd < target {
                    self.cwnd = target;
                }
            }
            BbrState::ProbeBW => {
                // Maintain target cwnd
                self.cwnd = target;
            }
        }
        
        // Enforce minimum
        self.cwnd = max(self.cwnd, bbr_constants::MIN_CWND_SEGMENTS * self.mss);
    }
    
    /// Update bottleneck bandwidth filter (max filter)
    fn update_btl_bw(&mut self, bw: u64, current_time: u64) {
        // Add sample to circular buffer
        self.btl_bw_filter[self.bw_filter_idx] = BwSample { bw, timestamp: current_time };
        self.bw_filter_idx = (self.bw_filter_idx + 1) % bbr_constants::BTLBW_FILTER_LEN;
        
        // Find maximum
        self.btl_bw = self.btl_bw_filter.iter().map(|s| s.bw).max().unwrap_or(0);
    }
    
    /// Update RTprop filter (min filter)
    fn update_rt_prop(&mut self, rtt: u64, current_time: u64) {
        // Check if RTprop filter has expired
        self.rt_prop_expired = current_time.saturating_sub(self.rt_prop_stamp) 
            > bbr_constants::RTPROP_FILTER_LEN_MS;
        
        // Update if new minimum or filter expired
        if rtt < self.rt_prop || self.rt_prop_expired {
            self.rt_prop = rtt;
            self.rt_prop_stamp = current_time;
        }
    }
    
    /// Check for round-trip completion
    fn update_round(&mut self, delivered: u64) {
        if delivered >= self.next_round_delivered {
            self.round_start = true;
            self.round_count = self.round_count.wrapping_add(1);
            self.next_round_delivered = self.delivered;
        } else {
            self.round_start = false;
        }
    }
    
    /// Check if bandwidth growth has stalled (for exiting Startup)
    fn check_full_bw_reached(&mut self) {
        if self.full_bw_reached || !self.round_start {
            return;
        }
        
        // Check if BtlBw grew by at least 25%
        let threshold = (self.full_bw * bbr_constants::FULL_BW_THRESHOLD as u64) 
            / bbr_constants::GAIN_SCALE as u64;
        
        if self.btl_bw >= threshold {
            // Bandwidth still growing
            self.full_bw = self.btl_bw;
            self.full_bw_count = 0;
        } else {
            // Bandwidth plateaued
            self.full_bw_count = self.full_bw_count.saturating_add(1);
            if self.full_bw_count >= bbr_constants::FULL_BW_COUNT {
                self.full_bw_reached = true;
            }
        }
    }
    
    /// Startup state logic
    fn update_startup(&mut self) {
        if self.full_bw_reached {
            // Transition to Drain
            self.state = BbrState::Drain;
            self.pacing_gain = bbr_constants::DRAIN_GAIN;
            self.cwnd_gain = bbr_constants::STARTUP_GAIN; // Keep high cwnd during drain
        }
    }
    
    /// Drain state logic
    fn update_drain(&mut self) {
        // Exit Drain when inflight <= BDP
        if self.bytes_in_flight as u64 <= self.bdp() {
            self.state = BbrState::ProbeBW;
            self.pacing_gain = bbr_constants::STEADY_GAIN;
            self.cwnd_gain = bbr_constants::STEADY_GAIN * 2; // 2x BDP for buffering
            self.cycle_idx = 0;
        }
    }
    
    /// ProbeBW state logic - cycle through gains
    fn update_probe_bw(&mut self, current_time: u64) {
        // Advance cycle every RTT
        if self.round_start {
            self.cycle_idx = (self.cycle_idx + 1) % 8;
            self.pacing_gain = bbr_constants::PROBE_BW_GAINS[self.cycle_idx];
        }
        
        // Check if we should probe RTT
        if self.rt_prop_expired && self.bytes_in_flight == 0 {
            self.enter_probe_rtt(current_time);
        }
    }
    
    /// Enter ProbeRTT state
    fn enter_probe_rtt(&mut self, current_time: u64) {
        self.prior_cwnd = self.cwnd;
        self.state = BbrState::ProbeRTT;
        self.pacing_gain = bbr_constants::STEADY_GAIN;
        self.cwnd_gain = bbr_constants::STEADY_GAIN;
        self.probe_rtt_done_stamp = 0;
        self.probe_rtt_round_done = false;
    }
    
    /// ProbeRTT state logic
    fn update_probe_rtt(&mut self, current_time: u64) {
        // Wait for inflight to drain
        if self.probe_rtt_done_stamp == 0 {
            if self.bytes_in_flight <= bbr_constants::PROBE_RTT_CWND_SEGMENTS * self.mss {
                self.probe_rtt_done_stamp = current_time + bbr_constants::PROBE_RTT_DURATION_MS;
                self.probe_rtt_round_done = false;
            }
            return;
        }
        
        // Check for round completion during ProbeRTT
        if self.round_start {
            self.probe_rtt_round_done = true;
        }
        
        // Exit ProbeRTT after duration and round completion
        if current_time >= self.probe_rtt_done_stamp && self.probe_rtt_round_done {
            self.rt_prop_stamp = current_time;
            self.restore_cwnd();
            self.exit_probe_rtt();
        }
    }
    
    /// Restore cwnd after ProbeRTT
    fn restore_cwnd(&mut self) {
        self.cwnd = max(self.cwnd, self.prior_cwnd);
    }
    
    /// Exit ProbeRTT state
    fn exit_probe_rtt(&mut self) {
        if self.full_bw_reached {
            self.state = BbrState::ProbeBW;
            self.pacing_gain = bbr_constants::STEADY_GAIN;
            self.cwnd_gain = bbr_constants::STEADY_GAIN * 2;
            self.cycle_idx = 0;
        } else {
            self.state = BbrState::Startup;
            self.pacing_gain = bbr_constants::STARTUP_GAIN;
            self.cwnd_gain = bbr_constants::STARTUP_GAIN;
        }
    }
    
    /// Record packet send
    pub fn on_send(&mut self, bytes: u32, current_time: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        
        if self.first_sent_time == 0 {
            self.first_sent_time = current_time;
            self.delivered_time = current_time;
        }
    }
    
    /// ACK received - main entry point
    pub fn on_ack(&mut self, bytes_acked: u32, rtt_sample: u64, current_time: u64) {
        // Update delivery tracking
        self.delivered = self.delivered.saturating_add(bytes_acked as u64);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);
        self.last_rtt = rtt_sample;
        
        // Calculate delivery rate
        let delivery_interval = current_time.saturating_sub(self.delivered_time);
        if delivery_interval > 0 && bytes_acked > 0 {
            let delivery_rate = (bytes_acked as u64 * 1000) / delivery_interval; // bytes per second -> bytes per ms
            let bw = bytes_acked as u64 / delivery_interval.max(1);
            self.update_btl_bw(bw, current_time);
        }
        self.delivered_time = current_time;
        
        // Update RTprop filter
        if rtt_sample > 0 {
            self.update_rt_prop(rtt_sample, current_time);
        }
        
        // Update round tracking
        self.update_round(self.delivered);
        
        // State-specific updates
        match self.state {
            BbrState::Startup => {
                self.check_full_bw_reached();
                self.update_startup();
            }
            BbrState::Drain => {
                self.update_drain();
            }
            BbrState::ProbeBW => {
                self.update_probe_bw(current_time);
            }
            BbrState::ProbeRTT => {
                self.update_probe_rtt(current_time);
            }
        }
        
        // Update cwnd and pacing rate
        self.update_pacing_rate();
        self.update_cwnd();
    }
    
    /// Packet loss detected
    pub fn on_loss(&mut self, bytes_lost: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_lost);
        
        // BBR doesn't use loss as primary signal, but we record it
        // In BBRv2, loss would trigger more conservative behavior
    }
    
    /// Timeout - reset to initial state
    pub fn on_timeout(&mut self) {
        // On RTO, BBR restarts
        self.state = BbrState::Startup;
        self.pacing_gain = bbr_constants::STARTUP_GAIN;
        self.cwnd_gain = bbr_constants::STARTUP_GAIN;
        self.full_bw_reached = false;
        self.full_bw = 0;
        self.full_bw_count = 0;
        self.round_count = 0;
    }
    
    /// Available window for sending
    pub fn available_window(&self) -> u32 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }
    
    /// Can send bytes?
    pub fn can_send(&self, bytes: u32) -> bool {
        self.available_window() >= bytes
    }
    
    /// Reset controller
    pub fn reset(&mut self) {
        *self = Self::with_mss(self.mss);
    }
    
    /// Get debug info
    pub fn debug_info(&self) -> BbrDebugInfo {
        BbrDebugInfo {
            state: self.state,
            cwnd: self.cwnd,
            pacing_rate: self.pacing_rate,
            btl_bw: self.btl_bw,
            rt_prop: self.rt_prop(),
            bytes_in_flight: self.bytes_in_flight,
            round_count: self.round_count,
            full_bw_reached: self.full_bw_reached,
        }
    }
}

impl Default for BbrController {
    fn default() -> Self {
        Self::new()
    }
}

/// BBR debug information
#[derive(Debug, Clone)]
pub struct BbrDebugInfo {
    pub state: BbrState,
    pub cwnd: u32,
    pub pacing_rate: u64,
    pub btl_bw: u64,
    pub rt_prop: u64,
    pub bytes_in_flight: u32,
    pub round_count: u64,
    pub full_bw_reached: bool,
}

// =====================================================
// BBR テスト
// =====================================================

#[cfg(test)]
mod bbr_tests {
    use super::*;

    #[test_case]
    fn test_bbr_initial_state() {
        let bbr = BbrController::new();
        assert_eq!(bbr.state(), BbrState::Startup);
        assert_eq!(bbr.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
    }

    #[test_case]
    fn test_bbr_startup_growth() {
        let mut bbr = BbrController::with_mss(1000);
        
        // Simulate receiving ACKs with RTT samples
        for i in 0..10 {
            bbr.on_send(1000, i * 10);
            bbr.on_ack(1000, 50, i * 10 + 50);
        }
        
        // Should still be in Startup initially
        assert_eq!(bbr.state(), BbrState::Startup);
        assert!(bbr.btl_bw() > 0);
    }

    #[test_case]
    fn test_bbr_rt_prop_tracking() {
        let mut bbr = BbrController::with_mss(1000);
        
        // First RTT sample
        bbr.on_ack(1000, 100, 100);
        assert_eq!(bbr.rt_prop(), 100);
        
        // Smaller RTT should update
        bbr.on_ack(1000, 80, 200);
        assert_eq!(bbr.rt_prop(), 80);
        
        // Larger RTT should not update
        bbr.on_ack(1000, 120, 300);
        assert_eq!(bbr.rt_prop(), 80);
    }

    #[test_case]
    fn test_bbr_available_window() {
        let mut bbr = BbrController::with_mss(1000);
        bbr.cwnd = 10000;
        
        bbr.on_send(3000, 0);
        assert_eq!(bbr.available_window(), 7000);
        assert!(bbr.can_send(5000));
        assert!(!bbr.can_send(8000));
    }

    #[test_case]
    fn test_bbr_bdp_calculation() {
        let mut bbr = BbrController::with_mss(1000);
        
        // Simulate connection to establish BtlBw and RTprop
        bbr.btl_bw = 100; // 100 bytes/ms = 100 KB/s
        bbr.rt_prop = 50; // 50ms RTT
        
        // BDP = 100 * 50 = 5000 bytes
        assert_eq!(bbr.bdp(), 5000);
    }

    #[test_case]
    fn test_bbr_startup_to_drain() {
        let mut bbr = BbrController::with_mss(1000);
        
        // Simulate bandwidth plateau (3 consecutive rounds without growth)
        bbr.full_bw = 1000;
        bbr.btl_bw = 1000;
        bbr.round_start = true;
        
        bbr.check_full_bw_reached();
        bbr.round_start = true;
        bbr.check_full_bw_reached();
        bbr.round_start = true;
        bbr.check_full_bw_reached();
        
        assert!(bbr.full_bw_reached);
        
        bbr.update_startup();
        assert_eq!(bbr.state(), BbrState::Drain);
    }
}

