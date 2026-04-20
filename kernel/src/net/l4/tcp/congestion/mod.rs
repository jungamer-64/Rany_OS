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

/// Maximum Segment Size (デフォルト)
mod default_and_tests;
pub use default_and_tests::*;
mod variant_impl;

#[cfg(test)]
pub mod variant_tests {
    pub use super::default_and_tests::variant_tests::variant_tests::*;
}
pub const DEFAULT_MSS: u32 = 536;

/// 初期ウィンドウサイズ (RFC 6928: 10 MSS)
pub const INITIAL_WINDOW: u32 = 10;

/// 最小輻輳ウィンドウ
pub const MIN_CWND: u32 = 2;

/// 輻輳制御アルゴリズムの種類
///
/// 現在 `NewReno`, `Cubic`, `Bbr` の3種類が実装済み。
/// デフォルトは `NewReno`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// RFC 5681 NewReno
    NewReno,
    /// RFC 8312 CUBIC
    Cubic,
    /// BBR (Bottleneck Bandwidth and RTT)
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

    /// MSS更新時の処理 (RFC 6928: 初期ウィンドウを新MSSに合わせる)
    pub fn update_mss(&mut self, new_mss: u32) {
        let old_mss = self.mss;
        self.mss = new_mss;

        // 接続開始直後（まだデータ送信前）であれば、初期ウィンドウを再計算
        if self.state == CongestionState::SlowStart && self.cwnd == INITIAL_WINDOW * old_mss {
            self.cwnd = INITIAL_WINDOW * new_mss;
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
pub mod tests;

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

    /// MSS更新時の処理
    pub fn update_mss(&mut self, new_mss: u32) {
        self.base.update_mss(new_mss);
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
    ///
    /// Uses u128 intermediate calculations to avoid overflow when computing
    /// (t - K)^3 for large time differences (milliseconds cubed can exceed u64).
    fn cubic_update(&mut self, current_time_ms: u64) -> u32 {
        let mss = self.base.mss as u64;
        if mss == 0 {
            return self.origin_point;
        }

        // Calculate time since epoch start
        let t = current_time_ms.saturating_sub(self.epoch_start);

        // Calculate |t - K| in milliseconds
        let t_k_diff = if t > self.k { t - self.k } else { self.k - t };

        // Use u128 for cube calculation to prevent overflow
        // (t_k_diff in ms)^3 can easily exceed u64 for diffs > ~2642ms
        let t_k_cubed: u128 = (t_k_diff as u128)
            .saturating_mul(t_k_diff as u128)
            .saturating_mul(t_k_diff as u128);

        // W_cubic = C * (t - K)^3 + W_max (in segments)
        // Using fixed-point: C * x = (C_NUMERATOR * x) / C_DENOMINATOR
        // Division by 10^9 converts ms^3 to s^3
        let delta: u64 = ((cubic_constants::C_NUMERATOR as u128 * t_k_cubed)
            / (cubic_constants::C_DENOMINATOR as u128 * 1_000_000_000))
            .min(u64::MAX as u128) as u64;

        let origin_segments = self.origin_point as u64 / mss;

        let target_segments = if t > self.k {
            origin_segments.saturating_add(delta)
        } else {
            origin_segments.saturating_sub(delta)
        };

        // Convert back to bytes, clamped to u32
        let result = target_segments.saturating_mul(mss);
        result.min(u32::MAX as u64) as u32
    }

    /// ACK received - CUBIC window update
    pub fn on_ack(
        &mut self,
        bytes_acked: u32,
        is_dup_ack: bool,
        snd_una: u32,
        current_time_ms: u64,
    ) {
        self.base.bytes_in_flight = self.base.bytes_in_flight.saturating_sub(bytes_acked);

        if is_dup_ack {
            self.on_dup_ack(snd_una, current_time_ms);
            return;
        }

        self.base.dup_ack_count = 0;

        match self.base.state {
            CongestionState::SlowStart => {
                // Use standard slow start from base
                self.base.cwnd = self
                    .base
                    .cwnd
                    .saturating_add(min(bytes_acked, self.base.mss));

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
            self.origin_point =
                (self.w_max as u64 * cubic_constants::FAST_CONVERGENCE as u64 / 100) as u32;
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
// 統合輻輳制御バリアント (Unified Congestion Control)
// =====================================================
//
// NewReno / CUBIC / BBR をenumで統合。
// trait objectを避け、ゼロオーバーヘッドで委譲する。

/// 統合輻輳制御コントローラ
///
/// TCP接続ごとに選択可能な輻輳制御アルゴリズムをenumで管理。
/// vtableオーバーヘッドを避け、インライン展開可能な設計。
#[derive(Debug, Clone)]
pub enum CongestionControllerVariant {
    /// RFC 5681 NewReno (デフォルト)
    NewReno(CongestionController),
    /// RFC 8312 CUBIC
    Cubic(CubicController),
    /// BBRv1
    Bbr(BbrController),
}
