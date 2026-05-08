// ============================================================================
// kernel/src/net/l4/tcp/congestion/default_and_tests/mod.rs - L4 / TCP / congestion / default and tests モジュール
// ============================================================================

use super::*;

pub mod variant_tests;
impl Default for CongestionControllerVariant {
    fn default() -> Self {
        Self::NewReno(CongestionController::new())
    }
}

// =====================================================
// CUBIC テスト
// =====================================================

#[cfg(test)]
pub mod cubic_tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_cubic_initial_state() {
        let cc = CubicController::new();
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_cubic_slow_start() {
        let mut cc = CubicController::with_mss(1000);
        let initial = cc.cwnd();

        cc.on_ack(1000, false, 1000, 0);
        assert!(cc.cwnd() > initial);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_cubic_root() {
        assert_eq!(CubicController::cubic_root(0), 0);
        assert_eq!(CubicController::cubic_root(1), 1);
        assert_eq!(CubicController::cubic_root(8), 2);
        assert_eq!(CubicController::cubic_root(27), 3);
        assert_eq!(CubicController::cubic_root(1000), 10);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_cubic_fast_recovery() {
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
pub(crate) struct BwSample {
    /// Delivery rate in bytes per millisecond
    bw: u64,
    /// Timestamp when this sample was taken
    timestamp: u64,
}

/// RTT sample for min-filter
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RttSample {
    /// RTT in milliseconds
    rtt: u64,
    /// Timestamp when this sample was taken
    timestamp: u64,
}

/// BBR Congestion Controller
#[derive(Debug)]
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

    /// MSS更新時の処理
    pub fn update_mss(&mut self, new_mss: u32) {
        let old_mss = self.mss;
        self.mss = new_mss;

        // 初期状態（Startup）かつcwndが初期値のままであれば、新MSSに合わせて更新
        if self.state == BbrState::Startup && self.cwnd == INITIAL_WINDOW * old_mss {
            self.cwnd = INITIAL_WINDOW * new_mss;
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
        if self.rt_prop == u64::MAX {
            0
        } else {
            self.rt_prop
        }
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
            let rtt = if self.rt_prop == u64::MAX {
                100
            } else {
                self.rt_prop
            };
            if rtt > 0 {
                self.pacing_rate = self.cwnd as u64 / rtt;
            }
            return;
        }

        // pacing_rate = BtlBw * pacing_gain
        self.pacing_rate =
            (self.btl_bw * self.pacing_gain as u64) / bbr_constants::GAIN_SCALE as u64;
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
        self.btl_bw_filter[self.bw_filter_idx] = BwSample {
            bw,
            timestamp: current_time,
        };
        self.bw_filter_idx = (self.bw_filter_idx + 1) % bbr_constants::BTLBW_FILTER_LEN;

        // Find maximum
        self.btl_bw = self.btl_bw_filter.iter().map(|s| s.bw).max().unwrap_or(0);
    }

    /// Update RTprop filter (min filter)
    fn update_rt_prop(&mut self, rtt: u64, current_time: u64) {
        // Check if RTprop filter has expired
        self.rt_prop_expired =
            current_time.saturating_sub(self.rt_prop_stamp) > bbr_constants::RTPROP_FILTER_LEN_MS;

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
    fn enter_probe_rtt(&mut self, _current_time: u64) {
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
            let _delivery_rate = (bytes_acked as u64 * 1000) / delivery_interval; // bytes per second -> bytes per ms
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
#[derive(Debug)]
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
pub mod bbr_tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_bbr_initial_state() {
        let bbr = BbrController::new();
        assert_eq!(bbr.state(), BbrState::Startup);
        assert_eq!(bbr.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_bbr_startup_growth() {
        assert!(bbr_startup_growth_check());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_bbr_rt_prop_tracking() {
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

    #[cfg_attr(test, test_case)]
    pub fn test_bbr_available_window() {
        let mut bbr = BbrController::with_mss(1000);
        bbr.cwnd = 10000;

        bbr.on_send(3000, 0);
        assert_eq!(bbr.available_window(), 7000);
        assert!(bbr.can_send(5000));
        assert!(!bbr.can_send(8000));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_bbr_bdp_calculation() {
        let mut bbr = BbrController::with_mss(1000);

        // Simulate connection to establish BtlBw and RTprop
        bbr.btl_bw = 100; // 100 bytes/ms = 100 KB/s
        bbr.rt_prop = 50; // 50ms RTT

        // BDP = 100 * 50 = 5000 bytes
        assert_eq!(bbr.bdp(), 5000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_bbr_startup_to_drain() {
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

#[cfg(test)]
fn bbr_startup_growth_check() -> bool {
    let mut bbr = BbrController::with_mss(1000);
    let initial_cwnd = bbr.cwnd();

    for i in 0..10 {
        bbr.on_send(1000, i * 10);
        bbr.on_ack(1000, 50, i * 10 + 50);
    }

    bbr.btl_bw() > 0 && bbr.cwnd() >= initial_cwnd && bbr.round_count > 0
}
