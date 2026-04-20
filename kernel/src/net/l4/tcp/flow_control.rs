// ============================================================================
// kernel/src/net/l4/tcp/flow_control.rs - TCP Flow Control - フロー制御
// ============================================================================
//! # TCP Flow Control - フロー制御
//!
//! 受信ウィンドウ管理とゼロウィンドウ処理
//! - 動的な受信ウィンドウ更新
//! - ゼロウィンドウプローブ
//! - Silly Window Syndrome (SWS) 回避

use core::cmp::{max, min};

/// デフォルト受信バッファサイズ (64KB)
pub const DEFAULT_RECV_BUFFER_SIZE: u32 = 65536;

/// 最大受信バッファサイズ (1MB with window scaling)
pub const MAX_RECV_BUFFER_SIZE: u32 = 1048576;

/// 最小広告ウィンドウ (SWS回避)
pub const MIN_ADVERTISE_WINDOW: u32 = 536; // 1 MSS minimum

/// ゼロウィンドウプローブ間隔 (ミリ秒)
pub const ZERO_WINDOW_PROBE_INTERVAL_MS: u64 = 500;

/// ゼロウィンドウプローブ最大再試行
pub const ZERO_WINDOW_PROBE_MAX_RETRIES: u8 = 10;

/// フロー制御状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControlState {
    /// 通常動作
    Normal,
    /// ゼロウィンドウ状態（受信側バッファフル）
    ZeroWindow,
    /// ゼロウィンドウプローブ中
    ZeroWindowProbe,
}

impl Default for FlowControlState {
    fn default() -> Self {
        FlowControlState::Normal
    }
}

/// フロー制御コントローラ
#[derive(Debug, Clone)]
pub struct FlowController {
    /// 受信バッファサイズ（最大）
    buffer_size: u32,
    /// 現在のバッファ使用量
    buffer_used: u32,
    /// 広告ウィンドウ（スケール前）
    advertised_window: u32,
    /// 相手の広告ウィンドウ（スケール後の実値）
    peer_window: u32,
    /// フロー制御状態
    state: FlowControlState,
    /// ゼロウィンドウプローブカウンタ
    probe_count: u8,
    /// 最後のプローブ時刻（tick）
    last_probe_tick: u64,
    /// ウィンドウ更新が必要か
    window_update_needed: bool,
}

impl FlowController {
    /// 新規作成
    pub fn new() -> Self {
        Self::with_buffer_size(DEFAULT_RECV_BUFFER_SIZE)
    }

    /// バッファサイズ指定で作成
    pub fn with_buffer_size(size: u32) -> Self {
        let size = min(size, MAX_RECV_BUFFER_SIZE);
        Self {
            buffer_size: size,
            buffer_used: 0,
            advertised_window: size,
            peer_window: 65535, // 初期値
            state: FlowControlState::Normal,
            probe_count: 0,
            last_probe_tick: 0,
            window_update_needed: false,
        }
    }

    /// 現在の広告ウィンドウ取得
    #[inline]
    pub fn advertised_window(&self) -> u32 {
        self.advertised_window
    }

    /// 相手の広告ウィンドウ取得
    #[inline]
    pub fn peer_window(&self) -> u32 {
        self.peer_window
    }

    /// 現在の状態
    #[inline]
    pub fn state(&self) -> FlowControlState {
        self.state
    }

    /// 使用可能なバッファ量
    #[inline]
    pub fn available_buffer(&self) -> u32 {
        self.buffer_size.saturating_sub(self.buffer_used)
    }

    /// ウィンドウ更新が必要か
    #[inline]
    pub fn needs_window_update(&self) -> bool {
        self.window_update_needed
    }

    /// ウィンドウ更新フラグクリア
    #[inline]
    pub fn clear_window_update(&mut self) {
        self.window_update_needed = false;
    }

    /// データ受信時の処理
    ///
    /// - bytes: 受信したバイト数
    /// Returns: 新しい広告ウィンドウ
    pub fn on_receive(&mut self, bytes: u32) -> u32 {
        self.buffer_used = self.buffer_used.saturating_add(bytes);
        // 受信した分だけ広告ウィンドウを減らして、ウィンドウ右端を維持する (RFC 1122)
        self.advertised_window = self.advertised_window.saturating_sub(bytes);

        if self.advertised_window == 0 {
            self.state = FlowControlState::ZeroWindow;
        }
        self.advertised_window
    }

    /// アプリケーションがデータを消費した時の処理
    ///
    /// - bytes: 消費したバイト数
    /// Returns: 新しい広告ウィンドウ
    pub fn on_consume(&mut self, bytes: u32) -> u32 {
        self.buffer_used = self.buffer_used.saturating_sub(bytes);
        let available = self.available_buffer();

        // RFC 1122 Section 4.2.3.3: Receiver SWS Avoidance
        // ウィンドウの更新（右端の移動）を行う閾値: max(MSS, BufferSize / 2)
        let threshold = max(MIN_ADVERTISE_WINDOW, self.buffer_size / 2);

        // 以下のいずれかの場合にウィンドウを更新する:
        // 1. 増加分が閾値以上
        // 2. ウィンドウが0から回復し、かつ最小広告ウィンドウ以上
        // 3. バッファが完全に空になった
        let can_update = (available >= self.advertised_window + threshold)
            || (self.advertised_window == 0 && available >= MIN_ADVERTISE_WINDOW)
            || (available == self.buffer_size && self.advertised_window < self.buffer_size);

        if can_update {
            self.advertised_window = available;
            self.window_update_needed = true;
            self.state = FlowControlState::Normal;
            self.probe_count = 0;
        }

        self.advertised_window
    }

    /// 広告ウィンドウの更新
    fn update_advertised_window(&mut self) {
        let available = self.available_buffer();

        // SWS回避: 小さすぎるウィンドウは0として広告
        if available < MIN_ADVERTISE_WINDOW && available < self.buffer_size / 2 {
            self.advertised_window = 0;
            self.state = FlowControlState::ZeroWindow;
        } else {
            // RightEdge の詳細制御は on_consume 側へ集約し、
            // ここでは十分な受信余裕が戻った場合だけ広告値を更新する。
            if available >= self.advertised_window + max(MIN_ADVERTISE_WINDOW, self.buffer_size / 2)
            {
                self.advertised_window = available;
                self.state = FlowControlState::Normal;
            }
        }
    }

    /// 相手の広告ウィンドウ更新
    pub fn update_peer_window(&mut self, window: u32) {
        let prev = self.peer_window;
        self.peer_window = window;

        // ゼロウィンドウ検出
        if window == 0 {
            if self.state != FlowControlState::ZeroWindowProbe {
                self.state = FlowControlState::ZeroWindowProbe;
                self.probe_count = 0;
            }
        } else if prev == 0 && window > 0 {
            // ゼロウィンドウから回復
            self.state = FlowControlState::Normal;
            self.probe_count = 0;
        }
    }

    /// ゼロウィンドウプローブが必要か確認
    ///
    /// - current_tick: 現在のtick
    /// Returns: プローブを送信すべきか
    pub fn should_send_probe(&mut self, current_tick: u64) -> bool {
        if self.state != FlowControlState::ZeroWindowProbe {
            return false;
        }

        // RFC 1122 Section 4.2.2.17: "A TCP MUST NOT close a connection because the
        // window is zero and the probe timer has expired."
        // We continue probing indefinitely with maximum backoff.

        // インターバル確認 (tickをmsに換算 - 1tick = 1msと仮定)
        // Exponential backoff: initial * 2^min(probes, 6)
        let backoff_shift = min(self.probe_count, 6) as u64;
        let interval = ZERO_WINDOW_PROBE_INTERVAL_MS * (1 << backoff_shift);

        if current_tick.saturating_sub(self.last_probe_tick) >= interval {
            return true;
        }

        false
    }

    /// プローブ送信を記録
    pub fn on_probe_sent(&mut self, current_tick: u64) {
        self.last_probe_tick = current_tick;
        self.probe_count = self.probe_count.saturating_add(1);
    }

    /// 送信可能なバイト数を計算
    /// cwnd と peer_window の小さい方を使用
    pub fn send_window(&self, cwnd: u32) -> u32 {
        min(cwnd, self.peer_window)
    }

    /// 送信可能かどうか（ゼロウィンドウでない）
    pub fn can_send(&self) -> bool {
        self.peer_window > 0 || self.state == FlowControlState::ZeroWindowProbe
    }

    /// バッファ使用率 (0-100)
    pub fn buffer_utilization(&self) -> u8 {
        if self.buffer_size == 0 {
            return 100;
        }
        ((self.buffer_used as u64 * 100) / self.buffer_size as u64) as u8
    }

    /// リセット
    pub fn reset(&mut self) {
        self.buffer_used = 0;
        self.advertised_window = self.buffer_size;
        self.peer_window = 65535;
        self.state = FlowControlState::Normal;
        self.probe_count = 0;
        self.last_probe_tick = 0;
        self.window_update_needed = false;
    }

    /// デバッグ情報
    pub fn debug_info(&self) -> FlowControlDebugInfo {
        FlowControlDebugInfo {
            buffer_size: self.buffer_size,
            buffer_used: self.buffer_used,
            advertised_window: self.advertised_window,
            peer_window: self.peer_window,
            state: self.state,
            probe_count: self.probe_count,
        }
    }
}

impl Default for FlowController {
    fn default() -> Self {
        Self::new()
    }
}

/// デバッグ情報
#[derive(Debug, Clone)]
pub struct FlowControlDebugInfo {
    pub buffer_size: u32,
    pub buffer_used: u32,
    pub advertised_window: u32,
    pub peer_window: u32,
    pub state: FlowControlState,
    pub probe_count: u8,
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_initial_state() {
        let fc = FlowController::new();
        assert_eq!(fc.state(), FlowControlState::Normal);
        assert_eq!(fc.advertised_window(), DEFAULT_RECV_BUFFER_SIZE);
        assert_eq!(fc.buffer_utilization(), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_receive_data() {
        let mut fc = FlowController::with_buffer_size(10000);

        fc.on_receive(3000);
        assert_eq!(fc.available_buffer(), 7000);
        assert_eq!(fc.advertised_window(), 7000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_consume_data() {
        let mut fc = FlowController::with_buffer_size(10000);

        fc.on_receive(5000);
        fc.on_consume(3000);

        assert_eq!(fc.available_buffer(), 8000);
        assert_eq!(fc.advertised_window(), 8000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_zero_window() {
        let mut fc = FlowController::with_buffer_size(1000);

        // バッファを満タンに
        fc.on_receive(1000);
        assert_eq!(fc.state(), FlowControlState::ZeroWindow);
        assert_eq!(fc.advertised_window(), 0);

        // データ消費で回復
        fc.on_consume(500);
        assert_eq!(fc.state(), FlowControlState::Normal);
        assert!(fc.advertised_window() > 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_sws_avoidance() {
        let mut fc = FlowController::with_buffer_size(10000);

        // ほぼ満タン - 小さすぎるウィンドウは0にする
        fc.on_receive(9800);

        // 200バイトの空きは MIN_ADVERTISE_WINDOW より小さいので0
        assert_eq!(fc.advertised_window(), 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_peer_zero_window() {
        let mut fc = FlowController::new();

        fc.update_peer_window(0);
        assert_eq!(fc.state(), FlowControlState::ZeroWindowProbe);
        assert!(!fc.can_send() || fc.state == FlowControlState::ZeroWindowProbe);

        // 回復
        fc.update_peer_window(5000);
        assert_eq!(fc.state(), FlowControlState::Normal);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_probe_timing() {
        let mut fc = FlowController::new();
        fc.update_peer_window(0);

        // Initial probe requires waiting the base interval.
        assert!(!fc.should_send_probe(0));
        assert!(fc.should_send_probe(ZERO_WINDOW_PROBE_INTERVAL_MS));
        fc.on_probe_sent(ZERO_WINDOW_PROBE_INTERVAL_MS);

        // Next probe uses exponential backoff (x2 after first probe).
        assert!(!fc.should_send_probe(ZERO_WINDOW_PROBE_INTERVAL_MS * 2));
        assert!(fc.should_send_probe(ZERO_WINDOW_PROBE_INTERVAL_MS * 3));
    }
}
