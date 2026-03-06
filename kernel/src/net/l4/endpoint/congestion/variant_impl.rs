use super::*;

impl CongestionControllerVariant {
    /// アルゴリズム指定で作成
    pub fn from_algorithm(algorithm: CongestionAlgorithm) -> Self {
        match algorithm {
            CongestionAlgorithm::NewReno => Self::NewReno(CongestionController::new()),
            CongestionAlgorithm::Cubic => Self::Cubic(CubicController::new()),
            CongestionAlgorithm::Bbr => Self::Bbr(BbrController::new()),
        }
    }

    /// MSS指定でアルゴリズム選択して作成
    pub fn from_algorithm_with_mss(algorithm: CongestionAlgorithm, mss: u32) -> Self {
        match algorithm {
            CongestionAlgorithm::NewReno => Self::NewReno(CongestionController::with_mss(mss)),
            CongestionAlgorithm::Cubic => Self::Cubic(CubicController::with_mss(mss)),
            CongestionAlgorithm::Bbr => Self::Bbr(BbrController::with_mss(mss)),
        }
    }

    /// 現在のアルゴリズム種別を取得
    pub fn algorithm(&self) -> CongestionAlgorithm {
        match self {
            Self::NewReno(_) => CongestionAlgorithm::NewReno,
            Self::Cubic(_) => CongestionAlgorithm::Cubic,
            Self::Bbr(_) => CongestionAlgorithm::Bbr,
        }
    }

    /// 現在の輻輳ウィンドウ取得
    #[inline]
    pub fn cwnd(&self) -> u32 {
        match self {
            Self::NewReno(c) => c.cwnd(),
            Self::Cubic(c) => c.cwnd(),
            Self::Bbr(c) => c.cwnd(),
        }
    }

    /// 現在の状態取得 (NewReno/CUBIC用)
    #[inline]
    pub fn congestion_state(&self) -> CongestionState {
        match self {
            Self::NewReno(c) => c.state(),
            Self::Cubic(c) => c.state(),
            Self::Bbr(_) => CongestionState::CongestionAvoidance, // BBRは別ステートマシン
        }
    }

    /// MSS取得
    #[inline]
    pub fn mss(&self) -> u32 {
        match self {
            Self::NewReno(c) => c.mss(),
            Self::Cubic(c) => c.mss(),
            Self::Bbr(c) => c.mss(),
        }
    }

    /// MSS更新
    pub fn update_mss(&mut self, mss: u32) {
        match self {
            Self::NewReno(c) => c.update_mss(mss),
            Self::Cubic(c) => c.update_mss(mss),
            Self::Bbr(c) => c.update_mss(mss),
        }
    }

    /// 送信可能なバイト数を計算
    pub fn available_window(&self, rwnd: u32) -> u32 {
        match self {
            Self::NewReno(c) => c.available_window(rwnd),
            Self::Cubic(c) => c.available_window(rwnd),
            Self::Bbr(c) => {
                // BBRはrwndを考慮しつつ自身のcwndを使用
                let effective = min(c.cwnd(), rwnd);
                effective.saturating_sub(c.bytes_in_flight())
            }
        }
    }

    /// データ送信を記録
    pub fn on_send(&mut self, bytes: u32, current_time_ms: u64) {
        match self {
            Self::NewReno(c) => c.on_send(bytes),
            Self::Cubic(c) => c.on_send(bytes),
            Self::Bbr(c) => c.on_send(bytes, current_time_ms),
        }
    }

    /// ACK受信時の統合処理
    ///
    /// - `bytes_acked`: ACKされたバイト数
    /// - `is_dup_ack`: 重複ACKかどうか
    /// - `snd_una`: 未確認の最古シーケンス番号
    /// - `current_time_ms`: 現在時刻（ミリ秒）
    /// - `rtt_sample_ms`: RTTサンプル（BBR用、0なら無効）
    pub fn on_ack(
        &mut self,
        bytes_acked: u32,
        is_dup_ack: bool,
        snd_una: u32,
        current_time_ms: u64,
        rtt_sample_ms: u64,
    ) {
        match self {
            Self::NewReno(c) => c.on_ack(bytes_acked, is_dup_ack, snd_una),
            Self::Cubic(c) => c.on_ack(bytes_acked, is_dup_ack, snd_una, current_time_ms),
            Self::Bbr(c) => c.on_ack(bytes_acked, rtt_sample_ms, current_time_ms),
        }
    }

    /// タイムアウト時の処理
    pub fn on_timeout(&mut self, current_time_ms: u64) {
        match self {
            Self::NewReno(c) => c.on_timeout(),
            Self::Cubic(c) => c.on_timeout(current_time_ms),
            Self::Bbr(c) => c.on_timeout(),
        }
    }

    /// 接続リセット
    pub fn reset(&mut self) {
        match self {
            Self::NewReno(c) => c.reset(),
            Self::Cubic(c) => c.reset(),
            Self::Bbr(c) => c.reset(),
        }
    }
}
