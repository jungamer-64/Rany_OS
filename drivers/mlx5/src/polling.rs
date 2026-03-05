// ============================================================================
// drivers/mlx5/src/polling.rs - Adaptive Polling for ConnectX-4 Lx
// ============================================================================
//! 適応的ポーリング — 割り込み駆動とビジーポーリングのハイブリッド
//!
//! ## ExoRust 設計原則
//!
//! - 低負荷時: MSI-X 割り込み駆動（CPU 節約）
//! - 高負荷時: ビジーポーリング（低レイテンシ）
//! - NAPI-like: 一定量処理後にre-arm
//!
//! ## 動作モード遷移
//!
//! ```text
//! Interrupt Mode ──[高スループット検出]──> Polling Mode
//!         ^                                      │
//!         └────[アイドル検出]────────────────────┘
//! ```

/// ポーリングモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollingMode {
    /// MSI-X 割り込み駆動（低負荷時）
    Interrupt,
    /// ビジーポーリング（高負荷時）
    BusyPoll,
    /// ハイブリッド（状況に応じて切り替え）
    Adaptive,
}

/// 適応的ポーリングの設定パラメータ
#[derive(Debug, Clone)]
pub struct AdaptivePollingConfig {
    /// ポーリングモードに切り替えるスループット閾値（パケット/秒）
    pub high_throughput_threshold: u64,
    /// 割り込みモードに切り替えるアイドル閾値（連続空ポーリング回数）
    pub idle_threshold: u32,
    /// 1回のポーリングサイクルで処理する最大CQE数
    pub max_batch_size: u32,
    /// ビジーポーリングの最大反復回数（スターベーション防止）
    pub max_poll_iterations: u32,
    /// NAPI-likeバジェット（1回の割り込みで処理する最大CQE数）
    pub napi_budget: u32,
    /// CQ moderation: 割り込み結合の最大パケット数
    pub cq_max_count: u16,
    /// CQ moderation: 割り込み結合の最大遅延（マイクロ秒）
    pub cq_max_period_us: u16,
}

impl Default for AdaptivePollingConfig {
    fn default() -> Self {
        Self {
            high_throughput_threshold: 100_000,  // 100Kpps
            idle_threshold: 256,
            max_batch_size: 64,
            max_poll_iterations: 8,
            napi_budget: 64,
            cq_max_count: 16,
            cq_max_period_us: 50,
        }
    }
}

/// 適応的ポーリングの状態
pub struct AdaptivePollingState {
    /// 現在のモード
    mode: PollingMode,
    /// 設定
    config: AdaptivePollingConfig,
    /// 連続空ポーリング回数
    consecutive_empty_polls: u32,
    /// 直近のポーリングサイクルのCQE数
    last_poll_count: u32,
    /// 累積CQE数（統計用）
    total_cqes_processed: u64,
    /// ポーリングサイクル数
    total_poll_cycles: u64,
    /// モード遷移回数
    mode_transitions: u64,
}

impl AdaptivePollingState {
    /// 新しい適応的ポーリング状態を作成
    pub fn new(config: AdaptivePollingConfig) -> Self {
        Self {
            mode: PollingMode::Interrupt,
            config,
            consecutive_empty_polls: 0,
            last_poll_count: 0,
            total_cqes_processed: 0,
            total_poll_cycles: 0,
            mode_transitions: 0,
        }
    }

    /// デフォルト設定で作成
    pub fn with_defaults() -> Self {
        Self::new(AdaptivePollingConfig::default())
    }

    /// 現在のポーリングモード
    pub fn mode(&self) -> PollingMode {
        self.mode
    }

    /// ポーリングサイクルを記録し、モード遷移を判定する
    ///
    /// # Arguments
    /// - `cqes_processed`: 今回のサイクルで処理したCQE数
    ///
    /// # Returns
    /// CQの再ARM（割り込み再有効化）が必要かどうか
    pub fn record_poll_cycle(&mut self, cqes_processed: u32) -> bool {
        self.last_poll_count = cqes_processed;
        self.total_cqes_processed += cqes_processed as u64;
        self.total_poll_cycles += 1;

        if cqes_processed == 0 {
            self.consecutive_empty_polls += 1;
        } else {
            self.consecutive_empty_polls = 0;
        }

        let need_rearm = self.evaluate_transition();
        need_rearm
    }

    /// モード遷移の評価
    ///
    /// # Returns
    /// CQの再ARM が必要な場合 true
    fn evaluate_transition(&mut self) -> bool {
        match self.mode {
            PollingMode::Interrupt => {
                // 高負荷検出: バッチサイズがNAPIバジェットに近い場合
                if self.last_poll_count >= self.config.napi_budget / 2 {
                    self.mode = PollingMode::BusyPoll;
                    self.mode_transitions += 1;
                    log::trace!(target: "mlx5::poll", "→ BusyPoll mode (high throughput)");
                    false // ポーリングモードではre-arm不要
                } else {
                    true // 割り込みモードでは常にre-arm
                }
            }
            PollingMode::BusyPoll => {
                // アイドル検出: 連続空ポーリングが閾値を超えた場合
                if self.consecutive_empty_polls >= self.config.idle_threshold {
                    self.mode = PollingMode::Interrupt;
                    self.mode_transitions += 1;
                    self.consecutive_empty_polls = 0;
                    log::trace!(target: "mlx5::poll", "→ Interrupt mode (idle)");
                    true // 割り込みモードに戻るので re-arm
                } else {
                    false // ポーリング続行
                }
            }
            PollingMode::Adaptive => {
                // ハイブリッド: 常にre-armしつつポーリングも併用
                self.consecutive_empty_polls >= self.config.idle_threshold / 2
            }
        }
    }

    /// ビジーポーリングを実行すべきか
    pub fn should_busy_poll(&self) -> bool {
        self.mode == PollingMode::BusyPoll
    }

    /// 最大バッチサイズを取得
    pub fn max_batch_size(&self) -> u32 {
        self.config.max_batch_size
    }

    /// NAPI バジェットを取得
    pub fn napi_budget(&self) -> u32 {
        self.config.napi_budget
    }

    /// 統計情報
    pub fn stats(&self) -> PollingStats {
        PollingStats {
            mode: self.mode,
            total_cqes_processed: self.total_cqes_processed,
            total_poll_cycles: self.total_poll_cycles,
            mode_transitions: self.mode_transitions,
        }
    }
}

/// ポーリング統計情報
#[derive(Debug, Clone)]
pub struct PollingStats {
    /// 現在のモード
    pub mode: PollingMode,
    /// 累積処理CQE数
    pub total_cqes_processed: u64,
    /// 累積ポーリングサイクル数
    pub total_poll_cycles: u64,
    /// モード遷移回数
    pub mode_transitions: u64,
}

impl core::fmt::Display for PollingMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PollingMode::Interrupt => write!(f, "Interrupt"),
            PollingMode::BusyPoll => write!(f, "BusyPoll"),
            PollingMode::Adaptive => write!(f, "Adaptive"),
        }
    }
}
