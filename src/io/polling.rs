// ============================================================================
// src/io/polling.rs - Adaptive Polling/Interrupt Hybrid Mode
// 設計書 6.1: ポーリング vs 割り込み：ハイブリッド適応モデル
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// ポーリングモードのしきい値設定
pub struct PollingConfig {
    /// 割り込みからポーリングに切り替えるパケット数/秒のしきい値
    pub switch_to_polling_threshold: u64,
    /// ポーリングから割り込みに戻すパケット数/秒のしきい値
    pub switch_to_interrupt_threshold: u64,
    /// ポーリング間隔（マイクロ秒）
    pub polling_interval_us: u64,
    /// アイドル検出時間（ミリ秒）
    pub idle_timeout_ms: u64,
}

impl Default for PollingConfig {
    fn default() -> Self {
        Self {
            // DPDKやNAPIと同様のしきい値
            switch_to_polling_threshold: 10000,  // 10K packets/sec
            switch_to_interrupt_threshold: 1000,  // 1K packets/sec
            polling_interval_us: 10,              // 10μs
            idle_timeout_ms: 100,                 // 100ms
        }
    }
}

/// I/Oモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    /// 割り込み駆動（省電力）
    Interrupt,
    /// ポーリング（低レイテンシ）
    Polling,
    /// ハイブリッド（自動切り替え）
    Hybrid,
}

/// 適応的I/Oコントローラ
/// 設計書 6.1: トラフィック量に応じて割り込み/ポーリングを切り替え
pub struct AdaptiveIoController {
    /// 現在のモード
    mode: Mutex<IoMode>,
    /// ポーリングが有効かどうか
    polling_enabled: AtomicBool,
    /// 設定
    config: PollingConfig,
    /// 統計: 処理したパケット数
    packets_processed: AtomicU64,
    /// 統計: 最後のサンプリング時刻（ティック）
    last_sample_tick: AtomicU64,
    /// 統計: 前回サンプリング時のパケット数
    last_sample_count: AtomicU64,
    /// 統計: モード切り替え回数
    mode_switches: AtomicU64,
}

impl AdaptiveIoController {
    /// 新しいコントローラを作成
    pub const fn new() -> Self {
        Self {
            mode: Mutex::new(IoMode::Hybrid),
            polling_enabled: AtomicBool::new(false),
            config: PollingConfig {
                switch_to_polling_threshold: 10000,
                switch_to_interrupt_threshold: 1000,
                polling_interval_us: 10,
                idle_timeout_ms: 100,
            },
            packets_processed: AtomicU64::new(0),
            last_sample_tick: AtomicU64::new(0),
            last_sample_count: AtomicU64::new(0),
            mode_switches: AtomicU64::new(0),
        }
    }
    
    /// 設定を更新
    pub fn configure(&mut self, config: PollingConfig) {
        self.config = config;
    }
    
    /// パケット処理完了を通知
    pub fn notify_packet_processed(&self, count: u64) {
        self.packets_processed.fetch_add(count, Ordering::Relaxed);
    }
    
    /// 現在のモードを取得
    pub fn current_mode(&self) -> IoMode {
        *self.mode.lock()
    }
    
    /// ポーリングが有効かどうか
    pub fn is_polling(&self) -> bool {
        self.polling_enabled.load(Ordering::Relaxed)
    }
    
    /// モードを手動で設定
    pub fn set_mode(&self, mode: IoMode) {
        *self.mode.lock() = mode;
        match mode {
            IoMode::Polling => self.polling_enabled.store(true, Ordering::Release),
            IoMode::Interrupt => self.polling_enabled.store(false, Ordering::Release),
            IoMode::Hybrid => {} // 自動判断に任せる
        }
    }
    
    /// 適応的モード切り替えを評価（タイマー割り込みから定期的に呼ばれる）
    pub fn evaluate_mode(&self, current_tick: u64) {
        // Hybridモードでない場合は何もしない
        if *self.mode.lock() != IoMode::Hybrid {
            return;
        }
        
        let last_tick = self.last_sample_tick.swap(current_tick, Ordering::AcqRel);
        let elapsed_ticks = current_tick.saturating_sub(last_tick);
        
        // サンプリング間隔が短すぎる場合はスキップ
        if elapsed_ticks < 100 {
            return;
        }
        
        let current_count = self.packets_processed.load(Ordering::Relaxed);
        let last_count = self.last_sample_count.swap(current_count, Ordering::AcqRel);
        let packets_delta = current_count.saturating_sub(last_count);
        
        // パケットレートを計算（packets/sec）
        // 1ティック = 1ms と仮定
        let rate = if elapsed_ticks > 0 {
            (packets_delta * 1000) / elapsed_ticks
        } else {
            0
        };
        
        let currently_polling = self.polling_enabled.load(Ordering::Relaxed);
        
        // しきい値に基づいてモードを切り替え
        if currently_polling {
            // ポーリング中: トラフィックが減少したら割り込みに戻す
            if rate < self.config.switch_to_interrupt_threshold {
                self.switch_to_interrupt();
            }
        } else {
            // 割り込み中: トラフィックが増加したらポーリングに切り替え
            if rate > self.config.switch_to_polling_threshold {
                self.switch_to_polling();
            }
        }
    }
    
    /// ポーリングモードに切り替え
    fn switch_to_polling(&self) {
        self.polling_enabled.store(true, Ordering::Release);
        self.mode_switches.fetch_add(1, Ordering::Relaxed);
        
        // 割り込みをマスク（デバイス固有の処理が必要）
        // TODO: 実際のデバイスの割り込みマスク処理を呼び出す
    }
    
    /// 割り込みモードに切り替え
    fn switch_to_interrupt(&self) {
        self.polling_enabled.store(false, Ordering::Release);
        self.mode_switches.fetch_add(1, Ordering::Relaxed);
        
        // 割り込みを有効化（デバイス固有の処理が必要）
        // TODO: 実際のデバイスの割り込み有効化処理を呼び出す
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> IoStats {
        IoStats {
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            mode_switches: self.mode_switches.load(Ordering::Relaxed),
            currently_polling: self.polling_enabled.load(Ordering::Relaxed),
        }
    }
}

/// I/O統計
#[derive(Debug, Clone)]
pub struct IoStats {
    pub packets_processed: u64,
    pub mode_switches: u64,
    pub currently_polling: bool,
}

/// グローバルなネットワークI/Oコントローラ
static NET_IO_CONTROLLER: AdaptiveIoController = AdaptiveIoController::new();

/// ネットワークI/Oコントローラを取得
pub fn net_io_controller() -> &'static AdaptiveIoController {
    &NET_IO_CONTROLLER
}

/// ポーリングループの実装例
/// Executorから呼ばれる
pub async fn polling_loop() {
    loop {
        if NET_IO_CONTROLLER.is_polling() {
            // ポーリングモード: NICのリングバッファを直接チェック
            // TODO: 実際のNICドライバのポーリング処理
            
            // 処理したパケット数を通知
            // NET_IO_CONTROLLER.notify_packet_processed(processed_count);
        } else {
            // 割り込みモード: 短いスリープでCPUを解放
            // 割り込みが来るまで待機
            crate::task::sleep_ms(1).await;
        }
        
        // CPUを他のタスクに明け渡す
        core::hint::spin_loop();
    }
}

/// ブロックストレージ用の適応的I/Oコントローラ
static BLOCK_IO_CONTROLLER: AdaptiveIoController = AdaptiveIoController::new();

/// ブロックI/Oコントローラを取得
pub fn block_io_controller() -> &'static AdaptiveIoController {
    &BLOCK_IO_CONTROLLER
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_adaptive_mode() {
        let controller = AdaptiveIoController::new();
        
        // 初期状態はHybrid
        assert_eq!(controller.current_mode(), IoMode::Hybrid);
        assert!(!controller.is_polling());
        
        // 手動でモード設定
        controller.set_mode(IoMode::Polling);
        assert!(controller.is_polling());
        
        controller.set_mode(IoMode::Interrupt);
        assert!(!controller.is_polling());
    }
}
