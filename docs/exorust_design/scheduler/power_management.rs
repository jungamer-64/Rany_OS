//! 電力管理とC-state制御
//!
//! ポーリングモードとアイドル時の省電力戦略を実装します。
//! 設計書セクション9.4「電力管理（C-states）」参照。

use core::time::Duration;

/// CPU電力状態の管理
pub enum PowerState {
    /// C0: 通常動作
    Active,
    /// C1: HLT命令、即座復帰可能
    Halt,
    /// C1E/C3: 軽いスリープ
    LightSleep,
    /// C6: 深いスリープ、復帰コスト大
    DeepSleep,
}

/// アイドル時間のヒント情報
pub struct IdleHint {
    /// 予想されるアイドル継続時間
    pub expected_idle_duration: Duration,
}

/// 負荷に応じたC-state選択
///
/// 予想されるアイドル時間に基づいて、最適なCPU電力状態を選択します。
/// 短いアイドル時間では復帰コストの低い状態を、長いアイドル時間では
/// 電力消費を抑える深いスリープ状態を選択します。
pub fn select_cstate(idle_hint: IdleHint) -> PowerState {
    match idle_hint.expected_idle_duration {
        d if d < Duration::from_micros(10) => PowerState::Active, // スピンウェイト
        d if d < Duration::from_micros(100) => PowerState::Halt,  // HLT
        d if d < Duration::from_millis(1) => PowerState::LightSleep,
        _ => PowerState::DeepSleep,
    }
}

/// I/O動作モード
pub enum IoMode {
    /// ポーリングモード：高スループット、高電力消費
    Polling,
    /// 割り込み駆動モード：低電力、割り込みオーバーヘッド
    Interrupt,
    /// ハイブリッドモード：負荷に応じて切り替え
    Hybrid,
}

/// I/O統計情報
pub struct IoStats {
    /// 1秒あたりのパケット数
    pub packets_per_second: u64,
}

/// 100k pps以上でポーリングモード
const HIGH_THRESHOLD: u64 = 100_000;
/// 10k pps以下で割り込みモード
const LOW_THRESHOLD: u64 = 10_000;

/// 適応的I/Oモード選択
///
/// ネットワークの負荷（パケットレート）に応じて、最適なI/Oモードを選択します。
/// - 高負荷時: ポーリングモード（割り込みオーバーヘッド削減）
/// - 低負荷時: 割り込みモード（CPU使用率とレイテンシの最適化）
/// - 中間負荷: ハイブリッドモード
pub fn adaptive_io_mode(stats: &IoStats) -> IoMode {
    match stats.packets_per_second {
        pps if pps > HIGH_THRESHOLD => IoMode::Polling,
        pps if pps < LOW_THRESHOLD => IoMode::Interrupt,
        _ => IoMode::Hybrid,
    }
}
