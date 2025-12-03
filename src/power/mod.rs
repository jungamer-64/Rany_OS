//! 電源管理サブシステム
//!
//! ACPI電源管理機能を実装し、スリープ状態、シャットダウン、
//! 省電力モードなどを制御する。

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

use crate::io::acpi::Fadt;

/// 電源状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowerState {
    /// S0: フル稼働
    Working = 0,
    /// S1: スタンバイ (CPU停止、メモリ維持)
    Standby = 1,
    /// S2: 深いスタンバイ (CPUパワーオフ)
    DeepStandby = 2,
    /// S3: サスペンド・トゥ・RAM
    SuspendToRam = 3,
    /// S4: ハイバネート (サスペンド・トゥ・ディスク)
    Hibernate = 4,
    /// S5: ソフトオフ
    SoftOff = 5,
}

impl PowerState {
    /// u8から変換
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Working),
            1 => Some(Self::Standby),
            2 => Some(Self::DeepStandby),
            3 => Some(Self::SuspendToRam),
            4 => Some(Self::Hibernate),
            5 => Some(Self::SoftOff),
            _ => None,
        }
    }
}

/// CPUパワー状態 (C-States)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuPowerState {
    /// C0: アクティブ (命令実行中)
    Active = 0,
    /// C1: Halt (HLT命令、最低遅延)
    Halt = 1,
    /// C2: ストップクロック
    StopClock = 2,
    /// C3: ディープスリープ (キャッシュフラッシュ)
    DeepSleep = 3,
}

/// デバイスパワー状態 (D-States)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DevicePowerState {
    /// D0: フルオン
    FullOn = 0,
    /// D1: 中間省電力
    LowPower1 = 1,
    /// D2: 深い省電力
    LowPower2 = 2,
    /// D3hot: ソフトオフ (復帰可能)
    SoftOff = 3,
    /// D3cold: ハードオフ (完全電源断)
    HardOff = 4,
}

/// ACPI PM1コントロールレジスタビット
mod pm1_control {
    pub const SCI_EN: u16 = 1 << 0; // SCI割り込み有効
    pub const BM_RLD: u16 = 1 << 1; // バスマスターリロード
    pub const GBL_RLS: u16 = 1 << 2; // グローバルリリース
    pub const SLP_TYP_SHIFT: u16 = 10; // スリープタイプシフト
    pub const SLP_TYP_MASK: u16 = 0x07 << 10;
    pub const SLP_EN: u16 = 1 << 13; // スリープ有効
}

/// ACPI PM1ステータスレジスタビット
mod pm1_status {
    pub const TMR_STS: u16 = 1 << 0; // タイマーステータス
    pub const BM_STS: u16 = 1 << 4; // バスマスターステータス
    pub const GBL_STS: u16 = 1 << 5; // グローバルステータス
    pub const PWRBTN_STS: u16 = 1 << 8; // 電源ボタンステータス
    pub const SLPBTN_STS: u16 = 1 << 9; // スリープボタンステータス
    pub const RTC_STS: u16 = 1 << 10; // RTCステータス
    pub const WAK_STS: u16 = 1 << 15; // ウェイクステータス
}

/// ACPI電源管理設定
#[derive(Debug, Clone)]
pub struct AcpiPmConfig {
    /// PM1aイベントブロックアドレス
    pub pm1a_evt_blk: u16,
    /// PM1bイベントブロックアドレス
    pub pm1b_evt_blk: u16,
    /// PM1aコントロールブロックアドレス
    pub pm1a_cnt_blk: u16,
    /// PM1bコントロールブロックアドレス
    pub pm1b_cnt_blk: u16,
    /// PM2コントロールブロックアドレス
    pub pm2_cnt_blk: u16,
    /// PMタイマーブロックアドレス
    pub pm_tmr_blk: u16,
    /// GPE0ブロックアドレス
    pub gpe0_blk: u16,
    /// GPE1ブロックアドレス
    pub gpe1_blk: u16,
    /// PM1イベントブロック長
    pub pm1_evt_len: u8,
    /// PM1コントロールブロック長
    pub pm1_cnt_len: u8,
    /// PMタイマーの32ビットフラグ
    pub pm_tmr_32bit: bool,
    /// SLP_TYPa値 (S5用)
    pub s5_slp_typ_a: u8,
    /// SLP_TYPb値 (S5用)
    pub s5_slp_typ_b: u8,
}

impl AcpiPmConfig {
    /// デフォルト設定 (QEMUのデフォルト)
    pub const fn default() -> Self {
        Self {
            pm1a_evt_blk: 0x600,
            pm1b_evt_blk: 0,
            pm1a_cnt_blk: 0x604,
            pm1b_cnt_blk: 0,
            pm2_cnt_blk: 0,
            pm_tmr_blk: 0x608,
            gpe0_blk: 0x620,
            gpe1_blk: 0,
            pm1_evt_len: 4,
            pm1_cnt_len: 2,
            pm_tmr_32bit: true,
            s5_slp_typ_a: 0,
            s5_slp_typ_b: 0,
        }
    }

    /// FADTから設定を読み込み
    pub fn from_fadt(fadt: &Fadt) -> Self {
        Self {
            pm1a_evt_blk: fadt.pm1a_event_block as u16,
            pm1b_evt_blk: fadt.pm1b_event_block as u16,
            pm1a_cnt_blk: fadt.pm1a_control_block as u16,
            pm1b_cnt_blk: fadt.pm1b_control_block as u16,
            pm2_cnt_blk: fadt.pm2_control_block as u16,
            pm_tmr_blk: fadt.pm_timer_block as u16,
            gpe0_blk: fadt.gpe0_block as u16,
            gpe1_blk: fadt.gpe1_block as u16,
            pm1_evt_len: fadt.pm1_event_length,
            pm1_cnt_len: fadt.pm1_control_length,
            pm_tmr_32bit: (fadt.flags & 0x100) != 0,
            s5_slp_typ_a: 0, // S5テーブルから読む必要あり
            s5_slp_typ_b: 0,
        }
    }
}

/// 電源管理統計
pub struct PowerStats {
    /// 現在の電源状態
    pub current_state: AtomicU8,
    /// 状態遷移回数
    pub state_transitions: AtomicU64,
    /// 最終遷移時刻
    pub last_transition: AtomicU64,
    /// 電源ボタン押下回数
    pub power_button_presses: AtomicU64,
    /// スリープボタン押下回数
    pub sleep_button_presses: AtomicU64,
}

impl PowerStats {
    /// 新しい統計を作成
    pub const fn new() -> Self {
        Self {
            current_state: AtomicU8::new(PowerState::Working as u8),
            state_transitions: AtomicU64::new(0),
            last_transition: AtomicU64::new(0),
            power_button_presses: AtomicU64::new(0),
            sleep_button_presses: AtomicU64::new(0),
        }
    }
}

/// 電源管理サブシステム
pub struct PowerManager {
    /// ACPI PM設定
    config: Mutex<AcpiPmConfig>,
    /// 統計情報
    stats: PowerStats,
    /// SCI有効フラグ
    sci_enabled: Mutex<bool>,
}

impl PowerManager {
    /// 新しい電源マネージャーを作成
    pub const fn new() -> Self {
        Self {
            config: Mutex::new(AcpiPmConfig::default()),
            stats: PowerStats::new(),
            sci_enabled: Mutex::new(false),
        }
    }

    /// 設定を更新
    pub fn set_config(&self, config: AcpiPmConfig) {
        *self.config.lock() = config;
    }

    /// ACPI SCI割り込みを有効化
    pub fn enable_sci(&self) {
        let config = self.config.lock();

        if config.pm1a_cnt_blk != 0 {
            unsafe {
                let mut port: Port<u16> = Port::new(config.pm1a_cnt_blk);
                let value = port.read();
                port.write(value | pm1_control::SCI_EN);
            }
        }

        *self.sci_enabled.lock() = true;
    }

    /// PM1ステータスを読み込み
    pub fn read_pm1_status(&self) -> u16 {
        let config = self.config.lock();

        if config.pm1a_evt_blk == 0 {
            return 0;
        }

        unsafe {
            let mut port: Port<u16> = Port::new(config.pm1a_evt_blk);
            port.read()
        }
    }

    /// PM1ステータスをクリア
    pub fn clear_pm1_status(&self, bits: u16) {
        let config = self.config.lock();

        if config.pm1a_evt_blk != 0 {
            unsafe {
                let mut port: Port<u16> = Port::new(config.pm1a_evt_blk);
                port.write(bits); // 1を書くとクリア
            }
        }
    }

    /// PMタイマーを読み込み
    pub fn read_pm_timer(&self) -> u32 {
        let config = self.config.lock();

        if config.pm_tmr_blk == 0 {
            return 0;
        }

        unsafe {
            let mut port: Port<u32> = Port::new(config.pm_tmr_blk);
            let value = port.read();

            // 24ビットまたは32ビットタイマー
            if config.pm_tmr_32bit {
                value
            } else {
                value & 0x00FFFFFF
            }
        }
    }

    /// スリープ状態に遷移 (注意: 実際のスリープは危険)
    pub fn enter_sleep_state(&self, state: PowerState) -> Result<(), &'static str> {
        match state {
            PowerState::Working => {
                // 何もしない
                Ok(())
            }
            PowerState::Standby => {
                // S1状態 (HLT)
                unsafe {
                    core::arch::asm!("hlt");
                }
                Ok(())
            }
            PowerState::SoftOff => {
                // S5状態 (シャットダウン)
                self.shutdown()
            }
            _ => {
                // 他のスリープ状態は未実装
                Err("Sleep state not supported")
            }
        }
    }

    /// システムシャットダウン (ACPI S5)
    pub fn shutdown(&self) -> Result<(), &'static str> {
        let config = self.config.lock();

        if config.pm1a_cnt_blk == 0 {
            return Err("PM1a control block not available");
        }

        // QEMUでは特殊なシャットダウンポートを使用
        // 実機では正式なACPI S5遷移が必要

        // まずQEMUの直接シャットダウンを試行
        unsafe {
            let mut port: Port<u16> = Port::new(0x604);
            port.write(0x2000);
        }

        // それでもシャットダウンしない場合、ACPI経由
        unsafe {
            // SLP_TYP_S5とSLP_ENを設定
            let slp_typ_a = (config.s5_slp_typ_a as u16) << pm1_control::SLP_TYP_SHIFT;
            let value = slp_typ_a | pm1_control::SLP_EN;

            let mut port: Port<u16> = Port::new(config.pm1a_cnt_blk);
            port.write(value);
        }

        // シャットダウンに失敗した場合
        Err("Shutdown failed")
    }

    /// システムリブート
    pub fn reboot(&self) -> Result<(), &'static str> {
        // キーボードコントローラー経由でリブート
        unsafe {
            // 8042リセットコマンド
            let mut cmd_port: Port<u8> = Port::new(0x64);
            let _data_port: Port<u8> = Port::new(0x60);

            // コントローラー準備待ち
            for _ in 0..100000 {
                if cmd_port.read() & 0x02 == 0 {
                    break;
                }
            }

            // リセットコマンド送信
            cmd_port.write(0xFE);
        }

        // それでもリブートしない場合、トリプルフォルト
        // (危険なので通常は使用しない)

        Err("Reboot failed")
    }

    /// 電源ボタンイベントを処理
    pub fn handle_power_button(&self) {
        self.stats
            .power_button_presses
            .fetch_add(1, Ordering::Relaxed);

        // ステータスをクリア
        self.clear_pm1_status(pm1_status::PWRBTN_STS);

        // シャットダウンシーケンスを開始
        // 実際のOSではユーザーに確認を求める
    }

    /// スリープボタンイベントを処理
    pub fn handle_sleep_button(&self) {
        self.stats
            .sleep_button_presses
            .fetch_add(1, Ordering::Relaxed);

        // ステータスをクリア
        self.clear_pm1_status(pm1_status::SLPBTN_STS);

        // スリープモードに遷移
    }

    /// ACPI SCI割り込みハンドラ
    pub fn handle_sci(&self) {
        let status = self.read_pm1_status();

        if status & pm1_status::PWRBTN_STS != 0 {
            self.handle_power_button();
        }

        if status & pm1_status::SLPBTN_STS != 0 {
            self.handle_sleep_button();
        }

        if status & pm1_status::RTC_STS != 0 {
            self.clear_pm1_status(pm1_status::RTC_STS);
            // RTCウェイクアップ処理
        }

        if status & pm1_status::TMR_STS != 0 {
            self.clear_pm1_status(pm1_status::TMR_STS);
            // タイマーオーバーフロー処理
        }
    }

    /// 現在の電源状態を取得
    pub fn current_state(&self) -> PowerState {
        PowerState::from_u8(self.stats.current_state.load(Ordering::Relaxed))
            .unwrap_or(PowerState::Working)
    }

    /// 統計情報を取得
    pub fn stats(&self) -> &PowerStats {
        &self.stats
    }
}

/// CPUアイドル処理
pub struct CpuIdle {
    /// 現在のC状態
    current_state: AtomicU8,
    /// C1使用回数
    c1_count: AtomicU64,
    /// C2使用回数
    c2_count: AtomicU64,
    /// C3使用回数
    c3_count: AtomicU64,
}

impl CpuIdle {
    /// 新しいCPUアイドルマネージャーを作成
    pub const fn new() -> Self {
        Self {
            current_state: AtomicU8::new(CpuPowerState::Active as u8),
            c1_count: AtomicU64::new(0),
            c2_count: AtomicU64::new(0),
            c3_count: AtomicU64::new(0),
        }
    }

    /// アイドル状態に入る (C1 - HLT)
    pub fn idle(&self) {
        self.current_state
            .store(CpuPowerState::Halt as u8, Ordering::Relaxed);
        self.c1_count.fetch_add(1, Ordering::Relaxed);

        // 割り込みを有効にしてHLT
        unsafe {
            core::arch::asm!("sti", "hlt",);
        }

        self.current_state
            .store(CpuPowerState::Active as u8, Ordering::Relaxed);
    }

    /// MWAIT命令でアイドル (より効率的)
    pub fn mwait_idle(&self, _hint: u32) {
        self.current_state
            .store(CpuPowerState::Halt as u8, Ordering::Relaxed);
        self.c1_count.fetch_add(1, Ordering::Relaxed);

        unsafe {
            // MONITORとMWAITは対応CPUでのみ使用可能
            // ここでは簡易実装としてHLTにフォールバック
            core::arch::asm!("sti", "hlt",);
        }

        self.current_state
            .store(CpuPowerState::Active as u8, Ordering::Relaxed);
    }

    /// 現在のC状態を取得
    pub fn current_state(&self) -> CpuPowerState {
        match self.current_state.load(Ordering::Relaxed) {
            0 => CpuPowerState::Active,
            1 => CpuPowerState::Halt,
            2 => CpuPowerState::StopClock,
            3 => CpuPowerState::DeepSleep,
            _ => CpuPowerState::Active,
        }
    }

    /// アイドル統計を取得
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.c1_count.load(Ordering::Relaxed),
            self.c2_count.load(Ordering::Relaxed),
            self.c3_count.load(Ordering::Relaxed),
        )
    }
}

/// グローバル電源マネージャー
static POWER_MANAGER: PowerManager = PowerManager::new();

/// グローバルCPUアイドルマネージャー
static CPU_IDLE: CpuIdle = CpuIdle::new();

/// 電源マネージャーを取得
pub fn power_manager() -> &'static PowerManager {
    &POWER_MANAGER
}

/// CPUアイドルマネージャーを取得
pub fn cpu_idle() -> &'static CpuIdle {
    &CPU_IDLE
}

/// 電源管理を初期化
pub fn init() {
    // ACPI FADTから設定を読み込み
    // 実際の実装ではacpi::find_fadt()などを使用
}

/// FADTから電源管理を初期化
pub fn init_from_fadt(fadt: &Fadt) {
    let config = AcpiPmConfig::from_fadt(fadt);
    POWER_MANAGER.set_config(config);
    POWER_MANAGER.enable_sci();
}

/// システムシャットダウン
pub fn shutdown() -> ! {
    let _ = POWER_MANAGER.shutdown();

    // シャットダウンに失敗した場合は無限ループ
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

/// システムリブート
pub fn reboot() -> ! {
    let _ = POWER_MANAGER.reboot();

    // リブートに失敗した場合は無限ループ
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

/// CPUをアイドル状態にする
pub fn idle() {
    CPU_IDLE.idle();
}
