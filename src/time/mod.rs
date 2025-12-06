//! 時間管理サブシステム
//!
//! システム時計、高精度タイマー、RTC (Real-Time Clock) の管理。
//! TSC, HPET, PIT, RTC など複数のタイマーソースをサポート。

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

/// ナノ秒単位の時間
pub type Nanoseconds = u64;

/// タイムスタンプ (起動からのtick数)
pub type Timestamp = u64;

/// 1秒のナノ秒数
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// 1ミリ秒のナノ秒数
pub const NANOS_PER_MILLI: u64 = 1_000_000;

/// 1マイクロ秒のナノ秒数
pub const NANOS_PER_MICRO: u64 = 1_000;

/// タイマーソースの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerSource {
    /// TSC (Time Stamp Counter)
    TSC,
    /// HPET (High Precision Event Timer)
    HPET,
    /// LAPIC Timer
    LapicTimer,
    /// PIT (Programmable Interval Timer)
    PIT,
    /// ACPI PM Timer
    AcpiPmTimer,
}

/// タイマーソースの情報
pub struct TimerSourceInfo {
    /// ソースの種類
    pub source: TimerSource,
    /// 周波数 (Hz)
    pub frequency: u64,
    /// カウンタのビット幅
    pub counter_bits: u8,
    /// 不変周波数かどうか
    pub invariant: bool,
}

/// TSC情報
pub struct TscInfo {
    /// TSC周波数 (Hz)
    pub frequency: u64,
    /// 不変TSCかどうか
    pub invariant: bool,
    /// ナノ秒からTSCへの変換係数
    pub nanos_to_tsc_mult: u64,
    /// ナノ秒からTSCへの変換シフト
    pub nanos_to_tsc_shift: u8,
}

impl TscInfo {
    /// TSCカウントをナノ秒に変換
    pub fn tsc_to_nanos(&self, tsc: u64) -> u64 {
        if self.frequency == 0 {
            return 0;
        }
        // tsc * 1e9 / frequency をオーバーフローを避けて計算
        let secs = tsc / self.frequency;
        let remainder = tsc % self.frequency;
        secs * NANOS_PER_SEC + (remainder * NANOS_PER_SEC) / self.frequency
    }

    /// ナノ秒をTSCカウントに変換
    pub fn nanos_to_tsc(&self, nanos: u64) -> u64 {
        if self.frequency == 0 {
            return 0;
        }
        let secs = nanos / NANOS_PER_SEC;
        let remainder = nanos % NANOS_PER_SEC;
        secs * self.frequency + (remainder * self.frequency) / NANOS_PER_SEC
    }
}

/// PIT (Programmable Interval Timer) 定数
mod pit {
    pub const CHANNEL0_DATA: u16 = 0x40;
    pub const CHANNEL2_DATA: u16 = 0x42;
    pub const COMMAND: u16 = 0x43;

    /// PITの基本周波数 (Hz)
    pub const BASE_FREQUENCY: u64 = 1193182;

    // モードコマンド
    pub const MODE_SQUARE_WAVE: u8 = 0x36; // Channel 0, Mode 3
    pub const MODE_ONE_SHOT: u8 = 0x30; // Channel 0, Mode 0
    pub const MODE_RATE_GEN: u8 = 0x34; // Channel 0, Mode 2
    pub const READBACK: u8 = 0xE2; // Read-back command
}

/// RTC (Real-Time Clock) 定数
mod rtc {
    pub const CMOS_ADDR: u16 = 0x70;
    pub const CMOS_DATA: u16 = 0x71;

    // RTCレジスタ
    pub const SECONDS: u8 = 0x00;
    pub const MINUTES: u8 = 0x02;
    pub const HOURS: u8 = 0x04;
    pub const DAY_OF_WEEK: u8 = 0x06;
    pub const DAY_OF_MONTH: u8 = 0x07;
    pub const MONTH: u8 = 0x08;
    pub const YEAR: u8 = 0x09;
    pub const CENTURY: u8 = 0x32; // ACPIで定義

    pub const STATUS_A: u8 = 0x0A;
    pub const STATUS_B: u8 = 0x0B;
    pub const STATUS_C: u8 = 0x0C;
}

/// RTC日時構造体
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    /// Unixエポック (1970-01-01 00:00:00)
    pub const UNIX_EPOCH: Self = Self {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    /// Unixタイムスタンプに変換
    pub fn to_unix_timestamp(&self) -> i64 {
        // 簡易計算 (うるう年を考慮)
        let mut days: i64 = 0;

        // 1970年からの年数
        for year in 1970..self.year as i64 {
            days += if Self::is_leap_year(year as u16) {
                366
            } else {
                365
            };
        }

        // 今年の月日
        static DAYS_BEFORE_MONTH: [i64; 12] =
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        if self.month >= 1 && self.month <= 12 {
            days += DAYS_BEFORE_MONTH[(self.month - 1) as usize];
            // うるう年の3月以降は+1日
            if self.month > 2 && Self::is_leap_year(self.year) {
                days += 1;
            }
        }
        days += (self.day as i64) - 1;

        // 秒に変換
        days * 86400 + (self.hour as i64) * 3600 + (self.minute as i64) * 60 + (self.second as i64)
    }

    /// うるう年か判定
    fn is_leap_year(year: u16) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
}

/// RTCドライバ
pub struct Rtc {
    /// NMI無効化状態を保持
    nmi_disable: bool,
}

impl Rtc {
    /// 新しいRTCドライバを作成
    pub const fn new() -> Self {
        Self { nmi_disable: false }
    }

    /// CMOSレジスタを読み込み
    fn read_cmos(&self, reg: u8) -> u8 {
        let nmi_bit = if self.nmi_disable { 0x80 } else { 0x00 };

        unsafe {
            let mut addr_port: Port<u8> = Port::new(rtc::CMOS_ADDR);
            let mut data_port: Port<u8> = Port::new(rtc::CMOS_DATA);

            addr_port.write(reg | nmi_bit);
            data_port.read()
        }
    }

    /// CMOSレジスタに書き込み
    fn write_cmos(&self, reg: u8, value: u8) {
        let nmi_bit = if self.nmi_disable { 0x80 } else { 0x00 };

        unsafe {
            let mut addr_port: Port<u8> = Port::new(rtc::CMOS_ADDR);
            let mut data_port: Port<u8> = Port::new(rtc::CMOS_DATA);

            addr_port.write(reg | nmi_bit);
            data_port.write(value);
        }
    }

    /// RTC更新中かチェック
    fn update_in_progress(&self) -> bool {
        self.read_cmos(rtc::STATUS_A) & 0x80 != 0
    }

    /// BCDをバイナリに変換
    fn bcd_to_binary(value: u8) -> u8 {
        (value & 0x0F) + ((value >> 4) * 10)
    }

    /// 現在の日時を読み取り
    pub fn read_datetime(&self) -> DateTime {
        // 更新中は待機
        while self.update_in_progress() {}

        // 2回読んで一致するまで繰り返す (更新中の読み取りを防ぐ)
        loop {
            let first = self.read_datetime_internal();
            let second = self.read_datetime_internal();

            if first == second {
                return first;
            }
        }
    }

    fn read_datetime_internal(&self) -> DateTime {
        let status_b = self.read_cmos(rtc::STATUS_B);
        let is_binary = status_b & 0x04 != 0;
        let is_24h = status_b & 0x02 != 0;

        let mut second = self.read_cmos(rtc::SECONDS);
        let mut minute = self.read_cmos(rtc::MINUTES);
        let mut hour = self.read_cmos(rtc::HOURS);
        let mut day = self.read_cmos(rtc::DAY_OF_MONTH);
        let mut month = self.read_cmos(rtc::MONTH);
        let mut year = self.read_cmos(rtc::YEAR);
        let century = self.read_cmos(rtc::CENTURY);

        // BCDから変換
        if !is_binary {
            second = Self::bcd_to_binary(second);
            minute = Self::bcd_to_binary(minute);
            day = Self::bcd_to_binary(day);
            month = Self::bcd_to_binary(month);
            year = Self::bcd_to_binary(year);

            // 時間は特殊処理 (12時間形式の場合)
            if !is_24h && (hour & 0x80) != 0 {
                hour = ((Self::bcd_to_binary(hour & 0x7F) + 12) % 24) as u8;
            } else {
                hour = Self::bcd_to_binary(hour);
            }
        }

        // 年の補正
        let full_year = if century != 0 && century != 0xFF {
            Self::bcd_to_binary(century) as u16 * 100 + year as u16
        } else if year < 70 {
            2000 + year as u16
        } else {
            1900 + year as u16
        };

        DateTime {
            year: full_year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

/// システム時計
pub struct SystemClock {
    /// 起動時刻 (Unixタイムスタンプ)
    boot_time: AtomicU64,
    /// 起動からの経過ナノ秒
    uptime_nanos: AtomicU64,
    /// 使用中のタイマーソース
    timer_source: Mutex<TimerSource>,
    /// TSC情報
    tsc_info: Mutex<Option<TscInfo>>,
    /// 最後に読んだTSC値
    last_tsc: AtomicU64,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl SystemClock {
    /// 新しいシステム時計を作成
    pub const fn new() -> Self {
        Self {
            boot_time: AtomicU64::new(0),
            uptime_nanos: AtomicU64::new(0),
            timer_source: Mutex::new(TimerSource::PIT),
            tsc_info: Mutex::new(None),
            last_tsc: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    /// 起動時刻を設定
    pub fn set_boot_time(&self, unix_timestamp: u64) {
        self.boot_time.store(unix_timestamp, Ordering::SeqCst);
    }

    /// 起動時刻を取得 (Unixタイムスタンプ)
    pub fn boot_time(&self) -> u64 {
        self.boot_time.load(Ordering::SeqCst)
    }

    /// 稼働時間を取得 (ナノ秒)
    pub fn uptime_nanos(&self) -> u64 {
        self.uptime_nanos.load(Ordering::Relaxed)
    }

    /// 稼働時間を取得 (ミリ秒)
    pub fn uptime_millis(&self) -> u64 {
        self.uptime_nanos() / NANOS_PER_MILLI
    }

    /// 稼働時間を取得 (秒)
    pub fn uptime_secs(&self) -> u64 {
        self.uptime_nanos() / NANOS_PER_SEC
    }

    /// 現在のUnixタイムスタンプを取得
    pub fn now(&self) -> u64 {
        self.boot_time() + (self.uptime_nanos() / NANOS_PER_SEC)
    }

    /// 稼働時間を更新 (タイマー割り込みから呼ばれる)
    pub fn tick(&self, delta_nanos: u64) {
        self.uptime_nanos.fetch_add(delta_nanos, Ordering::Relaxed);
    }

    /// TSCを読み取り
    pub fn read_tsc(&self) -> u64 {
        let value = unsafe { core::arch::x86_64::_rdtsc() };
        self.last_tsc.store(value, Ordering::Relaxed);
        value
    }

    /// TSC情報を設定
    pub fn set_tsc_info(&self, info: TscInfo) {
        *self.tsc_info.lock() = Some(info);
        *self.timer_source.lock() = TimerSource::TSC;
    }

    /// 高精度な時刻を取得 (ナノ秒)
    pub fn precise_time_nanos(&self) -> u64 {
        if let Some(ref tsc_info) = *self.tsc_info.lock() {
            let tsc = self.read_tsc();
            return tsc_info.tsc_to_nanos(tsc);
        }

        self.uptime_nanos()
    }

    /// 使用中のタイマーソースを取得
    pub fn timer_source(&self) -> TimerSource {
        *self.timer_source.lock()
    }
}

/// PITドライバ
pub struct Pit {
    /// 現在の周波数
    frequency: Mutex<u64>,
}

impl Pit {
    /// 新しいPITドライバを作成
    pub const fn new() -> Self {
        Self {
            frequency: Mutex::new(0),
        }
    }

    /// PITを指定周波数で初期化
    pub fn init(&self, frequency: u64) {
        let divisor = pit::BASE_FREQUENCY / frequency;
        let divisor = divisor.max(1).min(65535) as u16;

        unsafe {
            let mut cmd_port: Port<u8> = Port::new(pit::COMMAND);
            let mut data_port: Port<u8> = Port::new(pit::CHANNEL0_DATA);

            // Channel 0, Mode 3 (Square wave), 16-bit
            cmd_port.write(pit::MODE_SQUARE_WAVE);

            // 分周比を設定 (Low byte, High byte)
            data_port.write((divisor & 0xFF) as u8);
            data_port.write((divisor >> 8) as u8);
        }

        let actual_freq = pit::BASE_FREQUENCY / divisor as u64;
        *self.frequency.lock() = actual_freq;
    }

    /// ワンショットディレイ (ビジーウェイト)
    pub fn delay_us(&self, microseconds: u64) {
        let ticks = (pit::BASE_FREQUENCY * microseconds) / 1_000_000;
        let ticks = ticks.max(1).min(65535) as u16;

        unsafe {
            let mut cmd_port: Port<u8> = Port::new(pit::COMMAND);
            let mut data_port: Port<u8> = Port::new(pit::CHANNEL0_DATA);

            // Channel 0, Mode 0 (One-shot), 16-bit
            cmd_port.write(pit::MODE_ONE_SHOT);

            // カウント値を設定
            data_port.write((ticks & 0xFF) as u8);
            data_port.write((ticks >> 8) as u8);

            // カウント完了を待機
            loop {
                cmd_port.write(pit::READBACK);
                let status = data_port.read();
                if status & 0x80 != 0 {
                    break;
                }
            }
        }
    }

    /// 現在の周波数を取得
    pub fn frequency(&self) -> u64 {
        *self.frequency.lock()
    }
}

/// TSC周波数をキャリブレーション
pub fn calibrate_tsc() -> Option<TscInfo> {
    // CPUIDでTSC周波数を取得できるか確認
    // 簡易実装: PITを使ってTSC周波数を測定

    // 10ms間のTSCカウントを測定
    let pit_ticks = (pit::BASE_FREQUENCY / 100) as u16; // 10ms

    unsafe {
        let mut cmd_port: Port<u8> = Port::new(pit::COMMAND);
        let mut data_port: Port<u8> = Port::new(pit::CHANNEL0_DATA);

        // Channel 0, Mode 0 (One-shot), 16-bit
        cmd_port.write(pit::MODE_ONE_SHOT);

        let start_tsc = core::arch::x86_64::_rdtsc();

        // カウント値を設定
        data_port.write((pit_ticks & 0xFF) as u8);
        data_port.write((pit_ticks >> 8) as u8);

        // カウント完了を待機
        loop {
            cmd_port.write(0xE2); // Read-back
            let status = data_port.read();
            if status & 0x80 != 0 {
                break;
            }
        }

        let end_tsc = core::arch::x86_64::_rdtsc();

        let tsc_diff = end_tsc.saturating_sub(start_tsc);
        let frequency = tsc_diff * 100; // 10ms → 1秒に換算

        // 不変TSCかどうかはCPUIDで確認 (簡易実装では常にtrue)
        Some(TscInfo {
            frequency,
            invariant: true,
            nanos_to_tsc_mult: 0,
            nanos_to_tsc_shift: 0,
        })
    }
}

/// グローバルシステム時計
static SYSTEM_CLOCK: SystemClock = SystemClock::new();

/// グローバルRTCドライバ
static RTC: Rtc = Rtc::new();

/// グローバルPITドライバ
static PIT: Pit = Pit::new();

/// システム時計を取得
pub fn system_clock() -> &'static SystemClock {
    &SYSTEM_CLOCK
}

/// RTCを取得
pub fn rtc() -> &'static Rtc {
    &RTC
}

/// PITを取得
pub fn pit() -> &'static Pit {
    &PIT
}

/// 時間管理を初期化
pub fn init(tick_frequency: u64) {
    // PITを初期化
    PIT.init(tick_frequency);

    // RTCから現在時刻を読み取り
    let datetime = RTC.read_datetime();
    let boot_time = datetime.to_unix_timestamp() as u64;
    SYSTEM_CLOCK.set_boot_time(boot_time);

    // TSCをキャリブレーション
    if let Some(tsc_info) = calibrate_tsc() {
        SYSTEM_CLOCK.set_tsc_info(tsc_info);
    }
}

/// タイマーティック (割り込みハンドラから呼ばれる)
pub fn tick(delta_nanos: u64) {
    SYSTEM_CLOCK.tick(delta_nanos);
}

/// 現在の稼働時間を取得 (tick)
pub fn current_tick() -> u64 {
    SYSTEM_CLOCK.uptime_millis()
}

/// 現在のUnixタイムスタンプを取得
pub fn now() -> u64 {
    SYSTEM_CLOCK.now()
}

/// 高精度な時刻を取得 (ナノ秒)
pub fn precise_time_nanos() -> u64 {
    SYSTEM_CLOCK.precise_time_nanos()
}
