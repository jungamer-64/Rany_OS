// ============================================================================
// src/io/rtc.rs - Real Time Clock Driver
// ============================================================================
//!
//! # RTC (Real Time Clock) ドライバ
//!
//! CMOSリアルタイムクロックのドライバ。
//!
//! ## 機能
//! - 日時の読み取り・設定
//! - 周期的割り込み
//! - アラーム割り込み
//! - NTP同期サポート

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ============================================================================
// RTC Constants
// ============================================================================

/// CMOSポート
const CMOS_ADDRESS: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

/// CMOSレジスタ
mod regs {
    pub const SECONDS: u8 = 0x00;
    pub const SECONDS_ALARM: u8 = 0x01;
    pub const MINUTES: u8 = 0x02;
    pub const MINUTES_ALARM: u8 = 0x03;
    pub const HOURS: u8 = 0x04;
    pub const HOURS_ALARM: u8 = 0x05;
    pub const DAY_OF_WEEK: u8 = 0x06;
    pub const DAY_OF_MONTH: u8 = 0x07;
    pub const MONTH: u8 = 0x08;
    pub const YEAR: u8 = 0x09;
    pub const STATUS_A: u8 = 0x0A;
    pub const STATUS_B: u8 = 0x0B;
    pub const STATUS_C: u8 = 0x0C;
    pub const STATUS_D: u8 = 0x0D;
    pub const CENTURY: u8 = 0x32; // ACPIで定義される場合
}

/// ステータスAビット
mod status_a {
    pub const UPDATE_IN_PROGRESS: u8 = 0x80;
    pub const DIVIDER_MASK: u8 = 0x70;
    pub const RATE_MASK: u8 = 0x0F;
}

/// ステータスBビット
mod status_b {
    pub const DAYLIGHT_SAVING: u8 = 0x01;
    pub const HOUR_24: u8 = 0x02;
    pub const BINARY_MODE: u8 = 0x04;
    pub const SQUARE_WAVE: u8 = 0x08;
    pub const UPDATE_ENDED_INT: u8 = 0x10;
    pub const ALARM_INT: u8 = 0x20;
    pub const PERIODIC_INT: u8 = 0x40;
    pub const SET: u8 = 0x80;
}

// ============================================================================
// Date and Time Types
// ============================================================================

/// 日時
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub day_of_week: u8, // 1=日曜日, 7=土曜日
}

impl DateTime {
    /// Unix時間に変換（1970年1月1日からの秒数）
    pub fn to_unix_timestamp(&self) -> i64 {
        // 簡易計算（閏年の厳密な計算は省略）
        let mut days: i64 = 0;

        // 年の計算
        for y in 1970..self.year as i64 {
            if is_leap_year(y as u16) {
                days += 366;
            } else {
                days += 365;
            }
        }

        // 月の計算
        let days_in_month = if is_leap_year(self.year) {
            [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        for m in 1..self.month {
            days += days_in_month[m as usize] as i64;
        }

        days += self.day as i64 - 1;

        // 秒に変換
        days * 86400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64
    }

    /// Unix時間から変換
    pub fn from_unix_timestamp(timestamp: i64) -> Self {
        let mut remaining = timestamp;

        // 秒・分・時を計算
        let second = (remaining % 60) as u8;
        remaining /= 60;
        let minute = (remaining % 60) as u8;
        remaining /= 60;
        let hour = (remaining % 24) as u8;
        remaining /= 24;

        // 曜日を計算（1970年1月1日は木曜日）
        let day_of_week = ((remaining + 4) % 7 + 1) as u8;

        // 年を計算
        let mut year: u16 = 1970;
        loop {
            let days_in_year = if is_leap_year(year) { 366 } else { 365 };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            year += 1;
        }

        // 月を計算
        let days_in_month = if is_leap_year(year) {
            [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut month: u8 = 1;
        while month <= 12 && remaining >= days_in_month[month as usize] as i64 {
            remaining -= days_in_month[month as usize] as i64;
            month += 1;
        }

        let day = remaining as u8 + 1;

        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            day_of_week,
        }
    }
}

impl core::fmt::Display for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// 閏年判定
fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ============================================================================
// RTC Driver
// ============================================================================

/// RTCドライバ
pub struct Rtc {
    /// バイナリモードか
    binary_mode: bool,
    /// 24時間モードか
    hour_24: bool,
    /// 世紀レジスタのアドレス（ACPIから取得）
    century_register: Option<u8>,
}

impl Rtc {
    /// CMOSレジスタを読み取り
    unsafe fn read_cmos(reg: u8) -> u8 {
        // NMIを無効化しながらアドレスを設定
        let address = (reg & 0x7F) | 0x80;
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_ADDRESS,
            in("al") address,
            options(nomem, nostack)
        );
        // 少し待機
        core::arch::asm!("jmp 2f", "2:", options(nomem, nostack));

        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") CMOS_DATA,
            options(nomem, nostack)
        );
        value
    }

    /// CMOSレジスタに書き込み
    unsafe fn write_cmos(reg: u8, value: u8) {
        let address = (reg & 0x7F) | 0x80;
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_ADDRESS,
            in("al") address,
            options(nomem, nostack)
        );
        core::arch::asm!("jmp 2f", "2:", options(nomem, nostack));
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_DATA,
            in("al") value,
            options(nomem, nostack)
        );
    }

    /// 更新中かどうかを確認
    unsafe fn is_update_in_progress() -> bool {
        (Self::read_cmos(regs::STATUS_A) & status_a::UPDATE_IN_PROGRESS) != 0
    }

    /// BCDをバイナリに変換
    fn bcd_to_binary(bcd: u8) -> u8 {
        (bcd & 0x0F) + ((bcd >> 4) * 10)
    }

    /// バイナリをBCDに変換
    fn binary_to_bcd(bin: u8) -> u8 {
        ((bin / 10) << 4) | (bin % 10)
    }

    /// 新しいRTCドライバを作成
    pub fn new() -> Self {
        let status_b = unsafe { Self::read_cmos(regs::STATUS_B) };
        Self {
            binary_mode: (status_b & status_b::BINARY_MODE) != 0,
            hour_24: (status_b & status_b::HOUR_24) != 0,
            century_register: None,
        }
    }

    /// 世紀レジスタを設定（ACPIから取得した場合）
    pub fn set_century_register(&mut self, reg: u8) {
        self.century_register = Some(reg);
    }

    /// 現在時刻を読み取り
    pub fn read_datetime(&self) -> DateTime {
        unsafe {
            // 更新が完了するまで待機
            while Self::is_update_in_progress() {}

            // 値を読み取り
            let second = Self::read_cmos(regs::SECONDS);
            let minute = Self::read_cmos(regs::MINUTES);
            let mut hour = Self::read_cmos(regs::HOURS);
            let day = Self::read_cmos(regs::DAY_OF_MONTH);
            let month = Self::read_cmos(regs::MONTH);
            let year = Self::read_cmos(regs::YEAR);
            let day_of_week = Self::read_cmos(regs::DAY_OF_WEEK);

            let century = if let Some(reg) = self.century_register {
                Self::read_cmos(reg)
            } else {
                0x20 // デフォルトで21世紀
            };

            // BCDの場合は変換
            let (second, minute, hour, day, month, year, century) = if !self.binary_mode {
                (
                    Self::bcd_to_binary(second),
                    Self::bcd_to_binary(minute),
                    {
                        let pm = (hour & 0x80) != 0;
                        let h = Self::bcd_to_binary(hour & 0x7F);
                        if !self.hour_24 && pm {
                            (h % 12) + 12
                        } else {
                            h
                        }
                    },
                    Self::bcd_to_binary(day),
                    Self::bcd_to_binary(month),
                    Self::bcd_to_binary(year),
                    Self::bcd_to_binary(century),
                )
            } else {
                let pm = (hour & 0x80) != 0;
                let h = hour & 0x7F;
                let adjusted_hour = if !self.hour_24 && pm {
                    (h % 12) + 12
                } else {
                    h
                };
                (second, minute, adjusted_hour, day, month, year, century)
            };

            let full_year = century as u16 * 100 + year as u16;

            DateTime {
                year: full_year,
                month,
                day,
                hour,
                minute,
                second,
                day_of_week,
            }
        }
    }

    /// 時刻を設定
    pub fn write_datetime(&self, dt: &DateTime) {
        unsafe {
            // ステータスBのSETビットを立てて更新を停止
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::SET);

            // 値を変換
            let (second, minute, hour, day, month, year, century) = if !self.binary_mode {
                (
                    Self::binary_to_bcd(dt.second),
                    Self::binary_to_bcd(dt.minute),
                    Self::binary_to_bcd(dt.hour),
                    Self::binary_to_bcd(dt.day),
                    Self::binary_to_bcd(dt.month),
                    Self::binary_to_bcd((dt.year % 100) as u8),
                    Self::binary_to_bcd((dt.year / 100) as u8),
                )
            } else {
                (
                    dt.second,
                    dt.minute,
                    dt.hour,
                    dt.day,
                    dt.month,
                    (dt.year % 100) as u8,
                    (dt.year / 100) as u8,
                )
            };

            // 書き込み
            Self::write_cmos(regs::SECONDS, second);
            Self::write_cmos(regs::MINUTES, minute);
            Self::write_cmos(regs::HOURS, hour);
            Self::write_cmos(regs::DAY_OF_MONTH, day);
            Self::write_cmos(regs::MONTH, month);
            Self::write_cmos(regs::YEAR, year);
            Self::write_cmos(regs::DAY_OF_WEEK, dt.day_of_week);

            if let Some(reg) = self.century_register {
                Self::write_cmos(reg, century);
            }

            // SETビットをクリア
            Self::write_cmos(regs::STATUS_B, status_b);
        }
    }

    /// アラームを設定
    pub fn set_alarm(&self, hour: u8, minute: u8, second: u8) {
        unsafe {
            let (h, m, s) = if !self.binary_mode {
                (
                    Self::binary_to_bcd(hour),
                    Self::binary_to_bcd(minute),
                    Self::binary_to_bcd(second),
                )
            } else {
                (hour, minute, second)
            };

            Self::write_cmos(regs::HOURS_ALARM, h);
            Self::write_cmos(regs::MINUTES_ALARM, m);
            Self::write_cmos(regs::SECONDS_ALARM, s);

            // アラーム割り込みを有効化
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::ALARM_INT);
        }
    }

    /// 周期的割り込みを設定
    /// rate: 3-15の値、周期 = 32768 >> (rate - 1) Hz
    pub fn set_periodic_interrupt(&self, rate: u8) {
        let rate = rate.clamp(3, 15);
        unsafe {
            let status_a = Self::read_cmos(regs::STATUS_A);
            Self::write_cmos(regs::STATUS_A, (status_a & !status_a::RATE_MASK) | rate);

            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::PERIODIC_INT);
        }
    }

    /// 割り込みを無効化
    pub fn disable_interrupts(&self) {
        unsafe {
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(
                regs::STATUS_B,
                status_b
                    & !(status_b::PERIODIC_INT | status_b::ALARM_INT | status_b::UPDATE_ENDED_INT),
            );
        }
    }

    /// 割り込みステータスを読み取り（これにより割り込みがクリアされる）
    pub fn read_interrupt_status(&self) -> InterruptStatus {
        let status_c = unsafe { Self::read_cmos(regs::STATUS_C) };
        InterruptStatus {
            update_ended: (status_c & 0x10) != 0,
            alarm: (status_c & 0x20) != 0,
            periodic: (status_c & 0x40) != 0,
            irq: (status_c & 0x80) != 0,
        }
    }
}

/// 割り込みステータス
#[derive(Clone, Copy, Debug)]
pub struct InterruptStatus {
    pub update_ended: bool,
    pub alarm: bool,
    pub periodic: bool,
    pub irq: bool,
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルRTC
static RTC: Mutex<Option<Rtc>> = Mutex::new(None);

/// システム起動時からの秒数
static SYSTEM_TIME: AtomicU64 = AtomicU64::new(0);

/// 起動時のUnixタイムスタンプ
static BOOT_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// RTCを初期化
pub fn init() {
    let rtc = Rtc::new();
    let datetime = rtc.read_datetime();
    let timestamp = datetime.to_unix_timestamp();

    if timestamp > 0 {
        BOOT_TIMESTAMP.store(timestamp as u64, Ordering::SeqCst);
    }

    *RTC.lock() = Some(rtc);
}

/// 現在時刻を取得
pub fn get_datetime() -> Option<DateTime> {
    RTC.lock().as_ref().map(|rtc| rtc.read_datetime())
}

/// 時刻を設定
pub fn set_datetime(dt: &DateTime) {
    if let Some(ref rtc) = *RTC.lock() {
        rtc.write_datetime(dt);
    }
}

/// 現在のUnixタイムスタンプを取得
pub fn get_unix_timestamp() -> i64 {
    BOOT_TIMESTAMP.load(Ordering::SeqCst) as i64 + SYSTEM_TIME.load(Ordering::SeqCst) as i64
}

/// システム起動時間（秒）を取得
pub fn get_uptime_seconds() -> u64 {
    SYSTEM_TIME.load(Ordering::SeqCst)
}

/// 周期的割り込みハンドラ（例: 1024Hz）
pub fn periodic_interrupt_handler() {
    // ステータスCを読み取って割り込みをクリア
    if let Some(ref rtc) = *RTC.lock() {
        let status = rtc.read_interrupt_status();
        if status.periodic {
            // 内部カウンタを更新
            static TICKS: AtomicU64 = AtomicU64::new(0);
            let ticks = TICKS.fetch_add(1, Ordering::SeqCst);
            // 1024Hzの場合、1024ティックで1秒
            if ticks % 1024 == 0 {
                SYSTEM_TIME.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// RTC割り込みハンドラ
pub fn rtc_interrupt_handler() {
    if let Some(ref rtc) = *RTC.lock() {
        let _status = rtc.read_interrupt_status();
        // 必要に応じて処理を追加
    }
}
