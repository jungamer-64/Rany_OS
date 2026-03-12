// ============================================================================
// kernel/src/time/mod.rs
// ============================================================================
//! 時間管理サブシステム
//!
//! システム時計、高精度タイマー、RTC (Real-Time Clock) の管理。
//! TSC, HPET, PIT, RTC など複数のタイマーソースをサポート。

#![allow(dead_code)]
#![allow(unused_variables)]

use crate::sync::{IrqPoisonLock, PoisonLock};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use hal::port_io::{IoPort, PortU8};

/// ナノ秒単位の時間
mod api;
pub use api::*;
pub type Nanoseconds = u64;

/// タイムスタンプ (起動からのtick数)
pub type Timestamp = u64;

/// 1秒のナノ秒数
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// 1ミリ秒のナノ秒数
pub const NANOS_PER_MILLI: u64 = 1_000_000;

/// 1マイクロ秒のナノ秒数
pub const NANOS_PER_MICRO: u64 = 1_000;

#[inline]
fn spin_until_or_limit<F>(mut should_continue: F, max_spins: u32) -> bool
where
    F: FnMut() -> bool,
{
    // LOOP_PROOF: mode=condition; reason=Helper loop is bounded by max_spins and exits early when the observed hardware condition clears.;
    for _ in 0..max_spins {
        if !should_continue() {
            return true;
        }
        core::hint::spin_loop();
    }
    !should_continue()
}

/// Read the Time Stamp Counter (TSC) with LFENCE serialization
#[inline]
pub fn rdtsc() -> u64 {
    unsafe {
        // LFENCE ensures all prior instructions complete before reading TSC
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
}

/// Read TSC without serialization (for non-critical paths)
#[inline]
pub fn rdtsc_unserialized() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

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
#[derive(Clone)]
pub struct TscInfo {
    /// TSC周波数 (Hz)
    pub frequency: u64,
    /// 不変TSCかどうか
    pub invariant: bool,
    /// TSC→ナノ秒変換係数 (固定小数点): nanos = (tsc * mult) >> shift
    pub tsc_to_nanos_mult: u64,
    /// TSC→ナノ秒変換シフト
    pub tsc_to_nanos_shift: u8,
}

impl TscInfo {
    /// 新しいTscInfoを作成し、固定小数点変換係数を計算
    pub fn new(frequency: u64, invariant: bool) -> Self {
        let (mult, shift) = compute_tsc_mult_shift(frequency);
        Self {
            frequency,
            invariant,
            tsc_to_nanos_mult: mult,
            tsc_to_nanos_shift: shift,
        }
    }

    /// TSCカウントをナノ秒に変換 (固定小数点最適化版)
    #[inline]
    pub fn tsc_to_nanos(&self, tsc: u64) -> u64 {
        if self.tsc_to_nanos_mult == 0 {
            if self.frequency == 0 {
                return 0;
            }
            let nanos = (tsc as u128 * NANOS_PER_SEC as u128) / self.frequency as u128;
            return nanos as u64;
        }
        let result = (tsc as u128 * self.tsc_to_nanos_mult as u128) >> self.tsc_to_nanos_shift;
        result as u64
    }

    /// TSCカウントをナノ秒に変換 (u128除算版、精度保証)
    #[inline]
    pub fn tsc_to_nanos_precise(&self, tsc: u64) -> u64 {
        if self.frequency == 0 {
            return 0;
        }
        let nanos = (tsc as u128 * NANOS_PER_SEC as u128) / self.frequency as u128;
        nanos as u64
    }

    /// ナノ秒をTSCカウントに変換
    pub fn nanos_to_tsc(&self, nanos: u64) -> u64 {
        if self.frequency == 0 {
            return 0;
        }
        let tsc = (nanos as u128 * self.frequency as u128) / NANOS_PER_SEC as u128;
        tsc as u64
    }
}

fn compute_tsc_mult_shift(frequency: u64) -> (u64, u8) {
    if frequency == 0 {
        return (0, 0);
    }

    for shift in (0..=63).rev() {
        let numerator = (NANOS_PER_SEC as u128) << shift;
        let mult = numerator / frequency as u128;

        if mult <= u64::MAX as u128 {
            return (mult as u64, shift);
        }
    }

    ((NANOS_PER_SEC / frequency), 0)
}

/// PIT (Programmable Interval Timer) 定数
mod pit {
    pub const CHANNEL0_DATA: u16 = 0x40;
    pub const CHANNEL2_DATA: u16 = 0x42;
    pub const COMMAND: u16 = 0x43;
    pub const SPEAKER_PORT: u16 = 0x61;
    pub const BASE_FREQUENCY: u64 = 1193182;
    pub const MODE_SQUARE_WAVE: u8 = 0x36;
    pub const MODE_ONE_SHOT: u8 = 0x30;
    pub const MODE_RATE_GEN: u8 = 0x34;
    pub const READBACK: u8 = 0xE2;
    pub const CH2_MODE_ONE_SHOT: u8 = 0xB0;
}

/// RTC (Real-Time Clock) 定数
mod rtc {
    pub const CMOS_ADDR: u16 = 0x70;
    pub const CMOS_DATA: u16 = 0x71;
    pub const SECONDS: u8 = 0x00;
    pub const MINUTES: u8 = 0x02;
    pub const HOURS: u8 = 0x04;
    pub const DAY_OF_WEEK: u8 = 0x06;
    pub const DAY_OF_MONTH: u8 = 0x07;
    pub const MONTH: u8 = 0x08;
    pub const YEAR: u8 = 0x09;
    pub const CENTURY: u8 = 0x32;
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
    pub const UNIX_EPOCH: Self = Self {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    pub fn to_unix_timestamp_safe(&self) -> Option<u64> {
        if self.year < 1970 {
            return None;
        }
        let ts = self.to_unix_timestamp();
        if ts < 0 { None } else { Some(ts as u64) }
    }

    pub fn to_unix_timestamp(&self) -> i64 {
        let mut days: i64 = 0;
        for year in 1970..self.year as i64 {
            days += if Self::is_leap_year(year as u16) {
                366
            } else {
                365
            };
        }
        static DAYS_BEFORE_MONTH: [i64; 12] =
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        if self.month >= 1 && self.month <= 12 {
            days += DAYS_BEFORE_MONTH[(self.month - 1) as usize];
            if self.month > 2 && Self::is_leap_year(self.year) {
                days += 1;
            }
        }
        days += (self.day as i64) - 1;
        days * 86400 + (self.hour as i64) * 3600 + (self.minute as i64) * 60 + (self.second as i64)
    }

    fn is_leap_year(year: u16) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
}

/// CMOS ポートアクセス用のグローバルロック
static CMOS_LOCK: IrqPoisonLock<()> = IrqPoisonLock::new(());

/// RTCドライバ
pub struct Rtc;

impl Rtc {
    pub const fn new() -> Self {
        Self
    }

    fn read_cmos(&self, reg: u8) -> u8 {
        let _guard = CMOS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut addr_port: PortU8 = IoPort::new(rtc::CMOS_ADDR);
        let mut data_port: PortU8 = IoPort::new(rtc::CMOS_DATA);
        addr_port.write(reg);
        data_port.read()
    }

    fn write_cmos(&self, reg: u8, value: u8) {
        let _guard = CMOS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut addr_port: PortU8 = IoPort::new(rtc::CMOS_ADDR);
        let mut data_port: PortU8 = IoPort::new(rtc::CMOS_DATA);
        addr_port.write(reg);
        data_port.write(value);
    }

    fn update_in_progress(&self) -> bool {
        self.read_cmos(rtc::STATUS_A) & 0x80 != 0
    }

    fn bcd_to_binary(value: u8) -> u8 {
        (value & 0x0F) + ((value >> 4) * 10)
    }

    fn decode_bcd(value: u8, is_binary: bool) -> u8 {
        if is_binary {
            value
        } else {
            Self::bcd_to_binary(value)
        }
    }

    fn decode_hour(raw: u8, is_binary: bool, is_24h: bool) -> u8 {
        let pm = (raw & 0x80) != 0;
        let h = raw & 0x7F;
        let hour_val = if is_binary { h } else { Self::bcd_to_binary(h) };
        if is_24h {
            hour_val
        } else {
            match (hour_val, pm) {
                (12, false) => 0,
                (12, true) => 12,
                (h, false) => h,
                (h, true) => h + 12,
            }
        }
    }

    pub fn read_datetime(&self) -> DateTime {
        const MAX_RETRIES: u32 = 3;
        const MAX_UPDATE_WAIT: u32 = 10000;
        let _ = spin_until_or_limit(|| self.update_in_progress(), MAX_UPDATE_WAIT);

        for retry in 0..MAX_RETRIES {
            let first = self.read_datetime_internal();
            let second = self.read_datetime_internal();
            if first == second {
                return first;
            }
            if retry + 1 == MAX_RETRIES {
                return second;
            }
            core::hint::spin_loop();
        }

        self.read_datetime_internal()
    }

    fn read_datetime_internal(&self) -> DateTime {
        let _guard = CMOS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut addr_port: PortU8 = IoPort::new(rtc::CMOS_ADDR);
        let mut data_port: PortU8 = IoPort::new(rtc::CMOS_DATA);
        let mut read_cmos_raw = |reg| {
            addr_port.write(reg);
            data_port.read()
        };
        let status_b = read_cmos_raw(rtc::STATUS_B);
        let is_binary = status_b & 0x04 != 0;
        let is_24h = status_b & 0x02 != 0;
        let second = Self::decode_bcd(read_cmos_raw(rtc::SECONDS), is_binary);
        let minute = Self::decode_bcd(read_cmos_raw(rtc::MINUTES), is_binary);
        let hour = Self::decode_hour(read_cmos_raw(rtc::HOURS), is_binary, is_24h);
        let day = Self::decode_bcd(read_cmos_raw(rtc::DAY_OF_MONTH), is_binary);
        let month = Self::decode_bcd(read_cmos_raw(rtc::MONTH), is_binary);
        let mut year = Self::decode_bcd(read_cmos_raw(rtc::YEAR), is_binary) as u16;
        let century = Self::decode_bcd(read_cmos_raw(rtc::CENTURY), is_binary);
        if century != 0 && century != 0xFF {
            year += (century as u16) * 100;
        } else {
            year += if year >= 70 { 1900 } else { 2000 };
        }
        DateTime {
            year,
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
    boot_time: AtomicU64,
    uptime_nanos: AtomicU64,
    timer_tick_nanos: AtomicU64,
    tsc_epoch_nanos: AtomicU64,
    tsc_epoch_tsc: AtomicU64,
    tsc_freq_hz: AtomicU64,
    tsc_available: AtomicBool,
    tsc_mult: AtomicU64,
    tsc_shift: AtomicU8,
}

impl SystemClock {
    pub const fn new() -> Self {
        Self {
            boot_time: AtomicU64::new(0),
            uptime_nanos: AtomicU64::new(0),
            timer_tick_nanos: AtomicU64::new(0),
            tsc_epoch_nanos: AtomicU64::new(0),
            tsc_epoch_tsc: AtomicU64::new(0),
            tsc_freq_hz: AtomicU64::new(0),
            tsc_available: AtomicBool::new(false),
            tsc_mult: AtomicU64::new(0),
            tsc_shift: AtomicU8::new(0),
        }
    }

    pub fn set_boot_time(&self, unix_timestamp: u64) {
        self.boot_time.store(unix_timestamp, Ordering::Release);
    }

    pub fn boot_time(&self) -> u64 {
        self.boot_time.load(Ordering::Acquire)
    }

    pub fn uptime_nanos(&self) -> u64 {
        self.uptime_nanos.load(Ordering::Relaxed)
    }

    pub fn set_timer_tick_nanos(&self, nanos: u64) {
        self.timer_tick_nanos.store(nanos, Ordering::Release);
    }

    pub fn timer_tick_nanos(&self) -> u64 {
        self.timer_tick_nanos.load(Ordering::Acquire)
    }

    pub fn uptime_millis(&self) -> u64 {
        self.uptime_nanos() / NANOS_PER_MILLI
    }

    pub fn uptime_secs(&self) -> u64 {
        self.uptime_nanos() / NANOS_PER_SEC
    }

    pub fn now(&self) -> u64 {
        self.boot_time() + (self.uptime_nanos() / NANOS_PER_SEC)
    }

    pub fn tick(&self, delta_nanos: u64) {
        self.uptime_nanos.fetch_add(delta_nanos, Ordering::Relaxed);
    }

    pub fn read_tsc(&self) -> u64 {
        rdtsc()
    }

    pub fn set_tsc_info(&self, info: TscInfo) {
        let (epoch_ns, epoch_tsc) = x86_64::instructions::interrupts::without_interrupts(|| {
            (self.uptime_nanos.load(Ordering::Relaxed), rdtsc())
        });
        self.tsc_epoch_nanos.store(epoch_ns, Ordering::Release);
        self.tsc_epoch_tsc.store(epoch_tsc, Ordering::Release);
        self.tsc_freq_hz.store(info.frequency, Ordering::Release);
        self.tsc_mult
            .store(info.tsc_to_nanos_mult, Ordering::Release);
        self.tsc_shift
            .store(info.tsc_to_nanos_shift, Ordering::Release);
        if info.invariant {
            self.tsc_available.store(true, Ordering::Release);
        }
    }

    pub fn tsc_frequency(&self) -> Option<u64> {
        if self.tsc_available.load(Ordering::Acquire) {
            Some(self.tsc_freq_hz.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    pub fn precise_time_nanos(&self) -> u64 {
        if self.tsc_available.load(Ordering::Acquire) {
            let base_ns = self.tsc_epoch_nanos.load(Ordering::Relaxed);
            let base_tsc = self.tsc_epoch_tsc.load(Ordering::Relaxed);
            let mult = self.tsc_mult.load(Ordering::Relaxed);
            let shift = self.tsc_shift.load(Ordering::Relaxed);
            let now_tsc = rdtsc_unserialized();
            let delta = now_tsc.wrapping_sub(base_tsc);
            let ns_delta = ((delta as u128 * mult as u128) >> shift) as u64;
            return base_ns + ns_delta;
        }
        self.uptime_nanos()
    }

    pub fn timer_source(&self) -> TimerSource {
        if self.tsc_available.load(Ordering::Acquire) {
            TimerSource::TSC
        } else {
            TimerSource::PIT
        }
    }
}

/// PITドライバ
pub struct Pit {
    frequency: PoisonLock<u64>,
}

impl Pit {
    pub const fn new() -> Self {
        Self {
            frequency: PoisonLock::new(0),
        }
    }

    pub fn init(&self, frequency: u64) {
        if frequency == 0 {
            *self.frequency.lock().unwrap_or_else(|e| e.into_inner()) = 0;
            return;
        }
        let divisor = pit::BASE_FREQUENCY / frequency;
        let divisor = divisor.max(1).min(65535) as u16;
        let mut cmd_port: PortU8 = IoPort::new(pit::COMMAND);
        let mut data_port: PortU8 = IoPort::new(pit::CHANNEL0_DATA);
        cmd_port.write(pit::MODE_SQUARE_WAVE);
        data_port.write((divisor & 0xFF) as u8);
        data_port.write((divisor >> 8) as u8);
        let actual_freq = pit::BASE_FREQUENCY / divisor as u64;
        *self.frequency.lock().unwrap_or_else(|e| e.into_inner()) = actual_freq;
    }

    pub fn delay_us(&self, microseconds: u64) {
        if let Some(freq) = system_clock().tsc_frequency() {
            let ticks_needed = (freq as u128 * microseconds as u128) / 1_000_000;
            let ticks_needed = ticks_needed as u64;
            let start = rdtsc_unserialized();
            // LOOP_PROOF: mode=condition; reason=Delay loop exits once elapsed TSC ticks reach the computed ticks_needed threshold.;
            while rdtsc_unserialized().wrapping_sub(start) < ticks_needed {
                core::hint::spin_loop();
            }
            return;
        }
        self.delay_us_channel2(microseconds);
    }

    fn delay_us_channel2(&self, microseconds: u64) {
        let ticks = (pit::BASE_FREQUENCY * microseconds) / 1_000_000;
        let ticks = ticks.max(1).min(65535) as u16;
        let max_spins = (u32::from(ticks).saturating_mul(16)).max(1024);
        let mut cmd_port: PortU8 = IoPort::new(pit::COMMAND);
        let mut data_port: PortU8 = IoPort::new(pit::CHANNEL2_DATA);
        let mut speaker_port: PortU8 = IoPort::new(pit::SPEAKER_PORT);
        let old_speaker = speaker_port.read();
        speaker_port.write(old_speaker & 0xFC);
        core::hint::spin_loop();
        cmd_port.write(pit::CH2_MODE_ONE_SHOT);
        speaker_port.write((old_speaker & 0xFC) | 0x01);
        data_port.write((ticks & 0xFF) as u8);
        data_port.write((ticks >> 8) as u8);
        let _ = spin_until_or_limit(|| (speaker_port.read() & 0x20) == 0, max_spins);
        speaker_port.write(old_speaker);
    }

    pub fn frequency(&self) -> u64 {
        *self.frequency.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn perform_single_pit_measurement(
    cmd_port: &mut PortU8,
    data_port: &mut PortU8,
    speaker_port: &mut PortU8,
    old_speaker: u8,
    pit_ticks: u16,
) -> Option<u64> {
    speaker_port.write(old_speaker & 0xFC);
    if !spin_until_or_limit(|| (speaker_port.read() & 0x20) != 0, 100_000) {
        return None;
    }
    cmd_port.write(pit::CH2_MODE_ONE_SHOT);
    speaker_port.write((old_speaker & 0xFC) | 0x01);
    let start_tsc = unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    };
    data_port.write((pit_ticks & 0xFF) as u8);
    data_port.write((pit_ticks >> 8) as u8);
    if !spin_until_or_limit(|| (speaker_port.read() & 0x20) == 0, 100_000_000) {
        return None;
    }
    let end_tsc = unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    };
    Some(end_tsc.saturating_sub(start_tsc) * 20)
}
