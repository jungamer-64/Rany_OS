#![no_std]
// Allow common patterns in RTC driver
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::if_not_else)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::struct_excessive_bools)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use exorust_sync::IrqPoisonLock;
use hal::port_io::PortU8;

// ============================================================================
// RTC Constants
// ============================================================================

const CMOS_ADDRESS: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

pub mod regs {
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
    pub const CENTURY: u8 = 0x32;
}

pub mod status_a {
    pub const UPDATE_IN_PROGRESS: u8 = 0x80;
    pub const DIVIDER_MASK: u8 = 0x70;
    pub const RATE_MASK: u8 = 0x0F;
}

pub mod status_b {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub day_of_week: u8,
}

impl DateTime {
    pub fn to_unix_timestamp(&self) -> i64 {
        let mut days: i64 = 0;
        for y in 1970..self.year as i64 {
            if is_leap_year(y as u16) {
                days += 366;
            } else {
                days += 365;
            }
        }
        let days_in_month = if is_leap_year(self.year) {
            [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        for m in 1..self.month {
            days += days_in_month[m as usize] as i64;
        }
        days += self.day as i64 - 1;
        days * 86400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64
    }

    pub const fn from_unix_timestamp(timestamp: i64) -> Self {
        let mut remaining = timestamp;
        let second = (remaining % 60) as u8;
        remaining /= 60;
        let minute = (remaining % 60) as u8;
        remaining /= 60;
        let hour = (remaining % 24) as u8;
        remaining /= 24;
        let day_of_week = ((remaining + 4) % 7 + 1) as u8;
        let mut year: u16 = 1970;
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let days_in_year = if is_leap_year(year) { 366 } else { 365 };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            year += 1;
        }
        let days_in_month = if is_leap_year(year) {
            [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut month: u8 = 1;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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

const fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ============================================================================
// RTC Driver
// ============================================================================

pub struct Rtc {
    binary_mode: bool,
    hour_24: bool,
    century_register: Option<u8>,
    periodic_rate: u32,
}

impl Default for Rtc {
    fn default() -> Self {
        Self::new()
    }
}

impl Rtc {
    unsafe fn read_cmos(reg: u8) -> u8 {
        let address = (reg & 0x7F) | 0x80;
        let mut port_address = PortU8::new(CMOS_ADDRESS);
        let mut port_data = PortU8::new(CMOS_DATA);
        port_address.write(address);
        port_data.read()
    }

    unsafe fn write_cmos(reg: u8, value: u8) {
        let address = (reg & 0x7F) | 0x80;
        let mut port_address = PortU8::new(CMOS_ADDRESS);
        let mut port_data = PortU8::new(CMOS_DATA);
        port_address.write(address);
        port_data.write(value);
    }

    unsafe fn is_update_in_progress() -> bool {
        unsafe { (Self::read_cmos(regs::STATUS_A) & status_a::UPDATE_IN_PROGRESS) != 0 }
    }
    const fn bcd_to_binary(bcd: u8) -> u8 {
        (bcd & 0x0F) + ((bcd >> 4) * 10)
    }
    const fn binary_to_bcd(bin: u8) -> u8 {
        ((bin / 10) << 4) | (bin % 10)
    }

    #[must_use]
    pub fn new() -> Self {
        let status_b = unsafe { Self::read_cmos(regs::STATUS_B) };
        let status_a = unsafe { Self::read_cmos(regs::STATUS_A) };
        let rate_sel = status_a & status_a::RATE_MASK;
        let periodic_rate = if (3..=15).contains(&rate_sel) {
            32768 >> (rate_sel - 1)
        } else {
            0
        };
        Self {
            binary_mode: (status_b & status_b::BINARY_MODE) != 0,
            hour_24: (status_b & status_b::HOUR_24) != 0,
            century_register: None,
            periodic_rate,
        }
    }

    pub fn set_century_register(&mut self, reg: u8) {
        self.century_register = Some(reg);
    }

    pub fn read_datetime(&self) -> DateTime {
        unsafe {
            while Self::is_update_in_progress() {}
            let second = Self::read_cmos(regs::SECONDS);
            let minute = Self::read_cmos(regs::MINUTES);
            let hour = Self::read_cmos(regs::HOURS);
            let day = Self::read_cmos(regs::DAY_OF_MONTH);
            let month = Self::read_cmos(regs::MONTH);
            let year = Self::read_cmos(regs::YEAR);
            let day_of_week = Self::read_cmos(regs::DAY_OF_WEEK);
            let century = if let Some(reg) = self.century_register {
                Self::read_cmos(reg)
            } else {
                0x20
            };
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

    pub fn write_datetime(&self, dt: &DateTime) {
        unsafe {
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::SET);
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
            Self::write_cmos(regs::STATUS_B, status_b);
        }
    }

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
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::ALARM_INT);
        }
    }

    pub fn set_periodic_interrupt(&mut self, rate: u8) {
        let rate = rate.clamp(3, 15);
        unsafe {
            let status_a = Self::read_cmos(regs::STATUS_A);
            Self::write_cmos(regs::STATUS_A, (status_a & !status_a::RATE_MASK) | rate);
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::PERIODIC_INT);
        }
        self.periodic_rate = 32768 >> (rate - 1);
    }

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

    pub fn read_interrupt_status(&self) -> InterruptStatus {
        let status_c = unsafe { Self::read_cmos(regs::STATUS_C) };
        InterruptStatus {
            update_ended: (status_c & 0x10) != 0,
            alarm: (status_c & 0x20) != 0,
            periodic: (status_c & 0x40) != 0,
            irq: (status_c & 0x80) != 0,
        }
    }

    pub fn set_alarm_relative(&mut self, seconds: u8) {
        let now = self.read_datetime();
        let mut second = now.second + seconds;
        let mut minute = now.minute;
        let mut hour = now.hour;
        while second >= 60 {
            second -= 60;
            minute += 1;
        }
        while minute >= 60 {
            minute -= 60;
            hour += 1;
        }
        hour %= 24;
        self.set_alarm(hour, minute, second);
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn set_frequency(&mut self, hz: u32) -> Result<(), &'static str> {
        let rate = match hz {
            8192 => 3,
            4096 => 4,
            2048 => 5,
            1024 => 6,
            512 => 7,
            256 => 8,
            128 => 9,
            64 => 10,
            32 => 11,
            16 => 12,
            8 => 13,
            4 => 14,
            2 => 15,
            _ => return Err("Unsupported frequency"),
        };
        self.set_periodic_interrupt(rate);
        Ok(())
    }

    pub fn enable_update_interrupt(&self) {
        unsafe {
            let status_b = Self::read_cmos(regs::STATUS_B);
            Self::write_cmos(regs::STATUS_B, status_b | status_b::UPDATE_ENDED_INT);
        }
    }
}

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

static RTC: IrqPoisonLock<Option<Rtc>> = IrqPoisonLock::new(None);
static SYSTEM_TIME: AtomicU64 = AtomicU64::new(0);
static BOOT_TIMESTAMP: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);
static ALARM_TRIGGERED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    let rtc = Rtc::new();
    let datetime = rtc.read_datetime();
    let timestamp = datetime.to_unix_timestamp();
    if timestamp > 0 {
        BOOT_TIMESTAMP.store(timestamp as u64, Ordering::SeqCst);
    }
    *RTC.lock().unwrap_or_else(|e| e.into_inner()) = Some(rtc);
}

pub fn get_datetime() -> Option<DateTime> {
    RTC.lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|rtc| rtc.read_datetime())
}

pub fn set_datetime(dt: &DateTime) {
    if let Some(ref rtc) = *RTC.lock().unwrap_or_else(|e| e.into_inner()) {
        rtc.write_datetime(dt);
    }
}

pub fn get_unix_timestamp() -> i64 {
    BOOT_TIMESTAMP.load(Ordering::Acquire) as i64 + SYSTEM_TIME.load(Ordering::Acquire) as i64
}

pub fn get_uptime_seconds() -> u64 {
    SYSTEM_TIME.load(Ordering::Acquire)
}

pub fn get_uptime_ms() -> u64 {
    let seconds = SYSTEM_TIME.load(Ordering::Acquire);
    let ticks = TICKS.load(Ordering::Acquire);
    if let Some(ref rtc) = *RTC.lock().unwrap_or_else(|e| e.into_inner()) {
        let rate = rtc.periodic_rate as u64;
        if rate > 0 {
            let sub_second_ticks = ticks % rate;
            return (seconds * 1000) + (sub_second_ticks * 1000 / rate);
        }
    }
    seconds * 1000
}

pub fn get_unix_timestamp_ms() -> i64 {
    get_unix_timestamp() * 1000 + (get_uptime_ms() % 1000) as i64
}
pub fn check_and_clear_alarm() -> bool {
    ALARM_TRIGGERED.swap(false, Ordering::Acquire)
}

pub fn rtc_interrupt_handler() {
    if let Some(ref rtc) = *RTC.lock().unwrap_or_else(|e| e.into_inner()) {
        let status = rtc.read_interrupt_status();
        if status.periodic {
            let ticks = TICKS.fetch_add(1, Ordering::Relaxed);
            let rate = rtc.periodic_rate as u64;
            if rate > 0 && (ticks + 1) % rate == 0 {
                SYSTEM_TIME.fetch_add(1, Ordering::Release);
            }
        }
        if status.alarm {
            ALARM_TRIGGERED.store(true, Ordering::Release);
        }
    }
}
