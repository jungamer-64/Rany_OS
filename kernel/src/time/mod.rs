// ============================================================================
// kernel/src/time/mod.rs
// ============================================================================
//! 時間管理サブシステム
//!
//! システム時計、高精度タイマー、RTC (Real-Time Clock) の管理。
//! TSC, HPET, PIT, RTC など複数のタイマーソースをサポート。

#![allow(dead_code)]
#![allow(unused_variables)]

use crate::sync::irq_mutex::IrqMutex;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use hal::port_io::{IoPort, PortU8};
use spin::Mutex;

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

/// Read the Time Stamp Counter (TSC) with LFENCE serialization
#[inline]
fn rdtsc() -> u64 {
    unsafe {
        // LFENCE ensures all prior instructions complete before reading TSC
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
}

/// Read TSC without serialization (for non-critical paths)
#[inline]
fn rdtsc_unserialized() -> u64 {
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
    /// 
    /// `nanos = (tsc * mult) >> shift` で高速変換
    #[inline]
    pub fn tsc_to_nanos(&self, tsc: u64) -> u64 {
        if self.tsc_to_nanos_mult == 0 {
            // フォールバック: 未初期化または設定エラー
            if self.frequency == 0 {
                return 0;
            }
            let nanos = (tsc as u128 * NANOS_PER_SEC as u128) / self.frequency as u128;
            return nanos as u64;
        }
        // 固定小数点乗算: u128 で中間値を保持してオーバーフロー防止
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
        // u128を使用してオーバーフローを防止
        let tsc = (nanos as u128 * self.frequency as u128) / NANOS_PER_SEC as u128;
        tsc as u64
    }
}

/// 固定小数点変換係数 (mult, shift) を計算
///
/// TSC → ナノ秒変換を `nanos = (tsc * mult) >> shift` で行うための係数。
/// Linux カーネルの cyc2ns と同様のアプローチ。
///
/// 目標: `mult / 2^shift ≈ 1e9 / frequency`
/// 精度向上: shift を大きい方から探索 (63→0)
fn compute_tsc_mult_shift(frequency: u64) -> (u64, u8) {
    if frequency == 0 {
        return (0, 0);
    }

    // 最適なシフト量を大きい方から探す (精度向上)
    // shift が大きいほど精度が上がるが、mult がオーバーフローするリスク
    // u64 に収まる最大の shift を選択
    //
    // mult = (1e9 << shift) / frequency
    // mult が u64::MAX を超えないように shift を決定
    
    let mut shift: u8 = 63;
    loop {
        // (NANOS_PER_SEC << shift) / frequency が u64 に収まるかチェック
        let numerator = (NANOS_PER_SEC as u128) << shift;
        let mult = numerator / frequency as u128;
        
        if mult <= u64::MAX as u128 {
            return (mult as u64, shift);
        }
        
        if shift == 0 {
            // シフト 0 でもオーバーフローする場合 (非常に低い周波数)
            // フォールバック: 精度は落ちるが動作はする
            return ((NANOS_PER_SEC / frequency), 0);
        }
        
        shift -= 1;
    }
}

/// PIT (Programmable Interval Timer) 定数
mod pit {
    pub const CHANNEL0_DATA: u16 = 0x40;
    pub const CHANNEL2_DATA: u16 = 0x42;
    pub const COMMAND: u16 = 0x43;
    /// Speaker/Timer control port
    pub const SPEAKER_PORT: u16 = 0x61;

    /// PITの基本周波数 (Hz)
    pub const BASE_FREQUENCY: u64 = 1193182;

    // モードコマンド
    pub const MODE_SQUARE_WAVE: u8 = 0x36; // Channel 0, Mode 3, lobyte/hibyte
    pub const MODE_ONE_SHOT: u8 = 0x30; // Channel 0, Mode 0, lobyte/hibyte
    pub const MODE_RATE_GEN: u8 = 0x34; // Channel 0, Mode 2
    pub const READBACK: u8 = 0xE2; // Read-back command

    // Channel 2 mode commands (for calibration - does NOT touch Channel 0)
    pub const CH2_MODE_ONE_SHOT: u8 = 0xB0; // Channel 2, Mode 0, lobyte/hibyte
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

    /// Unixタイムスタンプに変換 (安全版: 1970年以前は None)
    pub fn to_unix_timestamp_safe(&self) -> Option<u64> {
        if self.year < 1970 {
            return None;
        }
        let ts = self.to_unix_timestamp();
        if ts < 0 { None } else { Some(ts as u64) }
    }

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

/// CMOS ポートアクセス用のグローバルロック
/// CMOS は 0x70→0x71 の2段アクセスなので、途中で割り込まれると壊れる
static CMOS_LOCK: IrqMutex<()> = IrqMutex::new(());

/// RTCドライバ
pub struct Rtc;
    
    impl Rtc {
        /// 新しいRTCドライバを作成
        pub const fn new() -> Self {
            Self
        }

    /// CMOSレジスタを読み込み (IRQ-safe)
    fn read_cmos(&self, reg: u8) -> u8 {
        let _guard = CMOS_LOCK.lock();

        let mut addr_port: PortU8 = IoPort::new(rtc::CMOS_ADDR);
        let mut data_port: PortU8 = IoPort::new(rtc::CMOS_DATA);

        addr_port.write(reg);
        data_port.read()
    }

    /// CMOSレジスタに書き込み (IRQ-safe)
    fn write_cmos(&self, reg: u8, value: u8) {
        let _guard = CMOS_LOCK.lock();

        let mut addr_port: PortU8 = IoPort::new(rtc::CMOS_ADDR);
        let mut data_port: PortU8 = IoPort::new(rtc::CMOS_DATA);

        addr_port.write(reg);
        data_port.write(value);
    }

    /// RTC更新中かチェック
    fn update_in_progress(&self) -> bool {
        self.read_cmos(rtc::STATUS_A) & 0x80 != 0
    }

    /// BCDをバイナリに変換
    fn bcd_to_binary(value: u8) -> u8 {
        (value & 0x0F) + ((value >> 4) * 10)
    }

    /// BCD または Binary の値をデコード
    fn decode_bcd(value: u8, is_binary: bool) -> u8 {
        if is_binary { value } else { Self::bcd_to_binary(value) }
    }

    /// 時刻をデコード (12h/24h, BCD/Binary 両対応)
    ///
    /// 12時間表記の変換ルール:
    /// - 12 AM (真夜中) → 0
    /// - 12 PM (正午)   → 12  
    /// - 1-11 AM        → 1-11
    /// - 1-11 PM        → 13-23
    fn decode_hour(raw: u8, is_binary: bool, is_24h: bool) -> u8 {
        let pm = (raw & 0x80) != 0;
        let h = raw & 0x7F;

        // BCD/Binary 変換
        let hour_val = if is_binary { h } else { Self::bcd_to_binary(h) };

        if is_24h {
            // 24時間表記: そのまま返す
            hour_val
        } else {
            // 12時間表記: AM/PM 変換
            match (hour_val, pm) {
                (12, false) => 0,      // 12 AM = 真夜中
                (12, true) => 12,      // 12 PM = 正午
                (h, false) => h,       // AM: 1-11 はそのまま
                (h, true) => h + 12,   // PM: 1-11 → 13-23
            }
        }
    }

    /// 現在の日時を読み取り
    pub fn read_datetime(&self) -> DateTime {
        const MAX_RETRIES: u32 = 3; // 2回一致しなければ3回目で諦める
        const MAX_UPDATE_WAIT: u32 = 10000;
        
        // 更新中は待機 (タイムアウト付き)
        let mut wait_count = 0;
        while self.update_in_progress() {
            core::hint::spin_loop();
            wait_count += 1;
            if wait_count > MAX_UPDATE_WAIT {
                break; 
            }
        }

        // 2回読んで一致するまで繰り返す (最大リトライ付き)
        let mut retries = 0;
        loop {
            let first = self.read_datetime_internal();
            let second = self.read_datetime_internal();

            if first == second {
                return first;
            }
            
            retries += 1;
            if retries >= MAX_RETRIES {
                // 最後に読んだ値を返す
                return second;
            }
            
            core::hint::spin_loop();
        }
    }

    fn read_datetime_internal(&self) -> DateTime {
        // バッチ読み取り (1回のロックで全レジスタを読む)
        let _guard = CMOS_LOCK.lock();
        
        let mut addr_port: PortU8 = IoPort::new(rtc::CMOS_ADDR);
        let mut data_port: PortU8 = IoPort::new(rtc::CMOS_DATA);

        // ヘルパー: ロック済み前提で読む
        let mut read_cmos_raw = |reg| {
            addr_port.write(reg);
            data_port.read()
        };

        let status_b = read_cmos_raw(rtc::STATUS_B);
        let is_binary = status_b & 0x04 != 0;
        let is_24h = status_b & 0x02 != 0;

        let second_raw = read_cmos_raw(rtc::SECONDS);
        let minute_raw = read_cmos_raw(rtc::MINUTES);
        let hour_raw = read_cmos_raw(rtc::HOURS);
        let day_raw = read_cmos_raw(rtc::DAY_OF_MONTH);
        let month_raw = read_cmos_raw(rtc::MONTH);
        let year_raw = read_cmos_raw(rtc::YEAR);
        
        // Century は ACPI FADT が有効な場合のみ信頼できるが、ここでは簡易的チェック
        let century_raw = read_cmos_raw(rtc::CENTURY);

        let second = Self::decode_bcd(second_raw, is_binary);
        let minute = Self::decode_bcd(minute_raw, is_binary);
        let hour = Self::decode_hour(hour_raw, is_binary, is_24h);
        let day = Self::decode_bcd(day_raw, is_binary);
        let month = Self::decode_bcd(month_raw, is_binary);
        let mut year = Self::decode_bcd(year_raw, is_binary) as u16;
        let century = Self::decode_bcd(century_raw, is_binary);

        // 年の補正: Century が妥当なら採用、そうでなければ推定
        if century != 0 && century != 0xFF {
            year += (century as u16) * 100;
        } else {
            // 推定: 70以上なら1900年代、それ以外は2000年代
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
    /// 起動時の時刻 (Unixタイムスタンプ, 秒)
    boot_time: AtomicU64,
    /// 稼働時間 (ナノ秒, PITベースのmonotonic counter)
    uptime_nanos: AtomicU64,
    
    // === Lock-free fast path fields ===
    /// TSC Epoch: TSC切り替え時点の uptime_nanos (monotonic基準点)
    tsc_epoch_nanos: AtomicU64,
    /// TSC Epoch: TSC切り替え時点の TSC (monotonic基準点)
    tsc_epoch_tsc: AtomicU64,
    /// TSC 周波数 (Hz) - lock-free アクセス用
    tsc_freq_hz: AtomicU64,
    /// TSC 利用可能フラグ (true なら TSC ベース、false なら PIT ベース)
    tsc_available: AtomicBool,
    /// 固定小数点乗算係数 (fast path 用)
    tsc_mult: AtomicU64,
    /// 固定小数点シフト量 (u8)
    tsc_shift: AtomicU8,
}

impl SystemClock {
    /// 新しいシステム時計を作成
    pub const fn new() -> Self {
        Self {
            boot_time: AtomicU64::new(0),
            uptime_nanos: AtomicU64::new(0),
            // Lock-free fields
            tsc_epoch_nanos: AtomicU64::new(0),
            tsc_epoch_tsc: AtomicU64::new(0),
            tsc_freq_hz: AtomicU64::new(0),
            tsc_available: AtomicBool::new(false),
            tsc_mult: AtomicU64::new(0),
            tsc_shift: AtomicU8::new(0),
        }
    }

    /// 起動時刻を設定
    pub fn set_boot_time(&self, unix_timestamp: u64) {
        self.boot_time.store(unix_timestamp, Ordering::Release);
    }

    /// 起動時刻を取得 (Unixタイムスタンプ)
    pub fn boot_time(&self) -> u64 {
        self.boot_time.load(Ordering::Acquire)
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

    /// TSCを読み取り (serialized)
    pub fn read_tsc(&self) -> u64 {
        rdtsc()
    }

    /// TSC情報を設定し、fast path を有効化
    pub fn set_tsc_info(&self, info: TscInfo) {
        // 重要: 切り替え時点の (uptime, TSC) をペアで Atomic に記録
        // これにより PIT -> TSC の切り替えで時刻が連続する
        let (epoch_ns, epoch_tsc) = x86_64::instructions::interrupts::without_interrupts(|| {
            (self.uptime_nanos.load(Ordering::Relaxed), rdtsc())
        });

        self.tsc_epoch_nanos.store(epoch_ns, Ordering::Release);
        self.tsc_epoch_tsc.store(epoch_tsc, Ordering::Release);
        
        // 周波数を Atomic に格納 (lock-free fast path 用)
        self.tsc_freq_hz.store(info.frequency, Ordering::Release);
        
        // 固定小数点変換係数を Atomic に格納
        self.tsc_mult.store(info.tsc_to_nanos_mult, Ordering::Release);
        self.tsc_shift.store(info.tsc_to_nanos_shift, Ordering::Release);
        
        // invariant TSC の場合のみ fast path を有効化
        if info.invariant {
            self.tsc_available.store(true, Ordering::Release);
        } else {
            // Non-invariant: PIT フォールバックのまま
        }
    }

    /// TSC周波数を取得（設定されていれば Some(freq) を返す）
    pub fn tsc_frequency(&self) -> Option<u64> {
        if self.tsc_available.load(Ordering::Acquire) {
            Some(self.tsc_freq_hz.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// 高精度な時刻を取得 (ナノ秒) - Lock-free fast path
    ///
    /// 起動からの経過時間を返す (monotonic clock)。
    /// TSC が利用可能な場合は高精度、そうでなければ PIT tick ベース。
    /// Note: MP環境やInvariant TSCがない環境ではコア間ズレの可能性があります。
    pub fn precise_time_nanos(&self) -> u64 {
        // Lock-free: Atomic フラグで TSC 利用可能性をチェック
        if self.tsc_available.load(Ordering::Acquire) {
            let base_ns = self.tsc_epoch_nanos.load(Ordering::Relaxed);
            let base_tsc = self.tsc_epoch_tsc.load(Ordering::Relaxed);
            let mult = self.tsc_mult.load(Ordering::Relaxed);
            let shift = self.tsc_shift.load(Ordering::Relaxed);
            
            // monotonic な現在時刻 = epoch_ns + (delta_tsc * mult >> shift)
            // serialized不要 (monotonicity is guaranteed by epoch + delta logic, and we prize speed here)
            // Note: rdtsc() enforces ordering, rdtsc_unserialized() does not.
            // We use unserialized here for performance as suggested by review.
            let now_tsc = rdtsc_unserialized();
            let delta = now_tsc.wrapping_sub(base_tsc);
            
            // u128 で計算してオーバーフロー防止
            let ns_delta = ((delta as u128 * mult as u128) >> shift) as u64;
            return base_ns + ns_delta;
        }

        // フォールバック: PIT tick ベースの uptime
        self.uptime_nanos()
    }

    /// 使用中のタイマーソースを取得
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

    /// PITを指定周波数で初期化 (Channel 0 のみ)
    /// 
    /// Channel 0 は OS の周期 tick 専用。calibration や delay では使用しない。
    pub fn init(&self, frequency: u64) {
        if frequency == 0 {
            *self.frequency.lock() = 0;
            return;
        }
        let divisor = pit::BASE_FREQUENCY / frequency;
        let divisor = divisor.max(1).min(65535) as u16;

        let mut cmd_port: PortU8 = IoPort::new(pit::COMMAND);
        let mut data_port: PortU8 = IoPort::new(pit::CHANNEL0_DATA);

        // Channel 0, Mode 3 (Square wave), 16-bit
        cmd_port.write(pit::MODE_SQUARE_WAVE);

        // 分周比を設定 (Low byte, High byte)
        data_port.write((divisor & 0xFF) as u8);
        data_port.write((divisor >> 8) as u8);

        let actual_freq = pit::BASE_FREQUENCY / divisor as u64;
        *self.frequency.lock() = actual_freq;
    }

    /// ビジーウェイト遅延 - TSC ベース (Channel 0 を壊さない)
    ///
    /// TSC が利用可能な場合は TSC で delay、そうでなければ Channel 2 を使用。
    pub fn delay_us(&self, microseconds: u64) {
        // TSC が利用可能なら TSC で delay (最も高精度で Channel 0 に影響しない)
        if let Some(freq) = system_clock().tsc_frequency() {
            // u128 で計算してオーバーフロー防止
            let ticks_needed = (freq as u128 * microseconds as u128) / 1_000_000;
            let ticks_needed = ticks_needed as u64;
            
            let start = rdtsc_unserialized();
            while rdtsc_unserialized().wrapping_sub(start) < ticks_needed {
                core::hint::spin_loop();
            }
            return;
        }

        // フォールバック: Channel 2 を使用 (Channel 0 に影響しない)
        self.delay_us_channel2(microseconds);
    }

    /// Channel 2 を使った遅延 (早期ブート用フォールバック)
    fn delay_us_channel2(&self, microseconds: u64) {
        let ticks = (pit::BASE_FREQUENCY * microseconds) / 1_000_000;
        let ticks = ticks.max(1).min(65535) as u16;

        let mut cmd_port: PortU8 = IoPort::new(pit::COMMAND);
        let mut data_port: PortU8 = IoPort::new(pit::CHANNEL2_DATA);
        let mut speaker_port: PortU8 = IoPort::new(pit::SPEAKER_PORT);

        // Speaker port: disable speaker (bit 1), enable timer gate (bit 0)
        let old_speaker = speaker_port.read();
        
        // OUT2 を確実に Low にする: Gate=0 (bit0=0) にして待機
        speaker_port.write(old_speaker & 0xFC);
        core::hint::spin_loop();

        // Channel 2, Mode 0 (One-shot), 16-bit
        cmd_port.write(pit::CH2_MODE_ONE_SHOT);
        
        // Gate=1 (enable) にするが、カウンタ書くまでカウントは始まらない
        speaker_port.write((old_speaker & 0xFC) | 0x01);

        // カウント値を設定 (これでタイマー開始)
        data_port.write((ticks & 0xFF) as u8);
        data_port.write((ticks >> 8) as u8);

        // OUT2 (bit 5) が high になるまで待機
        while (speaker_port.read() & 0x20) == 0 {
            core::hint::spin_loop();
        }

        // Speaker port を復元
        speaker_port.write(old_speaker);
    }

    /// 現在の周波数を取得
    pub fn frequency(&self) -> u64 {
        *self.frequency.lock()
    }
}

/// PIT Channel 2 で 50ms の単一計測を行い TSC tick 数 × 20 (1秒換算) を返す
fn perform_single_pit_measurement(
    cmd_port: &mut PortU8,
    data_port: &mut PortU8,
    speaker_port: &mut PortU8,
    old_speaker: u8,
    pit_ticks: u16,
) -> Option<u64> {
    speaker_port.write(old_speaker & 0xFC);
    let mut timeout = 100_000;
    while (speaker_port.read() & 0x20) != 0 {
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 { return None; }
    }
    cmd_port.write(pit::CH2_MODE_ONE_SHOT);
    speaker_port.write((old_speaker & 0xFC) | 0x01);
    let start_tsc = unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    };
    data_port.write((pit_ticks & 0xFF) as u8);
    data_port.write((pit_ticks >> 8) as u8);
    let mut timeout = 100_000_000;
    loop {
        if (speaker_port.read() & 0x20) != 0 {
            break;
        }
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 { return None; }
    }
    let end_tsc = unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    };
    Some(end_tsc.saturating_sub(start_tsc) * 20)
}
