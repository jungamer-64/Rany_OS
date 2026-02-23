// Time Provider (RTC Integration Hook)
// ============================================================================

/// FAT32ファイルシステムに現在時刻を提供するトレイト
///
/// カーネルのRTCドライバからの時刻取得を可能にするフック。
/// デフォルトでは固定値を返すダミー実装が使用される。
///
/// # Example
/// ```ignore
/// struct KernelTimeProvider;
///
/// impl TimeProvider for KernelTimeProvider {
///     fn current_dos_time(&self) -> u16 {
///         let now = rtc::get_time();
///         ((now.hour as u16) << 11) | ((now.minute as u16) << 5) | (now.second as u16 / 2)
///     }
///
///     fn current_dos_date(&self) -> u16 {
///         let now = rtc::get_date();
///         (((now.year - 1980) as u16) << 9) | ((now.month as u16) << 5) | (now.day as u16)
///     }
/// }
/// ```
pub trait TimeProvider: Send + Sync {
    /// 現在のDOS形式時刻を取得
    ///
    /// ビットレイアウト: hhhhhmmmmmmsssss
    /// - ビット15-11: 時 (0-23)
    /// - ビット10-5: 分 (0-59)
    /// - ビット4-0: 秒/2 (0-29)
    fn current_dos_time(&self) -> u16;

    /// 現在のDOS形式日付を取得
    ///
    /// ビットレイアウト: yyyyyyymmmmddddd
    /// - ビット15-9: 年 (1980年からのオフセット, 0-127)
    /// - ビット8-5: 月 (1-12)
    /// - ビット4-0: 日 (1-31)
    fn current_dos_date(&self) -> u16;
}

/// デフォルトの時刻プロバイダー（固定値を返す）
///
/// テストやRTCが利用できない環境で使用。
/// 2024年1月1日 12:00:00 を返す。
pub struct DummyTimeProvider;

impl TimeProvider for DummyTimeProvider {
    fn current_dos_time(&self) -> u16 {
        // 12:00:00 = (12 << 11) | (0 << 5) | 0
        (12 << 11) | (0 << 5) | 0
    }

    fn current_dos_date(&self) -> u16 {
        // 2024-01-01 = ((2024 - 1980) << 9) | (1 << 5) | 1
        ((2024 - 1980) << 9) | (1 << 5) | 1
    }
}

// ============================================================================

/// Unixエポック秒をDOS形式の日付・時刻に変換
pub fn unix_to_dos(unix: u64) -> (u16, u16) {
    if unix == 0 {
        return (get_current_dos_date(), get_current_dos_time());
    }

    let days = (unix / 86_400) as i64;
    let secs_of_day = (unix % 86_400) as u32;
    let (mut year, mut month, mut day) = civil_from_days(days);

    if year < 1980 {
        year = 1980;
        month = 1;
        day = 1;
    } else if year > 2107 {
        year = 2107;
        month = 12;
        day = 31;
    }

    let hour = (secs_of_day / 3600) as u16;
    let min = ((secs_of_day % 3600) / 60) as u16;
    let sec = (secs_of_day % 60) as u16;
    let sec2 = (sec / 2).min(29);

    let date = ((year as u16 - 1980) << 9) | ((month as u16) << 5) | (day as u16);
    let time = (hour << 11) | (min << 5) | sec2;
    (date, time)
}

/// DOS形式の日付・時刻をUnixエポック秒に変換
pub fn dos_to_unix(date: u16, time: u16) -> u64 {
    if date == 0 {
        return 0;
    }
    // DOS Date: (year-1980) << 9 | month << 5 | day
    // DOS Time: hour << 11 | minute << 5 | (sec/2)
    let day = (date & 0x1F) as u64;
    let month = ((date >> 5) & 0x0F) as u64;
    let year = ((date >> 9) & 0x7F) as u64 + 1980;

    let sec = (time & 0x1F) as u64 * 2;
    let min = ((time >> 5) & 0x3F) as u64;
    let hour = ((time >> 11) & 0x1F) as u64;

    if month == 0 || month > 12 {
        return 0;
    }
    let max_day = days_in_month(year as i32, month as u32);
    if day == 0 || day > max_day as u64 {
        return 0;
    }

    let days_since_epoch = days_from_civil(year as i32, month as u32, day as u32);
    if days_since_epoch < 0 {
        return 0;
    }

    (days_since_epoch as u64) * 86_400 + hour * 3600 + min * 60 + sec
}

/// 現在のDOS形式時刻を取得（ダミー実装）
pub(crate) fn get_current_dos_time() -> u16 {
    (12 << 11) | (0 << 5) | 0
}

/// 現在のDOS形式日付を取得（ダミー実装）
pub(crate) fn get_current_dos_date() -> u16 {
    ((2024 - 1980) << 9) | (1 << 5) | 1
}

#[inline]
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[inline]
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

// Returns (year, month, day) for a day count since 1970-01-01 (UTC).
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

// Returns days since 1970-01-01 (UTC) for a civil date.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = year;
    let m = month as i32;
    let d = day as i32;
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + yoe / 400 + doy;
    (era as i64) * 146_097 + (doe as i64) - 719_468
}

// ============================================================================
