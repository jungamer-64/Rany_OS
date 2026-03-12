use super::*;

/// TSC周波数をキャリブレーション (Channel 2 使用 - Channel 0 を壊さない)
///
/// PIT Channel 2 (speaker timer) を使用して TSC 周波数を測定。
/// Channel 0 は OS の周期 tick 用に予約されているため使用しない。

pub fn calibrate_tsc() -> Option<TscInfo> {
    // 1. Invariant TSC の確認 (CPUID.80000007H:EDX[bit 8])
    // まず最大拡張機能リーフ (0x80000000) を確認して安全にアクセスする
    let invariant = {
        let max_ext_leaf = core::arch::x86_64::__cpuid(0x80000000).eax;
        if max_ext_leaf >= 0x80000007 {
            let result = core::arch::x86_64::__cpuid(0x80000007);
            (result.edx >> 8) & 1 == 1
        } else {
            false
        }
    };

    // 2. TSC 周波数測定
    // 50ms の測定を 3回行い、中央値採用 (ノイズ除去)
    // 割り込み禁止区間で行うことで測定ブレを防ぐ
    let measurements = x86_64::instructions::interrupts::without_interrupts(|| {
        const TRIALS: usize = 3;
        let mut measurements = [0u64; TRIALS];

        // 50ms 分の tick 数
        let pit_ticks = (pit::BASE_FREQUENCY / 20) as u16;

        // I/O ポート準備
        let mut cmd_port: PortU8 = IoPort::new(pit::COMMAND);
        let mut data_port: PortU8 = IoPort::new(pit::CHANNEL2_DATA);
        let mut speaker_port: PortU8 = IoPort::new(pit::SPEAKER_PORT);

        // スピーカーポートの初期状態を保存
        let old_speaker = speaker_port.read();

        for i in 0..TRIALS {
            measurements[i] = perform_single_pit_measurement(
                &mut cmd_port,
                &mut data_port,
                &mut speaker_port,
                old_speaker,
                pit_ticks,
            )?;
        }

        // スピーカーポート復元
        speaker_port.write(old_speaker);
        Some(measurements)
    });

    // 計測失敗なら None
    let mut measurements = measurements?;

    // 中央値 (Median) を取得
    measurements.sort_unstable();
    let frequency = measurements[measurements.len() / 2];

    // 異常値チェック (100MHz - 30GHz)
    if frequency < 100_000_000 || frequency > 30_000_000_000 {
        return None;
    }

    Some(TscInfo::new(frequency, invariant))
}

/// グローバルシステム時計
pub(crate) static SYSTEM_CLOCK: SystemClock = SystemClock::new();

/// グローバルRTCドライバ
pub(crate) static RTC: Rtc = Rtc::new();

/// グローバルPITドライバ
pub(crate) static PIT: Pit = Pit::new();

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
    // PITを初期化 (Channel 0 を周期 tick 用に設定)
    PIT.init(tick_frequency);
    let actual_frequency = PIT.frequency();
    let tick_nanos = if actual_frequency == 0 {
        0
    } else {
        NANOS_PER_SEC / actual_frequency
    };
    SYSTEM_CLOCK.set_timer_tick_nanos(tick_nanos);

    // RTCから現在時刻を読み取り
    let datetime = RTC.read_datetime();
    let boot_time = datetime.to_unix_timestamp_safe().unwrap_or(0);
    SYSTEM_CLOCK.set_boot_time(boot_time);

    // TSCをキャリブレーション (Channel 2 使用 - Channel 0 に影響しない)
    if let Some(tsc_info) = calibrate_tsc() {
        SYSTEM_CLOCK.set_tsc_info(tsc_info);
    }
}

/// タイマーティック (割り込みハンドラから呼ばれる)
pub fn tick(delta_nanos: u64) {
    SYSTEM_CLOCK.tick(delta_nanos);
}

/// 現在設定されているタイマーティック間隔 (ナノ秒)
#[inline]
pub fn timer_tick_nanos() -> u64 {
    SYSTEM_CLOCK.timer_tick_nanos()
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

/// 現在時刻をナノ秒で取得（precise_time_nanosのエイリアス）
#[inline]
pub fn current_time_ns() -> u64 {
    precise_time_nanos()
}

/// Return uptime in milliseconds (since boot)
#[inline]
pub fn get_uptime_ms() -> u64 {
    SYSTEM_CLOCK.uptime_millis()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
