use super::*;

static EARLY_WALL_CLOCK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static EARLY_TSC_INITIALIZED: AtomicBool = AtomicBool::new(false);
const EARLY_TSC_FALLBACK_HZ: u64 = 3_000_000_000;

/// TSC周波数をキャリブレーション (Channel 2 使用 - Channel 0 を壊さない)
///
/// PIT Channel 2 (speaker timer) を使用して TSC 周波数を測定。
/// Channel 0 は OS の周期 tick 用に予約されているため使用しない。

pub fn calibrate_tsc() -> Option<TscInfo> {
    // 1. Invariant TSC の確認 (CPUID.80000007H:EDX[bit 8])
    let invariant = detect_invariant_tsc();

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

fn detect_invariant_tsc() -> bool {
    // まず最大拡張機能リーフ (0x80000000) を確認して安全にアクセスする
    let max_ext_leaf = core::arch::x86_64::__cpuid(0x80000000).eax;
    if max_ext_leaf >= 0x80000007 {
        let result = core::arch::x86_64::__cpuid(0x80000007);
        (result.edx >> 8) & 1 == 1
    } else {
        false
    }
}

fn detect_tsc_support() -> bool {
    let max_basic_leaf = core::arch::x86_64::__cpuid(0).eax;
    if max_basic_leaf >= 1 {
        let result = core::arch::x86_64::__cpuid(1);
        (result.edx & (1 << 4)) != 0
    } else {
        false
    }
}

fn tsc_info_from_cpuid() -> Option<TscInfo> {
    let max_basic_leaf = core::arch::x86_64::__cpuid(0).eax;
    let invariant = detect_invariant_tsc();

    if max_basic_leaf >= 0x15 {
        let result = core::arch::x86_64::__cpuid_count(0x15, 0);
        let denom = result.eax as u64;
        let numer = result.ebx as u64;
        let crystal_hz = result.ecx as u64;
        if denom != 0 && numer != 0 && crystal_hz != 0 {
            let frequency = crystal_hz.saturating_mul(numer) / denom;
            if (100_000_000..=30_000_000_000).contains(&frequency) {
                return Some(TscInfo::new(frequency, invariant));
            }
        }
    }

    if max_basic_leaf >= 0x16 {
        let result = core::arch::x86_64::__cpuid(0x16);
        let base_mhz = result.eax as u64;
        if base_mhz != 0 {
            let frequency = base_mhz.saturating_mul(1_000_000);
            if (100_000_000..=30_000_000_000).contains(&frequency) {
                return Some(TscInfo::new(frequency, invariant));
            }
        }
    }

    let hypervisor = core::arch::x86_64::__cpuid(0x4000_0000);
    let mut hypervisor_sig = [0u8; 12];
    hypervisor_sig[0..4].copy_from_slice(&hypervisor.ebx.to_le_bytes());
    hypervisor_sig[4..8].copy_from_slice(&hypervisor.ecx.to_le_bytes());
    hypervisor_sig[8..12].copy_from_slice(&hypervisor.edx.to_le_bytes());
    if hypervisor.eax >= 0x4000_0010 && hypervisor_sig == *b"KVMKVMKVM\0\0\0" {
        let result = core::arch::x86_64::__cpuid(0x4000_0010);
        let tsc_khz = result.eax as u64;
        if tsc_khz != 0 {
            let frequency = tsc_khz.saturating_mul(1_000);
            if (100_000_000..=30_000_000_000).contains(&frequency) {
                return Some(TscInfo::new(frequency, invariant));
            }
        }
    }

    None
}

fn fallback_tsc_info() -> Option<TscInfo> {
    if detect_tsc_support() {
        // QEMU/TCG and some firmware paths do not expose CPUID timing leaves and
        // can fail PIT channel-2 calibration. Keep early structured logs moving
        // with a conservative estimate rather than pinning everything at 0.
        Some(TscInfo::new(EARLY_TSC_FALLBACK_HZ, false))
    } else {
        None
    }
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

/// PITを取得
pub fn pit() -> &'static Pit {
    &PIT
}

fn init_wall_clock_once() {
    // RTCから現在時刻を読み取り
    let datetime = RTC.read_datetime();
    let boot_time = datetime.to_unix_timestamp_safe().unwrap_or(0);
    let time_service = time_driver::time_service();
    let current_ms = time_service.unix_timestamp_ms();
    let target_ms = boot_time.saturating_mul(1000);
    let delta_ms = target_ms as i128 - current_ms as i128;
    let delta_ns = delta_ms.saturating_mul(NANOS_PER_MILLI as i128);
    time_service.adjust_wall_clock(delta_ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64);
}

fn try_init_tsc() -> bool {
    let bootstrap_start_tsc = rdtsc();

    // TSCをキャリブレーション (Channel 2 使用 - Channel 0 に影響しない)
    if let Some(tsc_info) = calibrate_tsc()
        .or_else(tsc_info_from_cpuid)
        .or_else(fallback_tsc_info)
    {
        SYSTEM_CLOCK.bootstrap_tsc_info(tsc_info, bootstrap_start_tsc);
        return true;
    }

    false
}

/// 割り込み有効化前でも使える早期クロック基盤を初期化する。
///
/// PIT IRQ に依存しない TSC/RTC の初期化だけを先に済ませ、logger が
/// early boot 中でも進行中のタイムスタンプを表示できるようにする。
pub fn init_early_clock() {
    if EARLY_WALL_CLOCK_INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        init_wall_clock_once();
    }

    if !EARLY_TSC_INITIALIZED.load(Ordering::Acquire) && try_init_tsc() {
        EARLY_TSC_INITIALIZED.store(true, Ordering::Release);
    }
}

/// 時間管理を初期化
pub fn init(tick_frequency: u64) {
    init_early_clock();

    // PITを初期化 (Channel 0 を周期 tick 用に設定)
    PIT.init(tick_frequency);
    // Preserve monotonicity across the early-clock -> periodic-tick handoff.
    SYSTEM_CLOCK.seed_uptime_nanos(SYSTEM_CLOCK.best_effort_time_nanos());
    let actual_frequency = PIT.frequency();
    let tick_nanos = if actual_frequency == 0 {
        0
    } else {
        NANOS_PER_SEC / actual_frequency
    };
    SYSTEM_CLOCK.set_timer_tick_nanos(tick_nanos);
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

/// 高精度な時刻を取得 (ナノ秒)
pub fn precise_time_nanos() -> u64 {
    SYSTEM_CLOCK.precise_time_nanos()
}

/// Return a best-effort monotonic time source for diagnostics/logging.
///
/// Early boot prefers calibrated TSC even before timer interrupts are enabled.
#[inline]
pub fn best_effort_time_nanos() -> u64 {
    SYSTEM_CLOCK.best_effort_time_nanos()
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
