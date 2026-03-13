use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_decode_hour_24h_mode() {
    // 24時間表記: そのまま返す

    // Binary mode: is_binary=true
    assert_eq!(Rtc::decode_hour(0, true, true), 0);
    assert_eq!(Rtc::decode_hour(18, true, true), 18); // Input 18 (0x12) -> 18
    assert_eq!(Rtc::decode_hour(12, true, true), 12);
    assert_eq!(Rtc::decode_hour(23, true, true), 23);

    // BCD mode: is_binary=false
    assert_eq!(Rtc::decode_hour(0x00, false, true), 0);
    assert_eq!(Rtc::decode_hour(0x12, false, true), 12); // BCD 0x12 -> 12
    assert_eq!(Rtc::decode_hour(0x23, false, true), 23); // BCD 0x23 -> 23
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_decode_hour_12h_mode_edge_cases() {
    // 12 AM (midnight) → 0
    assert_eq!(Rtc::decode_hour(0x12, false, false), 0); // BCD 12, no PM bit
    assert_eq!(Rtc::decode_hour(12, true, false), 0); // Binary 12, no PM bit

    // 12 PM (noon) → 12
    assert_eq!(Rtc::decode_hour(0x92, false, false), 12); // BCD 12 with PM bit (0x80 | 0x12)
    assert_eq!(Rtc::decode_hour(0x8C, true, false), 12); // Binary 12 with PM bit (0x80 | 12)

    // 1-11 AM → 1-11
    assert_eq!(Rtc::decode_hour(0x01, false, false), 1);
    assert_eq!(Rtc::decode_hour(0x11, false, false), 11); // BCD 0x11 = 11

    // 1-11 PM → 13-23
    assert_eq!(Rtc::decode_hour(0x81, false, false), 13); // BCD 1 with PM
    assert_eq!(Rtc::decode_hour(0x91, false, false), 23); // BCD 11 with PM (0x80 | 0x11)
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_tsc_to_nanos_overflow_safe() {
    // Use TscInfo::new() which computes mult/shift automatically
    let info = TscInfo::new(3_000_000_000, true); // 3 GHz

    // Large TSC value that would overflow with naive u64 multiplication
    let tsc = 10_000_000_000_000u64; // 10 trillion ticks
    let nanos = info.tsc_to_nanos(tsc);

    // Expected: 10e12 / 3e9 = 3333.33... seconds = 3333333333333 ns
    // Allow small rounding error due to fixed-point approximation
    let expected = 3_333_333_333_333u64;
    let error = if nanos > expected {
        nanos - expected
    } else {
        expected - nanos
    };
    assert!(
        error < 1_000_000,
        "Error too large: {} (expected ~{})",
        nanos,
        expected
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_compute_tsc_mult_shift() {
    // Test that mult/shift computation works for typical CPU frequencies
    let (mult, shift) = compute_tsc_mult_shift(3_000_000_000); // 3 GHz
    assert!(mult > 0, "mult should be non-zero");
    assert!(shift > 0, "shift should be non-zero");

    // Verify conversion accuracy: 1 second of TSC ticks
    let tsc = 3_000_000_000u64;
    let nanos = ((tsc as u128 * mult as u128) >> shift) as u64;
    let expected = NANOS_PER_SEC;
    let error = if nanos > expected {
        nanos - expected
    } else {
        expected - nanos
    };
    // Allow up to 0.1% error
    assert!(
        error < expected / 1000,
        "Conversion error too large: {} vs {}",
        nanos,
        expected
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_tsc_to_nanos_precise_vs_optimized() {
    let info = TscInfo::new(2_500_000_000, true); // 2.5 GHz

    // Compare precise vs optimized for various TSC values
    for &tsc in &[1_000_000u64, 1_000_000_000, 10_000_000_000, 100_000_000_000] {
        let precise = info.tsc_to_nanos_precise(tsc);
        let optimized = info.tsc_to_nanos(tsc);
        let error = if optimized > precise {
            optimized - precise
        } else {
            precise - optimized
        };
        // Allow up to 0.1% relative error or 1000 ns absolute error
        let max_error = (precise / 1000).max(1000);
        assert!(
            error <= max_error,
            "tsc={}: precise={}, optimized={}, error={}",
            tsc,
            precise,
            optimized,
            error
        );
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_system_clock_timer_tick_nanos_round_trip() {
    let clock = SystemClock::new();
    assert_eq!(clock.timer_tick_nanos(), 0);

    clock.set_timer_tick_nanos(NANOS_PER_MILLI);
    assert_eq!(clock.timer_tick_nanos(), NANOS_PER_MILLI);

    clock.tick(clock.timer_tick_nanos());
    assert_eq!(clock.uptime_millis(), 1);
}
