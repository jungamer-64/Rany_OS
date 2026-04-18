use super::*;

#[cfg_attr(test, test_case)]
pub fn test_initial_state() {
    let cc = CongestionController::new();
    assert_eq!(cc.state(), CongestionState::SlowStart);
    assert_eq!(cc.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
    assert_eq!(cc.ssthresh(), u32::MAX);
}

#[cfg_attr(test, test_case)]
pub fn test_slow_start_growth() {
    let mut cc = CongestionController::with_mss(1000);
    let initial_cwnd = cc.cwnd();

    // ACK受信でcwnd増加
    cc.on_ack(1000, false, 1000);
    assert!(cc.cwnd() > initial_cwnd);
    assert_eq!(cc.state(), CongestionState::SlowStart);
}

#[cfg_attr(test, test_case)]
pub fn test_transition_to_congestion_avoidance() {
    let mut cc = CongestionController::with_mss(1000);
    cc.ssthresh = 5000; // 強制的に低く設定

    // Slow Start で ssthresh を超えるまでACK
    for _ in 0..10 {
        cc.on_ack(1000, false, 0);
    }

    assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
}

#[cfg_attr(test, test_case)]
pub fn test_fast_retransmit() {
    let mut cc = CongestionController::with_mss(1000);
    cc.bytes_in_flight = 10000;

    // 3重複ACKでFast Recovery
    cc.on_ack(0, true, 1000);
    cc.on_ack(0, true, 1000);
    cc.on_ack(0, true, 1000);

    assert_eq!(cc.state(), CongestionState::FastRecovery);
    assert!(cc.ssthresh() < u32::MAX);
}

#[cfg_attr(test, test_case)]
pub fn test_timeout() {
    let mut cc = CongestionController::with_mss(1000);
    cc.cwnd = 50000;
    cc.bytes_in_flight = 30000;

    cc.on_timeout();

    assert_eq!(cc.state(), CongestionState::SlowStart);
    assert_eq!(cc.cwnd(), 1000); // 1 MSS
    assert_eq!(cc.ssthresh(), 15000); // FlightSize / 2
}

#[cfg_attr(test, test_case)]
pub fn test_available_window() {
    let mut cc = CongestionController::with_mss(1000);
    cc.cwnd = 10000;
    cc.bytes_in_flight = 3000;

    // cwnd制限
    assert_eq!(cc.available_window(20000), 7000);

    // rwnd制限
    assert_eq!(cc.available_window(5000), 2000);
}
