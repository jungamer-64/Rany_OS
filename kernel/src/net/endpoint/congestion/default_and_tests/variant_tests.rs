

// =====================================================
// CongestionControllerVariant テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod variant_tests {
    use crate::net::endpoint::congestion::{
        CongestionAlgorithm, CongestionControllerVariant, CongestionState, DEFAULT_MSS,
        INITIAL_WINDOW,
    };

    #[cfg_attr(test, test_case)]
    pub fn test_variant_from_algorithm() {
        let nr = CongestionControllerVariant::from_algorithm(CongestionAlgorithm::NewReno);
        assert_eq!(nr.algorithm(), CongestionAlgorithm::NewReno);
        assert_eq!(nr.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);

        let cubic = CongestionControllerVariant::from_algorithm(CongestionAlgorithm::Cubic);
        assert_eq!(cubic.algorithm(), CongestionAlgorithm::Cubic);
        assert_eq!(cubic.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);

        let bbr = CongestionControllerVariant::from_algorithm(CongestionAlgorithm::Bbr);
        assert_eq!(bbr.algorithm(), CongestionAlgorithm::Bbr);
        assert_eq!(bbr.cwnd(), INITIAL_WINDOW * DEFAULT_MSS);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_with_mss() {
        let v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::Cubic, 1000);
        assert_eq!(v.mss(), 1000);
        assert_eq!(v.cwnd(), INITIAL_WINDOW * 1000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_newreno_ack_delegation() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::NewReno, 1000);
        let initial_cwnd = v.cwnd();

        // New ACK should increase cwnd in slow start
        v.on_ack(1000, false, 1000, 0, 0);
        assert!(v.cwnd() > initial_cwnd);
        assert_eq!(v.congestion_state(), CongestionState::SlowStart);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_cubic_ack_delegation() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::Cubic, 1000);
        let initial_cwnd = v.cwnd();

        // New ACK should increase cwnd in slow start
        v.on_ack(1000, false, 1000, 100, 0);
        assert!(v.cwnd() > initial_cwnd);
        assert_eq!(v.congestion_state(), CongestionState::SlowStart);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_bbr_ack_delegation() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::Bbr, 1000);

        // Send then receive ACK
        v.on_send(1000, 0);
        v.on_ack(1000, false, 0, 50, 50);

        // BBR reports CongestionAvoidance for congestion_state()
        assert_eq!(v.congestion_state(), CongestionState::CongestionAvoidance);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_timeout_delegation() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::NewReno, 1000);

        // Simulate data in flight then timeout
        v.on_send(5000, 0);
        v.on_timeout(100);

        // Should be back in slow start with cwnd = 1 MSS
        assert_eq!(v.congestion_state(), CongestionState::SlowStart);
        assert_eq!(v.cwnd(), 1000); // 1 MSS
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_reset_delegation() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::Cubic, 1000);

        // Modify state
        v.on_send(5000, 0);
        v.on_timeout(100);
        assert_eq!(v.congestion_state(), CongestionState::SlowStart);
        assert_ne!(v.cwnd(), INITIAL_WINDOW * 1000);

        // Reset should restore initial state
        v.reset();
        assert_eq!(v.cwnd(), INITIAL_WINDOW * 1000);
        assert_eq!(v.congestion_state(), CongestionState::SlowStart);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_available_window() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::NewReno, 1000);

        v.on_send(3000, 0);

        // cwnd = 10000, bytes_in_flight = 3000, rwnd = 20000
        // available = min(10000, 20000) - 3000 = 7000
        assert_eq!(v.available_window(20000), 7000);

        // rwnd limited: min(10000, 5000) - 3000 = 2000
        assert_eq!(v.available_window(5000), 2000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_fast_retransmit_newreno() {
        let mut v = CongestionControllerVariant::from_algorithm_with_mss(CongestionAlgorithm::NewReno, 1000);

        v.on_send(10000, 0);

        // 3 duplicate ACKs should trigger Fast Recovery
        v.on_ack(0, true, 1000, 0, 0);
        v.on_ack(0, true, 1000, 0, 0);
        v.on_ack(0, true, 1000, 0, 0);

        assert_eq!(v.congestion_state(), CongestionState::FastRecovery);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_variant_default() {
        let v = CongestionControllerVariant::default();
        assert_eq!(v.algorithm(), CongestionAlgorithm::NewReno);
    }
}
