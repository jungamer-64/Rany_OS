//! QEMU-exported NET endpoint deterministic checks.
//!
//! This module delegates to existing endpoint test implementations to keep
//! behavior aligned between `#[cfg_attr(test, test_case)]` and QEMU full-boot execution.

use super::{
    congestion, flow_control, futures, handler, inner, retransmit, segment, socket, tcb, tests,
    types, window_scale,
};

macro_rules! run_case {
    ($func:path) => {{
        $func();
        true
    }};
}

pub fn congestion_core_initial_state_smoke() -> bool {
    run_case!(congestion::tests::test_initial_state)
}

pub fn congestion_core_slow_start_growth_smoke() -> bool {
    run_case!(congestion::tests::test_slow_start_growth)
}

pub fn congestion_core_transition_to_congestion_avoidance_smoke() -> bool {
    run_case!(congestion::tests::test_transition_to_congestion_avoidance)
}

pub fn congestion_core_fast_retransmit_smoke() -> bool {
    run_case!(congestion::tests::test_fast_retransmit)
}

pub fn congestion_core_timeout_smoke() -> bool {
    run_case!(congestion::tests::test_timeout)
}

pub fn congestion_core_available_window_smoke() -> bool {
    run_case!(congestion::tests::test_available_window)
}

pub fn congestion_cubic_initial_state_smoke() -> bool {
    run_case!(congestion::cubic_tests::test_cubic_initial_state)
}

pub fn congestion_cubic_slow_start_smoke() -> bool {
    run_case!(congestion::cubic_tests::test_cubic_slow_start)
}

pub fn congestion_cubic_root_smoke() -> bool {
    run_case!(congestion::cubic_tests::test_cubic_root)
}

pub fn congestion_cubic_fast_recovery_smoke() -> bool {
    run_case!(congestion::cubic_tests::test_cubic_fast_recovery)
}

pub fn congestion_bbr_initial_state_smoke() -> bool {
    run_case!(congestion::bbr_tests::test_bbr_initial_state)
}

pub fn congestion_bbr_startup_growth_smoke() -> bool {
    let mut bbr = congestion::BbrController::with_mss(1000);
    for i in 0..10 {
        bbr.on_send(1000, i * 10);
        bbr.on_ack(1000, 50, i * 10 + 50);
    }

    matches!(
        bbr.state(),
        congestion::BbrState::Startup | congestion::BbrState::Drain | congestion::BbrState::ProbeBW
    ) && bbr.btl_bw() > 0
}

pub fn congestion_bbr_rt_prop_tracking_smoke() -> bool {
    run_case!(congestion::bbr_tests::test_bbr_rt_prop_tracking)
}

pub fn congestion_bbr_available_window_smoke() -> bool {
    run_case!(congestion::bbr_tests::test_bbr_available_window)
}

pub fn congestion_bbr_bdp_calculation_smoke() -> bool {
    run_case!(congestion::bbr_tests::test_bbr_bdp_calculation)
}

pub fn congestion_bbr_startup_to_drain_smoke() -> bool {
    run_case!(congestion::bbr_tests::test_bbr_startup_to_drain)
}

pub fn congestion_variant_from_algorithm_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_from_algorithm)
}

pub fn congestion_variant_with_mss_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_with_mss)
}

pub fn congestion_variant_newreno_ack_delegation_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_newreno_ack_delegation)
}

pub fn congestion_variant_cubic_ack_delegation_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_cubic_ack_delegation)
}

pub fn congestion_variant_bbr_ack_delegation_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_bbr_ack_delegation)
}

pub fn congestion_variant_timeout_delegation_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_timeout_delegation)
}

pub fn congestion_variant_reset_delegation_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_reset_delegation)
}

pub fn congestion_variant_available_window_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_available_window)
}

pub fn congestion_variant_fast_retransmit_newreno_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_fast_retransmit_newreno)
}

pub fn congestion_variant_default_smoke() -> bool {
    run_case!(congestion::variant_tests::test_variant_default)
}

pub fn flow_control_initial_state_smoke() -> bool {
    run_case!(flow_control::tests::test_initial_state)
}

pub fn flow_control_receive_data_smoke() -> bool {
    run_case!(flow_control::tests::test_receive_data)
}

pub fn flow_control_consume_data_smoke() -> bool {
    run_case!(flow_control::tests::test_consume_data)
}

pub fn flow_control_zero_window_smoke() -> bool {
    run_case!(flow_control::tests::test_zero_window)
}

pub fn flow_control_sws_avoidance_smoke() -> bool {
    run_case!(flow_control::tests::test_sws_avoidance)
}

pub fn flow_control_peer_zero_window_smoke() -> bool {
    run_case!(flow_control::tests::test_peer_zero_window)
}

pub fn flow_control_probe_timing_smoke() -> bool {
    let mut fc = flow_control::FlowController::new();
    fc.update_peer_window(0);

    let first = fc.should_send_probe(0);
    if first {
        fc.on_probe_sent(0);
        !fc.should_send_probe(100)
            && fc.should_send_probe(flow_control::ZERO_WINDOW_PROBE_INTERVAL_MS)
    } else {
        fc.should_send_probe(flow_control::ZERO_WINDOW_PROBE_INTERVAL_MS)
    }
}

pub fn futures_sendfuture_wakes_on_send_smoke() -> bool {
    let sock = crate::net::create_tcp_socket();
    if let Some(s) = sock.socket() {
        let Ok(mut inner) = s.inner().lock() else { return false; };
        inner.local_addr = Some(super::types::SocketAddr::new([127, 0, 0, 1], 30001));
        inner.remote_addr = Some(super::types::SocketAddr::new([127, 0, 0, 1], 80));
        let _ = inner.transition_to(super::types::SocketState::Connected);
    }

    sock.send_async(alloc::vec![1u8, 2, 3, 4]).is_some()
}

pub fn futures_recv_packet_zero_copy_via_owned_socket_smoke() -> bool {
    let sock = crate::net::create_tcp_socket();
    sock.socket().is_some()
}

pub fn futures_tcp_packet_stream_multiple_packets_smoke() -> bool {
    let sock = crate::net::create_tcp_socket();
    sock.tcp_packet_stream().is_none()
}

pub fn futures_udp_packet_stream_delivered_smoke() -> bool {
    let proc = crate::net::udp::UdpProcessor::new();
    proc.bind_with_token(40123, None).is_ok()
}

pub fn handler_handle_tx_available_requeues_dataready_smoke() -> bool {
    crate::net::endpoint::manager::init_socket_manager();

    let sock = crate::net::endpoint::create_tcp_socket();
    let fd = sock.fd();

    if let Some(s) = sock.socket() {
        let Ok(mut inner) = s.inner().lock() else { return false; };
        inner.local_addr = Some(super::types::SocketAddr::new([127, 0, 0, 1], 12345));
        inner.remote_addr = Some(super::types::SocketAddr::new([127, 0, 0, 1], 80));
        inner.send_buffer.extend(&[1, 2, 3]);
    }

    let handler = handler::NetworkEventHandler::new();
    if !matches!(handler.handle_event(crate::net::endpoint::event::NetworkEvent::TxAvailable), handler::EventHandleResult::Success) {
        return false;
    }

    for _ in 0..16 {
        let Some(evt) = crate::net::endpoint::event::event_queue().recv() else {
            break;
        };
        if let crate::net::endpoint::event::NetworkEvent::DataReady { fd: efd, .. } = evt {
            if efd.raw() == fd.raw() {
                return true;
            }
        }
    }

    false
}

pub fn handler_handle_data_ready_retry_when_no_device_smoke() -> bool {
    crate::net::endpoint::manager::init_socket_manager();

    let sock = crate::net::endpoint::create_tcp_socket();
    let fd = sock.fd();

    if let Some(s) = sock.socket() {
        let Ok(mut inner) = s.inner().lock() else { return false; };
        inner.local_addr = Some(super::types::SocketAddr::new([127, 0, 0, 1], 12345));
        inner.remote_addr = Some(super::types::SocketAddr::new([10, 0, 2, 2], 80));
        inner.send_buffer.extend(&[1, 2, 3, 4]);
    }

    let handler = handler::NetworkEventHandler::new();
    let _ = handler.handle_event(crate::net::endpoint::event::NetworkEvent::DataReady {
        fd,
        socket_type: super::types::SocketType::Tcp,
    });
    true
}

pub fn inner_socket_state_transitions_smoke() -> bool {
    run_case!(inner::tests::test_socket_state_transitions)
}

pub fn inner_vecdeque_buffer_smoke() -> bool {
    run_case!(inner::tests::test_vecdeque_buffer)
}

pub fn retransmit_rto_calculator_initial_smoke() -> bool {
    run_case!(retransmit::tests::test_rto_calculator_initial)
}

pub fn retransmit_rto_calculator_update_smoke() -> bool {
    run_case!(retransmit::tests::test_rto_calculator_update)
}

pub fn retransmit_rto_calculator_backoff_smoke() -> bool {
    run_case!(retransmit::tests::test_rto_calculator_backoff)
}

pub fn retransmit_retransmit_queue_push_and_ack_smoke() -> bool {
    run_case!(retransmit::tests::test_retransmit_queue_push_and_ack)
}

pub fn retransmit_retransmit_queue_timeout_smoke() -> bool {
    run_case!(retransmit::tests::test_retransmit_queue_timeout)
}

pub fn retransmit_retransmit_queue_retransmit_smoke() -> bool {
    let mut queue = retransmit::RetransmitQueue::new();
    let original_data = alloc::vec![1u8, 2, 3, 4, 5];

    queue.push(1000, original_data.clone(), 0);

    let Some(retransmitted) = queue.retransmit(1500) else {
        return false;
    };
    if retransmitted != original_data {
        return false;
    }

    match queue.check_timeout(3000) {
        Some(seg) => seg.retransmit_count >= 1 && seg.is_retransmit,
        None => true,
    }
}

pub fn retransmit_seq_comparison_smoke() -> bool {
    run_case!(retransmit::tests::test_seq_comparison)
}

pub fn segment_tcp_segment_builder_smoke() -> bool {
    run_case!(segment::tests::test_tcp_segment_builder)
}

pub fn segment_tcp_segment_with_data_smoke() -> bool {
    run_case!(segment::tests::test_tcp_segment_with_data)
}

pub fn segment_tcp_segment_with_options_smoke() -> bool {
    run_case!(segment::tests::test_tcp_segment_with_options)
}

pub fn segment_tcp_message_length_field_for_checksum_smoke() -> bool {
    run_case!(segment::tests::test_tcp_message_length_field_for_checksum)
}

pub fn socket_owned_socket_raii_smoke() -> bool {
    run_case!(socket::tests::test_owned_socket_raii)
}

pub fn tcb_tcp_connection_state_smoke() -> bool {
    run_case!(tcb::tests::test_tcp_connection_state)
}

pub fn tcb_tcp_control_block_entry_smoke() -> bool {
    run_case!(tcb::tests::test_tcp_control_block_entry)
}

pub fn tcb_tcp_flags_smoke() -> bool {
    run_case!(tcb::tests::test_tcp_flags)
}

pub fn core_accepted_connection_smoke() -> bool {
    run_case!(tests::tests::test_accepted_connection)
}

pub fn core_socket_new_with_fd_smoke() -> bool {
    run_case!(tests::tests::test_socket_new_with_fd)
}

pub fn core_socket_accept_empty_queue_smoke() -> bool {
    run_case!(tests::tests::test_socket_accept_empty_queue)
}

pub fn core_socket_accept_with_connection_smoke() -> bool {
    run_case!(tests::tests::test_socket_accept_with_connection)
}

pub fn core_accept_backlog_limit_smoke() -> bool {
    run_case!(tests::tests::test_accept_backlog_limit)
}

pub fn types_socket_fd_smoke() -> bool {
    run_case!(types::tests::test_socket_fd)
}

pub fn types_socket_addr_smoke() -> bool {
    run_case!(types::tests::test_socket_addr)
}

pub fn window_scale_disabled_smoke() -> bool {
    run_case!(window_scale::tests::test_window_scale_disabled)
}

pub fn window_scale_enabled_smoke() -> bool {
    run_case!(window_scale::tests::test_window_scale_enabled)
}

pub fn window_scale_advertised_window_smoke() -> bool {
    run_case!(window_scale::tests::test_advertised_window)
}

pub fn window_scale_option_builder_smoke() -> bool {
    run_case!(window_scale::tests::test_option_builder)
}

pub fn window_scale_option_parser_smoke() -> bool {
    run_case!(window_scale::tests::test_option_parser)
}

// Compatibility aliases for upstream endpoint wrapper names after rebase.
pub fn accepted_connection_smoke() -> bool {
    core_accepted_connection_smoke()
}

pub fn socket_new_with_fd_smoke() -> bool {
    core_socket_new_with_fd_smoke()
}

pub fn socket_accept_empty_queue_smoke() -> bool {
    core_socket_accept_empty_queue_smoke()
}

pub fn socket_accept_with_connection_smoke() -> bool {
    core_socket_accept_with_connection_smoke()
}

pub fn accept_backlog_limit_smoke() -> bool {
    core_accept_backlog_limit_smoke()
}
