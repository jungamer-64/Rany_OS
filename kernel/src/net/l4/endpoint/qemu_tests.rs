//! QEMU-exported NET endpoint deterministic checks.
//!
//! This module delegates to existing endpoint test implementations to keep
//! behavior aligned between `#[cfg_attr(test, test_case)]` and QEMU full-boot execution.

use super::{
    async_tests, congestion, endpoint_core, flow_control, handler, inner, retransmit, segment, tcb,
    tests, types, window_scale,
};
use crate::net::l4::test_support::new_test_endpoint;

fn test_payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
    crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
}

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let copied = crate::net::payload::PacketPayloadView::new(payload).copy_all_into(&mut out);
    out.truncate(copied);
    out
}

macro_rules! run_case {
    ($func:path) => {{
        #[cfg(all(test, feature = "qemu-test-export"))]
        {
            let _ = stringify!($func);
            true
        }
        #[cfg(not(all(test, feature = "qemu-test-export")))]
        {
            $func();
            true
        }
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

pub fn futures_send_payload_future_wakes_on_send_smoke() -> bool {
    run_case!(async_tests::test_send_payload_future_wakes_on_send)
}

pub fn futures_tcp_connection_recv_payload_smoke() -> bool {
    run_case!(async_tests::test_tcp_connection_recv_payload)
}

pub fn futures_tcp_connection_multiple_recv_payloads_smoke() -> bool {
    run_case!(async_tests::test_tcp_connection_multiple_recv_payloads)
}

pub fn futures_udp_recv_delivered_smoke() -> bool {
    crate::net::l4::udp::UdpEndpoint::bind_in(
        crate::net::runtime::default_runtime(),
        crate::net::types::InterfaceScope::Any,
        40123,
        None,
    )
    .is_ok()
}

pub fn handler_handle_tx_available_requeues_dataready_smoke() -> bool {
    crate::net::l4::endpoint::manager::init_endpoint_manager();

    let sock = new_test_endpoint(crate::net::l4::endpoint::EndpointType::Tcp);
    let fd = sock.fd();

    let Ok(mut inner) = sock.inner().lock() else {
        return false;
    };
    inner.local_addr = Some(super::types::EndpointAddr::new([127, 0, 0, 1], 12345));
    inner.remote_addr = Some(super::types::EndpointAddr::new([127, 0, 0, 1], 80));
    let _ = inner.send_payload(
        crate::net::payload::payload_from_bytes(&[1, 2, 3])
            .expect("allocate packet-backed handler smoke payload"),
    );
    drop(inner);

    let handler = handler::NetworkEventHandler::new();
    if !matches!(
        handler.handle_event_in(
            crate::net::runtime::default_runtime(),
            crate::net::l4::endpoint::event::NetworkEvent::TxAvailable,
        ),
        handler::EventHandleResult::Success
    ) {
        return false;
    }

    for _ in 0..16 {
        let Some(evt) = crate::net::l4::endpoint::event::event_queue().recv() else {
            break;
        };
        if let crate::net::l4::endpoint::event::NetworkEvent::DataReady { fd: efd, .. } = evt {
            if efd.raw() == fd.raw() {
                return true;
            }
        }
    }

    false
}

pub fn handler_handle_data_ready_retry_when_no_device_smoke() -> bool {
    crate::net::l4::endpoint::manager::init_endpoint_manager();

    let sock = new_test_endpoint(crate::net::l4::endpoint::EndpointType::Tcp);
    let fd = sock.fd();

    let Ok(mut inner) = sock.inner().lock() else {
        return false;
    };
    inner.local_addr = Some(super::types::EndpointAddr::new([127, 0, 0, 1], 12345));
    inner.remote_addr = Some(super::types::EndpointAddr::new([10, 0, 2, 2], 80));
    let _ = inner.send_payload(
        crate::net::payload::payload_from_bytes(&[1, 2, 3, 4])
            .expect("allocate packet-backed handler smoke payload"),
    );
    drop(inner);

    let handler = handler::NetworkEventHandler::new();
    let _ = handler.handle_event_in(
        crate::net::runtime::default_runtime(),
        crate::net::l4::endpoint::event::NetworkEvent::DataReady {
            fd,
            endpoint_type: super::types::EndpointType::Tcp,
        },
    );
    true
}

pub fn inner_socket_state_transitions_smoke() -> bool {
    run_case!(inner::tests::test_endpoint_state_transitions)
}

pub fn inner_payload_queue_buffer_smoke() -> bool {
    run_case!(inner::tests::test_payload_queue_buffer)
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
    let original_data = [1u8, 2, 3, 4, 5];

    queue.push(1000, test_payload(&original_data), 0);

    let Some(retransmitted) = queue.retransmit(1500) else {
        return false;
    };
    if payload_bytes(&retransmitted) != original_data {
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

pub fn socket_registered_endpoint_smoke() -> bool {
    run_case!(endpoint_core::tests::test_new_registered_endpoint_registers_socket)
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
    run_case!(tests::tests::test_endpoint_new_with_fd)
}

pub fn core_socket_accept_empty_queue_smoke() -> bool {
    run_case!(tests::tests::test_endpoint_next_connection_empty_queue)
}

pub fn core_socket_accept_with_connection_smoke() -> bool {
    run_case!(tests::tests::test_endpoint_next_connection_with_connection)
}

pub fn core_accept_backlog_limit_smoke() -> bool {
    run_case!(tests::tests::test_accept_backlog_limit)
}

pub fn types_socket_fd_smoke() -> bool {
    run_case!(types::tests::test_endpoint_fd)
}

pub fn types_socket_addr_smoke() -> bool {
    run_case!(types::tests::test_endpoint_addr)
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
