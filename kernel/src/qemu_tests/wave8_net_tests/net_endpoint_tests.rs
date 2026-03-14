pub fn net_endpoint_congestion_default_cubic_initial_state_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::cubic_initial_state_smoke()
}

pub fn net_endpoint_congestion_default_cubic_slow_start_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::cubic_slow_start_smoke()
}

pub fn net_endpoint_congestion_default_cubic_root_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::cubic_root_smoke()
}

pub fn net_endpoint_congestion_default_cubic_fast_recovery_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::cubic_fast_recovery_smoke()
}

pub fn net_endpoint_congestion_default_bbr_initial_state_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::bbr_initial_state_smoke()
}

pub fn net_endpoint_congestion_default_bbr_startup_growth_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::bbr_startup_growth_smoke()
}

pub fn net_endpoint_congestion_default_bbr_rt_prop_tracking_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::bbr_rt_prop_tracking_smoke()
}

pub fn net_endpoint_congestion_default_bbr_available_window_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::bbr_available_window_smoke()
}

pub fn net_endpoint_congestion_default_bbr_bdp_calculation_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::bbr_bdp_calculation_smoke()
}

pub fn net_endpoint_congestion_default_bbr_startup_to_drain_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::bbr_startup_to_drain_smoke()
}

pub fn net_endpoint_congestion_variant_variant_from_algorithm_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_from_algorithm_smoke()
}

pub fn net_endpoint_congestion_variant_variant_with_mss_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_with_mss_smoke()
}

pub fn net_endpoint_congestion_variant_variant_newreno_ack_delegation_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_newreno_ack_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_variant_cubic_ack_delegation_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_cubic_ack_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_variant_bbr_ack_delegation_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_bbr_ack_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_variant_timeout_delegation_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_timeout_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_variant_reset_delegation_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_reset_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_variant_available_window_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_available_window_smoke()
}

pub fn net_endpoint_congestion_variant_variant_fast_retransmit_newreno_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_fast_retransmit_newreno_smoke()
}

pub fn net_endpoint_congestion_variant_variant_default_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::variant_default_smoke()
}

pub fn net_endpoint_congestion_core_initial_state_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::initial_state_smoke()
}

pub fn net_endpoint_congestion_core_slow_start_growth_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::slow_start_growth_smoke()
}

pub fn net_endpoint_congestion_core_transition_to_congestion_avoidance_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::transition_to_congestion_avoidance_smoke()
}

pub fn net_endpoint_congestion_core_fast_retransmit_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::fast_retransmit_smoke()
}

pub fn net_endpoint_congestion_core_timeout_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::timeout_smoke()
}

pub fn net_endpoint_congestion_core_available_window_smoke() -> bool {
    crate::net::l4::endpoint::congestion::qemu_tests::available_window_smoke()
}

pub fn net_endpoint_flow_control_initial_state_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::initial_state_smoke()
}

pub fn net_endpoint_flow_control_receive_data_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::receive_data_smoke()
}

pub fn net_endpoint_flow_control_consume_data_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::consume_data_smoke()
}

pub fn net_endpoint_flow_control_zero_window_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::zero_window_smoke()
}

pub fn net_endpoint_flow_control_sws_avoidance_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::sws_avoidance_smoke()
}

pub fn net_endpoint_flow_control_peer_zero_window_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::peer_zero_window_smoke()
}

pub fn net_endpoint_flow_control_probe_timing_smoke() -> bool {
    crate::net::l4::endpoint::flow_control::qemu_tests::probe_timing_smoke()
}

pub fn net_endpoint_futures_sendfuture_wakes_on_send_smoke() -> bool {
    crate::net::l4::endpoint::futures::qemu_tests::sendfuture_wakes_on_send_smoke()
}

pub fn net_endpoint_futures_recv_packet_zero_copy_via_owned_socket_smoke() -> bool {
    crate::net::l4::endpoint::futures::qemu_tests::recv_packet_zero_copy_via_owned_socket_smoke()
}

pub fn net_endpoint_futures_tcp_packet_stream_multiple_packets_smoke() -> bool {
    crate::net::l4::endpoint::futures::qemu_tests::tcp_packet_stream_multiple_packets_smoke()
}

pub fn net_endpoint_futures_udp_packet_stream_delivered_smoke() -> bool {
    crate::net::l4::endpoint::futures::qemu_tests::udp_packet_stream_delivered_smoke()
}

pub fn net_endpoint_handler_handle_tx_available_requeues_dataready_smoke() -> bool {
    crate::net::l4::endpoint::handler::qemu_tests::handle_tx_available_requeues_dataready_smoke()
}

pub fn net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke() -> bool {
    crate::net::l4::endpoint::handler::qemu_tests::handle_data_ready_retry_when_no_device_smoke()
}

pub fn net_endpoint_inner_socket_state_transitions_smoke() -> bool {
    crate::net::l4::endpoint::inner::qemu_tests::endpoint_state_transitions_smoke()
}

pub fn net_endpoint_inner_vecdeque_buffer_smoke() -> bool {
    crate::net::l4::endpoint::inner::qemu_tests::vecdeque_buffer_smoke()
}

pub fn net_endpoint_retransmit_rto_calculator_initial_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::rto_calculator_initial_smoke()
}

pub fn net_endpoint_retransmit_rto_calculator_update_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::rto_calculator_update_smoke()
}

pub fn net_endpoint_retransmit_rto_calculator_backoff_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::rto_calculator_backoff_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_push_and_ack_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::retransmit_queue_push_and_ack_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_timeout_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::retransmit_queue_timeout_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_retransmit_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::retransmit_queue_retransmit_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_process_sack_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::retransmit_queue_process_sack_smoke()
}

pub fn net_endpoint_retransmit_seq_comparison_smoke() -> bool {
    crate::net::l4::endpoint::retransmit::qemu_tests::seq_comparison_smoke()
}

pub fn net_endpoint_segment_tcp_segment_builder_smoke() -> bool {
    crate::net::l4::endpoint::segment::qemu_tests::tcp_segment_builder_smoke()
}

pub fn net_endpoint_segment_tcp_segment_with_data_smoke() -> bool {
    crate::net::l4::endpoint::segment::qemu_tests::tcp_segment_with_data_smoke()
}

pub fn net_endpoint_segment_tcp_segment_with_options_smoke() -> bool {
    crate::net::l4::endpoint::segment::qemu_tests::tcp_segment_with_options_smoke()
}

pub fn net_endpoint_segment_tcp_message_length_field_for_checksum_smoke() -> bool {
    crate::net::l4::endpoint::segment::qemu_tests::tcp_message_length_field_for_checksum_smoke()
}

pub fn net_endpoint_socket_owned_socket_raii_smoke() -> bool {
    crate::net::l4::endpoint::qemu_tests::socket_owned_socket_raii_smoke()
}

pub fn net_endpoint_tcb_tcp_connection_state_smoke() -> bool {
    crate::net::l4::endpoint::tcb::qemu_tests::tcp_connection_state_smoke()
}

pub fn net_endpoint_tcb_tcp_control_block_entry_smoke() -> bool {
    crate::net::l4::endpoint::tcb::qemu_tests::tcp_control_block_entry_smoke()
}

pub fn net_endpoint_tcb_tcp_flags_smoke() -> bool {
    crate::net::l4::endpoint::tcb::qemu_tests::tcp_flags_smoke()
}

pub fn net_endpoint_core_accepted_connection_smoke() -> bool {
    crate::net::l4::endpoint::qemu_tests::core_accepted_connection_smoke()
}

pub fn net_endpoint_core_socket_new_with_fd_smoke() -> bool {
    crate::net::l4::endpoint::qemu_tests::core_socket_new_with_fd_smoke()
}

pub fn net_endpoint_core_socket_accept_empty_queue_smoke() -> bool {
    crate::net::l4::endpoint::qemu_tests::core_socket_accept_empty_queue_smoke()
}

pub fn net_endpoint_core_socket_accept_with_connection_smoke() -> bool {
    crate::net::l4::endpoint::qemu_tests::core_socket_accept_with_connection_smoke()
}

pub fn net_endpoint_core_accept_backlog_limit_smoke() -> bool {
    crate::net::l4::endpoint::qemu_tests::core_accept_backlog_limit_smoke()
}

pub fn net_endpoint_types_socket_fd_smoke() -> bool {
    crate::net::l4::endpoint::types::qemu_tests::endpoint_fd_smoke()
}

pub fn net_endpoint_types_socket_addr_smoke() -> bool {
    crate::net::l4::endpoint::types::qemu_tests::endpoint_addr_smoke()
}

pub fn net_endpoint_window_scale_window_scale_disabled_smoke() -> bool {
    crate::net::l4::endpoint::window_scale::qemu_tests::window_scale_disabled_smoke()
}

pub fn net_endpoint_window_scale_window_scale_enabled_smoke() -> bool {
    crate::net::l4::endpoint::window_scale::qemu_tests::window_scale_enabled_smoke()
}

pub fn net_endpoint_window_scale_advertised_window_smoke() -> bool {
    crate::net::l4::endpoint::window_scale::qemu_tests::advertised_window_smoke()
}

pub fn net_endpoint_window_scale_option_builder_smoke() -> bool {
    crate::net::l4::endpoint::window_scale::qemu_tests::option_builder_smoke()
}

pub fn net_endpoint_window_scale_option_parser_smoke() -> bool {
    crate::net::l4::endpoint::window_scale::qemu_tests::option_parser_smoke()
}
