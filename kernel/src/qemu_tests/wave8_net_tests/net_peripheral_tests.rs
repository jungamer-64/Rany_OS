pub fn net_peripheral_tcp_retransmit_queue_rejection_and_return_smoke() -> bool {
    crate::net::qemu_tests::tcp_retransmit_queue_rejection_and_return_smoke()
}

pub fn net_peripheral_tcp_retransmit_ack_before_completion_smoke() -> bool {
    crate::net::qemu_tests::tcp_retransmit_ack_before_completion_smoke()
}

pub fn net_peripheral_payload_trim_respects_subspan_bounds_smoke() -> bool {
    crate::net::qemu_tests::payload_trim_respects_subspan_bounds_smoke()
}

pub fn net_peripheral_payload_bound_window_rejects_out_of_bounds_request_smoke() -> bool {
    crate::net::qemu_tests::payload_bound_window_rejects_out_of_bounds_request_smoke()
}

pub fn net_peripheral_packet_payload_take_front_splits_single_packet_smoke() -> bool {
    crate::net::qemu_tests::packet_payload_take_front_splits_single_packet_smoke()
}

pub fn net_peripheral_packet_payload_take_front_splits_on_chain_boundary_smoke() -> bool {
    crate::net::qemu_tests::packet_payload_take_front_splits_on_chain_boundary_smoke()
}

pub fn net_peripheral_packet_payload_take_front_splits_inside_chain_segment_smoke() -> bool {
    crate::net::qemu_tests::packet_payload_take_front_splits_inside_chain_segment_smoke()
}

pub fn net_peripheral_owned_payload_window_takes_bounds_from_same_payload_smoke() -> bool {
    crate::net::qemu_tests::owned_payload_window_takes_bounds_from_same_payload_smoke()
}

pub fn net_peripheral_payload_span_mut_mutates_only_checked_range_smoke() -> bool {
    crate::net::qemu_tests::payload_span_mut_mutates_only_checked_range_smoke()
}

pub fn net_peripheral_owned_payload_window_rejects_bounds_against_target_payload_smoke() -> bool {
    crate::net::qemu_tests::owned_payload_window_rejects_bounds_against_target_payload_smoke()
}

pub fn net_peripheral_socket_send_payload_rejects_partial_enqueue_without_slicing_smoke() -> bool {
    crate::net::qemu_tests::socket_send_payload_rejects_partial_enqueue_without_slicing_smoke()
}

pub fn net_peripheral_socket_take_send_segment_window_splits_front_payload_smoke() -> bool {
    crate::net::qemu_tests::socket_take_send_segment_window_splits_front_payload_smoke()
}

pub fn net_peripheral_socket_recv_payload_limit_does_not_split_front_payload_smoke() -> bool {
    crate::net::qemu_tests::socket_recv_payload_limit_does_not_split_front_payload_smoke()
}

pub fn net_peripheral_ethernet_owned_ipv4_payload_smoke() -> bool {
    crate::net::qemu_tests::ethernet_owned_ipv4_payload_smoke()
}

pub fn net_peripheral_tcp_segment_builder_smoke() -> bool {
    crate::net::qemu_tests::tcp_segment_builder_smoke()
}

pub fn net_peripheral_tcp_segment_with_data_smoke() -> bool {
    crate::net::qemu_tests::tcp_segment_with_data_smoke()
}

pub fn net_peripheral_tcp_segment_with_options_smoke() -> bool {
    crate::net::qemu_tests::tcp_segment_with_options_smoke()
}

pub fn net_peripheral_tcp_message_length_field_for_checksum_smoke() -> bool {
    crate::net::qemu_tests::tcp_message_length_field_for_checksum_smoke()
}

pub fn net_peripheral_tcp_checksum_v6_smoke() -> bool {
    crate::net::qemu_tests::tcp_checksum_v6_smoke()
}

pub fn net_peripheral_tcp_segment_mixed_family_rejection_smoke() -> bool {
    crate::net::qemu_tests::tcp_segment_mixed_family_rejection_smoke()
}

pub fn net_peripheral_tcp_segment_ipv4_queue_admission_smoke() -> bool {
    crate::net::qemu_tests::tcp_segment_ipv4_queue_admission_smoke()
}

pub fn net_peripheral_tcp_segment_ipv6_queue_admission_smoke() -> bool {
    crate::net::qemu_tests::tcp_segment_ipv6_queue_admission_smoke()
}

pub fn net_peripheral_ndp_build_ns_smoke() -> bool {
    crate::net::qemu_tests::ndp_build_ns_smoke()
}

pub fn net_peripheral_ndp_build_na_smoke() -> bool {
    crate::net::qemu_tests::ndp_build_na_smoke()
}

pub fn net_peripheral_ndp_build_rs_smoke() -> bool {
    crate::net::qemu_tests::ndp_build_rs_smoke()
}

pub fn net_peripheral_neighbor_resolution_completion_smoke() -> bool {
    crate::net::qemu_tests::neighbor_resolution_completion_smoke()
}

pub async fn net_peripheral_neighbor_resolution_elapsed_timeout_smoke() -> bool {
    crate::net::qemu_tests::neighbor_resolution_elapsed_timeout_smoke().await
}

pub fn net_peripheral_dhcp_v4_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip_smoke()
-> bool {
    crate::net::qemu_tests::dhcp_v4_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip_smoke()
}

pub fn net_peripheral_dhcp_v4_build_request_requesting_includes_serverid_and_requestedip_smoke()
-> bool {
    crate::net::qemu_tests::dhcp_v4_build_request_requesting_includes_serverid_and_requestedip_smoke(
    )
}

pub fn net_peripheral_dhcp_v4_build_discover_reuse_xid_on_retransmit_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_build_discover_reuse_xid_on_retransmit_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_chaddr_mismatch_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_chaddr_mismatch_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_ack_requesting_mismatch_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_ack_requesting_mismatch_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_ack_renewal_success_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_ack_renewal_success_smoke()
}

pub fn net_peripheral_dhcp_v4_build_decline_and_build_release_contents_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_build_decline_and_build_release_contents_smoke()
}

pub fn net_peripheral_dhcp_v4_release_clears_lease_and_sets_last_released_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_release_clears_lease_and_sets_last_released_smoke()
}

pub async fn net_peripheral_dhcp_v4_parse_t1_t2_and_timeout_transitions_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_parse_t1_t2_and_timeout_transitions_smoke().await
}

pub async fn net_peripheral_dhcp_v4_offer_probe_and_decline_flow_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_offer_probe_and_decline_flow_smoke().await
}

pub fn net_peripheral_dhcp_v6_build_solicit_min_size_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_build_solicit_min_size_smoke()
}

pub fn net_peripheral_dhcp_v6_parse_reply_with_iaaddr_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_parse_reply_with_iaaddr_smoke()
}

pub fn net_peripheral_dhcp_v6_build_request_min_size_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_build_request_min_size_smoke()
}

pub fn net_peripheral_dhcp_v6_bound_to_renewing_and_rebinding_transitions_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_bound_to_renewing_and_rebinding_transitions_smoke()
}

pub fn net_peripheral_dhcp_v6_handle_packet_stores_server_addr_and_duid_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_handle_packet_stores_server_addr_and_duid_smoke()
}

pub fn net_peripheral_dhcp_v6_advertise_triggers_request_and_requesting_state_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_advertise_triggers_request_and_requesting_state_smoke()
}

pub fn net_peripheral_dhcp_v6_requesting_retransmit_exhaustion_goes_to_init_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_requesting_retransmit_exhaustion_goes_to_init_smoke()
}

pub fn net_peripheral_dhcp_v6_solicit_advertise_request_reply_complete_flow_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_solicit_advertise_request_reply_complete_flow_smoke()
}

pub fn net_peripheral_dhcp_v6_renew_uses_known_server_address_for_dst_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v6_renew_uses_known_server_address_for_dst_smoke()
}

pub fn net_peripheral_igmp_igmp_type_conversion_smoke() -> bool {
    crate::net::qemu_tests::igmp_igmp_type_conversion_smoke()
}

pub fn net_peripheral_igmp_multicast_validation_smoke() -> bool {
    crate::net::qemu_tests::igmp_multicast_validation_smoke()
}

pub fn net_peripheral_igmp_join_group_smoke() -> bool {
    crate::net::qemu_tests::igmp_join_group_smoke()
}

pub fn net_peripheral_igmp_join_group_unsolicited_followup_smoke() -> bool {
    crate::net::qemu_tests::igmp_join_group_unsolicited_followup_smoke()
}

pub fn net_peripheral_igmp_join_invalid_address_smoke() -> bool {
    crate::net::qemu_tests::igmp_join_invalid_address_smoke()
}

pub fn net_peripheral_igmp_leave_group_smoke() -> bool {
    crate::net::qemu_tests::igmp_leave_group_smoke()
}

pub fn net_peripheral_igmp_leave_nonmember_smoke() -> bool {
    crate::net::qemu_tests::igmp_leave_nonmember_smoke()
}

pub fn net_peripheral_igmp_igmp_checksum_smoke() -> bool {
    crate::net::qemu_tests::igmp_igmp_checksum_smoke()
}

pub fn net_peripheral_igmp_build_report_smoke() -> bool {
    crate::net::qemu_tests::igmp_build_report_smoke()
}

pub fn net_peripheral_igmp_build_leave_smoke() -> bool {
    crate::net::qemu_tests::igmp_build_leave_smoke()
}

pub fn net_peripheral_igmp_multicast_ip_to_mac_smoke() -> bool {
    crate::net::qemu_tests::igmp_multicast_ip_to_mac_smoke()
}

pub fn net_peripheral_igmp_process_general_query_smoke() -> bool {
    crate::net::qemu_tests::igmp_process_general_query_smoke()
}

pub fn net_peripheral_igmp_report_suppression_smoke() -> bool {
    crate::net::qemu_tests::igmp_report_suppression_smoke()
}

pub fn net_peripheral_igmp_v3_report_minimal_layout_accepted_smoke() -> bool {
    crate::net::qemu_tests::igmp_v3_report_minimal_layout_accepted_smoke()
}

pub fn net_peripheral_igmp_v3_report_invalid_layout_rejected_smoke() -> bool {
    crate::net::qemu_tests::igmp_v3_report_invalid_layout_rejected_smoke()
}

pub fn net_peripheral_tcp_ooo_permits_and_bounded_queue_smoke() -> bool {
    crate::net::qemu_tests::tcp_ooo_permits_and_bounded_queue_smoke()
}

pub async fn net_peripheral_tcp_stateless_reset_budget_uses_system_uptime_smoke() -> bool {
    crate::net::qemu_tests::tcp_stateless_reset_budget_uses_system_uptime_smoke().await
}

pub fn net_peripheral_runtime_two_runtimes_bind_same_udp_port_independently_smoke() -> bool {
    crate::net::qemu_tests::runtime_two_runtimes_bind_same_udp_port_independently_smoke()
}

pub fn net_peripheral_runtime_udp_concrete_ingress_interface_is_preserved_smoke() -> bool {
    crate::net::qemu_tests::runtime_udp_concrete_ingress_interface_is_preserved_smoke()
}

pub fn net_peripheral_runtime_large_packet_headroom_preserves_request_smoke() -> bool {
    crate::net::qemu_tests::runtime_large_packet_headroom_preserves_request_smoke()
}

pub fn net_peripheral_runtime_fake_ports_smp_flow_failover_smoke() -> bool {
    crate::net::qemu_tests::runtime_fake_ports_smp_flow_failover_smoke()
}
