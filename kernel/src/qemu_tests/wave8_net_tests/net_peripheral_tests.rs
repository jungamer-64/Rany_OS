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

pub fn net_peripheral_dhcp_v4_parse_t1_t2_and_timeout_transitions_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_parse_t1_t2_and_timeout_transitions_smoke()
}

pub fn net_peripheral_dhcp_v4_offer_probe_and_decline_flow_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_offer_probe_and_decline_flow_smoke()
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

pub fn net_peripheral_runtime_two_runtimes_bind_same_udp_port_independently_smoke() -> bool {
    crate::net::qemu_tests::runtime_two_runtimes_bind_same_udp_port_independently_smoke()
}

pub fn net_peripheral_runtime_udp_concrete_ingress_interface_is_preserved_smoke() -> bool {
    crate::net::qemu_tests::runtime_udp_concrete_ingress_interface_is_preserved_smoke()
}

pub fn net_peripheral_runtime_large_packet_headroom_preserves_request_smoke() -> bool {
    crate::net::qemu_tests::runtime_large_packet_headroom_preserves_request_smoke()
}
