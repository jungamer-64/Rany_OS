pub fn net_peripheral_dhcp_v4_check_timeout_poisoned_state_reset_skips_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_check_timeout_poisoned_state_reset_skips_smoke()
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

pub fn net_peripheral_dhcp_v4_build_discover_state_lock_poison_returns_err_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_build_discover_state_lock_poison_returns_err_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_chaddr_mismatch_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_chaddr_mismatch_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke()
}

pub fn net_peripheral_dhcp_v4_process_response_siaddr_serverid_mismatch_smoke() -> bool {
    crate::net::qemu_tests::dhcp_v4_process_response_siaddr_serverid_mismatch_smoke()
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

pub fn net_peripheral_dns_primary_server_poisoned_returns_none_smoke() -> bool {
    crate::net::qemu_tests::dns_primary_server_poisoned_returns_none_smoke()
}

pub fn net_peripheral_dns_dns_header_truncated_flag_smoke() -> bool {
    crate::net::qemu_tests::dns_dns_header_truncated_flag_smoke()
}

pub fn net_peripheral_dns_dns_header_not_truncated_smoke() -> bool {
    crate::net::qemu_tests::dns_dns_header_not_truncated_smoke()
}

pub fn net_peripheral_dns_build_tcp_query_smoke() -> bool {
    crate::net::qemu_tests::dns_build_tcp_query_smoke()
}

pub fn net_peripheral_dns_needs_tcp_fallback_truncated_smoke() -> bool {
    crate::net::qemu_tests::dns_needs_tcp_fallback_truncated_smoke()
}

pub fn net_peripheral_dns_needs_tcp_fallback_512_bytes_smoke() -> bool {
    crate::net::qemu_tests::dns_needs_tcp_fallback_512_bytes_smoke()
}

pub fn net_peripheral_dns_needs_tcp_fallback_normal_smoke() -> bool {
    crate::net::qemu_tests::dns_needs_tcp_fallback_normal_smoke()
}

pub fn net_peripheral_dns_tcp_message_length_smoke() -> bool {
    crate::net::qemu_tests::dns_tcp_message_length_smoke()
}

pub fn net_peripheral_mdns_constants_smoke() -> bool {
    crate::net::qemu_tests::mdns_constants_smoke()
}

pub fn net_peripheral_mdns_multicast_mac_smoke() -> bool {
    crate::net::qemu_tests::mdns_multicast_mac_smoke()
}

pub fn net_peripheral_mdns_mdns_service_new_smoke() -> bool {
    crate::net::qemu_tests::mdns_mdns_service_new_smoke()
}

pub fn net_peripheral_mdns_encode_decode_dns_name_smoke() -> bool {
    crate::net::qemu_tests::mdns_encode_decode_dns_name_smoke()
}

pub fn net_peripheral_mdns_build_query_smoke() -> bool {
    crate::net::qemu_tests::mdns_build_query_smoke()
}

pub fn net_peripheral_mdns_build_response_smoke() -> bool {
    crate::net::qemu_tests::mdns_build_response_smoke()
}

pub fn net_peripheral_mdns_process_query_for_our_hostname_smoke() -> bool {
    crate::net::qemu_tests::mdns_process_query_for_our_hostname_smoke()
}

pub fn net_peripheral_mdns_process_query_for_other_hostname_smoke() -> bool {
    crate::net::qemu_tests::mdns_process_query_for_other_hostname_smoke()
}

pub fn net_peripheral_mdns_process_response_updates_cache_smoke() -> bool {
    crate::net::qemu_tests::mdns_process_response_updates_cache_smoke()
}

pub fn net_peripheral_mdns_cleanup_expired_smoke() -> bool {
    crate::net::qemu_tests::mdns_cleanup_expired_smoke()
}

pub fn net_peripheral_mdns_invalid_packet_too_short_smoke() -> bool {
    crate::net::qemu_tests::mdns_invalid_packet_too_short_smoke()
}

pub fn net_peripheral_mdns_names_equal_case_insensitive_smoke() -> bool {
    crate::net::qemu_tests::mdns_names_equal_case_insensitive_smoke()
}

pub fn net_peripheral_mdns_dns_name_compression_smoke() -> bool {
    crate::net::qemu_tests::mdns_dns_name_compression_smoke()
}

pub fn net_peripheral_mdns_encode_dns_name_label_too_long_smoke() -> bool {
    crate::net::qemu_tests::mdns_encode_dns_name_label_too_long_smoke()
}

pub fn net_peripheral_mdns_roundtrip_query_response_smoke() -> bool {
    crate::net::qemu_tests::mdns_roundtrip_query_response_smoke()
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

pub fn net_peripheral_driver_bridge_zero_copy_via_bridge_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_zero_copy_via_bridge_smoke()
}

pub fn net_peripheral_driver_bridge_routing_and_nat_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_routing_and_nat_smoke()
}

pub fn net_peripheral_driver_bridge_nat_inbound_roundtrip_is_protocol_scoped_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_nat_inbound_roundtrip_is_protocol_scoped_smoke()
}

pub fn net_peripheral_driver_bridge_nat_gc_expires_idle_entries_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_nat_gc_expires_idle_entries_smoke()
}

pub fn net_peripheral_driver_bridge_zero_copy_via_bridge_v6_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_zero_copy_via_bridge_v6_smoke()
}

pub fn net_peripheral_driver_bridge_per_interface_bridge_stats_are_separated_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_per_interface_bridge_stats_are_separated_smoke()
}

pub fn net_peripheral_driver_bridge_register_virtio_port_is_idempotent_and_records_mapping_smoke()
-> bool {
    crate::net::qemu_tests::driver_bridge_register_virtio_port_is_idempotent_and_records_mapping_smoke()
}

pub fn net_peripheral_driver_bridge_register_virtio_port_prefers_vnet0_as_primary_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_register_virtio_port_prefers_vnet0_as_primary_smoke()
}

pub fn net_peripheral_driver_bridge_virtio_transmit_interface_argument_smoke() -> bool {
    crate::net::qemu_tests::driver_bridge_virtio_transmit_interface_argument_smoke()
}
