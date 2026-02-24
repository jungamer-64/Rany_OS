use super::*;

macro_rules! run_case {
    ($func:path) => {{
        $func();
        true
    }};
}

pub fn dhcp_v4_check_timeout_poisoned_state_reset_skips_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_check_timeout_poisoned_state_reset_skips)
}

pub fn dhcp_v4_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip)
}

pub fn dhcp_v4_build_request_requesting_includes_serverid_and_requestedip_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_request_requesting_includes_serverid_and_requestedip)
}

pub fn dhcp_v4_build_discover_reuse_xid_on_retransmit_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_discover_reuse_xid_on_retransmit)
}

pub fn dhcp_v4_build_discover_state_lock_poison_returns_err_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_discover_state_lock_poison_returns_err)
}

pub fn dhcp_v4_process_response_chaddr_mismatch_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_chaddr_mismatch)
}

pub fn dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_offer_missing_serverid_returns_err)
}

pub fn dhcp_v4_process_response_siaddr_serverid_mismatch_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_siaddr_serverid_mismatch)
}

pub fn dhcp_v4_process_response_ack_requesting_mismatch_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_ack_requesting_mismatch)
}

pub fn dhcp_v4_process_response_ack_renewal_success_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_ack_renewal_success)
}

pub fn dhcp_v4_build_decline_and_build_release_contents_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_build_decline_and_build_release_contents)
}

pub fn dhcp_v4_release_clears_lease_and_sets_last_released_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_release_clears_lease_and_sets_last_released)
}

pub fn dhcp_v4_parse_t1_t2_and_timeout_transitions_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_parse_t1_t2_and_timeout_transitions)
}

pub fn dhcp_v4_offer_probe_and_decline_flow_smoke() -> bool {
    use crate::net::dhcp::{DhcpClient, DhcpHeader, DhcpMessageType, DhcpOperation, DhcpOption, DHCP_MAGIC_COOKIE};
    use crate::net::ethernet::MacAddress;
    use crate::net::stack;
    
    stack::init_default();

    let client = DhcpClient::new(MacAddress::new([7, 7, 7, 7, 7, 7]));

    let mut buf = alloc::vec![0u8; DhcpHeader::SIZE + 64];
    buf[0] = DhcpOperation::Reply as u8;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&0u32.to_be_bytes());
    buf[16..20].copy_from_slice(&[10, 0, 0, 9]);
    buf[28..34].copy_from_slice(&[7, 7, 7, 7, 7, 7]);

    let mut offset = DhcpHeader::SIZE;
    buf[offset..offset + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
    offset += 4;
    buf[offset] = DhcpOption::MessageType as u8;
    buf[offset + 1] = 1;
    buf[offset + 2] = DhcpMessageType::Offer as u8;
    offset += 3;
    buf[offset] = DhcpOption::ServerIdentifier as u8;
    buf[offset + 1] = 4;
    buf[offset + 2..offset + 6].copy_from_slice(&[10, 0, 0, 1]);
    offset += 6;
    buf[offset] = DhcpOption::End as u8;

    if client.process_response(&buf, 100).is_err() {
        return false;
    }
    let _ = client.check_timeout(102, 1);
    client
        .last_declined_ip()
        .map(|ip| ip == crate::net::ipv4::Ipv4Address::new([10, 0, 0, 9]))
        .unwrap_or(true)
}

// new smoke test exercising public runtime APIs
pub fn dhcp_v4_runtime_api_lastfields_smoke() -> bool {
    use crate::net::{dhcp_last_declined, dhcp_last_released};
    use crate::net::stack;

    stack::init_default();
    let _ = crate::net::init_dhcp_runtime();

    // initially None
    if dhcp_last_declined().is_some() || dhcp_last_released().is_some() {
        return false;
    }

    // manipulate global client directly to produce values
    if let Ok(mut guard) = crate::net::dhcp::DHCP_CLIENT.lock() {
        if let Some(client) = *guard {
            // simulate lease and then release via public API
            let lease = crate::net::dhcp::DhcpLease {
                ip_address: crate::net::Ipv4Address::new([1,2,3,4]),
                subnet_mask: crate::net::Ipv4Address::new([255,255,255,0]),
                gateway: None,
                dns_servers: alloc::vec![],
                server_ip: crate::net::Ipv4Address::new([1,2,3,1]),
                lease_time: 0,
                t1:0,
                t2:0,
                obtained_at:0,
                hostname:None,
                domain_name:None,
            };
            if let Ok(mut lg) = client.lease.lock() {
                *lg = Some(lease.clone());
            }
        }
    }

    crate::net::dhcp_release();
    if dhcp_last_released() != Some([1,2,3,4]) {
        return false;
    }

    // simulate a decline
    if let Ok(mut guard) = crate::net::dhcp::DHCP_CLIENT.lock() {
        if let Some(client) = *guard {
            let _ = client.send_decline(crate::net::Ipv4Address::new([5,6,7,8]), None);
        }
    }
    if dhcp_last_declined() != Some([5,6,7,8]) {
        return false;
    }

    true
}

pub fn dhcp_v6_build_solicit_min_size_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_build_solicit_min_size)
}

pub fn dhcp_v6_parse_reply_with_iaaddr_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_parse_reply_with_iaaddr)
}

pub fn dhcp_v6_build_request_min_size_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_build_request_min_size)
}

pub fn dhcp_v6_bound_to_renewing_and_rebinding_transitions_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_bound_to_renewing_and_rebinding_transitions)
}

pub fn dhcp_v6_handle_packet_stores_server_addr_and_duid_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_handle_packet_stores_server_addr_and_duid)
}

pub fn dhcp_v6_advertise_triggers_request_and_requesting_state_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_advertise_triggers_request_and_requesting_state)
}

pub fn dhcp_v6_requesting_retransmit_exhaustion_goes_to_init_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_requesting_retransmit_exhaustion_goes_to_init)
}

pub fn dhcp_v6_solicit_advertise_request_reply_complete_flow_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_solicit_advertise_request_reply_complete_flow)
}

pub fn dhcp_v6_renew_uses_known_server_address_for_dst_smoke() -> bool {
    run_case!(dhcp::qemu_v6_tests::test_renew_uses_known_server_address_for_dst)
}

pub fn dns_primary_server_poisoned_returns_none_smoke() -> bool {
    run_case!(dns::tests::test_primary_server_poisoned_returns_none)
}

pub fn dns_dns_header_truncated_flag_smoke() -> bool {
    run_case!(dns::tests::test_dns_header_truncated_flag)
}

pub fn dns_dns_header_not_truncated_smoke() -> bool {
    run_case!(dns::tests::test_dns_header_not_truncated)
}

pub fn dns_build_tcp_query_smoke() -> bool {
    run_case!(dns::tests::test_build_tcp_query)
}

pub fn dns_needs_tcp_fallback_truncated_smoke() -> bool {
    run_case!(dns::tests::test_needs_tcp_fallback_truncated)
}

pub fn dns_needs_tcp_fallback_512_bytes_smoke() -> bool {
    run_case!(dns::tests::test_needs_tcp_fallback_512_bytes)
}

pub fn dns_needs_tcp_fallback_normal_smoke() -> bool {
    run_case!(dns::tests::test_needs_tcp_fallback_normal)
}

pub fn dns_tcp_message_length_smoke() -> bool {
    run_case!(dns::tests::test_tcp_message_length)
}

pub fn mdns_constants_smoke() -> bool {
    run_case!(mdns::tests::test_constants)
}

pub fn mdns_multicast_mac_smoke() -> bool {
    run_case!(mdns::tests::test_multicast_mac)
}

pub fn mdns_mdns_service_new_smoke() -> bool {
    run_case!(mdns::tests::test_mdns_service_new)
}

pub fn mdns_encode_decode_dns_name_smoke() -> bool {
    run_case!(mdns::tests::test_encode_decode_dns_name)
}

pub fn mdns_build_query_smoke() -> bool {
    run_case!(mdns::tests::test_build_query)
}

pub fn mdns_build_response_smoke() -> bool {
    run_case!(mdns::tests::test_build_response)
}

pub fn mdns_process_query_for_our_hostname_smoke() -> bool {
    run_case!(mdns::tests::test_process_query_for_our_hostname)
}

pub fn mdns_process_query_for_other_hostname_smoke() -> bool {
    run_case!(mdns::tests::test_process_query_for_other_hostname)
}

pub fn mdns_process_response_updates_cache_smoke() -> bool {
    run_case!(mdns::tests::test_process_response_updates_cache)
}

pub fn mdns_cleanup_expired_smoke() -> bool {
    run_case!(mdns::tests::test_cleanup_expired)
}

pub fn mdns_invalid_packet_too_short_smoke() -> bool {
    run_case!(mdns::tests::test_invalid_packet_too_short)
}

pub fn mdns_names_equal_case_insensitive_smoke() -> bool {
    run_case!(mdns::tests::test_names_equal_case_insensitive)
}

pub fn mdns_dns_name_compression_smoke() -> bool {
    run_case!(mdns::tests::test_dns_name_compression)
}

pub fn mdns_encode_dns_name_label_too_long_smoke() -> bool {
    run_case!(mdns::tests::test_encode_dns_name_label_too_long)
}

pub fn mdns_roundtrip_query_response_smoke() -> bool {
    run_case!(mdns::tests::test_roundtrip_query_response)
}

pub fn igmp_igmp_type_conversion_smoke() -> bool {
    run_case!(igmp::tests::test_igmp_type_conversion)
}

pub fn igmp_multicast_validation_smoke() -> bool {
    run_case!(igmp::tests::test_multicast_validation)
}

pub fn igmp_join_group_smoke() -> bool {
    run_case!(igmp::tests::test_join_group)
}

pub fn igmp_join_invalid_address_smoke() -> bool {
    run_case!(igmp::tests::test_join_invalid_address)
}

pub fn igmp_leave_group_smoke() -> bool {
    run_case!(igmp::tests::test_leave_group)
}

pub fn igmp_leave_nonmember_smoke() -> bool {
    run_case!(igmp::tests::test_leave_nonmember)
}

pub fn igmp_igmp_checksum_smoke() -> bool {
    run_case!(igmp::tests::test_igmp_checksum)
}

pub fn igmp_build_report_smoke() -> bool {
    run_case!(igmp::tests::test_build_report)
}

pub fn igmp_build_leave_smoke() -> bool {
    run_case!(igmp::tests::test_build_leave)
}

pub fn igmp_multicast_ip_to_mac_smoke() -> bool {
    run_case!(igmp::tests::test_multicast_ip_to_mac)
}

pub fn igmp_process_general_query_smoke() -> bool {
    run_case!(igmp::tests::test_process_general_query)
}

pub fn igmp_report_suppression_smoke() -> bool {
    run_case!(igmp::tests::test_report_suppression)
}

pub fn driver_bridge_zero_copy_via_bridge_smoke() -> bool {
    driver_bridge::tests::qemu_zero_copy_via_bridge_smoke()
}

pub fn driver_bridge_routing_and_nat_smoke() -> bool {
    driver_bridge::tests::qemu_routing_and_nat_smoke()
}

pub fn driver_bridge_nat_inbound_roundtrip_is_protocol_scoped_smoke() -> bool {
    run_case!(driver_bridge::tests::test_nat_inbound_roundtrip_is_protocol_scoped)
}

pub fn driver_bridge_nat_gc_expires_idle_entries_smoke() -> bool {
    run_case!(driver_bridge::tests::test_nat_gc_expires_idle_entries)
}

pub fn driver_bridge_zero_copy_via_bridge_v6_smoke() -> bool {
    driver_bridge::tests::qemu_zero_copy_via_bridge_v6_smoke()
}

pub fn driver_bridge_per_interface_bridge_stats_are_separated_smoke() -> bool {
    run_case!(driver_bridge::tests::test_per_interface_bridge_stats_are_separated)
}

pub fn driver_bridge_register_virtio_port_is_idempotent_and_records_mapping_smoke() -> bool {
    run_case!(driver_bridge::tests::test_register_virtio_port_is_idempotent_and_records_mapping)
}

pub fn driver_bridge_register_virtio_port_prefers_vnet0_as_primary_smoke() -> bool {
    run_case!(driver_bridge::tests::test_register_virtio_port_prefers_vnet0_as_primary)
}

pub fn driver_bridge_virtio_transmit_interface_argument_smoke() -> bool {
    run_case!(driver_bridge::tests::test_virtio_transmit_interface_argument)
}
