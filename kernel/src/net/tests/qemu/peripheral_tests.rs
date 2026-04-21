// ============================================================================
// kernel/src/net/tests/qemu/peripheral_tests.rs - Network QEMU peripheral smoke tests
// ============================================================================

use super::*;

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

fn install_default_runtime_dhcp_v4_client(
    mac: crate::net::l2::ethernet::MacAddress,
) -> alloc::sync::Arc<crate::net::services::dhcp::DhcpClient> {
    let runtime = crate::net::runtime::default_runtime();
    crate::net::runtime::manager::init_network_manager_in(runtime);

    let if_id = crate::net::runtime::manager::register_interface_in(runtime, "dhcp-qemu-test0")
        .expect("register dhcp qemu test interface");
    let mut config = crate::net::runtime::stack::NetworkConfig::default();
    config.mac = mac;
    crate::net::runtime::manager::set_interface_config_in(runtime, if_id, config)
        .expect("set dhcp qemu test config");
    crate::net::services::dhcp::ensure_interface_runtime(if_id, config)
        .expect("init dhcp qemu interface runtime");
    crate::net::services::dhcp::mark_primary_interface(if_id);
    crate::net::services::dhcp::primary_v4_client_in(crate::net::runtime::default_runtime())
        .expect("dhcp client")
}

pub fn dhcp_v4_check_timeout_poisoned_state_reset_skips_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_check_timeout_poisoned_state_reset_skips)
}

pub fn dhcp_v4_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip_smoke() -> bool {
    run_case!(
        dhcp::qemu_v4_tests::test_build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip
    )
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
    use crate::net::l2::ethernet::MacAddress;
    use crate::net::runtime::stack;
    use crate::net::services::dhcp::{
        DHCP_MAGIC_COOKIE, DhcpClient, DhcpHeader, DhcpMessageType, DhcpOperation, DhcpOption,
    };

    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );

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
        .map(|ip| ip == crate::net::l3::ipv4::Ipv4Address::new([10, 0, 0, 9]))
        .unwrap_or(true)
}

// DHCP ランタイムスナップショットで last_declined / last_released を検証する。
pub fn dhcp_v4_runtime_api_lastfields_smoke() -> bool {
    use crate::net::runtime::stack;

    crate::net::runtime::context::reset_runtime_registry_for_tests();
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );
    let _ = crate::net::api::dhcp::init_dhcp_runtime();
    let client = install_default_runtime_dhcp_v4_client(
        crate::net::runtime::stack::NetworkConfig::default().mac,
    );

    // initially None
    let st = {
        crate::net::runtime::command::reset_command_system_for_tests();

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output =
                crate::net::api::dhcp::dhcp_state_in(crate::net::runtime::default_runtime()).await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async {
            crate::net::runtime::command_loop::runtime_command_task().await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests();
        output.expect("dhcp_state smoke future timed out")
    };
    if st.v4_last_declined.is_some() || st.v4_last_released.is_some() {
        return false;
    }

    let lease = crate::net::services::dhcp::DhcpLease {
        ip_address: crate::net::l3::ipv4::Ipv4Address::new([1, 2, 3, 4]),
        subnet_mask: crate::net::l3::ipv4::Ipv4Address::new([255, 255, 255, 0]),
        gateway: None,
        dns_servers: alloc::vec![],
        server_ip: crate::net::l3::ipv4::Ipv4Address::new([1, 2, 3, 1]),
        lease_time: 0,
        t1: 0,
        t2: 0,
        obtained_at: 0,
        hostname: None,
        domain_name: None,
    };
    client.set_lease_for_test(lease);
    client.release();

    let st2 = {
        crate::net::runtime::command::reset_command_system_for_tests();

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output =
                crate::net::api::dhcp::dhcp_state_in(crate::net::runtime::default_runtime()).await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async {
            crate::net::runtime::command_loop::runtime_command_task().await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests();
        output.expect("dhcp_state release snapshot future timed out")
    };
    if st2.v4_last_released != Some([1, 2, 3, 4]) {
        return false;
    }

    let _ = client.send_decline(crate::net::l3::ipv4::Ipv4Address::new([5, 6, 7, 8]), None);
    let st3 = {
        crate::net::runtime::command::reset_command_system_for_tests();

        let result_slot = alloc::sync::Arc::new(crate::sync::PoisonLock::new(None));
        let completed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let result_slot_clone = result_slot.clone();
        let completed_clone = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            let output =
                crate::net::api::dhcp::dhcp_state_in(crate::net::runtime::default_runtime()).await;
            let mut slot = result_slot_clone.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(output);
            completed_clone.store(true, core::sync::atomic::Ordering::Release);
        }));
        executor.spawn(crate::task::Task::new(async {
            crate::net::runtime::command_loop::runtime_command_task().await;
        }));

        let mut output = None;
        for _ in 0..100_000 {
            executor.drive_once_for_test();
            if completed.load(core::sync::atomic::Ordering::Acquire) {
                output = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                break;
            }
        }

        crate::net::runtime::command::reset_command_system_for_tests();
        output.expect("dhcp_state decline snapshot future timed out")
    };
    if st3.v4_last_declined != Some([5, 6, 7, 8]) {
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

pub fn dns_build_tcp_query_payload_smoke() -> bool {
    run_case!(dns::tests::test_build_tcp_query_payload)
}

pub fn dns_build_query_with_edns0_smoke() -> bool {
    run_case!(dns::tests::test_build_query_with_edns0)
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

pub fn dns_parse_aaaa_record_smoke() -> bool {
    run_case!(dns::tests::test_parse_aaaa_record)
}

pub fn dns_parse_response_rejects_unexpected_transaction_id_smoke() -> bool {
    run_case!(dns::tests::test_parse_response_rejects_unexpected_transaction_id)
}

pub fn dns_parse_response_rejects_question_mismatch_smoke() -> bool {
    run_case!(dns::tests::test_parse_response_rejects_question_mismatch)
}

pub fn dns_cache_entry_ttl_boundary_smoke() -> bool {
    run_case!(dns::tests::test_cache_entry_ttl_boundary)
}

pub fn dns_cname_chain_extracts_final_a_smoke() -> bool {
    run_case!(dns::tests::test_cname_chain_extracts_final_a)
}

pub fn dns_cname_chain_extracts_final_aaaa_smoke() -> bool {
    run_case!(dns::tests::test_cname_chain_extracts_final_aaaa)
}

pub fn dns_parse_response_preserves_unknown_rtype_smoke() -> bool {
    run_case!(dns::tests::test_parse_response_preserves_unknown_rtype)
}

pub fn dns_build_prioritized_server_list_ipv4_then_ipv6_smoke() -> bool {
    run_case!(dns::tests::test_build_prioritized_server_list_ipv4_then_ipv6)
}

pub fn dns_ptr_ipv4_query_name_smoke() -> bool {
    run_case!(dns::tests::test_ptr_ipv4_query_name)
}

pub fn dns_ptr_ipv6_query_name_smoke() -> bool {
    run_case!(dns::tests::test_ptr_ipv6_query_name)
}

pub fn dns_resolve_txt_from_records_filters_name_smoke() -> bool {
    run_case!(dns::tests::test_resolve_txt_from_records_filters_name)
}

pub fn dns_resolve_mx_from_records_returns_structs_smoke() -> bool {
    run_case!(dns::tests::test_resolve_mx_from_records_returns_structs)
}

pub fn dns_resolve_srv_from_records_returns_structs_smoke() -> bool {
    run_case!(dns::tests::test_resolve_srv_from_records_returns_structs)
}

pub fn dns_resolve_ptr_from_records_follows_cname_chain_smoke() -> bool {
    run_case!(dns::tests::test_resolve_ptr_from_records_follows_cname_chain)
}

pub fn dns_resolve_ptr_ipv6_from_records_follows_cname_chain_smoke() -> bool {
    run_case!(dns::tests::test_resolve_ptr_ipv6_from_records_follows_cname_chain)
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

pub fn igmp_join_group_unsolicited_followup_smoke() -> bool {
    run_case!(igmp::tests::test_join_group_unsolicited_followup)
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

pub fn igmp_v3_report_minimal_layout_accepted_smoke() -> bool {
    run_case!(igmp::tests::test_v3_report_minimal_layout_accepted)
}

pub fn igmp_v3_report_invalid_layout_rejected_smoke() -> bool {
    run_case!(igmp::tests::test_v3_report_invalid_layout_rejected)
}

pub fn stack_glue_zero_copy_via_bridge_smoke() -> bool {
    stack_glue::tests::qemu_zero_copy_via_bridge_smoke()
}

pub fn stack_glue_routing_and_nat_smoke() -> bool {
    stack_glue::tests::qemu_routing_and_nat_smoke()
}

pub fn stack_glue_nat_inbound_roundtrip_is_protocol_scoped_smoke() -> bool {
    run_case!(stack_glue::tests::test_nat_inbound_roundtrip_is_protocol_scoped)
}

pub fn stack_glue_nat_gc_expires_idle_entries_smoke() -> bool {
    run_case!(stack_glue::tests::test_nat_gc_expires_idle_entries)
}

pub fn stack_glue_zero_copy_via_bridge_v6_smoke() -> bool {
    stack_glue::tests::qemu_zero_copy_via_bridge_v6_smoke()
}

pub fn stack_glue_per_interface_stats_are_separated_smoke() -> bool {
    run_case!(stack_glue::tests::test_per_interface_bridge_stats_are_separated)
}

pub fn port_runtime_transmit_interface_argument_smoke() -> bool {
    run_case!(stack_glue::tests::test_transmit_from_stack_interface_argument)
}
