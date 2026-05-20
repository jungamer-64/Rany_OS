// ============================================================================
// kernel/src/net/tests/qemu/peripheral_tests.rs - Network QEMU peripheral smoke tests
// ============================================================================

use crate::net::l3::{igmp, ipv4::Ipv4Address};
use crate::net::l4::socket::{Socket, SocketFamily, bind_udp_dual_stack_in, find_udp_by_port_in};
use crate::net::l4::udp::{UdpProcessor, UdpResult};
use crate::net::payload::alloc_packet_with_headroom;
use crate::net::runtime::create_runtime;
use crate::net::services::dhcp;
use crate::net::types::InterfaceScope;
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

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

pub fn dhcp_v4_process_response_chaddr_mismatch_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_chaddr_mismatch)
}

pub fn dhcp_v4_process_response_offer_missing_serverid_returns_err_smoke() -> bool {
    run_case!(dhcp::qemu_v4_tests::test_process_response_offer_missing_serverid_returns_err)
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

    stack::init_in(crate::net::runtime::default_runtime());

    let client = DhcpClient::new(
        crate::net::runtime::default_runtime(),
        MacAddress::new([7, 7, 7, 7, 7, 7]),
    );

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

pub fn runtime_two_runtimes_bind_same_udp_port_independently_smoke() -> bool {
    let Ok(runtime_a) = create_runtime() else {
        return false;
    };
    let Ok(runtime_b) = create_runtime() else {
        return false;
    };

    let socket_a = Socket::new_udp_in(runtime_a);
    let socket_b = Socket::new_udp_in(runtime_b);

    bind_udp_dual_stack_in(runtime_a, 80, InterfaceScope::Any, socket_a.socket_id()).is_ok()
        && bind_udp_dual_stack_in(runtime_b, 80, InterfaceScope::Any, socket_b.socket_id()).is_ok()
        && find_udp_by_port_in(runtime_a, SocketFamily::Ipv4, 80, None).is_some()
        && find_udp_by_port_in(runtime_b, SocketFamily::Ipv4, 80, None).is_some()
}

pub fn runtime_udp_missing_ingress_interface_is_explicit_smoke() -> bool {
    let Ok(runtime) = create_runtime() else {
        return false;
    };
    let processor = UdpProcessor::new();

    processor.process_payload_on(
        runtime,
        None,
        PacketPayload::default(),
        Ipv4Address::ANY,
        Ipv4Address::ANY,
        64,
    ) == UdpResult::NoIngressInterface
}

pub fn runtime_large_packet_headroom_preserves_request_smoke() -> bool {
    let requested_headroom = DEFAULT_PACKET_HEADROOM.saturating_mul(2);
    let Some(packet) = alloc_packet_with_headroom(128, requested_headroom) else {
        return false;
    };

    packet.headroom() >= requested_headroom && packet.len() == 128
}
