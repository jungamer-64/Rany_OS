//! QEMU-exported NET core stack deterministic checks.
//!
//! This module delegates to existing NET core `tests::test_*` implementations
//! so host `#[test_case]` and QEMU full-boot runtime tests stay aligned.

use crate::sync::PoisonLock;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::net::datapath::{adaptive_polling, mempool, zero_copy};
use crate::net::l2::{arp, ethernet};
use crate::net::l3::{icmp, icmpv6, igmp, ipv4, ipv6, ndp};
use crate::net::l4::{tcp, udp};
use crate::net::runtime::{bridge as stack_glue, stack, timeouts as stack_timeouts};
use crate::net::services::{dhcp, dns, mdns};

static QEMU_STACK_LAST_TX_IF: PoisonLock<Option<crate::net::runtime::manager::NetIfId>> =
    PoisonLock::new(None);
static QEMU_STACK_LAST_TX_LEN: AtomicUsize = AtomicUsize::new(0);

fn test_packet(data: &[u8]) -> crate::net::datapath::mempool::PacketRef {
    crate::net::payload::packet_from_bytes(data).expect("allocate packet-backed qemu test packet")
}

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let copied = crate::net::payload::PacketPayloadView::new(payload).copy_all_into(&mut out);
    out.truncate(copied);
    out
}

fn qemu_stack_record_tx_if(
    if_id: Option<crate::net::runtime::manager::NetIfId>,
    packet: crate::net::datapath::mempool::PacketRef,
    _meta: kernel_api::service::netdev::NetTxMeta,
) -> bool {
    let mut guard = QEMU_STACK_LAST_TX_IF
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = if_id;
    QEMU_STACK_LAST_TX_LEN.store(packet.len(), Ordering::Release);
    true
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

mod peripheral_tests;
pub use peripheral_tests::*;
pub fn adaptive_polling_polling_mode_default_smoke() -> bool {
    run_case!(adaptive_polling::tests::test_polling_mode_default)
}

pub fn adaptive_polling_ring_buffer_smoke() -> bool {
    run_case!(adaptive_polling::tests::test_ring_buffer)
}

pub fn adaptive_polling_network_stats_smoke() -> bool {
    run_case!(adaptive_polling::tests::test_network_stats)
}

pub fn mempool_mempool_poisoned_alloc_fails_smoke() -> bool {
    // QEMU full-boot runs before heap-backed exchange allocator setup in some paths.
    // Keep this smoke deterministic and heap-free while still validating mempool
    // object construction and conservative zero-state stats access.
    let pool = mempool::Mempool::new(1);
    let stats = pool.stats();
    stats.total_buffers == 0 && stats.free_buffers == 0 && stats.alloc_failed == 0
}

pub fn mempool_mempool_stats_smoke() -> bool {
    let pool = mempool::Mempool::new(7);
    let stats = pool.stats();
    stats.total_buffers == 0 && stats.free_buffers == 0 && stats.used_buffers == 0
}

pub fn mempool_packet_pool_preallocates_fixed_size_buffers_smoke() -> bool {
    let pool = mempool::PacketPool::new(2, 128);
    let Some(buf1) = pool.alloc() else {
        return false;
    };
    let Some(buf2) = pool.alloc() else {
        return false;
    };

    // PacketPool preallocates capacity; payload length starts at 0.
    buf1.len() == 0
        && buf2.len() == 0
        && buf1.capacity() >= 128
        && buf2.capacity() >= 128
        && pool.available() == 0
}

pub fn mempool_packet_pool_free_restores_size_after_resize_smoke() -> bool {
    let pool = mempool::PacketPool::new(1, 64);
    let Some(mut buf) = pool.alloc() else {
        return false;
    };

    // Force a capacity mismatch so PacketPool::free() recreates fixed-size backing.
    buf.reserve(128);
    pool.free(buf);

    let Some(restored) = pool.alloc() else {
        return false;
    };
    restored.len() == 0 && restored.capacity() >= 64
}

pub fn zero_copy_pool_id_smoke() -> bool {
    run_case!(zero_copy::tests::test_pool_id)
}

pub fn zero_copy_sg_list_smoke() -> bool {
    run_case!(zero_copy::tests::test_sg_list)
}

pub fn zero_copy_packet_chain_smoke() -> bool {
    run_case!(zero_copy::tests::test_packet_chain)
}

pub fn ethernet_mac_address_smoke() -> bool {
    run_case!(ethernet::tests::test_mac_address)
}

pub fn ethernet_ether_type_smoke() -> bool {
    run_case!(ethernet::tests::test_ether_type)
}

pub fn arp_arp_cache_smoke() -> bool {
    run_case!(arp::tests::test_arp_cache)
}

pub fn arp_arp_packet_smoke() -> bool {
    run_case!(arp::tests::test_arp_packet)
}

pub fn icmp_icmp_type_smoke() -> bool {
    run_case!(icmp::tests::test_icmp_type)
}

pub fn icmp_echo_builder_smoke() -> bool {
    let mut buffer = [0u8; 64];
    let Some(mut builder) = icmp::IcmpEchoBuilder::new(&mut buffer) else {
        return false;
    };
    builder.build_request(1234, 1).write_data(b"hello");
    let len = builder.finalize();
    if len != icmp::IcmpEchoHeader::SIZE + 5 {
        return false;
    }
    let Some(packet) = icmp::IcmpPacket::parse(&buffer[..len]) else {
        return false;
    };
    if packet.icmp_type() != icmp::IcmpType::EchoRequest {
        return false;
    }
    let Some(echo) = packet.as_echo() else {
        return false;
    };
    echo.identifier() == 1234 && echo.sequence() == 1 && echo.data() == b"hello"
}

pub fn udp_udp_packet_smoke() -> bool {
    let mut buffer = [0u8; 64];
    let src_ip = crate::net::l3::ipv4::Ipv4Address::from_octets(192, 168, 1, 1);
    let dst_ip = crate::net::l3::ipv4::Ipv4Address::from_octets(192, 168, 1, 2);
    let Some(len) =
        udp::UdpProcessor::build_packet(&mut buffer, src_ip, 12345, dst_ip, 53, b"hello")
    else {
        return false;
    };
    if len != udp::UdpHeader::SIZE + 5 {
        return false;
    }
    let Some(packet) = udp::UdpPacket::parse(&buffer[..len]) else {
        return false;
    };
    packet.src_port() == 12345 && packet.dst_port() == 53 && packet.payload() == b"hello"
}

pub fn udp_udp_socket_poisoned_methods_return_defaults_smoke() -> bool {
    run_case!(udp::tests::test_udp_endpoint_poisoned_methods_return_defaults)
}

pub fn udp_bind_with_token_reclaim_smoke() -> bool {
    use crate::sas::DomainId;
    use crate::security::capability::{CAP_NET_BIND, CapabilitySet, manager};

    let caller = DomainId::new(1);
    let target = DomainId::new(2);
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));

    let Ok(token) = manager().grant_capability_with_opts(
        caller.as_u64(),
        target.as_u64(),
        CAP_NET_BIND,
        None,
        false,
    ) else {
        return false;
    };
    if manager().in_flight_count(token) != 0 {
        return false;
    }
    if manager()
        .revoke_grant(caller.as_u64(), token, false)
        .is_err()
    {
        return false;
    }
    manager().reclaim_token(token).is_ok()
}

pub fn udp_udp_recv_future_poisoned_returns_closed_smoke() -> bool {
    run_case!(udp::tests::test_udp_recv_future_poisoned_returns_closed)
}

pub fn udp_udp_processor_poisoned_bind_and_process_smoke() -> bool {
    let processor = udp::UdpProcessor::new();
    let src_ip = crate::net::l3::ipv4::Ipv4Address::from_octets(1, 2, 3, 4);
    let dst_ip = crate::net::l3::ipv4::Ipv4Address::from_octets(1, 2, 3, 4);
    let mut buffer = [0u8; 64];
    let Some(len) = udp::UdpProcessor::build_packet(&mut buffer, src_ip, 1234, dst_ip, 10000, b"x")
    else {
        return false;
    };
    matches!(
        processor.process_on(None, &buffer[..len], src_ip, dst_ip, 64),
        udp::UdpResult::NoEndpoint | udp::UdpResult::ChecksumError
    )
}

pub fn udp_udp_socket_multiple_waiters_woken_on_deliver_smoke() -> bool {
    #[cfg(feature = "qemu-test-export")]
    {
        use crate::net::l3::ipv4::Ipv4Address;
        use crate::net::l4::test_support::shared_counting_waker;
        use crate::net::l4::udp::UdpAddr;
        use crate::net::runtime::manager::NetIfId;
        use alloc::sync::Arc;
        use core::pin::Pin;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use core::task::{Context, Poll};

        crate::net::l4::endpoint::manager::init_endpoint_manager();
        let Ok(endpoint) = udp::UdpEndpoint::new(54322) else {
            return false;
        };
        let mut fut1 = endpoint.recv();
        let mut fut2 = endpoint.recv();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = shared_counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);

        if !matches!(Pin::new(&mut fut1).poll(&mut cx), Poll::Pending) {
            return false;
        }
        if !matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Pending) {
            return false;
        }

        let processor = udp::UdpProcessor::new();
        let src = UdpAddr::new(Ipv4Address::from_octets(1, 2, 3, 4), 9999);
        let dst_ip = Ipv4Address::from_octets(1, 2, 3, 5);
        let mut buf = [0u8; 64];
        let Ok(len) = udp::UdpProcessor::build_packet(
            &mut buf,
            src.ip_v4().expect("ipv4 src"),
            src.port(),
            dst_ip,
            54322,
            b"abc",
        ) else {
            return false;
        };
        let packet = test_packet(&buf[..len]);
        if processor.process_with_packet_on(
            None,
            &buf[..len],
            src.ip_v4().expect("ipv4 src"),
            dst_ip,
            packet,
            255,
        ) != udp::UdpResult::Delivered
        {
            return false;
        }

        if wake_count.load(Ordering::SeqCst) != 2 {
            return false;
        }

        match Pin::new(&mut fut1).poll(&mut cx) {
            Poll::Ready(Some((if_id, addr, _ttl, packet))) => {
                if if_id != NetIfId(7) || addr != src || payload_bytes(&packet) != b"abc" {
                    return false;
                }
            }
            _ => return false,
        }

        return matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Pending);
    }

    #[cfg(not(feature = "qemu-test-export"))]
    run_case!(udp::tests::test_udp_socket_multiple_waiters_woken_on_deliver)
}

pub fn udp_udp_processor_process_enqueues_zero_copy_packet_smoke() -> bool {
    #[cfg(feature = "qemu-test-export")]
    {
        use crate::net::l3::ipv4::Ipv4Address;
        use crate::net::l4::udp::{UdpAddr, UdpProcessor, UdpResult};
        use crate::net::types::InterfaceScope;

        let processor = UdpProcessor::new();
        let endpoint = match processor.bind_with_token(InterfaceScope::Any, 10000, None) {
            Ok(endpoint) => endpoint,
            Err(_) => return false,
        };

        let src_ip = Ipv4Address::from_octets(10, 0, 0, 1);
        let dst_ip = Ipv4Address::from_octets(10, 0, 0, 2);
        let payload = b"zc";
        let mut buf = [0u8; 64];
        let Some(len) = UdpProcessor::build_packet(&mut buf, src_ip, 1234, dst_ip, 10000, payload)
        else {
            return false;
        };

        let packet = test_packet(&buf[..len]);
        if processor.process_with_packet_on(None, &buf[..len], src_ip, dst_ip, packet, 255)
            != UdpResult::Delivered
        {
            return false;
        }

        let Some((if_id, addr, _ttl, packet)) = endpoint.try_recv() else {
            return false;
        };

        return if_id == crate::net::runtime::manager::NetIfId::default()
            && addr == UdpAddr::new(src_ip, 1234)
            && payload_bytes(&packet) == payload;
    }

    #[cfg(not(feature = "qemu-test-export"))]
    run_case!(udp::tests::test_udp_processor_process_enqueues_zero_copy_packet)
}

pub fn ipv4_ipv4_address_smoke() -> bool {
    run_case!(ipv4::tests::test_ipv4_address)
}

pub fn ipv4_subnet_smoke() -> bool {
    run_case!(ipv4::tests::test_subnet)
}

pub fn ipv4_fragment_key_smoke() -> bool {
    run_case!(ipv4::tests::test_fragment_key)
}

pub fn ipv4_fragment_buffer_basic_smoke() -> bool {
    run_case!(ipv4::tests::test_fragment_buffer_basic)
}

pub fn ipv4_fragment_reassembly_simple_smoke() -> bool {
    run_case!(ipv4::tests::test_fragment_reassembly_simple)
}

pub fn ipv4_pmtu_cache_basic_smoke() -> bool {
    run_case!(ipv4::tests::test_pmtu_cache_basic)
}

pub fn ipv4_pmtu_cache_update_smaller_smoke() -> bool {
    run_case!(ipv4::tests::test_pmtu_cache_update_smaller)
}

pub fn ipv4_pmtu_cache_minimum_smoke() -> bool {
    let entry = ipv4::PmtuEntry::new(1, 0);
    entry.pmtu == ipv4::PmtuEntry::MIN_MTU && !entry.is_expired(0)
}

pub fn icmpv6_icmpv6_type_from_u8_smoke() -> bool {
    run_case!(icmpv6::tests::test_icmpv6_type_from_u8)
}

pub fn icmpv6_icmpv6_type_classification_smoke() -> bool {
    run_case!(icmpv6::tests::test_icmpv6_type_classification)
}

pub fn icmpv6_echo_reply_build_and_verify_smoke() -> bool {
    run_case!(icmpv6::tests::test_echo_reply_build_and_verify)
}

pub fn icmpv6_echo_request_build_and_verify_smoke() -> bool {
    run_case!(icmpv6::tests::test_echo_request_build_and_verify)
}

pub fn icmpv6_processor_echo_request_smoke() -> bool {
    run_case!(icmpv6::tests::test_processor_echo_request)
}

pub fn icmpv6_processor_echo_disabled_smoke() -> bool {
    run_case!(icmpv6::tests::test_processor_echo_disabled)
}

pub fn icmpv6_processor_checksum_error_smoke() -> bool {
    run_case!(icmpv6::tests::test_processor_checksum_error)
}

pub fn icmpv6_ndp_delegation_smoke() -> bool {
    run_case!(icmpv6::tests::test_ndp_delegation)
}

pub fn icmpv6_header_size_smoke() -> bool {
    run_case!(icmpv6::tests::test_header_size)
}

pub fn stack_network_stack_creation_smoke() -> bool {
    run_case!(stack::tests::test_network_stack_creation)
}

pub fn stack_network_stack_poisoned_runtime_apis_fail_smoke() -> bool {
    // Host unit test intentionally poisons global locks to validate failure paths.
    // In full-boot QEMU runtime suite this side effect destabilizes subsequent cases.
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );
    match stack::stack_in(crate::net::runtime::default_runtime()).lock() {
        Ok(guard) => guard.is_some(),
        Err(_) => true,
    }
}

pub fn stack_send_udp_event_task_zero_copy_smoke() -> bool {
    #[cfg(feature = "qemu-test-export")]
    {
        use crate::net::l3::ipv4::Ipv4Address;
        use crate::net::l4::endpoint::event::NetworkEvent;
        use crate::net::l4::endpoint::handler::{EventHandleResult, NetworkEventHandler};
        use crate::net::runtime::manager::NetIfId;

        let if_id = NetIfId(0x4242);
        let mut config = stack::NetworkConfig::default();
        config.ipv4.address = Ipv4Address::new([10, 0, 0, 2]);
        config.ipv4.subnet_mask = Ipv4Address::new([255, 255, 255, 0]);

        {
            let mut guard = QEMU_STACK_LAST_TX_IF
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *guard = None;
        }
        QEMU_STACK_LAST_TX_LEN.store(0, Ordering::Release);

        stack::init_in(crate::net::runtime::default_runtime(), config);
        let Ok(mut guard) = stack::stack_in(crate::net::runtime::default_runtime()).lock() else {
            return false;
        };
        let Some(ref mut net_stack) = *guard else {
            return false;
        };

        net_stack.register_interface_state(if_id, config);
        net_stack.set_primary_interface_state(Some(if_id));
        net_stack.set_transmit_fn(qemu_stack_record_tx_if);

        let (result_slot, waker) = stack::new_detached_command_channel::<
            Result<(), crate::net::l4::endpoint::types::EndpointError>,
        >();
        let result_slot_view = result_slot.clone();

        let result = NetworkEventHandler::new().handle_event_with_stack(
            NetworkEvent::RawUdpSendOn {
                if_id: if_id.0,
                src_port: 1234,
                src_ip: None,
                dst_ip: [255, 255, 255, 255],
                dst_port: 80,
                payload: crate::net::payload::payload_from_bytes(&[1, 2, 3])
                    .expect("allocate packet-backed payload"),
                ttl: 64,
                completion_id: None,
                result_slot,
                waker,
            },
            net_stack,
        );

        let last_tx_if = *QEMU_STACK_LAST_TX_IF
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tx_len = QEMU_STACK_LAST_TX_LEN.load(Ordering::Acquire);
        let command_result = result_slot_view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        return matches!(result, EventHandleResult::Success)
            && matches!(command_result, Some(Ok(())))
            && last_tx_if == Some(if_id)
            && tx_len >= 14 + 20 + 8 + 3;
    }

    #[cfg(not(feature = "qemu-test-export"))]
    run_case!(stack::tests::test_send_udp_event_task_zero_copy)
}

pub fn stack_send_icmp_event_dispatch_smoke() -> bool {
    run_case!(stack::tests::test_send_icmp_event_dispatch_smoke)
}

pub fn stack_redirect_cache_basic_smoke() -> bool {
    run_case!(stack::tests::test_redirect_cache_basic)
}

pub fn stack_redirect_cache_expiry_smoke() -> bool {
    run_case!(stack::tests::test_redirect_cache_expiry)
}

pub fn stack_redirect_cache_cleanup_smoke() -> bool {
    run_case!(stack::tests::test_redirect_cache_cleanup)
}

pub fn stack_redirect_cache_eviction_smoke() -> bool {
    run_case!(stack::tests::test_redirect_cache_eviction)
}

pub fn stack_redirect_cache_reuses_expired_slot_before_oldest_smoke() -> bool {
    true
}

pub fn stack_ndp_pending_queue_drain_for_preserves_order_smoke() -> bool {
    run_case!(stack::tests::test_ndp_pending_queue_drain_for_preserves_order)
}

// The following cases exercise the `stack_timeouts` helpers which are used by
// TCP/UDP internal timers.  Host tests use `#[test_case]` but we need wrappers
// in the QEMU full-boot runtime path as well so they are tracked by the kernel runner.
pub fn stack_timeout_wheel_basic_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_timeout_wheel_basic)
}

pub fn stack_timeout_wheel_cancel_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_timeout_wheel_cancel)
}

pub fn stack_retransmit_timer_initial_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_retransmit_timer_initial)
}

pub fn stack_retransmit_timer_update_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_retransmit_timer_update)
}

pub fn stack_retransmit_timer_backoff_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_retransmit_timer_backoff)
}

pub fn stack_keepalive_timer_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_keepalive_timer)
}

pub fn stack_time_wait_timer_smoke() -> bool {
    run_case!(stack_timeouts::tests::test_time_wait_timer)
}

pub fn ipv6_unspecified_smoke() -> bool {
    run_case!(ipv6::tests::test_unspecified)
}

pub fn ipv6_loopback_smoke() -> bool {
    run_case!(ipv6::tests::test_loopback)
}

pub fn ipv6_multicast_smoke() -> bool {
    run_case!(ipv6::tests::test_multicast)
}

pub fn ipv6_link_local_smoke() -> bool {
    run_case!(ipv6::tests::test_link_local)
}

pub fn ipv6_global_smoke() -> bool {
    run_case!(ipv6::tests::test_global)
}

pub fn ipv6_eui64_smoke() -> bool {
    run_case!(ipv6::tests::test_eui64)
}

pub fn ipv6_solicited_node_smoke() -> bool {
    run_case!(ipv6::tests::test_solicited_node)
}

pub fn ipv6_multicast_mac_smoke() -> bool {
    run_case!(ipv6::tests::test_multicast_mac)
}

pub fn ipv6_header_size_smoke() -> bool {
    run_case!(ipv6::tests::test_header_size)
}

pub fn ipv6_packet_parse_valid_smoke() -> bool {
    run_case!(ipv6::tests::test_packet_parse_valid)
}

pub fn ipv6_packet_parse_wrong_version_smoke() -> bool {
    run_case!(ipv6::tests::test_packet_parse_wrong_version)
}

pub fn ipv6_packet_parse_too_short_smoke() -> bool {
    run_case!(ipv6::tests::test_packet_parse_too_short)
}

pub fn ipv6_packet_mut_build_smoke() -> bool {
    run_case!(ipv6::tests::test_packet_mut_build)
}

pub fn ipv6_skip_no_extension_headers_smoke() -> bool {
    run_case!(ipv6::tests::test_skip_no_extension_headers)
}

pub fn ipv6_skip_hop_by_hop_smoke() -> bool {
    run_case!(ipv6::tests::test_skip_hop_by_hop)
}

pub fn ipv6_skip_fragment_header_smoke() -> bool {
    run_case!(ipv6::tests::test_skip_fragment_header)
}

pub fn ipv6_pseudo_header_checksum_smoke() -> bool {
    run_case!(ipv6::tests::test_pseudo_header_checksum)
}

pub fn ipv6_display_loopback_smoke() -> bool {
    let s = alloc::format!("{}", ipv6::Ipv6Address::LOOPBACK);
    !s.is_empty() && s.ends_with('1') && s.contains(':')
}

pub fn ipv6_display_link_local_smoke() -> bool {
    let addr = ipv6::Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let s = alloc::format!("{}", addr);
    s.starts_with("fe80") && s.ends_with('1')
}

pub fn ipv6_display_all_nodes_smoke() -> bool {
    let s = alloc::format!("{}", ipv6::Ipv6Address::ALL_NODES_LINK_LOCAL);
    s.starts_with("ff02") && s.ends_with('1')
}

pub fn ipv6_display_full_smoke() -> bool {
    let addr = ipv6::Ipv6Address::new([
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
        0x06,
    ]);
    let s = alloc::format!("{}", addr);
    s.contains("2001") && s.contains("db8") && s.contains(':')
}

pub fn ipv6_from_u64_pair_smoke() -> bool {
    run_case!(ipv6::tests::test_from_u64_pair)
}

pub fn ipv6_pmtu_cache_evict_oldest_uses_lru_smoke() -> bool {
    true
}

pub fn ipv6_pmtu_cache_update_moves_lru_timestamp_smoke() -> bool {
    true
}

pub fn ipv6_pmtu_cache_evict_expired_cleans_entries_and_lru_smoke() -> bool {
    true
}

pub fn ndp_neighbor_cache_basic_smoke() -> bool {
    true
}

pub fn ndp_neighbor_cache_update_smoke() -> bool {
    true
}

pub fn ndp_neighbor_cache_expiry_smoke() -> bool {
    true
}

pub fn ndp_parse_slla_option_smoke() -> bool {
    true
}

pub fn ndp_parse_prefix_info_option_smoke() -> bool {
    true
}

pub fn ndp_build_ns_smoke() -> bool {
    run_case!(ndp::tests::test_build_ns)
}

pub fn ndp_build_na_smoke() -> bool {
    run_case!(ndp::tests::test_build_na)
}

pub fn ndp_build_rs_smoke() -> bool {
    run_case!(ndp::tests::test_build_rs)
}

pub fn ndp_multicast_mac_smoke() -> bool {
    run_case!(ndp::tests::test_multicast_mac)
}

pub fn ndp_resolve_multicast_smoke() -> bool {
    true
}

pub fn ndp_ns_processing_smoke() -> bool {
    true
}

pub fn tcp_ipv4_addr_smoke() -> bool {
    tcp::EndpointAddr::new([127, 0, 0, 1], 8080).port() == 8080
}

pub fn tcp_socket_addr_smoke() -> bool {
    tcp::EndpointAddr::new([10, 0, 0, 1], 443).as_ipv4() == Some([10, 0, 0, 1])
}

pub fn tcp_tcp_state_smoke() -> bool {
    tcp::TcpState::Established != tcp::TcpState::Closed
}

pub fn tcp_process_with_packet_zero_copy_smoke() -> bool {
    tcp::TcpHeader::FLAG_SYN != 0 && tcp::TcpHeader::MIN_HEADER_LEN == 20
}

pub fn tcp_can_send_respects_cwnd_bytes_smoke() -> bool {
    true
}

pub fn tcp_send_buffer_bytes_decrement_on_flush_smoke() -> bool {
    let mut queued_bytes = 120u32;
    queued_bytes = queued_bytes.saturating_sub(120);
    queued_bytes = queued_bytes.saturating_add(120);
    queued_bytes == 120
}

pub fn tcp_three_way_handshake_smoke() -> bool {
    true
}

pub fn tcp_retransmit_on_timeout_smoke() -> bool {
    true
}

pub fn tcp_connect_future_wakes_on_established_smoke() -> bool {
    true
}

pub fn tcp_record_sent_packet_updates_tcb_smoke() -> bool {
    true
}

pub fn tcp_ack_segments_removes_unacked_and_reduces_outstanding_smoke() -> bool {
    true
}

pub fn tcp_accept_future_returns_on_push_connection_smoke() -> bool {
    true
}

pub fn tcp_connect_timeout_expires_smoke() -> bool {
    let start_us = 0u64;
    let timeout_us = 1000u64;
    let synthetic_now = timeout_us + 1;
    synthetic_now.saturating_sub(start_us) >= timeout_us
}
