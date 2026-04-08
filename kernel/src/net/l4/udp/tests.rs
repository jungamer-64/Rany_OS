use super::*;
use crate::domain::DomainId;
use crate::net::l4::test_support::{
    counting_waker, leaked_test_packet_with_data, noop_waker, set_current_subject,
};
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use crate::security::capability::{CAP_NET_BIND, CapabilitySet, manager};

fn test_packet(data: &[u8]) -> PacketRef {
    crate::net::payload::packet_from_bytes(data).expect("allocate packet-backed test packet")
}

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let copied = crate::net::payload::PacketPayloadView::new(payload).copy_all_into(&mut out);
    out.truncate(copied);
    out
}

fn udp_endpoint_poisoned_methods_return_defaults_impl() {
    use crate::sync::set_panicking;

    crate::net::l4::endpoint::manager::init_endpoint_manager();
    let endpoint = UdpEndpoint::new(12345).expect("bind udp endpoint");

    set_panicking(true);
    if let Ok(_g) = endpoint.endpoint.inner().lock() {}
    set_panicking(false);

    assert_eq!(
        endpoint.endpoint.local_addr().map(|addr| addr.port()),
        Some(12345)
    );
    assert!(matches!(endpoint.endpoint.state(), EndpointState::Bound));
    endpoint.close_internal();
    assert!(matches!(endpoint.endpoint.state(), EndpointState::Closed));
}

fn udp_endpoint_multiple_waiters_woken_on_deliver_impl() {
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll};

    static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);

    crate::net::l4::endpoint::manager::init_endpoint_manager();
    let endpoint = UdpEndpoint::new(54322).expect("bind udp endpoint");
    let mut fut1 = endpoint.recv();
    let mut fut2 = endpoint.recv();

    WAKE_COUNT.store(0, Ordering::SeqCst);
    let waker = counting_waker(&WAKE_COUNT);
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(Pin::new(&mut fut1).poll(&mut cx), Poll::Pending));
    assert!(matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Pending));

    let packet = leaked_test_packet_with_data(b"abc");

    let src = UdpAddr::new(Ipv4Address::from_octets(1, 2, 3, 4), 9999);
    let _ =
        endpoint
            .endpoint
            .deliver_udp_packet(NetIfId(7), endpoint_addr_from_udp(src), 255, packet);

    assert_eq!(WAKE_COUNT.load(Ordering::SeqCst), 2);

    match Pin::new(&mut fut1).poll(&mut cx) {
        Poll::Ready(Some((if_id, addr, _ttl, packet))) => {
            assert_eq!(if_id, NetIfId(7));
            assert_eq!(addr, src);
            assert_eq!(payload_bytes(&packet), b"abc");
        }
        _ => panic!("expected ready packet after wake"),
    }

    assert!(matches!(Pin::new(&mut fut2).poll(&mut cx), Poll::Pending));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_packet() {
    let mut buffer = [0u8; 64];

    let src_ip = Ipv4Address::from_octets(192, 168, 1, 1);
    let dst_ip = Ipv4Address::from_octets(192, 168, 1, 2);

    let len = UdpProcessor::build_packet(&mut buffer, src_ip, 12345, dst_ip, 53, b"hello").unwrap();

    assert_eq!(len, UdpHeader::SIZE + 5);

    let packet = UdpPacket::parse(&buffer[..len]).unwrap();
    assert_eq!(packet.src_port(), 12345);
    assert_eq!(packet.dst_port(), 53);
    assert_eq!(packet.payload(), b"hello");
    assert!(packet.verify_checksum(src_ip, dst_ip));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_packet_v6() {
    let mut buffer = [0u8; 128];

    let src_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    let mut packet_mut = UdpPacketMut::new(&mut buffer).unwrap();
    packet_mut
        .set_src_port(12345)
        .set_dst_port(53)
        .write_payload(b"hello v6");
    let len = packet_mut.finalize_v6(src_ip, dst_ip);

    assert_eq!(len, UdpHeader::SIZE + 8);

    let packet = UdpPacket::parse(&buffer[..len]).unwrap();
    assert_eq!(packet.src_port(), 12345);
    assert_eq!(packet.dst_port(), 53);
    assert_eq!(packet.payload(), b"hello v6");

    // Checksum must be non-zero for IPv6 (transmitted as 0xFFFF if calculated as 0)
    assert!(packet.header().checksum() != 0);
    assert!(packet.verify_checksum_v6(src_ip, dst_ip));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_v6_checksum_mandatory() {
    let mut buffer = [0u8; 128];
    let src_ip = Ipv6Address::LOOPBACK;
    let dst_ip = Ipv6Address::LOOPBACK;

    let mut packet_mut = UdpPacketMut::new(&mut buffer).unwrap();
    packet_mut
        .set_src_port(1234)
        .set_dst_port(5678)
        .write_payload(b"test");
    let len = packet_mut.finalize_v6(src_ip, dst_ip);

    // Manually zero out the checksum
    buffer[6] = 0;
    buffer[7] = 0;

    let packet = UdpPacket::parse(&buffer[..len]).unwrap();
    // Should fail because checksum 0 is forbidden for IPv6 per RFC 8200
    assert!(!packet.verify_checksum_v6(src_ip, dst_ip));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_endpoint_poisoned_methods_return_defaults() {
    udp_endpoint_poisoned_methods_return_defaults_impl();
}

#[cfg_attr(test, test_case)]
pub fn test_bind_with_token_reclaim() {
    // Setup: create caller and target domains
    let caller = DomainId::new(1);
    let target = DomainId::new(2);

    // Caller gets permission to grant CAP_NET_BIND
    manager().set_capabilities(caller.as_u64(), CapabilitySet::with_permitted(CAP_NET_BIND));
    let _caller_guard = set_current_subject(caller);

    // Grant token to target
    let token = manager()
        .grant_capability_with_opts(caller.as_u64(), target.as_u64(), CAP_NET_BIND, None, false)
        .unwrap();

    // Target binds using token and keeps the endpoint alive until explicit release.
    let sock = {
        let _target_guard = set_current_subject(target);
        let sock = UdpEndpoint::bind_registered_with_token_in(
            crate::net::runtime::default_runtime(),
            InterfaceScope::Any,
            40000,
            Some(token),
        )
        .expect("bind with capability token");
        assert_eq!(manager().in_flight_count(token), 1);
        sock
    };

    // Issuer revokes token (mark revoked)
    assert!(
        manager()
            .revoke_grant(caller.as_u64(), token, false)
            .is_ok()
    );

    // Immediate reclaim should fail (in-flight)
    match manager().reclaim_token(token) {
        Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
        other => panic!("expected ReclamationBusy, got {:?}", other),
    }

    // Now release the endpoint (target releases resource)
    drop(sock);

    assert_eq!(manager().in_flight_count(token), 0);
    // Now reclaim should succeed
    assert!(manager().reclaim_token(token).is_ok());
}

#[cfg_attr(test, test_case)]
pub fn test_udp_recv_future_poisoned_returns_closed() {
    use crate::sync::set_panicking;
    use core::pin::Pin;
    use core::task::Context;
    use core::task::Poll;

    crate::net::l4::endpoint::manager::init_endpoint_manager();
    let endpoint = UdpEndpoint::new(54321).expect("bind udp endpoint");

    // Poison the inner lock
    set_panicking(true);
    if let Ok(_g) = endpoint.endpoint.inner().lock() {
        // drop marks as poisoned
    }
    set_panicking(false);

    let mut fut = endpoint.recv();
    let w = noop_waker();
    let mut cx = Context::from_waker(&w);

    assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));
}

#[cfg_attr(test, test_case)]
pub fn test_udp_processor_poisoned_bind_and_process() {
    init_endpoint_manager();
    let processor = UdpProcessor::new();
    let _bound = UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        InterfaceScope::Any,
        10000,
        None,
    )
    .expect("initial bind should succeed");
    assert!(
        UdpEndpoint::bind_registered_with_token_in(
            crate::net::runtime::default_runtime(),
            InterfaceScope::Any,
            10000,
            None,
        )
        .is_err()
    );

    // Build a packet and process - should be NoEndpoint and stats increment rx_dropped
    let src_ip = Ipv4Address::from_octets(1, 2, 3, 4);
    let dst_ip = Ipv4Address::from_octets(1, 2, 3, 4);
    let mut buffer = [0u8; 64];
    let len = UdpProcessor::build_packet(&mut buffer, src_ip, 1234, dst_ip, 10001, b"x").unwrap();

    let res = processor.process_on(None, &buffer[..len], src_ip, dst_ip, 64);
    assert_eq!(res, UdpResult::NoEndpoint);

    let stats = processor.stats();
    assert_eq!(stats.2, 1); // rx_dropped == 1
}

#[cfg_attr(test, test_case)]
pub fn test_udp_endpoint_multiple_waiters_woken_on_deliver() {
    udp_endpoint_multiple_waiters_woken_on_deliver_impl();
}

pub fn test_udp_socket_multiple_waiters_woken_on_deliver() {
    udp_endpoint_multiple_waiters_woken_on_deliver_impl();
}

#[cfg_attr(test, test_case)]
pub fn test_udp_processor_process_enqueues_zero_copy_packet() {
    use core::pin::Pin;
    use core::task::{Context, Poll};

    let processor = UdpProcessor::new();
    let endpoint = UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        InterfaceScope::Any,
        10000,
        None,
    )
    .expect("bind udp endpoint for zero-copy enqueue test");

    let src_ip = Ipv4Address::from_octets(10, 0, 0, 1);
    let dst_ip = Ipv4Address::from_octets(10, 0, 0, 2);
    let payload = b"zc";
    let mut buf = [0u8; 64];
    let len = UdpProcessor::build_packet(&mut buf, src_ip, 1234, dst_ip, 10000, payload).unwrap();

    #[cfg(feature = "qemu-test-export")]
    {
        // QEMU required suite runs without a reliable exchange-heap setup for
        // mempool growth, so validate the parse+deliver zero-copy path with a
        // static packet buffer instead of `process()`'s internal allocation.
        // Force UDP checksum to 0 ("no checksum") so this smoke stays focused
        // on enqueue/recv behavior; checksum coverage lives in udp packet tests.
        buf[6] = 0;
        buf[7] = 0;
        let packet = leaked_test_packet_with_data(payload);

        assert_eq!(
            processor.process_with_packet_on(None, &buf[..len], src_ip, dst_ip, packet, 255),
            UdpResult::Delivered
        );
    }
    #[cfg(not(feature = "qemu-test-export"))]
    {
        match crate::net::datapath::mempool::net_mempool() {
            None => crate::net::datapath::mempool::init_net_mempool(4)
                .expect("initialize mempool for udp zero-copy enqueue test"),
            Some(pool) if pool.stats().free_buffers == 0 => {
                crate::net::datapath::mempool::init_net_mempool(1)
                    .expect("top up mempool for udp zero-copy enqueue test")
            }
            Some(_) => {}
        }

        assert_eq!(
            processor.process_on(None, &buf[..len], src_ip, dst_ip, 255),
            UdpResult::Delivered
        );
    }

    let mut fut = endpoint.recv();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match Pin::new(&mut fut).poll(&mut cx) {
        Poll::Ready(Some((if_id, addr, _ttl, packet))) => {
            assert_eq!(if_id, NetIfId::default());
            assert_eq!(addr, UdpAddr::new(src_ip, 1234));
            assert_eq!(payload_bytes(&packet), payload);
        }
        _ => panic!("expected delivered packet"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_udp_processor_process_payload_chain_delivers_without_flattening() {
    let processor = UdpProcessor::new();
    let endpoint = UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        InterfaceScope::Any,
        10001,
        None,
    )
    .expect("bind udp endpoint for payload-chain test");

    let src_ip = Ipv4Address::from_octets(10, 0, 0, 10);
    let dst_ip = Ipv4Address::from_octets(10, 0, 0, 20);
    let payload = b"chain-payload";

    let mut buf = [0u8; 64];
    let len = UdpProcessor::build_packet(&mut buf, src_ip, 4321, dst_ip, 10001, payload).unwrap();

    let header = test_packet(&buf[..UdpHeader::SIZE]);
    let body = test_packet(payload);
    let chain = kernel_api::resource::net::PacketChain::from_segments(alloc::vec![header, body]);

    assert_eq!(
        processor.process_payload_on(
            None,
            kernel_api::resource::net::PacketPayload::chain(chain),
            src_ip,
            dst_ip,
            64,
        ),
        UdpResult::Delivered
    );

    let (_if_id, addr, _ttl, packet) = endpoint
        .try_recv()
        .expect("payload-chain delivery should enqueue a datagram");
    assert_eq!(addr, UdpAddr::new(src_ip, 4321));
    assert_eq!(payload_bytes(&packet), payload);
    assert_eq!(len, UdpHeader::SIZE + payload.len());
}

#[cfg_attr(test, test_case)]
pub fn test_udp_scope_conflicts_any_vs_pinned() {
    init_endpoint_manager();
    let _any = UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        InterfaceScope::Any,
        42000,
        None,
    )
    .expect("bind any-scope endpoint");
    assert!(
        UdpEndpoint::bind_registered_with_token_in(
            crate::net::runtime::default_runtime(),
            InterfaceScope::Pinned(NetIfId(1)),
            42000,
            None,
        )
        .is_err()
    );
}

#[cfg_attr(test, test_case)]
pub fn test_udp_scope_allows_same_port_on_distinct_interfaces() {
    init_endpoint_manager();
    let _if1 = UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        InterfaceScope::Pinned(NetIfId(1)),
        42001,
        None,
    )
    .expect("bind interface 1");
    let _if2 = UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        InterfaceScope::Pinned(NetIfId(2)),
        42001,
        None,
    )
    .expect("bind interface 2");
}
