use crate::net::l4::endpoint::EndpointAddr;
use crate::net::l4::endpoint::manager::init_endpoint_manager;
use crate::net::l4::endpoint::tcb::{TcpConnectionState, TcpControlBlockEntry};
use crate::net::l4::endpoint::{Endpoint, EndpointState, EndpointType, NetworkEvent};
use crate::net::l4::test_support::{
    counting_waker, new_test_endpoint, noop_waker, tcp_stream_from_endpoint,
};
use crate::net::runtime::stack;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::AtomicUsize;
use core::task::{Context, Poll};
use kernel_api::resource::net::PacketPayload;

fn test_payload(data: &[u8]) -> PacketPayload {
    crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
}

fn new_tcp_socket() -> Endpoint {
    new_test_endpoint(EndpointType::Tcp)
}

fn new_udp_socket() -> Endpoint {
    new_test_endpoint(EndpointType::Udp)
}

fn payload_bytes(payload: &PacketPayload) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let copied = crate::net::payload::PacketPayloadView::new(payload).copy_all_into(&mut out);
    out.truncate(copied);
    out
}

fn configure_connected_tcp_endpoint(sock: &Endpoint, local: EndpointAddr, remote: EndpointAddr) {
    let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
    inner.local_addr = Some(local);
    inner.remote_addr = Some(remote);
    let _ = inner.transition_to(EndpointState::Bound);
    let _ = inner.transition_to(EndpointState::Connected);
}

fn push_tcp_bytes(sock: &Endpoint, data: &[u8]) {
    assert_eq!(sock.push_payload(test_payload(data)), data.len());
}

fn configure_bound_udp_endpoint(sock: &Endpoint, local: EndpointAddr) {
    {
        let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.ensure_udp();
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
    }

    let guard = crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let manager = guard.as_ref().expect("endpoint manager");
    manager
        .bind_udp_dual_stack(
            local.port(),
            crate::net::types::InterfaceScope::Any,
            sock.fd(),
        )
        .expect("bind UDP endpoint");
}

// Simple test that verifies TcpStream::write queues payload and posts DataReady.
#[cfg_attr(test, test_case)]
pub fn test_write_future_wakes_on_send() {
    init_endpoint_manager();

    // Initialize stack and set a dummy transmit function that always succeeds
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );
    if let Ok(mut guard) = stack::stack_in(crate::net::runtime::default_runtime()).lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(
                |_if: Option<crate::net::runtime::manager::NetIfId>,
                 _packet: crate::net::datapath::mempool::PacketRef,
                 _meta: kernel_api::service::netdev::NetTxMeta| {
                    assert!(_if.is_none());
                    true
                },
            );
        }
    }

    // Create endpoint and set local/remote
    let sock = new_tcp_socket();
    let fd = sock.fd();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
    inner.local_addr = Some(local);
    inner.remote_addr = Some(remote);
    drop(inner);

    // Insert an Established TCB so handler will proceed
    let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
    tcb.state = TcpConnectionState::Established;
    crate::net::l4::endpoint::tcb::tcb_table().insert(tcb);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let Some(mut stream) = tcp_stream_from_endpoint(&sock) else {
        panic!("tcp stream should exist");
    };
    let data = [1u8, 2u8, 3u8, 4u8];
    let mut fut = stream.write(&data);
    let mut pinned = Pin::new(&mut fut);

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => assert_eq!(n, data.len()),
        other => panic!("write future returned unexpected result: {:?}", other),
    }

    let queued = sock
        .endpoint()
        .expect("endpoint")
        .inner()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send_payload_bytes();
    assert_eq!(queued, data.len());

    let Some(event) = crate::net::l4::endpoint::event::event_queue().recv() else {
        panic!("expected queued DataReady event");
    };
    assert!(matches!(
        event,
        NetworkEvent::DataReady {
            fd: event_fd,
            endpoint_type: crate::net::l4::endpoint::types::EndpointType::Tcp,
        } if event_fd.raw() == fd.raw()
    ));
}

#[cfg_attr(test, test_case)]
pub fn test_write_future_wakes_on_send_v6() {
    init_endpoint_manager();

    // Initialize stack with IPv6 enabled and set transmit to always succeed
    let mut cfg = crate::net::runtime::stack::NetworkConfig::default();
    cfg.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(&[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]));
    crate::net::runtime::stack::init_in(crate::net::runtime::default_runtime(), cfg);

    if let Ok(mut guard) =
        crate::net::runtime::stack::stack_in(crate::net::runtime::default_runtime()).lock()
    {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(
                |_if: Option<crate::net::runtime::manager::NetIfId>,
                 _packet: crate::net::datapath::mempool::PacketRef,
                 _meta: kernel_api::service::netdev::NetTxMeta| {
                    assert!(_if.is_none());
                    true
                },
            );
        }
    }

    // Create endpoint and set IPv6 local/remote (remote uses multicast so no NDP needed)
    let sock = new_tcp_socket();
    let fd = sock.fd();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(
        crate::net::l3::ipv6::Ipv6Address::ALL_NODES_LINK_LOCAL.octets(),
        80,
    );
    let mut inner = sock.inner().lock().unwrap_or_else(|e| e.into_inner());
    inner.local_addr = Some(local);
    inner.remote_addr = Some(remote);
    drop(inner);

    // Insert an Established TCB so handler will proceed
    let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
    tcb.state = TcpConnectionState::Established;
    crate::net::l4::endpoint::tcb::tcb_table().insert(tcb);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let Some(mut stream) = tcp_stream_from_endpoint(&sock) else {
        panic!("tcp stream should exist");
    };
    let data = [9u8, 8u8, 7u8, 6u8];
    let mut fut = stream.write(&data);
    let mut pinned = Pin::new(&mut fut);

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => assert_eq!(n, data.len()),
        other => panic!("write future returned unexpected result: {:?}", other),
    }

    let queued = sock
        .endpoint()
        .expect("endpoint")
        .inner()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send_payload_bytes();
    assert_eq!(queued, data.len());

    let Some(event) = crate::net::l4::endpoint::event::event_queue().recv() else {
        panic!("expected queued DataReady event");
    };
    assert!(matches!(
        event,
        NetworkEvent::DataReady {
            fd: event_fd,
            endpoint_type: crate::net::l4::endpoint::types::EndpointType::Tcp,
        } if event_fd.raw() == fd.raw()
    ));
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_stream_read_zero_copy() {
    init_endpoint_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );

    let sock = new_tcp_socket();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    let data = [1u8, 2u8, 3u8, 4u8];
    configure_connected_tcp_endpoint(&sock, local, remote);
    push_tcp_bytes(&sock, &data);

    static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);
    let waker = counting_waker(&WAKE_COUNT);
    let mut cx = Context::from_waker(&waker);

    let Some(mut stream) = tcp_stream_from_endpoint(&sock) else {
        panic!("tcp_stream should exist");
    };
    let mut fut = stream.read_zero_copy();
    let mut pinned = Pin::new(&mut fut);

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), data),
        Poll::Ready(None) => panic!("Expected packet, got None"),
        Poll::Pending => panic!("Future pending despite packet present"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_stream_read_zero_copy_v6() {
    init_endpoint_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );

    let sock = new_tcp_socket();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    let data = [9u8, 10u8, 11u8];
    configure_connected_tcp_endpoint(&sock, local, remote);
    push_tcp_bytes(&sock, &data);

    static WAKE_COUNT_V6: AtomicUsize = AtomicUsize::new(0);
    let waker = counting_waker(&WAKE_COUNT_V6);
    let mut cx = Context::from_waker(&waker);

    let Some(mut stream) = tcp_stream_from_endpoint(&sock) else {
        panic!("tcp_stream should exist");
    };
    let mut fut = stream.read_zero_copy();
    let mut pinned = Pin::new(&mut fut);

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), data),
        Poll::Ready(None) => panic!("Expected packet, got None"),
        Poll::Pending => panic!("Future pending despite packet present"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_stream_multiple_reads() {
    init_endpoint_manager();
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );

    let sock = new_tcp_socket();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    configure_connected_tcp_endpoint(&sock, local, remote);

    let d1 = [10u8, 11u8];
    let d2 = [20u8, 21u8, 22u8];

    let Some(mut stream) = tcp_stream_from_endpoint(&sock) else {
        panic!("tcp_stream should exist");
    };

    static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);
    let waker = counting_waker(&WAKE_COUNT);
    let mut cx = Context::from_waker(&waker);

    push_tcp_bytes(&sock, &d1);
    let mut fut1 = stream.read_zero_copy();
    let mut pinned1 = Pin::new(&mut fut1);
    match pinned1.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d1),
        _ => panic!("Expected first packet"),
    }

    push_tcp_bytes(&sock, &d2);
    let mut fut2 = stream.read_zero_copy();
    let mut pinned2 = Pin::new(&mut fut2);
    match pinned2.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d2),
        _ => panic!("Expected second packet"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_stream_multiple_reads_v6() {
    init_endpoint_manager();
    stack::init_in(
        crate::net::runtime::default_runtime(),
        stack::NetworkConfig::default(),
    );

    let sock = new_tcp_socket();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    configure_connected_tcp_endpoint(&sock, local, remote);

    let d1 = [10u8, 11u8];
    let d2 = [20u8, 21u8, 22u8];

    let Some(mut stream) = tcp_stream_from_endpoint(&sock) else {
        panic!("tcp_stream should exist");
    };

    static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);
    let waker = counting_waker(&WAKE_COUNT);
    let mut cx = Context::from_waker(&waker);

    push_tcp_bytes(&sock, &d1);
    let mut fut1 = stream.read_zero_copy();
    let mut pinned1 = Pin::new(&mut fut1);
    match pinned1.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d1),
        _ => panic!("Expected first packet"),
    }

    push_tcp_bytes(&sock, &d2);
    let mut fut2 = stream.read_zero_copy();
    let mut pinned2 = Pin::new(&mut fut2);
    match pinned2.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d2),
        _ => panic!("Expected second packet"),
    }
}
#[cfg_attr(test, test_case)]
pub fn test_udp_recv_delivered() {
    init_endpoint_manager();

    let port = 40000u16;
    let sock = crate::net::l4::udp::UdpEndpoint::bind_registered_with_token_in(
        crate::net::runtime::default_runtime(),
        crate::net::types::InterfaceScope::Any,
        port,
        None,
    )
    .expect("bind UDP endpoint");

    // Build a UDP packet into a PacketRef and process it via the processor (zero-copy path)
    let src_ip = crate::net::l3::ipv4::Ipv4Address::from_octets(127, 0, 0, 1);
    let dst_ip = src_ip;
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc");
    let len = crate::net::l4::udp::UdpProcessor::build_packet(
        packet.data_mut(),
        src_ip,
        12345,
        dst_ip,
        port,
        b"hello",
    )
    .unwrap();
    packet.set_len(len);

    let packet_data = alloc::vec::Vec::from(packet.data());
    let res = processor.process_with_packet_on(None, &packet_data, src_ip, dst_ip, packet, 255);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

    static WAKE_COUNT2: AtomicUsize = AtomicUsize::new(0);
    let waker2 = counting_waker(&WAKE_COUNT2);
    let mut cx2 = Context::from_waker(&waker2);

    let mut fut = sock.recv();
    let mut pinned = Pin::new(&mut fut);
    match pinned.as_mut().poll(&mut cx2) {
        Poll::Ready(Some((_if_id, addr, _ttl, pkt))) => {
            assert_eq!(payload_bytes(&pkt), b"hello");
            assert_eq!(addr.port(), 12345);
        }
        _ => panic!("Expected UDP packet"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_udp_try_recv_from_reads_zero_copy_socket_queue() {
    init_endpoint_manager();

    let processor = crate::net::l4::udp::UdpProcessor::new();
    let port = 40001u16;
    let sock = new_udp_socket();
    configure_bound_udp_endpoint(&sock, EndpointAddr::new([127, 0, 0, 1], port));
    let endpoint = &sock;

    let src_ip = crate::net::l3::ipv4::Ipv4Address::from_octets(127, 0, 0, 1);
    let dst_ip = src_ip;
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc");
    let len = crate::net::l4::udp::UdpProcessor::build_packet(
        packet.data_mut(),
        src_ip,
        54321,
        dst_ip,
        port,
        b"zero-copy",
    )
    .unwrap();
    packet.set_len(len);

    let packet_data = alloc::vec::Vec::from(packet.data());
    let res = processor.process_with_packet_on(None, &packet_data, src_ip, dst_ip, packet, 128);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

    let (if_id, addr, _ttl, payload) = endpoint
        .try_recv_udp_payload()
        .expect("try_recv_udp_payload should read UDP socket queue");
    let mut buf = [0u8; 32];
    let len = crate::net::payload::PacketPayloadView::new(&payload).copy_into(&mut buf);
    assert_eq!(&buf[..len], b"zero-copy");
    assert_eq!(addr, EndpointAddr::new([127, 0, 0, 1], 54321));
    assert_eq!(if_id, crate::net::runtime::manager::NetIfId::default());
}

#[cfg_attr(test, test_case)]
pub fn test_udp_try_recv_from_reads_zero_copy_socket_queue_v6() {
    init_endpoint_manager();

    let processor = crate::net::l4::udp::UdpProcessor::new();
    let port = 40002u16;
    let sock = new_udp_socket();
    configure_bound_udp_endpoint(
        &sock,
        EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), port),
    );
    let endpoint = &sock;

    let src_ip = crate::net::l3::ipv6::Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    let dst_ip = crate::net::l3::ipv6::Ipv6Address::LOOPBACK;
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc");
    let len = {
        let mut udp_packet =
            crate::net::l4::udp::UdpPacketMut::new(packet.data_mut()).expect("udp packet");
        udp_packet
            .set_src_port(54322)
            .set_dst_port(port)
            .write_payload(b"zero-copy-v6");
        udp_packet.finalize_v6(src_ip, dst_ip)
    };
    packet.set_len(len);

    let packet_data = alloc::vec::Vec::from(packet.data());
    let res = processor.process_with_packet_v6_on(None, &packet_data, src_ip, dst_ip, packet, 64);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

    let (if_id, addr, _ttl, payload) = endpoint
        .try_recv_udp_payload()
        .expect("try_recv_udp_payload should read UDP socket queue");
    let mut buf = [0u8; 32];
    let len = crate::net::payload::PacketPayloadView::new(&payload).copy_into(&mut buf);
    assert_eq!(&buf[..len], b"zero-copy-v6");
    assert_eq!(
        addr,
        EndpointAddr::new_v6(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            54322,
        )
    );
    assert_eq!(if_id, crate::net::runtime::manager::NetIfId::default());
}
