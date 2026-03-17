use super::*;
use crate::net::l4::endpoint::EndpointAddr;
use crate::net::l4::endpoint::manager::init_endpoint_manager;
use crate::net::l4::endpoint::tcb::{TcpConnectionState, TcpControlBlockEntry};
use crate::net::l4::endpoint::{NetworkEvent, create_tcp_endpoint, create_udp_endpoint};
use crate::net::runtime::stack;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use kernel_api::resource::net::PacketPayload;

fn test_payload(data: &[u8]) -> PacketPayload {
    crate::net::payload::payload_from_bytes(data).expect("allocate packet-backed test payload")
}

fn payload_bytes(payload: &PacketPayload) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; payload.total_len()];
    let copied = crate::net::payload::PacketPayloadView::new(payload).copy_all_into(&mut out);
    out.truncate(copied);
    out
}

fn configure_connected_tcp_endpoint(
    sock: &crate::net::l4::endpoint::OwnedEndpoint,
    local: EndpointAddr,
    remote: EndpointAddr,
) {
    if let Some(endpoint) = sock.endpoint() {
        let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
    }
}

fn push_tcp_bytes(sock: &crate::net::l4::endpoint::OwnedEndpoint, data: &[u8]) {
    let endpoint = sock.endpoint().expect("tcp endpoint should exist");
    assert_eq!(endpoint.push_payload(test_payload(data)), data.len());
}

// Simple test that verifies TcpStream::write queues payload and posts DataReady.
#[cfg_attr(test, test_case)]
pub fn test_write_future_wakes_on_send() {
    init_endpoint_manager();

    // Initialize stack and set a dummy transmit function that always succeeds
    stack::init_default();
    if let Ok(mut guard) = stack::stack().lock() {
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
    let sock = create_tcp_endpoint();
    let fd = sock.fd();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Insert an Established TCB so handler will proceed
    let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
    tcb.state = TcpConnectionState::Established;
    crate::net::l4::endpoint::tcb::tcb_table().insert(tcb);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    let Some(mut stream) = sock.tcp_stream() else {
        panic!("tcp stream should exist");
    };
    let data = [1u8, 2u8, 3u8, 4u8];
    let mut fut = stream.write(&data);
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

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
    crate::net::runtime::stack::init(cfg);

    if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
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
    let sock = create_tcp_endpoint();
    let fd = sock.fd();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(
        crate::net::l3::ipv6::Ipv6Address::ALL_NODES_LINK_LOCAL.octets(),
        80,
    );
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Insert an Established TCB so handler will proceed
    let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
    tcb.state = TcpConnectionState::Established;
    crate::net::l4::endpoint::tcb::tcb_table().insert(tcb);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    let Some(mut stream) = sock.tcp_stream() else {
        panic!("tcp stream should exist");
    };
    let data = [9u8, 8u8, 7u8, 6u8];
    let mut fut = stream.write(&data);
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

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
pub fn test_recv_packet_zero_copy_via_owned_endpoint() {
    init_endpoint_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_default();

    let sock = create_tcp_endpoint();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    let data = [1u8, 2u8, 3u8, 4u8];
    configure_connected_tcp_endpoint(&sock, local, remote);
    push_tcp_bytes(&sock, &data);

    // Prepare a simple waker
    static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {
            WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        },
        |_| {
            WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        },
        |_| {},
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    // Create RecvPacketFuture and poll → should be Ready with the packet
    let mut fut = sock
        .recv_packet()
        .expect("recv_packet should return future");
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), data),
        Poll::Ready(None) => panic!("Expected packet, got None"),
        Poll::Pending => panic!("Future pending despite packet present"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_recv_packet_zero_copy_via_owned_endpoint_v6() {
    init_endpoint_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_default();

    let sock = create_tcp_endpoint();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    let data = [9u8, 10u8, 11u8];
    configure_connected_tcp_endpoint(&sock, local, remote);
    push_tcp_bytes(&sock, &data);

    // Prepare a simple waker
    static WAKE_COUNT_V6: AtomicU32 = AtomicU32::new(0);
    const VTABLE_V6: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE_V6),
        |_| {
            WAKE_COUNT_V6.fetch_add(1, Ordering::SeqCst);
        },
        |_| {
            WAKE_COUNT_V6.fetch_add(1, Ordering::SeqCst);
        },
        |_| {},
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE_V6);
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    // Create RecvPacketFuture and poll → should be Ready with the packet
    let mut fut = sock
        .recv_packet()
        .expect("recv_packet should return future");
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), data),
        Poll::Ready(None) => panic!("Expected packet, got None"),
        Poll::Pending => panic!("Future pending despite packet present"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_packet_stream_multiple_packets() {
    init_endpoint_manager();
    stack::init_default();

    let sock = create_tcp_endpoint();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    configure_connected_tcp_endpoint(&sock, local, remote);

    let d1 = [10u8, 11u8];
    let d2 = [20u8, 21u8, 22u8];

    let stream_wrapper = sock
        .tcp_packet_stream()
        .expect("tcp_packet_stream should exist");

    // Prepare a simple waker
    static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {
            WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        },
        |_| {
            WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        },
        |_| {},
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    push_tcp_bytes(&sock, &d1);
    let mut fut1 = stream_wrapper.next_packet();
    let mut pinned1 = unsafe { Pin::new_unchecked(&mut fut1) };
    match pinned1.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d1),
        _ => panic!("Expected first packet"),
    }

    push_tcp_bytes(&sock, &d2);
    let mut fut2 = stream_wrapper.next_packet();
    let mut pinned2 = unsafe { Pin::new_unchecked(&mut fut2) };
    match pinned2.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d2),
        _ => panic!("Expected second packet"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_packet_stream_multiple_packets_v6() {
    init_endpoint_manager();
    stack::init_default();

    let sock = create_tcp_endpoint();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    configure_connected_tcp_endpoint(&sock, local, remote);

    let d1 = [10u8, 11u8];
    let d2 = [20u8, 21u8, 22u8];

    let stream_wrapper = sock
        .tcp_packet_stream()
        .expect("tcp_packet_stream should exist");

    // Prepare a simple waker
    static WAKE_COUNT: AtomicU32 = AtomicU32::new(0);
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {
            WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        },
        |_| {
            WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
        },
        |_| {},
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    push_tcp_bytes(&sock, &d1);
    let mut fut1 = stream_wrapper.next_packet();
    let mut pinned1 = unsafe { Pin::new_unchecked(&mut fut1) };
    match pinned1.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d1),
        _ => panic!("Expected first packet"),
    }

    push_tcp_bytes(&sock, &d2);
    let mut fut2 = stream_wrapper.next_packet();
    let mut pinned2 = unsafe { Pin::new_unchecked(&mut fut2) };
    match pinned2.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(payload_bytes(&pkt), d2),
        _ => panic!("Expected second packet"),
    }
}
#[cfg_attr(test, test_case)]
pub fn test_udp_packet_stream_delivered() {
    init_endpoint_manager();

    // Use a UdpProcessor instance and bind a endpoint to a port
    let processor = crate::net::l4::udp::UdpProcessor::new();
    let port = 40000u16;
    let u = processor
        .bind_with_token(crate::net::types::InterfaceScope::Any, port, None)
        .expect("bind failed");

    // Create an OwnedEndpoint and attach the UdpEndpoint instance to its inner state
    let sock = create_udp_endpoint();
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(EndpointAddr::new([127, 0, 0, 1], port));
        inner.ensure_udp().socket = Some(u.clone());
        let _ = inner.transition_to(EndpointState::Connected);
    }

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
    let res = processor.process_with_packet(&packet_data, src_ip, dst_ip, packet, 255);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

    // Get stream wrapper and receive the packet
    let stream = sock
        .udp_packet_stream()
        .expect("udp_packet_stream should exist");

    // Prepare a simple waker
    static WAKE_COUNT2: AtomicU32 = AtomicU32::new(0);
    const VTABLE2: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE2),
        |_| {
            WAKE_COUNT2.fetch_add(1, Ordering::SeqCst);
        },
        |_| {
            WAKE_COUNT2.fetch_add(1, Ordering::SeqCst);
        },
        |_| {},
    );
    let raw2 = RawWaker::new(core::ptr::null(), &VTABLE2);
    let waker2 = unsafe { Waker::from_raw(raw2) };
    let mut cx2 = Context::from_waker(&waker2);

    let mut fut = stream.next_packet();
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.as_mut().poll(&mut cx2) {
        Poll::Ready(Some((_if_id, addr, _ttl, pkt))) => {
            assert_eq!(payload_bytes(&pkt), b"hello");
            assert_eq!(addr.port(), 12345);
        }
        _ => panic!("Expected UDP packet"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_udp_recv_from_sync_reads_zero_copy_socket_queue() {
    init_endpoint_manager();

    let processor = crate::net::l4::udp::UdpProcessor::new();
    let port = 40001u16;
    let udp_socket = processor
        .bind_with_token(crate::net::types::InterfaceScope::Any, port, None)
        .expect("bind failed");

    let sock = create_udp_endpoint();
    let endpoint = sock.endpoint().expect("udp endpoint should exist");
    {
        let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(EndpointAddr::new([127, 0, 0, 1], port));
        inner.ensure_udp().socket = Some(udp_socket.clone());
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
    }

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
    let res = processor.process_with_packet(&packet_data, src_ip, dst_ip, packet, 128);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

    let mut buf = [0u8; 32];
    let (len, addr, if_id) = endpoint
        .recv_from_sync(&mut buf)
        .expect("recv_from_sync should read UDP socket queue");
    assert_eq!(&buf[..len], b"zero-copy");
    assert_eq!(addr, EndpointAddr::new([127, 0, 0, 1], 54321));
    assert_eq!(if_id, crate::net::runtime::manager::NetIfId::default());
}

#[cfg_attr(test, test_case)]
pub fn test_udp_recv_from_sync_reads_zero_copy_socket_queue_v6() {
    init_endpoint_manager();

    let processor = crate::net::l4::udp::UdpProcessor::new();
    let port = 40002u16;
    let udp_socket = processor
        .bind_with_token(crate::net::types::InterfaceScope::Any, port, None)
        .expect("bind failed");

    let sock = create_udp_endpoint();
    let endpoint = sock.endpoint().expect("udp endpoint should exist");
    {
        let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(EndpointAddr::new_v6(
            crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(),
            port,
        ));
        inner.ensure_udp().socket = Some(udp_socket.clone());
        let _ = inner.transition_to(EndpointState::Bound);
        let _ = inner.transition_to(EndpointState::Connected);
    }

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
    let res = processor.process_with_packet_v6(&packet_data, src_ip, dst_ip, packet, 64);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

    let mut buf = [0u8; 32];
    let (len, addr, if_id) = endpoint
        .recv_from_sync(&mut buf)
        .expect("recv_from_sync should read UDP socket queue");
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
