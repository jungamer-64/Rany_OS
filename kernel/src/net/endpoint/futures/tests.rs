use super::*;
use crate::net::{create_tcp_socket, create_udp_socket, NetworkEvent};
use crate::net::endpoint::manager::init_socket_manager;
use crate::net::stack;
use crate::net::endpoint::SocketAddr;
use crate::net::endpoint::tcb::{TcpControlBlockEntry, TcpConnectionState};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// Simple test that verifies SendFuture writes into socket buffer
// and is woken when the DataReady event is processed successfully
#[test_case]
fn test_sendfuture_wakes_on_send() {
    init_socket_manager();

    // Initialize stack and set a dummy transmit function that always succeeds
    stack::init_default();
    if let Ok(mut guard) = stack::stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(|_data: &[u8]| true);
        }
    }

    // Create socket and set local/remote
    let sock = create_tcp_socket();
    let fd = sock.fd();
    let local = SocketAddr::new([127, 0, 0, 1], 12345);
    let remote = SocketAddr::new([127, 0, 0, 1], 80);
    if let Some(s) = sock.socket() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Insert an Established TCB so handler will proceed
    let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
    tcb.state = TcpConnectionState::Established;
    crate::net::endpoint::tcb::tcb_table().insert(tcb);

    // Prepare a waker that increments a counter
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

    // Create SendFuture and poll once (should register waker and queue DataReady)
    let data = alloc::vec![1u8, 2u8, 3u8, 4u8];
    let mut fut = sock.send_async(data).expect("send_async should return future");
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(_) => panic!("SendFuture should not complete immediately"),
    }

    // Now simulate the network task processing the DataReady event and sending
    let handler = crate::net::endpoint::handler::NetworkEventHandler::new();
    let res = handler.handle_event(NetworkEvent::DataReady {
        fd,
        socket_type: crate::net::endpoint::types::SocketType::Tcp,
    });
    // Should either succeed or ask for retry; for our test transmit succeeds so Success
    assert!(matches!(res, crate::net::endpoint::handler::EventHandleResult::Success));

    // Waker should have been called
    assert!(WAKE_COUNT.load(Ordering::SeqCst) > 0);

    // Re-poll the future: it should now be Ready with the number of bytes sent
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 4usize),
        Poll::Ready(Err(e)) => panic!("SendFuture returned error: {:?}", e),
        Poll::Pending => panic!("SendFuture still pending after send"),
    }
}

#[test_case]
fn test_recv_packet_zero_copy_via_owned_socket() {
    init_socket_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_default();

    let sock = create_tcp_socket();
    let fd = sock.fd();
    let local = SocketAddr::new([127, 0, 0, 1], 12345);
    let remote = SocketAddr::new([127, 0, 0, 1], 80);
    if let Some(s) = sock.socket() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Create TCB and attach a TcpStream to the socket
    use alloc::sync::Arc;
    use crate::sync::PoisonLock;
    use crate::net::tcp::{TcpControlBlock, TcpState, SocketAddr as TcpSocketAddr, Ipv4Addr as TcpIpv4Addr, TcpStream};

    let t_local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 12345);
    let t_remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 80);

    let mut tcb = TcpControlBlock::new(t_local);
    tcb.remote_addr = Some(t_remote);
    tcb.state = TcpState::Established;
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let stream = TcpStream { tcb: tcb_arc.clone() };

    if let Some(s) = sock.socket() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.tcp_stream = Some(stream.clone());
        let _ = inner.transition_to(SocketState::Connected);
    }

    // Prepare a packet and push it into the TCB recv buffer
    let mut packet = crate::net::mempool::alloc_packet().expect("alloc packet");
    let data = [1u8, 2u8, 3u8, 4u8];
    packet.data_mut()[..data.len()].copy_from_slice(&data);
    packet.set_len(data.len());

    {
        if let Ok(mut tlock) = tcb_arc.lock() {
            tlock.recv_buffer.push_back(packet);
        } else {
            panic!("TCB lock poisoned");
        }
    }

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
    let mut fut = sock.recv_packet_async().expect("recv_packet_async should return future");
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(pkt.data(), &data),
        Poll::Ready(None) => panic!("Expected packet, got None"),
        Poll::Pending => panic!("Future pending despite packet present"),
    }
}

#[test_case]
fn test_tcp_packet_stream_multiple_packets() {
    init_socket_manager();
    stack::init_default();

    let sock = create_tcp_socket();
    let fd = sock.fd();
    let local = SocketAddr::new([127, 0, 0, 1], 12345);
    let remote = SocketAddr::new([127, 0, 0, 1], 80);
    if let Some(s) = sock.socket() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Create TCB and attach a TcpStream to the socket
    use alloc::sync::Arc;
    use crate::sync::PoisonLock;
    use crate::net::tcp::{TcpControlBlock, TcpState, SocketAddr as TcpSocketAddr, Ipv4Addr as TcpIpv4Addr, TcpStream};

    let t_local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 12345);
    let t_remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 80);

    let mut tcb = TcpControlBlock::new(t_local);
    tcb.remote_addr = Some(t_remote);
    tcb.state = TcpState::Established;
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let stream = TcpStream { tcb: tcb_arc.clone() };

    if let Some(s) = sock.socket() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.tcp_stream = Some(stream.clone());
        let _ = inner.transition_to(SocketState::Connected);
    }

    // Prepare two packets and push into TCB recv buffer
    let mut p1 = crate::net::mempool::alloc_packet().expect("alloc packet");
    let d1 = [10u8, 11u8];
    p1.data_mut()[..d1.len()].copy_from_slice(&d1);
    p1.set_len(d1.len());

    let mut p2 = crate::net::mempool::alloc_packet().expect("alloc packet");
    let d2 = [20u8, 21u8, 22u8];
    p2.data_mut()[..d2.len()].copy_from_slice(&d2);
    p2.set_len(d2.len());

    {
        if let Ok(mut tlock) = tcb_arc.lock() {
            tlock.recv_buffer.push_back(p1);
            tlock.recv_buffer.push_back(p2);
        } else {
            panic!("TCB lock poisoned");
        }
    }

    let stream_wrapper = sock.tcp_packet_stream().expect("tcp_packet_stream should exist");

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

    // First packet
    let mut fut1 = stream_wrapper.next_packet();
    let mut pinned1 = unsafe { Pin::new_unchecked(&mut fut1) };
    match pinned1.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(pkt.data(), &d1),
        _ => panic!("Expected first packet"),
    }

    // Second packet
    let mut fut2 = stream_wrapper.next_packet();
    let mut pinned2 = unsafe { Pin::new_unchecked(&mut fut2) };
    match pinned2.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(pkt.data(), &d2),
        _ => panic!("Expected second packet"),
    }
}

#[test_case]
fn test_udp_packet_stream_delivered() {
    init_socket_manager();

    // Use a UdpProcessor instance and bind a socket to a port
    let proc = crate::net::udp::UdpProcessor::new();
    let port = 40000u16;
    let u = proc.bind_with_token(port, None).expect("bind failed");

    // Create an OwnedSocket and attach the UdpSocket instance to its inner state
    let sock = create_udp_socket();
    if let Some(s) = sock.socket() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(SocketAddr::new([127, 0, 0, 1], port));
        inner.udp_socket = Some(u.clone());
        let _ = inner.transition_to(SocketState::Connected);
    }

    // Build a UDP packet into a PacketRef and process it via the processor (zero-copy path)
    let src_ip = crate::net::ipv4::Ipv4Address::from_octets(127, 0, 0, 1);
    let dst_ip = src_ip;
    let mut packet = crate::net::mempool::alloc_packet().expect("alloc");
    let len = crate::net::udp::UdpProcessor::build_packet(packet.data_mut(), src_ip, 12345, dst_ip, port, b"hello").unwrap();
    packet.set_len(len);

    let packet_data = alloc::vec::Vec::from(packet.data());
    let res = proc.process_with_packet(&packet_data, src_ip, dst_ip, packet);
    assert_eq!(res, crate::net::udp::UdpResult::Delivered);

    // Get stream wrapper and receive the packet
    let stream = sock.udp_packet_stream().expect("udp_packet_stream should exist");

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
        Poll::Ready(Some((addr, pkt))) => {
            assert_eq!(pkt.data(), b"hello");
            assert_eq!(addr.port(), 12345);
        }
        _ => panic!("Expected UDP packet"),
    }
}
