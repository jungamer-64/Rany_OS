use super::*;
use crate::net::l4::endpoint::{create_tcp_endpoint, create_udp_endpoint, NetworkEvent};
use crate::net::l4::endpoint::manager::init_endpoint_manager;
use crate::net::runtime::stack;
use crate::net::l4::endpoint::EndpointAddr;
use crate::net::l4::endpoint::tcb::{TcpControlBlockEntry, TcpConnectionState};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// Simple test that verifies SendFuture writes into endpoint buffer
// and is woken when the DataReady event is processed successfully
#[cfg_attr(test, test_case)]
pub fn test_sendfuture_wakes_on_send() {
    init_endpoint_manager();

    // Initialize stack and set a dummy transmit function that always succeeds
    stack::init_default();
    if let Ok(mut guard) = stack::stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(|_if: Option<crate::net::runtime::manager::NetIfId>, _data: &[u8]| {
                assert!(_if.is_none());
                true
            });
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
    let handler = crate::net::l4::endpoint::handler::NetworkEventHandler::new();
    let res = handler.handle_event(NetworkEvent::DataReady {
        fd,
        endpoint_type: crate::net::l4::endpoint::types::EndpointType::Tcp,
    });
    // Should either succeed or ask for retry; for our test transmit succeeds so Success
    assert!(matches!(res, crate::net::l4::endpoint::handler::EventHandleResult::Success));

    // Waker should have been called
    assert!(WAKE_COUNT.load(Ordering::SeqCst) > 0);

    // Re-poll the future: it should now be Ready with the number of bytes sent
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 4usize),
        Poll::Ready(Err(e)) => panic!("SendFuture returned error: {:?}", e),
        Poll::Pending => panic!("SendFuture still pending after send"),
    }
}


#[cfg_attr(test, test_case)]
pub fn test_sendfuture_wakes_on_send_v6() {
    init_endpoint_manager();

    // Initialize stack with IPv6 enabled and set transmit to always succeed
    let mut cfg = crate::net::runtime::stack::NetworkConfig::default();
    cfg.ipv6 = Some(crate::net::l3::ipv6::Ipv6Config::from_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
    crate::net::runtime::stack::init(cfg);

    if let Ok(mut guard) = crate::net::runtime::stack::stack().lock() {
        if let Some(ref mut s) = *guard {
            s.set_transmit_fn(|_if: Option<crate::net::runtime::manager::NetIfId>, _data: &[u8]| {
                assert!(_if.is_none());
                true
            });
        }
    }

    // Create endpoint and set IPv6 local/remote (remote uses multicast so no NDP needed)
    let sock = create_tcp_endpoint();
    let fd = sock.fd();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::ALL_NODES_LINK_LOCAL.octets(), 80);
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Insert an Established TCB so handler will proceed
    let mut tcb = TcpControlBlockEntry::new(fd, local, remote);
    tcb.state = TcpConnectionState::Established;
    crate::net::l4::endpoint::tcb::tcb_table().insert(tcb);

    // Prepare a waker that increments a counter
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

    // Create SendFuture and poll once (should register waker and queue DataReady)
    let data = alloc::vec![9u8, 8u8, 7u8, 6u8];
    let mut fut = sock.send_async(data).expect("send_async should return future");
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(_) => panic!("SendFuture should not complete immediately"),
    }

    // Trigger DataReady event
    let handler = crate::net::l4::endpoint::handler::NetworkEventHandler::new();
    let res = handler.handle_event(NetworkEvent::DataReady {
        fd,
        endpoint_type: crate::net::l4::endpoint::types::EndpointType::Tcp,
    });

    assert!(matches!(res, crate::net::l4::endpoint::handler::EventHandleResult::Success));
    assert!(WAKE_COUNT_V6.load(Ordering::SeqCst) > 0);

    // Re-poll the future: it should now be Ready with the number of bytes sent
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 4usize),
        other => panic!("SendFuture returned unexpected result: {:?}", other),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_recv_packet_zero_copy_via_owned_endpoint() {
    init_endpoint_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_default();

    let sock = create_tcp_endpoint();
    let _fd = sock.fd();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Create TCB and attach a TcpStream to the endpoint
    use alloc::sync::Arc;
    use crate::sync::PoisonLock;
    use crate::net::l4::tcp::{TcpControlBlock, EndpointAddr as TcpEndpointAddr, Ipv4Addr as TcpIpv4Addr, TcpStream};

    let t_local = TcpEndpointAddr::new([127, 0, 0, 1], 12345);
    let t_remote = TcpEndpointAddr::new([127, 0, 0, 1], 80);

    let mut tcb = TcpControlBlock::new(t_local);
    tcb.set_remote_addr(t_remote);
    tcb.enter_established();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let stream = TcpStream { tcb: tcb_arc.clone() };

    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.ensure_tcp().stream = Some(stream.clone());
        let _ = inner.transition_to(EndpointState::Connected);
    }

    // Prepare a packet and push it into the TCB recv buffer
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let data = [1u8, 2u8, 3u8, 4u8];
    packet.data_mut()[..data.len()].copy_from_slice(&data);
    packet.set_len(data.len());

    {
        if let Ok(mut tlock) = tcb_arc.lock() {
            tlock.push_recv_packet(packet);
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


#[cfg_attr(test, test_case)]
pub fn test_recv_packet_zero_copy_via_owned_endpoint_v6() {
    init_endpoint_manager();

    // Initialize stack (some operations rely on stack state)
    stack::init_default();

    let sock = create_tcp_endpoint();
    let _fd = sock.fd();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Create TCB and attach a TcpStream to the endpoint (IPv6)
    use alloc::sync::Arc;
    use crate::sync::PoisonLock;
    use crate::net::l4::tcp::{TcpControlBlock, EndpointAddr as TcpEndpointAddr, TcpStream};

    let t_local = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let t_remote = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);

    let mut tcb = TcpControlBlock::new(t_local);
    tcb.set_remote_addr(t_remote);
    tcb.enter_established();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let stream = TcpStream { tcb: tcb_arc.clone() };

    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.ensure_tcp().stream = Some(stream.clone());
        let _ = inner.transition_to(EndpointState::Connected);
    }

    // Prepare a packet and push it into the TCB recv buffer
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let data = [9u8, 10u8, 11u8];
    packet.data_mut()[..data.len()].copy_from_slice(&data);
    packet.set_len(data.len());

    {
        if let Ok(mut tlock) = tcb_arc.lock() {
            tlock.push_recv_packet(packet);
        } else {
            panic!("TCB lock poisoned");
        }
    }

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
    let mut fut = sock.recv_packet_async().expect("recv_packet_async should return future");
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Some(pkt)) => assert_eq!(pkt.data(), &data),
        Poll::Ready(None) => panic!("Expected packet, got None"),
        Poll::Pending => panic!("Future pending despite packet present"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_packet_stream_multiple_packets() {
    init_endpoint_manager();
    stack::init_default();

    let sock = create_tcp_endpoint();
    let _fd = sock.fd();
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Create TCB and attach a TcpStream to the endpoint
    use alloc::sync::Arc;
    use crate::sync::PoisonLock;
    use crate::net::l4::tcp::{TcpControlBlock, EndpointAddr as TcpEndpointAddr, Ipv4Addr as TcpIpv4Addr, TcpStream};

    let t_local = TcpEndpointAddr::new([127, 0, 0, 1], 12345);
    let t_remote = TcpEndpointAddr::new([127, 0, 0, 1], 80);

    let mut tcb = TcpControlBlock::new(t_local);
    tcb.set_remote_addr(t_remote);
    tcb.enter_established();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let stream = TcpStream { tcb: tcb_arc.clone() };

    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.ensure_tcp().stream = Some(stream.clone());
        let _ = inner.transition_to(EndpointState::Connected);
    }

    // Prepare two packets and push into TCB recv buffer
    let mut p1 = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let d1 = [10u8, 11u8];
    p1.data_mut()[..d1.len()].copy_from_slice(&d1);
    p1.set_len(d1.len());

    let mut p2 = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let d2 = [20u8, 21u8, 22u8];
    p2.data_mut()[..d2.len()].copy_from_slice(&d2);
    p2.set_len(d2.len());

    {
        if let Ok(mut tlock) = tcb_arc.lock() {
            tlock.push_recv_packet(p1);
            tlock.push_recv_packet(p2);
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

#[cfg_attr(test, test_case)]
pub fn test_tcp_packet_stream_multiple_packets_v6() {
    init_endpoint_manager();
    stack::init_default();

    let sock = create_tcp_endpoint();
    let _fd = sock.fd();
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.local_addr = Some(local);
        inner.remote_addr = Some(remote);
    }

    // Create TCB and attach a TcpStream to the endpoint (IPv6)
    use alloc::sync::Arc;
    use crate::sync::PoisonLock;
    use crate::net::l4::tcp::{TcpControlBlock, EndpointAddr as TcpEndpointAddr, TcpStream};

    let t_local = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12345);
    let t_remote = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);

    let mut tcb = TcpControlBlock::new(t_local);
    tcb.set_remote_addr(t_remote);
    tcb.enter_established();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let stream = TcpStream { tcb: tcb_arc.clone() };

    if let Some(s) = sock.endpoint() {
        let mut inner = s.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.ensure_tcp().stream = Some(stream.clone());
        let _ = inner.transition_to(EndpointState::Connected);
    }

    // Prepare two packets and push into TCB recv buffer
    let mut p1 = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let d1 = [10u8, 11u8];
    p1.data_mut()[..d1.len()].copy_from_slice(&d1);
    p1.set_len(d1.len());

    let mut p2 = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let d2 = [20u8, 21u8, 22u8];
    p2.data_mut()[..d2.len()].copy_from_slice(&d2);
    p2.set_len(d2.len());

    {
        if let Ok(mut tlock) = tcb_arc.lock() {
            tlock.push_recv_packet(p1);
            tlock.push_recv_packet(p2);
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
#[cfg_attr(test, test_case)]
pub fn test_udp_packet_stream_delivered() {
    init_endpoint_manager();

    // Use a UdpProcessor instance and bind a endpoint to a port
    let processor = crate::net::l4::udp::UdpProcessor::new();
    let port = 40000u16;
    let u = processor.bind_with_token(port, None).expect("bind failed");

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
    let len = crate::net::l4::udp::UdpProcessor::build_packet(packet.data_mut(), src_ip, 12345, dst_ip, port, b"hello").unwrap();
    packet.set_len(len);

    let packet_data = alloc::vec::Vec::from(packet.data());
    let res = processor.process_with_packet(&packet_data, src_ip, dst_ip, packet, 255);
    assert_eq!(res, crate::net::l4::udp::UdpResult::Delivered);

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
        Poll::Ready(Some((addr, _ttl, pkt))) => {
            assert_eq!(pkt.data(), b"hello");
            assert_eq!(addr.port(), 12345);
        }
        _ => panic!("Expected UDP packet"),
    }
}
