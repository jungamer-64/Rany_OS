use super::*;
use crate::net::l3::ipv4::Ipv4Address;
use alloc::{format, vec};

#[cfg_attr(test, test_case)]
pub fn test_ipv4_addr() {
    let addr = Ipv4Addr::new(192, 168, 1, 1);
    assert_eq!(addr.octets(), [192, 168, 1, 1]);
    assert_eq!(format!("{}", addr), "192.168.1.1");
}

#[cfg_attr(test, test_case)]
pub fn test_socket_addr() {
    let addr = EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 8080);
    assert_eq!(format!("{}", addr), "127.0.0.1:8080");
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_state() {
    let tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::UNSPECIFIED.octets(), 0));
    assert_eq!(tcb.state(), TcpState::Closed);
}

#[cfg_attr(test, test_case)]
pub fn test_send_capacity_respects_scaled_window() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::UNSPECIFIED.octets(), 0));
    tcb.enter_established();
    // peer advertised window = 100 with scale factor 4 -> effective 1600
    tcb.seq.snd_wnd = 100;
    tcb.set_peer_wscale(4);
    tcb.congestion.cwnd = 10_000; // large, not limiting

    assert_eq!(tcb.get_effective_snd_wnd(), 100u32 << 4);
    assert_eq!(tcb.send_capacity_bytes(), (100u32 << 4) as usize);
}

#[cfg_attr(test, test_case)]
pub fn test_tcp_stats_rx_wire_and_app_delivery_are_separate() {
    let mut stats = TcpStats::default();
    stats.record_rx_segment(128);
    stats.record_rx_delivered(64);
    stats.record_rx_delivered(64);

    assert_eq!(stats.bytes_received, 128);
    assert_eq!(stats.packets_received, 1);
    assert_eq!(stats.app_bytes_delivered, 128);
}

#[cfg_attr(test, test_case)]
pub fn test_process_with_packet_zero_copy() {
    // Initialize a small mempool for tests
    let _ = crate::net::datapath::mempool::init_net_mempool(2);

    let mut processor = TcpProcessor::new();
    let local = EndpointAddr::new([127, 0, 0, 1], 1000);
    let remote = EndpointAddr::new([127, 0, 0, 1], 2000);

    // Create TCB and register connection
    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    tcb.set_rcv_nxt(1);
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    processor.connections.insert((local, remote), tcb_arc.clone());

    // Build a simple TCP segment with a small payload
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let payload = b"hello";
    let header_len = 20usize;

    // Src port 2000, dst port 1000
    packet.data_mut()[0..2].copy_from_slice(&2000u16.to_be_bytes());
    packet.data_mut()[2..4].copy_from_slice(&1000u16.to_be_bytes());
    // Seq = 1 (in-order)
    packet.data_mut()[4..8].copy_from_slice(&1u32.to_be_bytes());
    // Ack = 0
    packet.data_mut()[8..12].copy_from_slice(&0u32.to_be_bytes());
    // Data offset = 5 (20 bytes), flags = 0
    let data_off_flags = ((5u16 << 12) | 0u16).to_be_bytes();
    packet.data_mut()[12..14].copy_from_slice(&data_off_flags);
    // Window
    packet.data_mut()[14..16].copy_from_slice(&65535u16.to_be_bytes());
    // Payload
    packet.data_mut()[header_len..header_len + payload.len()].copy_from_slice(payload);
    packet.set_len(header_len + payload.len());

    // Call process_with_packet (zero-copy path)
    let data = alloc::vec::Vec::from(packet.data());
    let _res = processor.process_with_packet(
        &data,
        Ipv4Address::from_octets(127, 0, 0, 1),
        Ipv4Address::from_octets(127, 0, 0, 1),
        packet,
        0,
    );

    // Ensure payload was enqueued as PacketRef
    if let Ok(g) = tcb_arc.lock() {
        assert!(!g.recv_buffer_is_empty());
        assert_eq!(g.recv_buffer_front_data(), Some(&payload[..]));
    } else {
        panic!("TCB lock poisoned in test");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_copy_fallback_queues_payload_and_keeps_connection_alive() {
    let _ = crate::net::datapath::mempool::init_net_mempool(2);

    let mut processor = TcpProcessor::new();
    let local = EndpointAddr::new([127, 0, 0, 1], 3000);
    let remote = EndpointAddr::new([127, 0, 0, 1], 4000);

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    // since copy-fallback is disabled by default we must give the TCB a
    // nonzero limit for this test
    tcb.set_recv_copy_fallback_limit_bytes(64 * 1024);
    tcb.set_rcv_nxt(10);
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    processor.connections.insert((local, remote), tcb_arc.clone());

    let header_len = 20usize;
    let payload_len = 5000usize; // Larger than typical mempool packet capacity, forces Vec fallback path
    let mut seg = vec![0u8; header_len + payload_len];
    seg[0..2].copy_from_slice(&4000u16.to_be_bytes()); // src port
    seg[2..4].copy_from_slice(&3000u16.to_be_bytes()); // dst port
    seg[4..8].copy_from_slice(&10u32.to_be_bytes());   // in-order seq
    seg[8..12].copy_from_slice(&0u32.to_be_bytes());   // ack
    seg[12..14].copy_from_slice(&((5u16 << 12) | 0u16).to_be_bytes());
    seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
    seg[header_len..].fill(0x5A);

    let result = processor.process(
        &seg,
        Ipv4Address::from_octets(127, 0, 0, 1),
        Ipv4Address::from_octets(127, 0, 0, 1),
        0,
    );

    match result {
        TcpProcessResult::SendPacket { flags, ack, .. } => {
            assert!(flags & TcpHeader::FLAG_ACK != 0, "ACK flag should be set");
            assert!(flags & TcpHeader::FLAG_RST == 0, "RST should NOT be set");
            assert_eq!(ack, 10u32.wrapping_add(payload_len as u32), "ACK should advance");
        }
        other => panic!("expected ACK SendPacket, got {:?}", other),
    }

    let guard = match tcb_arc.lock() {
        Ok(guard) => guard,
        Err(_) => panic!("TCB lock"),
    };
    assert_eq!(guard.state(), TcpState::Established);
    assert_eq!(guard.recv_copy_fallback_len(), 1);
    assert_eq!(guard.recv_copy_fallback_bytes(), payload_len);
    let stats = guard.stats_snapshot();
    assert_eq!(stats.recv_copy_fallback_packets, 1);
    assert_eq!(stats.recv_copy_fallback_bytes, payload_len as u64);
    assert_eq!(stats.recv_copy_fallback_peak_bytes, payload_len as u64);
    assert_eq!(stats.oom_dropped_packets, 0);
    assert_eq!(stats.oom_dropped_bytes, 0);
}

#[cfg_attr(test, test_case)]
pub fn test_recv_copy_fallback_overflow_sends_rst_and_closes() {
    let _ = crate::net::datapath::mempool::init_net_mempool(2);

    let mut processor = TcpProcessor::new();
    let local = EndpointAddr::new([127, 0, 0, 1], 3100);
    let remote = EndpointAddr::new([127, 0, 0, 1], 4100);

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    // ensure at least some space for payload, overflow will be triggered later
    tcb.set_recv_copy_fallback_limit_bytes(1024);
    tcb.set_rcv_nxt(42);
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    processor.connections.insert((local, remote), tcb_arc.clone());

    let header_len = 20usize;
    let payload_len = 5000usize;
    let mut seg = vec![0u8; header_len + payload_len];
    seg[0..2].copy_from_slice(&4100u16.to_be_bytes()); // src port
    seg[2..4].copy_from_slice(&3100u16.to_be_bytes()); // dst port
    seg[4..8].copy_from_slice(&42u32.to_be_bytes());   // in-order seq
    seg[8..12].copy_from_slice(&0u32.to_be_bytes());   // ack
    seg[12..14].copy_from_slice(&((5u16 << 12) | 0u16).to_be_bytes());
    seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
    seg[header_len..].fill(0xA5);

    let result = processor.process(
        &seg,
        Ipv4Address::from_octets(127, 0, 0, 1),
        Ipv4Address::from_octets(127, 0, 0, 1),
        0,
    );

    match result {
        TcpProcessResult::SendPacket { flags, ack, .. } => {
            assert!(flags & TcpHeader::FLAG_RST != 0, "RST should be set");
            assert!(flags & TcpHeader::FLAG_ACK != 0, "ACK should be set");
            assert_eq!(ack, 42, "ACK should not advance when enqueue fails");
        }
        other => panic!("expected RST+ACK SendPacket, got {:?}", other),
    }

    let guard = match tcb_arc.lock() {
        Ok(guard) => guard,
        Err(_) => panic!("TCB lock"),
    };
    assert_eq!(guard.state(), TcpState::Closed);
    assert_eq!(guard.recv_copy_fallback_bytes(), 0);
    assert!(guard.recv_copy_fallback_is_empty());
    assert_eq!(guard.stats_snapshot().recv_copy_fallback_packets, 0);
}

#[cfg_attr(test, test_case)]
pub fn test_poll_read_consumes_recv_copy_fallback_queue_with_remainder() {
    let local = EndpointAddr::new([127, 0, 0, 1], 3200);
    let remote = EndpointAddr::new([127, 0, 0, 1], 4200);

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    // make room for the small queue we will push in
    tcb.set_recv_copy_fallback_limit_bytes(16);
    assert!(tcb.enqueue_recv_copy_fallback(&[1, 2, 3, 4, 5]));

    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let mut stream = TcpStream { tcb: tcb_arc.clone() };

    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);

    let mut buf = [0u8; 3];
    let mut pinned_stream = unsafe { Pin::new_unchecked(&mut stream) };
    match pinned_stream.as_mut().poll_read(&mut cx, &mut buf) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 3),
        other => panic!("poll_read returned {:?}", other),
    }
    assert_eq!(&buf, &[1, 2, 3]);

    {
        let guard = match tcb_arc.lock() {
            Ok(guard) => guard,
            Err(_) => panic!("TCB lock"),
        };
        assert_eq!(guard.recv_copy_fallback_bytes(), 2);
        assert_eq!(guard.recv_copy_fallback_front_data(), Some(&[4, 5][..]));
    }

    let mut buf2 = [0u8; 8];
    match pinned_stream.as_mut().poll_read(&mut cx, &mut buf2) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 2),
        other => panic!("second poll_read returned {:?}", other),
    }
    assert_eq!(&buf2[..2], &[4, 5]);

    let guard = match tcb_arc.lock() {
        Ok(guard) => guard,
        Err(_) => panic!("TCB lock"),
    };
    assert_eq!(guard.recv_copy_fallback_bytes(), 0);
    assert!(guard.recv_copy_fallback_is_empty());
}

#[cfg_attr(test, test_case)]
pub fn test_can_send_respects_cwnd_bytes() {
    let _ = crate::net::datapath::mempool::init_net_mempool(2);
    let local = EndpointAddr::new([127, 0, 0, 1], 1000);
    let mut tcb = TcpControlBlock::new(local);
    tcb.enter_established();
    tcb.set_cwnd_for_test(100);
    assert!(tcb.can_send());
    // If queued bytes alone already exceed cwnd, cannot send
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    packet.set_len(100);
    tcb.enqueue_send_packet(packet);
    assert!(!tcb.can_send());
}

#[cfg_attr(test, test_case)]
pub fn test_send_buffer_bytes_decrement_on_flush() {
    // Initialize a small mempool for tests
    let _ = crate::net::datapath::mempool::init_net_mempool(2);

    let local = EndpointAddr::new([127,0,0,1], 1001);
    let remote = EndpointAddr::new([127,0,0,1], 2001);

    // Create TCB and wrap in Arc<PoisonLock>
    let mut tcb = TcpControlBlock::new(local);
    tcb.enter_established();
    tcb.set_remote_addr(remote);
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    let mut stream = TcpStream { tcb: tcb_arc.clone() };

    // Create packet and enqueue
    let mut packet = crate::net::datapath::mempool::alloc_packet().expect("alloc packet");
    let payload = [0u8; 120];
    packet.data_mut()[..payload.len()].copy_from_slice(&payload);
    packet.set_len(payload.len());

    if let Ok(mut g) = tcb_arc.lock() {
        g.enqueue_send_packet(packet);
    } else {
        panic!("TCB lock poisoned in test");
    }

    // Create a noop Context
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};
    use core::pin::Pin;
    use core::task::Poll;
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);

    // Call poll_flush
    let mut pinned_stream = unsafe { Pin::new_unchecked(&mut stream) };
    match pinned_stream.as_mut().poll_flush(&mut cx) {
        Poll::Ready(Ok(())) => {},
        other => panic!("poll_flush returned {:?}", other),
    }

    // Verify packet was requeued on send failure and outstanding is unchanged
    if let Ok(g) = tcb_arc.lock() {
        assert_eq!(g.send_buffer_bytes(), payload.len() as u32);
        assert!(!g.send_buffer_is_empty());
        assert_eq!(g.outstanding_bytes(), 0);
    } else {
        panic!("TCB lock poisoned");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_three_way_handshake() {
    // Initialize mempool for any packet allocations
    let _ = crate::net::datapath::mempool::init_net_mempool(4);

    let mut client = TcpProcessor::new();
    let mut server = TcpProcessor::new();

    let client_addr = EndpointAddr::new([127,0,0,1], 2000);
    let server_addr = EndpointAddr::new([127,0,0,1], 1000);

    // Server binds (creates a listener with backlog)
    let listener = server.bind(server_addr, None).expect("bind");

    // Client initiates connection (sets up a SynSent TCB)
    let _client_stream = client.connect(client_addr, server_addr).expect("connect");

    // Grab client's initial sequence number
    let client_tcb_arc = client
        .connections
        .get(&(client_addr, server_addr))
        .expect("client tcb missing")
        .clone();

    let client_initial_seq = match client_tcb_arc.lock() {
        Ok(g) => g.snd_nxt(),
        Err(_) => panic!("TCB lock poisoned"),
    };

    // Build SYN from client -> server
    let mut syn = [0u8; 20];
    syn[0..2].copy_from_slice(&client_addr.port().to_be_bytes());
    syn[2..4].copy_from_slice(&server_addr.port().to_be_bytes());
    syn[4..8].copy_from_slice(&client_initial_seq.to_be_bytes());
    syn[8..12].copy_from_slice(&0u32.to_be_bytes());
    let data_off_flags = ((5u16 << 12) | TcpHeader::FLAG_SYN).to_be_bytes();
    syn[12..14].copy_from_slice(&data_off_flags);
    syn[14..16].copy_from_slice(&65535u16.to_be_bytes());

    // Server processes SYN -> should return a SYN-ACK
    let res = server.process(
        &syn,
        Ipv4Address::from_octets(127, 0, 0, 1),
        Ipv4Address::from_octets(127, 0, 0, 1),
        0,
    );
    let syn_ack_pkt = match res {
        TcpProcessResult::SendPacket { local, remote, seq, ack, flags, .. } => {
            assert!(flags & TcpHeader::FLAG_SYN != 0);
            assert!(flags & TcpHeader::FLAG_ACK != 0);
            (local, remote, seq, ack)
        }
        _ => panic!("Expected SYN-ACK from server"),
    };

    // Build SYN-ACK bytes and feed to client
    let mut synack = [0u8; 20];
    synack[0..2].copy_from_slice(&syn_ack_pkt.0.port().to_be_bytes());
    synack[2..4].copy_from_slice(&syn_ack_pkt.1.port().to_be_bytes());
    synack[4..8].copy_from_slice(&syn_ack_pkt.2.to_be_bytes());
    synack[8..12].copy_from_slice(&syn_ack_pkt.3.to_be_bytes());
    let off_flags = ((5u16 << 12) | (TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK)).to_be_bytes();
    synack[12..14].copy_from_slice(&off_flags);
    synack[14..16].copy_from_slice(&65535u16.to_be_bytes());

    // Client processes SYN-ACK -> should generate an ACK
    let client_res = client.process(
        &synack,
        Ipv4Address::from_octets(127, 0, 0, 1),
        Ipv4Address::from_octets(127, 0, 0, 1),
        0,
    );

    let ack_pkt = match client_res {
        TcpProcessResult::SendPacket { local, remote, seq, ack, flags, .. } => {
            assert!(flags & TcpHeader::FLAG_ACK != 0);
            (local, remote, seq, ack)
        }
        _ => panic!("Expected ACK from client"),
    };

    // Build ACK bytes and feed back to server to complete handshake
    let mut ack = [0u8; 20];
    ack[0..2].copy_from_slice(&ack_pkt.0.port().to_be_bytes());
    ack[2..4].copy_from_slice(&ack_pkt.1.port().to_be_bytes());
    ack[4..8].copy_from_slice(&ack_pkt.2.to_be_bytes());
    ack[8..12].copy_from_slice(&ack_pkt.3.to_be_bytes());
    let ack_off_flags = ((5u16 << 12) | (TcpHeader::FLAG_ACK)).to_be_bytes();
    ack[12..14].copy_from_slice(&ack_off_flags);
    ack[14..16].copy_from_slice(&65535u16.to_be_bytes());

    let srv_res = server.process(
        &ack,
        Ipv4Address::from_octets(127, 0, 0, 1),
        Ipv4Address::from_octets(127, 0, 0, 1),
        0,
    );

    // Server should have moved the child TCB to Established and queued it in backlog
    match srv_res {
        TcpProcessResult::SendPacket { flags, .. } => {
            // Server may send an ACK back; that's fine
            assert!(flags & TcpHeader::FLAG_ACK != 0);
        }
        TcpProcessResult::None => {}
    }

    // Check backlog
    if let Ok(mut backlog) = listener.backlog.lock() {
        assert!(!backlog.is_empty());
        let stream = backlog.pop_front().unwrap();
        assert_eq!(stream.peer_addr().unwrap(), client_addr);
    } else {
        panic!("Listener backlog poisoned");
    }
}


#[cfg_attr(test, test_case)]
pub fn test_three_way_handshake_v6() {
    // IPv6 three-way handshake using TcpProcessor::process_v6
    let _ = crate::net::datapath::mempool::init_net_mempool(4);

    let mut client = TcpProcessor::new();
    let mut server = TcpProcessor::new();

    let client_addr = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 3000);
    let server_addr = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 4000);

    let listener = server.bind(server_addr, None).expect("bind v6");

    let _client_stream = client.connect(client_addr, server_addr).expect("connect v6");

    let client_tcb_arc = client
        .connections
        .get(&(client_addr, server_addr))
        .expect("client tcb missing")
        .clone();

    let client_initial_seq = match client_tcb_arc.lock() {
        Ok(g) => g.snd_nxt(),
        Err(_) => panic!("TCB lock poisoned"),
    };

    // Build SYN bytes
    let mut syn = [0u8; 20];
    syn[0..2].copy_from_slice(&client_addr.port().to_be_bytes());
    syn[2..4].copy_from_slice(&server_addr.port().to_be_bytes());
    syn[4..8].copy_from_slice(&client_initial_seq.to_be_bytes());
    syn[8..12].copy_from_slice(&0u32.to_be_bytes());
    let data_off_flags = ((5u16 << 12) | TcpHeader::FLAG_SYN).to_be_bytes();
    syn[12..14].copy_from_slice(&data_off_flags);
    syn[14..16].copy_from_slice(&65535u16.to_be_bytes());

    // Server processes SYN (IPv6)
    let res = server.process_v6(
        &syn,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        0,
    );

    let syn_ack_pkt = match res {
        TcpProcessResult::SendPacket { local, remote, seq, ack, flags, .. } => {
            assert!(flags & TcpHeader::FLAG_SYN != 0);
            assert!(flags & TcpHeader::FLAG_ACK != 0);
            (local, remote, seq, ack)
        }
        _ => panic!("Expected SYN-ACK from server (v6)"),
    };

    // Build SYN-ACK and feed to client
    let mut synack = [0u8; 20];
    synack[0..2].copy_from_slice(&syn_ack_pkt.0.port().to_be_bytes());
    synack[2..4].copy_from_slice(&syn_ack_pkt.1.port().to_be_bytes());
    synack[4..8].copy_from_slice(&syn_ack_pkt.2.to_be_bytes());
    synack[8..12].copy_from_slice(&syn_ack_pkt.3.to_be_bytes());
    let off_flags = ((5u16 << 12) | (TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK)).to_be_bytes();
    synack[12..14].copy_from_slice(&off_flags);
    synack[14..16].copy_from_slice(&65535u16.to_be_bytes());

    let client_res = client.process_v6(
        &synack,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        0,
    );

    let ack_pkt = match client_res {
        TcpProcessResult::SendPacket { local, remote, seq, ack, flags, .. } => {
            assert!(flags & TcpHeader::FLAG_ACK != 0);
            (local, remote, seq, ack)
        }
        _ => panic!("Expected ACK from client (v6)"),
    };

    let mut ack = [0u8; 20];
    ack[0..2].copy_from_slice(&ack_pkt.0.port().to_be_bytes());
    ack[2..4].copy_from_slice(&ack_pkt.1.port().to_be_bytes());
    ack[4..8].copy_from_slice(&ack_pkt.2.to_be_bytes());
    ack[8..12].copy_from_slice(&ack_pkt.3.to_be_bytes());
    let ack_off_flags = ((5u16 << 12) | (TcpHeader::FLAG_ACK)).to_be_bytes();
    ack[12..14].copy_from_slice(&ack_off_flags);
    ack[14..16].copy_from_slice(&65535u16.to_be_bytes());

    let srv_res = server.process_v6(
        &ack,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        0,
    );

    match srv_res {
        TcpProcessResult::SendPacket { flags, .. } => {
            assert!(flags & TcpHeader::FLAG_ACK != 0);
        }
        TcpProcessResult::None => {}
    }

    if let Ok(mut backlog) = listener.backlog.lock() {
        assert!(!backlog.is_empty());
        let stream = backlog.pop_front().unwrap();
        assert_eq!(stream.peer_addr().unwrap(), client_addr);
    } else {
        panic!("Listener backlog poisoned");
    }
}
#[cfg_attr(test, test_case)]
pub fn test_retransmit_on_timeout() {
    let _ = crate::net::datapath::mempool::init_net_mempool(2);

    let mut processor = TcpProcessor::new();
    let local = EndpointAddr::new([127,0,0,1], 1000);
    let remote = EndpointAddr::new([127,0,0,1], 2000);

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    // Add an unacked segment with old timestamp (also updates outstanding_bytes)
    tcb.queue_unacked(1, vec![1, 2, 3], 0, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
    tcb.set_rto_for_test(1); // small RTO

    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    processor.connections.insert((local, remote), tcb_arc.clone());

    let res = processor.check_retransmissions(2); // current_time > sent_time + rto
    assert_eq!(res.len(), 1);
    if let TcpProcessResult::SendPacket { seq, payload, .. } = &res[0] {
        assert_eq!(*seq, 1);
        assert_eq!(payload, &vec![1,2,3]);
    } else {
        panic!("Expected SendPacket");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_connect_future_wakes_on_established() {
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};
    use core::pin::Pin;
    use core::task::Poll;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);

    // Create a TCB in SynSent state
    let local = EndpointAddr::new([127,0,0,1], 4000);
    let mut tcb = TcpControlBlock::new(local);
    tcb.enter_syn_sent();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));

    // Create ConnectFuture
    let mut fut = ConnectFuture { tcb: tcb_arc.clone() };

    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| { WAKE_COUNT.fetch_add(1, Ordering::SeqCst); },
        |_| { WAKE_COUNT.fetch_add(1, Ordering::SeqCst); },
        |_| {},
    );
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);

    let mut pinned_fut = unsafe { Pin::new_unchecked(&mut fut) };

    // First poll should be Pending and register waker
    match pinned_fut.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        other => panic!("ConnectFuture poll expected Pending, got {:?}", other),
    }

    // Ensure TCB lock is still accessible after registration
    if tcb_arc.lock().is_err() {
        panic!("TCB lock poisoned");
    }

    // Simulate connection establishment and wake
    if let Ok(mut g) = tcb_arc.lock() {
        g.enter_established();
        g.wake_connect_waiter();
    }

    // Poll again, should be Ready(Ok(()))
    match pinned_fut.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(())) => {}
        other => panic!("ConnectFuture poll expected Ready(Ok(())), got {:?}", other),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_record_sent_packet_updates_tcb() {
    // Create processor and register a connection
    let mut processor = TcpProcessor::new();
    let local = EndpointAddr::new([127,0,0,1], 7000);
    let remote = EndpointAddr::new([127,0,0,1], 8000);

    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));
    processor.connections.insert((local, remote), tcb_arc.clone());

    // Simulate sending a data segment (length 4)
    let seq = 100u32;
    let payload = [1u8, 2, 3, 4];
    let now = 123456u64;

    processor.record_sent_packet(local, remote, seq, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK, &payload, now);

    if let Ok(g) = tcb_arc.lock() {
        assert_eq!(g.outstanding_bytes(), 4);
        assert_eq!(g.snd_nxt(), seq.wrapping_add(4));
        assert_eq!(g.oldest_unacked_seq(), Some(seq));
    } else {
        panic!("TCB lock poisoned");
    }
}

#[cfg_attr(test, test_case)]
pub fn test_ack_segments_removes_unacked_and_reduces_outstanding() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 9000));
    tcb.enter_established();

    // Add an unacked segment (also updates outstanding_bytes)
    tcb.queue_unacked(10, vec![1, 2, 3, 4], 0, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);

    // ACK that acknowledges the segment
    tcb.ack_segments(14); // seq + len

    assert!(tcb.oldest_unacked_seq().is_none());
    assert_eq!(tcb.outstanding_bytes(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_ack_segments_partial_ack_keeps_later_segments_and_updates_outstanding() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 9002));
    tcb.enter_established();

    tcb.queue_unacked(10, vec![1, 2, 3, 4], 0, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
    tcb.queue_unacked(14, vec![5, 6, 7], 0, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
    assert_eq!(tcb.outstanding_bytes(), 7);

    // ACK only the first segment
    tcb.ack_segments(14, 0);
    assert_eq!(tcb.oldest_unacked_seq(), Some(14));
    assert_eq!(tcb.outstanding_bytes(), 3);

    // ACK the remaining segment
    tcb.ack_segments(17);
    assert!(tcb.oldest_unacked_seq().is_none());
    assert_eq!(tcb.outstanding_bytes(), 0);
}

#[cfg_attr(test, test_case)]
pub fn test_ack_segments_partial_within_segment_trims_retransmit_entry() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 9003));
    tcb.enter_established();

    tcb.queue_unacked(100, vec![1, 2, 3, 4], 0, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
    assert_eq!(tcb.outstanding_bytes(), 4);

    // Partial ACK for first 2 bytes of payload.
    tcb.ack_segments(102);
    assert_eq!(tcb.outstanding_bytes(), 2);
    assert_eq!(tcb.oldest_unacked_seq(), Some(102));

    let (seq, flags, payload) = tcb
        .clone_oldest_unacked_packet_for_retransmit()
        .expect("trimmed segment should remain queued");
    assert_eq!(seq, 102);
    assert_eq!(flags, TcpHeader::FLAG_PSH | TcpHeader::FLAG_ACK);
    assert_eq!(payload, vec![3, 4]);

    tcb.ack_segments(104);
    assert_eq!(tcb.outstanding_bytes(), 0);
    assert!(tcb.oldest_unacked_seq().is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_ack_segments_partial_trims_syn_then_payload() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 9004));
    tcb.enter_established();

    tcb.queue_unacked(100, vec![10, 11, 12], 0, TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK);
    assert_eq!(tcb.outstanding_bytes(), 4); // SYN + 3 bytes

    // ACK only the SYN and first payload byte.
    tcb.ack_segments(102);
    assert_eq!(tcb.outstanding_bytes(), 2);
    assert_eq!(tcb.oldest_unacked_seq(), Some(102));

    let (seq, flags, payload) = tcb
        .clone_oldest_unacked_packet_for_retransmit()
        .expect("trimmed SYN segment should remain queued");
    assert_eq!(seq, 102);
    assert_eq!(flags, TcpHeader::FLAG_ACK); // SYN removed
    assert_eq!(payload, vec![11, 12]);
}

#[cfg_attr(test, test_case)]
pub fn test_ack_segments_partial_trims_payload_but_keeps_fin() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 9005));
    tcb.enter_established();

    tcb.queue_unacked(200, vec![1, 2, 3], 0, TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK);
    assert_eq!(tcb.outstanding_bytes(), 4); // 3 bytes + FIN

    // ACK first 2 payload bytes, FIN is still outstanding.
    tcb.ack_segments(202);
    assert_eq!(tcb.outstanding_bytes(), 2); // remaining payload byte + FIN
    assert_eq!(tcb.oldest_unacked_seq(), Some(202));

    let (seq, flags, payload) = tcb
        .clone_oldest_unacked_packet_for_retransmit()
        .expect("trimmed FIN segment should remain queued");
    assert_eq!(seq, 202);
    assert_eq!(flags, TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK); // FIN preserved
    assert_eq!(payload, vec![3]);
}

#[cfg_attr(test, test_case)]
pub fn test_unacked_sequence_space_accounts_for_syn_and_fin() {
    let mut tcb = TcpControlBlock::new(EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 9001));
    tcb.enter_established();

    // SYN consumes one sequence number even with empty payload.
    tcb.queue_unacked(100, vec![], 0, TcpHeader::FLAG_SYN | TcpHeader::FLAG_ACK);
    assert_eq!(tcb.outstanding_bytes(), 1);
    tcb.ack_segments(101);
    assert_eq!(tcb.outstanding_bytes(), 0);
    assert!(tcb.oldest_unacked_seq().is_none());

    // FIN also consumes one sequence number in addition to payload bytes.
    tcb.queue_unacked(200, vec![1, 2], 0, TcpHeader::FLAG_FIN | TcpHeader::FLAG_ACK);
    assert_eq!(tcb.outstanding_bytes(), 3);
    tcb.ack_segments(203);
    assert_eq!(tcb.outstanding_bytes(), 0);
    assert!(tcb.oldest_unacked_seq().is_none());
}

#[cfg_attr(test, test_case)]
pub fn test_accept_future_returns_on_push_connection() {
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};
    use core::pin::Pin;
    use core::task::Poll;

    let mut server = TcpProcessor::new();
    let server_addr = EndpointAddr::new([127,0,0,1], 5000);
    let listener = server.bind(server_addr, None).expect("bind");

    // Create AcceptFuture manually
    let mut fut = AcceptFuture { listener: &listener };

    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);

    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    // First poll: Pending (no backlog)
    match pinned.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        _ => panic!("AcceptFuture expected Pending"),
    }

    // Prepare a TcpStream and push into backlog
    let local = EndpointAddr::new([127,0,0,1], 5000);
    let remote = EndpointAddr::new([127,0,0,1], 6000);
    let mut tcb = TcpControlBlock::new(local);
    tcb.set_remote_addr(remote);
    tcb.enter_established();
    let stream = TcpStream { tcb: Arc::new(PoisonLock::new(tcb)) };

    listener.push_connection(stream, remote);

    // Second poll should return Ready with the connection
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Ok((stream, addr))) => {
            assert_eq!(addr, remote);
            assert!(stream.peer_addr().is_some());
        }
        _ => panic!("AcceptFuture expected Ready"),
    }
}

#[cfg_attr(test, test_case)]
pub fn test_connect_timeout_expires() {
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};
    use core::pin::Pin;
    use core::task::Poll;

    let now = crate::task::timer::current_tick();
    let local = EndpointAddr::new(Ipv4Addr::LOCALHOST.octets(), 4001);
    let mut tcb = TcpControlBlock::new(local);
    tcb.enter_syn_sent();
    let tcb_arc = Arc::new(PoisonLock::new(tcb));

    // Create a ConnectTimeoutFuture that already expired
    let timeout_us = 1000u64;
    let start_us = now.saturating_sub(timeout_us + 1);
    let mut fut = ConnectTimeoutFuture {
        tcb: tcb_arc.clone(),
        start_us,
        timeout_us,
    };

    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw_waker = RawWaker::new(core::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);

    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(Err(TcpError::Timeout)) => {}
        other => panic!("ConnectTimeoutFuture expected Timeout, got {:?}", other),
    }
}
