// ============================================================================
// kernel/src/net/tests/qemu/tcp_ooo_tests.rs - TCP receive queue admission
// ============================================================================

use crate::net::l4::socket::{Socket, TcpSocketState, unregister_socket_in};
use crate::net::l4::tcp::ooo_queue::{
    drain_ooo_contiguous, has_ooo_segments, insert_ooo_segment, remove_ooo_queue,
};
use crate::net::l4::tcp::tcb::TcpControlBlock;
use crate::net::l4::types::EndpointAddr;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;
use alloc::vec::Vec;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

const CONNECTION_CAPACITY: usize = 16;
const RUNTIME_CAPACITY: usize = 512;
const TEST_INTERFACE: NetIfId = NetIfId(65_020);

fn payload(runtime: NetRuntimeHandle, byte: u8) -> PacketPayload {
    let mut packet =
        crate::net::payload::alloc_packet_with_headroom_in(runtime, 1, DEFAULT_PACKET_HEADROOM)
            .expect("OOO packet allocation");
    packet.data_mut()[0] = byte;
    PacketPayload::try_single(packet).expect("non-empty OOO packet")
}

fn insert(runtime: NetRuntimeHandle, local: EndpointAddr, seq: u32, byte: u8) {
    insert_ooo_segment(
        runtime,
        TEST_INTERFACE,
        local,
        remote(),
        seq,
        Some(payload(runtime, byte)),
        false,
    );
}

fn remote() -> EndpointAddr {
    EndpointAddr::new([127, 0, 0, 1], 80)
}

fn drain_one(runtime: NetRuntimeHandle, local: EndpointAddr, seq: u32) -> Option<u8> {
    let mut delivered = None;
    let (next, fin) = drain_ooo_contiguous(
        runtime,
        TEST_INTERFACE,
        local,
        remote(),
        seq,
        |delivered_seq, packet| {
            assert_eq!(delivered_seq, seq);
            assert_eq!(packet.total_len(), 1);
            assert!(delivered.is_none());
            delivered = Some(packet.segments()[0].data()[0]);
            (1, None)
        },
    );
    assert_eq!(next, seq + u32::from(delivered.is_some()));
    assert!(!fin);
    delivered
}

pub fn tcp_ooo_permits_and_bounded_queue_smoke() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("OOO runtime");
    let table = tcp_table_in(runtime);
    let mut connections = Vec::new();
    for index in 0..=RUNTIME_CAPACITY / CONNECTION_CAPACITY {
        let local = EndpointAddr::new([127, 0, 0, 1], 56_000 + index as u16);
        let socket = Socket::new_tcp_in(runtime, TcpSocketState::Connecting);
        table
            .insert(TcpControlBlock::start_connect(
                socket.socket_id(),
                local,
                remote(),
                1,
                false,
                TEST_INTERFACE,
            ))
            .expect("registered OOO connection");
        connections.push((local, socket));
    }
    let sentinel = connections[0].0;

    insert(runtime, sentinel, 100, 1);
    assert!(has_ooo_segments(
        runtime,
        TEST_INTERFACE,
        sentinel,
        remote()
    ));
    insert(runtime, sentinel, 100, 2);
    assert!(!has_ooo_segments(
        runtime,
        TEST_INTERFACE,
        sentinel,
        remote()
    ));
    insert(runtime, sentinel, 200, 3);
    remove_ooo_queue(runtime, TEST_INTERFACE, sentinel, remote());
    assert!(!has_ooo_segments(
        runtime,
        TEST_INTERFACE,
        sentinel,
        remote()
    ));

    for index in 0..CONNECTION_CAPACITY {
        insert(runtime, sentinel, 100 + index as u32 * 2, index as u8);
    }
    insert(runtime, sentinel, 1000, 0xff);
    insert(runtime, sentinel, 50, 0xfe);
    assert_eq!(drain_one(runtime, sentinel, 50), Some(0xfe));
    for index in 0..CONNECTION_CAPACITY - 1 {
        assert_eq!(
            drain_one(runtime, sentinel, 100 + index as u32 * 2),
            Some(index as u8)
        );
    }
    assert_eq!(drain_one(runtime, sentinel, 130), None);
    assert_eq!(drain_one(runtime, sentinel, 1000), None);
    assert!(!has_ooo_segments(
        runtime,
        TEST_INTERFACE,
        sentinel,
        remote()
    ));

    // Fill the advertised aggregate capacity after overlap, clear, eviction,
    // rejection and delivery. A leaked permit makes a later delivery missing.
    for (local, _) in &connections[1..] {
        for index in 0..CONNECTION_CAPACITY {
            insert(runtime, *local, 100 + index as u32 * 2, index as u8);
        }
    }
    insert(runtime, sentinel, 200, 7);
    assert!(!has_ooo_segments(
        runtime,
        TEST_INTERFACE,
        sentinel,
        remote()
    ));

    let first = connections[1].0;
    assert_eq!(drain_one(runtime, first, 100), Some(0));
    insert(runtime, sentinel, 200, 7);
    assert_eq!(drain_one(runtime, sentinel, 200), Some(7));
    insert(runtime, first, 100, 0);

    // Removing a live TCB must release all of its queue owners and permits.
    drop(
        table
            .remove(TEST_INTERFACE, first, remote())
            .expect("live OOO connection"),
    );
    for index in 0..CONNECTION_CAPACITY {
        insert(runtime, sentinel, 100 + index as u32 * 2, index as u8);
    }
    for index in 0..CONNECTION_CAPACITY {
        assert_eq!(
            drain_one(runtime, sentinel, 100 + index as u32 * 2),
            Some(index as u8)
        );
    }
    for (local, _) in &connections[2..] {
        for index in 0..CONNECTION_CAPACITY {
            assert_eq!(
                drain_one(runtime, *local, 100 + index as u32 * 2),
                Some(index as u8)
            );
        }
    }

    for (local, socket) in connections {
        if local != first {
            drop(
                table
                    .remove(TEST_INTERFACE, local, remote())
                    .expect("empty OOO connection"),
            );
        }
        assert!(unregister_socket_in(runtime, socket.socket_id()).is_some());
    }
    true
}
