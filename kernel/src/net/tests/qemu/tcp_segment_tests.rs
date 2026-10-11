// ============================================================================
// kernel/src/net/tests/qemu/tcp_segment_tests.rs - TCP packet construction and admission
// ============================================================================

use crate::net::l4::tcp::segment::{TcpSegmentBuilder, send_tcp_segment_payload_in};
use crate::net::l4::tcp::tcb::tcp_flags;
use crate::net::l4::types::EndpointAddr;
use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView};
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;
use kernel_api::resource::net::PacketPayload;

fn test_payload_bytes(data: &[u8]) -> PacketPayload {
    let mut writer = GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM)
        .expect("test packet payload allocation");
    writer
        .write_generated_bytes(data)
        .expect("test packet payload write succeeds");
    writer.finish().expect("test packet payload is exact")
}

fn build_test_segment(builder: TcpSegmentBuilder) -> PacketPayload {
    builder.build_packet().expect("test TCP segment allocation")
}

fn send_test_segment(
    runtime: crate::net::runtime::NetRuntimeHandle,
    local: EndpointAddr,
    remote: EndpointAddr,
    segment: PacketPayload,
) -> bool {
    send_tcp_segment_payload_in(
        runtime,
        crate::net::runtime::manager::NetIfId(1),
        local,
        remote,
        segment,
    )
}

pub fn tcp_segment_builder_smoke() -> bool {
    // SYNセグメント構築
    let segment = build_test_segment(
        TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535),
    );
    let view = PacketPayloadView::new(&segment);

    // ヘッダサイズは20バイト（オプションなし）
    assert_eq!(view.total_len(), 20);

    // ポート検証
    assert_eq!(view.read_u16_be(0), Some(12345));
    assert_eq!(view.read_u16_be(2), Some(80));

    // シーケンス番号検証
    assert_eq!(view.read_u32_be(4), Some(1000));

    // フラグ検証（SYN = 0x02）
    let data_offset_flags = view.read_u16_be(12).expect("TCP data offset flags");
    let flags = (data_offset_flags & 0x3F) as u8;
    assert_eq!(flags & tcp_flags::SYN, tcp_flags::SYN);
    true
}

pub fn tcp_segment_with_data_smoke() -> bool {
    let data = alloc::vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
    let segment = build_test_segment(
        TcpSegmentBuilder::new(8080, 80)
            .seq(2000)
            .ack(3000)
            .ack_flag()
            .payload_packet(test_payload_bytes(&data)),
    );
    let view = PacketPayloadView::new(&segment);

    // ヘッダ20バイト + データ5バイト
    assert_eq!(view.total_len(), 25);

    // データ検証
    assert_eq!(
        view.read_fixed_bytes::<5>(20, 5)
            .expect("TCP payload")
            .as_slice(),
        b"Hello"
    );
    true
}

pub fn tcp_segment_with_options_smoke() -> bool {
    // SYNセグメント with TCP options
    let segment = build_test_segment(
        TcpSegmentBuilder::new(12345, 80)
            .seq(1000)
            .syn()
            .window(65535)
            .syn_options(1460, Some(7), true, None), // MSS=1460, WS=7, SACK
    );
    let view = PacketPayloadView::new(&segment);

    // ヘッダ20バイト + オプション12バイト = 32バイト (MSS:4, WS:3, SACK:2, EOL/padding:3)
    assert_eq!(view.total_len(), 32);

    // Data Offset = 8 (32バイト / 4 = 8)
    let data_offset_flags = view.read_u16_be(12).expect("TCP data offset flags");
    let data_offset = ((data_offset_flags >> 12) & 0xF) as u8;
    assert_eq!(data_offset, 8);

    // オプション検証
    // MSS (Kind=2, Length=4, Value=1460)
    assert_eq!(view.read_u8(20), Some(2)); // Kind
    assert_eq!(view.read_u8(21), Some(4)); // Length
    assert_eq!(view.read_u16_be(22), Some(1460)); // MSS

    // Window Scale (Kind=3, Length=3, Shift=7)
    assert_eq!(view.read_u8(24), Some(3)); // Kind
    assert_eq!(view.read_u8(25), Some(3)); // Length
    assert_eq!(view.read_u8(26), Some(7)); // Shift

    // SACK Permitted (Kind=4, Length=2)
    assert_eq!(view.read_u8(27), Some(4)); // Kind
    assert_eq!(view.read_u8(28), Some(2)); // Length

    // RFC 9293 section 3.1 requires zero padding after End of Option List.
    assert_eq!(view.read_u8(29), Some(0)); // EOL
    assert_eq!(view.read_u8(30), Some(0));
    assert_eq!(view.read_u8(31), Some(0));
    true
}

pub fn tcp_message_length_field_for_checksum_smoke() -> bool {
    let mut segment = build_test_segment(
        TcpSegmentBuilder::new(12345, 80)
            .seq(1)
            .ack(1)
            .ack_flag()
            .payload_packet(test_payload_bytes(b"abc")),
    );

    TcpSegmentBuilder::calculate_checksum(&mut segment, [192, 168, 1, 10], [192, 168, 1, 20]);

    let checksum = PacketPayloadView::new(&segment)
        .read_u16_be(16)
        .expect("TCP checksum");
    assert_eq!(checksum, 0x3775);
    true
}

pub fn tcp_checksum_v6_smoke() -> bool {
    let mut segment = build_test_segment(TcpSegmentBuilder::new(1234, 80).seq(1).ack(0));
    TcpSegmentBuilder::calculate_checksum_v6(
        &mut segment,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
        crate::net::l3::ipv6::Ipv6Address::LOOPBACK,
    );
    // RFC 9293 section 3.1: IPv6 pseudo-header plus the 20-byte segment.
    assert_eq!(
        PacketPayloadView::new(&segment).read_u16_be(16),
        Some(0xaac0)
    );
    true
}

pub fn tcp_segment_mixed_family_rejection_smoke() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
    let local = EndpointAddr::new([127, 0, 0, 1], 12345);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    let segment = build_test_segment(TcpSegmentBuilder::new(local.port(), remote.port()).syn());

    assert!(!send_test_segment(runtime, local, remote, segment));
    let current = crate::cpu::CurrentCpu::acquire().expect("TCP rejection CPU");
    let resources =
        crate::net::runtime::command::command_resources_for_cpu_in(runtime, current.id())
            .expect("TCP rejection command resources");
    assert!(resources.command_queue.recv().is_none());
    true
}

pub fn tcp_segment_ipv4_queue_admission_smoke() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
    let local = EndpointAddr::new([127, 0, 0, 1], 12346);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    let segment = build_test_segment(TcpSegmentBuilder::new(local.port(), remote.port()).syn());

    let backing = segment.segments()[0].data().as_ptr();
    assert!(send_test_segment(runtime, local, remote, segment));
    let current = crate::cpu::CurrentCpu::acquire().expect("TCP IPv4 admission CPU");
    let resources =
        crate::net::runtime::command::command_resources_for_cpu_in(runtime, current.id())
            .expect("TCP IPv4 command resources");
    let command = resources
        .command_queue
        .recv()
        .expect("accepted TCP IPv4 command");
    match command {
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawSend {
                command:
                    crate::net::runtime::command::RawSendCommand::Ipv4 {
                        scope,
                        dst,
                        transport: crate::net::runtime::command::RawIpv4Transport::Tcp { src },
                        payload,
                        completion_id,
                    },
                ..
            },
        ) => {
            assert_eq!(
                scope,
                crate::net::types::InterfaceScope::Pinned(crate::net::runtime::manager::NetIfId(1),)
            );
            assert_eq!(src, [127, 0, 0, 1]);
            assert_eq!(dst, [127, 0, 0, 1]);
            assert_eq!(payload.total_len(), 20);
            assert_eq!(payload.segments()[0].data().as_ptr(), backing);
            assert_eq!(completion_id, None);
        }
        _ => panic!("TCP IPv4 queue contains the wrong owned command"),
    }
    assert!(resources.command_queue.recv().is_none());
    true
}

pub fn tcp_segment_ipv6_queue_admission_smoke() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
    let local = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 12347);
    let remote = EndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
    let segment = build_test_segment(TcpSegmentBuilder::new(local.port(), remote.port()).syn());

    let backing = segment.segments()[0].data().as_ptr();
    assert!(send_test_segment(runtime, local, remote, segment));
    let current = crate::cpu::CurrentCpu::acquire().expect("TCP IPv6 admission CPU");
    let resources =
        crate::net::runtime::command::command_resources_for_cpu_in(runtime, current.id())
            .expect("TCP IPv6 command resources");
    let command = resources
        .command_queue
        .recv()
        .expect("accepted TCP IPv6 command");
    match command {
        crate::net::runtime::command::RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::RawSend {
                command:
                    crate::net::runtime::command::RawSendCommand::Ipv6 {
                        scope,
                        dst,
                        transport: crate::net::runtime::command::RawIpv6Transport::Tcp { src },
                        payload,
                        completion_id,
                    },
                ..
            },
        ) => {
            assert_eq!(
                scope,
                crate::net::types::InterfaceScope::Pinned(crate::net::runtime::manager::NetIfId(1),)
            );
            assert_eq!(src, crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets());
            assert_eq!(dst, crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets());
            assert_eq!(payload.total_len(), 20);
            assert_eq!(payload.segments()[0].data().as_ptr(), backing);
            assert_eq!(completion_id, None);
        }
        _ => panic!("TCP IPv6 queue contains the wrong owned command"),
    }
    assert!(resources.command_queue.recv().is_none());
    true
}
