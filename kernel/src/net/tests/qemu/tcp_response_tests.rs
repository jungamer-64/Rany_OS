// ============================================================================
// kernel/src/net/tests/qemu/tcp_response_tests.rs - TCP control response admission
// ============================================================================

use crate::net::l4::tcp::segment::TcpSegmentBuilder;
use crate::net::l4::tcp::tcb::tcp_flags;
use crate::net::l4::tcp::tcp_rx::process_tcp_segment_payload_on;
use crate::net::l4::types::EndpointAddr;
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    RawIpv4Transport, RawSendCommand, RuntimeCommand, TransportCommand,
    command_resources_for_cpu_in,
};
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;

fn closed_port_response(runtime: NetRuntimeHandle, ack: u32) -> bool {
    let current = crate::cpu::CurrentCpu::acquire().expect("TCP response CPU");
    let resources = command_resources_for_cpu_in(runtime, current.id()).expect("response queue");
    let local = EndpointAddr::new([127, 0, 0, 1], 58_000);
    let remote = EndpointAddr::new([127, 0, 0, 2], 58_001);
    let if_id = NetIfId(65_021);
    let incoming = TcpSegmentBuilder::new(remote.port(), local.port())
        .seq(123)
        .ack(ack)
        .ack_flag()
        .build_checked_packet(remote, local)
        .expect("incoming TCP ACK");
    process_tcp_segment_payload_on(runtime, if_id, [127, 0, 0, 2], [127, 0, 0, 1], incoming);
    let Some(command) = resources.command_queue.recv() else {
        return false;
    };
    match command {
        RuntimeCommand::Transport(TransportCommand::RawSend {
            command:
                RawSendCommand::Ipv4 {
                    scope,
                    dst,
                    transport: RawIpv4Transport::Tcp { src },
                    payload,
                    ..
                },
            ..
        }) => {
            assert_eq!(scope, crate::net::types::InterfaceScope::Pinned(if_id));
            assert_eq!(src, [127, 0, 0, 1]);
            assert_eq!(dst, [127, 0, 0, 2]);
            let view = PacketPayloadView::new(&payload);
            assert_eq!(view.total_len(), 20);
            assert_eq!(view.read_array::<2>(0), Some(local.port().to_be_bytes()));
            assert_eq!(view.read_array::<2>(2), Some(remote.port().to_be_bytes()));
            assert_eq!(view.read_array::<4>(4), Some(ack.to_be_bytes()));
            assert_eq!(view.read_array::<1>(13), Some([tcp_flags::RST]));
        }
        _ => panic!("closed TCP port must publish one stateless RST"),
    }
    assert!(resources.command_queue.recv().is_none());
    true
}

pub async fn tcp_stateless_reset_budget_uses_system_uptime_smoke() -> bool {
    let first = crate::net::runtime::create_runtime().expect("first response runtime");
    let second = crate::net::runtime::create_runtime().expect("second response runtime");
    crate::task::sleep_ms(1100)
        .await
        .expect("response window elapsed");
    assert_eq!(tcp_table_in(first).get_current_tick(), 0);
    assert_eq!(tcp_table_in(second).get_current_tick(), 0);
    for ack in 0..10 {
        let runtime = if ack % 2 == 0 { first } else { second };
        assert!(closed_port_response(runtime, ack));
    }
    assert!(!closed_port_response(first, 10));
    assert!(!closed_port_response(second, 11));

    crate::task::sleep_ms(1100)
        .await
        .expect("response budget renewed");
    assert_eq!(tcp_table_in(first).get_current_tick(), 0);
    assert_eq!(tcp_table_in(second).get_current_tick(), 0);
    assert!(closed_port_response(second, 12));
    true
}
