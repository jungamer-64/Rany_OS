// ============================================================================
// kernel/src/net/tests/qemu/tcp_retransmit_tests.rs - Queued TCP ownership returns
// ============================================================================

use crate::net::l4::tcp::retransmit::{
    complete_tx_owner, get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_push,
    retransmit_queue_remove, retransmit_queue_transmit_ready,
};
use crate::net::l4::tcp::segment::TcpSegmentBuilder;
use crate::net::l4::types::EndpointAddr;
use crate::net::runtime::command::{
    ControlCommand, RawSendCommand, RuntimeCommand, RuntimeCommandQueue, TransportCommand,
    command_resources_for_cpu_in, try_enqueue_command_in,
};
use crate::net::runtime::manager::NetIfId;
use kernel_api::resource::net::PacketPayload;
use kernel_api::service::netdev::TxDeviceOutcome;

fn take_owned_tcp_packet(queue: &RuntimeCommandQueue) -> (u64, PacketPayload) {
    match queue.recv().expect("accepted TCP request") {
        RuntimeCommand::Transport(TransportCommand::RawSend {
            command:
                RawSendCommand::Ipv4 {
                    payload,
                    completion_id: Some(id),
                    ..
                },
            ..
        }) => (id, payload),
        _ => panic!("tracked TCP command must retain its payload and completion identity"),
    }
}

pub fn tcp_retransmit_queue_rejection_and_return_smoke() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("retransmit runtime");
    let current = crate::cpu::CurrentCpu::acquire().expect("retransmit CPU");
    let resources = command_resources_for_cpu_in(runtime, current.id()).expect("command resources");
    let if_id = NetIfId(65_011);
    let local = EndpointAddr::new([127, 0, 0, 1], 55_011);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    assert!(get_or_create_retransmit_queue(
        runtime, if_id, local, remote
    ));
    let payload = TcpSegmentBuilder::new(local.port(), remote.port())
        .seq(100)
        .syn()
        .build_checked_packet(local, remote)
        .expect("retransmit packet");
    let backing = payload.segments()[0].data().as_ptr();
    retransmit_queue_push(runtime, if_id, local, remote, 100, 1, payload);

    // LOOP_PROOF: mode=event; reason=This fresh runtime has no consumer, so each accepted request occupies a bounded slot until rejection takes the explicit break.;
    loop {
        if try_enqueue_command_in(
            runtime,
            RuntimeCommand::Control(ControlCommand::ProcessLocalTimeouts),
        )
        .is_err()
        {
            break;
        }
    }
    assert!(!retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 100
    ));
    // LOOP_PROOF: mode=condition; reason=The fixture is the sole consumer and no producer remains, so each receive removes one queued request until empty.;
    while resources.command_queue.recv().is_some() {}
    assert!(retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 100
    ));
    let (first_id, payload) = take_owned_tcp_packet(&resources.command_queue);
    assert_eq!(payload.segments()[0].data().as_ptr(), backing);
    assert!(!retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 100
    ));
    assert!(resources.command_queue.recv().is_none());
    assert!(complete_tx_owner(
        runtime,
        first_id,
        payload,
        TxDeviceOutcome::OutcomeUnknown
    ));

    assert!(retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 100
    ));
    let (second_id, payload) = take_owned_tcp_packet(&resources.command_queue);
    assert_ne!(first_id, second_id);
    assert_eq!(payload.segments()[0].data().as_ptr(), backing);
    retransmit_queue_ack(runtime, if_id, local, remote, 101);
    assert!(complete_tx_owner(
        runtime,
        second_id,
        payload,
        TxDeviceOutcome::Transmitted
    ));
    assert!(get_or_create_retransmit_queue(
        runtime, if_id, local, remote
    ));
    retransmit_queue_remove(runtime, if_id, local, remote);
    true
}

pub fn tcp_retransmit_ack_before_completion_smoke() -> bool {
    let runtime = crate::net::runtime::create_runtime().expect("ACK runtime");
    let current = crate::cpu::CurrentCpu::acquire().expect("ACK CPU");
    let resources = command_resources_for_cpu_in(runtime, current.id()).expect("command resources");
    let if_id = NetIfId(65_012);
    let local = EndpointAddr::new([127, 0, 0, 1], 55_012);
    let remote = EndpointAddr::new([127, 0, 0, 1], 80);
    assert!(get_or_create_retransmit_queue(
        runtime, if_id, local, remote
    ));
    let payload = TcpSegmentBuilder::new(local.port(), remote.port())
        .seq(200)
        .syn()
        .build_checked_packet(local, remote)
        .expect("ACK packet");
    let backing = payload.segments()[0].data().as_ptr();
    retransmit_queue_push(runtime, if_id, local, remote, 200, 1, payload);
    assert!(retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 200
    ));
    let (id, payload) = take_owned_tcp_packet(&resources.command_queue);
    retransmit_queue_ack(runtime, if_id, local, remote, 201);
    assert!(!retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 200
    ));
    assert!(resources.command_queue.recv().is_none());
    assert_eq!(payload.segments()[0].data().as_ptr(), backing);
    assert_eq!(payload.total_len(), 20);
    assert!(complete_tx_owner(
        runtime,
        id,
        payload,
        TxDeviceOutcome::Transmitted
    ));
    assert!(get_or_create_retransmit_queue(
        runtime, if_id, local, remote
    ));
    retransmit_queue_remove(runtime, if_id, local, remote);
    true
}
