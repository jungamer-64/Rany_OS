// ============================================================================
// kernel/src/net/tests/qemu/tcp_retransmit_tests.rs - Retained TCP retransmission owners
// ============================================================================

use crate::net::l4::tcp::retransmit::{
    get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_push,
    retransmit_queue_remove, retransmit_queue_transmit_ready,
};
use crate::net::l4::tcp::segment::TcpSegmentBuilder;
use crate::net::l4::types::EndpointAddr;
use crate::net::runtime::command::{
    ControlCommand, RawIpv4Transport, RawSendCommand, RuntimeCommand, RuntimeCommandQueue,
    TransportCommand, command_resources_for_cpu_in, try_enqueue_command_in,
};
use crate::net::runtime::device::TxBody;
use crate::net::runtime::manager::NetIfId;

fn take_sent_segment(queue: &RuntimeCommandQueue) -> TxBody {
    match queue.recv().expect("accepted TCP request") {
        RuntimeCommand::Transport(TransportCommand::RawSend {
            command:
                RawSendCommand::Ipv4 {
                    transport: RawIpv4Transport::Tcp { segment, .. },
                    ..
                },
            ..
        }) => segment,
        _ => panic!("queued TCP transmission must carry its segment"),
    }
}

/// A rejected transmission leaves the queued segment ready; every accepted
/// transmission sends a retained copy of the same backing.
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
    let first = take_sent_segment(&resources.command_queue);
    assert!(matches!(first, TxBody::Retained(_)));
    assert_eq!(first.payload().segments()[0].data().as_ptr(), backing);

    // The queue still owns the segment while the first copy is outstanding.
    assert!(retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 100
    ));
    let second = take_sent_segment(&resources.command_queue);
    assert_eq!(second.payload().segments()[0].data().as_ptr(), backing);
    assert!(resources.command_queue.recv().is_none());

    retransmit_queue_ack(runtime, if_id, local, remote, 101);
    assert!(!retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 100
    ));
    drop((first, second));
    retransmit_queue_remove(runtime, if_id, local, remote);
    true
}

/// An ACK releases the queue's owner at once; copies that are still waiting
/// for the device keep the bytes readable until they are released.
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
    let copy = take_sent_segment(&resources.command_queue);
    retransmit_queue_ack(runtime, if_id, local, remote, 201);
    assert!(!retransmit_queue_transmit_ready(
        runtime, if_id, local, remote, 200
    ));
    assert!(resources.command_queue.recv().is_none());
    assert_eq!(copy.payload().segments()[0].data().as_ptr(), backing);
    assert_eq!(copy.total_len(), 20);
    drop(copy);
    retransmit_queue_remove(runtime, if_id, local, remote);
    true
}
