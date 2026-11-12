// ============================================================================
// kernel/src/net/tests/qemu/tcp_close_tests.rs - TCP connection release
// ============================================================================

use crate::net::l4::socket::{Socket, TcpSocketState, lookup_socket_in};
use crate::net::l4::tcp::TcpConnection;
use crate::net::l4::tcp::retransmit::{complete_tx_owner, get_or_create_retransmit_queue};
use crate::net::l4::tcp::segment::TcpSegmentBuilder;
use crate::net::l4::tcp::tcb::{TcpConnectionState, TcpControlBlock, tcp_flags};
use crate::net::l4::tcp::tcp_rx::process_tcp_segment_payload_on;
use crate::net::l4::types::EndpointAddr;
use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    RawSendCommand, RuntimeCommand, TransportCommand, command_resources_for_cpu_in,
};
use crate::net::runtime::context::NetCpuResources;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};
use kernel_api::service::netdev::TxDeviceOutcome;

const IF_ID: NetIfId = NetIfId(65_030);
const LOCAL_IP: [u8; 4] = [127, 0, 0, 1];
const REMOTE_IP: [u8; 4] = [127, 0, 0, 2];
const LOCAL_ISN: u32 = 1000;
const PEER_ISN: u32 = 5000;

struct Fixture {
    runtime: NetRuntimeHandle,
    resources: Arc<NetCpuResources>,
    socket: Socket,
    local: EndpointAddr,
    remote: EndpointAddr,
}

struct SentSegment {
    completion_id: Option<u64>,
    payload: PacketPayload,
}

impl SentSegment {
    fn seq(&self) -> u32 {
        u32::from_be_bytes(
            PacketPayloadView::new(&self.payload)
                .read_array::<4>(4)
                .expect("TCP sequence number"),
        )
    }

    fn flags(&self) -> u8 {
        PacketPayloadView::new(&self.payload)
            .read_array::<1>(13)
            .expect("TCP flags")[0]
    }

    fn data_len(&self) -> usize {
        self.payload.total_len() - 20
    }
}

impl Fixture {
    /// An ESTABLISHED connection whose socket is held by its application
    /// handle. The fixture assembles the transmit state an established
    /// connection owns.
    fn established(local_port: u16) -> Self {
        let runtime = crate::net::runtime::create_runtime().expect("close runtime");
        let current = crate::cpu::CurrentCpu::acquire().expect("close CPU");
        let resources =
            command_resources_for_cpu_in(runtime, current.id()).expect("command resources");
        let local = EndpointAddr::new(LOCAL_IP, local_port);
        let remote = EndpointAddr::new(REMOTE_IP, 58_200);
        let socket = Socket::new_registered_tcp_in(runtime, TcpSocketState::Connected);
        socket
            .with_inner_mut(|inner| {
                inner.local_addr = Some(local);
                inner.remote_addr = Some(remote);
                inner.scope = crate::net::types::InterfaceScope::Pinned(IF_ID);
            })
            .expect("registered connection socket");
        let table = tcp_table_in(runtime);
        table
            .insert(TcpControlBlock::start_connect(
                socket.socket_id(),
                local,
                remote,
                LOCAL_ISN,
                true,
                IF_ID,
            ))
            .expect("connection TCB");
        assert!(table.mark_syn_sent(IF_ID, local, remote));
        assert!(get_or_create_retransmit_queue(
            runtime, IF_ID, local, remote
        ));
        let fixture = Self {
            runtime,
            resources,
            socket,
            local,
            remote,
        };
        let syn_ack = TcpSegmentBuilder::new(remote.port(), local.port())
            .seq(PEER_ISN)
            .ack(LOCAL_ISN + 1)
            .syn()
            .ack_flag()
            .window(65535)
            .build_checked_packet(remote, local)
            .expect("SYN-ACK");
        process_tcp_segment_payload_on(runtime, IF_ID, REMOTE_IP, LOCAL_IP, syn_ack);
        assert_eq!(fixture.tcb_state(), Some(TcpConnectionState::Established));
        assert_eq!(fixture.take_segments().len(), 1);
        fixture
    }

    fn take_segments(&self) -> Vec<SentSegment> {
        let mut segments = Vec::new();
        // LOOP_PROOF: mode=condition; reason=The fixture is the sole consumer of the fresh runtime queue and no producer remains, so each receive removes one queued request until empty.;
        while let Some(command) = self.resources.command_queue.recv() {
            match command {
                RuntimeCommand::Transport(TransportCommand::RawSend {
                    command:
                        RawSendCommand::Ipv4 {
                            payload,
                            completion_id,
                            ..
                        },
                    ..
                }) => segments.push(SentSegment {
                    completion_id,
                    payload,
                }),
                _ => panic!("the connection may only publish TCP segments here"),
            }
        }
        segments
    }

    fn peer_segment(&self, seq: u32, ack: u32, fin: bool) {
        let mut builder = TcpSegmentBuilder::new(self.remote.port(), self.local.port())
            .seq(seq)
            .ack(ack)
            .ack_flag()
            .window(65535);
        if fin {
            builder = builder.fin();
        }
        let segment = builder
            .build_checked_packet(self.remote, self.local)
            .expect("peer TCP segment");
        process_tcp_segment_payload_on(self.runtime, IF_ID, REMOTE_IP, LOCAL_IP, segment);
    }

    fn tcb_state(&self) -> Option<TcpConnectionState> {
        tcp_table_in(self.runtime).read(IF_ID, self.local, self.remote, |tcb| tcb.state())
    }

    fn socket_registered(&self) -> bool {
        lookup_socket_in(self.runtime, self.socket.socket_id()).is_some()
    }
}

fn data_payload(data: &[u8]) -> PacketPayload {
    let mut writer =
        GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM).expect("data allocation");
    writer.write_generated_bytes(data).expect("data write");
    writer.finish().expect("exact data payload")
}

/// Passive close: releasing the handle through `close` in CLOSE-WAIT leaves
/// the socket to the runtime, which sends the queued data and then the FIN.
/// The peer's ACK of the FIN ends the TCB and unregisters the socket.
pub fn tcp_close_hands_connection_to_runtime_until_fin_ack_smoke() -> bool {
    let fixture = Fixture::established(58_100);
    fixture.peer_segment(PEER_ISN + 1, LOCAL_ISN + 1, true);
    assert_eq!(fixture.tcb_state(), Some(TcpConnectionState::CloseWait));
    let fin_ack = fixture.take_segments();
    assert_eq!(fin_ack.len(), 1);
    assert_eq!(fin_ack[0].flags(), tcp_flags::ACK);

    fixture
        .socket
        .with_inner_mut(|inner| inner.send_payload(data_payload(b"data")))
        .expect("registered connection socket")
        .unwrap_or_else(|_| panic!("send buffer admits the payload"));
    TcpConnection::from_socket(fixture.socket).close();
    assert!(fixture.socket_registered());
    assert_eq!(fixture.tcb_state(), Some(TcpConnectionState::CloseWait));

    let close = fixture
        .resources
        .command_queue
        .recv()
        .expect("close request reaches the runtime");
    assert!(matches!(
        close,
        RuntimeCommand::Transport(TransportCommand::CloseSocket { socket_id })
            if socket_id == fixture.socket.socket_id()
    ));
    let _ = crate::net::runtime::command_handler::drive_command_in(fixture.runtime, close);

    let sent = fixture.take_segments();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].seq(), LOCAL_ISN + 1);
    assert_eq!(sent[0].data_len(), 4);
    assert_eq!(sent[0].flags() & tcp_flags::FIN, 0);
    assert_eq!(sent[1].seq(), LOCAL_ISN + 5);
    assert_eq!(sent[1].data_len(), 0);
    assert_eq!(sent[1].flags(), tcp_flags::FIN | tcp_flags::ACK);
    assert_eq!(fixture.tcb_state(), Some(TcpConnectionState::LastAck));
    assert!(fixture.socket_registered());
    for segment in sent {
        assert!(complete_tx_owner(
            fixture.runtime,
            segment.completion_id.expect("retransmittable segment"),
            segment.payload,
            TxDeviceOutcome::Transmitted,
        ));
    }

    fixture.peer_segment(PEER_ISN + 2, LOCAL_ISN + 6, false);
    assert_eq!(fixture.tcb_state(), None);
    assert!(!fixture.socket_registered());
    assert!(fixture.take_segments().is_empty());
    true
}

/// Dropping a handle without `close` aborts the connection: the peer is reset
/// at SND.NXT and the TCB and socket are released together.
pub fn tcp_drop_without_close_resets_connection_smoke() -> bool {
    let fixture = Fixture::established(58_101);
    drop(TcpConnection::from_socket(fixture.socket));
    assert_eq!(fixture.tcb_state(), None);
    assert!(!fixture.socket_registered());
    let sent = fixture.take_segments();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].seq(), LOCAL_ISN + 1);
    assert_eq!(sent[0].flags(), tcp_flags::RST);
    assert_eq!(sent[0].completion_id, None);
    true
}
