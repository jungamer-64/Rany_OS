// ============================================================================
// kernel/src/net/tests/qemu/tcp_close_tests.rs - TCP connection release
// ============================================================================

use crate::net::l4::socket::{Socket, TcpSocketState, lookup_socket_in};
use crate::net::l4::tcp::TcpConnection;
use crate::net::l4::tcp::segment::TcpSegmentBuilder;
use crate::net::l4::tcp::tcb::{TcpConnectionState, TcpControlBlock, tcp_flags};
use crate::net::l4::tcp::tcp_rx::process_tcp_segment_payload_on;
use crate::net::l4::types::EndpointAddr;
use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    RawIpv4Transport, RawSendCommand, RuntimeCommand, TransportCommand,
    command_resources_for_cpu_in,
};
use crate::net::runtime::context::NetCpuResources;
use crate::net::runtime::device::TxBody;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

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
    payload: TxBody,
}

impl SentSegment {
    fn seq(&self) -> u32 {
        u32::from_be_bytes(
            PacketPayloadView::new(self.payload.payload())
                .read_array::<4>(4)
                .expect("TCP sequence number"),
        )
    }

    fn flags(&self) -> u8 {
        PacketPayloadView::new(self.payload.payload())
            .read_array::<1>(13)
            .expect("TCP flags")[0]
    }

    fn data_len(&self) -> usize {
        self.payload.total_len() - 20
    }

    /// Retransmittable segments stay queued and are sent as retained copies.
    fn retransmittable(&self) -> bool {
        matches!(self.payload, TxBody::Retained(_))
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
        let socket = Socket::new_registered_tcp_in(runtime, TcpSocketState::Connecting);
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
                            transport: RawIpv4Transport::Tcp { segment, .. },
                            ..
                        },
                    ..
                }) => segments.push(SentSegment { payload: segment }),
                _ => panic!("the connection may only publish TCP segments here"),
            }
        }
        segments
    }

    fn peer_segment(&self, seq: u32, ack: u32, fin: bool, payload: Option<PacketPayload>) {
        let mut builder = TcpSegmentBuilder::new(self.remote.port(), self.local.port())
            .seq(seq)
            .ack(ack)
            .ack_flag()
            .window(65535);
        if fin {
            builder = builder.fin();
        }
        if let Some(payload) = payload {
            builder = builder.payload_packet(payload);
        }
        let segment = builder
            .build_checked_packet(self.remote, self.local)
            .expect("peer TCP segment");
        process_tcp_segment_payload_on(self.runtime, IF_ID, REMOTE_IP, LOCAL_IP, segment);
    }

    fn tcb_state(&self) -> Option<TcpConnectionState> {
        tcp_table_in(self.runtime).read(IF_ID, self.local, self.remote, |tcb| tcb.state())
    }

    fn peer_window_ack(&self, ack: u32, window: u16) {
        let segment = TcpSegmentBuilder::new(self.remote.port(), self.local.port())
            .seq(PEER_ISN + 1)
            .ack(ack)
            .ack_flag()
            .window(window)
            .build_checked_packet(self.remote, self.local)
            .expect("peer window ACK");
        process_tcp_segment_payload_on(self.runtime, IF_ID, REMOTE_IP, LOCAL_IP, segment);
    }

    fn drive_data_ready(&self) {
        let command = self
            .resources
            .command_queue
            .recv()
            .expect("pending send command");
        assert!(
            matches!(command, RuntimeCommand::Transport(TransportCommand::TcpDataReady { socket_id }) if socket_id == self.socket.socket_id())
        );
        let _ = crate::net::runtime::command_handler::drive_command_in(self.runtime, command);
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
    fixture.peer_segment(
        PEER_ISN + 1,
        LOCAL_ISN + 1,
        true,
        Some(data_payload(b"last")),
    );
    let connection = TcpConnection::from_socket(fixture.socket);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    let core::task::Poll::Ready(Ok(Some(last))) = connection.poll_recv_payload(&mut cx) else {
        panic!("data preceding EOF must remain readable");
    };
    assert_eq!(
        PacketPayloadView::new(&last).read_array::<4>(0),
        Some(*b"last")
    );
    assert!(matches!(
        connection.poll_recv_payload(&mut cx),
        core::task::Poll::Ready(Ok(None))
    ));
    assert_eq!(fixture.tcb_state(), Some(TcpConnectionState::CloseWait));
    let fin_ack = fixture.take_segments();
    assert_eq!(fin_ack.len(), 1);
    assert_eq!(fin_ack[0].flags(), tcp_flags::ACK);

    fixture
        .socket
        .with_inner_mut(|inner| inner.send_payload(data_payload(b"data")))
        .expect("registered connection socket")
        .unwrap_or_else(|_| panic!("send buffer admits the payload"));
    connection.close();
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
    assert!(sent.iter().all(SentSegment::retransmittable));
    drop(sent);

    fixture.peer_segment(PEER_ISN + 6, LOCAL_ISN + 6, false, None);
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
    assert!(!sent[0].retransmittable());
    true
}

/// A full peer window does not prevent local admission. A persist probe and
/// the reopening ACK drive all queued bytes without another application send.
pub fn tcp_zero_window_send_and_resume_smoke() -> bool {
    use core::future::Future;
    use core::sync::atomic::Ordering;
    use core::task::{Context, Poll, Waker};

    let fixture = Fixture::established(58_102);
    fixture.peer_window_ack(LOCAL_ISN + 1, 0);
    let mut connection = TcpConnection::from_socket(fixture.socket);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut send = core::pin::pin!(connection.send_payload(data_payload(b"data")));
        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }
    fixture.drive_data_ready();
    assert!(fixture.take_segments().is_empty());

    let table = tcp_table_in(fixture.runtime);
    table.current_tick.store(500, Ordering::Relaxed);
    table.tick(fixture.runtime);
    fixture.drive_data_ready();
    let probe = fixture.take_segments();
    assert_eq!(probe.len(), 1);
    assert_eq!(probe[0].seq(), LOCAL_ISN + 1);
    assert_eq!(probe[0].data_len(), 1);
    assert!(probe[0].retransmittable());
    assert_eq!(
        PacketPayloadView::new(probe[0].payload.payload()).read_array::<1>(20),
        Some(*b"d")
    );
    drop(probe);

    fixture.peer_window_ack(LOCAL_ISN + 2, 65535);
    fixture.drive_data_ready();
    let sent = fixture.take_segments();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].seq(), LOCAL_ISN + 2);
    assert_eq!(sent[0].data_len(), 3);
    assert!(sent[0].retransmittable());
    assert_eq!(
        PacketPayloadView::new(sent[0].payload.payload()).read_array::<3>(20),
        Some(*b"ata")
    );
    drop(connection);
    true
}
