// ============================================================================
// kernel/src/net/l4/tcp/tcp_rx.rs - TCP受信処理 - 3ウェイハンドシェイク・データ受信
// ============================================================================
//! # TCP受信処理 - 3ウェイハンドシェイク・データ受信
//!
//! process_tcp_segment_payload_on
//!
//! ## 最適化
//! - **TCP Fast Path**: ESTABLISHED状態で期待通りのseq/ackを受信した場合、
//!   フルプロトコル処理をバイパスして高速にデータを受信バッファに投入する。
//! - **Delayed ACK**: RFC 1122/5681準拠。連続データ受信時にACKを遅延させ、
//!   2セグメントごとまたは最大200msでACKを送信してACKトラフィックを半減させる。

// Building block: TCP RX processing helpers

use core::sync::atomic::{AtomicU64, Ordering};

use super::congestion::CongestionAction;
use super::ooo_queue;
use super::retransmit::{
    get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_fast_retransmit,
};
use super::segment::{TcpSegmentBuilder, send_tcp_segment_payload_in};
use super::tcb::{
    AckSegment, TcpConnectionState, TcpControlBlock, TcpControlBlockSnapshot, TcpHandshakeOptions,
    tcp_flags,
};
use super::termination::{TcpTermination, abort_connection_in, terminate_connection_in};
use super::window_scale::TcpOptionParser;
use crate::net::l4::socket::{
    Socket, find_listening_tcp_socket_in, generate_socket_id_in, lookup_socket_in,
};
use crate::net::l4::types::{
    AcceptedConnection, EndpointAddr, EndpointError, SocketId, seq_after, seq_before, seq_leq,
};
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::device::TxBody;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;
use crate::sync::PoisonLock;
use kernel_api::resource::net::PacketPayload;

// ============================================================================
// TCP Fast Path Statistics
// ============================================================================

/// ファストパスで処理されたパケット数
static FAST_PATH_HITS: AtomicU64 = AtomicU64::new(0);
/// スローパスにフォールバックしたパケット数
static SLOW_PATH_HITS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Delayed ACK
// ============================================================================

/// Delayed ACK の最大遅延時間 (ミリ秒, RFC 1122: 最大500ms, 推奨200ms)
const DELAYED_ACK_TIMEOUT_MS: u64 = 200;

/// Delayed ACK が溜まる最大セグメント数 (RFC 5681: 2セグメントごとにACK)
const DELAYED_ACK_SEGMENTS: u8 = 2;

/// RFC 7323準拠のTCPタイムスタンプ生成
pub(crate) fn generate_tcp_timestamp_in(runtime: NetRuntimeHandle) -> u32 {
    let ms = tcp_table_in(runtime).get_current_tick();
    (ms / 10) as u32
}

// seq_before は types モジュールの統一実装を使用

/// RFC 793 Step 1: 受信セグメントのシーケンス番号妥当性を検証
///
/// SEG.LEN は SYN および FIN ビットを含むシーケンス空間の長さを指定する必要がある。
fn is_acceptable_sequence(tcb: &TcpControlBlockSnapshot, seq_num: u32, seg_len: usize) -> bool {
    let rcv_nxt = tcb.rcv_nxt;
    let rcv_wnd = tcb.effective_recv_window();

    if seg_len == 0 {
        if rcv_wnd == 0 {
            seq_num == rcv_nxt
        } else {
            // rcv_nxt <= seq_num < rcv_nxt + rcv_wnd
            let diff = seq_num.wrapping_sub(rcv_nxt);
            diff < rcv_wnd
        }
    } else {
        if rcv_wnd == 0 {
            // RFC 1122 Section 4.2.2.17: "The receiver MUST accept a zero-window
            // probe containing a single octet of new data."
            // "a TCP SHOULD accept and process at least the first octet of a zero-window probe"
            seq_num == rcv_nxt
        } else {
            // rcv_nxt <= seq_num < rcv_nxt + rcv_wnd OR
            // rcv_nxt <= seq_num + seg_len - 1 < rcv_nxt + rcv_wnd
            let diff_start = seq_num.wrapping_sub(rcv_nxt);
            let diff_end = seq_num
                .wrapping_add(seg_len as u32)
                .wrapping_sub(1)
                .wrapping_sub(rcv_nxt);
            diff_start < rcv_wnd || diff_end < rcv_wnd
        }
    }
}

/// RFC 7323 timestamp admission (Section 3.2 and PAWS, Section 5.3 R1).
enum TimestampAdmission {
    /// The segment may be processed; carries the peer TSval when present.
    Admit(Option<u32>),
    /// TSval is older than TS.Recent: drop and acknowledge.
    PawsRejected,
    /// A timestamp-enabled connection received a non-RST segment without
    /// TSopt: drop silently.
    MissingTimestamp,
}

fn admit_timestamp(tcb: &TcpControlBlockSnapshot, flags: u8, options: &[u8]) -> TimestampAdmission {
    if !tcb.ts_enabled || (flags & tcp_flags::RST) != 0 {
        return TimestampAdmission::Admit(None);
    }
    let timestamps = if options.is_empty() {
        None
    } else {
        TcpOptionParser::new(options).find_timestamps()
    };
    match timestamps {
        Some((peer_ts_val, _)) if seq_before(peer_ts_val, tcb.ts_ecr) => {
            TimestampAdmission::PawsRejected
        }
        Some((peer_ts_val, _)) => TimestampAdmission::Admit(Some(peer_ts_val)),
        None if tcb.state == TcpConnectionState::SynSent => TimestampAdmission::Admit(None),
        None => TimestampAdmission::MissingTimestamp,
    }
}

/// Apply an ACK that passed RFC 5961 validation: congestion state, the
/// guarded window update, close-state progress, and retransmit queue release.
fn apply_acceptable_ack(
    runtime: NetRuntimeHandle,
    tcb: &TcpControlBlockSnapshot,
    segment: AckSegment,
) {
    let current_time_ms = tcp_table_in(runtime).get_current_tick();
    let (should_remove, action) = tcp_table_in(runtime)
        .record_ack_and_close_progress(tcb.if_id, tcb.local, tcb.remote, segment, current_time_ms)
        .unwrap_or((false, CongestionAction::None));

    // RFC 6582 Section 3.2: release the cumulatively acknowledged prefix
    // before retransmitting the oldest unacknowledged segment.
    retransmit_queue_ack(runtime, tcb.if_id, tcb.local, tcb.remote, segment.ack);
    if action == CongestionAction::FastRetransmit {
        retransmit_queue_fast_retransmit(runtime, tcb.if_id, tcb.local, tcb.remote);
    }
    if should_remove {
        terminate_connection_in(
            runtime,
            tcb.if_id,
            tcb.local,
            tcb.remote,
            TcpTermination::Completed,
        );
        return;
    }
    resume_closing_transmission(runtime, tcb.socket_id);
}

/// A closing socket no longer has an application writer to drive the send
/// path, so window progress from an ACK resumes it until the queued data and
/// the deferred FIN are out. A full command queue leaves the retry to the next
/// ACK, which retransmission and zero-window probing keep producing.
fn resume_closing_transmission(runtime: NetRuntimeHandle, socket_id: SocketId) {
    let pending = lookup_socket_in(runtime, socket_id)
        .and_then(|socket| {
            socket.with_inner(|inner| inner.is_tcp_closing_or_closed() && inner.has_send_data())
        })
        .unwrap_or(false);
    if pending
        && crate::net::runtime::command::try_enqueue_command_in(
            runtime,
            crate::net::runtime::command::RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDataReady { socket_id },
            ),
        )
        .is_err()
    {
        log::debug!("[TCP] closing transmission resume deferred to the next ACK");
    }
}

const RESPONSE_WINDOW_MS: u64 = 1000;
static CHALLENGE_ACK_BUDGET: ResponseBudget = ResponseBudget::new(100);
static CLOSED_PORT_RST_BUDGET: ResponseBudget = ResponseBudget::new(10);

struct ResponseWindow {
    started_ms: u64,
    reserved: u32,
}

impl ResponseWindow {
    const fn new() -> Self {
        Self {
            started_ms: 0,
            reserved: 0,
        }
    }

    fn try_reserve(&mut self, now_ms: u64, limit: u32) -> bool {
        if now_ms.saturating_sub(self.started_ms) >= RESPONSE_WINDOW_MS {
            self.started_ms = now_ms;
            self.reserved = 0;
        }
        if self.reserved >= limit {
            return false;
        }
        self.reserved += 1;
        true
    }
}

/// Kernel-wide control response admission uses the system uptime, independently
/// of each runtime's transport ticks. Window renewal and reservation share one
/// critical section. Rejected requests never increment a wrapping counter, and
/// poisoning denies admission. A reservation remains charged if packet creation
/// or submission subsequently fails, bounding attempted control responses too.
struct ResponseBudget {
    window: PoisonLock<ResponseWindow>,
    limit: u32,
}

impl ResponseBudget {
    const fn new(limit: u32) -> Self {
        Self {
            window: PoisonLock::new(ResponseWindow::new()),
            limit,
        }
    }

    fn try_reserve(&self, uptime_ms: impl FnOnce() -> u64) -> bool {
        let Ok(mut window) = self.window.lock() else {
            return false;
        };
        window.try_reserve(uptime_ms(), self.limit)
    }
}

#[cfg(test)]
mod response_budget_tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn response_budget_exhaustion_and_exact_window_boundary() {
        let budget = ResponseBudget::new(10);
        for _ in 0..10 {
            assert!(budget.try_reserve(|| 0));
        }
        for _ in 0..5 {
            assert!(!budget.try_reserve(|| 999));
        }
        assert!(budget.try_reserve(|| 1000));
        for _ in 0..9 {
            assert!(budget.try_reserve(|| 1999));
        }
        assert!(!budget.try_reserve(|| 1999));
        assert!(!budget.try_reserve(|| 0));
        assert!(budget.try_reserve(|| 2000));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn response_budget_zero_limit_and_terminal_timestamp() {
        let disabled = ResponseBudget::new(0);
        assert!(!disabled.try_reserve(|| 0));
        assert!(!disabled.try_reserve(|| u64::MAX));
        let budget = ResponseBudget::new(1);
        assert!(budget.try_reserve(|| u64::MAX));
        assert!(!budget.try_reserve(|| u64::MAX));
    }

    #[cfg(any(feature = "std", target_os = "linux"))]
    #[test]
    fn concurrent_window_renewal_admits_exactly_one_budget() {
        let budget = ResponseBudget::new(10);
        for _ in 0..10 {
            assert!(budget.try_reserve(|| 0));
        }
        let barrier = std::sync::Barrier::new(4);
        let admitted = std::thread::scope(|scope| {
            let workers: [_; 4] = core::array::from_fn(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    (0..10).filter(|_| budget.try_reserve(|| 1000)).count()
                })
            });
            workers
                .into_iter()
                .map(|worker| worker.join().expect("response reservation worker"))
                .sum::<usize>()
        });
        assert_eq!(admitted, 10);
        assert!(!budget.try_reserve(|| 1000));
        assert!(budget.try_reserve(|| 2000));
    }
}

/// チャレンジACK（シーケンス番号エラー時の応答）を送信
fn send_challenge_ack(runtime: NetRuntimeHandle, tcb: &TcpControlBlockSnapshot) {
    if !CHALLENGE_ACK_BUDGET.try_reserve(crate::time::get_uptime_ms) {
        log::debug!("[TCP] Challenge ACK rate limit exceeded, dropping");
        return;
    }
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(tcb.rcv_nxt)
        .ack_flag()
        .window(tcb.advertised_recv_window());

    if tcb.ts_enabled {
        builder = builder
            .nop()
            .nop()
            .timestamp(generate_tcp_timestamp_in(runtime), tcb.ts_ecr);
    }

    let Ok(ack) = builder.build_checked_packet(tcb.local, tcb.remote) else {
        return;
    };
    // Challenge ACKs are best effort; rejection returns the unsubmitted packet.
    if let Err((cause, _returned)) = send_tcp_segment_payload_in(
        runtime,
        tcb.if_id,
        tcb.local,
        tcb.remote,
        TxBody::Owned(ack),
    ) {
        log::debug!("[TCP] Challenge ACK queue rejection: {:?}", cause);
    }
}

pub(super) fn send_control_segment(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    builder: TcpSegmentBuilder,
) {
    let Ok(segment) = builder.build_checked_packet(local, remote) else {
        return;
    };
    if let Err((cause, _returned)) =
        send_tcp_segment_payload_in(runtime, if_id, local, remote, TxBody::Owned(segment))
    {
        log::debug!("[TCP] Control segment queue rejection: {:?}", cause);
    }
}

/// TCPチェックサム検証（IPv4疑似ヘッダ込み）
fn payload_checksum_fold(view: &PacketPayloadView<'_>, initial: u32) -> u16 {
    let mut sum = initial;
    let mut trailing = None;

    view.for_each_chunk(|chunk| {
        let mut index = 0usize;
        if let Some(prev) = trailing.take() {
            if let Some((&first, rest)) = chunk.split_first() {
                sum += u16::from_be_bytes([prev, first]) as u32;
                index = 1;
                if rest.is_empty() {
                    return;
                }
            } else {
                trailing = Some(prev);
                return;
            }
        }

        // LOOP_PROOF: mode=bounded; reason=index advances by two through the finite TCP payload chunk and leaves at most one trailing byte.;
        while index + 1 < chunk.len() {
            sum += u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32;
            index += 2;
        }
        if index < chunk.len() {
            trailing = Some(chunk[index]);
        }
    });

    if let Some(last) = trailing {
        sum += u16::from_be_bytes([last, 0]) as u32;
    }

    // LOOP_PROOF: mode=condition; reason=Carry folding reduces the high half of this 32-bit checksum until the accumulator fits in 16 bits.;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum as u16
}

fn verify_tcp_checksum(segment: &PacketPayload, src_ip: [u8; 4], dst_ip: [u8; 4]) -> bool {
    let view = PacketPayloadView::new(segment);
    if view.total_len() < 20 {
        return false;
    }

    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // Protocol (TCP)
    sum += view.total_len() as u32;

    payload_checksum_fold(&view, sum) == 0xFFFF
}

/// TCPチェックサム検証（IPv6疑似ヘッダ込み）
fn verify_tcp_checksum_v6(
    segment: &PacketPayload,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
) -> bool {
    let view = PacketPayloadView::new(segment);
    if view.total_len() < 20 {
        return false;
    }

    use crate::net::l3::ipv4::IpProtocol;
    use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;

    let pseudo =
        ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Tcp, view.total_len() as u32);
    payload_checksum_fold(&view, pseudo) == 0xFFFF
}

#[derive(Clone, Copy)]
struct ParsedTcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    urgent_ptr: u16,
}

struct TcpOptionsScratch {
    len: usize,
    bytes: [u8; 40],
}

impl TcpOptionsScratch {
    fn parse(segment: PacketPayload) -> Option<(ParsedTcpHeader, Self, Option<PacketPayload>)> {
        let view = PacketPayloadView::new(&segment);
        let header = view.read_array::<20>(0)?;
        let data_off_flags = u16::from_be_bytes([header[12], header[13]]);
        let data_offset = ((data_off_flags >> 12) & 0x0F) as usize * 4;
        if data_offset < 20 || data_offset > view.total_len() || data_offset > 60 {
            return None;
        }

        let options_len = data_offset.saturating_sub(20);
        let mut scratch = Self {
            len: options_len,
            bytes: [0u8; 40],
        };
        if options_len > 0 {
            let options = view.read_fixed_bytes::<40>(20, options_len)?;
            scratch.bytes[..options_len].copy_from_slice(options.as_slice());
        }

        let payload_len = view.total_len().saturating_sub(data_offset);
        let payload = if payload_len == 0 {
            None
        } else {
            let bounds = crate::net::payload::OwnedPayloadBounds::checked(
                &segment,
                data_offset,
                payload_len,
            )?;
            Some(bounds.take_from(segment)?.into_payload().ok()?)
        };

        Some((
            ParsedTcpHeader {
                src_port: u16::from_be_bytes([header[0], header[1]]),
                dst_port: u16::from_be_bytes([header[2], header[3]]),
                seq_num: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                ack_num: u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
                flags: data_off_flags as u8,
                window: u16::from_be_bytes([header[14], header[15]]),
                urgent_ptr: u16::from_be_bytes([header[18], header[19]]),
            },
            scratch,
            payload,
        ))
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn process_parsed_tcp_segment(
    runtime: NetRuntimeHandle,
    local: EndpointAddr,
    remote: EndpointAddr,
    ingress_if_id: NetIfId,
    header: ParsedTcpHeader,
    options: &[u8],
    data_payload: Option<PacketPayload>,
) {
    if let Some(tcb) = tcp_table_in(runtime).read(ingress_if_id, local, remote, |entry| {
        TcpControlBlockSnapshot::from(entry)
    }) {
        let mut data_payload = data_payload;
        let payload_len = data_payload.as_ref().map_or(0, PacketPayload::total_len);

        // The fast path admits only in-order data on ESTABLISHED that passes
        // the same timestamp admission as the slow path; every other segment
        // goes through the full RFC 9293 pipeline in process_tcp_with_tcb.
        let base_flags = header.flags & !(tcp_flags::CWR | tcp_flags::ECE);
        let can_try_fast_path = tcb.state == TcpConnectionState::Established
            && header.seq_num == tcb.rcv_nxt
            && payload_len > 0
            && (base_flags == tcp_flags::ACK || base_flags == (tcp_flags::ACK | tcp_flags::PSH));
        if can_try_fast_path
            && let TimestampAdmission::Admit(peer_timestamp) =
                admit_timestamp(&tcb, header.flags, options)
        {
            let payload = data_payload
                .take()
                .expect("fast path requires a non-empty TCP payload");
            let segment = AckSegment {
                seq: header.seq_num,
                ack: header.ack_num,
                window: header.window,
                occupies_sequence_space: true,
            };
            match try_fast_path(runtime, &tcb, segment, peer_timestamp, payload) {
                Ok(()) => {
                    FAST_PATH_HITS.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(payload) => {
                    data_payload = Some(payload);
                }
            }
        }

        SLOW_PATH_HITS.fetch_add(1, Ordering::Relaxed);
        process_tcp_with_tcb(
            runtime,
            tcb,
            header.flags,
            header.seq_num,
            header.ack_num,
            header.window,
            header.urgent_ptr,
            options,
            data_payload,
        );
        return;
    }

    let is_syn = (header.flags & tcp_flags::SYN) != 0;
    let is_ack = (header.flags & tcp_flags::ACK) != 0;
    let is_rst = (header.flags & tcp_flags::RST) != 0;

    if is_syn && !is_ack && !is_rst {
        process_tcp_new_connection(
            runtime,
            local,
            remote,
            ingress_if_id,
            header.flags,
            header.seq_num,
            header.ack_num,
            header.urgent_ptr,
            options,
            data_payload,
        );
    } else if is_ack && !is_rst {
        let client_isn = header.seq_num.wrapping_sub(1);
        if let Some(mss_idx) =
            tcp_table_in(runtime).verify_syncookie(local, remote, header.ack_num, client_isn)
        {
            log::info!(
                "[TCP] SYN Cookie verified for {}, creating connection",
                remote
            );

            if let Some(socket) = find_listening_tcp_socket_in(runtime, local, ingress_if_id) {
                let mss = match mss_idx {
                    2 => 1460,
                    1 => 536,
                    _ => 64,
                };

                let tcb = TcpControlBlock::established_from_syncookie(
                    socket.socket_id(),
                    local,
                    remote,
                    AckSegment {
                        seq: header.seq_num,
                        ack: header.ack_num,
                        window: header.window,
                        occupies_sequence_space: data_payload.is_some(),
                    },
                    mss,
                    ingress_if_id,
                );

                if let Err(e) = tcp_table_in(runtime).insert(tcb) {
                    log::warn!(
                        "[TCP] Failed to insert TCB after SYN Cookie verification: {}",
                        e
                    );
                    return;
                }

                if !complete_passive_open(runtime, ingress_if_id, local, remote) {
                    return;
                }

                if let Some(data_payload) = data_payload
                    && let Some(snapshot) =
                        tcp_table_in(runtime).read(ingress_if_id, local, remote, |entry| {
                            TcpControlBlockSnapshot::from(entry)
                        })
                {
                    process_tcp_with_tcb(
                        runtime,
                        snapshot,
                        header.flags,
                        header.seq_num,
                        header.ack_num,
                        header.window,
                        header.urgent_ptr,
                        options,
                        Some(data_payload),
                    );
                }
                return;
            }
        }

        // RFC 9293 Section 3.10.7.1: If no TCB and SYN Cookie validation fails, send stateless RST
        send_stateless_rst(
            runtime,
            ingress_if_id,
            local,
            remote,
            header.flags,
            header.seq_num,
            header.ack_num,
            data_payload.as_ref().map_or(0, PacketPayload::total_len),
        );
    } else if !is_rst {
        // RFC 9293 Section 3.10.7.1: Incoming segment (e.g. FIN, DATA) on CLOSED connection
        send_stateless_rst(
            runtime,
            ingress_if_id,
            local,
            remote,
            header.flags,
            header.seq_num,
            header.ack_num,
            data_payload.as_ref().map_or(0, PacketPayload::total_len),
        );
    }
}

/// Header-prediction path for in-order data on ESTABLISHED.
///
/// Rejection returns the untouched payload and leaves the connection state
/// unchanged, so the slow path processes the same segment from scratch. The
/// payload is admitted to the socket before the ACK is applied, and nothing
/// after that point can reject the segment.
fn try_fast_path(
    runtime: NetRuntimeHandle,
    tcb: &TcpControlBlockSnapshot,
    segment: AckSegment,
    peer_timestamp: Option<u32>,
    data_payload: PacketPayload,
) -> Result<(), PacketPayload> {
    let payload_len = data_payload.total_len();
    if payload_len == 0 {
        return Err(data_payload);
    }

    if seq_before(segment.ack, tcb.snd_una) || seq_after(segment.ack, tcb.snd_nxt) {
        return Err(data_payload);
    }

    if ooo_queue::has_ooo_segments(runtime, tcb.if_id, tcb.local, tcb.remote) {
        return Err(data_payload);
    }

    let new_rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);

    let Some(socket) = get_socket_by_socket_id(runtime, tcb.socket_id) else {
        return Err(data_payload);
    };
    let can_accept = socket
        .with_inner(|inner| {
            inner
                .recv_buffer_limit
                .saturating_sub(inner.recv_payload_bytes())
                >= payload_len
        })
        .unwrap_or(false);
    if !can_accept {
        return Err(data_payload);
    }
    socket.try_push_payload(data_payload)?;

    apply_acceptable_ack(runtime, tcb, segment);

    let timestamp_echo =
        peer_timestamp.map(|peer_ts_val| (peer_ts_val, generate_tcp_timestamp_in(runtime)));
    let should_ack_now = tcp_table_in(runtime)
        .record_receive_progress_with_delayed_ack(
            tcb.if_id,
            tcb.local,
            tcb.remote,
            new_rcv_nxt,
            tcp_table_in(runtime).get_current_tick(),
            timestamp_echo,
        )
        .map(|pending| pending >= DELAYED_ACK_SEGMENTS)
        .unwrap_or(true);

    if should_ack_now {
        send_ack_for_fast_path(runtime, tcb, new_rcv_nxt);
        tcp_table_in(runtime).clear_delayed_ack(tcb.if_id, tcb.local, tcb.remote);
    }

    Ok(())
}

pub fn process_tcp_segment_v6_payload_on(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    segment: PacketPayload,
) {
    if !verify_tcp_checksum_v6(&segment, src_ip, dst_ip) {
        log::warn!("[TCP] IPv6 Checksum verification failed, dropping segment");
        return;
    }

    let Some((header, options, data_payload)) = TcpOptionsScratch::parse(segment) else {
        return;
    };

    let remote = EndpointAddr::new_v6(src_ip.octets(), header.src_port);
    let local = EndpointAddr::new_v6(dst_ip.octets(), header.dst_port);
    let ingress_if_id = if_id;
    process_parsed_tcp_segment(
        runtime,
        local,
        remote,
        ingress_if_id,
        header,
        options.as_slice(),
        data_payload,
    );
}

pub fn process_tcp_segment_payload_on(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    segment: PacketPayload,
) {
    if !verify_tcp_checksum(&segment, src_ip, dst_ip) {
        log::warn!("[TCP] Checksum verification failed, dropping segment");
        return;
    }

    let Some((header, options, data_payload)) = TcpOptionsScratch::parse(segment) else {
        return;
    };

    let remote = EndpointAddr::new(src_ip, header.src_port);
    let local = EndpointAddr::new(dst_ip, header.dst_port);
    let ingress_if_id = if_id;
    process_parsed_tcp_segment(
        runtime,
        local,
        remote,
        ingress_if_id,
        header,
        options.as_slice(),
        data_payload,
    );
}

/// ファストパス用の軽量ACK送信
///
/// TCPオプション(Timestamps等)が有効なら含めるが、
/// SACKブロック等の複雑な処理は行わない。
#[inline]
fn send_ack_for_fast_path(runtime: NetRuntimeHandle, tcb: &TcpControlBlockSnapshot, rcv_nxt: u32) {
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(rcv_nxt)
        .ack_flag()
        .window(tcb.advertised_recv_window());

    if tcb.ts_enabled {
        builder = builder
            .nop()
            .nop()
            .timestamp(generate_tcp_timestamp_in(runtime), tcb.ts_ecr);
    }

    send_control_segment(runtime, tcb.if_id, tcb.local, tcb.remote, builder);
}

/// Delayed ACK タイマー処理
///
/// 定期的に呼び出され、遅延中のACKを送信する。
/// `DELAYED_ACK_TIMEOUT_MS` 経過した接続の保留ACKをフラッシュする。
pub fn flush_delayed_acks_in(runtime: NetRuntimeHandle) {
    let now = tcp_table_in(runtime).get_current_tick();

    // Step 1: 期限切れの保留ACKがある接続を収集（読み取りロック）
    let mut pending: alloc::vec::Vec<(
        NetIfId,
        EndpointAddr,
        EndpointAddr,
        u32,
        u32,
        u16,
        bool,
        u32,
    )> = alloc::vec::Vec::new();
    tcp_table_in(runtime).for_each_established(|entry| {
        if let Some(due) = entry.delayed_ack_due(now, DELAYED_ACK_TIMEOUT_MS) {
            pending.push((
                due.if_id,
                due.local,
                due.remote,
                due.rcv_nxt,
                due.snd_nxt,
                due.window,
                due.timestamp_enabled,
                due.timestamp_echo,
            ));
        }
    });

    // Step 2: 収集した接続にACKを送信（ロック解放後）
    for (if_id, local, remote, rcv_nxt, snd_nxt, window, ts_enabled, ts_ecr) in pending {
        let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
            .seq(snd_nxt)
            .ack(rcv_nxt)
            .ack_flag()
            .window(window);

        if ts_enabled {
            builder = builder
                .nop()
                .nop()
                .timestamp(generate_tcp_timestamp_in(runtime), ts_ecr);
        }

        send_control_segment(runtime, if_id, local, remote, builder);

        tcp_table_in(runtime).clear_delayed_ack(if_id, local, remote);
    }
}

/// SYN-SENT状態でのセグメント処理（RFC 9293 Section 3.10.7.3 準拠パイプライン）
fn handle_syn_sent_segment(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    options: &[u8],
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;

    // 1. First, check the ACK bit
    let mut ack_acceptable = false;
    if is_ack {
        // Acceptable ACK condition: SND.UNA < SEG.ACK <= SND.NXT
        // (SYN-SENT では SND.UNA == ISS)
        let is_invalid_ack = ack_num.wrapping_sub(tcb.snd_una) as i32 <= 0
            || (ack_num.wrapping_sub(tcb.snd_nxt) as i32) > 0;

        if is_invalid_ack {
            if !is_rst {
                send_rst_for_unexpected_ack(runtime, &tcb, ack_num);
            }
            return;
        }
        ack_acceptable = true;
    }

    // 2. Second, check the RST bit
    if is_rst {
        if ack_acceptable {
            // RFC 9293 Section 3.10.7.3: a RST with an acceptable ACK refuses
            // the connection; its sequence number is not checked.
            terminate_connection_in(
                runtime,
                tcb.if_id,
                tcb.local,
                tcb.remote,
                TcpTermination::Refused,
            );
        }
        // Unacceptable ACK or bare RST in SYN-SENT: drop segment
        return;
    }

    // 3. Third, check the SYN bit
    if is_syn {
        if is_ack {
            // RFC 9293: SYN-ACK (3-way handshake completion)
            handle_syn_ack_received(runtime, tcb, seq_num, ack_num, window, options);
        } else {
            // RFC 9293: Simultaneous Open (双方からSYNを送信した場合)
            // SYN-SENT -> SYN-RECEIVED 遷移し、SYN-ACKを返送する
            handle_simultaneous_syn_received(runtime, tcb, seq_num, options);
        }
        return;
    }

    // 4. If neither SYN nor RST, drop or handle bare acceptable ACK
    if is_ack {
        // SYNなしの素のACKセグメントは不正
        send_rst_for_unexpected_ack(runtime, &tcb, ack_num);
    }
}

/// 同時オープン(Simultaneous Open)時のSYN受信処理
fn handle_simultaneous_syn_received(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    seq_num: u32,
    options: &[u8],
) {
    // TCPオプション解析
    let (peer_ts, sack_permitted) = if !options.is_empty() {
        let mut parser = TcpOptionParser::new(options);
        (parser.find_timestamps(), parser.find_sack_permitted())
    } else {
        (None, false)
    };

    tcp_table_in(runtime).enter_simultaneous_syn_received(
        tcb.if_id,
        tcb.local,
        tcb.remote,
        seq_num,
        TcpHandshakeOptions {
            peer_ts_val: peer_ts.map(|(peer_ts_val, _)| peer_ts_val),
            local_ts_val: peer_ts.map(|_| generate_tcp_timestamp_in(runtime)),
            sack_permitted,
            peer_mss: None,
            peer_window_scale: None,
        },
    );

    // SYN-ACKを送信
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_una) // 自分の初期ISN
        .ack(seq_num.wrapping_add(1))
        .syn()
        .ack_flag()
        .window(65535);

    if let Some((peer_ts_val, _)) = peer_ts {
        builder = builder
            .nop()
            .nop()
            .timestamp(generate_tcp_timestamp_in(runtime), peer_ts_val);
    }

    send_control_segment(runtime, tcb.if_id, tcb.local, tcb.remote, builder);
}

/// 予期しないACKに対するRST送信 (RFC 793)
fn send_rst_for_unexpected_ack(
    runtime: NetRuntimeHandle,
    tcb: &TcpControlBlockSnapshot,
    ack_num: u32,
) {
    let builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(ack_num)
        .rst();
    send_control_segment(runtime, tcb.if_id, tcb.local, tcb.remote, builder);
}

/// 既存TCBに対するTCPセグメント処理（RFC 793 / 9293 / 5961 準拠）
fn handle_synchronized_segment(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    urgent_ptr: u16,
    peer_timestamp: Option<u32>,
    options: &[u8],
    data_payload: Option<PacketPayload>,
) {
    let is_rst = (flags & tcp_flags::RST) != 0;
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_fin = (flags & tcp_flags::FIN) != 0;
    let is_urg = (flags & tcp_flags::URG) != 0;
    let payload_len = data_payload.as_ref().map_or(0, PacketPayload::total_len);

    // 1. Check RST bit (RFC 793 / RFC 5961 Section 3.2)
    if is_rst {
        handle_rst_received(runtime, tcb, seq_num);
        return;
    }

    // 2. Check SYN bit (RFC 5961 Section 4.2)
    // Synchronized states: ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT
    // SynReceived は必要に応じて別経路で扱い、ここでは同期済み状態だけを対象にする。
    if is_syn {
        log::warn!(
            "[TCP] SYN in synchronized state {:?} from {} (seq={}), sending Challenge ACK (RFC 5961)",
            tcb.state,
            tcb.remote,
            seq_num
        );
        send_challenge_ack(runtime, &tcb);
        return;
    }

    // 3. Check ACK bit (RFC 793 / RFC 5961 Section 5.2)
    if !is_ack {
        // All segments in synchronized states MUST have ACK bit set (except RST)
        return;
    }

    // RFC 5961 Section 5.2: ACK validation
    // SND.UNA - MAX.SND.WND <= SEG.ACK <= SND.NXT
    let diff_nxt = ack_num.wrapping_sub(tcb.snd_nxt) as i32;
    let diff_una = tcb.snd_una.wrapping_sub(ack_num) as i32;
    let max_wnd = tcb.max_snd_wnd as i32;

    if diff_nxt > 0 || diff_una > max_wnd {
        log::warn!(
            "[TCP] ACK value outside acceptable range (ack={}, una={}, nxt={}, max_wnd={}), sending Challenge ACK (RFC 5961)",
            ack_num,
            tcb.snd_una,
            tcb.snd_nxt,
            max_wnd
        );
        send_challenge_ack(runtime, &tcb);
        return;
    }

    // Only a segment that passed RST, SYN and ACK validation may move
    // TS.Recent or the retransmit scoreboard.
    //
    // RFC 7323 Section 4.3: record TSval when SEG.SEQ <= Last.ACK.sent <
    // SEG.SEQ + SEG.LEN (Last.ACK.sent is RCV.NXT here), or for a zero-length
    // segment at RCV.NXT.
    if let Some(peer_ts_val) = peer_timestamp {
        let seg_len = payload_len as u32 + u32::from(is_fin);
        let covers_last_ack =
            seq_leq(seq_num, tcb.rcv_nxt) && seq_before(tcb.rcv_nxt, seq_num.wrapping_add(seg_len));
        if covers_last_ack || seq_num == tcb.rcv_nxt {
            tcp_table_in(runtime).record_timestamp_echo(
                tcb.if_id,
                tcb.local,
                tcb.remote,
                peer_ts_val,
                generate_tcp_timestamp_in(runtime),
            );
        }
    }
    if tcb.sack_enabled
        && !options.is_empty()
        && let Some(blocks) = TcpOptionParser::new(options).find_sack_blocks()
        && !blocks.is_empty()
    {
        crate::net::l4::tcp::retransmit::retransmit_queue_process_sack(
            runtime, tcb.if_id, tcb.local, tcb.remote, &blocks,
        );
    }

    // Acceptable ACK: Process it
    apply_acceptable_ack(
        runtime,
        &tcb,
        AckSegment {
            seq: seq_num,
            ack: ack_num,
            window,
            occupies_sequence_space: payload_len > 0 || is_fin,
        },
    );

    // 4. Check URG bit (RFC 793 / RFC 6093)
    if is_urg && urgent_ptr > 0 {
        handle_urgent_received(runtime, tcb, seq_num, urgent_ptr);
    }

    // 5. Process segment data and FIN (RFC 793)
    if payload_len > 0 || is_fin {
        handle_data_received_with_delayed_ack(runtime, tcb, seq_num, data_payload, is_fin);
    }
}

/// Slow path データ受信処理 (Delayed ACK対応)
fn handle_data_received_with_delayed_ack(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    mut seq_num: u32,
    mut data_payload: Option<PacketPayload>,
    fin: bool,
) {
    let mut payload_len = data_payload.as_ref().map_or(0, PacketPayload::total_len) as u32;

    // --- PARTIAL OVERLAP HANDLING (RFC 793) ---
    // If the segment starts before rcv_nxt but contains new data after it,
    // we trim the old part so it can be processed as in-order.
    let diff = tcb.rcv_nxt.wrapping_sub(seq_num) as i32;
    if diff > 0 {
        let skip = diff as usize;
        if skip >= payload_len as usize {
            // All payload is old. Only FIN (if any) might be new.
            if fin && skip == payload_len as usize {
                seq_num = tcb.rcv_nxt;
                payload_len = 0;
                data_payload = None;
            } else {
                // Entirely old, just send ACK
                send_ack_for_fast_path(runtime, &tcb, tcb.rcv_nxt);
                return;
            }
        } else {
            // Trim prefix
            let Some(payload) = data_payload.as_ref() else {
                send_ack_for_fast_path(runtime, &tcb, tcb.rcv_nxt);
                return;
            };
            let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                payload,
                skip,
                payload_len as usize - skip,
            ) else {
                send_ack_for_fast_path(runtime, &tcb, tcb.rcv_nxt);
                return;
            };
            let Some(trimmed) = bounds
                .take_from(
                    data_payload
                        .take()
                        .expect("partial overlap requires a payload owner"),
                )
                .and_then(|window| window.into_payload().ok())
            else {
                send_ack_for_fast_path(runtime, &tcb, tcb.rcv_nxt);
                return;
            };
            data_payload = Some(trimmed);
            payload_len -= skip as u32;
            seq_num = tcb.rcv_nxt;
        }
    }

    if seq_num != tcb.rcv_nxt {
        // Out-of-order: OOOキューに追加して即座に重複ACKを送信 (RFC 5681)
        ooo_queue::insert_ooo_segment(
            runtime,
            tcb.if_id,
            tcb.local,
            tcb.remote,
            seq_num,
            data_payload,
            fin,
        );
        send_ack_for_fast_path(runtime, &tcb, tcb.rcv_nxt);
        return;
    }

    let mut new_rcv_nxt = tcb.rcv_nxt;
    let mut fin_encountered = false;

    // ソケットの受信バッファにデータ追加
    if let Some(socket) = get_socket_by_socket_id(runtime, tcb.socket_id) {
        if payload_len > 0 {
            let payload = data_payload
                .take()
                .expect("positive TCP payload length requires an owner");
            let (pushed, _remainder) = socket.push_payload_with_remainder(payload);
            new_rcv_nxt = new_rcv_nxt.wrapping_add(pushed as u32);

            // RFC 1122: If some data could not be accepted, we MUST NOT advance
            // rcv_nxt past the accepted data.
            if (pushed as u32) < payload_len {
                // Buffer full, some data dropped.
                // we don't process OOO or FIN if we couldn't take all data.
                tcp_table_in(runtime).record_receive_progress(
                    tcb.if_id,
                    tcb.local,
                    tcb.remote,
                    new_rcv_nxt,
                );
                send_ack_for_fast_path(runtime, &tcb, new_rcv_nxt);
                return;
            }
        } else {
            // No payload, but maybe a zero-length segment or pure FIN
        }

        // OOOキューから連続セグメントをドレインしてバッファに追加
        let (drained_nxt, ooo_fin) = ooo_queue::drain_ooo_contiguous(
            runtime,
            tcb.if_id,
            tcb.local,
            tcb.remote,
            new_rcv_nxt,
            |_, seg_payload| socket.push_payload_with_remainder(seg_payload),
        );
        new_rcv_nxt = drained_nxt;
        if ooo_fin || (payload_len == 0 && fin) {
            fin_encountered = true;
        }
    }

    if fin_encountered {
        // FINを処理（rcv_nxtをさらに+1し、状態遷移させる）
        handle_fin_in_order(runtime, tcb, new_rcv_nxt);
        return;
    }

    // Delayed ACK 判定 (RFC 1122 / 5681)
    // TIME_WAIT 状態では常に即座にACKを返す (RFC 793)
    let should_ack_now = if tcb.state == TcpConnectionState::TimeWait {
        tcp_table_in(runtime).record_receive_progress(
            tcb.if_id,
            tcb.local,
            tcb.remote,
            new_rcv_nxt,
        );
        true
    } else {
        tcp_table_in(runtime)
            .record_receive_progress_with_delayed_ack(
                tcb.if_id,
                tcb.local,
                tcb.remote,
                new_rcv_nxt,
                tcp_table_in(runtime).get_current_tick(),
                None,
            )
            .map(|pending| pending >= DELAYED_ACK_SEGMENTS)
            .unwrap_or(true)
    };

    if should_ack_now {
        send_ack_for_fast_path(runtime, &tcb, new_rcv_nxt);
        tcp_table_in(runtime).clear_delayed_ack(tcb.if_id, tcb.local, tcb.remote);
    }
}

/// 既存TCBに対するTCPセグメント処理
fn process_tcp_with_tcb(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    urgent_ptr: u16,
    options: &[u8],
    data_payload: Option<PacketPayload>,
) {
    let payload_len = data_payload.as_ref().map_or(0, PacketPayload::total_len);

    // RFC 7323 Section 3.2 & Section 5.3: Timestamps and PAWS
    let peer_timestamp = match admit_timestamp(&tcb, flags, options) {
        TimestampAdmission::Admit(peer_timestamp) => peer_timestamp,
        TimestampAdmission::PawsRejected => {
            log::warn!(
                "[TCP] PAWS check failed (TSrecent {}) for {} - dropping segment (RFC 7323)",
                tcb.ts_ecr,
                tcb.remote
            );
            send_challenge_ack(runtime, &tcb);
            return;
        }
        TimestampAdmission::MissingTimestamp => {
            log::warn!(
                "[TCP] Missing required Timestamp option on timestamp-enabled connection to {} - silently dropping (RFC 7323)",
                tcb.remote
            );
            return;
        }
    };

    // RFC 793 / 9293 Section 3.10.7.1: 受信セグメントのシーケンス番号妥当性を検証
    let mut seg_len = payload_len;
    if (flags & tcp_flags::SYN) != 0 {
        seg_len += 1;
    }
    if (flags & tcp_flags::FIN) != 0 {
        seg_len += 1;
    }

    if tcb.state != TcpConnectionState::SynSent && !is_acceptable_sequence(&tcb, seq_num, seg_len) {
        if (flags & tcp_flags::RST) == 0 {
            log::warn!(
                "[TCP] Incoming segment out of window (seq={}, len={}) for connection to {}, sending Challenge ACK",
                seq_num,
                seg_len,
                tcb.remote
            );
            send_challenge_ack(runtime, &tcb);
        }
        return;
    }

    match tcb.state {
        TcpConnectionState::SynSent => {
            handle_syn_sent_segment(runtime, tcb, flags, seq_num, ack_num, window, options);
        }
        TcpConnectionState::SynReceived => {
            // RFC 793: If ACK bit is set, check if acceptable and transition to Established
            if (flags & tcp_flags::ACK) != 0 {
                if seq_after(ack_num, tcb.snd_una) && seq_leq(ack_num, tcb.snd_nxt) {
                    let established = tcp_table_in(runtime).establish_syn_received(
                        tcb.if_id,
                        tcb.local,
                        tcb.remote,
                        AckSegment {
                            seq: seq_num,
                            ack: ack_num,
                            window,
                            occupies_sequence_space: seg_len > 0,
                        },
                    );
                    if !established
                        || !complete_passive_open(runtime, tcb.if_id, tcb.local, tcb.remote)
                    {
                        return;
                    }

                    // Continue processing in Established state
                    if let Some(established_tcb) =
                        tcp_table_in(runtime).read(tcb.if_id, tcb.local, tcb.remote, |entry| {
                            TcpControlBlockSnapshot::from(entry)
                        })
                    {
                        handle_synchronized_segment(
                            runtime,
                            established_tcb,
                            flags,
                            seq_num,
                            ack_num,
                            window,
                            urgent_ptr,
                            peer_timestamp,
                            options,
                            data_payload,
                        );
                    }
                } else if (flags & tcp_flags::RST) == 0 {
                    send_rst_for_unexpected_ack(runtime, &tcb, ack_num);
                }
            } else if (flags & tcp_flags::SYN) != 0 {
                // Duplicate SYN in SynReceived: Ignore or re-send SYN-ACK
            }
        }
        TcpConnectionState::Established
        | TcpConnectionState::FinWait1
        | TcpConnectionState::FinWait2
        | TcpConnectionState::CloseWait
        | TcpConnectionState::Closing
        | TcpConnectionState::LastAck
        | TcpConnectionState::TimeWait => {
            handle_synchronized_segment(
                runtime,
                tcb,
                flags,
                seq_num,
                ack_num,
                window,
                urgent_ptr,
                peer_timestamp,
                options,
                data_payload,
            );
        }
        _ => {}
    }
}

/// Stateless RST 送信（RFC 793 / RFC 9293 Section 3.10.7.1）
fn send_stateless_rst(
    runtime: NetRuntimeHandle,
    ingress_if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    payload_len: usize,
) {
    if (flags & tcp_flags::RST) != 0 {
        return;
    }
    if !CLOSED_PORT_RST_BUDGET.try_reserve(crate::time::get_uptime_ms) {
        return;
    }

    let is_ack = (flags & tcp_flags::ACK) != 0;
    let mut builder = TcpSegmentBuilder::new(local.port(), remote.port()).rst();

    if is_ack {
        // <SEQ=SEG.ACK><CTL=RST>
        builder = builder.seq(ack_num);
    } else {
        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        let is_syn = (flags & tcp_flags::SYN) != 0;
        let is_fin = (flags & tcp_flags::FIN) != 0;
        let seg_len = (if is_syn { 1 } else { 0 }) + (if is_fin { 1 } else { 0 });
        let ack = seq_num
            .wrapping_add(seg_len as u32)
            .wrapping_add(payload_len as u32);
        builder = builder.seq(0).ack(ack).ack_flag();
    }

    send_control_segment(runtime, ingress_if_id, local, remote, builder);
}

/// Handle ICMP Error (RFC 1122 Section 4.2.3.9)
pub fn handle_icmp_error(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    icmp_type: crate::net::l3::icmp::IcmpType,
    code: u8,
) {
    use crate::net::l3::icmp::{DestUnreachCode, IcmpType};

    let error = if icmp_type == IcmpType::DestinationUnreachable {
        match DestUnreachCode::from(code) {
            DestUnreachCode::PortUnreachable => EndpointError::ConnectionRefused,
            DestUnreachCode::ProtocolUnreachable => EndpointError::ProtocolUnreachable,
            DestUnreachCode::HostUnreachable => EndpointError::HostUnreachable,
            DestUnreachCode::NetworkUnreachable => EndpointError::NetworkUnreachable,
            _ => return, // Ignore other errors for now
        }
    } else {
        return;
    };

    let socket_id = tcp_table_in(runtime).record_icmp_error(if_id, local, remote, error);

    if let Some(id) = socket_id {
        log::info!(
            "[TCP] Connection failed due to ICMP error ({:?}) in SYN-SENT",
            error
        );
        if let Some(socket) = get_socket_by_socket_id(runtime, id) {
            let _ = socket.with_inner_mut(|inner| {
                inner.last_error = Some(error);
                inner.connect_waker.wake();
            });
        }
    }
}

/// Handle ICMPv6 Error (RFC 4443 Section 3)
pub fn handle_icmpv6_error(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    icmp_type: crate::net::l3::icmpv6::Icmpv6Type,
    code: u8,
) {
    use crate::net::l3::icmpv6::Icmpv6Type;

    let error = if icmp_type == Icmpv6Type::DestinationUnreachable {
        match code {
            0 => EndpointError::NetworkUnreachable, // No route to destination
            1 => EndpointError::ConnectionRefused, // Communication with destination administratively prohibited
            3 => EndpointError::HostUnreachable,   // Address unreachable
            4 => EndpointError::ConnectionRefused, // Port unreachable
            _ => return,                           // Ignore other codes
        }
    } else {
        return; // Ignore other error types for now
    };

    let socket_id = tcp_table_in(runtime).record_icmp_error(if_id, local, remote, error);

    if let Some(id) = socket_id {
        log::info!(
            "[TCP-V6] Connection failed due to ICMPv6 error ({:?}) in SYN-SENT",
            error
        );
        if let Some(socket) = get_socket_by_socket_id(runtime, id) {
            let _ = socket.with_inner_mut(|inner| {
                inner.last_error = Some(error);
                inner.connect_waker.wake();
            });
        }
    }
}
/// SYN-ACK受信処理（クライアント側3ウェイハンドシェイク）
fn handle_syn_ack_received(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    options: &[u8],
) {
    // ACK番号を検証 (RFC 793 / RFC 9293 Section 3.10.7.3)
    // SYN-SENT状態で不正なACK番号を受信した場合はRSTを返送する
    if ack_num != tcb.snd_nxt {
        log::info!(
            "TCP: Invalid SYN-ACK ack_num: expected {}, got {}, sending RST (RFC 9293)",
            tcb.snd_nxt,
            ack_num
        );
        send_rst_for_unexpected_ack(runtime, &tcb, ack_num);
        return;
    }

    // SYN-ACKのTCPオプションを解析（TSopt / SACK-Permitted / MSS / WSCALE検出）
    let (peer_ts, sack_permitted, peer_mss, peer_ws) = if !options.is_empty() {
        let mut parser = TcpOptionParser::new(options);
        (
            parser.find_timestamps(),
            parser.find_sack_permitted(),
            parser.find_mss(),
            parser.find_window_scale(),
        )
    } else {
        (None, false, None, None)
    };

    let updated = tcp_table_in(runtime).establish_from_syn_ack(
        tcb.if_id,
        tcb.local,
        tcb.remote,
        AckSegment {
            seq: seq_num,
            ack: ack_num,
            window,
            occupies_sequence_space: true,
        },
        TcpHandshakeOptions {
            peer_ts_val: peer_ts.map(|(peer_ts_val, _)| peer_ts_val),
            local_ts_val: peer_ts.map(|_| generate_tcp_timestamp_in(runtime)),
            sack_permitted,
            peer_mss,
            peer_window_scale: peer_ws,
        },
    );

    if !updated {
        return;
    }
    let Some(established) = tcp_table_in(runtime).read(tcb.if_id, tcb.local, tcb.remote, |entry| {
        TcpControlBlockSnapshot::from(entry)
    }) else {
        return;
    };

    // The handshake-completing ACK is the first segment whose window is
    // scaled, and it carries TSopt when timestamps were negotiated.
    send_ack_for_fast_path(runtime, &established, established.rcv_nxt);
    log::info!(
        "TCP: Connection established {} <-> {}",
        tcb.local,
        tcb.remote
    );
}

/// Helper to get a socket by its file descriptor.
fn get_socket_by_socket_id(runtime: NetRuntimeHandle, socket_id: SocketId) -> Option<Socket> {
    lookup_socket_in(runtime, socket_id)
}

/// 新規接続処理（SYN受信 - サーバー側、またはCLOSED状態へのセグメント受信）
fn process_tcp_new_connection(
    runtime: NetRuntimeHandle,
    local: EndpointAddr,
    remote: EndpointAddr,
    ingress_if_id: NetIfId,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    _urgent_ptr: u16,
    options: &[u8],
    data_payload: Option<PacketPayload>,
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;

    // RFC 793: If the connection does not exist (CLOSED) then a reset is sent
    // in response to any incoming segment except another reset.
    if is_rst {
        return;
    }

    // リッスン中のソケットを探す
    let socket = find_listening_tcp_socket_in(runtime, local, ingress_if_id);

    // リッスン中のソケットがない場合、または SYN 以外を受信した場合
    if socket.is_none() || !is_syn {
        send_stateless_rst(
            runtime,
            ingress_if_id,
            local,
            remote,
            flags,
            seq_num,
            ack_num,
            data_payload.as_ref().map_or(0, PacketPayload::total_len),
        );
        return;
    }

    let Some(socket) = socket else {
        return;
    };
    let Some(nodelay) = socket
        .with_inner(|inner| {
            if !inner.is_tcp_listening() {
                return None;
            }
            Some(inner.tcp().map_or(false, |t| t.nodelay))
        })
        .flatten()
    else {
        return;
    };

    // TCPオプション解析 (Timestamps / SACK Permitted / MSS / WSCALE)
    let (peer_ts, sack_permitted, peer_mss, peer_ws) = if !options.is_empty() {
        let mut parser = TcpOptionParser::new(options);
        (
            parser.find_timestamps(),
            parser.find_sack_permitted(),
            parser.find_mss(),
            parser.find_window_scale(),
        )
    } else {
        (None, false, None, None)
    };

    // TCB作成
    // SECURITY: SYN Flood 対策として SYN Cookie を使用
    // SYN キューが半分以上埋まっている場合に発動
    let use_syncookies = tcp_table_in(runtime).syn_recv_count() > 2048;

    let (isn, handshake_options) = if use_syncookies {
        // MSS インデックスを選択 (簡易版: 相手の MSS を見て適切なものを選択)
        let mss_idx = match peer_mss {
            Some(m) if m >= 1460 => 2, // 1460 (Ethernet)
            Some(m) if m >= 536 => 1,  // 536 (Default)
            _ => 0,                    // 64
        };
        // The cookie encodes only the MSS index. Window scaling, SACK and
        // timestamps cannot be reconstructed from the returning ACK, so the
        // stateless SYN-ACK must not offer them.
        (
            tcp_table_in(runtime).generate_syncookie(local, remote, seq_num, mss_idx),
            TcpHandshakeOptions {
                peer_mss,
                ..TcpHandshakeOptions::default()
            },
        )
    } else {
        (
            tcp_table_in(runtime).generate_isn(local, remote),
            TcpHandshakeOptions {
                peer_ts_val: peer_ts.map(|(peer_ts_val, _)| peer_ts_val),
                local_ts_val: peer_ts.map(|_| generate_tcp_timestamp_in(runtime)),
                sack_permitted,
                peer_mss,
                peer_window_scale: peer_ws,
            },
        )
    };

    let tcb = TcpControlBlock::passive_open(
        socket.socket_id(),
        local,
        remote,
        isn,
        seq_num,
        nodelay,
        ingress_if_id,
        handshake_options,
    );

    // SYN-ACK送信に必要な値をinsertの前にキャプチャ
    let Some(syn_ack) = tcb.passive_open_syn_ack() else {
        return;
    };

    // SYN Cookie 使用時は TCB をテーブルに挿入しない (Stateless)
    if !use_syncookies {
        // TCBをテーブルに挿入 (リソース制限チェック)
        if let Err(e) = tcp_table_in(runtime).insert(tcb) {
            log::warn!(
                "[NET] TCP: Failed to accept new connection from {}: {}",
                remote,
                e
            );
            return;
        }
    } else {
        log::info!("[TCP] SYN Cookie sent to {} (SYN flood protection)", remote);
    }

    // SYN-ACK送信 (TCPオプション付き)
    // MSS=1460 (標準的なイーサネットMTU 1500 - IPヘッダ20 - TCPヘッダ20)
    let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
        .seq(syn_ack.isn)
        .ack(seq_num.wrapping_add(1))
        .syn()
        .ack_flag()
        .window(65535)
        .syn_options(1460, syn_ack.window_scale, syn_ack.sack_enabled, None);

    // TSopt付きSYN-ACK (RFC 7323 Section 3.2)
    if let Some((our_ts, peer_ts_val)) = syn_ack.timestamp {
        builder = builder.nop().nop().timestamp(our_ts, peer_ts_val);
    }

    // パケット送信
    send_control_segment(runtime, ingress_if_id, local, remote, builder);
    log::info!("TCP: SYN-ACK sent {} -> {}", local, remote);
}

/// RST受信処理 (RFC 5961準拠)
///
/// RFC 5961: RSTパケットのシーケンス番号がrcv_nxtと完全一致する場合のみ受理する。
/// ウィンドウ内だが不一致の場合はChallenge ACKを送信する。
/// ウィンドウ外の場合は黙って破棄する。
fn handle_rst_received(runtime: NetRuntimeHandle, tcb: TcpControlBlockSnapshot, seq_num: u32) {
    if seq_num == tcb.rcv_nxt {
        // RFC 5961: 完全一致 → 接続をリセット。SYN-RECEIVED からのリセットは、
        // passive open ならリスナーに影響せず、active open なら接続拒否となる。
        let termination = if tcb.state == TcpConnectionState::SynReceived {
            TcpTermination::Refused
        } else {
            TcpTermination::Reset
        };
        terminate_connection_in(runtime, tcb.if_id, tcb.local, tcb.remote, termination);
    } else {
        // RFC 5961: ウィンドウ内ならChallenge ACKを送信
        let rcv_wnd = tcb.effective_recv_window();
        let diff = seq_num.wrapping_sub(tcb.rcv_nxt);
        if diff < rcv_wnd {
            log::warn!(
                "[TCP] RST with in-window but non-exact seq_num ({} != {}), sending Challenge ACK",
                seq_num,
                tcb.rcv_nxt
            );
            send_challenge_ack(runtime, &tcb);
        }
        // ウィンドウ外のRSTは黙って破棄（RFC 5961）
    }
}

/// Hand a connection that just reached ESTABLISHED through a passive open to
/// its listener's accept queue.
///
/// The TCB is rebound from the listener's socket id to a fresh connection id
/// only once the accept queue has admitted it. If the listener is gone or its
/// backlog is full, the connection is aborted with RST and its TCB removed, so
/// no established connection exists without an owner that can accept it.
/// Returns whether the connection was admitted.
fn complete_passive_open(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
) -> bool {
    let admitted = generate_socket_id_in(runtime).is_some_and(|socket_id| {
        find_listening_tcp_socket_in(runtime, local, if_id).is_some_and(|listener| {
            listener
                .with_inner_mut(|inner| {
                    if !inner.is_tcp_listening() {
                        return false;
                    }
                    let Some(tcp) = inner.tcp_mut() else {
                        return false;
                    };
                    if tcp.accept_queue.len() >= tcp.accept_backlog {
                        return false;
                    }
                    tcp.accept_queue
                        .push_back(AcceptedConnection::new(socket_id, local, remote, if_id));
                    inner.accept_waker.wake();
                    true
                })
                .unwrap_or(false)
                && tcp_table_in(runtime).set_socket_id(if_id, local, remote, socket_id)
        })
    });

    if admitted {
        get_or_create_retransmit_queue(runtime, if_id, local, remote);
        return true;
    }

    log::info!(
        "[TCP] Accept queue rejected {} -> {}, resetting connection",
        remote,
        local
    );
    if let Some(removed) = tcp_table_in(runtime).remove(if_id, local, remote) {
        abort_connection_in(runtime, removed);
    }
    false
}

/// 順序通りに到達した（またはOOOから復元された）FINを処理
fn handle_fin_in_order(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    rcv_nxt_at_fin: u32,
) {
    let Some((final_rcv_nxt, should_ack)) = tcp_table_in(runtime).record_fin_received(
        tcb.if_id,
        tcb.local,
        tcb.remote,
        rcv_nxt_at_fin,
        tcp_table_in(runtime).get_current_tick(),
    ) else {
        return;
    };

    if should_ack {
        // FINに対するACKを送信 (rcv_nxtは既に+1済み)
        send_ack_for_fast_path(runtime, &tcb, final_rcv_nxt);
    }

    // ソケットに接続相手のクローズを通知
    // recv_wakerを起こして、readがEOFを返せるようにする
    notify_socket_peer_fin(runtime, tcb.socket_id);
}

/// ソケットに相手側FIN受信を通知
///
/// recv_wakerを起こすことで、アプリケーション側のread操作が
/// EOF (0バイト読み取り) を返せるようにする。
fn notify_socket_peer_fin(runtime: NetRuntimeHandle, socket_id: SocketId) {
    if let Some(socket) = lookup_socket_in(runtime, socket_id) {
        let _ = socket.with_inner_mut(|inner| {
            // recv_wakerを起こしてEOFを通知
            inner.recv_waker.wake();
        });
    }
}

/// Urgent data受信処理 (RFC 793/6093)
///
/// URGフラグが設定されたセグメントを受信した際の処理。
/// urgent pointerは、セグメント開始からurgent dataの最後のバイトまでのオフセットを示す。
fn handle_urgent_received(
    runtime: NetRuntimeHandle,
    tcb: TcpControlBlockSnapshot,
    seq_num: u32,
    urgent_ptr: u16,
) {
    if let Some(socket_id) = tcp_table_in(runtime)
        .record_urgent_received(tcb.if_id, tcb.local, tcb.remote, seq_num, urgent_ptr)
    {
        notify_socket_urgent(runtime, socket_id);
    }
}

/// ソケットにurgent data到着を通知
fn notify_socket_urgent(runtime: NetRuntimeHandle, socket_id: SocketId) {
    if let Some(socket) = lookup_socket_in(runtime, socket_id) {
        let _ = socket.with_inner_mut(|inner| {
            // urgent flagを設定
            inner.set_urgent_pending(true);
            // recv wakerを起こす（OOBデータ待ちの可能性）
            inner.recv_waker.wake();
        });
    }
}

// End of file
