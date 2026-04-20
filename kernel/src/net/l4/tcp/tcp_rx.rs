// ============================================================================
// kernel/src/net/l4/tcp/tcp_rx.rs
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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ooo_queue;
use super::retransmit::{
    get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_remove,
};
use super::segment::{TcpSegmentBuilder, send_tcp_segment_payload};
use super::tcb::{
    TcpConnectionState, TcpControlBlockEntry, TcpControlBlockSnapshot, tcb_table, tcp_flags,
};
use super::window_scale::TcpOptionParser;
use crate::net::l4::socket::{
    Socket, TcpSocketState, find_listening_tcp_socket, generate_socket_id, lookup_socket,
};
use crate::net::l4::types::{AcceptedConnection, EndpointAddr, EndpointError, SocketId};
use crate::net::payload::PacketPayloadView;
use crate::net::runtime::manager::NetIfId;
use kernel_api::resource::net::PacketPayload;

// ============================================================================
// TCP Fast Path Statistics
// ============================================================================

/// ファストパスで処理されたパケット数
static FAST_PATH_HITS: AtomicU64 = AtomicU64::new(0);
/// スローパスにフォールバックしたパケット数
static SLOW_PATH_HITS: AtomicU64 = AtomicU64::new(0);

/// ファストパス統計を取得
pub fn fast_path_stats() -> (u64, u64) {
    (
        FAST_PATH_HITS.load(Ordering::Relaxed),
        SLOW_PATH_HITS.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Delayed ACK
// ============================================================================

/// Delayed ACK の最大遅延時間 (ミリ秒, RFC 1122: 最大500ms, 推奨200ms)
const DELAYED_ACK_TIMEOUT_MS: u64 = 200;

/// Delayed ACK が溜まる最大セグメント数 (RFC 5681: 2セグメントごとにACK)
const DELAYED_ACK_SEGMENTS: u8 = 2;

/// RFC 7323準拠のTCPタイムスタンプ生成
pub(crate) fn generate_tcp_timestamp() -> u32 {
    let ms = tcb_table().get_current_tick();
    (ms / 10) as u32
}

fn resolve_ingress_if_id(if_id: Option<NetIfId>) -> NetIfId {
    if let Some(if_id) = if_id {
        return if_id;
    }
    crate::net::runtime::device::primary_if_in(crate::net::runtime::default_runtime())
        .or_else(|| {
            crate::net::runtime::manager::list_interfaces_in(crate::net::runtime::default_runtime())
                .ok()
                .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
        })
        .unwrap_or_default()
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

/// Challenge ACK rate limiting (RFC 5961 Section 10)
/// Recommended limit: 100 segments per second
static CHALLENGE_ACK_LIMIT_MS: u64 = 1000; // 1 second window
static CHALLENGE_ACK_MAX_COUNT: u32 = 100;
static CHALLENGE_ACK_COUNT: AtomicU32 = AtomicU32::new(0);
static CHALLENGE_ACK_LAST_RESET: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Closed-port RST rate limiting (anti-scan flood)
// ============================================================================

/// 閉ポート宛RST送信のグローバルレートリミット（1秒あたり最大数）
/// インターネット直結環境ではスキャンパケットが大量に届くため、
/// 状態を作らずRSTを返す場合でもイベントキュー圧迫を防止する。
const CLOSED_PORT_RST_LIMIT_MS: u64 = 1000;
const CLOSED_PORT_RST_MAX_COUNT: u32 = 10;
static CLOSED_PORT_RST_COUNT: AtomicU32 = AtomicU32::new(0);
static CLOSED_PORT_RST_LAST_RESET: AtomicU64 = AtomicU64::new(0);
/// レート制限によりドロップされたパケット数（統計用）
static CLOSED_PORT_RST_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Update closed-port RST rate statistics and check if a new RST should be sent.
///
/// This function implements rate limiting for stateless resets to protect
/// the kernel event queue from exhaustion during port scans.
/// RFC 793/9293 says a host SHOULD send a reset, but we MUST also protect
/// system resources. When the limit is exceeded, we drop the RST and
/// increment `CLOSED_PORT_RST_DROPPED` for telemetry.
fn check_closed_port_rst_rate() -> bool {
    let now = tcb_table().get_current_tick();
    let last_reset = CLOSED_PORT_RST_LAST_RESET.load(Ordering::Relaxed);

    if now.saturating_sub(last_reset) >= CLOSED_PORT_RST_LIMIT_MS {
        CLOSED_PORT_RST_COUNT.store(0, Ordering::Relaxed);
        CLOSED_PORT_RST_LAST_RESET.store(now, Ordering::Relaxed);
    }

    let count = CLOSED_PORT_RST_COUNT.fetch_add(1, Ordering::Relaxed);
    if count < CLOSED_PORT_RST_MAX_COUNT {
        true
    } else {
        // exceeding the window: record for telemetry and drop to protect event queue
        CLOSED_PORT_RST_DROPPED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// 閉ポートRSTのドロップ統計を取得
pub fn closed_port_rst_dropped_count() -> u64 {
    CLOSED_PORT_RST_DROPPED.load(Ordering::Relaxed)
}

//======================================================================
// Unit tests
//======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn closed_port_rst_rate_counters_increment_but_always_allow() {
        // clear previous state
        CLOSED_PORT_RST_COUNT.store(0, Ordering::Relaxed);
        CLOSED_PORT_RST_LAST_RESET.store(0, Ordering::Relaxed);
        CLOSED_PORT_RST_DROPPED.store(0, Ordering::Relaxed);

        // call more than the max count inside the same window
        for i in 0..(CLOSED_PORT_RST_MAX_COUNT + 5) {
            assert!(
                check_closed_port_rst_rate(),
                "function should always return true"
            );
        }
        // dropped counter should reflect excess above limit
        assert_eq!(
            CLOSED_PORT_RST_DROPPED.load(Ordering::Relaxed) as u32,
            5,
            "dropped count should track excess resets"
        );

        // advance window manually by resetting last_reset further back
        let now = CLOSED_PORT_RST_LAST_RESET.load(Ordering::Relaxed);
        CLOSED_PORT_RST_LAST_RESET.store(now - CLOSED_PORT_RST_LIMIT_MS - 1, Ordering::Relaxed);

        // next call should reset the counter
        assert!(check_closed_port_rst_rate());
        assert_eq!(CLOSED_PORT_RST_COUNT.load(Ordering::Relaxed), 1);
    }
}

fn check_challenge_ack_rate_limit() -> bool {
    let now = tcb_table().get_current_tick();
    let last_reset = CHALLENGE_ACK_LAST_RESET.load(Ordering::Relaxed);

    if now.saturating_sub(last_reset) >= CHALLENGE_ACK_LIMIT_MS {
        CHALLENGE_ACK_COUNT.store(0, Ordering::Relaxed);
        CHALLENGE_ACK_LAST_RESET.store(now, Ordering::Relaxed);
    }

    let count = CHALLENGE_ACK_COUNT.fetch_add(1, Ordering::Relaxed);
    count < CHALLENGE_ACK_MAX_COUNT
}

/// チャレンジACK（シーケンス番号エラー時の応答）を送信
fn send_challenge_ack(tcb: &TcpControlBlockSnapshot) {
    if !check_challenge_ack_rate_limit() {
        log::debug!("[TCP] Challenge ACK rate limit exceeded, dropping");
        return;
    }
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(tcb.rcv_nxt)
        .ack_flag()
        .window(u16::try_from(tcb.advertised_recv_window()).unwrap_or(u16::MAX));

    if tcb.ts_enabled {
        builder = builder
            .nop()
            .nop()
            .timestamp(generate_tcp_timestamp(), tcb.ts_ecr);
    }

    let Ok(ack) = builder.build_checked_packet(tcb.local, tcb.remote) else {
        return;
    };
    send_tcp_segment_payload(tcb.local, tcb.remote, ack);
}

fn send_control_segment(local: EndpointAddr, remote: EndpointAddr, builder: TcpSegmentBuilder) {
    let Ok(segment) = builder.build_checked_packet(local, remote) else {
        return;
    };
    send_tcp_segment_payload(local, remote, segment);
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
    fn parse(segment: PacketPayload) -> Option<(ParsedTcpHeader, Self, PacketPayload)> {
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
        if options_len > 0 && view.copy_range(20, &mut scratch.bytes[..options_len]) != options_len
        {
            return None;
        }

        let payload_len = view.total_len().saturating_sub(data_offset);
        let payload =
            crate::net::payload::retain_payload_window_owned(segment, data_offset, payload_len)?;

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
    local: EndpointAddr,
    remote: EndpointAddr,
    ingress_if_id: NetIfId,
    header: ParsedTcpHeader,
    options: &[u8],
    data_payload: PacketPayload,
) {
    let _ = tcb_table().update(local, remote, |entry| {
        entry.ingress_if_id = Some(ingress_if_id)
    });

    if let Some(tcb) = tcb_table().read(local, remote, |entry| TcpControlBlockSnapshot::from(entry))
    {
        tcb_table().update(local, remote, |entry| {
            entry.update_peer_window(header.window);
        });

        let mut data_payload = data_payload;
        let payload_len = data_payload.total_len();
        let mut seg_len = payload_len;
        if (header.flags & tcp_flags::SYN) != 0 {
            seg_len += 1;
        }
        if (header.flags & tcp_flags::FIN) != 0 {
            seg_len += 1;
        }

        if !is_acceptable_sequence(&tcb, header.seq_num, seg_len) {
            if (header.flags & tcp_flags::RST) == 0 {
                send_challenge_ack(&tcb);
            }
            return;
        }

        let base_flags = header.flags & !(tcp_flags::CWR | tcp_flags::ECE);
        let can_try_fast_path = tcb.state == TcpConnectionState::Established
            && header.seq_num == tcb.rcv_nxt
            && payload_len > 0
            && (base_flags == tcp_flags::ACK || base_flags == (tcp_flags::ACK | tcp_flags::PSH));
        if can_try_fast_path {
            match try_fast_path(&tcb, header.ack_num, options, data_payload) {
                Ok(()) => {
                    FAST_PATH_HITS.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(payload) => {
                    data_payload = payload;
                }
            }
        }

        SLOW_PATH_HITS.fetch_add(1, Ordering::Relaxed);
        process_tcp_with_tcb(
            tcb,
            header.flags,
            header.seq_num,
            header.ack_num,
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
            tcb_table().verify_syncookie(local, remote, header.ack_num, client_isn)
        {
            log::info!(
                "[TCP] SYN Cookie verified for {}, creating connection",
                remote
            );

            if let Some(socket) = find_listening_tcp_socket(local, Some(ingress_if_id)) {
                let mss = match mss_idx {
                    2 => 1460,
                    1 => 536,
                    _ => 64,
                };

                let mut tcb = TcpControlBlockEntry::new(socket.socket_id(), local, remote);
                tcb.snd_una = header.ack_num.wrapping_sub(1);
                tcb.snd_nxt = header.ack_num;
                tcb.rcv_nxt = header.seq_num;
                tcb.state = TcpConnectionState::Established;
                tcb.mss = mss;

                if let Err(e) = tcb_table().insert(tcb) {
                    log::warn!(
                        "[TCP] Failed to insert TCB after SYN Cookie verification: {}",
                        e
                    );
                    return;
                }

                if let Some(accepted) = create_accepted_socket(local, remote, ingress_if_id) {
                    let _ = push_to_accept_queue(local.port(), Some(ingress_if_id), accepted);
                }

                if !data_payload.is_empty() {
                    if let Some(snapshot) = tcb_table()
                        .read(local, remote, |entry| TcpControlBlockSnapshot::from(entry))
                    {
                        process_tcp_with_tcb(
                            snapshot,
                            header.flags,
                            header.seq_num,
                            header.ack_num,
                            header.urgent_ptr,
                            options,
                            data_payload,
                        );
                    }
                }
            }
        }
    }
}

fn try_fast_path(
    tcb: &TcpControlBlockSnapshot,
    ack_num: u32,
    options: &[u8],
    data_payload: PacketPayload,
) -> Result<(), PacketPayload> {
    let payload_len = data_payload.total_len();
    if payload_len == 0 {
        return Err(data_payload);
    }

    let ack_diff_una = ack_num.wrapping_sub(tcb.snd_una) as i32;
    let ack_diff_nxt = tcb.snd_nxt.wrapping_sub(ack_num) as i32;
    if ack_diff_una < 0 || ack_diff_nxt < 0 {
        return Err(data_payload);
    }

    if ooo_queue::has_ooo_segments(tcb.local, tcb.remote) {
        return Err(data_payload);
    }

    let new_rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);

    if ack_diff_una > 0 {
        let current_time_ms = tcb_table().get_current_tick();
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.on_ack_received(ack_num, false, current_time_ms, 0);
        });
        retransmit_queue_ack(tcb.local, tcb.remote, ack_num);
    }

    if let Some(socket) = get_socket_by_socket_id(tcb.socket_id) {
        let can_accept = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner
                .recv_buffer_limit
                .saturating_sub(inner.recv_payload_bytes())
                >= payload_len
        };
        if !can_accept {
            return Err(data_payload);
        }
        let pushed = socket.push_payload(data_payload);
        if pushed < payload_len {
            return Err(PacketPayload::default());
        }
    } else {
        return Err(data_payload);
    }

    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = new_rcv_nxt;
        if entry.delayed_ack_pending == 0 {
            entry.delayed_ack_timer = tcb_table().get_current_tick();
        }
        entry.delayed_ack_pending = entry.delayed_ack_pending.saturating_add(1);

        if entry.ts_enabled && !options.is_empty() {
            let mut parser = TcpOptionParser::new(options);
            if let Some((peer_ts_val, _)) = parser.find_timestamps() {
                entry.ts_ecr = peer_ts_val;
                entry.ts_val = generate_tcp_timestamp();
            }
        }
    });

    let should_ack_now = tcb_table()
        .read(tcb.local, tcb.remote, |entry| entry.delayed_ack_pending)
        .map(|pending| pending >= DELAYED_ACK_SEGMENTS)
        .unwrap_or(true);

    if should_ack_now {
        send_ack_for_fast_path(tcb, new_rcv_nxt);
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.delayed_ack_pending = 0;
        });
    }

    Ok(())
}

pub fn process_tcp_segment_v6_payload_on(
    if_id: Option<NetIfId>,
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    segment: PacketPayload,
) {
    if !crate::net::runtime::bridge::rx_csum_hw_verified()
        && !verify_tcp_checksum_v6(&segment, src_ip, dst_ip)
    {
        log::warn!("[TCP] IPv6 Checksum verification failed, dropping segment");
        return;
    }

    let Some((header, options, data_payload)) = TcpOptionsScratch::parse(segment) else {
        return;
    };

    let remote = EndpointAddr::new_v6(src_ip.octets(), header.src_port);
    let local = EndpointAddr::new_v6(dst_ip.octets(), header.dst_port);
    let ingress_if_id = resolve_ingress_if_id(if_id);
    process_parsed_tcp_segment(
        local,
        remote,
        ingress_if_id,
        header,
        options.as_slice(),
        data_payload,
    );
}

pub fn process_tcp_segment_payload_on(
    if_id: Option<NetIfId>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    segment: PacketPayload,
) {
    if !crate::net::runtime::bridge::rx_csum_hw_verified()
        && !verify_tcp_checksum(&segment, src_ip, dst_ip)
    {
        log::warn!("[TCP] Checksum verification failed, dropping segment");
        return;
    }

    let Some((header, options, data_payload)) = TcpOptionsScratch::parse(segment) else {
        return;
    };

    let remote = EndpointAddr::new(src_ip, header.src_port);
    let local = EndpointAddr::new(dst_ip, header.dst_port);
    let ingress_if_id = resolve_ingress_if_id(if_id);
    process_parsed_tcp_segment(
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
fn send_ack_for_fast_path(tcb: &TcpControlBlockSnapshot, rcv_nxt: u32) {
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(rcv_nxt)
        .ack_flag()
        .window(tcb.advertised_recv_window());

    if tcb.ts_enabled {
        builder = builder
            .nop()
            .nop()
            .timestamp(generate_tcp_timestamp(), tcb.ts_ecr);
    }

    send_control_segment(tcb.local, tcb.remote, builder);
}

/// Delayed ACK タイマー処理
///
/// 定期的に呼び出され、遅延中のACKを送信する。
/// `DELAYED_ACK_TIMEOUT_MS` 経過した接続の保留ACKをフラッシュする。
pub fn flush_delayed_acks() {
    let now = tcb_table().get_current_tick();

    // Step 1: 期限切れの保留ACKがある接続を収集（読み取りロック）
    let mut pending: alloc::vec::Vec<(EndpointAddr, EndpointAddr, u32, u32, u16, bool, u32)> =
        alloc::vec::Vec::new();
    tcb_table().for_each_established(|entry| {
        if entry.delayed_ack_pending > 0
            && now.saturating_sub(entry.delayed_ack_timer) >= DELAYED_ACK_TIMEOUT_MS
        {
            pending.push((
                entry.local,
                entry.remote,
                entry.rcv_nxt,
                entry.snd_nxt,
                entry.advertised_recv_window(),
                entry.ts_enabled,
                entry.ts_ecr,
            ));
        }
    });

    // Step 2: 収集した接続にACKを送信（ロック解放後）
    for (local, remote, rcv_nxt, snd_nxt, window, ts_enabled, ts_ecr) in pending {
        let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
            .seq(snd_nxt)
            .ack(rcv_nxt)
            .ack_flag()
            .window(window);

        if ts_enabled {
            builder = builder
                .nop()
                .nop()
                .timestamp(generate_tcp_timestamp(), ts_ecr);
        }

        send_control_segment(local, remote, builder);

        // カウンタリセット
        tcb_table().update(local, remote, |e| {
            e.delayed_ack_pending = 0;
        });
    }
}

/// SYN-SENT状態でのセグメント処理
fn handle_syn_sent_segment(
    tcb: TcpControlBlockSnapshot,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    options: &[u8],
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;

    if is_syn && is_ack {
        handle_syn_ack_received(tcb, seq_num, ack_num, options);
    } else if is_syn {
        // RFC 793: Simultaneous Open (双方からSYNを送信した場合)
        // SYN-SENT -> SYN-RECEIVED 遷移し、SYN-ACKを返送する。
        handle_simultaneous_syn_received(tcb, seq_num, options);
    } else if is_rst {
        handle_rst_received(tcb, seq_num);
    } else if is_ack {
        // RFC 793: SYN-SENT状態でSYNなしACKを受信した場合はRSTでリセット
        send_rst_for_unexpected_ack(&tcb, ack_num);
    }
}

/// 同時オープン(Simultaneous Open)時のSYN受信処理
fn handle_simultaneous_syn_received(tcb: TcpControlBlockSnapshot, seq_num: u32, options: &[u8]) {
    // TCPオプション解析
    let (peer_ts, sack_permitted) = if !options.is_empty() {
        let mut parser = TcpOptionParser::new(options);
        (parser.find_timestamps(), parser.find_sack_permitted())
    } else {
        (None, false)
    };

    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = seq_num.wrapping_add(1);
        entry.state = TcpConnectionState::SynReceived;

        if let Some((peer_ts_val, _)) = peer_ts {
            entry.ts_enabled = true;
            entry.ts_ecr = peer_ts_val;
            entry.ts_val = generate_tcp_timestamp();
        }
        if sack_permitted {
            entry.sack_enabled = true;
        }
    });

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
            .timestamp(generate_tcp_timestamp(), peer_ts_val);
    }

    send_control_segment(tcb.local, tcb.remote, builder);
}

/// 予期しないACKに対するRST送信 (RFC 793)
fn send_rst_for_unexpected_ack(tcb: &TcpControlBlockSnapshot, ack_num: u32) {
    let builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(ack_num)
        .rst();
    send_control_segment(tcb.local, tcb.remote, builder);
}

/// 既存TCBに対するTCPセグメント処理（RFC 793 / 9293 / 5961 準拠）
fn handle_synchronized_segment(
    tcb: TcpControlBlockSnapshot,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    urgent_ptr: u16,
    options: &[u8],
    data_payload: PacketPayload,
) {
    let is_rst = (flags & tcp_flags::RST) != 0;
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_fin = (flags & tcp_flags::FIN) != 0;
    let is_urg = (flags & tcp_flags::URG) != 0;
    let payload_len = data_payload.total_len();

    // 0. Parse TCP Options (SACK / Timestamps)
    if !options.is_empty() {
        let mut parser = TcpOptionParser::new(options);

        // 受信SACKオプション（送信側の再送キューに反映）
        if tcb.sack_enabled {
            if let Some(blocks) = parser.find_sack_blocks() {
                if !blocks.is_empty() {
                    crate::net::l4::tcp::retransmit::retransmit_queue_process_sack(
                        tcb.local, tcb.remote, &blocks,
                    );
                }
            }
        }

        // Timestamp (RFC 7323 Section 5.3)
        if tcb.ts_enabled {
            if let Some((peer_ts_val, _peer_ts_ecr)) = parser.find_timestamps() {
                // RFC 7323: SEG.SEQ <= last.ACK.sent < SEG.SEQ + SEG.LEN の場合に更新。
                // last.ACK.sent はここでは tcb.rcv_nxt。
                let seg_len_u32 = payload_len as u32
                    + (if is_syn { 1 } else { 0 })
                    + (if is_fin { 1 } else { 0 });
                let is_in_window = (seq_num.wrapping_sub(tcb.rcv_nxt) as i32) <= 0
                    && (tcb.rcv_nxt.wrapping_sub(seq_num) as i32) < seg_len_u32 as i32;

                if is_in_window || seq_num == tcb.rcv_nxt {
                    tcb_table().update(tcb.local, tcb.remote, |entry| {
                        entry.ts_ecr = peer_ts_val; // 次のACKのTSecrに使用
                        entry.ts_val = generate_tcp_timestamp();
                    });
                }
            }
        }
    }

    // 1. Check RST bit (RFC 793 / RFC 5961 Section 3.2)
    if is_rst {
        handle_rst_received(tcb, seq_num);
        return;
    }

    // 2. Check SYN bit (RFC 5961 Section 4.2)
    // Synchronized states: ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT
    // (Note: SynReceived is handled separately if needed, but here we assume synchronized)
    if is_syn {
        log::warn!(
            "[TCP] SYN in synchronized state {:?} from {} (seq={}), sending Challenge ACK (RFC 5961)",
            tcb.state,
            tcb.remote,
            seq_num
        );
        send_challenge_ack(&tcb);
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
        send_challenge_ack(&tcb);
        return;
    }

    // Acceptable ACK: Process it
    handle_ack_received(tcb, ack_num);

    // 4. Check URG bit (RFC 793 / RFC 6093)
    if is_urg && urgent_ptr > 0 {
        handle_urgent_received(tcb, seq_num, urgent_ptr);
    }

    // 5. Process segment data and FIN (RFC 793)
    if payload_len > 0 || is_fin {
        handle_data_received_with_delayed_ack(tcb, seq_num, data_payload, is_fin);
    }
}

/// Slow path データ受信処理 (Delayed ACK対応)
fn handle_data_received_with_delayed_ack(
    tcb: TcpControlBlockSnapshot,
    mut seq_num: u32,
    mut data_payload: PacketPayload,
    fin: bool,
) {
    let mut payload_len = data_payload.total_len() as u32;

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
                data_payload = PacketPayload::default();
            } else {
                // Entirely old, just send ACK
                send_ack_for_fast_path(&tcb, tcb.rcv_nxt);
                return;
            }
        } else {
            // Trim prefix
            if !crate::net::payload::discard_payload_prefix(&mut data_payload, skip) {
                send_ack_for_fast_path(&tcb, tcb.rcv_nxt);
                return;
            }
            payload_len -= skip as u32;
            seq_num = tcb.rcv_nxt;
        }
    }

    if seq_num != tcb.rcv_nxt {
        // Out-of-order: OOOキューに追加して即座に重複ACKを送信 (RFC 5681)
        ooo_queue::insert_ooo_segment(tcb.local, tcb.remote, seq_num, data_payload, fin);
        send_ack_for_fast_path(&tcb, tcb.rcv_nxt);
        return;
    }

    let mut new_rcv_nxt = tcb.rcv_nxt;
    let mut fin_encountered = false;

    // ソケットの受信バッファにデータ追加
    if let Some(socket) = get_socket_by_socket_id(tcb.socket_id) {
        if payload_len > 0 {
            let (pushed, _remainder) = socket.push_payload_with_remainder(data_payload);
            new_rcv_nxt = new_rcv_nxt.wrapping_add(pushed as u32);

            // RFC 1122: If some data could not be accepted, we MUST NOT advance
            // rcv_nxt past the accepted data.
            if (pushed as u32) < payload_len {
                // Buffer full, some data dropped.
                // Note: we don't process OOO or FIN if we couldn't take all data.
                tcb_table().update(tcb.local, tcb.remote, |entry| {
                    entry.rcv_nxt = new_rcv_nxt;
                });
                send_ack_for_fast_path(&tcb, new_rcv_nxt);
                return;
            }
        } else {
            // No payload, but maybe a zero-length segment or pure FIN
        }

        // OOOキューから連続セグメントをドレインしてバッファに追加
        let (drained_nxt, ooo_fin) = ooo_queue::drain_ooo_contiguous(
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
        handle_fin_in_order(tcb, new_rcv_nxt);
        return;
    }

    // TCB更新
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = new_rcv_nxt;
        // Delayed ACK: セグメントカウンタをインクリメント
        if entry.delayed_ack_pending == 0 {
            entry.delayed_ack_timer = tcb_table().get_current_tick();
        }
        entry.delayed_ack_pending = entry.delayed_ack_pending.saturating_add(1);
    });

    // Delayed ACK 判定 (RFC 1122 / 5681)
    // TIME_WAIT 状態では常に即座にACKを返す (RFC 793)
    let should_ack_now = if tcb.state == TcpConnectionState::TimeWait {
        true
    } else {
        tcb_table()
            .read(tcb.local, tcb.remote, |entry| {
                entry.delayed_ack_pending >= DELAYED_ACK_SEGMENTS
            })
            .unwrap_or(true)
    };

    if should_ack_now {
        send_ack_for_fast_path(&tcb, new_rcv_nxt);
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.delayed_ack_pending = 0;
        });
    }
}

/// 既存TCBに対するTCPセグメント処理
fn process_tcp_with_tcb(
    tcb: TcpControlBlockSnapshot,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    urgent_ptr: u16,
    options: &[u8],
    data_payload: PacketPayload,
) {
    let payload_len = data_payload.total_len();

    // RFC 7323 Section 5.8: PAWS (Protection Against Wrapped Sequence numbers)
    if tcb.ts_enabled && !options.is_empty() {
        let mut parser = TcpOptionParser::new(options);
        if let Some((peer_ts_val, _peer_ts_ecr)) = parser.find_timestamps() {
            if (flags & tcp_flags::RST) == 0 && peer_ts_val < tcb.ts_ecr {
                log::warn!(
                    "[TCP] PAWS check failed (TSval {} < TSrecent {}) for {} - dropping segment (RFC 7323)",
                    peer_ts_val,
                    tcb.ts_ecr,
                    tcb.remote
                );
                send_challenge_ack(&tcb);
                return;
            }
        }
    }

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
            send_challenge_ack(&tcb);
        }
        return;
    }

    match tcb.state {
        TcpConnectionState::SynSent => {
            handle_syn_sent_segment(tcb, flags, seq_num, ack_num, options);
        }
        TcpConnectionState::SynReceived => {
            // RFC 793: If ACK bit is set, check if acceptable and transition to Established
            if (flags & tcp_flags::ACK) != 0 {
                if ack_num.wrapping_sub(tcb.snd_una) as i32 > 0
                    && ack_num.wrapping_sub(tcb.snd_nxt) as i32 <= 0
                {
                    // Valid ACK: Transition to Established
                    tcb_table().update(tcb.local, tcb.remote, |entry| {
                        entry.snd_una = ack_num;
                        entry.state = TcpConnectionState::Established;
                    });

                    // Continue processing in Established state
                    if let Some(established_tcb) =
                        tcb_table().read(tcb.local, tcb.remote, |entry| {
                            TcpControlBlockSnapshot::from(entry)
                        })
                    {
                        handle_synchronized_segment(
                            established_tcb,
                            flags,
                            seq_num,
                            ack_num,
                            urgent_ptr,
                            options,
                            data_payload,
                        );
                    }
                } else if (flags & tcp_flags::RST) == 0 {
                    send_rst_for_unexpected_ack(&tcb, ack_num);
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
                tcb,
                flags,
                seq_num,
                ack_num,
                urgent_ptr,
                options,
                data_payload,
            );
        }
        _ => {}
    }
}

/// Handle ICMP Source Quench (RFC 1122 Section 4.2.3.9)
pub fn handle_source_quench(local: EndpointAddr, remote: EndpointAddr) {
    tcb_table().update(local, remote, |entry| {
        entry.on_source_quench();
    });
}

/// Handle ICMP Error (RFC 1122 Section 4.2.3.9)
pub fn handle_icmp_error(
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

    let mut should_close = false;
    let mut socket_id = None;

    tcb_table().update(local, remote, |entry| {
        // RFC 1122 Section 4.2.3.9: ICMP error handling
        // A TCP SHOULD notify the user of the error, but it SHOULD NOT close
        // the connection (it's a "soft" error), except for certain "hard"
        // errors in SYN-SENT state.
        if entry.state == TcpConnectionState::SynSent {
            match error {
                EndpointError::ConnectionRefused | EndpointError::ProtocolUnreachable => {
                    // Hard errors: close the connection (RFC 1122)
                    should_close = true;
                    socket_id = Some(entry.socket_id);
                }
                _ => {
                    // Soft errors (Host/Network unreachable): keep connection open,
                    // letting it time out naturally or succeed if route recovers.
                }
            }
        }

        // Notify the user of the error (RFC 1122 requirement)
        entry.on_icmp_error(error);
    });

    if should_close {
        log::info!(
            "[TCP] Connection failed due to ICMP error ({:?}) in SYN-SENT",
            error
        );
        if let Some(id) = socket_id {
            if let Some(socket) = get_socket_by_socket_id(id) {
                let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                inner.last_error = Some(error);
                if let Some(waker) = inner.connect_waker.take() {
                    waker.wake();
                }
            }
        }
    }
}

/// Handle ICMPv6 Error (RFC 4443 Section 3)
pub fn handle_icmpv6_error(
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

    let mut should_close = false;
    let mut socket_id = None;

    tcb_table().update(local, remote, |entry| {
        // RFC 4443 Section 2.4 / RFC 1122 Section 4.2.3.9
        if entry.state == TcpConnectionState::SynSent {
            match error {
                EndpointError::ConnectionRefused | EndpointError::ProtocolUnreachable => {
                    should_close = true;
                    socket_id = Some(entry.socket_id);
                }
                _ => {}
            }
        }
        entry.on_icmp_error(error);
    });

    if should_close {
        log::info!(
            "[TCP-V6] Connection failed due to ICMPv6 error ({:?}) in SYN-SENT",
            error
        );
        if let Some(id) = socket_id {
            if let Some(socket) = get_socket_by_socket_id(id) {
                let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                inner.last_error = Some(error);
                if let Some(waker) = inner.connect_waker.take() {
                    waker.wake();
                }
            }
        }
    }
}
/// SYN-ACK受信処理（クライアント側3ウェイハンドシェイク）
fn handle_syn_ack_received(
    tcb: TcpControlBlockSnapshot,
    seq_num: u32,
    ack_num: u32,
    options: &[u8],
) {
    // ACK番号を検証
    if ack_num != tcb.snd_nxt {
        log::info!(
            "TCP: Invalid SYN-ACK ack_num: expected {}, got {}",
            tcb.snd_nxt,
            ack_num
        );
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

    // TCB更新
    let updated = tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = seq_num.wrapping_add(1); // SYNは1バイト消費
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::Established;

        // TCP Timestamps (RFC 7323)
        if let Some((peer_ts_val, _)) = peer_ts {
            entry.ts_enabled = true;
            entry.ts_ecr = peer_ts_val;
            entry.ts_val = generate_tcp_timestamp();
        }

        // SACK negotiation
        if sack_permitted {
            entry.sack_enabled = true;
        }

        // MSS (RFC 793 / 1122)
        if let Some(mss) = peer_mss {
            entry.set_mss(mss as u32);
        }

        // Window Scale (RFC 7323)
        if let Some(ws) = peer_ws {
            entry.window_scale.enabled = true;
            entry.window_scale.set_snd_scale(ws);
        } else {
            // WSopt not present in SYN-ACK: disable scaling for this connection
            entry.window_scale.enabled = false;
        }
    });

    if !updated {
        return;
    }

    // ACKパケット送信
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(ack_num)
        .ack(seq_num.wrapping_add(1))
        .ack_flag()
        .window(65535);

    // TCP Timestamps: 3ウェイハンドシェイクの最終ACKにもTSoptを付与
    if let Some((peer_ts_val, _)) = peer_ts {
        let our_ts = generate_tcp_timestamp();
        builder = builder.nop().nop().timestamp(our_ts, peer_ts_val);
    }

    // パケット送信
    send_control_segment(tcb.local, tcb.remote, builder);
    log::info!(
        "TCP: Connection established {} <-> {}",
        tcb.local,
        tcb.remote
    );
}

/// Helper to get a socket by its file descriptor.
fn get_socket_by_socket_id(socket_id: SocketId) -> Option<Socket> {
    lookup_socket(socket_id)
}

/// Helper to notify a socket that it is connected.
fn notify_socket_connected(socket_id: SocketId) {
    if let Some(socket) = get_socket_by_socket_id(socket_id) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        let _ = inner.set_tcp_state(TcpSocketState::Connected);
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
    }
}

/// 新規接続処理（SYN受信 - サーバー側、またはCLOSED状態へのセグメント受信）
fn process_tcp_new_connection(
    local: EndpointAddr,
    remote: EndpointAddr,
    ingress_if_id: NetIfId,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    _urgent_ptr: u16,
    options: &[u8],
    data_payload: PacketPayload,
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;

    // RFC 793: If the connection does not exist (CLOSED) then a reset is sent
    // in response to any incoming segment except another reset.
    if is_rst {
        return;
    }

    // リッスン中のソケットを探す
    let socket = find_listening_tcp_socket(local, Some(ingress_if_id));

    // リッスン中のソケットがない場合、または SYN 以外を受信した場合
    if socket.is_none() || !is_syn {
        // ────────────────────────────────────────────────────────
        // 閉ポート宛: stateless RST with rate limiting
        // ────────────────────────────────────────────────────────
        // インターネット直結環境ではポートスキャンが大量に届く。
        // 各パケットにRSTを返すとイベントキュー（容量256）が溢れ、
        // 正規トラフィックの ResourceExhausted を引き起こす。
        // We still maintain a simple rate counter to avoid pathological
        // packet storms, but the RFC guidance is a **SHOULD** rather than a
        // **MUST**.  To remain compliant we always attempt to send the RST
        // even when the rate window has been exceeded; the underlying async
        // queue may still drop packets if it is full, but the host has at least
        // made an effort to respond.  The counter returned by
        // `closed_port_rst_dropped_count()` now reflects the number of packets
        // that *actually* dropped under the policy, useful for
        // telemetry.
        if !check_closed_port_rst_rate() {
            return;
        }

        // RFC 793 / RFC 9293 Section 3.10.7.1:
        // If the segment has an ACK field, the reset takes its sequence number
        // from the ACK field of the segment, otherwise the reset has sequence
        // number zero and the ACK field is set to the sum of the sequence
        // number and segment length of the incoming segment.

        let mut builder = TcpSegmentBuilder::new(local.port(), remote.port()).rst();

        if is_ack {
            // <SEQ=SEG.ACK><CTL=RST>
            builder = builder.seq(ack_num);
        } else {
            // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            let is_syn = (flags & tcp_flags::SYN) != 0;
            let is_fin = (flags & tcp_flags::FIN) != 0;
            let payload_len = data_payload.total_len();
            let seg_len = (if is_syn { 1 } else { 0 }) + (if is_fin { 1 } else { 0 });
            let ack = seq_num
                .wrapping_add(seg_len as u32)
                .wrapping_add(payload_len as u32);
            builder = builder.seq(0).ack(ack).ack_flag();
        }

        send_control_segment(local, remote, builder);
        return;
    }

    let Some(socket) = socket else {
        return;
    };
    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
    if !inner.is_tcp_listening() {
        return;
    }
    let nodelay = inner.tcp().map_or(false, |t| t.nodelay); // 設定を取得
    let priority = inner.priority;
    drop(inner);

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
    // Security: SYN Flood 対策として SYN Cookie を使用
    // SYN キューが半分以上埋まっている場合に発動
    let use_syncookies = tcb_table().syn_recv_count() > 2048;

    let isn = if use_syncookies {
        // MSS インデックスを選択 (簡易版: 相手の MSS を見て適切なものを選択)
        let mss_idx = match peer_mss {
            Some(m) if m >= 1460 => 2, // 1460 (Ethernet)
            Some(m) if m >= 536 => 1,  // 536 (Default)
            _ => 0,                    // 64
        };
        tcb_table().generate_syncookie(local, remote, seq_num, mss_idx)
    } else {
        tcb_table().generate_isn(local, remote)
    };

    let mut tcb = TcpControlBlockEntry::new(socket.socket_id(), local, remote);
    tcb.initialize_seq(isn);
    tcb.set_nodelay(nodelay);
    tcb.set_priority(priority); // 設定を反映
    tcb.rcv_nxt = seq_num.wrapping_add(1);
    tcb.state = TcpConnectionState::SynReceived;

    // TCP options negotiation (RFC 793 / 7323 / 2018)
    if let Some((peer_ts_val, _)) = peer_ts {
        tcb.ts_enabled = true;
        tcb.ts_ecr = peer_ts_val; // SYN-ACKのTSecr = 相手のTSval
    }
    if sack_permitted {
        tcb.sack_enabled = true;
    }
    if let Some(mss) = peer_mss {
        tcb.set_mss(mss as u32);
    }
    if let Some(ws) = peer_ws {
        tcb.window_scale.enabled = true;
        tcb.window_scale.set_snd_scale(ws);
    } else {
        // Peer did not send WSopt: disable scaling (RFC 7323)
        tcb.window_scale.enabled = false;
    }

    // TCB更新: SYN-ACKは1シーケンス番号を消費する (RFC 793)
    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);

    // SYN-ACK送信に必要な値をinsertの前にキャプチャ
    let ws_enabled = tcb.window_scale.enabled;
    let sack_opt = tcb.sack_enabled;
    let ts_enabled = tcb.ts_enabled;
    let isn = tcb.snd_nxt.wrapping_sub(1); // insert前のISN

    // SYN Cookie 使用時は TCB をテーブルに挿入しない (Stateless)
    if !use_syncookies {
        // TCBをテーブルに挿入 (リソース制限チェック)
        if let Err(e) = tcb_table().insert(tcb) {
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
    let ws_opt = if ws_enabled { Some(7) } else { None };
    let _ts_opt = if ts_enabled {
        Some(generate_tcp_timestamp())
    } else {
        None
    };

    let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
        .seq(isn)
        .ack(seq_num.wrapping_add(1))
        .syn()
        .ack_flag()
        .window(65535)
        .syn_options(1460, ws_opt, sack_opt, None);

    // TSopt付きSYN-ACK (RFC 7323 Section 3.2)
    if let Some((peer_ts_val, _)) = peer_ts {
        let our_ts = generate_tcp_timestamp();
        builder = builder.nop().nop().timestamp(our_ts, peer_ts_val);
    }

    // パケット送信
    send_control_segment(local, remote, builder);
    log::info!("TCP: SYN-ACK sent {} -> {}", local, remote);
}

/// RST受信処理 (RFC 5961準拠)
///
/// RFC 5961: RSTパケットのシーケンス番号がrcv_nxtと完全一致する場合のみ受理する。
/// ウィンドウ内だが不一致の場合はChallenge ACKを送信する。
/// ウィンドウ外の場合は黙って破棄する。
fn handle_rst_received(tcb: TcpControlBlockSnapshot, seq_num: u32) {
    if seq_num == tcb.rcv_nxt {
        // RFC 5961: 完全一致 → 接続をリセット
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.state = TcpConnectionState::Closed;
        });

        // ソケットにエラー通知
        if let Some(socket) = get_socket_by_socket_id(tcb.socket_id) {
            let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.last_error = Some(EndpointError::ConnectionRefused);
            if let Some(waker) = inner.connect_waker.take() {
                waker.wake();
            }
        }

        // リソースクリーンアップ
        retransmit_queue_remove(tcb.local, tcb.remote);
        ooo_queue::remove_ooo_queue(tcb.local, tcb.remote);
        tcb_table().remove(tcb.local, tcb.remote);
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
            send_challenge_ack(&tcb);
        }
        // ウィンドウ外のRSTは黙って破棄（RFC 5961）
    }
}

/// ACK受信処理（データ確認応答 + 輻輳制御）
fn handle_ack_received(tcb: TcpControlBlockSnapshot, ack_num: u32) {
    // RFC 793 validation: SND.UNA < SEG.ACK =< SND.NXT
    // ack_num > snd_nxt の場合、送信していないデータのACKなので不正。
    let diff_nxt = ack_num.wrapping_sub(tcb.snd_nxt) as i32;
    if diff_nxt > 0 {
        log::warn!(
            "[TCP] Received ACK for unsent data (ack={} > nxt={}), sending challenge ACK",
            ack_num,
            tcb.snd_nxt
        );
        send_challenge_ack(&tcb);
        return;
    }

    // 現在時刻を取得（輻輳制御アルゴリズム用）
    let current_time_ms = tcb_table().get_current_tick();

    // 重複ACK判定: ack_num == snd_una なら新データ未確認（重複ACK）
    let is_dup = ack_num == tcb.snd_una;

    let mut should_remove = false;
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        // 輻輳制御に委譲（snd_una更新含む）
        entry.on_ack_received(ack_num, is_dup, current_time_ms, 0);

        if !is_dup {
            entry.retransmit_count = 0;

            // RFC 793: State transitions on ACK
            match entry.state {
                TcpConnectionState::FinWait1 => {
                    if ack_num == entry.snd_nxt {
                        entry.state = TcpConnectionState::FinWait2;
                    }
                }
                TcpConnectionState::Closing => {
                    if ack_num == entry.snd_nxt {
                        entry.state = TcpConnectionState::TimeWait;
                    }
                }
                TcpConnectionState::LastAck => {
                    if ack_num == entry.snd_nxt {
                        entry.state = TcpConnectionState::Closed;
                        should_remove = true;
                    }
                }
                _ => {}
            }
        }
    });

    if should_remove {
        tcb_table().remove(tcb.local, tcb.remote);
    }

    // 再送キューからACK済みセグメントを削除（RTT測定も実行）
    retransmit_queue_ack(tcb.local, tcb.remote, ack_num);
}

/// SYN確認応答処理（サーバー側）
/// ハンドシェイク完了時にAcceptキューに追加
fn handle_ack_for_syn(tcb: TcpControlBlockSnapshot, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }
    let ingress_if_id = tcb.ingress_if_id.unwrap_or_default();

    // TCBを更新してEstablished状態に
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::Established;
    });

    log::info!(
        "TCP: Server connection established {} <- {}",
        tcb.local,
        tcb.remote
    );

    // 新しい接続用ソケットを作成
    let new_socket = match create_accepted_socket(tcb.local, tcb.remote, ingress_if_id) {
        Some(s) => s,
        None => {
            log::info!("TCP: Failed to create accepted socket");
            return;
        }
    };

    // Listeningソケットを探してAcceptキューに追加
    if !push_to_accept_queue(tcb.local.port(), Some(ingress_if_id), new_socket) {
        log::info!(
            "TCP: No listening socket found for port {}",
            tcb.local.port()
        );
    }
}

/// Accept用の新規ソケットを作成
fn create_accepted_socket(
    local: EndpointAddr,
    remote: EndpointAddr,
    ingress_if_id: NetIfId,
) -> Option<AcceptedConnection> {
    // 新しいFDを割り当て
    let new_socket_id = generate_socket_id()?;

    // TCB情報を更新してFDを紐付け
    tcb_table().update(local, remote, |entry| {
        entry.socket_id = new_socket_id;
    });

    // 再送キューを作成
    get_or_create_retransmit_queue(local, remote);

    Some(AcceptedConnection::new(
        new_socket_id,
        local,
        remote,
        ingress_if_id,
    ))
}

/// Listeningソケットを探してAcceptキューに追加
fn push_to_accept_queue(
    local_port: u16,
    ingress_if_id: Option<NetIfId>,
    conn: AcceptedConnection,
) -> bool {
    // ローカルポートでリッスン中のソケットを検索
    if let Some(socket) = find_listening_tcp_socket(conn.local_addr, ingress_if_id) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());

        // Listening状態でなければスキップ
        if !inner.is_tcp_listening() {
            return false;
        }

        // バックログがいっぱいでないか確認
        let tcp = match inner.tcp_mut() {
            Some(t) => t,
            None => return false,
        };
        if tcp.accept_queue.len() >= tcp.accept_backlog {
            log::info!("TCP: Accept queue full for port {}", local_port);
            return false;
        }

        // Acceptキューに追加
        tcp.accept_queue.push_back(conn);

        // Accept待ちのWakerを起こす
        if let Some(waker) = inner.accept_waker.take() {
            waker.wake();
        }

        log::info!(
            "TCP: Pushed to accept queue (queue_len={})",
            inner.tcp().map_or(0, |t| t.accept_queue.len())
        );

        return true;
    }

    false
}

/// 順序通りに到達した（またはOOOから復元された）FINを処理
fn handle_fin_in_order(tcb: TcpControlBlockSnapshot, rcv_nxt_at_fin: u32) {
    let mut should_ack = false;
    let mut final_rcv_nxt = rcv_nxt_at_fin;

    tcb_table().update(tcb.local, tcb.remote, |entry| {
        // FINは1シーケンス番号を消費 (RFC 793)
        entry.rcv_nxt = rcv_nxt_at_fin.wrapping_add(1);
        final_rcv_nxt = entry.rcv_nxt;

        match entry.state {
            TcpConnectionState::Established => {
                // ESTABLISHED → CLOSE_WAIT
                // 相手がクローズを開始。アプリケーションが明示的にcloseするまで待つ。
                entry.state = TcpConnectionState::CloseWait;
                should_ack = true;
                log::info!(
                    "[TCP] FIN received in ESTABLISHED: {} <- {} → CLOSE_WAIT",
                    entry.local,
                    entry.remote
                );
            }
            TcpConnectionState::FinWait1 => {
                // FIN_WAIT_1 → CLOSING (同時クローズ)
                // 我々のFINがまだACKされていないが、相手もFINを送信した
                entry.state = TcpConnectionState::Closing;
                should_ack = true;
                log::info!(
                    "[TCP] FIN received in FIN_WAIT_1: {} <- {} → CLOSING",
                    entry.local,
                    entry.remote
                );
            }
            TcpConnectionState::FinWait2 => {
                // FIN_WAIT_2 → TIME_WAIT
                // 正常なアクティブクローズの最終段階
                entry.state = TcpConnectionState::TimeWait;
                // TIME_WAIT開始時刻を記録
                entry.last_send_tick = tcb_table().get_current_tick();
                should_ack = true;
                log::info!(
                    "[TCP] FIN received in FIN_WAIT_2: {} <- {} → TIME_WAIT",
                    entry.local,
                    entry.remote
                );
            }
            _ => {
                // 他の状態ではFINは無視またはACKのみ
                should_ack = true;
            }
        }
    });

    if should_ack {
        // FINに対するACKを送信 (rcv_nxtは既に+1済み)
        send_ack_for_fast_path(&tcb, final_rcv_nxt);
    }

    // ソケットに接続相手のクローズを通知
    // recv_wakerを起こして、readがEOFを返せるようにする
    notify_socket_peer_fin(tcb.socket_id);
}

/// ソケットに相手側FIN受信を通知
///
/// recv_wakerを起こすことで、アプリケーション側のread操作が
/// EOF (0バイト読み取り) を返せるようにする。
fn notify_socket_peer_fin(socket_id: SocketId) {
    if let Some(socket) = lookup_socket(socket_id) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        // recv_wakerを起こしてEOFを通知
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }
}

/// Urgent data受信処理 (RFC 793/6093)
///
/// URGフラグが設定されたセグメントを受信した際の処理。
/// urgent pointerは、セグメント開始からurgent dataの最後のバイトまでのオフセットを示す。
fn handle_urgent_received(tcb: TcpControlBlockSnapshot, seq_num: u32, urgent_ptr: u16) {
    // TCBのurgent状態を更新
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        let has_new_urgent = entry.on_urgent_received(seq_num, urgent_ptr);

        if has_new_urgent {
            // ソケットにurgent dataの存在を通知
            notify_socket_urgent(entry.socket_id);
        }
    });
}

/// ソケットにurgent data到着を通知
fn notify_socket_urgent(socket_id: SocketId) {
    if let Some(socket) = lookup_socket(socket_id) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        // urgent flagを設定
        inner.set_urgent_pending(true);
        // recv wakerを起こす（OOBデータ待ちの可能性）
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }
}

// End of file
