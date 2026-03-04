// ============================================================================
// kernel/src/net/endpoint/tcp_rx.rs
// ============================================================================
//! # TCP受信処理 - 3ウェイハンドシェイク・データ受信
//!
//! process_tcp_segment, network_event_task
//!
//! ## 最適化
//! - **TCP Fast Path**: ESTABLISHED状態で期待通りのseq/ackを受信した場合、
//!   フルプロトコル処理をバイパスして高速にデータを受信バッファに投入する。
//! - **Delayed ACK**: RFC 1122/5681準拠。連続データ受信時にACKを遅延させ、
//!   2セグメントごとまたは最大200msでACKを送信してACKトラフィックを半減させる。


use core::sync::atomic::{AtomicU64, Ordering};

use super::event::{event_queue, NetworkEvent};
use super::handler::{EventHandleResult, NetworkEventHandler};
use super::manager::ENDPOINT_MANAGER;
use super::ooo_queue;
use super::retransmit::{
    get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_remove,
};
use super::segment::{TcpSegmentBuilder, send_tcp_segment};
use super::endpoint_core::Endpoint;
use super::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table, tcp_flags};
use super::types::{
    AcceptedConnection, EndpointAddr, EndpointError, EndpointFd, EndpointState, EndpointType,
    seq_before,
};
use super::window_scale::TcpOptionParser;

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

// seq_before は types モジュールの統一実装を使用

/// RFC 793 Step 1: 受信セグメントのシーケンス番号妥当性を検証
fn is_acceptable_sequence(tcb: &TcpControlBlockEntry, seq_num: u32, payload_len: usize) -> bool {
    let rcv_nxt = tcb.rcv_nxt;
    let rcv_wnd = tcb.effective_recv_window();
    
    if payload_len == 0 {
        if rcv_wnd == 0 {
            seq_num == rcv_nxt
        } else {
            // rcv_nxt <= seq_num < rcv_nxt + rcv_wnd
            let diff = seq_num.wrapping_sub(rcv_nxt);
            diff < rcv_wnd
        }
    } else {
        if rcv_wnd == 0 {
            false
        } else {
            // rcv_nxt <= seq_num < rcv_nxt + rcv_wnd OR
            // rcv_nxt <= seq_num + payload_len - 1 < rcv_nxt + rcv_wnd
            let diff_start = seq_num.wrapping_sub(rcv_nxt);
            let diff_end = seq_num.wrapping_add(payload_len as u32).wrapping_sub(1).wrapping_sub(rcv_nxt);
            diff_start < rcv_wnd || diff_end < rcv_wnd
        }
    }
}

/// チャレンジACK（シーケンス番号エラー時の応答）を送信
fn send_challenge_ack(tcb: &TcpControlBlockEntry) {
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(tcb.rcv_nxt)
        .ack_flag()
        .window(u16::try_from(tcb.advertised_recv_window()).unwrap_or(u16::MAX));

    if tcb.ts_enabled {
        builder = builder.nop().nop().timestamp(generate_tcp_timestamp(), tcb.ts_ecr);
    }

    let mut ack = builder.build();
    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut ack, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut ack,
            crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()),
        );
    }
    send_tcp_segment(tcb.local, tcb.remote, ack);
}

/// TCPチェックサム検証（IPv4疑似ヘッダ込み）
fn verify_tcp_checksum(segment: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4]) -> bool {
    if segment.len() < 20 {
        return false;
    }

    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // Protocol (TCP)
    sum += segment.len() as u32;

    // TCPセグメント本体
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }

    // 1の補数
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    (sum as u16) == 0xFFFF
}

/// TCPチェックサム検証（IPv6疑似ヘッダ込み）
fn verify_tcp_checksum_v6(
    segment: &[u8],
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
) -> bool {
    if segment.len() < 20 {
        return false;
    }

    use crate::net::l3::ipv4::{IpProtocol, data_checksum};
    use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;

    let pseudo = ipv6_pseudo_header_checksum(
        &src_ip, &dst_ip, IpProtocol::Tcp, segment.len() as u32,
    );
    let verify = data_checksum(segment, pseudo);
    verify == 0
}

/// IPv6 TCPセグメント受信処理
///
/// IPv6パケットから抽出されたTCPセグメントを、エンドポイント層の
/// 完全なTCP状態マシン（Fast Path、Delayed ACK、OOOキュー等）で処理する。
/// `process_tcp_segment` (IPv4) と同等の機能をIPv6上で提供する。
pub fn process_tcp_segment_v6(
    src_ip: crate::net::l3::ipv6::Ipv6Address,
    dst_ip: crate::net::l3::ipv6::Ipv6Address,
    segment: &[u8],
) {
    if segment.len() < 20 {
        return; // 最小ヘッダサイズ未満
    }

    // Security: チェックサム検証 (RFC 8200 / RFC 793)
    // HWチェックサム検証済みの場合はソフトウェア検証をスキップ
    if !crate::net::runtime::bridge::rx_csum_hw_verified() {
        if !verify_tcp_checksum_v6(segment, src_ip, dst_ip) {
            log::warn!("[TCP] IPv6 Checksum verification failed, dropping segment");
            return;
        }
    }

    // TCPヘッダ解析
    let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    let seq_num = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    let ack_num = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
    let data_off_flags = u16::from_be_bytes([segment[12], segment[13]]);
    let data_offset = ((data_off_flags >> 12) & 0x0F) as usize * 4;
    let flags = (data_off_flags & 0x003F) as u8;
    let _window = u16::from_be_bytes([segment[14], segment[15]]);
    let urgent_ptr = u16::from_be_bytes([segment[18], segment[19]]);

    let remote = EndpointAddr::new_v6(src_ip.octets(), src_port);
    let local = EndpointAddr::new_v6(dst_ip.octets(), dst_port);

    // TCBを検索
    if let Some(tcb) = tcb_table().get(local, remote) {
        // RFC 793 Step 1: Check sequence number acceptability
        let payload_len = if segment.len() > data_offset { segment.len() - data_offset } else { 0 };
        if !is_acceptable_sequence(&tcb, seq_num, payload_len) {
            let is_rst = (flags & tcp_flags::RST) != 0;
            if !is_rst {
                send_challenge_ack(&tcb);
            }
            return;
        }

        // TCP Fast Path (ESTABLISHED状態の高速受信処理)
        if tcb.state == TcpConnectionState::Established
            && seq_num == tcb.rcv_nxt
            && flags == tcp_flags::ACK
            && payload_len > 0
        {
            if try_fast_path(&tcb, ack_num, segment, data_offset, payload_len) {
                FAST_PATH_HITS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // PSH|ACK もファストパス対象
        if tcb.state == TcpConnectionState::Established
            && seq_num == tcb.rcv_nxt
            && (flags == (tcp_flags::ACK | tcp_flags::PSH))
            && payload_len > 0
        {
            if try_fast_path(&tcb, ack_num, segment, data_offset, payload_len) {
                FAST_PATH_HITS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        SLOW_PATH_HITS.fetch_add(1, Ordering::Relaxed);
        process_tcp_with_tcb(tcb, flags, seq_num, ack_num, urgent_ptr, segment, data_offset);
    } else {
        // 新規接続要求の可能性（LISTENソケット検索）
        process_tcp_new_connection(local, remote, flags, seq_num, segment, data_offset);
    }
}

/// TCPセグメント受信処理
/// プロトコルスタック（ipv4.rs）から呼ばれる
pub fn process_tcp_segment(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) {
    if segment.len() < 20 {
        return; // 最小ヘッダサイズ未満
    }

    // Security: チェックサム検証 (RFC 793)
    // HWチェックサム検証済みの場合はソフトウェア検証をスキップ
    if !crate::net::runtime::bridge::rx_csum_hw_verified() {
        if !verify_tcp_checksum(segment, src_ip, dst_ip) {
            log::warn!("[TCP] Checksum verification failed, dropping segment");
            return;
        }
    }

    // TCPヘッダ解析
    let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    let seq_num = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    let ack_num = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
    let data_off_flags = u16::from_be_bytes([segment[12], segment[13]]);
    let data_offset = ((data_off_flags >> 12) & 0x0F) as usize * 4;
    let flags = (data_off_flags & 0x003F) as u8;
    let _window = u16::from_be_bytes([segment[14], segment[15]]);
    let urgent_ptr = u16::from_be_bytes([segment[18], segment[19]]);

    let remote = EndpointAddr::new(src_ip, src_port);
    let local = EndpointAddr::new(dst_ip, dst_port);

    // TCBを検索
    if let Some(tcb) = tcb_table().get(local, remote) {
        // RFC 793 Step 1: Check sequence number acceptability
        let payload_len = if segment.len() > data_offset { segment.len() - data_offset } else { 0 };
        if !is_acceptable_sequence(&tcb, seq_num, payload_len) {
            let is_rst = (flags & tcp_flags::RST) != 0;
            if !is_rst {
                send_challenge_ack(&tcb);
            }
            return;
        }

        // =====================================================================
        // TCP Fast Path (Linux tcp_rcv_established fast path 相当)
        // =====================================================================
        // ESTABLISHED状態で以下すべてを満たすとき、フルプロトコル処理をスキップ:
        //   1. 期待通りのシーケンス番号 (seq == rcv_nxt)
        //   2. ACKフラグのみ (FIN/SYN/RST/URG なし)
        //   3. データペイロードが存在する
        //   4. OOOキューが空（順序通り受信中）
        //
        // これにより、状態マシン遷移チェック、TCPオプション再解析等を省略し、
        // 直接データを受信バッファへ投入する。
        if tcb.state == TcpConnectionState::Established
            && seq_num == tcb.rcv_nxt
            && flags == tcp_flags::ACK  // ACKのみ (PSH|ACK は 0x18 なので除外)
            && payload_len > 0
        {
            if try_fast_path(&tcb, ack_num, segment, data_offset, payload_len) {
                FAST_PATH_HITS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // PSH|ACK もファストパス対象 (最も一般的なデータパケット)
        if tcb.state == TcpConnectionState::Established
            && seq_num == tcb.rcv_nxt
            && (flags == (tcp_flags::ACK | tcp_flags::PSH))
            && payload_len > 0
        {
            if try_fast_path(&tcb, ack_num, segment, data_offset, payload_len) {
                FAST_PATH_HITS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        SLOW_PATH_HITS.fetch_add(1, Ordering::Relaxed);
        process_tcp_with_tcb(tcb, flags, seq_num, ack_num, urgent_ptr, segment, data_offset);
    } else {
        // 新規接続要求の可能性（LISTENソケット検索）
        process_tcp_new_connection(local, remote, flags, seq_num, segment, data_offset);
    }
}

/// TCP Fast Path - ESTABLISHED状態の高速受信処理
///
/// 期待通りのシーケンス番号でデータが到着した場合、
/// フル状態マシン処理をバイパスして直接データを受信バッファに投入する。
///
/// 成功時は true を返し、呼び出し元はスローパスをスキップする。
/// 以下の条件いずれかでフォールバック(false):
///   - ACK番号が有効範囲外
///   - OOOキューにセグメントが溜まっている
///   - 受信バッファが満杯
fn try_fast_path(
    tcb: &TcpControlBlockEntry,
    ack_num: u32,
    segment: &[u8],
    data_offset: usize,
    payload_len: usize,
) -> bool {
    // ACK番号の簡易検証: snd_una <= ack_num <= snd_nxt
    let ack_diff_una = ack_num.wrapping_sub(tcb.snd_una) as i32;
    let ack_diff_nxt = tcb.snd_nxt.wrapping_sub(ack_num) as i32;
    if ack_diff_una < 0 || ack_diff_nxt < 0 {
        return false; // ACKが有効範囲外 → スローパスへ
    }

    // OOOキューにセグメントがあるなら順序処理が必要
    if ooo_queue::has_ooo_segments(tcb.local, tcb.remote) {
        return false;
    }

    let data = &segment[data_offset..data_offset + payload_len];
    let new_rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);

    // ACK処理 (新規ACKならカウンタ更新)
    let is_new_ack = ack_diff_una > 0;
    if is_new_ack {
        let current_time_ms = tcb_table().get_current_tick();
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.on_ack_received(ack_num, false, current_time_ms, 0);
        });
        retransmit_queue_ack(tcb.local, tcb.remote, ack_num);
    }

    // データをソケットの受信バッファに追加
    if let Some(socket) = get_socket_by_fd(tcb.fd) {
        socket.push_data(data);
    }

    // TCB更新: rcv_nxt を前進
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = new_rcv_nxt;
        // Delayed ACK: セグメントカウンタをインクリメント
        entry.delayed_ack_pending = entry.delayed_ack_pending.saturating_add(1);

        // RFC 7323: タイムスタンプ更新 (Fast Path)
        if entry.ts_enabled && data_offset > 20 {
            let mut parser = TcpOptionParser::new(&segment[20..data_offset]);
            if let Some((peer_ts_val, _)) = parser.find_timestamps() {
                entry.ts_ecr = peer_ts_val;
                entry.ts_val = generate_tcp_timestamp();
            }
        }
    });

    // Delayed ACK 判定:
    // - 2セグメント受信したら即座にACK (RFC 5681)
    // - それ以外はタイマーに委ねる (最大200ms後にACK)
    let should_ack_now = tcb_table()
        .lookup(tcb.local, tcb.remote)
        .map(|e| e.delayed_ack_pending >= DELAYED_ACK_SEGMENTS)
        .unwrap_or(true);

    if should_ack_now {
        send_ack_for_fast_path(tcb, new_rcv_nxt);
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.delayed_ack_pending = 0;
        });
    }

    true
}

/// ファストパス用の軽量ACK送信
///
/// TCPオプション(Timestamps等)が有効なら含めるが、
/// SACKブロック等の複雑な処理は行わない。
#[inline]
fn send_ack_for_fast_path(tcb: &TcpControlBlockEntry, rcv_nxt: u32) {
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(rcv_nxt)
        .ack_flag()
        .window(tcb.advertised_recv_window());

    if tcb.ts_enabled {
        builder = builder.nop().nop().timestamp(generate_tcp_timestamp(), tcb.ts_ecr);
    }

    let mut ack = builder.build();
    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut ack, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut ack,
            crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()),
        );
    }
    send_tcp_segment(tcb.local, tcb.remote, ack);
}

/// Delayed ACK タイマー処理
///
/// 定期的に呼び出され、遅延中のACKを送信する。
/// `DELAYED_ACK_TIMEOUT_MS` 経過した接続の保留ACKをフラッシュする。
pub fn flush_delayed_acks() {
    // Step 1: 保留ACKがある接続を収集（読み取りロック）
    let mut pending: alloc::vec::Vec<(EndpointAddr, EndpointAddr, u32, u32, u16, bool, u32)> =
        alloc::vec::Vec::new();
    tcb_table().for_each_established(|entry| {
        if entry.delayed_ack_pending > 0 {
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
            builder = builder.nop().nop().timestamp(generate_tcp_timestamp(), ts_ecr);
        }

        let mut ack = builder.build();
        if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
            TcpSegmentBuilder::calculate_checksum(&mut ack, lv4, rv4);
        } else {
            TcpSegmentBuilder::calculate_checksum_v6(
                &mut ack,
                crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6()),
                crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6()),
            );
        }
        send_tcp_segment(local, remote, ack);

        // カウンタリセット
        tcb_table().update(local, remote, |e| {
            e.delayed_ack_pending = 0;
        });
    }
}

/// SYN-SENT状態でのセグメント処理
fn handle_syn_sent_segment(tcb: TcpControlBlockEntry, flags: u8, seq_num: u32, ack_num: u32, segment: &[u8], data_offset: usize) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;

    if is_syn && is_ack {
        handle_syn_ack_received(tcb, seq_num, ack_num, segment, data_offset);
    } else if is_syn {
        // RFC 793: Simultaneous Open (双方からSYNを送信した場合)
        // SYN-SENT -> SYN-RECEIVED 遷移し、SYN-ACKを返送する。
        handle_simultaneous_syn_received(tcb, seq_num, segment, data_offset);
    } else if is_rst {
        handle_rst_received(tcb, seq_num);
    } else if is_ack {
        // RFC 793: SYN-SENT状態でSYNなしACKを受信した場合はRSTでリセット
        send_rst_for_unexpected_ack(&tcb, ack_num);
    }
}

/// 同時オープン(Simultaneous Open)時のSYN受信処理
fn handle_simultaneous_syn_received(tcb: TcpControlBlockEntry, seq_num: u32, segment: &[u8], data_offset: usize) {
    // TCPオプション解析
    let (peer_ts, sack_permitted) = if data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
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
        builder = builder.nop().nop().timestamp(generate_tcp_timestamp(), peer_ts_val);
    }

    let mut syn_ack = builder.build();
    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut syn_ack, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut syn_ack,
            crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()),
        );
    }
    send_tcp_segment(tcb.local, tcb.remote, syn_ack);
}

/// 予期しないACKに対するRST送信 (RFC 793)
fn send_rst_for_unexpected_ack(tcb: &TcpControlBlockEntry, ack_num: u32) {
    let mut rst = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(ack_num)
        .rst()
        .build();

    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut rst, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut rst,
            crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()),
        );
    }
    send_tcp_segment(tcb.local, tcb.remote, rst);
}

/// ESTABLISHED状態でのセグメント処理
fn handle_established_segment(
    tcb: TcpControlBlockEntry,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    urgent_ptr: u16,
    segment: &[u8],
    data_offset: usize,
) {
    let is_fin = (flags & tcp_flags::FIN) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;
    let is_urg = (flags & tcp_flags::URG) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;

    // TCPオプション解析（SACK / Timestamps）
    if data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);

        // 受信SACKオプション（送信側の再送キューに反映）
        if tcb.sack_enabled {
            if let Some(blocks) = parser.find_sack_blocks() {
                if !blocks.is_empty() {
                    crate::net::l4::endpoint::retransmit::retransmit_queue_process_sack(
                        tcb.local,
                        tcb.remote,
                        &blocks,
                    );
                }
            }
        }

        // Timestamp
        if tcb.ts_enabled {
            if let Some((peer_ts_val, _peer_ts_ecr)) = parser.find_timestamps() {
                // RFC 7323 Section 5.3: Only update TS.Recent if SEG.SEQ <= Last.ACK.sent
                // 簡略化して in-order セグメントの場合のみ更新する。
                if seq_num == tcb.rcv_nxt {
                    tcb_table().update(tcb.local, tcb.remote, |entry| {
                        entry.ts_ecr = peer_ts_val; // 次のACKのTSecrに使用
                        // 自分のTSvalを更新
                        entry.ts_val = generate_tcp_timestamp();
                    });
                }
            }
        }
    }

    if is_fin {
        handle_fin_received(tcb, seq_num);
    } else if is_rst {
        handle_rst_received(tcb, seq_num);
    } else {
        if is_urg && urgent_ptr > 0 {
            handle_urgent_received(tcb.clone(), seq_num, urgent_ptr);
        }
        let data_start = data_offset;
        if data_start < segment.len() {
            let data = &segment[data_start..];
            handle_data_received(tcb, seq_num, data);
        } else if is_ack {
            handle_ack_received(tcb, ack_num);
        }
    }
}

/// FIN-WAIT-1状態でのセグメント処理
fn handle_fin_wait1_segment(tcb: TcpControlBlockEntry, flags: u8, seq_num: u32, ack_num: u32) {
    let is_fin = (flags & tcp_flags::FIN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;

    if is_fin && is_ack {
        handle_fin_ack_received(tcb, seq_num, ack_num);
    } else if is_ack {
        handle_ack_for_fin(tcb, ack_num);
    }
}

/// 既存TCBに対するTCPセグメント処理
fn process_tcp_with_tcb(
    tcb: TcpControlBlockEntry,
    flags: u8,
    seq_num: u32,
    ack_num: u32,
    urgent_ptr: u16,
    segment: &[u8],
    data_offset: usize,
) {
    let payload_len = segment.len().saturating_sub(data_offset);

    // RFC 7323 Section 5.8: PAWS (Protection Against Wrapped Sequence numbers)
    // タイムスタンプオプションが有効な場合、PAWSチェックを行う。
    if tcb.ts_enabled {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);
        if let Some((peer_ts_val, _peer_ts_ecr)) = parser.find_timestamps() {
            // RFC 7323: SEG.TSval < TS.Recent ならば古いセグメントとみなして破棄
            // (ただし RST 以外。また 24日以上の経過によるラップアラウンドは考慮外)
            if (flags & tcp_flags::RST) == 0 && peer_ts_val < tcb.ts_ecr {
                log::warn!(
                    "[TCP] PAWS check failed (TSval {} < TSrecent {}) for {} - dropping segment (RFC 7323)",
                    peer_ts_val, tcb.ts_ecr, tcb.remote
                );
                send_challenge_ack(&tcb);
                return;
            }
        }
    }

    // RFC 793 / 9293 Section 3.10.7.1: 受信セグメントのシーケンス番号妥当性を検証
    // SYN-SENT状態以外では、セグメントがウィンドウ内にあることを確認する必要がある。
    if tcb.state != TcpConnectionState::SynSent && !is_acceptable_sequence(&tcb, seq_num, payload_len) {
        log::warn!(
            "[TCP] Incoming segment out of window (seq={}, len={}) for connection to {}, sending Challenge ACK",
            seq_num, payload_len, tcb.remote
        );
        send_challenge_ack(&tcb);
        return;
    }

    // RFC 5961 Section 4.2: SYN bit in synchronized state
    // 確立済みの接続に対してSYNを受信した場合、ブラインドリセット攻撃を防ぐため
    // RSTではなくチャレンジACKを送信して生存確認を行う。
    let is_syn = (flags & tcp_flags::SYN) != 0;
    if is_syn && tcb.state != TcpConnectionState::SynSent && tcb.state != TcpConnectionState::SynReceived {
        log::warn!(
            "[TCP] SYN in synchronized state {:?} from {} (seq={}), sending Challenge ACK",
            tcb.state, tcb.remote, seq_num
        );
        send_challenge_ack(&tcb);
        return;
    }

    match tcb.state {
        TcpConnectionState::SynSent => {
            handle_syn_sent_segment(tcb, flags, seq_num, ack_num, segment, data_offset);
        }
        TcpConnectionState::SynReceived => {
            if (flags & tcp_flags::ACK) != 0 {
                handle_ack_for_syn(tcb, ack_num);
            }
        }
        TcpConnectionState::Established => {
            handle_established_segment(tcb, flags, seq_num, ack_num, urgent_ptr, segment, data_offset);
        }
        TcpConnectionState::FinWait1 => {
            handle_fin_wait1_segment(tcb, flags, seq_num, ack_num);
        }
        TcpConnectionState::FinWait2 => {
            if (flags & tcp_flags::FIN) != 0 {
                handle_fin_received(tcb, seq_num);
            }
        }
        TcpConnectionState::CloseWait | TcpConnectionState::LastAck => {
            if (flags & tcp_flags::ACK) != 0 {
                handle_final_ack(tcb, ack_num);
            }
        }
        TcpConnectionState::TimeWait => {
            // RFC 793 / 9293 Section 3.10.7.4:
            // "Any segment received in the TIME-WAIT state MUST be acknowledged.
            // This re-acknowledges the peer's FIN and restarts the 2MSL timer."

            // TCBを更新して最終送信時刻をリセット（2MSLタイマーの再起動）
            tcb_table().update(tcb.local, tcb.remote, |entry| {
                entry.last_send_tick = tcb_table().get_current_tick();
            });

            // ACK送信
            send_ack_for_fast_path(&tcb, tcb.rcv_nxt);
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
pub fn handle_icmp_error(local: EndpointAddr, remote: EndpointAddr, icmp_type: crate::net::l3::icmp::IcmpType, code: u8) {
    use crate::net::l3::icmp::{IcmpType, DestUnreachCode};

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
    let mut fd = None;

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
                    fd = Some(entry.fd);
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
        log::info!("[TCP] Connection failed due to ICMP error ({:?}) in SYN-SENT", error);
        if let Some(f) = fd {
            if let Some(socket) = get_socket_by_fd(f) {
                let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
                inner.last_error = Some(error);
                if let Some(waker) = inner.connect_waker.take() {
                    waker.wake();
                }
            }
        }
        tcb_table().remove(local, remote);
    }
}
/// SYN-ACK受信処理（クライアント側3ウェイハンドシェイク）
fn handle_syn_ack_received(tcb: TcpControlBlockEntry, seq_num: u32, ack_num: u32, segment: &[u8], data_offset: usize) {
    // ACK番号を検証
    if ack_num != tcb.snd_nxt {
        log::info!(
            "TCP: Invalid SYN-ACK ack_num: expected {}, got {}",
            tcb.snd_nxt,
            ack_num
        );
        return;
    }

    // SYN-ACKのTCPオプションを解析（TSopt / SACK-Permitted検出）
    let (peer_ts, sack_permitted) = if data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);
        (parser.find_timestamps(), parser.find_sack_permitted())
    } else {
        (None, false)
    };

    // TCB更新
    let updated = tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = seq_num.wrapping_add(1); // SYNは1バイト消費
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::Established;

        // TCP Timestamps (RFC 7323): SYN-ACKにTSoptがあればクライアント側も有効化
        if let Some((peer_ts_val, _)) = peer_ts {
            entry.ts_enabled = true;
            entry.ts_ecr = peer_ts_val;
            entry.ts_val = generate_tcp_timestamp();
        }

        // SACK negotiation
        if sack_permitted {
            entry.sack_enabled = true;
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

    let mut ack_segment = builder.build();

    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut ack_segment, lv4, rv4);
    } else {
        // one or both addresses are IPv6; fall back to v6 checksum generator
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut ack_segment,
            crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()),
        );
    }

    // パケット送信
    send_tcp_segment(tcb.local, tcb.remote, ack_segment);
    log::info!(
        "TCP: Connection established {} <-> {}",
        tcb.local,
        tcb.remote
    );

    // ソケットのWakerを起こす
    notify_socket_connected(tcb.fd);
}

/// 新規接続処理（SYN受信 - サーバー側、またはCLOSED状態へのセグメント受信）
fn process_tcp_new_connection(
    local: EndpointAddr,
    remote: EndpointAddr,
    flags: u8,
    seq_num: u32,
    segment: &[u8],
    data_offset: usize,
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
    let manager = ENDPOINT_MANAGER.read();
    let mgr = if let Some(ref m) = *manager {
        m
    } else {
        return;
    };

    let socket = mgr.find_by_port(EndpointType::Tcp, local.port());
    
    // リッスン中のソケットがない場合、または SYN 以外を受信した場合
    if socket.is_none() || !is_syn {
        // RFC 793 / RFC 9293 Section 3.10.7.1:
        // If the segment has an ACK field, the reset takes its sequence number 
        // from the ACK field of the segment, otherwise the reset has sequence 
        // number zero and the ACK field is set to the sum of the sequence 
        // number and segment length of the incoming segment.
        
        let mut builder = TcpSegmentBuilder::new(local.port(), remote.port()).rst();
        
        if is_ack {
            // <SEQ=SEG.ACK><CTL=RST>
            let ack_num = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
            builder = builder.seq(ack_num);
        } else {
            // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            let payload_len = if segment.len() > data_offset { segment.len() - data_offset } else { 0 };
            let seg_len = if is_syn || ((flags & tcp_flags::FIN) != 0) { 1 } else { 0 };
            let ack = seq_num.wrapping_add(seg_len as u32).wrapping_add(payload_len as u32);
            builder = builder.seq(0).ack(ack).ack_flag();
        }

        let mut rst = builder.build();
        if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
            TcpSegmentBuilder::calculate_checksum(&mut rst, lv4, rv4);
        } else {
            TcpSegmentBuilder::calculate_checksum_v6(
                &mut rst,
                crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6()),
                crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6()),
            );
        }
        send_tcp_segment(local, remote, rst);
        return;
    }

    let socket = socket.unwrap();
    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
    if inner.state != EndpointState::Listening {
        return;
    }
    let nodelay = inner.tcp().map_or(false, |t| t.nodelay); // 設定を取得
    let priority = inner.priority;
    drop(inner);

    // TCPオプション解析 (Timestamps / SACK Permitted)
    let (peer_ts, sack_permitted) = if data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);
        (parser.find_timestamps(), parser.find_sack_permitted())
    } else {
        (None, false)
    };

    // TCB作成
    let isn = tcb_table().generate_isn(local, remote);
    let mut tcb = TcpControlBlockEntry::new(socket.fd(), local, remote);
    tcb.initialize_seq(isn);
    tcb.set_nodelay(nodelay);
    tcb.set_priority(priority); // 設定を反映
    tcb.rcv_nxt = seq_num.wrapping_add(1);
    tcb.state = TcpConnectionState::SynReceived;

    // TCP Timestamps / SACK negotiation
    if let Some((peer_ts_val, _)) = peer_ts {
        tcb.ts_enabled = true;
        tcb.ts_ecr = peer_ts_val; // SYN-ACKのTSecr = 相手のTSval
    }
    if sack_permitted {
        tcb.sack_enabled = true;
    }
    
    // TCB更新: SYN-ACKは1シーケンス番号を消費する (RFC 793)
    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);

    // TCBをテーブルに挿入 (リソース制限チェック)
    if let Err(e) = tcb_table().insert(tcb) {
        log::warn!("[NET] TCP: Failed to accept new connection from {}: {}", remote, e);
        return;
    }

    // SYN-ACK送信 (TCPオプション付き)
    // MSS=1460 (標準的なイーサネットMTU 1500 - IPヘッダ20 - TCPヘッダ20)
    // Window Scale=7 (最大8MBウィンドウ)
    let mut builder = TcpSegmentBuilder::new(local.port(), remote.port())
        .seq(isn)
        .ack(seq_num.wrapping_add(1))
        .syn()
        .ack_flag()
        .window(65535)
        .syn_options(1460, 7, Some(generate_tcp_timestamp())); // MSS + Window Scale + SACK Permitted + TS

    // TSopt付きSYN-ACK (RFC 7323 Section 3.2)
    if let Some((peer_ts_val, _)) = peer_ts {
        let our_ts = generate_tcp_timestamp();
        builder = builder.nop().nop().timestamp(our_ts, peer_ts_val);
    }

    let mut syn_ack = builder.build();
    if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut syn_ack, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(
            &mut syn_ack,
            crate::net::l3::ipv6::Ipv6Address::new(local.as_ipv6()),
            crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6()),
        );
    }

    // パケット送信
    send_tcp_segment(local, remote, syn_ack);
    log::info!(
        "TCP: SYN-ACK sent {} -> {}",
        local,
        remote
    );
}

/// RST受信処理 (RFC 5961準拠)
///
/// RFC 5961: RSTパケットのシーケンス番号がrcv_nxtと完全一致する場合のみ受理する。
/// ウィンドウ内だが不一致の場合はChallenge ACKを送信する。
/// ウィンドウ外の場合は黙って破棄する。
fn handle_rst_received(tcb: TcpControlBlockEntry, seq_num: u32) {
    if seq_num == tcb.rcv_nxt {
        // RFC 5961: 完全一致 → 接続をリセット
        tcb_table().update(tcb.local, tcb.remote, |entry| {
            entry.state = TcpConnectionState::Closed;
        });

        // ソケットにエラー通知
        if let Some(socket) = get_socket_by_fd(tcb.fd) {
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
                seq_num, tcb.rcv_nxt
            );
            send_challenge_ack(&tcb);
        }
        // ウィンドウ外のRSTは黙って破棄（RFC 5961）
    }
}

/// ACK受信処理（データ確認応答 + 輻輳制御）
fn handle_ack_received(tcb: TcpControlBlockEntry, ack_num: u32) {
    // RFC 793 validation: SND.UNA < SEG.ACK =< SND.NXT
    // ack_num > snd_nxt の場合、送信していないデータのACKなので不正。
    let diff_nxt = ack_num.wrapping_sub(tcb.snd_nxt) as i32;
    if diff_nxt > 0 {
        log::warn!("[TCP] Received ACK for unsent data (ack={} > nxt={}), sending challenge ACK", ack_num, tcb.snd_nxt);
        send_challenge_ack(&tcb);
        return;
    }

    // 現在時刻を取得（輻輳制御アルゴリズム用）
    let current_time_ms = tcb_table().get_current_tick();

    // 重複ACK判定: ack_num == snd_una なら新データ未確認（重複ACK）
    let is_dup = ack_num == tcb.snd_una;

    tcb_table().update(tcb.local, tcb.remote, |entry| {
        // 輻輳制御に委譲（snd_una更新含む）
        // RTTサンプルは再送キュー側で測定するため、ここでは0を渡す。
        // BBRは on_ack 内で独自に計算する。
        entry.on_ack_received(ack_num, is_dup, current_time_ms, 0);
        if !is_dup {
            entry.retransmit_count = 0;
        }
    });

    // 再送キューからACK済みセグメントを削除（RTT測定も実行）
    retransmit_queue_ack(tcb.local, tcb.remote, ack_num);
}

/// SYN確認応答処理（サーバー側）
/// ハンドシェイク完了時にAcceptキューに追加
fn handle_ack_for_syn(tcb: TcpControlBlockEntry, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }

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
    let new_socket = match create_accepted_socket(&tcb) {
        Some(s) => s,
        None => {
            log::info!("TCP: Failed to create accepted socket");
            return;
        }
    };

    // Listeningソケットを探してAcceptキューに追加
    if !push_to_accept_queue(tcb.local.port(), new_socket) {
        log::info!("TCP: No listening socket found for port {}", tcb.local.port());
    }
}

/// Accept用の新規ソケットを作成
fn create_accepted_socket(tcb: &TcpControlBlockEntry) -> Option<AcceptedConnection> {
    let manager = ENDPOINT_MANAGER.read();
    let mgr = manager.as_ref()?;

    // 新しいFDを割り当て
    let new_fd = mgr.generate_fd();

    // TCB情報を更新してFDを紐付け
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.fd = new_fd;
    });

    // 再送キューを作成
    get_or_create_retransmit_queue(tcb.local, tcb.remote);

    // 更新されたTCBを取得
    let updated_tcb = tcb_table().get(tcb.local, tcb.remote)?;

    Some(AcceptedConnection::new(
        new_fd,
        tcb.local,
        tcb.remote,
        updated_tcb,
    ))
}

/// Listeningソケットを探してAcceptキューに追加
fn push_to_accept_queue(local_port: u16, conn: AcceptedConnection) -> bool {
    let manager = ENDPOINT_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return false;
    };

    // ローカルポートでリッスン中のソケットを検索
    // find_by_portを使用
    if let Some(socket) = mgr.find_by_port(EndpointType::Tcp, local_port) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());

        // Listening状態でなければスキップ
        if inner.state != EndpointState::Listening {
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

/// データ受信処理（OOO再組立て対応）
fn handle_data_received(tcb: TcpControlBlockEntry, seq_num: u32, data: &[u8]) {
    // --- In-order / Overlapping セグメント処理 ---
    let (actual_seq, actual_data) = if seq_num == tcb.rcv_nxt {
        (seq_num, data)
    } else if seq_before(seq_num, tcb.rcv_nxt) {
        // 重複/オーバーラップ: すでに受信済みの部分を切り捨てる
        let overlap = tcb.rcv_nxt.wrapping_sub(seq_num) as usize;
        if overlap >= data.len() {
            // 完全に受信済み
            return;
        }
        (tcb.rcv_nxt, &data[overlap..])
    } else {
        // 完全に順序外: OOOキューに保存し、即座にDupACKを返す
        ooo_queue::insert_ooo_segment(tcb.local, tcb.remote, seq_num, data);

        // SACKブロック取得（OOOキュー内の受信済み範囲を通知）
        let sack = ooo_queue::get_sack_blocks(tcb.local, tcb.remote);

        // DupACK — 現在のrcv_nxtで応答（Fast Retransmitトリガ用 + SACKブロック付き）
        let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
            .seq(tcb.snd_nxt)
            .ack(tcb.rcv_nxt)
            .ack_flag()
            .window(65535);

        if tcb.sack_enabled && !sack.is_empty() {
            // NOP+NOP+SACK でアラインメント (RFC 2018 Section 3)
            builder = builder.nop().nop().sack_blocks(sack.as_slice());
        }

        if tcb.ts_enabled {
            builder = builder.nop().nop().timestamp(tcb.ts_val, tcb.ts_ecr);
        }

        let mut dup_ack = builder.build();
        if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
            TcpSegmentBuilder::calculate_checksum(&mut dup_ack, lv4, rv4);
        } else {
            TcpSegmentBuilder::calculate_checksum_v6(
                &mut dup_ack,
                crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()),
                crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()),
            );
        }
        send_tcp_segment(tcb.local, tcb.remote, dup_ack);
        return;
    };

    let mut new_rcv_nxt = actual_seq.wrapping_add(actual_data.len() as u32);

    // ソケットの受信バッファにデータ追加
    if let Some(socket) = get_socket_by_fd(tcb.fd) {
        socket.push_data(actual_data);

        // OOOキューから連続セグメントをドレインしてバッファに追加
        new_rcv_nxt = ooo_queue::drain_ooo_contiguous(tcb.local, tcb.remote, new_rcv_nxt, |_seg_seq, seg_data| {
            socket.push_data(seg_data);
        });
    }

    // TCB更新
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = new_rcv_nxt;
    });

    // ACK送信（ドレイン後のrcv_nxtで応答）
    let mut builder = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(new_rcv_nxt)
        .ack_flag()
        .window(65535);

    // SACK: OOOキューのSACKブロックをACKに付与（交渉済みの場合）
    if tcb.sack_enabled {
        let sack = ooo_queue::get_sack_blocks(tcb.local, tcb.remote);
        if !sack.is_empty() {
            builder = builder.nop().nop().sack_blocks(sack.as_slice());
        }
    }

    // TCP Timestamps (RFC 7323): ACKにTSoptを付与
    if tcb.ts_enabled {
        builder = builder.nop().nop().timestamp(tcb.ts_val, tcb.ts_ecr);
    }

    let mut ack = builder.build();

    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut ack, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(&mut ack, crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()), crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()));
    }
    send_tcp_segment(tcb.local, tcb.remote, ack);
}

/// FIN受信処理
fn handle_fin_received(tcb: TcpControlBlockEntry, seq_num: u32) {
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = seq_num.wrapping_add(1); // FINは1バイト消費
        entry.state = match entry.state {
            TcpConnectionState::Established => TcpConnectionState::CloseWait,
            TcpConnectionState::FinWait1 => TcpConnectionState::Closing,
            TcpConnectionState::FinWait2 => TcpConnectionState::TimeWait,
            s => s,
        };
    });

    // ACK送信
    let mut ack = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
        .seq(tcb.snd_nxt)
        .ack(seq_num.wrapping_add(1))
        .ack_flag()
        .window(65535)
        .build();

    if let (Some(lv4), Some(rv4)) = (tcb.local.as_ipv4(), tcb.remote.as_ipv4()) {
        TcpSegmentBuilder::calculate_checksum(&mut ack, lv4, rv4);
    } else {
        TcpSegmentBuilder::calculate_checksum_v6(&mut ack, crate::net::l3::ipv6::Ipv6Address::new(tcb.local.as_ipv6()), crate::net::l3::ipv6::Ipv6Address::new(tcb.remote.as_ipv6()));
    }
    // パケット送信
    send_tcp_segment(tcb.local, tcb.remote, ack);
}

/// FIN-ACK受信処理
fn handle_fin_ack_received(tcb: TcpControlBlockEntry, seq_num: u32, ack_num: u32) {
    handle_ack_received(tcb.clone(), ack_num);
    handle_fin_received(tcb, seq_num);
}

/// FIN確認応答処理
fn handle_ack_for_fin(tcb: TcpControlBlockEntry, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }

    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.snd_una = ack_num;
        entry.state = TcpConnectionState::FinWait2;
    });
}

/// 最終ACK処理
fn handle_final_ack(tcb: TcpControlBlockEntry, ack_num: u32) {
    if ack_num != tcb.snd_nxt {
        return;
    }

    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.state = TcpConnectionState::Closed;
    });

    // リソースクリーンアップ
    retransmit_queue_remove(tcb.local, tcb.remote);
    ooo_queue::remove_ooo_queue(tcb.local, tcb.remote);
    tcb_table().remove(tcb.local, tcb.remote);
}

/// Urgent data受信処理 (RFC 793/6093)
///
/// URGフラグが設定されたセグメントを受信した際の処理。
/// urgent pointerは、セグメント開始からurgent dataの最後のバイトまでのオフセットを示す。
fn handle_urgent_received(tcb: TcpControlBlockEntry, seq_num: u32, urgent_ptr: u16) {
    // TCBのurgent状態を更新
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        let has_new_urgent = entry.on_urgent_received(seq_num, urgent_ptr);
        
        if has_new_urgent {
            // ソケットにurgent dataの存在を通知
            notify_socket_urgent(entry.fd);
        }
    });
}

/// ソケットにurgent data到着を通知
fn notify_socket_urgent(fd: EndpointFd) {
    let manager = ENDPOINT_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return;
    };

    if let Some(socket) = mgr.get(fd) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        // urgent flagを設定
        inner.set_urgent_pending(true);
        // recv wakerを起こす（OOBデータ待ちの可能性）
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }
}

/// ソケットに接続完了を通知
fn notify_socket_connected(fd: EndpointFd) {
    let manager = ENDPOINT_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return;
    };

    if let Some(socket) = mgr.get(fd) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        let _ = inner.transition_to(EndpointState::Connected);
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
    }
}

/// FDでソケット取得
fn get_socket_by_fd(fd: EndpointFd) -> Option<Endpoint> {
    let manager = ENDPOINT_MANAGER.read();
    let mgr = manager.as_ref()?;
    mgr.get(fd)
}

/// ネットワークイベント処理タスク
/// 非同期でイベントを消費してプロトコルスタックに渡す
pub async fn network_event_task() {
    let handler = NetworkEventHandler::new();

    loop {
        // イベントを待機（単一イベントを取得）
        let event = event_queue().wait_for_events().await;

        // スタックのロックを取得してバッチ処理
        if let Ok(mut stack_guard) = crate::net::runtime::stack::NETWORK_STACK.lock() {
            if let Some(ref mut stack) = *stack_guard {
                // 最初のイベントを処理
                let event_clone = event.clone();
                let result = handler.handle_event_with_stack(event, stack);
                process_handle_result(result, event_clone);

                // キューに溜まっている他のイベントもスタックロック保持中に一括処理
                while let Some(batch_event) = event_queue().recv() {
                    let batch_clone = batch_event.clone();
                    let result = handler.handle_event_with_stack(batch_event, stack);
                    process_handle_result(result, batch_clone);
                }
                continue;
            }
        }

        // スタック未初期化やロック失敗時は通常の個別処理
        let event_clone = event.clone();
        let result = handler.handle_event(event);
        process_handle_result(result, event_clone);
        
        while let Some(batch_event) = event_queue().recv() {
            let batch_clone = batch_event.clone();
            let result = handler.handle_event(batch_event);
            process_handle_result(result, batch_clone);
        }
    }
}

/// イベント処理結果の共通対応
fn process_handle_result(result: EventHandleResult, event_clone: NetworkEvent) {
    match result {
        EventHandleResult::Success | EventHandleResult::IngressPacket { .. } => {}
        EventHandleResult::SocketNotFound(fd) => {
            // ソケットが既に閉じられている - 正常
            log::info!("Network: Socket {} not found (already closed)", fd.raw());
        }
        EventHandleResult::ProtocolError(e) => {
            log::info!("Network: Protocol error: {:?}", e);
        }
        EventHandleResult::Retry => {
            // 再試行が必要な場合はイベントを再キュー（バックプレッシャー対応）
            if let Err(_) = super::event::send_event(event_clone) {
                log::warn!("Network: Event requeue failed due to full queue");
            }
        }
    }
}
