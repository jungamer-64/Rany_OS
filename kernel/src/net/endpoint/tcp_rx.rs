// ============================================================================
// kernel/src/net/endpoint/tcp_rx.rs
// ============================================================================
//! # TCP受信処理 - 3ウェイハンドシェイク・データ受信
//!
//! process_tcp_segment, network_event_task

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use super::event::event_queue;
use super::handler::{EventHandleResult, NetworkEventHandler};
use super::manager::SOCKET_MANAGER;
use super::ooo_queue;
use super::retransmit::{
    get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_remove,
};
use super::segment::{TcpSegmentBuilder, send_tcp_segment};
use super::socket::Socket;
use super::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table, tcp_flags};
use super::types::{
    AcceptedConnection, SocketAddr, SocketError, SocketFd, SocketState, SocketType,
};
use super::window_scale::TcpOptionParser;

/// TCPタイムスタンプ値を生成（10ms粒度、RFC 7323準拠）
fn generate_tcp_timestamp() -> u32 {
    let ms = tcb_table().get_current_tick();
    (ms / 10) as u32
}

/// TCPセグメント受信処理
/// プロトコルスタック（ipv4.rs）から呼ばれる
pub fn process_tcp_segment(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) {
    if segment.len() < 20 {
        return; // 最小ヘッダサイズ未満
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

    let remote = SocketAddr::new(src_ip, src_port);
    let local = SocketAddr::new(dst_ip, dst_port);

    // TCBを検索
    if let Some(tcb) = tcb_table().get(local, remote) {
        process_tcp_with_tcb(tcb, flags, seq_num, ack_num, urgent_ptr, segment, data_offset);
    } else {
        // 新規接続要求の可能性（LISTENソケット検索）
        process_tcp_new_connection(local, remote, flags, seq_num, segment, data_offset);
    }
}

/// SYN-SENT状態でのセグメント処理
fn handle_syn_sent_segment(tcb: TcpControlBlockEntry, flags: u8, seq_num: u32, ack_num: u32, segment: &[u8], data_offset: usize) {
    let is_syn = (flags & tcp_flags::SYN) != 0;
    let is_ack = (flags & tcp_flags::ACK) != 0;
    let is_rst = (flags & tcp_flags::RST) != 0;

    if is_syn && is_ack {
        handle_syn_ack_received(tcb, seq_num, ack_num, segment, data_offset);
    } else if is_rst {
        handle_rst_received(tcb);
    }
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

    // TCP Timestamps (RFC 7323): 受信セグメントのTSvalをTCBに記録
    if tcb.ts_enabled && data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);
        if let Some((peer_ts_val, _peer_ts_ecr)) = parser.find_timestamps() {
            tcb_table().update(tcb.local, tcb.remote, |entry| {
                entry.ts_ecr = peer_ts_val; // 次のACKのTSecrに使用
                // 自分のTSvalを更新
                entry.ts_val = generate_tcp_timestamp();
            });
        }
    }

    if is_fin {
        handle_fin_received(tcb, seq_num);
    } else if is_rst {
        handle_rst_received(tcb);
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
        _ => {}
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

    // SYN-ACKのTCPオプションを解析（TSopt検出）
    let peer_ts = if data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);
        parser.find_timestamps()
    } else {
        None
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
    });

    if !updated {
        return;
    }

    // ACKパケット送信
    let mut builder = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
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

    TcpSegmentBuilder::calculate_checksum(&mut ack_segment, tcb.local.ip, tcb.remote.ip);

    // パケット送信
    send_tcp_segment(tcb.local, tcb.remote, ack_segment);
    log::info!(
        "TCP: Connection established {}:{} <-> {}:{}",
        tcb.local.ip[0],
        tcb.local.port,
        tcb.remote.ip[0],
        tcb.remote.port
    );

    // ソケットのWakerを起こす
    notify_socket_connected(tcb.fd);
}

/// 新規接続処理（SYN受信 - サーバー側）
fn process_tcp_new_connection(
    local: SocketAddr,
    remote: SocketAddr,
    flags: u8,
    seq_num: u32,
    segment: &[u8],
    data_offset: usize,
) {
    let is_syn = (flags & tcp_flags::SYN) != 0;

    if !is_syn {
        // SYN以外の新規接続は無視（またはRST送信）
        return;
    }

    // SYNのTCPオプションを解析（TSopt検出）
    let peer_ts = if data_offset > 20 && data_offset <= segment.len() {
        let options = &segment[20..data_offset];
        let mut parser = TcpOptionParser::new(options);
        parser.find_timestamps()
    } else {
        None
    };

    // リッスン中のソケットを探す
    let manager = SOCKET_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return;
    };

    let socket = mgr.find_by_port(SocketType::Tcp, local.port);
    let Some(socket) = socket else {
        // リッスン中のソケットがない → RST送信
        let mut rst = TcpSegmentBuilder::new(local.port, remote.port)
            .seq(0)
            .ack(seq_num.wrapping_add(1))
            .rst()
            .ack_flag()
            .window(0)
            .build();
        TcpSegmentBuilder::calculate_checksum(&mut rst, local.ip, remote.ip);
        send_tcp_segment(local, remote, rst);
        return;
    };

    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
    if inner.state != SocketState::Listening {
        return;
    }
    drop(inner);

    // TCB作成
    let isn = tcb_table().generate_isn();
    let mut tcb = TcpControlBlockEntry::new(socket.fd(), local, remote);
    tcb.initialize_seq(isn);
    tcb.rcv_nxt = seq_num.wrapping_add(1);
    tcb.state = TcpConnectionState::SynReceived;

    // TCP Timestamps (RFC 7323): SYNにTSoptがあれば有効化
    if let Some((peer_ts_val, _)) = peer_ts {
        tcb.ts_enabled = true;
        tcb.ts_ecr = peer_ts_val; // SYN-ACKのTSecr = 相手のTSval
    }
    tcb_table().insert(tcb);

    // SYN-ACK送信 (TCPオプション付き)
    // MSS=1460 (標準的なイーサネットMTU 1500 - IPヘッダ20 - TCPヘッダ20)
    // Window Scale=7 (最大8MBウィンドウ)
    let mut builder = TcpSegmentBuilder::new(local.port, remote.port)
        .seq(isn)
        .ack(seq_num.wrapping_add(1))
        .syn()
        .ack_flag()
        .window(65535)
        .syn_options(1460, 7); // MSS + Window Scale + SACK Permitted

    // TSopt付きSYN-ACK (RFC 7323 Section 3.2)
    if let Some((peer_ts_val, _)) = peer_ts {
        let our_ts = generate_tcp_timestamp();
        builder = builder.nop().nop().timestamp(our_ts, peer_ts_val);
    }

    let mut syn_ack = builder.build();
    TcpSegmentBuilder::calculate_checksum(&mut syn_ack, local.ip, remote.ip);

    // パケット送信
    send_tcp_segment(local, remote, syn_ack);
    log::info!(
        "TCP: SYN-ACK sent {}:{} -> {}:{}",
        local.ip[0],
        local.port,
        remote.ip[0],
        remote.port
    );
}

/// RST受信処理
fn handle_rst_received(tcb: TcpControlBlockEntry) {
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.state = TcpConnectionState::Closed;
    });

    // ソケットにエラー通知
    if let Some(socket) = get_socket_by_fd(tcb.fd) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.last_error = Some(SocketError::ConnectionRefused);
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
    }

    // リソースクリーンアップ
    retransmit_queue_remove(tcb.local, tcb.remote);
    ooo_queue::remove_ooo_queue(tcb.local, tcb.remote);
    tcb_table().remove(tcb.local, tcb.remote);
}

/// ACK受信処理（データ確認応答 + 輻輳制御）
fn handle_ack_received(tcb: TcpControlBlockEntry, ack_num: u32) {
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
        "TCP: Server connection established {}:{} <- {}:{}",
        tcb.local.ip[0],
        tcb.local.port,
        tcb.remote.ip[0],
        tcb.remote.port
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
    if !push_to_accept_queue(tcb.local.port, new_socket) {
        log::info!("TCP: No listening socket found for port {}", tcb.local.port);
    }
}

/// Accept用の新規ソケットを作成
fn create_accepted_socket(tcb: &TcpControlBlockEntry) -> Option<AcceptedConnection> {
    let manager = SOCKET_MANAGER.read();
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
    let manager = SOCKET_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return false;
    };

    // ローカルポートでリッスン中のソケットを検索
    // find_by_portを使用
    if let Some(socket) = mgr.find_by_port(SocketType::Tcp, local_port) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());

        // Listening状態でなければスキップ
        if inner.state != SocketState::Listening {
            return false;
        }

        // バックログがいっぱいでないか確認
        if inner.accept_queue.len() >= inner.accept_backlog {
            log::info!("TCP: Accept queue full for port {}", local_port);
            return false;
        }

        // Acceptキューに追加
        inner.accept_queue.push_back(conn);

        // Accept待ちのWakerを起こす
        if let Some(waker) = inner.accept_waker.take() {
            waker.wake();
        }

        log::info!(
            "TCP: Pushed to accept queue (queue_len={})",
            inner.accept_queue.len()
        );

        return true;
    }

    false
}

/// データ受信処理（OOO再組立て対応）
fn handle_data_received(tcb: TcpControlBlockEntry, seq_num: u32, data: &[u8]) {
    if seq_num != tcb.rcv_nxt {
        // Out-of-order: OOOキューに保存し、即座にDupACKを返す
        ooo_queue::insert_ooo_segment(tcb.local, tcb.remote, seq_num, data);

        // SACKブロック取得（OOOキュー内の受信済み範囲を通知）
        let sack = ooo_queue::get_sack_blocks(tcb.local, tcb.remote);

        // DupACK — 現在のrcv_nxtで応答（Fast Retransmitトリガ用 + SACKブロック付き）
        let mut builder = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
            .seq(tcb.snd_nxt)
            .ack(tcb.rcv_nxt)
            .ack_flag()
            .window(65535);

        // TCP Timestamps (RFC 7323): DupACKにもTSoptを付与
        if tcb.ts_enabled {
            builder = builder.nop().nop().timestamp(tcb.ts_val, tcb.ts_ecr);
        }

        if !sack.is_empty() {
            // NOP+NOP+SACK でアラインメント (RFC 2018 Section 3)
            builder = builder.nop().nop().sack_blocks(&sack);
        }

        let mut dup_ack = builder.build();
        TcpSegmentBuilder::calculate_checksum(&mut dup_ack, tcb.local.ip, tcb.remote.ip);
        send_tcp_segment(tcb.local, tcb.remote, dup_ack);
        return;
    }

    // --- In-order セグメント処理 ---
    let mut new_rcv_nxt = tcb.rcv_nxt.wrapping_add(data.len() as u32);

    // ソケットの受信バッファにデータ追加
    if let Some(socket) = get_socket_by_fd(tcb.fd) {
        socket.push_data(data);

        // OOOキューから連続セグメントをドレインしてバッファに追加
        let (drained, final_rcv_nxt) =
            ooo_queue::drain_ooo_contiguous(tcb.local, tcb.remote, new_rcv_nxt);
        for (_seg_seq, seg_data) in &drained {
            socket.push_data(seg_data);
        }
        new_rcv_nxt = final_rcv_nxt;
    }

    // TCB更新
    tcb_table().update(tcb.local, tcb.remote, |entry| {
        entry.rcv_nxt = new_rcv_nxt;
    });

    // ACK送信（ドレイン後のrcv_nxtで応答）
    let mut builder = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
        .seq(tcb.snd_nxt)
        .ack(new_rcv_nxt)
        .ack_flag()
        .window(65535);

    // TCP Timestamps (RFC 7323): ACKにTSoptを付与
    if tcb.ts_enabled {
        builder = builder.nop().nop().timestamp(tcb.ts_val, tcb.ts_ecr);
    }

    let mut ack = builder.build();

    TcpSegmentBuilder::calculate_checksum(&mut ack, tcb.local.ip, tcb.remote.ip);
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
    let mut ack = TcpSegmentBuilder::new(tcb.local.port, tcb.remote.port)
        .seq(tcb.snd_nxt)
        .ack(seq_num.wrapping_add(1))
        .ack_flag()
        .window(65535)
        .build();

    TcpSegmentBuilder::calculate_checksum(&mut ack, tcb.local.ip, tcb.remote.ip);
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
fn notify_socket_urgent(fd: SocketFd) {
    let manager = SOCKET_MANAGER.read();
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
fn notify_socket_connected(fd: SocketFd) {
    let manager = SOCKET_MANAGER.read();
    let Some(ref mgr) = *manager else {
        return;
    };

    if let Some(socket) = mgr.get(fd) {
        let mut inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        let _ = inner.transition_to(SocketState::Connected);
        if let Some(waker) = inner.connect_waker.take() {
            waker.wake();
        }
    }
}

/// FDでソケット取得
fn get_socket_by_fd(fd: SocketFd) -> Option<Socket> {
    let manager = SOCKET_MANAGER.read();
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

        // イベントを処理
        let event_clone = event.clone();
        let result = handler.handle_event(event);
        match result {
            EventHandleResult::Success => {}
            EventHandleResult::SocketNotFound(fd) => {
                // ソケットが既に閉じられている - 正常
                log::info!("Network: Socket {} not found (already closed)", fd.raw());
            }
            EventHandleResult::ProtocolError(e) => {
                log::info!("Network: Protocol error: {:?}", e);
            }
            EventHandleResult::Retry => {
                // 再試行が必要な場合はイベントを再キュー
                if let Err(_) = super::event::send_event(event_clone) {
                    log::warn!("Network: Event requeue failed due to full queue");
                }
            }
        }

        // 残りのイベントも処理（バッチ処理）
        while let Some(event) = event_queue().recv() {
            let event_clone = event.clone();
            let result = handler.handle_event(event);
            match result {
                EventHandleResult::SocketNotFound(fd) => {
                    log::info!("Network: Socket {} not found", fd.raw());
                }
                EventHandleResult::Retry => {
                    // 再試行イベントを再キュー
                    if let Err(_) = super::event::send_event(event_clone) {
                        log::warn!("Network: Event requeue failed due to full queue");
                    }
                }
                _ => {}
            }
        }
    }
}
