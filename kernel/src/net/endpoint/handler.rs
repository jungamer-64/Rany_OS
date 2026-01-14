//! # NetworkEventHandler - ネットワークイベントハンドラ
//!
//! NetworkEventHandler, EventHandleResult

use alloc::vec::Vec;

use super::event::NetworkEvent;
use super::manager::SOCKET_MANAGER;
use super::segment::TcpSegmentBuilder;
use super::tcb::{TcpConnectionState, TcpControlBlockEntry, tcb_table};
use super::types::{SocketAddr, SocketError, SocketFd, SocketResult, SocketType};

/// イベント処理の結果
#[derive(Debug)]
pub enum EventHandleResult {
    /// 処理成功
    Success,
    /// ソケットが見つからない
    SocketNotFound(SocketFd),
    /// プロトコルエラー
    ProtocolError(SocketError),
    /// 再試行が必要
    Retry,
}

/// ネットワークイベントハンドラ
/// プロトコルスタック（TCP/UDP）と連携する
pub struct NetworkEventHandler {
    /// ソケットマネージャへの参照を使用
    _marker: core::marker::PhantomData<()>,
}

impl NetworkEventHandler {
    /// 新規ハンドラ作成
    pub fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }

    /// イベントを処理
    pub fn handle_event(&self, event: NetworkEvent) -> EventHandleResult {
        match event {
            NetworkEvent::DataReady { fd, socket_type } => self.handle_data_ready(fd, socket_type),
            NetworkEvent::Connect { fd, local, remote } => self.handle_connect(fd, local, remote),
            NetworkEvent::Listen { fd, local, backlog } => self.handle_listen(fd, local, backlog),
            NetworkEvent::Close { fd } => self.handle_close(fd),
            NetworkEvent::SendTo { fd, data, remote } => self.handle_send_to(fd, remote, data),
        }
    }

    /// DataReadyイベント処理
    /// 送信バッファにデータがあるのでTCPで送信
    fn handle_data_ready(&self, fd: SocketFd, _socket_type: SocketType) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // 送信バッファからデータを取得
        let (data, local, remote) = {
            let mut inner = socket.inner().lock();
            if inner.send_buffer.is_empty() {
                return EventHandleResult::Success;
            }
            let local = match inner.local_addr {
                Some(addr) => addr,
                None => return EventHandleResult::ProtocolError(SocketError::NotConnected),
            };
            let remote = match inner.remote_addr {
                Some(addr) => addr,
                None => return EventHandleResult::ProtocolError(SocketError::NotConnected),
            };
            (
                inner.send_buffer.drain(..).collect::<Vec<u8>>(),
                local,
                remote,
            )
        };

        // TCBから現在のシーケンス番号を取得して更新
        let data_len = data.len() as u32;
        let result = tcb_table().lookup_mut(local, remote, |tcb| {
            if tcb.state != TcpConnectionState::Established {
                return Err(SocketError::NotConnected);
            }
            let seq = tcb.snd_nxt;
            let ack = tcb.rcv_nxt;
            let window = tcb.rcv_wnd;
            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(data_len);
            Ok((seq, ack, window))
        });

        let (seq, ack, window) = match result {
            Some(Ok(vals)) => vals,
            Some(Err(e)) => return EventHandleResult::ProtocolError(e),
            None => return EventHandleResult::ProtocolError(SocketError::NotConnected),
        };

        // TCPセグメントを構築
        let mut segment = TcpSegmentBuilder::new(local.port, remote.port)
            .seq(seq)
            .ack(ack)
            .psh() // PSH: 即座にアプリケーションに渡す
            .window(window)
            .payload(&data)
            .build();

        TcpSegmentBuilder::calculate_checksum(&mut segment, local.ip, remote.ip);

        // パケット送信
        if let Err(e) = self.send_tcp_segment(local, remote, segment) {
            log::info!("TCP: Failed to send data: {:?}", e);
            return EventHandleResult::ProtocolError(SocketError::Internal);
        }

        log::info!(
            "TCP: Sent {} bytes (seq={}, ack={}) fd={}",
            data.len(),
            seq,
            ack,
            fd.raw()
        );

        EventHandleResult::Success
    }

    /// Connectイベント処理
    /// TCPハンドシェイクを開始（SYN送信）
    fn handle_connect(
        &self,
        fd: SocketFd,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // ローカルポートが未割り当ての場合はエフェメラルポートを割り当て
        let local_port = if local.port == 0 {
            mgr.allocate_ephemeral_port(SocketType::Tcp)
                .unwrap_or(49152)
        } else {
            local.port
        };
        let local_addr = SocketAddr::new(local.ip, local_port);

        // ソケットのローカルアドレスを更新
        {
            let mut inner = socket.inner().lock();
            inner.local_addr = Some(local_addr);
        }

        // TCB（TCP Control Block）を作成
        let isn = tcb_table().generate_isn();
        let mut tcb = TcpControlBlockEntry::new(fd, local_addr, remote);
        tcb.initialize_seq(isn);
        tcb.state = TcpConnectionState::SynSent;
        tcb_table().insert(tcb);

        // SYNパケット構築
        let mut syn_segment = TcpSegmentBuilder::new(local_port, remote.port)
            .seq(isn)
            .syn()
            .window(65535)
            .build();

        // チェックサム計算
        TcpSegmentBuilder::calculate_checksum(&mut syn_segment, local_addr.ip, remote.ip);

        // パケット送信（IPスタック経由）
        if let Err(e) = self.send_tcp_segment(local_addr, remote, syn_segment) {
            log::info!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(SocketError::Internal);
        }

        log::info!(
            "TCP: SYN sent {}:{} -> {}:{} (seq={})",
            local_addr.ip[0],
            local_addr.ip[1],
            remote.ip[0],
            remote.ip[1],
            isn
        );

        // 注: SYN-ACK受信後にWakerを起こす（受信処理側で行う）
        // ここではまだ接続は完了していない

        EventHandleResult::Success
    }

    /// TCPセグメント送信（IPスタック経由）
    fn send_tcp_segment(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        segment: Vec<u8>,
    ) -> SocketResult<()> {
        // Convert addresses and forward to the global network stack
        let src_ip = crate::net::ipv4::Ipv4Address::new(src.ip);
        let dst_ip = crate::net::ipv4::Ipv4Address::new(dst.ip);

        if crate::net::stack::send_tcp(src_ip, dst_ip, &segment) {
            Ok(())
        } else {
            Err(SocketError::ResourceExhausted)
        }
    }

    /// Listenイベント処理
    /// サーバーソケットを設定
    fn handle_listen(&self, fd: SocketFd, local: SocketAddr, backlog: u32) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        // ローカルアドレスをソケットに設定
        {
            let mut inner = socket.inner().lock();
            inner.local_addr = Some(local);
        }

        // TCBテーブルにリスナーエントリを作成
        let mut tcb = TcpControlBlockEntry::new(
            fd,
            local,
            SocketAddr::new([0, 0, 0, 0], 0), // リモートは未定
        );
        tcb.state = TcpConnectionState::Listen;
        // backlog値を保存（接続要求キューの最大サイズ）
        // 注: 実際の接続要求キューはTCBテーブル側で管理
        let _ = backlog; // 現在のTCB構造体にはbacklogフィールドなし
        tcb_table().insert(tcb);

        log::info!(
            "TCP: Listening on {}:{} (fd={}, backlog={})",
            local.ip[0],
            local.ip[1],
            fd.raw(),
            backlog
        );

        EventHandleResult::Success
    }

    /// Closeイベント処理
    /// 接続を終了
    fn handle_close(&self, fd: SocketFd) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let inner = socket.inner().lock();
        let local = match inner.local_addr {
            Some(addr) => addr,
            None => {
                log::info!("TCP: Close failed - no local address");
                return EventHandleResult::ProtocolError(SocketError::Internal);
            }
        };
        let remote = match inner.remote_addr {
            Some(addr) => addr,
            None => {
                // リモートアドレスがない場合（Listenソケットなど）は直接クローズ
                tcb_table().remove_by_fd(fd);
                return EventHandleResult::Success;
            }
        };

        // TCBエントリの状態を取得
        let state = tcb_table()
            .lookup(local, remote)
            .map(|tcb| tcb.state)
            .unwrap_or(TcpConnectionState::Closed);

        match state {
            TcpConnectionState::Established => {
                // FINパケットを送信
                let seq = tcb_table()
                    .lookup_mut(local, remote, |tcb| {
                        let seq = tcb.snd_nxt;
                        tcb.state = TcpConnectionState::FinWait1;
                        seq
                    })
                    .unwrap_or(0);

                let mut fin_segment = TcpSegmentBuilder::new(local.port, remote.port)
                    .seq(seq)
                    .fin()
                    .ack(0) // ACKは最新の受信シーケンス番号
                    .window(65535)
                    .build();

                TcpSegmentBuilder::calculate_checksum(&mut fin_segment, local.ip, remote.ip);

                if let Err(e) = self.send_tcp_segment(local, remote, fin_segment) {
                    log::info!("TCP: Failed to send FIN: {:?}", e);
                    return EventHandleResult::ProtocolError(SocketError::Internal);
                }

                log::info!("TCP: FIN sent for fd={}", fd.raw());
            }
            TcpConnectionState::CloseWait => {
                // 相手からFINを受信済み、自分からFINを送信
                let seq = tcb_table()
                    .lookup_mut(local, remote, |tcb| {
                        let seq = tcb.snd_nxt;
                        tcb.state = TcpConnectionState::LastAck;
                        seq
                    })
                    .unwrap_or(0);

                let mut fin_segment = TcpSegmentBuilder::new(local.port, remote.port)
                    .seq(seq)
                    .fin()
                    .ack(0)
                    .window(65535)
                    .build();

                TcpSegmentBuilder::calculate_checksum(&mut fin_segment, local.ip, remote.ip);

                if let Err(e) = self.send_tcp_segment(local, remote, fin_segment) {
                    log::info!("TCP: Failed to send FIN (LastAck): {:?}", e);
                }
            }
            TcpConnectionState::Listen | TcpConnectionState::SynSent => {
                // まだ接続が確立していない場合は即座にクローズ
                tcb_table().remove(local, remote);
            }
            _ => {
                // 他の状態では何もしない（既にクローズ処理中など）
            }
        }

        EventHandleResult::Success
    }

    /// SendToイベント処理
    /// UDPパケットを送信
    fn handle_send_to(&self, fd: SocketFd, remote: SocketAddr, data: Vec<u8>) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let inner = socket.inner().lock();
        let local = match inner.local_addr {
            Some(addr) => addr,
            None => {
                // ローカルアドレスが未設定の場合はエフェメラルポートを使用
                let port = mgr
                    .allocate_ephemeral_port(SocketType::Udp)
                    .unwrap_or(49152);
                SocketAddr::new([0, 0, 0, 0], port)
            }
        };

        if inner.udp_socket.is_some() {
            // UDPパケットを構築
            // UDPヘッダ: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8バイト
            let udp_len = 8 + data.len();
            let mut udp_packet = Vec::with_capacity(udp_len);

            // Source port (2バイト)
            udp_packet.push((local.port >> 8) as u8);
            udp_packet.push(local.port as u8);

            // Destination port (2バイト)
            udp_packet.push((remote.port >> 8) as u8);
            udp_packet.push(remote.port as u8);

            // Length (2バイト) - ヘッダ + データ
            udp_packet.push((udp_len >> 8) as u8);
            udp_packet.push(udp_len as u8);

            // Checksum (2バイト) - 0 = チェックサム無効
            // 注: UDPでは計算してもオプション（IPv4の場合）
            udp_packet.push(0);
            udp_packet.push(0);

            // データ
            udp_packet.extend_from_slice(&data);

            // UDPパケット送信（IPスタック経由）
            if let Err(e) = self.send_udp_packet(local, remote, udp_packet) {
                log::info!("UDP: Failed to send packet: {:?}", e);
                return EventHandleResult::ProtocolError(SocketError::Internal);
            }

            log::info!(
                "UDP: Sent {} bytes to {}:{} from port {}",
                data.len(),
                remote.ip[0],
                remote.ip[1],
                local.port
            );

            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(SocketError::InvalidStateTransition)
        }
    }

    /// UDPパケット送信（IPスタック経由）
    fn send_udp_packet(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        packet: Vec<u8>,
    ) -> SocketResult<()> {
        // The `packet` contains a UDP header followed by payload. Extract payload.
        if packet.len() < 8 {
            return Err(SocketError::InvalidArgument);
        }

        let payload = &packet[8..];
        let dst_ip = crate::net::ipv4::Ipv4Address::new(dst.ip);

        if crate::net::stack::send_udp(src.port, dst_ip, dst.port, payload) {
            Ok(())
        } else {
            Err(SocketError::ResourceExhausted)
        }
    }
}

impl Default for NetworkEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// ネットワークイベント処理の初期化
pub fn init_network_event_handler() {
    // イベントキューは既に初期化済み（NETWORK_EVENT_QUEUE）
    // タスクスケジューラにnetwork_event_taskを登録する
    // Note: network_event_taskはasync関数なので、per_core_executor経由でspawnする
    // ネットワークイベント処理はCPU 0で実行（ネットワーク割り込みと同じコア）
    log::info!("Network: Event handler initialized");

    // タスクスポーン（実行時にエグゼキュータが初期化されている必要がある）
    // crate::task::per_core_executor::spawn(super::tcp_rx::network_event_task());
    // 上記は起動シーケンスで呼び出される必要があるため、ここではログのみ
}
