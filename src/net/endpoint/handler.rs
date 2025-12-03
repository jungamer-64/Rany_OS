//! # NetworkEventHandler - ネットワークイベントハンドラ
//!
//! NetworkEventHandler, EventHandleResult

use alloc::vec::Vec;

use super::types::{SocketFd, SocketType, SocketError, SocketAddr, SocketResult};
use super::event::NetworkEvent;
use super::tcb::{TcbTable, TcpControlBlockEntry, TcpConnectionState, tcb_table};
use super::segment::TcpSegmentBuilder;
use super::manager::SOCKET_MANAGER;

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
            NetworkEvent::DataReady { fd, socket_type } => {
                self.handle_data_ready(fd, socket_type)
            }
            NetworkEvent::Connect { fd, local, remote } => {
                self.handle_connect(fd, local, remote)
            }
            NetworkEvent::Listen { fd, local, backlog } => {
                self.handle_listen(fd, local, backlog)
            }
            NetworkEvent::Close { fd } => self.handle_close(fd),
            NetworkEvent::SendTo { fd, data, remote } => {
                self.handle_send_to(fd, remote, data)
            }
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
        let data = {
            let mut inner = socket.inner().lock();
            if inner.send_buffer.is_empty() {
                return EventHandleResult::Success;
            }
            inner.send_buffer.drain(..).collect::<Vec<u8>>()
        };
        
        // TCPストリーム経由で送信（実際のプロトコルスタック呼び出し）
        let inner = socket.inner().lock();
        if let Some(ref _tcp_stream) = inner.tcp_stream {
            // TODO: TCP送信の実装
            // tcp_stream.send(&data)?;
            let _ = data; // 現時点では未使用警告を抑制
            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(SocketError::NotConnected)
        }
    }
    
    /// Connectイベント処理
    /// TCPハンドシェイクを開始（SYN送信）
    fn handle_connect(&self, fd: SocketFd, local: SocketAddr, remote: SocketAddr) -> EventHandleResult {
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
            crate::serial_println!("TCP: Failed to send SYN packet: {:?}", e);
            return EventHandleResult::ProtocolError(SocketError::Internal);
        }
        
        crate::serial_println!(
            "TCP: SYN sent {}:{} -> {}:{} (seq={})",
            local_addr.ip[0], local_addr.ip[1],
            remote.ip[0], remote.ip[1],
            isn
        );
        
        // 注: SYN-ACK受信後にWakerを起こす（受信処理側で行う）
        // ここではまだ接続は完了していない
        
        EventHandleResult::Success
    }
    
    /// TCPセグメント送信（IPスタック経由）
    fn send_tcp_segment(&self, src: SocketAddr, dst: SocketAddr, segment: Vec<u8>) -> SocketResult<()> {
        // IPv4パケットを構築して送信
        // 1. IPv4ヘッダ構築
        // 2. ネットワークスタック経由で送信
        
        // TODO: 実際のIP層との統合
        // 現時点ではスタブ実装
        let _ = (src, dst, segment);
        
        // グローバルネットワークスタックを使用
        // crate::net::stack::global_stack()?.send_ipv4(
        //     dst.ip,
        //     crate::net::ipv4::IpProtocol::TCP,
        //     &segment
        // )?;
        
        Ok(())
    }
    
    /// Listenイベント処理
    /// サーバーソケットを設定
    fn handle_listen(&self, fd: SocketFd, local: SocketAddr, backlog: u32) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(_socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        // TODO: TCP Listenの実装
        // 1. TCPリスナー登録
        // 2. 接続要求キューの設定
        let _ = (local, backlog);
        
        EventHandleResult::Success
    }
    
    /// Closeイベント処理
    /// 接続を終了
    fn handle_close(&self, fd: SocketFd) -> EventHandleResult {
        let manager = SOCKET_MANAGER.read();
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        let Some(_socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };
        
        // TODO: TCP終了処理
        // 1. FINパケット送信
        // 2. FIN-ACK待機
        // 3. リソース解放
        
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
        if let Some(ref _udp_socket) = inner.udp_socket {
            // TODO: UDP送信の実装
            // udp_socket.send_to(&data, addr)?;
            let _ = (remote, data);
            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(SocketError::InvalidStateTransition)
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
    // TODO: タスクスケジューラとの統合
    crate::serial_println!("Network: Event handler initialized");
}
