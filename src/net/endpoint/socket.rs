//! # Socket - Arc<Mutex<SocketInner>>ラッパー
//!
//! Socket, OwnedSocket, および関連ヘルパー関数

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::Mutex;

use crate::net::tcp::{TcpStream, TcpListener as TcpListenerImpl, SocketAddr as TcpSocketAddr, Ipv4Addr};

use super::types::{SocketFd, SocketType, SocketState, SocketError, SocketAddr, SocketResult, NEXT_FD};
use super::inner::SocketInner;
use super::event::{NetworkEvent, send_event, send_event_ignore};
use super::manager::SOCKET_MANAGER;

/// ソケット構造体（細粒度ロック対応）
pub struct Socket {
    /// ファイルディスクリプタ
    fd: SocketFd,
    /// ソケットタイプ（不変）
    socket_type: SocketType,
    /// 内部状態（Arc<Mutex>で保護）
    inner: Arc<Mutex<SocketInner>>,
}

impl Socket {
    /// 新規ソケット作成
    pub fn new(socket_type: SocketType) -> Self {
        let fd = SocketFd::from_raw(NEXT_FD.fetch_add(1, Ordering::Relaxed));
        Self {
            fd,
            socket_type,
            inner: Arc::new(Mutex::new(SocketInner::new())),
        }
    }
    
    /// 指定FDでソケット作成（Accept用）
    pub fn new_with_fd(socket_type: SocketType, fd: SocketFd) -> Self {
        Self {
            fd,
            socket_type,
            inner: Arc::new(Mutex::new(SocketInner::new())),
        }
    }
    
    /// ファイルディスクリプタ取得
    #[inline(always)]
    pub const fn fd(&self) -> SocketFd {
        self.fd
    }
    
    /// ソケットタイプ取得
    #[inline(always)]
    pub const fn socket_type(&self) -> SocketType {
        self.socket_type
    }
    
    /// 現在の状態取得
    #[inline]
    pub fn state(&self) -> SocketState {
        self.inner.lock().state
    }
    
    /// ローカルアドレス取得
    #[inline]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.lock().local_addr
    }
    
    /// リモートアドレス取得
    #[inline]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.lock().remote_addr
    }
    
    /// 内部状態への参照取得（高度な操作用）
    #[inline]
    pub fn inner(&self) -> &Arc<Mutex<SocketInner>> {
        &self.inner
    }
    
    /// バインド
    pub fn bind(&self, addr: SocketAddr) -> SocketResult<()> {
        let mut inner = self.inner.lock();
        
        if !inner.state.can_bind() {
            return Err(SocketError::AlreadyBound);
        }
        
        // ポートの重複チェックはSocketManagerで行う
        inner.local_addr = Some(addr);
        inner.transition_to(SocketState::Bound)
    }
    
    /// 接続（TCP用）
    pub fn connect(&self, addr: SocketAddr) -> SocketResult<()> {
        let local_addr;
        {
            let mut inner = self.inner.lock();
            
            if !inner.state.can_connect() {
                return Err(SocketError::AlreadyConnected);
            }
            
            // ローカルアドレスが未設定ならエフェメラルポートを割り当て
            local_addr = inner.local_addr.unwrap_or_else(|| {
                SocketAddr::new([0, 0, 0, 0], 0) // 後でマネージャが割り当て
            });
            
            inner.remote_addr = Some(addr);
            inner.transition_to(SocketState::Connecting)?;
        }
        
        // TCPスタックに接続イベントを送信（バックプレッシャー対応）
        send_event(NetworkEvent::Connect {
            fd: self.fd,
            local: local_addr,
            remote: addr,
        })
    }
    
    /// リッスン開始（TCP用）
    pub fn listen(&self, backlog: u32) -> SocketResult<()> {
        if self.socket_type != SocketType::Tcp {
            return Err(SocketError::InvalidArgument);
        }
        
        let local_addr;
        {
            let mut inner = self.inner.lock();
            
            if !inner.state.can_listen() {
                return Err(SocketError::InvalidStateTransition);
            }
            
            local_addr = inner.local_addr.ok_or(SocketError::InvalidArgument)?;
            
            // TCPリスナー作成 - tcp.rsのSocketAddr型に変換
            let tcp_addr = TcpSocketAddr::new(
                Ipv4Addr::new(local_addr.ip[0], local_addr.ip[1], local_addr.ip[2], local_addr.ip[3]),
                local_addr.port
            );
            let listener = TcpListenerImpl::bind(tcp_addr)
                .map_err(|_| SocketError::AddressInUse)?;
            inner.tcp_listener = Some(listener);
            inner.transition_to(SocketState::Listening)?;
        }
        
        // ネットワークスタックにリッスンイベントを送信（バックプレッシャー対応）
        send_event(NetworkEvent::Listen {
            fd: self.fd,
            local: local_addr,
            backlog,
        })
    }
    
    /// 接続受け入れ（TCP用）- 非ブロッキング
    /// Acceptキューから接続を取得、空の場合はTimeoutを返す
    pub fn accept(&self) -> SocketResult<(Socket, SocketAddr)> {
        if self.socket_type != SocketType::Tcp {
            return Err(SocketError::InvalidArgument);
        }
        
        let mut inner = self.inner.lock();
        
        if inner.state != SocketState::Listening {
            return Err(SocketError::InvalidStateTransition);
        }
        
        // Acceptキューから接続を取得
        if let Some(conn) = inner.accept_queue.pop_front() {
            // 新しいソケットを作成
            let new_socket = Socket::new_with_fd(SocketType::Tcp, conn.fd);
            {
                let mut new_inner = new_socket.inner.lock();
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                let _ = new_inner.transition_to(SocketState::Connected);
            }
            
            // ソケットマネージャに登録
            if let Some(ref mgr) = *SOCKET_MANAGER.read() {
                mgr.register(new_socket.clone());
            }
            
            crate::serial_println!(
                "TCP: Accepted connection from {:?}:{}",
                conn.remote_addr.ip, conn.remote_addr.port
            );
            
            return Ok((new_socket, conn.remote_addr));
        }
        
        // キューが空の場合はPending（Timeout）を返す
        Err(SocketError::Timeout)
    }
    
    /// Accept用Wakerを登録（非同期用）
    pub fn register_accept_waker(&self, waker: core::task::Waker) {
        let mut inner = self.inner.lock();
        inner.accept_waker = Some(waker);
    }
    
    /// 接続受け入れ（内部用 - バックログ経由）
    pub fn accept_from_backlog(&self, stream: TcpStream, remote_addr: SocketAddr) -> SocketResult<Socket> {
        if self.socket_type != SocketType::Tcp {
            return Err(SocketError::InvalidArgument);
        }
        
        let inner = self.inner.lock();
        
        if inner.state != SocketState::Listening {
            return Err(SocketError::InvalidStateTransition);
        }
        
        let new_socket = Socket::new(SocketType::Tcp);
        {
            let mut new_inner = new_socket.inner.lock();
            new_inner.local_addr = inner.local_addr;
            new_inner.remote_addr = Some(remote_addr);
            new_inner.tcp_stream = Some(stream);
            let _ = new_inner.transition_to(SocketState::Connected);
        }
        
        Ok(new_socket)
    }
    
    /// データ送信
    pub fn send(&self, data: &[u8]) -> SocketResult<usize> {
        let len = {
            let mut inner = self.inner.lock();
            
            if !inner.state.can_send() {
                return Err(SocketError::NotConnected);
            }
            
            inner.send_to_buffer(data)?
        };
        
        // 送信データがあることをネットワークスタックに通知（バックプレッシャー対応）
        if len > 0 {
            send_event(NetworkEvent::DataReady {
                fd: self.fd,
                socket_type: self.socket_type,
            })?;
        }
        
        Ok(len)
    }
    
    /// データ受信
    pub fn recv(&self, buf: &mut [u8]) -> SocketResult<usize> {
        let mut inner = self.inner.lock();
        
        if !inner.state.can_receive() {
            return Err(SocketError::NotConnected);
        }
        
        let len = inner.recv_from_buffer(buf);
        if len > 0 {
            Ok(len)
        } else {
            Err(SocketError::Timeout)
        }
    }
    
    /// UDP送信
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> SocketResult<usize> {
        if self.socket_type != SocketType::Udp {
            return Err(SocketError::InvalidArgument);
        }
        
        {
            let inner = self.inner.lock();
            
            if !matches!(inner.state, SocketState::Bound | SocketState::Connected) {
                return Err(SocketError::NotConnected);
            }
        }
        
        // UDPパケット送信イベント（バックプレッシャー対応）
        send_event(NetworkEvent::SendTo {
            fd: self.fd,
            data: data.to_vec(),
            remote: addr,
        })?;
        
        Ok(data.len())
    }
    
    /// UDP受信
    pub fn recv_from(&self, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
        if self.socket_type != SocketType::Udp {
            return Err(SocketError::InvalidArgument);
        }
        
        let mut inner = self.inner.lock();
        
        if let Some((addr, data)) = inner.pending_packets.pop_front() {
            let len = buf.len().min(data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, addr))
        } else {
            Err(SocketError::Timeout)
        }
    }
    
    /// 受信バッファにデータ追加（内部用）
    /// プロトコルスタックから呼ばれる
    pub fn push_data(&self, data: &[u8]) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.push_recv_data(data);
            // 待機中のタスクを起こす準備
            inner.recv_waker.take()
        };
        
        // ロック外でWakerを起こす（デッドロック回避）
        if let Some(w) = waker {
            w.wake();
        }
    }
    
    /// UDPパケット追加（内部用）
    /// プロトコルスタックから呼ばれる
    pub fn push_packet(&self, addr: SocketAddr, data: Vec<u8>) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.pending_packets.push_back((addr, data));
            // 待機中のタスクを起こす準備
            inner.recv_waker.take()
        };
        
        // ロック外でWakerを起こす
        if let Some(w) = waker {
            w.wake();
        }
    }
    
    /// クローズ
    pub fn close(&self) -> SocketResult<()> {
        {
            let mut inner = self.inner.lock();
            
            // TCPストリームのクリーンアップ
            inner.tcp_stream = None;
            
            // リスナーのクリーンアップ
            inner.tcp_listener = None;
            inner.udp_socket = None;
            
            // バッファクリア
            inner.recv_buffer.clear();
            inner.send_buffer.clear();
            
            // 待機中のタスクを起こす
            if let Some(waker) = inner.recv_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.send_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.connect_waker.take() {
                waker.wake();
            }
            
            inner.transition_to(SocketState::Closed)?;
        }
        
        // ネットワークスタックにクローズを通知（エラーは無視 - クローズは必ず進める）
        send_event_ignore(NetworkEvent::Close { fd: self.fd });
        
        Ok(())
    }
    
    /// 受信バッファのデータ量
    #[inline]
    pub fn recv_buffer_len(&self) -> usize {
        self.inner.lock().recv_buffer.len()
    }
    
    /// 送信バッファのデータ量
    #[inline]
    pub fn send_buffer_len(&self) -> usize {
        self.inner.lock().send_buffer.len()
    }
    
    /// 受信データがあるか
    #[inline]
    pub fn has_data(&self) -> bool {
        self.inner.lock().recv_buffer.len() > 0
    }
}

impl Clone for Socket {
    fn clone(&self) -> Self {
        Self {
            fd: self.fd,
            socket_type: self.socket_type,
            inner: Arc::clone(&self.inner),
        }
    }
}

// =====================================================
// OwnedSocket - RAII リソース管理
// =====================================================

/// RAII管理されるソケット（Drop時に自動クローズ）
pub struct OwnedSocket {
    socket: Option<Socket>,
}

impl OwnedSocket {
    /// 新規OwnedSocket作成
    pub fn new(socket_type: SocketType) -> Self {
        let socket = Socket::new(socket_type);
        // SocketManagerに登録
        if let Some(ref manager) = *SOCKET_MANAGER.read() {
            manager.register(socket.clone());
        }
        Self {
            socket: Some(socket),
        }
    }
    
    /// 既存ソケットからOwnedSocket作成
    pub fn from_socket(socket: Socket) -> Self {
        Self {
            socket: Some(socket),
        }
    }
    
    /// ファイルディスクリプタ取得
    pub fn fd(&self) -> SocketFd {
        self.socket.as_ref().map(|s| s.fd()).unwrap_or(SocketFd::INVALID)
    }
    
    /// 内部ソケットへの参照
    pub fn socket(&self) -> Option<&Socket> {
        self.socket.as_ref()
    }
    
    /// 内部ソケットへの可変参照
    pub fn socket_mut(&mut self) -> Option<&mut Socket> {
        self.socket.as_mut()
    }
    
    /// ソケットを取り出し（所有権移動、Dropしなくなる）
    pub fn into_inner(mut self) -> Option<Socket> {
        self.socket.take()
    }
    
    /// バインド
    pub fn bind(&self, addr: SocketAddr) -> SocketResult<()> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.bind(addr)
    }
    
    /// 接続
    pub fn connect(&self, addr: SocketAddr) -> SocketResult<()> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.connect(addr)
    }
    
    /// リッスン
    pub fn listen(&self, backlog: u32) -> SocketResult<()> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.listen(backlog)
    }
    
    /// 接続受け入れ
    pub fn accept(&self) -> SocketResult<(OwnedSocket, SocketAddr)> {
        let (socket, addr) = self.socket.as_ref().ok_or(SocketError::NotFound)?.accept()?;
        Ok((OwnedSocket::from_socket(socket), addr))
    }
    
    /// 送信
    pub fn send(&self, data: &[u8]) -> SocketResult<usize> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.send(data)
    }
    
    /// 受信
    pub fn recv(&self, buf: &mut [u8]) -> SocketResult<usize> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.recv(buf)
    }
    
    /// UDP送信
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> SocketResult<usize> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.send_to(data, addr)
    }
    
    /// UDP受信
    pub fn recv_from(&self, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
        self.socket.as_ref().ok_or(SocketError::NotFound)?.recv_from(buf)
    }
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Some(ref socket) = self.socket {
            // ソケットクローズ
            let _ = socket.close();
            
            // SocketManagerから登録解除
            if let Some(ref manager) = *SOCKET_MANAGER.read() {
                manager.unregister(socket.fd());
            }
        }
    }
}

// =====================================================
// 便利関数 - OwnedSocket API
// =====================================================

/// TCPソケット作成
pub fn create_tcp_socket() -> OwnedSocket {
    OwnedSocket::new(SocketType::Tcp)
}

/// UDPソケット作成
pub fn create_udp_socket() -> OwnedSocket {
    OwnedSocket::new(SocketType::Udp)
}

/// RAWソケット作成
pub fn create_raw_socket() -> OwnedSocket {
    OwnedSocket::new(SocketType::Raw)
}

/// TCPサーバー作成（バインド+リッスン）
pub fn create_tcp_server(addr: SocketAddr, backlog: u32) -> SocketResult<OwnedSocket> {
    let socket = create_tcp_socket();
    socket.bind(addr)?;
    socket.listen(backlog)?;
    Ok(socket)
}

/// TCP接続
pub fn tcp_connect(addr: SocketAddr) -> SocketResult<OwnedSocket> {
    let socket = create_tcp_socket();
    socket.connect(addr)?;
    Ok(socket)
}

/// UDPバインド
pub fn udp_bind(addr: SocketAddr) -> SocketResult<OwnedSocket> {
    let socket = create_udp_socket();
    socket.bind(addr)?;
    Ok(socket)
}

// =====================================================
// テスト
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_owned_socket_raii() {
        // OwnedSocketはスコープ終了時に自動クローズ
        {
            let _socket = OwnedSocket::new(SocketType::Tcp);
            // スコープ終了時にDropが呼ばれる
        }
        // ソケットは自動的にクローズされている
    }
}
