// ============================================================================
// kernel/src/net/endpoint/socket.rs
// ============================================================================
//! # Socket - Arc<PoisonLock<EndpointInner>>ラッパー
//!
//! Socket, OwnedEndpoint, および関連ヘルパー関数

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::sync::poison_lock::PoisonLock;

use crate::net::l4::tcp::{
    TcpListener as TcpListenerImpl, TcpStream,
};

use super::event::{NetworkEvent, send_event, send_event_ignore};
use super::inner::EndpointInner;
use super::manager::ENDPOINT_MANAGER;
use super::types::{
    NEXT_FD, EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointState, EndpointType,
};

/// ソケット構造体（細粒度ロック対応）
pub struct Endpoint {
    /// ファイルディスクリプタ
    fd: EndpointFd,
    /// エンドポイントタイプ（不変）
    endpoint_type: EndpointType,
    /// 内部状態（Arc<PoisonLock>で保護 — 設計書 8.4準拠）
    inner: Arc<PoisonLock<EndpointInner>>,
}

impl Endpoint {
    /// 新規エンドポイント作成
    pub fn new(endpoint_type: EndpointType) -> Self {
        let fd = EndpointFd::from_raw(NEXT_FD.fetch_add(1, Ordering::Relaxed));
        Self {
            fd,
            endpoint_type,
            inner: Arc::new(PoisonLock::new(EndpointInner::new())),
        }
    }

    /// 指定FDでエンドポイント作成（Accept用）
    pub fn new_with_fd(endpoint_type: EndpointType, fd: EndpointFd) -> Self {
        Self {
            fd,
            endpoint_type,
            inner: Arc::new(PoisonLock::new(EndpointInner::new())),
        }
    }

    /// ファイルディスクリプタ取得
    #[inline(always)]
    pub const fn fd(&self) -> EndpointFd {
        self.fd
    }

    /// ソケットタイプ取得
    #[inline(always)]
    pub const fn socket_type(&self) -> EndpointType {
        self.endpoint_type
    }

    /// Backward-compatible alias for legacy tests.
    #[inline(always)]
    pub const fn endpoint_type(&self) -> EndpointType {
        self.socket_type()
    }

    /// 現在の状態取得
    #[inline]
    pub fn state(&self) -> EndpointState {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state
    }

    /// ローカルアドレス取得
    #[inline]
    pub fn local_addr(&self) -> Option<EndpointAddr> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).local_addr
    }

    /// リモートアドレス取得
    #[inline]
    pub fn remote_addr(&self) -> Option<EndpointAddr> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remote_addr
    }

    /// 内部状態への参照取得（高度な操作用）
    #[inline]
    pub fn inner(&self) -> &Arc<PoisonLock<EndpointInner>> {
        &self.inner
    }

    /// ローカルアドレスを設定（推奨API）
    ///
    /// 【設計書】POSIXのbind()ではなく、set_local_addr()を使用
    pub fn set_local_addr(&self, addr: EndpointAddr) -> EndpointResult<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if !inner.state.can_bind() {
            return Err(EndpointError::AlreadyBound);
        }

        // ポートの重複チェックはEndpointManagerで行う
        inner.local_addr = Some(addr);
        inner.transition_to(EndpointState::Bound)
    }


    /// リモートアドレスへ接続を開始（推奨API）
    ///
    /// 【設計書】POSIXのconnect()ではなく、open_connection()を使用
    pub fn open_connection(&self, addr: EndpointAddr) -> EndpointResult<()> {
        let local_addr;
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            if !inner.state.can_connect() {
                return Err(EndpointError::AlreadyConnected);
            }

            // ローカルアドレスが未設定ならエフェメラルポートを割り当て
            local_addr = inner.local_addr.unwrap_or_else(|| {
                EndpointAddr::new([0, 0, 0, 0], 0) // 後でマネージャが割り当て
            });

            inner.remote_addr = Some(addr);
            inner.transition_to(EndpointState::Connecting)?;
        }

        // TCPスタックに接続イベントを送信（バックプレッシャー対応）
        send_event(NetworkEvent::Connect {
            fd: self.fd,
            local: local_addr,
            remote: addr,
        })
    }


    /// リッスンモードを開始（推奨API）
    ///
    /// 【設計書】POSIXのlisten()ではなく、start_listening()を使用
    pub fn start_listening(&self, backlog: u32) -> EndpointResult<()> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        let local_addr;
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            if !inner.state.can_listen() {
                return Err(EndpointError::InvalidStateTransition);
            }

            local_addr = inner.local_addr.ok_or(EndpointError::InvalidArgument)?;

            // TCPリスナー - EndpointAddr は同一型のためそのまま使用
            let tcp_addr = local_addr;
            let listener = TcpListenerImpl::bind(tcp_addr).map_err(|_| EndpointError::AddressInUse)?;
            inner.tcp_listener = Some(listener);
            inner.transition_to(EndpointState::Listening)?;
        }

        // ネットワークスタックにリッスンイベントを送信（バックプレッシャー対応）
        send_event(NetworkEvent::Listen {
            fd: self.fd,
            local: local_addr,
            backlog,
        })
    }


    /// 次の接続を取得（推奨API）
    ///
    /// 【設計書】POSIXのaccept()ではなく、next_incoming()を使用
    /// Acceptキューから接続を取得、空の場合はTimeoutを返す
    pub fn next_incoming(&self) -> EndpointResult<(Endpoint, EndpointAddr)> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != EndpointState::Listening {
            return Err(EndpointError::InvalidStateTransition);
        }

        // Acceptキューから接続を取得
        if let Some(conn) = inner.accept_queue.pop_front() {
            // 新しいソケットを作成
            let new_socket = Endpoint::new_with_fd(EndpointType::Tcp, conn.fd);
            {
                let mut new_inner = new_socket.inner.lock().unwrap_or_else(|e| e.into_inner());
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                new_inner.tcp_nodelay = inner.tcp_nodelay; // 設定を引き継ぐ
                new_inner.priority = inner.priority; // 優先度を引き継ぐ
                let _ = new_inner.transition_to(EndpointState::Connected);
            }

            // ソケットマネージャに登録
            if let Some(ref mgr) = *ENDPOINT_MANAGER.read() {
                mgr.register(new_socket.clone());
            }

            log::info!(
                "TCP: Accepted connection from {}",
                conn.remote_addr
            );

            return Ok((new_socket, conn.remote_addr));
        }

        // キューが空の場合はPending（Timeout）を返す
        Err(EndpointError::Timeout)
    }


    /// Accept用Wakerを登録（非同期用）
    pub fn register_accept_waker(&self, waker: core::task::Waker) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.accept_waker = Some(waker);
    }

    /// 受信待ちWakerを登録（非同期用）
    pub fn register_recv_waker(&self, waker: core::task::Waker) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.recv_waker = Some(waker);
    }

    /// 送信待ちWakerを登録（非同期用）
    pub fn register_send_waker(&self, waker: core::task::Waker) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.send_waker = Some(waker);
    }

    /// 接続受け入れ（内部用 - バックログ経由）
    pub fn accept_from_backlog(
        &self,
        stream: TcpStream,
        remote_addr: EndpointAddr,
    ) -> EndpointResult<Endpoint> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != EndpointState::Listening {
            return Err(EndpointError::InvalidStateTransition);
        }

        let new_socket = Endpoint::new(EndpointType::Tcp);
        {
            let mut new_inner = new_socket.inner.lock().unwrap_or_else(|e| e.into_inner());
            new_inner.local_addr = inner.local_addr;
            new_inner.remote_addr = Some(remote_addr);
            new_inner.tcp_stream = Some(stream);
            let _ = new_inner.transition_to(EndpointState::Connected);
        }

        Ok(new_socket)
    }

    /// データ送信
    pub fn send(&self, data: &[u8]) -> EndpointResult<usize> {
        let len = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            if !inner.state.can_send() {
                return Err(EndpointError::NotConnected);
            }

            inner.send_to_buffer(data)?
        };

        // 送信データがあることをネットワークスタックに通知（バックプレッシャー対応）
        if len > 0 {
            send_event(NetworkEvent::DataReady {
                fd: self.fd,
                endpoint_type: self.endpoint_type,
            })?;
        }

        Ok(len)
    }

    /// データ受信
    pub fn recv(&self, buf: &mut [u8]) -> EndpointResult<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if !inner.state.can_receive() {
            return Err(EndpointError::NotConnected);
        }

        let len = inner.recv_from_buffer(buf);
        if len > 0 {
            Ok(len)
        } else {
            Err(EndpointError::Timeout)
        }
    }

    /// UDP送信
    pub fn send_to(&self, data: &[u8], addr: EndpointAddr) -> EndpointResult<usize> {
        if self.endpoint_type != EndpointType::Udp {
            return Err(EndpointError::InvalidArgument);
        }

        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            if !matches!(inner.state, EndpointState::Bound | EndpointState::Connected) {
                return Err(EndpointError::NotConnected);
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
    pub fn recv_from(&self, buf: &mut [u8]) -> EndpointResult<(usize, EndpointAddr)> {
        if self.endpoint_type != EndpointType::Udp {
            return Err(EndpointError::InvalidArgument);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some((addr, data)) = inner.pending_packets.pop_front() {
            let len = buf.len().min(data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, addr))
        } else {
            Err(EndpointError::Timeout)
        }
    }

    /// 受信バッファにデータ追加（内部用）
    /// プロトコルスタックから呼ばれる
    pub fn push_data(&self, data: &[u8]) {
        let waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
    pub fn push_packet(&self, addr: EndpointAddr, data: Vec<u8>) {
        let waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
    pub fn close(&self) -> EndpointResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

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

            inner.transition_to(EndpointState::Closed)?;
        }

        // ネットワークスタックにクローズを通知（エラーは無視 - クローズは必ず進める）
        send_event_ignore(NetworkEvent::Close { fd: self.fd });

        Ok(())
    }

    /// 受信バッファのデータ量
    #[inline]
    pub fn recv_buffer_len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).recv_buffer.len()
    }

    /// 送信バッファのデータ量
    #[inline]
    pub fn send_buffer_len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).send_buffer.len()
    }

    /// 受信データがあるか
    #[inline]
    pub fn has_data(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).recv_buffer.len() > 0
    }

    /// TCP_NODELAY (Nagleアルゴリズム無効化) を設定
    pub fn set_nodelay(&self, nodelay: bool) -> EndpointResult<()> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.tcp_nodelay = nodelay;
        }

        // ネットワークスタックに通知（接続済みの場合、TCBに反映させる）
        send_event(NetworkEvent::SetNoDelay {
            fd: self.fd,
            nodelay,
        })
    }

    /// QoS優先度 (DSCP) を設定
    pub fn set_priority(&self, priority: u8) -> EndpointResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.priority = priority & 0x3F; // DSCPは6ビット
        }

        // ネットワークスタックに通知
        send_event(NetworkEvent::SetPriority {
            fd: self.fd,
            priority: priority & 0x3F,
        })
    }
}

impl Clone for Endpoint {
    fn clone(&self) -> Self {
        Self {
            fd: self.fd,
            endpoint_type: self.endpoint_type,
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Backward-compatible alias used by legacy endpoint tests.
pub type Socket = Endpoint;

// =====================================================
// OwnedEndpoint - RAII リソース管理
// =====================================================

/// RAII管理されるソケット（Drop時に自動クローズ）
pub struct OwnedEndpoint {
    endpoint: Option<Endpoint>,
}

impl OwnedEndpoint {
    /// 新規OwnedEndpoint作成
    pub fn new(ep_type: EndpointType) -> Self {
        let ep = Endpoint::new(ep_type);
        // EndpointManagerに登録
        if let Some(ref manager) = *ENDPOINT_MANAGER.read() {
            manager.register(ep.clone());
        }
        Self {
            endpoint: Some(ep),
        }
    }

    /// 既存ソケットからOwnedEndpoint作成
    pub fn from_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
        }
    }

    /// ファイルディスクリプタ取得
    pub fn fd(&self) -> EndpointFd {
        self.endpoint
            .as_ref()
            .map(|s| s.fd())
            .unwrap_or(EndpointFd::INVALID)
    }

    /// 内部ソケットへの参照
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    /// `endpoint()` 互換の旧API名
    pub fn socket(&self) -> Option<&Endpoint> {
        self.endpoint()
    }

    /// 内部ソケットへの可変参照
    pub fn endpoint_mut(&mut self) -> Option<&mut Endpoint> {
        self.endpoint.as_mut()
    }

    /// ソケットを取り出し（所有権移動、Dropしなくなる）
    pub fn into_inner(mut self) -> Option<Endpoint> {
        self.endpoint.take()
    }

    /// ローカルアドレスを設定（推奨API）
    pub fn set_local_addr(&self, addr: EndpointAddr) -> EndpointResult<()> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .set_local_addr(addr)
    }


    /// リモートアドレスへ接続を開始（推奨API）
    pub fn open_connection(&self, addr: EndpointAddr) -> EndpointResult<()> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .open_connection(addr)
    }


    /// リッスンモードを開始（推奨API）
    pub fn start_listening(&self, backlog: u32) -> EndpointResult<()> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .start_listening(backlog)
    }


    /// 次の接続を取得（推奨API）
    pub fn next_incoming(&self) -> EndpointResult<(OwnedEndpoint, EndpointAddr)> {
        let (ep, addr) = self
            .endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .next_incoming()?;
        Ok((OwnedEndpoint::from_endpoint(ep), addr))
    }


    /// 送信
    pub fn send(&self, data: &[u8]) -> EndpointResult<usize> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .send(data)
    }

    /// 受信
    pub fn recv(&self, buf: &mut [u8]) -> EndpointResult<usize> {
        self.endpoint.as_ref().ok_or(EndpointError::NotFound)?.recv(buf)
    }

    /// UDP送信
    pub fn send_to(&self, data: &[u8], addr: EndpointAddr) -> EndpointResult<usize> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .send_to(data, addr)
    }

    /// UDP受信
    pub fn recv_from(&self, buf: &mut [u8]) -> EndpointResult<(usize, EndpointAddr)> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .recv_from(buf)
    }

    /// TCP_NODELAY設定
    pub fn set_nodelay(&self, nodelay: bool) -> EndpointResult<()> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .set_nodelay(nodelay)
    }

    /// QoS優先度設定
    pub fn set_priority(&self, priority: u8) -> EndpointResult<()> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .set_priority(priority)
    }
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        if let Some(ref ep) = self.endpoint {
            // エンドポイントクローズ
            let _ = ep.close();

            // EndpointManagerから登録解除
            if let Some(ref manager) = *ENDPOINT_MANAGER.read() {
                manager.unregister(ep.fd());
            }
        }
    }
}

// =====================================================
// 便利関数 - OwnedEndpoint API
// =====================================================

/// TCPソケット作成
pub fn create_tcp_endpoint() -> OwnedEndpoint {
    OwnedEndpoint::new(EndpointType::Tcp)
}

/// TCPソケット作成（輻輳制御アルゴリズム指定）
///
/// デフォルトはNewReno。CUBIC/BBRを使用する場合はこちらを利用。
/// アルゴリズムは接続開始時にTCBに反映される。
pub fn create_tcp_endpoint_with_algorithm(
    algorithm: super::congestion::CongestionAlgorithm,
) -> OwnedEndpoint {
    let ep = OwnedEndpoint::new(EndpointType::Tcp);
    if let Some(inner_ep) = ep.endpoint() {
        let mut inner = inner_ep.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.congestion_algorithm = Some(algorithm);
    }
    ep
}

/// UDPソケット作成
pub fn create_udp_endpoint() -> OwnedEndpoint {
    OwnedEndpoint::new(EndpointType::Udp)
}

/// RAWソケット作成
pub fn create_raw_endpoint() -> OwnedEndpoint {
    OwnedEndpoint::new(EndpointType::Raw)
}

/// TCPサーバー作成（推奨API）
///
/// 【設計書】POSIXソケットAPIを模倣しない
pub fn create_tcp_server(addr: EndpointAddr, backlog: u32) -> EndpointResult<OwnedEndpoint> {
    let ep = create_tcp_endpoint();
    ep.set_local_addr(addr)?;
    ep.start_listening(backlog)?;
    Ok(ep)
}

/// TCP接続（推奨API）
///
/// 【設計書】POSIXソケットAPIを模倣しない
pub fn open_tcp_connection(addr: EndpointAddr) -> EndpointResult<OwnedEndpoint> {
    let ep = create_tcp_endpoint();
    ep.open_connection(addr)?;
    Ok(ep)
}


/// UDPエンドポイント作成とローカルアドレス設定（推奨API）
pub fn create_udp_endpoint_bound(addr: EndpointAddr) -> EndpointResult<OwnedEndpoint> {
    let ep = create_udp_endpoint();
    ep.set_local_addr(addr)?;
    Ok(ep)
}


// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_owned_socket_raii() {
        // OwnedEndpointはスコープ終了時に自動クローズ
        {
            let _socket = OwnedEndpoint::new(EndpointType::Tcp);
            // スコープ終了時にDropが呼ばれる
        }
        // ソケットは自動的にクローズされている
    }
}


#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn owned_socket_raii_smoke() -> bool {
        {
            let _socket = OwnedEndpoint::new(EndpointType::Tcp);
        }
        true
    }
}
