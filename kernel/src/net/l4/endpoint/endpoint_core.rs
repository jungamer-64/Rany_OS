// ============================================================================
// kernel/src/net/l4/endpoint/endpoint_core.rs
// ============================================================================
//! # Socket - Arc<PoisonLock<EndpointInner>>ラッパー
//!
//! Socket, OwnedEndpoint, および関連ヘルパー関数

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::net::datapath::mempool::PacketRef;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::l4::udp::UdpAddr;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};
use crate::sync::poison_lock::PoisonLock;
use kernel_api::resource::net::PacketPayload;

use crate::net::l4::tcp::TcpStream;

use super::event::{NetworkEvent, enqueue_event_ignore_in, enqueue_event_in};
use super::inner::EndpointInner;
use super::manager::ENDPOINT_MANAGER;
use super::types::{
    EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointState, EndpointType, NEXT_FD,
};

/// ソケット構造体（細粒度ロック対応）
pub struct Endpoint {
    /// ファイルディスクリプタ
    fd: EndpointFd,
    /// エンドポイントタイプ（不変）
    endpoint_type: EndpointType,
    /// 所属するネットワークランタイム
    runtime: NetRuntimeHandle,
    /// 内部状態（Arc<PoisonLock>で保護 — 設計書 8.4準拠）
    inner: Arc<PoisonLock<EndpointInner>>,
}

impl Endpoint {
    /// 新規エンドポイント作成
    pub fn new(endpoint_type: EndpointType) -> Self {
        Self::new_in(endpoint_type, default_runtime())
    }

    /// 指定ランタイムの新規エンドポイント作成
    pub fn new_in(endpoint_type: EndpointType, runtime: NetRuntimeHandle) -> Self {
        let fd = EndpointFd::from_raw(NEXT_FD.fetch_add(1, Ordering::Relaxed));
        Self {
            fd,
            endpoint_type,
            runtime,
            inner: Arc::new(PoisonLock::new(EndpointInner::new())),
        }
    }

    /// 指定FDでエンドポイント作成（Accept用）
    pub fn new_with_fd(endpoint_type: EndpointType, fd: EndpointFd) -> Self {
        Self::new_with_fd_in(endpoint_type, fd, default_runtime())
    }

    /// 指定FD・ランタイムでエンドポイント作成（Accept用）
    pub fn new_with_fd_in(
        endpoint_type: EndpointType,
        fd: EndpointFd,
        runtime: NetRuntimeHandle,
    ) -> Self {
        Self {
            fd,
            endpoint_type,
            runtime,
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

    /// 所属ランタイム取得
    #[inline(always)]
    pub const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
    }

    /// 現在の状態取得
    #[inline]
    pub fn state(&self) -> EndpointState {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state
    }

    /// ローカルアドレス取得
    #[inline]
    pub fn local_addr(&self) -> Option<EndpointAddr> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .local_addr
    }

    /// リモートアドレス取得
    #[inline]
    pub fn remote_addr(&self) -> Option<EndpointAddr> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remote_addr
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

    /// 次の接続を取得（同期バッファ読み取り）
    ///
    /// Acceptキューから接続を取得する。NETWORK_STACKロックは使用しない。
    /// 空の場合はTimeoutを返す。`AcceptFuture` が内部で使用する。
    pub fn try_next_incoming(&self) -> EndpointResult<(Endpoint, EndpointAddr, NetIfId)> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != EndpointState::Listening {
            return Err(EndpointError::InvalidStateTransition);
        }

        // Acceptキューから接続を取得
        if let Some(conn) = inner.tcp_mut().and_then(|t| t.accept_queue.pop_front()) {
            // 新しいソケットを作成
            let new_socket = Endpoint::new_with_fd_in(EndpointType::Tcp, conn.fd, self.runtime);
            {
                let mut new_inner = new_socket.inner.lock().unwrap_or_else(|e| e.into_inner());
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                new_inner.scope = crate::net::types::InterfaceScope::Pinned(conn.if_id);
                new_inner.last_ingress_if_id = Some(conn.if_id);
                new_inner.ensure_tcp().nodelay = inner.tcp().map_or(false, |t| t.nodelay); // 設定を引き継ぐ
                new_inner.priority = inner.priority; // 優先度を引き継ぐ
                let _ = new_inner.transition_to(EndpointState::Connected);
            }

            // ソケットマネージャに登録
            if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
                mgr.register(new_socket.clone());
            }

            log::info!("TCP: Accepted connection from {}", conn.remote_addr);

            return Ok((new_socket, conn.remote_addr, conn.if_id));
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
        _stream: TcpStream,
        remote_addr: EndpointAddr,
    ) -> EndpointResult<Endpoint> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if inner.state != EndpointState::Listening {
            return Err(EndpointError::InvalidStateTransition);
        }

        let new_socket = Endpoint::new_in(EndpointType::Tcp, self.runtime);
        {
            let mut new_inner = new_socket.inner.lock().unwrap_or_else(|e| e.into_inner());
            new_inner.local_addr = inner.local_addr;
            new_inner.remote_addr = Some(remote_addr);
            let _ = new_inner.transition_to(EndpointState::Connected);
        }

        Ok(new_socket)
    }

    /// データ受信（同期バッファ読み取り）
    ///
    /// 内部バッファから読み取るのみ。ネットワークスタックロックは使用しない。
    pub fn try_recv(&self, buf: &mut [u8]) -> EndpointResult<usize> {
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

    /// UDP受信（同期バッファ読み取り）
    ///
    /// 内部バッファから読み取るのみ。ネットワークスタックロックは使用しない。
    pub fn try_recv_from(&self, buf: &mut [u8]) -> EndpointResult<(usize, EndpointAddr, NetIfId)> {
        if self.endpoint_type != EndpointType::Udp {
            return Err(EndpointError::InvalidArgument);
        }

        let socket = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            if let Some((if_id, addr, mut data)) =
                inner.udp_mut().and_then(|u| u.pending_packets.pop_front())
            {
                inner.last_ingress_if_id = Some(if_id);
                let len = data.copy_into(buf);
                return Ok((len, addr, if_id));
            }

            inner.udp().and_then(|u| u.socket.clone())
        };

        if let Some(socket) = socket {
            if let Some((if_id, addr, _ttl, mut payload)) = socket.try_recv() {
                let len = payload.copy_into(buf);
                let endpoint_addr = match addr {
                    UdpAddr::V4 { ip, port } => EndpointAddr::new(ip.octets(), port),
                    UdpAddr::V6 { ip, port } => EndpointAddr::new_v6(ip.octets(), port),
                };
                self.inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last_ingress_if_id = Some(if_id);
                return Ok((len, endpoint_addr, if_id));
            }
        }

        Err(EndpointError::Timeout)
    }

    /// 受信バッファにデータ追加（内部用）
    /// プロトコルスタックから呼ばれる
    /// 実際にバッファに追加されたバイト数を返す。
    pub fn push_payload(&self, payload: PacketPayload) -> usize {
        let (pushed, local, remote, waker) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let pushed = inner.push_recv_payload(payload);
            let local = inner.local_addr;
            let remote = inner.remote_addr;
            if pushed > 0 {
                if let Some(tcp) = inner.tcp_mut() {
                    tcp.stats.record_rx_segment(pushed);
                }
            }
            // 待機中のタスクを起こす準備 (push_recv_payloadがwakeする場合もあるが、
            // ここでwakerを取り出すのは古いコードとの互換性/安全策)
            (pushed, local, remote, inner.recv_waker.take())
        };

        if pushed > 0 {
            if let (Some(local), Some(remote)) = (local, remote) {
                let _ =
                    crate::net::l4::endpoint::tcb::tcb_table().lookup_mut(local, remote, |tcb| {
                        tcb.on_data_received(pushed as u32);
                    });
            }
        }

        // ロック外でWakerを起こす（デッドロック回避）
        if let Some(w) = waker {
            w.wake();
        }
        pushed
    }

    /// UDPパケット追加（内部用）
    pub fn push_packet_payload(&self, if_id: NetIfId, addr: EndpointAddr, payload: PacketPayload) {
        let waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.last_ingress_if_id = Some(if_id);
            inner
                .ensure_udp()
                .pending_packets
                .push_back((if_id, addr, payload));
            // 待機中のタスクを起こす準備
            inner.recv_waker.take()
        };

        // ロック外でWakerを起こす
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// UDPパケット追加（ゼロコピー内部キュー優先）
    ///
    /// 内部UDPソケットがある場合は `PacketRef` の所有権をそのまま移動し、
    /// 呼び出し側が `recv_from*()` を使う場合のみコピーする。
    pub fn deliver_udp_packet(
        &self,
        if_id: NetIfId,
        addr: EndpointAddr,
        ttl: u8,
        packet: PacketRef,
    ) -> EndpointResult<()> {
        self.deliver_udp_payload(if_id, addr, ttl, PacketPayload::single(packet))
    }

    pub fn deliver_udp_payload(
        &self,
        if_id: NetIfId,
        addr: EndpointAddr,
        ttl: u8,
        payload: PacketPayload,
    ) -> EndpointResult<()> {
        if self.endpoint_type != EndpointType::Udp {
            return Err(EndpointError::InvalidArgument);
        }

        let (socket, recv_waker) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.last_ingress_if_id = Some(if_id);

            let socket = inner.ensure_udp().socket.clone();
            if socket.is_none() {
                inner
                    .ensure_udp()
                    .pending_packets
                    .push_back((if_id, addr, payload.clone()));
            }

            (socket, inner.recv_waker.take())
        };

        if let Some(socket) = socket {
            let udp_addr = match addr {
                EndpointAddr::V4 { ip, port } => UdpAddr::new(Ipv4Address::new(ip), port),
                EndpointAddr::V6 { ip, port } => UdpAddr::new_v6(Ipv6Address::new(ip), port),
            };
            socket.deliver_payload(if_id, udp_addr, ttl, payload);
        }

        if let Some(waker) = recv_waker {
            waker.wake();
        }

        Ok(())
    }

    pub fn try_recv_raw_payload(&self) -> EndpointResult<(PacketPayload, NetIfId)> {
        if self.endpoint_type != EndpointType::Raw {
            return Err(EndpointError::InvalidArgument);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.state.can_receive() {
            return Err(EndpointError::NotConnected);
        }

        if let Some((if_id, payload)) = inner
            .raw_mut()
            .and_then(|raw| raw.pending_payloads.pop_front())
        {
            inner.last_ingress_if_id = Some(if_id);
            return Ok((payload, if_id));
        }

        Err(EndpointError::Timeout)
    }

    pub fn deliver_raw_payload(
        &self,
        if_id: NetIfId,
        payload: PacketPayload,
    ) -> EndpointResult<()> {
        if self.endpoint_type != EndpointType::Raw {
            return Err(EndpointError::InvalidArgument);
        }

        let recv_waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.last_ingress_if_id = Some(if_id);
            inner
                .ensure_raw()
                .pending_payloads
                .push_back((if_id, payload));
            inner.recv_waker.take()
        };

        if let Some(waker) = recv_waker {
            waker.wake();
        }

        Ok(())
    }

    /// クローズ
    pub(crate) fn close_immediate(&self) -> EndpointResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            // プロトコル状態のクリーンアップ
            inner.clear_tcp_payload_queues();
            inner.clear_protocol();

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
        enqueue_event_ignore_in(self.runtime, NetworkEvent::Close { fd: self.fd });

        Ok(())
    }

    /// 受信バッファのデータ量
    #[inline]
    pub fn recv_buffer_len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_payload_bytes()
    }

    /// 送信バッファのデータ量
    #[inline]
    pub fn send_buffer_len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send_payload_bytes()
    }

    /// 受信データがあるか
    #[inline]
    pub fn has_data(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_recv_data()
    }

    /// TCP_NODELAY (Nagleアルゴリズム無効化) を設定
    pub fn set_nodelay(&self, nodelay: bool) -> EndpointResult<()> {
        if self.endpoint_type != EndpointType::Tcp {
            return Err(EndpointError::InvalidArgument);
        }

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_tcp().nodelay = nodelay;
        }

        // ネットワークスタックに通知（接続済みの場合、TCBに反映させる）
        enqueue_event_in(
            self.runtime,
            NetworkEvent::SetNoDelay {
                fd: self.fd,
                nodelay,
            },
        )
    }

    /// QoS優先度 (DSCP) を設定
    pub fn set_priority(&self, priority: u8) -> EndpointResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.priority = priority & 0x3F; // DSCPは6ビット
        }

        // ネットワークスタックに通知
        enqueue_event_in(
            self.runtime,
            NetworkEvent::SetPriority {
                fd: self.fd,
                priority: priority & 0x3F,
            },
        )
    }

    // =====================================================
    // 非同期API（Async-First設計準拠）
    // =====================================================

    /// 非同期接続開始（推奨API）
    ///
    /// イベントキュー経由でTCPハンドシェイクを開始し、
    /// 接続完了をFutureで待機する。NETWORK_STACKロックの
    /// 同期取得を完全に回避する。
    ///
    /// # 使用例
    /// ```ignore
    /// let endpoint = create_tcp_endpoint();
    /// endpoint.open_connection(addr).await?;
    /// ```
    pub fn open_connection(&self, addr: EndpointAddr) -> super::futures::OpenConnectionFuture {
        super::futures::OpenConnectionFuture::new(self.clone(), addr)
    }

    /// 非同期リッスン開始（推奨API）
    ///
    /// イベントキュー経由で非同期にTCPリスナーをbindし、
    /// Listenモードに遷移する。NETWORK_STACKロックの
    /// 同期取得を完全に回避する。
    ///
    /// # 使用例
    /// ```ignore
    /// let endpoint = create_tcp_endpoint();
    /// endpoint.set_local_addr(addr)?;
    /// endpoint.start_listening(128).await?;
    /// ```
    pub fn start_listening(&self, backlog: u32) -> super::futures::StartListeningFuture {
        super::futures::StartListeningFuture::new(self.clone(), backlog)
    }

    /// 非同期クローズ（推奨API）
    ///
    /// エンドポイントの状態をクリーンアップし、
    /// イベントキュー経由でCloseを送出する。
    ///
    /// # 使用例
    /// ```ignore
    /// endpoint.close().await?;
    /// ```
    pub fn close(&self) -> super::futures::CloseFuture {
        super::futures::CloseFuture::new(self.clone())
    }

    // =====================================================
    // 非同期データ送受信API（Async-First設計準拠）
    // =====================================================

    /// 非同期データ受信（推奨API）
    ///
    /// Futureベースの受信。受信バッファにデータが到着するまで
    /// 非同期に待機する。
    ///
    /// # 使用例
    /// ```ignore
    /// let data = endpoint.recv(1024).await?;
    /// ```
    pub fn recv(&self, size: usize) -> super::futures::RecvFuture {
        super::futures::RecvFuture::new(self.clone(), size)
    }

    /// 非同期UDP送信（推奨API）
    ///
    /// イベントキュー経由でUDPデータグラムを非同期に送信する。
    ///
    /// # 使用例
    /// ```ignore
    /// let n = endpoint.send_to(data, addr).await?;
    /// ```
    pub fn send_to(
        &self,
        payload: PacketPayload,
        addr: EndpointAddr,
    ) -> super::futures::SendToFuture {
        super::futures::SendToFuture::new(self.clone(), payload, addr)
    }

    /// 非同期UDP受信（推奨API）
    ///
    /// Futureベースの受信。UDPパケットが到着するまで
    /// 非同期に待機する。
    ///
    /// # 使用例
    /// ```ignore
    /// let (data, addr) = endpoint.recv_from(1500).await?;
    /// ```
    pub fn recv_from(&self, size: usize) -> super::futures::RecvFromFuture {
        super::futures::RecvFromFuture::new(self.clone(), size)
    }

    /// 非同期Accept（推奨API）
    ///
    /// Futureベースの接続受け入れ。新しい接続が到着するまで
    /// 非同期に待機する。
    ///
    /// # 使用例
    /// ```ignore
    /// let (ep, addr) = endpoint.accept().await?;
    /// ```
    pub fn accept(&self) -> super::futures::AcceptFuture {
        super::futures::AcceptFuture::new(self.clone())
    }
}

impl Clone for Endpoint {
    fn clone(&self) -> Self {
        Self {
            fd: self.fd,
            endpoint_type: self.endpoint_type,
            runtime: self.runtime,
            inner: Arc::clone(&self.inner),
        }
    }
}

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
        Self::new_in(default_runtime(), ep_type)
    }

    /// 指定ランタイムの新規OwnedEndpoint作成
    pub fn new_in(runtime: NetRuntimeHandle, ep_type: EndpointType) -> Self {
        let ep = Endpoint::new_in(ep_type, runtime);
        // EndpointManagerに登録
        if let Some(ref manager) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            manager.register(ep.clone());
        }
        Self { endpoint: Some(ep) }
    }

    /// 既存ソケットからOwnedEndpoint作成
    pub fn from_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
        }
    }

    /// 所属ランタイム取得
    pub fn runtime(&self) -> Option<NetRuntimeHandle> {
        self.endpoint.as_ref().map(Endpoint::runtime)
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

    /// 次の接続を取得（同期版）
    ///
    /// NETWORK_STACKロックは使用しない。`AcceptFuture` が内部で使用する。
    /// asyncコンテキストでは `accept()` を推奨。
    pub fn try_next_incoming(&self) -> EndpointResult<(OwnedEndpoint, EndpointAddr, NetIfId)> {
        let (ep, addr, if_id) = self
            .endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .try_next_incoming()?;
        Ok((OwnedEndpoint::from_endpoint(ep), addr, if_id))
    }

    /// 受信（同期）
    pub fn try_recv(&self, buf: &mut [u8]) -> EndpointResult<usize> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .try_recv(buf)
    }

    /// UDP受信（同期）
    pub fn try_recv_from(&self, buf: &mut [u8]) -> EndpointResult<(usize, EndpointAddr, NetIfId)> {
        self.endpoint
            .as_ref()
            .ok_or(EndpointError::NotFound)?
            .try_recv_from(buf)
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

    // =====================================================
    // 非同期API（Async-First設計準拠）
    // =====================================================

    /// 非同期接続開始（推奨API）
    ///
    /// NETWORK_STACKロックの同期取得を完全に回避する。
    pub fn open_connection(
        &self,
        addr: EndpointAddr,
    ) -> Option<super::futures::OpenConnectionFuture> {
        self.endpoint.as_ref().map(|ep| ep.open_connection(addr))
    }

    /// 非同期リッスン開始（推奨API）
    ///
    /// NETWORK_STACKロックの同期取得を完全に回避する。
    pub fn start_listening(&self, backlog: u32) -> Option<super::futures::StartListeningFuture> {
        self.endpoint.as_ref().map(|ep| ep.start_listening(backlog))
    }

    /// 非同期クローズ（推奨API）
    pub fn close(&self) -> Option<super::futures::CloseFuture> {
        self.endpoint.as_ref().map(|ep| ep.close())
    }
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        if let Some(ref ep) = self.endpoint {
            // エンドポイントクローズ
            let _ = ep.close_immediate();

            // EndpointManagerから登録解除
            if let Some(ref manager) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
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
    create_tcp_endpoint_in(default_runtime())
}

/// 指定ランタイムのTCPソケット作成
pub fn create_tcp_endpoint_in(runtime: NetRuntimeHandle) -> OwnedEndpoint {
    OwnedEndpoint::new_in(runtime, EndpointType::Tcp)
}

/// TCPソケット作成（輻輳制御アルゴリズム指定）
///
/// デフォルトはNewReno。CUBIC/BBRを使用する場合はこちらを利用。
/// アルゴリズムは接続開始時にTCBに反映される。
pub fn create_tcp_endpoint_with_algorithm(
    algorithm: super::congestion::CongestionAlgorithm,
) -> OwnedEndpoint {
    create_tcp_endpoint_with_algorithm_in(default_runtime(), algorithm)
}

/// 指定ランタイムのTCPソケット作成（輻輳制御アルゴリズム指定）
pub fn create_tcp_endpoint_with_algorithm_in(
    runtime: NetRuntimeHandle,
    algorithm: super::congestion::CongestionAlgorithm,
) -> OwnedEndpoint {
    let ep = OwnedEndpoint::new_in(runtime, EndpointType::Tcp);
    if let Some(inner_ep) = ep.endpoint() {
        let mut inner = inner_ep.inner().lock().unwrap_or_else(|e| e.into_inner());
        inner.ensure_tcp().congestion_algorithm = Some(algorithm);
    }
    ep
}

/// UDPソケット作成
pub fn create_udp_endpoint() -> OwnedEndpoint {
    create_udp_endpoint_in(default_runtime())
}

/// 指定ランタイムのUDPソケット作成
pub fn create_udp_endpoint_in(runtime: NetRuntimeHandle) -> OwnedEndpoint {
    OwnedEndpoint::new_in(runtime, EndpointType::Udp)
}

/// RAWソケット作成
pub fn create_raw_endpoint() -> OwnedEndpoint {
    create_raw_endpoint_in(default_runtime())
}

/// 指定ランタイムのRAWソケット作成
pub fn create_raw_endpoint_in(runtime: NetRuntimeHandle) -> OwnedEndpoint {
    OwnedEndpoint::new_in(runtime, EndpointType::Raw)
}

/// 非同期TCPサーバー作成（推奨API）
///
/// イベントキュー経由でbind/listenを非同期に実行する。
/// NETWORK_STACKロックの同期取得を完全に回避し、
/// asyncタスクからの安全な使用を保証する。
///
/// # 使用例
/// ```ignore
/// let server = create_tcp_server(addr, 128).await?;
/// loop {
///     let result = server.accept().unwrap().await;
/// }
/// ```
pub async fn create_tcp_server(addr: EndpointAddr, backlog: u32) -> EndpointResult<OwnedEndpoint> {
    create_tcp_server_in(default_runtime(), addr, backlog).await
}

/// 指定ランタイムの非同期TCPサーバー作成
pub async fn create_tcp_server_in(
    runtime: NetRuntimeHandle,
    addr: EndpointAddr,
    backlog: u32,
) -> EndpointResult<OwnedEndpoint> {
    let ep = create_tcp_endpoint_in(runtime);
    ep.set_local_addr(addr)?;
    let fut = ep.start_listening(backlog).ok_or(EndpointError::NotFound)?;
    fut.await?;
    Ok(ep)
}

/// 非同期TCP接続（推奨API）
///
/// イベントキュー経由で接続を非同期に開始する。
/// SYN送信とハンドシェイク完了をFutureで非同期に待機し、
/// NETWORK_STACKロックの同期取得を完全に回避する。
///
/// # 使用例
/// ```ignore
/// let conn = open_tcp_connection(addr).await?;
/// ```
pub async fn open_tcp_connection(addr: EndpointAddr) -> EndpointResult<OwnedEndpoint> {
    open_tcp_connection_in(default_runtime(), addr).await
}

/// 指定ランタイムの非同期TCP接続
pub async fn open_tcp_connection_in(
    runtime: NetRuntimeHandle,
    addr: EndpointAddr,
) -> EndpointResult<OwnedEndpoint> {
    let ep = create_tcp_endpoint_in(runtime);
    let fut = ep.open_connection(addr).ok_or(EndpointError::NotFound)?;
    fut.await?;
    Ok(ep)
}

/// 非同期UDPエンドポイント作成とバインド（推奨API）
///
/// ローカルアドレスを設定し、UDPソケットを非同期でbindする。
/// NETWORK_STACKロックの同期取得を完全に回避する。
///
/// # 使用例
/// ```ignore
/// let udp = create_udp_endpoint_bound(addr).await?;
/// ```
pub async fn create_udp_endpoint_bound(addr: EndpointAddr) -> EndpointResult<OwnedEndpoint> {
    create_udp_endpoint_bound_in(default_runtime(), addr).await
}

/// 指定ランタイムの非同期UDPエンドポイント作成とバインド
pub async fn create_udp_endpoint_bound_in(
    runtime: NetRuntimeHandle,
    addr: EndpointAddr,
) -> EndpointResult<OwnedEndpoint> {
    let ep = create_udp_endpoint_in(runtime);
    ep.set_local_addr(addr)?;

    // UDPソケットを非同期でbind（イベントキュー経由）
    let udp_bind_future = crate::net::runtime::stack::bind_udp_endpoint_in(runtime, addr.port());
    if let Some(udp_ep) = udp_bind_future.await {
        if let Some(inner_ep) = ep.endpoint() {
            let mut inner = inner_ep.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_udp().socket = Some(udp_ep);
        }
    }

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
