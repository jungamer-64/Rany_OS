// ============================================================================
// kernel/src/net/l4/endpoint/endpoint_core.rs
// ============================================================================
//! # Socket - Arc<PoisonLock<EndpointInner>>ラッパー
//!
//! Socket と関連ヘルパー関数

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};

use crate::net::datapath::mempool::PacketRef;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};
use crate::sync::poison_lock::PoisonLock;
use kernel_api::resource::net::PacketPayload;

use crate::net::l4::tcp::TcpStream;

use super::event::{EventDispatch, NetworkEvent, enqueue_event_ignore_in, enqueue_event_in};
use super::inner::EndpointInner;
use super::manager::ENDPOINT_MANAGER;
use super::types::{
    EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointState, EndpointType, NEXT_FD,
};

fn register_endpoint(endpoint: &Endpoint) {
    if let Some(ref manager) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
        manager.register(endpoint.clone());
    }
}

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

    /// EndpointManager に登録済みの新規エンドポイント作成
    pub(crate) fn new_registered_in(
        endpoint_type: EndpointType,
        runtime: NetRuntimeHandle,
    ) -> Self {
        let endpoint = Self::new_in(endpoint_type, runtime);
        register_endpoint(&endpoint);
        endpoint
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
    /// 空の場合はTimeoutを返す。`TcpListener::next_connection()` が内部で使用する。
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
            register_endpoint(&new_socket);

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

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some((if_id, addr, _ttl, mut data)) =
            inner.udp_mut().and_then(|u| u.pending_packets.pop_front())
        {
            inner.last_ingress_if_id = Some(if_id);
            let len = data.copy_into(buf);
            return Ok((len, addr, if_id));
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
    pub fn push_packet_payload(
        &self,
        if_id: NetIfId,
        addr: EndpointAddr,
        ttl: u8,
        payload: PacketPayload,
    ) {
        let waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.last_ingress_if_id = Some(if_id);
            let udp = inner.ensure_udp();
            udp.ttl = ttl;
            udp.pending_packets.push_back((if_id, addr, ttl, payload));
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

        let recv_waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.last_ingress_if_id = Some(if_id);
            let udp = inner.ensure_udp();
            udp.ttl = ttl;
            udp.pending_packets.push_back((if_id, addr, ttl, payload));
            inner.recv_waker.take()
        };

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

    pub fn try_recv_udp_payload(
        &self,
    ) -> EndpointResult<(NetIfId, EndpointAddr, u8, PacketPayload)> {
        if self.endpoint_type != EndpointType::Udp {
            return Err(EndpointError::InvalidArgument);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if !inner.state.can_receive() {
            return Err(EndpointError::NotConnected);
        }

        if let Some((if_id, addr, ttl, payload)) = inner
            .udp_mut()
            .and_then(|udp| udp.pending_packets.pop_front())
        {
            inner.last_ingress_if_id = Some(if_id);
            return Ok((if_id, addr, ttl, payload));
        }

        Err(EndpointError::Timeout)
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

    /// 非同期クローズ（推奨API）
    ///
    /// エンドポイントの状態をクリーンアップし、
    /// イベントキュー経由でCloseを送出する。
    ///
    /// # 使用例
    /// ```ignore
    /// endpoint.close().await?;
    /// ```
    pub fn close(&self) -> impl core::future::Future<Output = EndpointResult<()>> {
        CloseFuture::new(self.clone())
    }
}

struct CloseFuture {
    endpoint: Endpoint,
    cleaned_up: bool,
    dispatch: EventDispatch,
}

impl CloseFuture {
    fn new(endpoint: Endpoint) -> Self {
        let runtime = endpoint.runtime();
        Self {
            endpoint,
            cleaned_up: false,
            dispatch: EventDispatch::new_in(runtime),
        }
    }
}

impl Future for CloseFuture {
    type Output = EndpointResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.cleaned_up {
            {
                let mut inner = this
                    .endpoint
                    .inner()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());

                inner.clear_tcp_payload_queues();
                inner.clear_protocol();

                if let Some(waker) = inner.recv_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = inner.send_waker.take() {
                    waker.wake();
                }
                if let Some(waker) = inner.connect_waker.take() {
                    waker.wake();
                }

                let _ = inner.transition_to(EndpointState::Closed);
            }

            this.cleaned_up = true;
        }

        match this.dispatch.poll(cx, || NetworkEvent::Close {
            fd: this.endpoint.fd(),
        }) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
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
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_new_registered_endpoint_registers_socket() {
        crate::net::l4::endpoint::manager::init_endpoint_manager();
        let endpoint = Endpoint::new_registered_in(EndpointType::Tcp, default_runtime());
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let manager = manager.as_ref().expect("endpoint manager");
        assert!(manager.get(endpoint.fd()).is_some());
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn registered_endpoint_smoke() -> bool {
        crate::net::l4::endpoint::manager::init_endpoint_manager();
        let endpoint = Endpoint::new_registered_in(EndpointType::Tcp, default_runtime());
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        manager
            .as_ref()
            .and_then(|mgr| mgr.get(endpoint.fd()))
            .is_some()
    }
}
