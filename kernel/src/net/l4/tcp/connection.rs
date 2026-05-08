// ============================================================================
// kernel/src/net/l4/tcp/connection.rs - L4 / TCP / 接続
// ============================================================================

use super::*;
use crate::net::l4::socket::{Socket, TcpSocketState};
use crate::net::l4::tcp::tcb::tcb_table;
use crate::net::l4::types::{EndpointError, SocketId};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{RuntimeCommand, enqueue_command_ignore_in, send_command_in};
use crate::net::types::InterfaceScope;
use crate::sync::PoisonLock;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use kernel_api::resource::net::PacketPayload;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    ConnectionClosed,
    ConnectionRefused,
    ConnectionReset,
    Timeout,
    AddressInUse,
    BufferFull,
    InvalidState,
    NetworkUnreachable,
    PermissionDenied,
}

fn tcp_error_from_socket(error: EndpointError) -> TcpError {
    match error {
        EndpointError::NotConnected => TcpError::ConnectionClosed,
        EndpointError::ConnectionRefused => TcpError::ConnectionRefused,
        EndpointError::Timeout => TcpError::Timeout,
        EndpointError::AddressInUse => TcpError::AddressInUse,
        EndpointError::BufferFull => TcpError::BufferFull,
        EndpointError::NetworkUnreachable => TcpError::NetworkUnreachable,
        EndpointError::PermissionDenied => TcpError::PermissionDenied,
        _ => TcpError::InvalidState,
    }
}

fn socket_send_budget(
    local: Option<EndpointAddr>,
    remote: Option<EndpointAddr>,
    queued_bytes: usize,
) -> usize {
    match (local, remote) {
        (Some(local), Some(remote)) => tcb_table()
            .read(local, remote, |tcb| tcb.effective_send_window() as usize)
            .unwrap_or(0)
            .saturating_sub(queued_bytes),
        _ => 0,
    }
}

fn on_recv_progress(local: Option<EndpointAddr>, remote: Option<EndpointAddr>, len: usize) {
    if len == 0 {
        return;
    }
    if let (Some(local), Some(remote)) = (local, remote) {
        let _ = tcb_table().lookup_mut(local, remote, |tcb| {
            tcb.on_data_consumed(len as u32);
        });
    }
}

fn socket_inner_stats(socket: &Socket) -> TcpStats {
    socket
        .inner()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .tcp()
        .map(|tcp| tcp.stats.clone())
        .unwrap_or_default()
}

type TcpCommandResultSlot<T> = alloc::sync::Arc<PoisonLock<Option<Result<T, TcpError>>>>;
type TcpCommandWaker = alloc::sync::Arc<crate::sync::atomic_waker::AtomicWaker>;

fn new_tcp_command_channel<T>() -> (TcpCommandResultSlot<T>, TcpCommandWaker) {
    (
        alloc::sync::Arc::new(PoisonLock::new(None)),
        alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
    )
}

fn poll_tcp_command_result<T>(
    result_slot: &TcpCommandResultSlot<T>,
    waker: &TcpCommandWaker,
    cx: &mut Context<'_>,
) -> Poll<Result<T, TcpError>> {
    if let Ok(mut slot) = result_slot.lock() {
        if let Some(result) = slot.take() {
            return Poll::Ready(result);
        }
    }

    waker.register(cx.waker());

    if let Ok(mut slot) = result_slot.lock() {
        if let Some(result) = slot.take() {
            return Poll::Ready(result);
        }
    }

    Poll::Pending
}

fn poll_tcp_dispatch<T>(
    runtime: NetRuntimeHandle,
    sent: &mut bool,
    result_slot: &TcpCommandResultSlot<T>,
    waker: &TcpCommandWaker,
    cx: &mut Context<'_>,
    event: RuntimeCommand,
) -> Poll<Result<T, TcpError>> {
    if !*sent {
        let mut enqueue = send_command_in(runtime, event);
        match Future::poll(Pin::new(&mut enqueue), cx) {
            Poll::Ready(Ok(())) => {
                *sent = true;
            }
            Poll::Ready(Err(_)) => return Poll::Ready(Err(TcpError::InvalidState)),
            Poll::Pending => return Poll::Pending,
        }
    }

    poll_tcp_command_result(result_slot, waker, cx)
}

struct TcpDialDispatchFuture {
    runtime: NetRuntimeHandle,
    result_slot: TcpCommandResultSlot<TcpConnection>,
    waker: TcpCommandWaker,
    sent: bool,
    local: EndpointAddr,
    remote: EndpointAddr,
    scope: InterfaceScope,
}

impl TcpDialDispatchFuture {
    fn new(
        runtime: NetRuntimeHandle,
        scope: InterfaceScope,
        local: EndpointAddr,
        remote: EndpointAddr,
    ) -> Self {
        let (result_slot, waker) = new_tcp_command_channel();
        Self {
            runtime,
            result_slot,
            waker,
            sent: false,
            local,
            remote,
            scope,
        }
    }
}

impl Future for TcpDialDispatchFuture {
    type Output = Result<TcpConnection, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let runtime = self.runtime;
        let local = self.local;
        let remote = self.remote;
        let scope = self.scope;
        let result_slot = self.result_slot.clone();
        let waker = self.waker.clone();
        let event =
            RuntimeCommand::Transport(crate::net::runtime::command::TransportCommand::TcpDial {
                local,
                remote,
                scope,
                result_slot: result_slot.clone(),
                waker: waker.clone(),
            });
        let sent = &mut self.sent;
        poll_tcp_dispatch(runtime, sent, &result_slot, &waker, cx, event)
    }
}

struct TcpAcceptorBindDispatchFuture {
    runtime: NetRuntimeHandle,
    result_slot: TcpCommandResultSlot<TcpAcceptor>,
    waker: TcpCommandWaker,
    sent: bool,
    addr: EndpointAddr,
    scope: InterfaceScope,
    backlog: u32,
}

impl TcpAcceptorBindDispatchFuture {
    fn new(
        runtime: NetRuntimeHandle,
        scope: InterfaceScope,
        addr: EndpointAddr,
        backlog: u32,
    ) -> Self {
        let (result_slot, waker) = new_tcp_command_channel();
        Self {
            runtime,
            result_slot,
            waker,
            sent: false,
            addr,
            scope,
            backlog,
        }
    }
}

impl Future for TcpAcceptorBindDispatchFuture {
    type Output = Result<TcpAcceptor, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let runtime = self.runtime;
        let addr = self.addr;
        let scope = self.scope;
        let backlog = self.backlog;
        let result_slot = self.result_slot.clone();
        let waker = self.waker.clone();
        let event =
            RuntimeCommand::Transport(crate::net::runtime::command::TransportCommand::TcpBind {
                local: addr,
                scope,
                backlog,
                result_slot: result_slot.clone(),
                waker: waker.clone(),
            });

        let sent = &mut self.sent;
        poll_tcp_dispatch(runtime, sent, &result_slot, &waker, cx, event)
    }
}

#[derive(Clone)]
pub struct TcpConnection {
    socket: Socket,
    runtime: NetRuntimeHandle,
    close_on_drop: bool,
}

impl core::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpConnection")
            .field("socket_id", &self.socket.socket_id().raw())
            .field("local_addr", &self.socket.local_addr())
            .field("peer_addr", &self.socket.remote_addr())
            .finish()
    }
}

impl TcpConnection {
    pub(crate) fn from_socket(socket: Socket) -> Self {
        debug_assert!(socket.is_tcp());
        Self {
            runtime: socket.runtime(),
            socket,
            close_on_drop: true,
        }
    }

    pub(crate) fn from_retained_socket(socket: Socket) -> Self {
        debug_assert!(socket.is_tcp());
        Self {
            runtime: socket.runtime(),
            socket,
            close_on_drop: false,
        }
    }

    pub(crate) fn socket(&self) -> &Socket {
        &self.socket
    }

    pub(crate) fn socket_id(&self) -> SocketId {
        self.socket.socket_id()
    }

    pub(crate) fn into_retained_handle(mut self) -> SocketId {
        self.close_on_drop = false;
        self.socket.socket_id()
    }

    pub async fn dial_in(runtime: NetRuntimeHandle, addr: EndpointAddr) -> Result<Self, TcpError> {
        Self::dial_scoped_in(runtime, InterfaceScope::Any, addr).await
    }

    pub async fn dial_scoped_in(
        runtime: NetRuntimeHandle,
        scope: InterfaceScope,
        addr: EndpointAddr,
    ) -> Result<Self, TcpError> {
        let local_addr = if addr.is_ipv6() {
            EndpointAddr::new_v6([0; 16], 0)
        } else {
            EndpointAddr::new([0, 0, 0, 0], 0)
        };

        let connection = TcpDialDispatchFuture::new(runtime, scope, local_addr, addr).await?;
        ConnectFuture {
            connection: connection.clone(),
        }
        .await?;
        Ok(connection)
    }

    pub async fn dial_timeout_in(
        runtime: NetRuntimeHandle,
        addr: EndpointAddr,
        timeout_us: u64,
    ) -> Result<Self, TcpError> {
        let local_addr = if addr.is_ipv6() {
            EndpointAddr::new_v6([0; 16], 0)
        } else {
            EndpointAddr::new([0, 0, 0, 0], 0)
        };

        let connection =
            TcpDialDispatchFuture::new(runtime, InterfaceScope::Any, local_addr, addr).await?;
        ConnectTimeoutFuture {
            connection: connection.clone(),
            start_us: crate::time::precise_time_nanos() / 1000,
            timeout_us,
        }
        .await?;
        Ok(connection)
    }

    pub const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
    }

    pub fn local_addr(&self) -> EndpointAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|| EndpointAddr::new([0, 0, 0, 0], 0))
    }

    pub fn peer_addr(&self) -> Option<EndpointAddr> {
        self.socket.remote_addr()
    }

    pub fn stats(&self) -> TcpStats {
        socket_inner_stats(&self.socket)
    }

    pub async fn recv_payload(&mut self) -> Option<PacketPayload> {
        RecvPayloadFuture { connection: self }.await
    }

    pub fn poll_recv_payload(&self, cx: &mut Context<'_>) -> Poll<Option<PacketPayload>> {
        let mut inner = self
            .socket
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            log::warn!(
                "[NET][tcp] payload receive observed socket error: {:?}",
                err
            );
        }

        if inner.has_recv_data() {
            let local = inner.local_addr;
            let remote = inner.remote_addr;
            let Some(payload) = inner.recv_payload(None) else {
                inner.recv_waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let delivered_len = payload.total_len();
            if let Some(tcp) = inner.tcp_mut() {
                tcp.stats.record_rx_delivered(delivered_len);
            }
            drop(inner);
            on_recv_progress(local, remote, delivered_len);
            return Poll::Ready(Some(payload));
        }

        if inner.is_tcp_closing_or_closed() {
            return Poll::Ready(None);
        }

        inner.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub async fn send_payload(&mut self, payload: PacketPayload) -> Result<(), TcpError> {
        SendPayloadFuture {
            connection: self,
            payload: Some(payload),
        }
        .await
    }

    pub async fn drain_tx(&mut self) -> Result<(), TcpError> {
        DrainTxFuture { connection: self }.await
    }

    pub fn close(&mut self) -> Result<(), TcpError> {
        let mut inner = self
            .socket
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        match inner.tcp_state() {
            Some(TcpSocketState::Closed | TcpSocketState::Closing) => return Ok(()),
            Some(TcpSocketState::Connected | TcpSocketState::Connecting) => {
                let _ = inner.set_tcp_state(TcpSocketState::Closing);
            }
            _ => return Err(TcpError::InvalidState),
        }
        drop(inner);

        enqueue_command_ignore_in(
            self.runtime,
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::CloseSocket {
                    socket_id: self.socket.socket_id(),
                },
            ),
        );
        Ok(())
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        if !self.close_on_drop {
            return;
        }

        if alloc::sync::Arc::strong_count(self.socket.inner()) > 2 {
            return;
        }

        enqueue_command_ignore_in(
            self.runtime,
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::CloseSocket {
                    socket_id: self.socket.socket_id(),
                },
            ),
        );
    }
}

#[derive(Clone)]
pub struct TcpAcceptor {
    socket: Socket,
    runtime: NetRuntimeHandle,
    close_on_drop: bool,
}

impl core::fmt::Debug for TcpAcceptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpAcceptor")
            .field("socket_id", &self.socket.socket_id().raw())
            .field("local_addr", &self.socket.local_addr())
            .finish()
    }
}

impl TcpAcceptor {
    pub(crate) fn from_socket(socket: Socket) -> Self {
        debug_assert!(socket.is_tcp());
        Self {
            runtime: socket.runtime(),
            socket,
            close_on_drop: true,
        }
    }

    pub(crate) fn from_retained_socket(socket: Socket) -> Self {
        debug_assert!(socket.is_tcp());
        Self {
            runtime: socket.runtime(),
            socket,
            close_on_drop: false,
        }
    }

    pub(crate) fn socket(&self) -> &Socket {
        &self.socket
    }

    pub(crate) fn into_retained_handle(mut self) -> SocketId {
        self.close_on_drop = false;
        self.socket.socket_id()
    }

    pub async fn bind_in(runtime: NetRuntimeHandle, addr: EndpointAddr) -> Result<Self, TcpError> {
        Self::bind_scoped_in(
            runtime,
            InterfaceScope::Any,
            addr,
            crate::net::l4::socket::DEFAULT_TCP_ACCEPT_BACKLOG as u32,
        )
        .await
    }

    pub async fn bind_scoped_in(
        runtime: NetRuntimeHandle,
        scope: InterfaceScope,
        addr: EndpointAddr,
        backlog: u32,
    ) -> Result<Self, TcpError> {
        TcpAcceptorBindDispatchFuture::new(runtime, scope, addr, backlog).await
    }

    pub fn local_addr(&self) -> EndpointAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|| EndpointAddr::new([0, 0, 0, 0], 0))
    }

    pub const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
    }

    pub async fn next_connection(&self) -> Result<(TcpConnection, EndpointAddr), TcpError> {
        AcceptFuture { acceptor: self }.await
    }
}

impl Drop for TcpAcceptor {
    fn drop(&mut self) {
        if !self.close_on_drop {
            return;
        }

        if alloc::sync::Arc::strong_count(self.socket.inner()) > 2 {
            return;
        }

        enqueue_command_ignore_in(
            self.runtime,
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::CloseSocket {
                    socket_id: self.socket.socket_id(),
                },
            ),
        );
    }
}

pub(crate) struct ConnectFuture {
    connection: TcpConnection,
}

impl Future for ConnectFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this
            .connection
            .socket
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_socket(err)));
        }

        match inner.tcp_state() {
            Some(TcpSocketState::Connected) => Poll::Ready(Ok(())),
            Some(TcpSocketState::Closed | TcpSocketState::Closing) => {
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
            Some(TcpSocketState::Connecting) => {
                inner.connect_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            _ => Poll::Ready(Err(TcpError::InvalidState)),
        }
    }
}

pub(crate) struct ConnectTimeoutFuture {
    connection: TcpConnection,
    start_us: u64,
    timeout_us: u64,
}

impl Future for ConnectTimeoutFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this
            .connection
            .socket
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_socket(err)));
        }

        match inner.tcp_state() {
            Some(TcpSocketState::Connected) => Poll::Ready(Ok(())),
            Some(TcpSocketState::Closed | TcpSocketState::Closing) => {
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
            Some(TcpSocketState::Connecting) => {
                let now = crate::time::precise_time_nanos() / 1000;
                if now.saturating_sub(this.start_us) >= this.timeout_us {
                    drop(inner);
                    enqueue_command_ignore_in(
                        this.connection.runtime,
                        RuntimeCommand::Transport(
                            crate::net::runtime::command::TransportCommand::CloseSocket {
                                socket_id: this.connection.socket.socket_id(),
                            },
                        ),
                    );
                    return Poll::Ready(Err(TcpError::Timeout));
                }
                inner.connect_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            _ => Poll::Ready(Err(TcpError::InvalidState)),
        }
    }
}

pub(crate) struct AcceptFuture<'a> {
    acceptor: &'a TcpAcceptor,
}

impl<'a> Future for AcceptFuture<'a> {
    type Output = Result<(TcpConnection, EndpointAddr), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.acceptor.socket.try_next_incoming() {
            Ok((socket, addr, _if_id)) => {
                Poll::Ready(Ok((TcpConnection::from_socket(socket), addr)))
            }
            Err(EndpointError::Timeout) => {
                self.acceptor
                    .socket
                    .register_accept_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(tcp_error_from_socket(err))),
        }
    }
}

pub(crate) struct RecvPayloadFuture<'a> {
    connection: &'a mut TcpConnection,
}

impl<'a> Future for RecvPayloadFuture<'a> {
    type Output = Option<PacketPayload>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.connection.poll_recv_payload(cx)
    }
}

pub(crate) struct SendPayloadFuture<'a> {
    connection: &'a mut TcpConnection,
    payload: Option<PacketPayload>,
}

impl<'a> Future for SendPayloadFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let Some(payload) = this.payload.take() else {
            return Poll::Ready(Err(TcpError::InvalidState));
        };
        let payload_len = payload.total_len();
        if payload_len == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut inner = this
            .connection
            .socket
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            this.payload = Some(payload);
            return Poll::Ready(Err(tcp_error_from_socket(err)));
        }

        if inner.is_tcp_closing_or_closed() {
            return Poll::Ready(Err(TcpError::ConnectionClosed));
        }

        if !matches!(inner.tcp_state(), Some(TcpSocketState::Connected)) {
            return Poll::Ready(Err(TcpError::InvalidState));
        }

        if payload_len > inner.send_buffer_limit {
            return Poll::Ready(Err(TcpError::BufferFull));
        }

        let queued_bytes = inner.send_payload_bytes();
        let available =
            inner
                .send_buffer_limit
                .saturating_sub(queued_bytes)
                .min(socket_send_budget(
                    inner.local_addr,
                    inner.remote_addr,
                    queued_bytes,
                ));

        if available < payload_len {
            let has_queued_data = inner.has_send_data();
            inner.send_waker = Some(cx.waker().clone());
            drop(inner);
            if has_queued_data {
                enqueue_command_ignore_in(
                    this.connection.runtime,
                    RuntimeCommand::Transport(
                        crate::net::runtime::command::TransportCommand::TcpDataReady {
                            socket_id: this.connection.socket.socket_id(),
                        },
                    ),
                );
            }
            this.payload = Some(payload);
            return Poll::Pending;
        }

        match inner.send_payload(payload) {
            Ok(()) => {
                if let Some(tcp) = inner.tcp_mut() {
                    tcp.stats.record_tx_enqueued(payload_len);
                }
            }
            Err(err) => return Poll::Ready(Err(tcp_error_from_socket(err))),
        }
        drop(inner);

        enqueue_command_ignore_in(
            this.connection.runtime,
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDataReady {
                    socket_id: this.connection.socket.socket_id(),
                },
            ),
        );

        Poll::Ready(Ok(()))
    }
}

pub(crate) struct DrainTxFuture<'a> {
    connection: &'a mut TcpConnection,
}

impl<'a> Future for DrainTxFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this
            .connection
            .socket
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_socket(err)));
        }

        if !inner.has_send_data() {
            return Poll::Ready(Ok(()));
        }

        inner.send_waker = Some(cx.waker().clone());
        drop(inner);

        enqueue_command_ignore_in(
            this.connection.runtime,
            RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::TcpDataReady {
                    socket_id: this.connection.socket.socket_id(),
                },
            ),
        );
        Poll::Pending
    }
}
