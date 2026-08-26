// ============================================================================
// kernel/src/net/l4/tcp/connection.rs - L4 / TCP / 接続
// ============================================================================

use super::*;
use crate::net::l4::socket::{Socket, TcpSocketState};
use crate::net::l4::types::{EndpointError, SocketId};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    CommandFuture, CommandReplyPayload, CommandReplyTicket, RuntimeCommand, new_command_channel_in,
    send_command_in, try_enqueue_command_in,
};
use crate::net::runtime::transport::tcp_table_in;
use crate::net::types::InterfaceScope;
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

pub struct TcpPayloadSendError {
    cause: TcpError,
    payload: PacketPayload,
}

impl TcpPayloadSendError {
    pub const fn cause(&self) -> TcpError {
        self.cause
    }

    pub fn into_parts(self) -> (TcpError, PacketPayload) {
        (self.cause, self.payload)
    }
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
    runtime: NetRuntimeHandle,
    socket_id: SocketId,
    queued_bytes: usize,
) -> usize {
    tcp_table_in(runtime)
        .read_by_socket_id(socket_id, |tcb| tcb.effective_send_window() as usize)
        .unwrap_or(0)
        .saturating_sub(queued_bytes)
}

fn on_recv_progress(runtime: NetRuntimeHandle, socket_id: SocketId, len: usize) {
    if len == 0 {
        return;
    }
    let _ = tcp_table_in(runtime).record_data_consumed_by_socket_id(socket_id, len as u32);
}

fn close_socket_abortively_in(runtime: NetRuntimeHandle, socket_id: SocketId) {
    let _ = tcp_table_in(runtime).remove_by_socket_id(socket_id);
    if let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, socket_id) {
        let _ = socket.with_inner_mut(|inner| {
            inner.mark_closed();
            inner.recv_waker.wake();
            inner.send_waker.wake();
            inner.connect_waker.wake();
            inner.accept_waker.wake();
        });
    }
    let _ = crate::net::l4::socket::unregister_socket_in(runtime, socket_id);
}

fn try_enqueue_close_socket_in(
    runtime: NetRuntimeHandle,
    socket_id: SocketId,
) -> Result<(), TcpError> {
    try_enqueue_command_in(
        runtime,
        RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::CloseSocket { socket_id },
        ),
    )
    .map_err(|_| TcpError::BufferFull)
}

fn trigger_tcp_data_ready_in(runtime: NetRuntimeHandle, socket_id: SocketId) {
    if try_enqueue_command_in(
        runtime,
        RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::TcpDataReady { socket_id },
        ),
    )
    .is_err()
    {
        let _ = crate::net::runtime::command_handler::drive_tcp_data_ready_in(runtime, socket_id);
    }
}

fn socket_inner_stats(socket: &Socket) -> TcpStats {
    socket
        .with_inner(|inner| inner.tcp().map(|tcp| tcp.stats).unwrap_or_default())
        .unwrap_or_default()
}

fn poll_tcp_dispatch<T>(
    runtime: NetRuntimeHandle,
    sent: &mut bool,
    command_future: &mut CommandFuture<Result<T, TcpError>>,
    cx: &mut Context<'_>,
    event: RuntimeCommand,
) -> Poll<Result<T, TcpError>>
where
    Result<T, TcpError>: CommandReplyPayload,
{
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

    Future::poll(Pin::new(command_future), cx)
}

struct TcpDialDispatchFuture {
    runtime: NetRuntimeHandle,
    reply: CommandReplyTicket<Result<TcpConnection, TcpError>>,
    command_future: CommandFuture<Result<TcpConnection, TcpError>>,
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
        let (reply, command_future) = new_command_channel_in(runtime);
        Self {
            runtime,
            reply,
            command_future,
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
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        let runtime = this.runtime;
        let local = this.local;
        let remote = this.remote;
        let scope = this.scope;
        let reply = this.reply;
        let event =
            RuntimeCommand::Transport(crate::net::runtime::command::TransportCommand::TcpDial {
                local,
                remote,
                scope,
                reply,
            });
        let sent = &mut this.sent;
        let command_future = &mut this.command_future;
        poll_tcp_dispatch(runtime, sent, command_future, cx, event)
    }
}

struct TcpAcceptorBindDispatchFuture {
    runtime: NetRuntimeHandle,
    reply: CommandReplyTicket<Result<TcpAcceptor, TcpError>>,
    command_future: CommandFuture<Result<TcpAcceptor, TcpError>>,
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
        let (reply, command_future) = new_command_channel_in(runtime);
        Self {
            runtime,
            reply,
            command_future,
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
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        let runtime = this.runtime;
        let addr = this.addr;
        let scope = this.scope;
        let backlog = this.backlog;
        let reply = this.reply;
        let event =
            RuntimeCommand::Transport(crate::net::runtime::command::TransportCommand::TcpBind {
                local: addr,
                scope,
                backlog,
                reply,
            });

        let sent = &mut this.sent;
        let command_future = &mut this.command_future;
        poll_tcp_dispatch(runtime, sent, command_future, cx, event)
    }
}

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
            connection: &connection,
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
            connection: &connection,
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
        enum RecvOutcome {
            Payload(PacketPayload, usize),
            Closed,
            Pending,
        }

        let outcome = self
            .socket
            .with_inner_mut(|inner| {
                if let Some(err) = inner.last_error.take() {
                    log::warn!(
                        "[NET][tcp] payload receive observed socket error: {:?}",
                        err
                    );
                }

                if inner.has_recv_data() {
                    let Some(payload) = inner.recv_payload(None) else {
                        inner.recv_waker.register(cx.waker());
                        return RecvOutcome::Pending;
                    };
                    let delivered_len = payload.total_len();
                    if let Some(tcp) = inner.tcp_mut() {
                        tcp.stats.record_rx_delivered(delivered_len);
                    }
                    return RecvOutcome::Payload(payload, delivered_len);
                }

                if inner.is_tcp_closing_or_closed() {
                    return RecvOutcome::Closed;
                }

                inner.recv_waker.register(cx.waker());
                RecvOutcome::Pending
            })
            .unwrap_or(RecvOutcome::Closed);

        match outcome {
            RecvOutcome::Payload(payload, delivered_len) => {
                on_recv_progress(self.runtime, self.socket.socket_id(), delivered_len);
                Poll::Ready(Some(payload))
            }
            RecvOutcome::Closed => Poll::Ready(None),
            RecvOutcome::Pending => Poll::Pending,
        }
    }

    pub async fn send_payload(
        &mut self,
        payload: PacketPayload,
    ) -> Result<(), TcpPayloadSendError> {
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
        self.socket
            .with_inner_mut(|inner| match inner.tcp_state() {
                Some(TcpSocketState::Closed | TcpSocketState::Closing) => Ok(()),
                Some(TcpSocketState::Connected | TcpSocketState::Connecting) => {
                    let _ = inner.set_tcp_state(TcpSocketState::Closing);
                    Ok(())
                }
                _ => Err(TcpError::InvalidState),
            })
            .unwrap_or(Err(TcpError::InvalidState))?;

        try_enqueue_close_socket_in(self.runtime, self.socket.socket_id())?;
        Ok(())
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        if !self.close_on_drop {
            return;
        }

        close_socket_abortively_in(self.runtime, self.socket.socket_id());
    }
}

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

        close_socket_abortively_in(self.runtime, self.socket.socket_id());
    }
}

pub(crate) struct ConnectFuture<'a> {
    connection: &'a TcpConnection,
}

impl<'a> Future for ConnectFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.connection
            .socket
            .with_inner_mut(|inner| {
                if let Some(err) = inner.last_error.take() {
                    return Poll::Ready(Err(tcp_error_from_socket(err)));
                }

                match inner.tcp_state() {
                    Some(TcpSocketState::Connected) => Poll::Ready(Ok(())),
                    Some(TcpSocketState::Closed | TcpSocketState::Closing) => {
                        Poll::Ready(Err(TcpError::ConnectionRefused))
                    }
                    Some(TcpSocketState::Connecting) => {
                        inner.connect_waker.register(cx.waker());
                        Poll::Pending
                    }
                    _ => Poll::Ready(Err(TcpError::InvalidState)),
                }
            })
            .unwrap_or(Poll::Ready(Err(TcpError::InvalidState)))
    }
}

pub(crate) struct ConnectTimeoutFuture<'a> {
    connection: &'a TcpConnection,
    start_us: u64,
    timeout_us: u64,
}

impl<'a> Future for ConnectTimeoutFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let now = crate::time::precise_time_nanos() / 1000;
        let timeout = now.saturating_sub(this.start_us) >= this.timeout_us;
        let outcome = this
            .connection
            .socket
            .with_inner_mut(|inner| {
                if let Some(err) = inner.last_error.take() {
                    return Poll::Ready(Err(tcp_error_from_socket(err)));
                }

                match inner.tcp_state() {
                    Some(TcpSocketState::Connected) => Poll::Ready(Ok(())),
                    Some(TcpSocketState::Closed | TcpSocketState::Closing) => {
                        Poll::Ready(Err(TcpError::ConnectionRefused))
                    }
                    Some(TcpSocketState::Connecting) => {
                        if timeout {
                            return Poll::Ready(Err(TcpError::Timeout));
                        }
                        inner.connect_waker.register(cx.waker());
                        Poll::Pending
                    }
                    _ => Poll::Ready(Err(TcpError::InvalidState)),
                }
            })
            .unwrap_or(Poll::Ready(Err(TcpError::InvalidState)));

        if matches!(outcome, Poll::Ready(Err(TcpError::Timeout))) {
            close_socket_abortively_in(this.connection.runtime, this.connection.socket.socket_id());
        }
        outcome
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
                self.acceptor.socket.register_accept_waker(cx.waker());
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
    type Output = Result<(), TcpPayloadSendError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        enum SendOutcome {
            Enqueued,
            Pending {
                payload: PacketPayload,
                has_queued_data: bool,
            },
            Ready(TcpError),
        }

        let this = &mut *self;
        let Some(payload) = this.payload.take() else {
            panic!("TCP send future polled after completion");
        };
        let runtime = this.connection.runtime;
        let payload_len = payload.total_len();
        let mut owner = Some(payload);

        let outcome =
            this.connection
                .socket
                .with_inner_mut(|inner| {
                    if let Some(err) = inner.last_error.take() {
                        return SendOutcome::Ready(tcp_error_from_socket(err));
                    }

                    if inner.is_tcp_closing_or_closed() {
                        return SendOutcome::Ready(TcpError::ConnectionClosed);
                    }

                    if !matches!(inner.tcp_state(), Some(TcpSocketState::Connected)) {
                        return SendOutcome::Ready(TcpError::InvalidState);
                    }

                    if payload_len > inner.send_buffer_limit {
                        return SendOutcome::Ready(TcpError::BufferFull);
                    }

                    let queued_bytes = inner.send_payload_bytes();
                    let available = inner.send_buffer_limit.saturating_sub(queued_bytes).min(
                        socket_send_budget(
                            runtime,
                            this.connection.socket.socket_id(),
                            queued_bytes,
                        ),
                    );

                    if available < payload_len {
                        let has_queued_data = inner.has_send_data();
                        inner.send_waker.register(cx.waker());
                        return SendOutcome::Pending {
                            payload: owner
                                .take()
                                .expect("pending TCP send preserves the payload owner"),
                            has_queued_data,
                        };
                    }

                    match inner
                        .send_payload(owner.take().expect("admitted TCP send owns the payload"))
                    {
                        Ok(()) => {
                            if let Some(tcp) = inner.tcp_mut() {
                                tcp.stats.record_tx_enqueued(payload_len);
                            }
                            SendOutcome::Enqueued
                        }
                        Err((err, payload)) => {
                            owner = Some(payload);
                            SendOutcome::Ready(tcp_error_from_socket(err))
                        }
                    }
                })
                .unwrap_or(SendOutcome::Ready(TcpError::InvalidState));

        match outcome {
            SendOutcome::Enqueued => {
                trigger_tcp_data_ready_in(
                    this.connection.runtime,
                    this.connection.socket.socket_id(),
                );
                Poll::Ready(Ok(()))
            }
            SendOutcome::Pending {
                payload,
                has_queued_data,
            } => {
                if has_queued_data {
                    trigger_tcp_data_ready_in(
                        this.connection.runtime,
                        this.connection.socket.socket_id(),
                    );
                }
                this.payload = Some(payload);
                Poll::Pending
            }
            SendOutcome::Ready(cause) => Poll::Ready(Err(TcpPayloadSendError {
                cause,
                payload: owner.expect("rejected TCP send preserves the payload owner"),
            })),
        }
    }
}

pub(crate) struct DrainTxFuture<'a> {
    connection: &'a mut TcpConnection,
}

impl<'a> Future for DrainTxFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let has_send_data = match this.connection.socket.with_inner_mut(|inner| {
            if let Some(err) = inner.last_error.take() {
                return Err(tcp_error_from_socket(err));
            }

            if !inner.has_send_data() {
                return Ok(false);
            }

            inner.send_waker.register(cx.waker());
            Ok(true)
        }) {
            Some(Ok(has_send_data)) => has_send_data,
            Some(Err(err)) => return Poll::Ready(Err(err)),
            None => return Poll::Ready(Err(TcpError::InvalidState)),
        };

        if !has_send_data {
            return Poll::Ready(Ok(()));
        }

        trigger_tcp_data_ready_in(this.connection.runtime, this.connection.socket.socket_id());
        Poll::Pending
    }
}
