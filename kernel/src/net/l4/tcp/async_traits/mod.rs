use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::l4::endpoint::endpoint_core::Endpoint;
use crate::net::l4::endpoint::event::{NetworkEvent, enqueue_event_ignore_in};
use crate::net::l4::endpoint::tcb::tcb_table;
use crate::net::l4::endpoint::types::{EndpointError, EndpointFd, EndpointState, EndpointType};
use crate::net::payload::payload_from_bytes;
use crate::net::runtime::{NetRuntimeHandle, default_runtime};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use kernel_api::resource::net::PacketPayload;

/// Non-POSIX async read API for TCP streams.
pub trait AsyncRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>>;
}

/// Non-POSIX async write API for TCP streams.
pub trait AsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>>;

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>>;

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>>;
}

/// Public TCP error surface.
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

fn tcp_error_from_endpoint(error: EndpointError) -> TcpError {
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

fn endpoint_send_budget(
    local: Option<EndpointAddr>,
    remote: Option<EndpointAddr>,
    queued_bytes: usize,
) -> usize {
    match (local, remote) {
        (Some(local), Some(remote)) => tcb_table()
            .get(local, remote)
            .map(|tcb| tcb.effective_send_window() as usize)
            .unwrap_or(0)
            .saturating_sub(queued_bytes),
        _ => 0,
    }
}

fn on_read_progress(local: Option<EndpointAddr>, remote: Option<EndpointAddr>, len: usize) {
    if len == 0 {
        return;
    }
    if let (Some(local), Some(remote)) = (local, remote) {
        let _ = tcb_table().lookup_mut(local, remote, |tcb| {
            tcb.on_data_consumed(len as u32);
        });
    }
}

fn endpoint_inner_stats(endpoint: &Endpoint) -> TcpStats {
    endpoint
        .inner()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .tcp()
        .map(|tcp| tcp.stats.clone())
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct TcpStream {
    endpoint: Endpoint,
    runtime: NetRuntimeHandle,
    close_on_drop: bool,
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("fd", &self.endpoint.fd().raw())
            .field("local_addr", &self.endpoint.local_addr())
            .field("peer_addr", &self.endpoint.remote_addr())
            .finish()
    }
}

impl TcpStream {
    pub(crate) fn from_endpoint(endpoint: Endpoint) -> Self {
        Self::from_endpoint_with_drop(endpoint, true)
    }

    pub(crate) fn from_endpoint_with_drop(endpoint: Endpoint, close_on_drop: bool) -> Self {
        debug_assert_eq!(endpoint.socket_type(), EndpointType::Tcp);
        Self {
            runtime: endpoint.runtime(),
            endpoint,
            close_on_drop,
        }
    }

    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub(crate) fn fd(&self) -> EndpointFd {
        self.endpoint.fd()
    }

    pub(crate) fn into_retained_handle(mut self) -> EndpointFd {
        self.close_on_drop = false;
        self.endpoint.fd()
    }

    pub async fn dial(addr: EndpointAddr) -> Result<Self, TcpError> {
        Self::dial_in(default_runtime(), addr).await
    }

    pub async fn dial_in(runtime: NetRuntimeHandle, addr: EndpointAddr) -> Result<Self, TcpError> {
        let local_addr = if addr.is_ipv6() {
            EndpointAddr::new_v6([0; 16], 0)
        } else {
            EndpointAddr::new([0, 0, 0, 0], 0)
        };

        let stream =
            crate::net::runtime::stack::connect_tcp_stream_in(runtime, local_addr, addr).await?;
        ConnectFuture {
            stream: stream.clone(),
        }
        .await?;
        Ok(stream)
    }

    pub async fn dial_timeout(addr: EndpointAddr, timeout_us: u64) -> Result<Self, TcpError> {
        Self::dial_timeout_in(default_runtime(), addr, timeout_us).await
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

        let stream =
            crate::net::runtime::stack::connect_tcp_stream_in(runtime, local_addr, addr).await?;
        ConnectTimeoutFuture {
            stream: stream.clone(),
            start_us: crate::time::precise_time_nanos() / 1000,
            timeout_us,
        }
        .await?;
        Ok(stream)
    }

    pub const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
    }

    pub fn local_addr(&self) -> EndpointAddr {
        self.endpoint
            .local_addr()
            .unwrap_or_else(|| EndpointAddr::new([0, 0, 0, 0], 0))
    }

    pub fn peer_addr(&self) -> Option<EndpointAddr> {
        self.endpoint.remote_addr()
    }

    pub fn stats(&self) -> TcpStats {
        endpoint_inner_stats(&self.endpoint)
    }

    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadFuture<'a> {
        ReadFuture { stream: self, buf }
    }

    pub async fn read_zero_copy(&mut self) -> Option<PacketPayload> {
        ZeroCopyReadFuture { stream: self }.await
    }

    pub fn poll_recv_zero_copy(&self, cx: &mut Context<'_>) -> Poll<Option<PacketPayload>> {
        let mut inner = self
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            log::warn!(
                "[NET][tcp] zero-copy receive observed endpoint error: {:?}",
                err
            );
        }

        if inner.has_recv_data() {
            let local = inner.local_addr;
            let remote = inner.remote_addr;
            let Some(payload) = inner.recv_payload(Some(1500)) else {
                inner.recv_waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let delivered_len = payload.total_len();
            if let Some(tcp) = inner.tcp_mut() {
                tcp.stats.record_rx_delivered(delivered_len);
            }
            drop(inner);
            on_read_progress(local, remote, delivered_len);
            return Poll::Ready(Some(payload));
        }

        if matches!(inner.state, EndpointState::Closed | EndpointState::Closing) {
            return Poll::Ready(None);
        }

        inner.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub fn write<'a>(&'a mut self, buf: &'a [u8]) -> WriteFuture<'a> {
        WriteFuture { stream: self, buf }
    }

    pub fn flush(&mut self) -> FlushFuture<'_> {
        FlushFuture { stream: self }
    }

    pub async fn write_zero_copy(&mut self, packet: PacketRef) -> Result<(), TcpError> {
        ZeroCopyWriteFuture {
            stream: self,
            packet: Some(packet),
        }
        .await
    }

    pub async fn shutdown(&mut self) -> Result<(), TcpError> {
        ShutdownFuture { stream: self }.await
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if !self.close_on_drop {
            return;
        }

        if alloc::sync::Arc::strong_count(self.endpoint.inner()) > 2 {
            return;
        }

        enqueue_event_ignore_in(
            self.runtime,
            NetworkEvent::Close {
                fd: self.endpoint.fd(),
            },
        );
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>> {
        let this = self.get_mut();
        let mut inner = this
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_endpoint(err)));
        }

        if inner.has_recv_data() {
            let local = inner.local_addr;
            let remote = inner.remote_addr;
            let len = inner.recv_from_buffer(buf);
            if let Some(tcp) = inner.tcp_mut() {
                tcp.stats.record_rx_delivered(len);
            }
            drop(inner);
            on_read_progress(local, remote, len);
            return Poll::Ready(Ok(len));
        }

        if matches!(inner.state, EndpointState::Closed | EndpointState::Closing) {
            return Poll::Ready(Ok(0));
        }

        if !inner.state.can_receive() {
            return Poll::Ready(Err(TcpError::InvalidState));
        }

        inner.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>> {
        let this = self.get_mut();
        let mut inner = this
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_endpoint(err)));
        }

        if matches!(inner.state, EndpointState::Closed | EndpointState::Closing) {
            return Poll::Ready(Err(TcpError::ConnectionClosed));
        }

        if !inner.state.can_send() {
            return Poll::Ready(Err(TcpError::InvalidState));
        }

        let send_buffer_limit = inner.send_buffer_limit;
        let queued_bytes = inner.send_payload_bytes();
        let available = send_buffer_limit
            .saturating_sub(queued_bytes)
            .min(endpoint_send_budget(
                inner.local_addr,
                inner.remote_addr,
                queued_bytes,
            ));

        if available == 0 {
            inner.send_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let len = available.min(buf.len());
        let Some(payload) = payload_from_bytes(&buf[..len]) else {
            return Poll::Ready(Err(TcpError::BufferFull));
        };
        match inner.send_payload(payload) {
            Ok(queued) => {
                if let Some(tcp) = inner.tcp_mut() {
                    tcp.stats.record_tx_enqueued(queued);
                }
            }
            Err(err) => return Poll::Ready(Err(tcp_error_from_endpoint(err))),
        }
        drop(inner);

        enqueue_event_ignore_in(
            this.runtime,
            NetworkEvent::DataReady {
                fd: this.endpoint.fd(),
                endpoint_type: EndpointType::Tcp,
            },
        );

        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        let this = self.get_mut();
        let mut inner = this
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if !inner.has_send_data() {
            return Poll::Ready(Ok(()));
        }

        inner.send_waker = Some(cx.waker().clone());
        drop(inner);

        enqueue_event_ignore_in(
            this.runtime,
            NetworkEvent::DataReady {
                fd: this.endpoint.fd(),
                endpoint_type: EndpointType::Tcp,
            },
        );

        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        let this = self.get_mut();
        let mut inner = this
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        match inner.state {
            EndpointState::Connected => {
                let _ = inner.transition_to(EndpointState::Closing);
            }
            EndpointState::Closing | EndpointState::Closed => return Poll::Ready(Ok(())),
            _ => return Poll::Ready(Err(TcpError::InvalidState)),
        }
        drop(inner);

        enqueue_event_ignore_in(
            this.runtime,
            NetworkEvent::Close {
                fd: this.endpoint.fd(),
            },
        );

        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
pub struct TcpListener {
    endpoint: Endpoint,
    runtime: NetRuntimeHandle,
    close_on_drop: bool,
}

impl core::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpListener")
            .field("fd", &self.endpoint.fd().raw())
            .field("local_addr", &self.endpoint.local_addr())
            .finish()
    }
}

impl TcpListener {
    pub(crate) fn from_endpoint(endpoint: Endpoint) -> Self {
        Self::from_endpoint_with_drop(endpoint, true)
    }

    pub(crate) fn from_endpoint_with_drop(endpoint: Endpoint, close_on_drop: bool) -> Self {
        debug_assert_eq!(endpoint.socket_type(), EndpointType::Tcp);
        Self {
            runtime: endpoint.runtime(),
            endpoint,
            close_on_drop,
        }
    }

    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub(crate) fn into_retained_handle(mut self) -> EndpointFd {
        self.close_on_drop = false;
        self.endpoint.fd()
    }

    pub async fn listen_on(addr: EndpointAddr) -> Result<Self, TcpError> {
        Self::listen_on_in(default_runtime(), addr).await
    }

    pub async fn listen_on_in(
        runtime: NetRuntimeHandle,
        addr: EndpointAddr,
    ) -> Result<Self, TcpError> {
        crate::net::runtime::stack::bind_tcp_listener_in(runtime, addr).await
    }

    pub async fn listen_on_with_token(
        addr: EndpointAddr,
        token: Option<u64>,
    ) -> Result<Self, TcpError> {
        Self::listen_on_with_token_in(default_runtime(), addr, token).await
    }

    pub async fn listen_on_with_token_in(
        runtime: NetRuntimeHandle,
        addr: EndpointAddr,
        token: Option<u64>,
    ) -> Result<Self, TcpError> {
        crate::net::runtime::stack::bind_tcp_listener_with_token_in(runtime, addr, token).await
    }

    pub fn local_addr(&self) -> EndpointAddr {
        self.endpoint
            .local_addr()
            .unwrap_or_else(|| EndpointAddr::new([0, 0, 0, 0], 0))
    }

    pub const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
    }

    pub async fn next_connection(&self) -> Result<(TcpStream, EndpointAddr), TcpError> {
        AcceptFuture { listener: self }.await
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if !self.close_on_drop {
            return;
        }

        if alloc::sync::Arc::strong_count(self.endpoint.inner()) > 2 {
            return;
        }

        enqueue_event_ignore_in(
            self.runtime,
            NetworkEvent::UnbindTcpListener {
                fd: self.endpoint.fd(),
                result_slot: alloc::sync::Arc::new(crate::sync::PoisonLock::new(None)),
                waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
            },
        );
    }
}

pub(crate) struct ConnectFuture {
    stream: TcpStream,
}

impl Future for ConnectFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this
            .stream
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_endpoint(err)));
        }

        match inner.state {
            EndpointState::Connected => Poll::Ready(Ok(())),
            EndpointState::Closed | EndpointState::Closing => {
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
            EndpointState::Connecting => {
                inner.connect_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            _ => Poll::Ready(Err(TcpError::InvalidState)),
        }
    }
}

pub(crate) struct ConnectTimeoutFuture {
    stream: TcpStream,
    start_us: u64,
    timeout_us: u64,
}

impl Future for ConnectTimeoutFuture {
    type Output = Result<(), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this
            .stream
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            return Poll::Ready(Err(tcp_error_from_endpoint(err)));
        }

        match inner.state {
            EndpointState::Connected => Poll::Ready(Ok(())),
            EndpointState::Closed | EndpointState::Closing => {
                Poll::Ready(Err(TcpError::ConnectionRefused))
            }
            EndpointState::Connecting => {
                let now = crate::time::precise_time_nanos() / 1000;
                if now.saturating_sub(this.start_us) >= this.timeout_us {
                    drop(inner);
                    enqueue_event_ignore_in(
                        this.stream.runtime,
                        NetworkEvent::Close {
                            fd: this.stream.endpoint.fd(),
                        },
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

pub struct ReadFuture<'a> {
    stream: &'a mut TcpStream,
    buf: &'a mut [u8],
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<usize, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_read(cx, this.buf)
    }
}

pub struct WriteFuture<'a> {
    stream: &'a mut TcpStream,
    buf: &'a [u8],
}

impl<'a> Future for WriteFuture<'a> {
    type Output = Result<usize, TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_write(cx, this.buf)
    }
}

pub struct FlushFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for FlushFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_flush(cx)
    }
}

pub(crate) struct AcceptFuture<'a> {
    listener: &'a TcpListener,
}

impl<'a> Future for AcceptFuture<'a> {
    type Output = Result<(TcpStream, EndpointAddr), TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.listener.endpoint.next_incoming_sync() {
            Ok((endpoint, addr, _if_id)) => {
                Poll::Ready(Ok((TcpStream::from_endpoint(endpoint), addr)))
            }
            Err(EndpointError::Timeout) => {
                self.listener
                    .endpoint
                    .register_accept_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(tcp_error_from_endpoint(err))),
        }
    }
}

pub(crate) struct ShutdownFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for ShutdownFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.stream).poll_shutdown(cx)
    }
}

pub(crate) struct ZeroCopyReadFuture<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Future for ZeroCopyReadFuture<'a> {
    type Output = Option<PacketPayload>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.stream.poll_recv_zero_copy(cx)
    }
}

pub(crate) struct ZeroCopyWriteFuture<'a> {
    stream: &'a mut TcpStream,
    packet: Option<PacketRef>,
}

impl<'a> Future for ZeroCopyWriteFuture<'a> {
    type Output = Result<(), TcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let Some(packet) = this.packet.take() else {
            return Poll::Ready(Err(TcpError::InvalidState));
        };

        let mut inner = this
            .stream
            .endpoint
            .inner()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(err) = inner.last_error.take() {
            this.packet = Some(packet);
            return Poll::Ready(Err(tcp_error_from_endpoint(err)));
        }

        if matches!(inner.state, EndpointState::Closed | EndpointState::Closing) {
            return Poll::Ready(Err(TcpError::ConnectionClosed));
        }

        if !inner.state.can_send() {
            return Poll::Ready(Err(TcpError::InvalidState));
        }

        let send_buffer_limit = inner.send_buffer_limit;
        let queued_bytes = inner.send_payload_bytes();
        let available = send_buffer_limit
            .saturating_sub(queued_bytes)
            .min(endpoint_send_budget(
                inner.local_addr,
                inner.remote_addr,
                queued_bytes,
            ));
        let len = packet.data().len();

        if available < len {
            inner.send_waker = Some(cx.waker().clone());
            this.packet = Some(packet);
            return Poll::Pending;
        }

        match inner.send_payload(PacketPayload::single(packet)) {
            Ok(queued) => {
                if let Some(tcp) = inner.tcp_mut() {
                    tcp.stats.record_tx_enqueued(queued);
                }
            }
            Err(err) => return Poll::Ready(Err(tcp_error_from_endpoint(err))),
        }
        drop(inner);

        enqueue_event_ignore_in(
            this.stream.runtime,
            NetworkEvent::DataReady {
                fd: this.stream.endpoint.fd(),
                endpoint_type: EndpointType::Tcp,
            },
        );

        Poll::Ready(Ok(()))
    }
}
