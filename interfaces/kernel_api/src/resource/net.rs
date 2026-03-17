extern crate alloc;

use crate::service::kernel;
use crate::{KapiError, KapiResult};
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub use crate::types_impl::{
    AsyncRead, AsyncWrite, DEFAULT_PACKET_HEADROOM, InterfaceScope, NetSocketAddr, PacketChain,
    PacketMeta, PacketPayload, PacketRef, PacketRefStorage, PacketRefVTable, PacketType,
    PhysicalAddress, TcpError,
};

type PayloadFuture = Pin<Box<dyn Future<Output = KapiResult<PacketPayload>> + Send>>;
type PayloadSendFuture = Pin<Box<dyn Future<Output = KapiResult<usize>> + Send>>;
type TcpAcceptFuture = Pin<Box<dyn Future<Output = KapiResult<TcpStream>> + Send>>;

fn tcp_error_from_kapi(err: KapiError) -> TcpError {
    match err {
        KapiError::PermissionDenied => TcpError::PermissionDenied,
        KapiError::ResourceExhausted => TcpError::BufferFull,
        KapiError::InvalidHandle => TcpError::ConnectionClosed,
        KapiError::Timeout => TcpError::Timeout,
        KapiError::NotFound => TcpError::NetworkUnreachable,
        KapiError::ConnectionError => TcpError::ConnectionReset,
        _ => TcpError::InvalidState,
    }
}

#[derive(Default)]
pub struct TcpStream {
    id: u64,
    default_scope: InterfaceScope,
    pending_recv: Option<PayloadFuture>,
    pending_send: Option<PayloadSendFuture>,
    recv_stash: Option<PacketPayload>,
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("id", &self.id)
            .field("default_scope", &self.default_scope)
            .finish()
    }
}

impl TcpStream {
    pub const fn from_raw_parts(id: u64, default_scope: InterfaceScope) -> Self {
        Self {
            id,
            default_scope,
            pending_recv: None,
            pending_send: None,
            recv_stash: None,
        }
    }

    pub async fn connect(remote: NetSocketAddr, scope: InterfaceScope) -> KapiResult<Self> {
        kernel::instance().net_open_tcp_stream(remote, scope).await
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    pub async fn recv_payload(&mut self) -> KapiResult<PacketPayload> {
        if let Some(payload) = self.recv_stash.take() {
            if !payload.is_empty() {
                return Ok(payload);
            }
        }
        kernel::instance()
            .net_tcp_stream_recv_payload(Self::from_raw_parts(self.id, self.default_scope))
            .await
    }

    pub async fn send_payload(&mut self, payload: PacketPayload) -> KapiResult<usize> {
        kernel::instance()
            .net_tcp_stream_send_payload(Self::from_raw_parts(self.id, self.default_scope), payload)
            .await
    }

    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_close_tcp_stream(self)
    }

    fn drain_stash(&mut self, buf: &mut [u8]) -> Option<usize> {
        let stash = self.recv_stash.as_mut()?;
        let copied = stash.copy_into(buf);
        if stash.is_empty() {
            self.recv_stash = None;
        }
        Some(copied)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, TcpError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(copied) = self.as_mut().get_mut().drain_stash(buf) {
            return Poll::Ready(Ok(copied));
        }

        if self.pending_recv.is_none() {
            self.pending_recv = Some(
                kernel::instance()
                    .net_tcp_stream_recv_payload(Self::from_raw_parts(self.id, self.default_scope)),
            );
        }

        let result = self
            .pending_recv
            .as_mut()
            .expect("pending_recv initialized")
            .as_mut()
            .poll(cx);

        match result {
            Poll::Ready(Ok(mut payload)) => {
                self.pending_recv = None;
                let copied = payload.copy_into(buf);
                if !payload.is_empty() {
                    self.recv_stash = Some(payload);
                }
                Poll::Ready(Ok(copied))
            }
            Poll::Ready(Err(err)) => {
                self.pending_recv = None;
                Poll::Ready(Err(tcp_error_from_kapi(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, TcpError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.pending_send.is_none() {
            self.pending_send = Some(kernel::instance().net_tcp_stream_send_payload(
                Self::from_raw_parts(self.id, self.default_scope),
                PacketPayload::from_vec(buf.to_vec()),
            ));
        }

        match self
            .pending_send
            .as_mut()
            .expect("pending_send initialized")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(Ok(written)) => {
                self.pending_send = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                self.pending_send = None;
                Poll::Ready(Err(tcp_error_from_kapi(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        let Some(pending) = self.pending_send.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match pending.as_mut().poll(cx) {
            Poll::Ready(Ok(_)) => {
                self.pending_send = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.pending_send = None;
                Poll::Ready(Err(tcp_error_from_kapi(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TcpError>> {
        if self.pending_send.is_some() {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        match kernel::instance()
            .net_close_tcp_stream(Self::from_raw_parts(self.id, self.default_scope))
        {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(tcp_error_from_kapi(err))),
        }
    }
}

#[derive(Default)]
pub struct TcpListener {
    id: u64,
    default_scope: InterfaceScope,
    pending_accept: Option<TcpAcceptFuture>,
}

impl core::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpListener")
            .field("id", &self.id)
            .field("default_scope", &self.default_scope)
            .finish()
    }
}

impl TcpListener {
    pub const fn from_raw_parts(id: u64, default_scope: InterfaceScope) -> Self {
        Self {
            id,
            default_scope,
            pending_accept: None,
        }
    }

    pub async fn listen_on(
        local: NetSocketAddr,
        scope: InterfaceScope,
        backlog: u32,
    ) -> KapiResult<Self> {
        kernel::instance()
            .net_open_tcp_listener(local, scope, backlog)
            .await
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    pub async fn accept(&mut self) -> KapiResult<TcpStream> {
        kernel::instance()
            .net_tcp_listener_accept(Self::from_raw_parts(self.id, self.default_scope))
            .await
    }

    pub fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<KapiResult<TcpStream>> {
        if self.pending_accept.is_none() {
            self.pending_accept = Some(
                kernel::instance()
                    .net_tcp_listener_accept(Self::from_raw_parts(self.id, self.default_scope)),
            );
        }

        match self
            .pending_accept
            .as_mut()
            .expect("pending_accept initialized")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(result) => {
                self.pending_accept = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_close_tcp_listener(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEndpoint {
    id: u64,
    default_scope: InterfaceScope,
}

impl RawEndpoint {
    pub const fn from_raw_parts(id: u64, default_scope: InterfaceScope) -> Self {
        Self { id, default_scope }
    }

    pub fn open(scope: InterfaceScope) -> KapiResult<Self> {
        kernel::instance().net_open_raw_endpoint(scope)
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    pub async fn recv_payload(&self) -> KapiResult<PacketPayload> {
        kernel::instance().net_raw_recv_payload(*self).await
    }

    pub async fn send_payload(&self, payload: PacketPayload) -> KapiResult<()> {
        kernel::instance()
            .net_raw_send_payload(*self, payload)
            .await
    }

    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_close_raw_endpoint(self)
    }
}
