// ============================================================================
// kernel/src/net/l4/raw/mod.rs - L4 / Raw モジュール
// ============================================================================
//! Raw IP facade backed by the internal socket registry.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::net::l4::socket::{Socket, register_raw_scope, unregister_socket};
use crate::net::l4::types::{EndpointError, SocketId};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::{InterfaceScope, NetworkError};
use kernel_api::resource::net::PacketPayload;

fn network_error_to_socket(error: NetworkError) -> EndpointError {
    match error {
        NetworkError::PermissionDenied => EndpointError::PermissionDenied,
        NetworkError::Timeout => EndpointError::Timeout,
        NetworkError::NetworkUnreachable => EndpointError::NetworkUnreachable,
        NetworkError::PortInUse => EndpointError::PortInUse,
        NetworkError::BufferTooSmall => EndpointError::BufferFull,
        NetworkError::ConnectionClosed => EndpointError::NotConnected,
        NetworkError::ResourceExhausted
        | NetworkError::ArpResolutionPending
        | NetworkError::TransmitFailed => EndpointError::ResourceExhausted,
        NetworkError::InvalidAddress => EndpointError::InvalidArgument,
        NetworkError::LockPoisoned | NetworkError::Unknown => EndpointError::Internal,
    }
}

pub struct RawEndpoint {
    socket: Socket,
    registered: bool,
}

impl core::fmt::Debug for RawEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scope = self
            .socket
            .with_inner(|inner| inner.scope)
            .unwrap_or(InterfaceScope::Any);
        f.debug_struct("RawEndpoint")
            .field("socket_id", &self.socket.socket_id().raw())
            .field("scope", &scope)
            .finish()
    }
}

impl RawEndpoint {
    pub fn open_in(
        runtime: NetRuntimeHandle,
        scope: InterfaceScope,
    ) -> Result<Self, EndpointError> {
        let socket = Socket::new_registered_raw_in(runtime);
        socket
            .with_inner_mut(|inner| {
                inner.scope = scope;
            })
            .ok_or(EndpointError::Internal)?;

        register_raw_scope(scope, socket.socket_id())?;

        Ok(Self {
            socket,
            registered: true,
        })
    }

    pub(crate) fn from_retained_socket(socket: Socket) -> Self {
        Self {
            socket,
            registered: false,
        }
    }

    pub(crate) fn from_registered_socket(socket: Socket) -> Self {
        Self {
            socket,
            registered: true,
        }
    }

    pub(crate) fn into_retained_handle(mut self) -> SocketId {
        self.registered = false;
        self.socket.socket_id()
    }

    pub fn runtime(&self) -> NetRuntimeHandle {
        self.socket.runtime()
    }

    pub(crate) fn set_scope(&self, scope: InterfaceScope) {
        let _ = self.socket.with_inner_mut(|inner| {
            inner.scope = scope;
        });
    }

    pub fn recv_payload(&self) -> RawRecvFuture {
        RawRecvFuture {
            socket: self.socket,
        }
    }

    pub fn try_recv_payload(&self) -> Result<(PacketPayload, NetIfId), EndpointError> {
        self.socket.try_recv_raw_payload()
    }

    pub async fn send_payload(&self, payload: PacketPayload) -> Result<(), EndpointError> {
        let scope = self
            .socket
            .with_inner(|inner| inner.scope)
            .ok_or(EndpointError::Internal)?;
        let runtime = self.socket.runtime();
        let mut guard = crate::net::runtime::stack::stack_in(runtime)
            .lock()
            .map_err(|_| EndpointError::Internal)?;
        let stack = guard.as_mut().ok_or(EndpointError::NotFound)?;
        stack
            .send_raw_ip_payload_scoped(scope, payload)
            .map_err(network_error_to_socket)
    }

    pub fn close(&self) -> Result<(), EndpointError> {
        self.socket.close_immediate()?;
        if self.registered {
            let _ = unregister_socket(self.socket.socket_id());
        }
        Ok(())
    }
}

impl Drop for RawEndpoint {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub struct RawRecvFuture {
    socket: Socket,
}

impl Future for RawRecvFuture {
    type Output = Result<(PacketPayload, NetIfId), EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.socket.try_recv_raw_payload() {
            Ok(result) => Poll::Ready(Ok(result)),
            Err(EndpointError::Timeout) => {
                self.socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}
