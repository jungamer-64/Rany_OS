// ============================================================================
// kernel/src/net/l4/raw/mod.rs
// ============================================================================
//! Raw IP facade backed by the internal endpoint registry.

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::net::l4::socket::{Endpoint, register_raw_scope, unregister_endpoint};
use crate::net::l4::types::{EndpointError, EndpointFd, EndpointState, EndpointType};
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::types::{InterfaceScope, NetworkError};
use kernel_api::resource::net::PacketPayload;

fn network_error_to_endpoint(error: NetworkError) -> EndpointError {
    match error {
        NetworkError::PermissionDenied => EndpointError::PermissionDenied,
        NetworkError::Timeout => EndpointError::Timeout,
        NetworkError::NetworkUnreachable => EndpointError::NetworkUnreachable,
        NetworkError::PortInUse => EndpointError::PortInUse,
        NetworkError::BufferTooSmall => EndpointError::BufferFull,
        NetworkError::ConnectionClosed => EndpointError::NotConnected,
        NetworkError::ArpResolutionPending | NetworkError::TransmitFailed => {
            EndpointError::ResourceExhausted
        }
        NetworkError::InvalidAddress => EndpointError::InvalidArgument,
        NetworkError::LockPoisoned | NetworkError::Unknown => EndpointError::Internal,
    }
}

#[derive(Clone)]
pub struct RawEndpoint {
    endpoint: Endpoint,
    registered: bool,
}

impl core::fmt::Debug for RawEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scope = self
            .endpoint
            .inner()
            .lock()
            .map(|inner| inner.scope)
            .unwrap_or(InterfaceScope::Any);
        f.debug_struct("RawEndpoint")
            .field("fd", &self.endpoint.fd().raw())
            .field("scope", &scope)
            .finish()
    }
}

impl RawEndpoint {
    pub fn open_in(runtime: NetRuntimeHandle, scope: InterfaceScope) -> Result<Self, EndpointError> {
        let endpoint = Endpoint::new_registered_in(EndpointType::Raw, runtime);
        {
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.scope = scope;
            inner.ensure_raw();
            inner.transition_to(EndpointState::Bound)?;
        }

        register_raw_scope(scope, endpoint.fd())?;

        Ok(Self {
            endpoint,
            registered: true,
        })
    }

    pub(crate) fn from_retained_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            registered: false,
        }
    }

    pub(crate) fn from_registered_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            registered: true,
        }
    }

    pub(crate) fn into_retained_handle(mut self) -> EndpointFd {
        self.registered = false;
        self.endpoint.fd()
    }

    pub fn runtime(&self) -> NetRuntimeHandle {
        self.endpoint.runtime()
    }

    pub(crate) fn set_scope(&self, scope: InterfaceScope) {
        if let Ok(mut inner) = self.endpoint.inner().lock() {
            inner.scope = scope;
        }
    }

    pub fn recv_payload(&self) -> RawRecvFuture {
        RawRecvFuture {
            endpoint: self.endpoint.clone(),
        }
    }

    pub fn try_recv_payload(&self) -> Result<(PacketPayload, NetIfId), EndpointError> {
        self.endpoint.try_recv_raw_payload()
    }

    pub async fn send_payload(&self, payload: PacketPayload) -> Result<(), EndpointError> {
        let scope = self
            .endpoint
            .inner()
            .lock()
            .map(|inner| inner.scope)
            .map_err(|_| EndpointError::Internal)?;
        let runtime = self.endpoint.runtime();
        let mut guard = crate::net::runtime::stack::stack_in(runtime)
            .lock()
            .map_err(|_| EndpointError::Internal)?;
        let stack = guard.as_mut().ok_or(EndpointError::NotFound)?;
        stack
            .send_raw_ip_payload_scoped(scope, payload)
            .map_err(network_error_to_endpoint)
    }

    pub fn close(&self) -> Result<(), EndpointError> {
        self.endpoint.close_immediate()?;
        if self.registered {
            let _ = unregister_endpoint(self.endpoint.fd());
        }
        Ok(())
    }
}

impl Drop for RawEndpoint {
    fn drop(&mut self) {
        let threshold = if self.registered { 2 } else { 1 };
        if Arc::strong_count(self.endpoint.inner()) > threshold {
            return;
        }

        let _ = self.close();
    }
}

pub struct RawRecvFuture {
    endpoint: Endpoint,
}

impl Future for RawRecvFuture {
    type Output = Result<(PacketPayload, NetIfId), EndpointError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.endpoint.try_recv_raw_payload() {
            Ok(result) => Poll::Ready(Ok(result)),
            Err(EndpointError::Timeout) => {
                self.endpoint.register_recv_waker(cx.waker().clone());
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}
