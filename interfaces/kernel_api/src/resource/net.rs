// ============================================================================
// interfaces/kernel_api/src/resource/net.rs - Network resource ABI
// ============================================================================

use crate::service::kernel;
use crate::{KapiError, KapiResult};

pub use crate::types_impl::{
    DEFAULT_PACKET_HEADROOM, InterfaceScope, NetSocketAddr, PacketByteCount, PacketFront,
    PacketMeta, PacketOwnershipError, PacketPayload, PacketPayloadError, PacketPayloadFront,
    PacketPayloadOwnershipError, PacketRef, PacketRefStorage, PacketRefVTable, PacketSegments,
    PacketType, PacketWindowError, PhysicalAddress,
};

/// # Errors
///
/// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
pub async fn tcp_connection_dial(
    remote: NetSocketAddr,
    scope: InterfaceScope,
) -> KapiResult<TcpConnection> {
    kernel::instance()
        .net_tcp_connection_dial(remote, scope)
        .await
}

/// # Errors
///
/// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
pub async fn tcp_acceptor_bind(
    local: NetSocketAddr,
    scope: InterfaceScope,
    backlog: u32,
) -> KapiResult<TcpAcceptor> {
    kernel::instance()
        .net_tcp_acceptor_bind(local, scope, backlog)
        .await
}

/// # Errors
///
/// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
pub async fn tcp_acceptor_next_connection(acceptor: &TcpAcceptor) -> KapiResult<TcpConnection> {
    kernel::instance()
        .net_tcp_acceptor_next_connection(TcpAcceptor::from_raw_parts(
            acceptor.id,
            acceptor.default_scope,
        ))
        .await
}

/// # Errors
///
/// Returns an error if the request is invalid or the required state cannot be read.
pub async fn tcp_connection_recv_payload(
    connection: &TcpConnection,
) -> KapiResult<TcpReceiveOutcome> {
    kernel::instance()
        .net_tcp_connection_recv_payload(TcpConnection::from_raw_parts(
            connection.id,
            connection.default_scope,
        ))
        .await
}

/// # Errors
///
/// Returns an error if the request is invalid or the receiver cannot accept the operation.
pub async fn tcp_connection_send_payload(
    connection: &TcpConnection,
    payload: PacketPayload,
) -> Result<(), PayloadSendError> {
    kernel::instance()
        .net_tcp_connection_send_payload(
            TcpConnection::from_raw_parts(connection.id, connection.default_scope),
            payload,
        )
        .await
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub fn raw_endpoint_open(scope: InterfaceScope) -> KapiResult<RawEndpoint> {
    kernel::instance().net_raw_endpoint_open(scope)
}

/// # Errors
///
/// Returns an error if the request is invalid or the required state cannot be read.
pub async fn raw_endpoint_recv_payload(endpoint: &RawEndpoint) -> KapiResult<PacketPayload> {
    kernel::instance()
        .net_raw_endpoint_recv_payload(RawEndpoint::from_raw_parts(
            endpoint.id,
            endpoint.default_scope,
        ))
        .await
}

/// # Errors
///
/// Returns an error if the request is invalid or the receiver cannot accept the operation.
pub async fn raw_endpoint_send_payload(
    endpoint: &RawEndpoint,
    payload: PacketPayload,
) -> Result<(), PayloadSendError> {
    kernel::instance()
        .net_raw_endpoint_send_payload(
            RawEndpoint::from_raw_parts(endpoint.id, endpoint.default_scope),
            payload,
        )
        .await
}

pub enum TcpReceiveOutcome {
    Payload(PacketPayload),
    EndOfStream,
}

pub struct PayloadSendError {
    cause: KapiError,
    payload: PacketPayload,
}

impl PayloadSendError {
    pub const fn new(cause: KapiError, payload: PacketPayload) -> Self {
        Self { cause, payload }
    }

    pub const fn cause(&self) -> KapiError {
        self.cause
    }

    pub fn into_parts(self) -> (KapiError, PacketPayload) {
        (self.cause, self.payload)
    }
}

#[derive(Default)]
pub struct TcpConnection {
    id: u64,
    default_scope: InterfaceScope,
}

impl core::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpConnection")
            .field("id", &self.id)
            .field("default_scope", &self.default_scope)
            .finish()
    }
}

impl TcpConnection {
    pub const fn from_raw_parts(id: u64, default_scope: InterfaceScope) -> Self {
        Self { id, default_scope }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_tcp_connection_close(self)
    }
}

#[derive(Default)]
pub struct TcpAcceptor {
    id: u64,
    default_scope: InterfaceScope,
}

impl core::fmt::Debug for TcpAcceptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpAcceptor")
            .field("id", &self.id)
            .field("default_scope", &self.default_scope)
            .finish()
    }
}

impl TcpAcceptor {
    pub const fn from_raw_parts(id: u64, default_scope: InterfaceScope) -> Self {
        Self { id, default_scope }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_tcp_acceptor_close(self)
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

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_raw_endpoint_close(self)
    }
}
