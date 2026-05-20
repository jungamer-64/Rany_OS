// ============================================================================
// interfaces/kernel_api/src/resource/net.rs - Network resource ABI
// ============================================================================

use crate::KapiResult;
use crate::service::kernel;

pub use crate::types_impl::{
    DEFAULT_PACKET_HEADROOM, InterfaceScope, NetSocketAddr, PacketByteCount, PacketChain,
    PacketFront, PacketMeta, PacketPayload, PacketPayloadFront, PacketRef, PacketRefStorage,
    PacketRefVTable, PacketType, PacketWindowError, PhysicalAddress,
};

pub async fn tcp_connection_dial(
    remote: NetSocketAddr,
    scope: InterfaceScope,
) -> KapiResult<TcpConnection> {
    kernel::instance()
        .net_tcp_connection_dial(remote, scope)
        .await
}

pub async fn tcp_acceptor_bind(
    local: NetSocketAddr,
    scope: InterfaceScope,
    backlog: u32,
) -> KapiResult<TcpAcceptor> {
    kernel::instance()
        .net_tcp_acceptor_bind(local, scope, backlog)
        .await
}

pub async fn tcp_acceptor_next_connection(acceptor: &TcpAcceptor) -> KapiResult<TcpConnection> {
    kernel::instance()
        .net_tcp_acceptor_next_connection(TcpAcceptor::from_raw_parts(
            acceptor.id,
            acceptor.default_scope,
        ))
        .await
}

pub async fn tcp_connection_recv_payload(connection: &TcpConnection) -> KapiResult<PacketPayload> {
    kernel::instance()
        .net_tcp_connection_recv_payload(TcpConnection::from_raw_parts(
            connection.id,
            connection.default_scope,
        ))
        .await
}

pub async fn tcp_connection_send_payload(
    connection: &TcpConnection,
    payload: PacketPayload,
) -> KapiResult<()> {
    kernel::instance()
        .net_tcp_connection_send_payload(
            TcpConnection::from_raw_parts(connection.id, connection.default_scope),
            payload,
        )
        .await
}

pub fn raw_endpoint_open(scope: InterfaceScope) -> KapiResult<RawEndpoint> {
    kernel::instance().net_raw_endpoint_open(scope)
}

pub async fn raw_endpoint_recv_payload(endpoint: &RawEndpoint) -> KapiResult<PacketPayload> {
    kernel::instance()
        .net_raw_endpoint_recv_payload(RawEndpoint::from_raw_parts(
            endpoint.id,
            endpoint.default_scope,
        ))
        .await
}

pub async fn raw_endpoint_send_payload(
    endpoint: &RawEndpoint,
    payload: PacketPayload,
) -> KapiResult<()> {
    kernel::instance()
        .net_raw_endpoint_send_payload(
            RawEndpoint::from_raw_parts(endpoint.id, endpoint.default_scope),
            payload,
        )
        .await
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

    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_raw_endpoint_close(self)
    }
}
