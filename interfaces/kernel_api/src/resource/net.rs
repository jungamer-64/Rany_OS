use crate::service::kernel;
use crate::KapiResult;

pub use crate::types_impl::{
    DEFAULT_PACKET_HEADROOM, InterfaceScope, NetSocketAddr, PacketChain, PacketMeta,
    PacketPayload, PacketRef, PacketRefStorage, PacketRefVTable, PacketType, PhysicalAddress,
};

pub async fn tcp_stream_dial(
    remote: NetSocketAddr,
    scope: InterfaceScope,
) -> KapiResult<TcpStream> {
    kernel::instance().net_tcp_stream_dial(remote, scope).await
}

pub async fn tcp_listener_listen_on(
    local: NetSocketAddr,
    scope: InterfaceScope,
    backlog: u32,
) -> KapiResult<TcpListener> {
    kernel::instance()
        .net_tcp_listener_listen_on(local, scope, backlog)
        .await
}

pub async fn tcp_listener_next_connection(listener: &TcpListener) -> KapiResult<TcpStream> {
    kernel::instance()
        .net_tcp_listener_next_connection(TcpListener::from_raw_parts(
            listener.id,
            listener.default_scope,
        ))
        .await
}

pub async fn tcp_stream_recv_payload(stream: &TcpStream) -> KapiResult<PacketPayload> {
    kernel::instance()
        .net_tcp_stream_recv_payload(TcpStream::from_raw_parts(stream.id, stream.default_scope))
        .await
}

pub async fn tcp_stream_send_payload(
    stream: &TcpStream,
    payload: PacketPayload,
) -> KapiResult<usize> {
    kernel::instance()
        .net_tcp_stream_send_payload(
            TcpStream::from_raw_parts(stream.id, stream.default_scope),
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
pub struct TcpStream {
    id: u64,
    default_scope: InterfaceScope,
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
        Self { id, default_scope }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_tcp_stream_close(self)
    }
}

#[derive(Default)]
pub struct TcpListener {
    id: u64,
    default_scope: InterfaceScope,
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
        Self { id, default_scope }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn default_scope(&self) -> InterfaceScope {
        self.default_scope
    }

    pub fn close(self) -> KapiResult<()> {
        kernel::instance().net_tcp_listener_close(self)
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
