// ============================================================================
// kernel/src/net/l4/udp/mod.rs - L4 / UDP モジュール
// ============================================================================
//! UDP (User Datagram Protocol) Implementation for ExoRust
//!
//! This module implements zero-copy UDP packet processing
//! for the ExoRust networking stack.

use crate::net::l3::ipv4::{IpProtocol, Ipv4Address, data_checksum, pseudo_header_checksum};
use crate::net::l3::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};
use crate::net::l4::EndpointAddr;
use crate::net::l4::socket::{
    Socket, allocate_udp_ephemeral_port_in, bind_udp_dual_stack_in, unregister_socket_in,
};
use crate::net::l4::types::EndpointError;
use crate::net::payload::{OwnedPayloadWindow, PacketPayloadView};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::CommandDispatch;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use crate::net::types::NetworkError;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};
use kernel_api::resource::net::PacketPayload;

extern crate alloc;

#[inline]
fn ipv6_checksum(
    src: &Ipv6Address,
    dst: &Ipv6Address,
    next_header: IpProtocol,
    data: &[u8],
) -> u16 {
    let pseudo = ipv6_pseudo_header_checksum(src, dst, next_header, data.len() as u32);
    data_checksum(data, pseudo)
}

fn payload_checksum(view: &PacketPayloadView<'_>, initial: u32) -> u16 {
    let mut sum = initial;
    let mut trailing = None;

    view.for_each_chunk(|chunk| {
        let mut index = 0usize;
        if let Some(prev) = trailing.take() {
            if let Some((&first, rest)) = chunk.split_first() {
                sum = sum.saturating_add(u16::from_be_bytes([prev, first]) as u32);
                index = 1;
                if rest.is_empty() {
                    return;
                }
            } else {
                trailing = Some(prev);
                return;
            }
        }

        while index + 1 < chunk.len() {
            sum = sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
            index += 2;
        }
        if index < chunk.len() {
            trailing = Some(chunk[index]);
        }
    });

    if let Some(last) = trailing {
        sum = sum.saturating_add(u16::from_be_bytes([last, 0]) as u32);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP header
mod types;
pub use types::*;
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UdpHeader {
    /// Source port (big-endian)
    pub src_port: [u8; 2],
    /// Destination port (big-endian)
    pub dst_port: [u8; 2],
    /// Length including header (big-endian)
    pub length: [u8; 2],
    /// Checksum (big-endian)
    pub checksum: [u8; 2],
}

impl UdpHeader {
    /// Header size
    pub const SIZE: usize = 8;

    /// Get source port
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    /// Set source port
    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = port.to_be_bytes();
    }

    /// Get destination port
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    /// Set destination port
    pub fn set_dst_port(&mut self, port: u16) {
        self.dst_port = port.to_be_bytes();
    }

    /// Get length
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Set length
    pub fn set_length(&mut self, len: u16) {
        self.length = len.to_be_bytes();
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Set checksum
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }
}

/// Zero-copy UDP packet view
pub struct UdpPacket<'a> {
    header: &'a UdpHeader,
    /// Raw packet data
    data: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    /// Parse a UDP packet from raw bytes
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let header = crate::util::get_ref::<UdpHeader>(data, 0)?;

        // Verify length field
        let length = header.length() as usize;
        if length < UdpHeader::SIZE || length > data.len() {
            return None;
        }

        Some(UdpPacket { header, data })
    }

    /// Get the UDP header
    pub fn header(&self) -> &UdpHeader {
        self.header
    }

    /// Get source port
    pub fn src_port(&self) -> u16 {
        self.header().src_port()
    }

    /// Get destination port
    pub fn dst_port(&self) -> u16 {
        self.header().dst_port()
    }

    /// Get payload (zero-copy)
    pub fn payload(&self) -> &'a [u8] {
        let length = self.header().length() as usize;
        &self.data[UdpHeader::SIZE..length]
    }

    /// Get raw packet data
    pub fn as_bytes(&self) -> &'a [u8] {
        let length = self.header().length() as usize;
        &self.data[..length]
    }

    /// Verify checksum for IPv4 (RFC 768)
    pub fn verify_checksum(&self, src_ip: Ipv4Address, dst_ip: Ipv4Address) -> bool {
        let checksum = self.header().checksum();

        // Checksum of 0 means no checksum (optional in IPv4)
        if checksum == 0 {
            return true;
        }

        let length = self.header().length();
        let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length);

        // Include the checksum in the data for verification
        let actual_checksum = data_checksum(&self.data[..length as usize], pseudo);
        actual_checksum == 0
    }

    /// Verify checksum for IPv6 (RFC 8200 - Mandatory)
    pub fn verify_checksum_v6(&self, src_ip: Ipv6Address, dst_ip: Ipv6Address) -> bool {
        let checksum = self.header().checksum();

        // RFC 8200 Section 8.1: Checksum 0 is forbidden for IPv6 UDP
        if checksum == 0 {
            return false;
        }

        let length = self.header().length();
        if length as usize > self.data.len() {
            return false;
        }

        ipv6_checksum(
            &src_ip,
            &dst_ip,
            IpProtocol::Udp,
            &self.data[..length as usize],
        ) == 0
    }
}

/// Mutable UDP packet builder
pub struct UdpPacketMut<'a> {
    buffer: &'a mut [u8],
    payload_len: usize,
}

impl<'a> UdpPacketMut<'a> {
    /// Create a new UDP packet builder
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < UdpHeader::SIZE {
            return None;
        }
        Some(UdpPacketMut {
            buffer,
            payload_len: 0,
        })
    }

    /// Get mutable header
    pub fn header_mut(&mut self) -> Option<&mut UdpHeader> {
        crate::util::get_mut_ref::<UdpHeader>(self.buffer, 0)
    }

    /// Set source port
    pub fn set_src_port(&mut self, port: u16) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_src_port(port);
        }
        self
    }

    /// Set destination port
    pub fn set_dst_port(&mut self, port: u16) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_dst_port(port);
        }
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[UdpHeader::SIZE..]
    }

    /// Set payload length
    pub fn set_payload_len(&mut self, len: usize) {
        let max_udp = 65527;
        self.payload_len = len.min(self.buffer.len() - UdpHeader::SIZE).min(max_udp);
    }

    /// Finalize the packet for IPv4 (compute checksum)
    pub fn finalize(&mut self, src_ip: Ipv4Address, dst_ip: Ipv4Address) -> usize {
        let total_len = (UdpHeader::SIZE + self.payload_len) as u16;

        if let Some(h) = self.header_mut() {
            h.set_length(total_len);
            h.set_checksum(0);
        }

        // Calculate checksum with pseudo-header
        let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, total_len);
        let checksum = data_checksum(&self.buffer[..total_len as usize], pseudo);

        // Use 0xFFFF instead of 0 (0 means no checksum)
        let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        if let Some(h) = self.header_mut() {
            h.set_checksum(final_checksum);
        }

        total_len as usize
    }

    /// Finalize the packet for IPv6 (compute mandatory checksum)
    pub fn finalize_v6(&mut self, src_ip: Ipv6Address, dst_ip: Ipv6Address) -> usize {
        let total_len = (UdpHeader::SIZE + self.payload_len) as u16;

        if let Some(h) = self.header_mut() {
            h.set_length(total_len);
            h.set_checksum(0);
        }

        // Calculate checksum with IPv6 pseudo-header (mandatory per RFC 8200)
        let checksum = ipv6_checksum(
            &src_ip,
            &dst_ip,
            IpProtocol::Udp,
            &self.buffer[..total_len as usize],
        );

        // In IPv6, a checksum of 0 is transmitted as 0xFFFF.
        let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        if let Some(h) = self.header_mut() {
            h.set_checksum(final_checksum);
        }

        total_len as usize
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..UdpHeader::SIZE + self.payload_len]
    }
}

/// UDP socket address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpAddr {
    /// IPv4 address + port
    V4 { ip: Ipv4Address, port: u16 },
    /// IPv6 address + port
    V6 { ip: Ipv6Address, port: u16 },
}

impl UdpAddr {
    /// Create a new IPv4 UDP address
    pub const fn new(ip: Ipv4Address, port: u16) -> Self {
        UdpAddr::V4 { ip, port }
    }

    /// Create a new IPv6 UDP address
    pub const fn new_v6(ip: Ipv6Address, port: u16) -> Self {
        UdpAddr::V6 { ip, port }
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match *self {
            UdpAddr::V4 { port, .. } => port,
            UdpAddr::V6 { port, .. } => port,
        }
    }

    /// Get IPv4 address if available
    pub fn ip_v4(&self) -> Option<Ipv4Address> {
        match *self {
            UdpAddr::V4 { ip, .. } => Some(ip),
            _ => None,
        }
    }

    /// Get IPv6 address if available
    pub fn ip_v6(&self) -> Option<Ipv6Address> {
        match *self {
            UdpAddr::V6 { ip, .. } => Some(ip),
            _ => None,
        }
    }
}

fn udp_addr_from_socket(addr: EndpointAddr) -> UdpAddr {
    match addr {
        EndpointAddr::V4 { ip, port } => UdpAddr::new(Ipv4Address::new(ip), port),
        EndpointAddr::V6 { ip, port } => UdpAddr::new_v6(Ipv6Address::new(ip), port),
    }
}

fn socket_addr_from_udp(addr: UdpAddr) -> EndpointAddr {
    match addr {
        UdpAddr::V4 { ip, port } => EndpointAddr::new(ip.octets(), port),
        UdpAddr::V6 { ip, port } => EndpointAddr::new_v6(ip.octets(), port),
    }
}

fn socket_error_to_network(err: EndpointError) -> NetworkError {
    match err {
        EndpointError::PermissionDenied => NetworkError::PermissionDenied,
        EndpointError::PortInUse | EndpointError::AddressInUse | EndpointError::AlreadyBound => {
            NetworkError::PortInUse
        }
        EndpointError::Timeout => NetworkError::Timeout,
        EndpointError::NotConnected => NetworkError::ConnectionClosed,
        EndpointError::NetworkUnreachable
        | EndpointError::HostUnreachable
        | EndpointError::ProtocolUnreachable => NetworkError::NetworkUnreachable,
        EndpointError::BufferFull => NetworkError::BufferTooSmall,
        EndpointError::ResourceExhausted => NetworkError::ResourceExhausted,
        EndpointError::Internal => NetworkError::LockPoisoned,
        EndpointError::InvalidArgument
        | EndpointError::InvalidStateTransition
        | EndpointError::NotFound
        | EndpointError::AlreadyConnected
        | EndpointError::ConnectionRefused
        | EndpointError::Interrupted => NetworkError::Unknown,
    }
}

fn validate_udp_bind_permission(port: u16, token: Option<u64>) -> Result<(), NetworkError> {
    if port == 0 || port >= 1024 {
        return Ok(());
    }

    let subject = crate::task::context::current_subject();
    let caller = subject.domain.as_u64();
    if subject.domain == crate::domain::DomainId::KERNEL
        || crate::security::capability::manager()
            .has_capability(caller, crate::security::capability::CAP_NET_BIND)
    {
        return Ok(());
    }

    if let Some(token) = token {
        if crate::security::capability::manager().validate_token(
            caller,
            token,
            crate::security::capability::CAP_NET_BIND,
        ) {
            return Ok(());
        }
    }

    Err(NetworkError::PermissionDenied)
}

fn configure_udp_socket(
    socket: &Socket,
    scope: InterfaceScope,
    port: u16,
    token: Option<u64>,
) -> Result<(), NetworkError> {
    socket
        .with_inner_mut(|inner| {
            inner.local_addr = Some(EndpointAddr::new_v6([0; 16], port));
            inner.scope = scope;
            let Some(udp) = inner.udp_mut() else {
                return Err(NetworkError::InvalidAddress);
            };
            udp.ttl = 64;
            udp.token = token;
            Ok(())
        })
        .unwrap_or(Err(NetworkError::Unknown))
}

pub struct UdpEndpoint {
    socket: Socket,
    runtime: NetRuntimeHandle,
    registered: bool,
}

impl core::fmt::Debug for UdpEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scope = self
            .socket
            .with_inner(|inner| inner.scope)
            .unwrap_or(InterfaceScope::Any);
        f.debug_struct("UdpEndpoint")
            .field("socket_id", &self.socket.socket_id().raw())
            .field("local_addr", &self.socket.local_addr())
            .field("scope", &scope)
            .finish()
    }
}

impl UdpEndpoint {
    pub(crate) fn bind_in(
        runtime: NetRuntimeHandle,
        scope: InterfaceScope,
        port: u16,
        token: Option<u64>,
    ) -> Result<Self, NetworkError> {
        validate_udp_bind_permission(port, token)?;

        let local_port = if port == 0 {
            allocate_udp_ephemeral_port_in(runtime).ok_or(NetworkError::PortInUse)?
        } else {
            port
        };

        if let Some(token) = token {
            crate::security::capability::manager()
                .increment_in_flight(token)
                .map_err(|_| NetworkError::PermissionDenied)?;
        }

        let socket = Socket::new_udp_in(runtime);
        if let Err(error) = configure_udp_socket(&socket, scope, local_port, token) {
            if let Some(token) = token {
                let _ = crate::security::capability::manager().decrement_in_flight(token);
            }
            return Err(error);
        }

        if let Err(error) = bind_udp_dual_stack_in(runtime, local_port, scope, socket.socket_id()) {
            let _ = unregister_socket_in(runtime, socket.socket_id());
            return Err(socket_error_to_network(error));
        }

        Ok(Self {
            socket,
            runtime,
            registered: true,
        })
    }

    fn close_internal(&self) {
        let _ = self.socket.close_immediate();
        if self.registered {
            let _ = unregister_socket_in(self.runtime, self.socket.socket_id());
        }
    }

    pub fn set_ttl(&self, ttl: u8) {
        let _ = self.socket.with_inner_mut(|inner| {
            if let Some(udp) = inner.udp_mut() {
                udp.ttl = ttl;
            }
        });
    }

    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            socket: self.socket,
        }
    }

    pub fn try_recv(&self) -> Option<(NetIfId, UdpAddr, u8, PacketPayload)> {
        self.socket
            .try_recv_udp_payload()
            .ok()
            .map(|(if_id, addr, ttl, payload)| (if_id, udp_addr_from_socket(addr), ttl, payload))
    }

    pub fn join_multicast_group(&self, group: Ipv4Address) -> impl Future<Output = bool> {
        let runtime = self.runtime;
        let scope = self.socket.with_inner(|inner| inner.scope);
        async move {
            let Some(if_id) = scope.and_then(|scope| match scope {
                InterfaceScope::Pinned(if_id) => {
                    crate::net::runtime::manager::is_interface_operational_in(runtime, if_id)
                        .then_some(if_id)
                }
                InterfaceScope::Any => {
                    crate::net::runtime::manager::lookup_ipv4_route_in(runtime, group)
                        .ok()
                        .flatten()
                        .map(|route| route.if_id)
                }
            }) else {
                return false;
            };
            crate::net::runtime::stack::join_multicast_in(runtime, if_id, group).await
        }
    }

    pub fn leave_multicast_group(&self, group: Ipv4Address) -> impl Future<Output = bool> {
        let runtime = self.runtime;
        let scope = self.socket.with_inner(|inner| inner.scope);
        async move {
            let Some(if_id) = scope.and_then(|scope| match scope {
                InterfaceScope::Pinned(if_id) => {
                    crate::net::runtime::manager::is_interface_operational_in(runtime, if_id)
                        .then_some(if_id)
                }
                InterfaceScope::Any => {
                    crate::net::runtime::manager::lookup_ipv4_route_in(runtime, group)
                        .ok()
                        .flatten()
                        .map(|route| route.if_id)
                }
            }) else {
                return false;
            };
            crate::net::runtime::stack::leave_multicast_in(runtime, if_id, group).await
        }
    }

    pub fn send(&self, payload: PacketPayload, dst: UdpAddr) -> UdpSendFuture {
        let payload_len = payload.total_len();
        UdpSendFuture {
            socket: self.socket,
            payload: Some(payload),
            payload_len,
            dst: socket_addr_from_udp(dst),
            dispatch: CommandDispatch::new_in(self.runtime),
        }
    }
}

impl Drop for UdpEndpoint {
    fn drop(&mut self) {
        self.close_internal();
    }
}

pub struct UdpRecvFuture {
    socket: Socket,
}

impl Future for UdpRecvFuture {
    type Output = Option<(NetIfId, UdpAddr, u8, PacketPayload)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.socket.try_recv_udp_payload() {
            Ok((if_id, addr, ttl, payload)) => {
                Poll::Ready(Some((if_id, udp_addr_from_socket(addr), ttl, payload)))
            }
            Err(EndpointError::Timeout) => {
                self.socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
            Err(
                EndpointError::NotConnected
                | EndpointError::InvalidStateTransition
                | EndpointError::NotFound,
            ) => Poll::Ready(None),
            Err(_) => Poll::Ready(None),
        }
    }
}

pub struct UdpSendFuture {
    socket: Socket,
    payload: Option<PacketPayload>,
    payload_len: usize,
    dst: EndpointAddr,
    dispatch: CommandDispatch,
}

impl Future for UdpSendFuture {
    type Output = Result<usize, NetworkError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        {
            let Some(is_bound) = this.socket.with_inner(|inner| inner.is_udp_bound()) else {
                return Poll::Ready(Err(NetworkError::Unknown));
            };
            if !is_bound {
                return Poll::Ready(Err(NetworkError::ConnectionClosed));
            }
        }

        match this.dispatch.poll(cx, || {
            crate::net::runtime::command::RuntimeCommand::Transport(
                crate::net::runtime::command::TransportCommand::UdpSendTo {
                    socket_id: this.socket.socket_id(),
                    payload: this
                        .payload
                        .take()
                        .expect("UdpSendFuture payload already dispatched"),
                    remote: this.dst,
                },
            )
        }) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.payload_len)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(socket_error_to_network(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Default)]
pub struct UdpStats {
    pub rx_datagrams: AtomicU64,
    pub tx_datagrams: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub checksum_errors: AtomicU64,
}

impl UdpStats {
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.rx_datagrams.load(Ordering::Relaxed),
            self.tx_datagrams.load(Ordering::Relaxed),
            self.rx_dropped.load(Ordering::Relaxed),
            self.checksum_errors.load(Ordering::Relaxed),
        )
    }
}
