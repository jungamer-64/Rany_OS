// ============================================================================
// kernel/src/net/udp.rs
// ============================================================================
//! UDP (User Datagram Protocol) Implementation for ExoRust
//!
//! This module implements zero-copy UDP packet processing
//! for the ExoRust networking stack.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use super::ipv4::{IpProtocol, Ipv4Address, data_checksum, pseudo_header_checksum};
use crate::sync::PoisonLock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use crate::net::mempool::PacketRef;
use crate::net::NetworkError;

extern crate alloc;

/// UDP header
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
    /// Raw packet data
    data: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    /// Parse a UDP packet from raw bytes
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < UdpHeader::SIZE {
            return None;
        }

        let packet = UdpPacket { data };

        // Verify length field
        let length = packet.header().length() as usize;
        if length < UdpHeader::SIZE || length > data.len() {
            return None;
        }

        Some(packet)
    }

    /// Get the UDP header
    pub fn header(&self) -> &UdpHeader {
        // SAFETY: We verified the length in parse(). Use the centralized helper
        // to obtain a typed reference with bounds & alignment checks.
        crate::util::get_ref::<UdpHeader>(self.data, 0).expect("UDP header slice out of bounds")
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

    /// Verify checksum
    pub fn verify_checksum(&self, src_ip: Ipv4Address, dst_ip: Ipv4Address) -> bool {
        let checksum = self.header().checksum();

        // Checksum of 0 means no checksum
        if checksum == 0 {
            return true;
        }

        let length = self.header().length();
        let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length);

        // Include the checksum in the data for verification
        let actual_checksum = data_checksum(&self.data[..length as usize], pseudo);
        actual_checksum == 0xFFFF
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
    pub fn header_mut(&mut self) -> &mut UdpHeader {
        // SAFETY: Buffer size checked in new(). Use centralized helper to get a mutable reference.
        crate::util::get_mut_ref::<UdpHeader>(self.buffer, 0)
            .expect("UDP header slice out of bounds")
    }

    /// Set source port
    pub fn set_src_port(&mut self, port: u16) -> &mut Self {
        self.header_mut().set_src_port(port);
        self
    }

    /// Set destination port
    pub fn set_dst_port(&mut self, port: u16) -> &mut Self {
        self.header_mut().set_dst_port(port);
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[UdpHeader::SIZE..]
    }

    /// Write payload
    pub fn write_payload(&mut self, data: &[u8]) -> usize {
        let max = self.buffer.len() - UdpHeader::SIZE;
        let len = data.len().min(max);
        self.buffer[UdpHeader::SIZE..UdpHeader::SIZE + len].copy_from_slice(&data[..len]);
        self.payload_len = len;
        len
    }

    /// Set payload length
    pub fn set_payload_len(&mut self, len: usize) {
        self.payload_len = len.min(self.buffer.len() - UdpHeader::SIZE);
    }

    /// Finalize the packet (compute checksum)
    pub fn finalize(&mut self, src_ip: Ipv4Address, dst_ip: Ipv4Address) -> usize {
        let total_len = (UdpHeader::SIZE + self.payload_len) as u16;

        // Set length
        self.header_mut().set_length(total_len);

        // Clear checksum for calculation
        self.header_mut().set_checksum(0);

        // Calculate checksum with pseudo-header
        let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, total_len);
        let checksum = data_checksum(&self.buffer[..total_len as usize], pseudo);

        // Use 0xFFFF instead of 0 (0 means no checksum)
        let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        self.header_mut().set_checksum(final_checksum);

        total_len as usize
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..UdpHeader::SIZE + self.payload_len]
    }
}

/// UDP socket address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpAddr {
    /// IP address
    pub ip: Ipv4Address,
    /// Port number
    pub port: u16,
}

impl UdpAddr {
    /// Create a new UDP address
    pub const fn new(ip: Ipv4Address, port: u16) -> Self {
        UdpAddr { ip, port }
    }
}

/// Received UDP datagram
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    /// Source address
    pub src: UdpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Payload data
    pub data: Vec<u8>,
}

/// UDP socket state
pub(crate) struct UdpSocketInner {
    /// Local port
    local_port: u16,
    /// Receive queue (copy-based datagrams)
    rx_queue: VecDeque<UdpDatagram>,
    /// Receive queue (zero-copy PacketRef)
    rx_packet_queue: VecDeque<(UdpAddr, PacketRef)>,
    /// Waker for async receive
    waker: Option<Waker>,
    /// Is socket closed
    closed: bool,
    /// Optional associated grant token id used to authorize this binding
    token: Option<u64>,
}  

/// UDP socket (async)
pub struct UdpSocket {
    inner: Arc<PoisonLock<UdpSocketInner>>,
}

impl Clone for UdpSocket {
    fn clone(&self) -> Self {
        UdpSocket { inner: self.inner.clone() }
    }
}

impl UdpSocket {
    /// Create a new UDP socket bound to a port
    pub fn new(local_port: u16) -> Self {
        Self::new_with_token(local_port, None)
    }

    /// Create a new UDP socket bound to a port and associated with an optional capability token
    pub fn new_with_token(local_port: u16, token: Option<u64>) -> Self {
        UdpSocket {
            inner: Arc::new(PoisonLock::new(UdpSocketInner {
                local_port,
                rx_queue: VecDeque::new(),
                rx_packet_queue: VecDeque::new(),
                waker: None,
                closed: false,
                token,
            })),
        }
    }

    /// Get local port
    pub fn local_port(&self) -> u16 {
        match self.inner.lock() {
            Ok(g) => g.local_port,
            Err(_) => {
                log::error!("[NET] UDP Socket poisoned (local_port)");
                0
            }
        }
    }

    /// Receive a datagram (async)
    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            socket: self.inner.clone(),
        }
    }

    /// Receive a datagram as PacketRef (zero-copy)
    pub fn recv_packet(&self) -> UdpRecvPacketFuture {
        UdpRecvPacketFuture {
            socket: self.inner.clone(),
        }
    }

    /// Deliver a datagram to this socket (called by the network stack)
    pub fn deliver(&self, datagram: UdpDatagram) {
        match self.inner.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    return;
                }

                inner.rx_queue.push_back(datagram);

                if let Some(waker) = inner.waker.take() {
                    waker.wake();
                }
            }
            Err(_) => log::error!("[NET] UDP Socket poisoned during deliver - dropping datagram"),
        }
    }

    /// Close the socket
    pub fn close(&self) {
        match self.inner.lock() {
            Ok(mut inner) => {
                inner.closed = true;
                inner.rx_queue.clear();

                if let Some(waker) = inner.waker.take() {
                    waker.wake();
                }
            }
            Err(_) => log::error!("[NET] UDP Socket poisoned during close - no-op"),
        }
    }

    /// Check if socket is closed
    pub fn is_closed(&self) -> bool {
        match self.inner.lock() {
            Ok(g) => g.closed,
            Err(_) => {
                log::error!("[NET] UDP Socket poisoned (is_closed)");
                true
            }
        }
    }

    /// Get receive queue length
    pub fn rx_queue_len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.rx_queue.len(),
            Err(_) => {
                log::error!("[NET] UDP Socket poisoned (rx_queue_len)");
                0
            }
        }
    }

    /// Send a datagram to the specified address (async-friendly, non-blocking)
    /// 
    /// Returns the number of bytes sent, or an error.
    pub fn send_to(&self, data: &[u8], dst: UdpAddr) -> Result<usize, NetworkError> {
        let local_port = match self.inner.lock() {
            Ok(g) => {
                if g.closed {
                    return Err(NetworkError::ConnectionClosed);
                }
                g.local_port
            }
            Err(_) => return Err(NetworkError::LockPoisoned),
        };

        // Send via network stack using existing send_udp
        let dst_ip = dst.ip;
        let dst_port = dst.port;
        
        if crate::net::stack::send_udp(local_port, dst_ip, dst_port, data) {
            Ok(data.len())
        } else {
            Err(NetworkError::TransmitFailed)
        }
    }
}


/// Future for receiving UDP datagrams
pub struct UdpRecvFuture {
    socket: Arc<PoisonLock<UdpSocketInner>>,
}

impl Future for UdpRecvFuture {
    type Output = Option<UdpDatagram>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.socket.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    return Poll::Ready(None);
                }

                if let Some(datagram) = inner.rx_queue.pop_front() {
                    Poll::Ready(Some(datagram))
                } else {
                    inner.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] UDP Socket poisoned in recv future - returning closed");
                Poll::Ready(None)
            }
        }
    }
}

/// Future for receiving UDP datagrams as PacketRef
pub struct UdpRecvPacketFuture {
    socket: Arc<PoisonLock<UdpSocketInner>>,
}

impl Future for UdpRecvPacketFuture {
    type Output = Option<(UdpAddr, PacketRef)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.socket.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    return Poll::Ready(None);
                }

                if let Some((addr, packet)) = inner.rx_packet_queue.pop_front() {
                    Poll::Ready(Some((addr, packet)))
                } else {
                    inner.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] UDP Socket poisoned in recv_packet future - returning closed");
                Poll::Ready(None)
            }
        }
    }
}

/// Maximum UDP sockets
const MAX_UDP_SOCKETS: usize = 256;

/// UDP socket table
pub struct UdpSocketTable {
    /// Sockets indexed by local port
    sockets: PoisonLock<[Option<Arc<PoisonLock<UdpSocketInner>>>; MAX_UDP_SOCKETS]>,
    /// Statistics
    stats: UdpStats,
}

/// UDP statistics
#[derive(Debug, Default)]
pub struct UdpStats {
    /// Datagrams received
    pub rx_datagrams: core::sync::atomic::AtomicU64,
    /// Datagrams transmitted
    pub tx_datagrams: core::sync::atomic::AtomicU64,
    /// Datagrams dropped (no socket)
    pub rx_dropped: core::sync::atomic::AtomicU64,
    /// Checksum errors
    pub checksum_errors: core::sync::atomic::AtomicU64,
}

impl UdpSocketTable {
    /// Create a new UDP socket table
    pub const fn new() -> Self {
        const NONE: Option<Arc<PoisonLock<UdpSocketInner>>> = None;
        UdpSocketTable {
            sockets: PoisonLock::new([NONE; MAX_UDP_SOCKETS]),
            stats: UdpStats {
                rx_datagrams: core::sync::atomic::AtomicU64::new(0),
                tx_datagrams: core::sync::atomic::AtomicU64::new(0),
                rx_dropped: core::sync::atomic::AtomicU64::new(0),
                checksum_errors: core::sync::atomic::AtomicU64::new(0),
            },
        }
    }

    // Legacy `bind(port)` wrapper removed. Use `bind_with_token(port, None)` instead.

    /// Bind a socket to a port and associate it with an optional capability token.
    /// If `token` is Some(id), this will attempt to increment the token's in-flight
    /// counter. On failure, bind will return None.
    pub fn bind_with_token(&self, port: u16, token: Option<u64>) -> Option<UdpSocket> {
        match self.sockets.lock() {
            Ok(mut sockets) => {
                // Find slot for this port
                let slot = (port as usize) % MAX_UDP_SOCKETS;

                // Check if already bound
                if sockets[slot].is_some() {
                    return None;
                }

                // If a token was provided, attempt to increment in-flight. If it fails,
                // abort bind.
                if let Some(t) = token {
                    if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                        return None;
                    }
                }

                let inner = Arc::new(PoisonLock::new(UdpSocketInner {
                    local_port: port,
                    rx_queue: VecDeque::new(),
                    rx_packet_queue: VecDeque::new(),
                    waker: None,
                    closed: false,
                    token,
                }));

                sockets[slot] = Some(inner.clone());

                Some(UdpSocket { inner })
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned during bind");
                // If we incremented in-flight above, roll back
                if let Some(t) = token {
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                None
            }
        }
    }

    /// Unbind a socket from a port and decrement any associated token in-flight counter
    pub fn unbind(&self, port: u16) {
        match self.sockets.lock() {
            Ok(mut sockets) => {
                let slot = (port as usize) % MAX_UDP_SOCKETS;
                if let Some(inner) = sockets[slot].take() {
                    match inner.lock() {
                        Ok(mut guard) => {
                            if let Some(t) = guard.token.take() {
                                let _ = crate::security::capability::manager().decrement_in_flight(t);
                            }
                        }
                        Err(_) => log::error!("[NET] UDP Socket poisoned during unbind - token cleanup skipped"),
                    }
                }
            }
            Err(_) => log::error!("[NET] UDP Table poisoned during unbind"),
        }
    }

    /// Find a socket by port
    pub(crate) fn find(&self, port: u16) -> Option<Arc<PoisonLock<UdpSocketInner>>> {
        match self.sockets.lock() {
            Ok(sockets) => {
                let slot = (port as usize) % MAX_UDP_SOCKETS;

                if let Some(ref inner) = sockets[slot] {
                    match inner.lock() {
                        Ok(socket) => {
                            if socket.local_port == port && !socket.closed {
                                return Some(inner.clone());
                            }
                        }
                        Err(_) => {
                            log::error!("[NET] UDP Socket poisoned during find");
                            return None;
                        }
                    }
                }

                None
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned (find)");
                None
            }
        }
    }

    /// Deliver a datagram to the appropriate socket
    pub fn deliver(&self, datagram: UdpDatagram) -> bool {
        use core::sync::atomic::Ordering;

        if let Some(socket) = self.find(datagram.dst_port) {
            match socket.lock() {
                Ok(mut inner) => {
                    if inner.closed {
                        self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }

                    inner.rx_queue.push_back(datagram);

                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }

                    self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(_) => {
                    log::error!("[NET] UDP Socket poisoned during deliver - dropping datagram");
                    self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Deliver a packet to the appropriate socket using a PacketRef (zero-copy)
    pub fn deliver_packet(&self, src: UdpAddr, dst_port: u16, packet: PacketRef) -> bool {
        use core::sync::atomic::Ordering;

        if let Some(socket) = self.find(dst_port) {
            match socket.lock() {
                Ok(mut inner) => {
                    if inner.closed {
                        self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }

                    inner.rx_packet_queue.push_back((src, packet));

                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }

                    self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(_) => {
                    log::error!("[NET] UDP Socket poisoned during deliver_packet - dropping packet");
                    self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        use core::sync::atomic::Ordering;
        (
            self.stats.rx_datagrams.load(Ordering::Relaxed),
            self.stats.tx_datagrams.load(Ordering::Relaxed),
            self.stats.rx_dropped.load(Ordering::Relaxed),
            self.stats.checksum_errors.load(Ordering::Relaxed),
        )
    }

    /// List all bound UDP sockets (for netstat)
    pub fn list_sockets(&self) -> alloc::vec::Vec<UdpSocketSnapshot> {
        let mut result = alloc::vec::Vec::new();
        match self.sockets.lock() {
            Ok(sockets) => {
                for slot in sockets.iter() {
                    if let Some(inner) = slot {
                        match inner.lock() {
                            Ok(socket) => {
                                if !socket.closed {
                                    result.push(UdpSocketSnapshot {
                                        local_port: socket.local_port,
                                        rx_queue_len: socket.rx_queue.len() + socket.rx_packet_queue.len(),
                                    });
                                }
                            }
                            Err(_) => {
                                // Skip poisoned sockets
                            }
                        }
                    }
                }
            }
            Err(_) => {
                log::error!("[NET] UDP Table poisoned during list_sockets");
            }
        }
        result
    }

    /// Get number of bound sockets
    pub fn socket_count(&self) -> usize {
        match self.sockets.lock() {
            Ok(sockets) => sockets.iter().filter(|s| s.is_some()).count(),
            Err(_) => 0,
        }
    }
}

/// UDP socket snapshot for monitoring
#[derive(Debug, Clone)]
pub struct UdpSocketSnapshot {
    /// Local port
    pub local_port: u16,
    /// Number of pending datagrams in receive queue
    pub rx_queue_len: usize,
}

/// UDP processor for handling UDP packets

pub struct UdpProcessor {
    /// Socket table
    sockets: UdpSocketTable,
}

/// Result of UDP processing
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UdpResult {
    /// Delivered to socket
    Delivered,
    /// No socket for this port
    NoSocket,
    /// Checksum error
    ChecksumError,
    /// Invalid packet
    Invalid,
}

impl UdpProcessor {
    /// Create a new UDP processor
    pub fn new() -> Self {
        UdpProcessor {
            sockets: UdpSocketTable::new(),
        }
    }

    /// Get socket table
    pub fn sockets(&self) -> &UdpSocketTable {
        &self.sockets
    }

    /// Process an incoming UDP packet
    pub fn process(&self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        // Verify checksum
        if !packet.verify_checksum(src_ip, dst_ip) {
            self.sockets
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let datagram = UdpDatagram {
            src: UdpAddr::new(src_ip, packet.src_port()),
            dst_port: packet.dst_port(),
            data: packet.payload().to_vec(),
        };

        if self.sockets.deliver(datagram) {
            UdpResult::Delivered
        } else {
            UdpResult::NoSocket
        }
    }

    /// Process an incoming UDP packet with an existing PacketRef (zero-copy)
    pub fn process_with_packet(&self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, packet: PacketRef) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet_view = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        if !packet_view.verify_checksum(src_ip, dst_ip) {
            self.sockets
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let src = UdpAddr::new(src_ip, packet_view.src_port());
        let dst_port = packet_view.dst_port();

        if self.sockets.deliver_packet(src, dst_port, packet) {
            UdpResult::Delivered
        } else {
            UdpResult::NoSocket
        }
    }

    // Legacy `bind` removed; use `bind_with_token(port, None)` instead.

    /// Bind to a port with a capability token
    pub fn bind_with_token(&self, port: u16, token: Option<u64>) -> Result<UdpSocket, NetworkError> {
        // If no token provided, delegate directly to socket table's token-aware bind
        if token.is_none() {
            return self.sockets.bind_with_token(port, None).ok_or(NetworkError::PortInUse);
        }

        // Token present - validate ownership and capability
        let t = token.unwrap();
        let caller_domain = crate::task::context::current_subject().domain;
        if !crate::security::capability::manager().validate_token(caller_domain.as_u64(), t, crate::security::capability::CAP_NET_BIND) {
             return Err(NetworkError::PermissionDenied);
        }
        
        self.sockets.bind_with_token(port, Some(t)).ok_or(NetworkError::PortInUse)
    }

    /// Unbind a socket
    pub fn unbind(&self, port: u16) {
        self.sockets.unbind(port)
    }

    /// Build a UDP packet for transmission
    pub fn build_packet<'a>(
        buffer: &'a mut [u8],
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<usize> {
        let mut packet = UdpPacketMut::new(buffer)?;
        packet
            .set_src_port(src_port)
            .set_dst_port(dst_port)
            .write_payload(payload);
        Some(packet.finalize(src_ip, dst_ip))
    }
}

impl Default for UdpProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
