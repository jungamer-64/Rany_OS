// ============================================================================
// kernel/src/net/udp.rs
// ============================================================================
//! UDP (User Datagram Protocol) Implementation for ExoRust
//!
//! This module implements zero-copy UDP packet processing
//! for the ExoRust networking stack.


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
mod types;
pub use types::*;
mod socket_table_impl;
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
    pub fn header_mut(&mut self) -> Option<&mut UdpHeader> {
        crate::util::get_mut_ref::<UdpHeader>(self.buffer, 0)
    }

    /// Set source port
    pub fn set_src_port(&mut self, port: u16) -> &mut Self {
        if let Some(h) = self.header_mut() { h.set_src_port(port); }
        self
    }

    /// Set destination port
    pub fn set_dst_port(&mut self, port: u16) -> &mut Self {
        if let Some(h) = self.header_mut() { h.set_dst_port(port); }
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[UdpHeader::SIZE..]
    }

    /// Write payload
    pub fn write_payload(&mut self, data: &[u8]) -> usize {
        let max_buffer = self.buffer.len() - UdpHeader::SIZE;
        // RFC 768: UDP length is 16-bit, so total length (header+payload) <= 65535.
        // Payload max = 65535 - 8 = 65527.
        let max_udp = 65527;
        let max = max_buffer.min(max_udp);

        let len = data.len().min(max);
        self.buffer[UdpHeader::SIZE..UdpHeader::SIZE + len].copy_from_slice(&data[..len]);
        self.payload_len = len;
        len
    }

    /// Set payload length
    pub fn set_payload_len(&mut self, len: usize) {
        let max_udp = 65527;
        self.payload_len = len.min(self.buffer.len() - UdpHeader::SIZE).min(max_udp);
    }

    /// Finalize the packet (compute checksum)
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

/// UDP socket state
pub(crate) struct UdpSocketInner {
    /// Local port
    local_port: u16,
    /// Receive queue (zero-copy PacketRef)
    rx_packet_queue: VecDeque<(UdpAddr, PacketRef)>,
    /// Wakers for async receive
    wakers: Vec<Waker>,
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
                rx_packet_queue: VecDeque::with_capacity(64),
                wakers: Vec::new(),
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

    /// Receive a datagram (async, zero-copy)
    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            socket: self.inner.clone(),
        }
    }

    /// Deliver a packet to this socket (called by the network stack)
    pub fn deliver(&self, src: UdpAddr, packet: PacketRef) {
        match self.inner.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    return;
                }

                if inner.rx_packet_queue.len() < 64 {
                    inner.rx_packet_queue.push_back((src, packet));

                    for waker in inner.wakers.drain(..) {
                        waker.wake();
                    }
                }
            }
            Err(_) => log::error!("[NET] UDP Socket poisoned during deliver - dropping packet"),
        }
    }

    /// Close the socket
    pub fn close(&self) {
        match self.inner.lock() {
            Ok(mut inner) => {
                inner.closed = true;
                inner.rx_packet_queue.clear();

                for waker in inner.wakers.drain(..) {
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
            Ok(g) => g.rx_packet_queue.len(),
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
                    inner.wakers.push(cx.waker().clone());
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

/// Maximum UDP sockets
const MAX_UDP_SOCKETS: usize = 1024;

/// UDP socket table
pub struct UdpSocketTable {
    /// Sockets indexed by local port
    sockets: PoisonLock<alloc::collections::BTreeMap<u16, Arc<PoisonLock<UdpSocketInner>>>>,
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
