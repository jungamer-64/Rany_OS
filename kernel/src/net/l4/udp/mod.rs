// ============================================================================
// kernel/src/net/udp.rs
// ============================================================================
//! UDP (User Datagram Protocol) Implementation for ExoRust
//!
//! This module implements zero-copy UDP packet processing
//! for the ExoRust networking stack.


use crate::net::l3::ipv4::{IpProtocol, Ipv4Address, data_checksum, pseudo_header_checksum};
use crate::net::l3::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};
use crate::sync::PoisonLock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use crate::net::datapath::mempool::PacketRef;
use crate::net::types::NetworkError;

extern crate alloc;

#[inline]
fn ipv6_checksum(src: &Ipv6Address, dst: &Ipv6Address, next_header: IpProtocol, data: &[u8]) -> u16 {
    let pseudo = ipv6_pseudo_header_checksum(src, dst, next_header, data.len() as u32);
    data_checksum(data, pseudo)
}

/// UDP header
mod types;
pub use types::*;
mod endpoint_table_impl;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
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

        ipv6_checksum(&src_ip, &dst_ip, IpProtocol::Udp, &self.data[..length as usize]) == 0
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
        let checksum = ipv6_checksum(&src_ip, &dst_ip, IpProtocol::Udp, &self.buffer[..total_len as usize]);

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

/// UDP endpoint address
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

impl core::fmt::Debug for UdpEndpointInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpEndpointInner")
            .field("local_port", &self.local_port)
            .field("rx_queue_bytes", &self.rx_queue_bytes)
            .field("closed", &self.closed)
            .field("token", &self.token)
            .finish()
    }
}

/// UDP endpoint state
pub(crate) struct UdpEndpointInner {
    /// Local port
    local_port: u16,
    /// Receive queue (zero-copy PacketRef + source addr + IP TTL/HopLimit)
    rx_packet_queue: VecDeque<(UdpAddr, u8, PacketRef)>,
    /// Total bytes in receive queue
    rx_queue_bytes: usize,
    /// Wakers for async receive
    wakers: Vec<Waker>,
    /// Is endpoint closed
    closed: bool,
    /// Default TTL for outgoing packets
    pub(crate) ttl: u8,
    /// Optional associated grant token id used to authorize this binding
    token: Option<u64>,
}

/// Maximum UDP receive queue size in bytes (e.g., 256 KB per endpoint)
const MAX_UDP_RX_QUEUE_BYTES: usize = 256 * 1024;
/// UDP endpoint (async)
#[derive(Debug)]
pub struct UdpEndpoint {
    inner: Arc<PoisonLock<UdpEndpointInner>>,
}

impl Clone for UdpEndpoint {
    fn clone(&self) -> Self {
        UdpEndpoint { inner: self.inner.clone() }
    }
}

impl Drop for UdpEndpoint {
    fn drop(&mut self) {
        // Automatically unbind the port when the last endpoint handle is dropped.
        // The global table holds one reference (count=1), so if strong_count is 2,
        // this is the last external handle.
        // イベントキュー経由で非同期unbindを送信（Drop内では同期ロックを回避）
        if Arc::strong_count(&self.inner) == 2 {
            let port = self.local_port();
            if port != 0 {
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::AsyncUnbindUdp {
                        port,
                        result_slot: alloc::sync::Arc::new(crate::sync::PoisonLock::new(None)),
                        waker: alloc::sync::Arc::new(crate::sync::atomic_waker::AtomicWaker::new()),
                    },
                );
            }
        }
    }
}

impl UdpEndpoint {
    /// Create a new UDP endpoint bound to a port
    pub fn new(local_port: u16) -> Self {
        Self::new_with_token(local_port, None)
    }

    /// Create a new UDP endpoint bound to a port and associated with an optional capability token
    pub fn new_with_token(local_port: u16, token: Option<u64>) -> Self {
        UdpEndpoint {
            inner: Arc::new(PoisonLock::new(UdpEndpointInner {
                local_port,
                rx_packet_queue: VecDeque::with_capacity(64),
                rx_queue_bytes: 0,
                wakers: Vec::new(),
                closed: false,
                ttl: 64,
                token,
            })),
        }
    }

    /// Get local port
    pub fn local_port(&self) -> u16 {
        match self.inner.lock() {
            Ok(g) => g.local_port,
            Err(_) => {
                log::error!("[NET] UDP Endpoint poisoned (local_port)");
                0
            }
        }
    }

    /// Set default TTL for outgoing packets
    pub fn set_ttl(&self, ttl: u8) {
        if let Ok(mut g) = self.inner.lock() {
            g.ttl = ttl;
        }
    }

    /// Get default TTL for outgoing packets
    pub fn ttl(&self) -> u8 {
        self.inner.lock().map(|g| g.ttl).unwrap_or(64)
    }

    /// Receive a datagram (async, zero-copy)
    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            endpoint: self.inner.clone(),
        }
    }

    /// Deliver a packet to this socket (called by the network stack)
    pub fn deliver(&self, src: UdpAddr, ttl: u8, packet: PacketRef) {
        match self.inner.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    return;
                }

                let pkt_len = packet.len();
                if inner.rx_packet_queue.len() < 64 && inner.rx_queue_bytes + pkt_len <= MAX_UDP_RX_QUEUE_BYTES {
                    inner.rx_queue_bytes += pkt_len;
                    inner.rx_packet_queue.push_back((src, ttl, packet));

                    for waker in inner.wakers.drain(..) {
                        waker.wake();
                    }
                } else {
                    log::warn!("[NET] UDP socket queue full, dropping packet (len={}, queue_bytes={})", pkt_len, inner.rx_queue_bytes);
                }
            }
            Err(_) => log::error!("[NET] UDP Endpoint poisoned during deliver - dropping packet"),
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
            Err(_) => log::error!("[NET] UDP Endpoint poisoned during close - no-op"),
        }
    }

    /// Check if socket is closed
    pub fn is_closed(&self) -> bool {
        match self.inner.lock() {
            Ok(g) => g.closed,
            Err(_) => {
                log::error!("[NET] UDP Endpoint poisoned (is_closed)");
                true
            }
        }
    }

    /// Join a multicast group (async, event-queue based)
    ///
    /// NETWORK_STACKロックを取得せず、イベントキュー経由で処理する。
    pub fn join_multicast_group(&self, group: Ipv4Address) -> crate::net::runtime::stack::MulticastJoinFuture {
        crate::net::runtime::stack::join_multicast_async(group)
    }

    /// Leave a multicast group (async, event-queue based)
    ///
    /// NETWORK_STACKロックを取得せず、イベントキュー経由で処理する。
    pub fn leave_multicast_group(&self, group: Ipv4Address) -> crate::net::runtime::stack::MulticastLeaveFuture {
        crate::net::runtime::stack::leave_multicast_async(group)
    }

    /// Get receive queue length
    pub fn rx_queue_len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.rx_packet_queue.len(),
            Err(_) => {
                log::error!("[NET] UDP Endpoint poisoned (rx_queue_len)");
                0
            }
        }
    }

    /// Send a datagram to the specified address (async-friendly, non-blocking)
    /// 
    /// The send request is posted to the async event queue instead of synchronously
    /// locking the global network stack. This avoids lock contention and potential
    /// deadlocks when called from async contexts (e.g., within DHCP, mDNS, DNS tasks).
    /// 
    /// Returns the number of bytes sent, or an error.
    pub fn send_to(&self, data: &[u8], dst: UdpAddr) -> Result<usize, NetworkError> {
        let (local_port, ttl) = match self.inner.lock() {
            Ok(g) => {
                if g.closed {
                    return Err(NetworkError::ConnectionClosed);
                }
                (g.local_port, g.ttl)
            }
            Err(_) => return Err(NetworkError::LockPoisoned),
        };

        // Send via async event queue to avoid synchronous NETWORK_STACK lock
        match dst {
            UdpAddr::V4 { ip, port } => {
                if crate::net::runtime::stack::send_udp_async(local_port, ip, port, data, ttl) {
                    Ok(data.len())
                } else {
                    Err(NetworkError::TransmitFailed)
                }
            }
            UdpAddr::V6 { ip, port } => {
                if crate::net::runtime::stack::send_udp_v6_async(local_port, Ipv6Address::UNSPECIFIED, ip, port, data, ttl) {
                    Ok(data.len())
                } else {
                    Err(NetworkError::TransmitFailed)
                }
            }
        }
    }

    /// 【設計書 6.2準拠】非同期UDP送信 (async/await対応)
    ///
    /// `send_to` のFutureラッパー。async/await構文で利用できる。
    /// イベントキューが満杯の場合は自動的にリトライする。
    ///
    /// # 使用例
    /// ```ignore
    /// let sent = socket.send_async(data, dst).await?;
    /// ```
    pub fn send_async<'a>(&'a self, data: &'a [u8], dst: UdpAddr) -> UdpSendFuture<'a> {
        UdpSendFuture {
            endpoint: self,
            data,
            dst,
        }
    }

    /// 【設計書 6.2準拠】ゼロコピー非同期UDP送信
    ///
    /// PacketRefの所有権をスタックに移動して送信する。
    /// コピーが発生しないため高スループットアプリケーションに推奨。
    ///
    /// # 使用例
    /// ```ignore
    /// let mut packet = mempool::alloc_packet().unwrap();
    /// packet.data_mut()[..data.len()].copy_from_slice(data);
    /// packet.set_len(data.len());
    /// socket.send_zero_copy(packet, dst).await?;
    /// ```
    pub fn send_zero_copy(&self, packet: PacketRef, dst: UdpAddr) -> UdpSendZeroCopyFuture {
        UdpSendZeroCopyFuture {
            inner: self.inner.clone(),
            packet: Some(packet),
            dst,
        }
    }
}


/// Future for receiving UDP datagrams
pub struct UdpRecvFuture {
    endpoint: Arc<PoisonLock<UdpEndpointInner>>,
}

impl Future for UdpRecvFuture {
    type Output = Option<(UdpAddr, u8, PacketRef)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.endpoint.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    return Poll::Ready(None);
                }

                if let Some((addr, ttl, packet)) = inner.rx_packet_queue.pop_front() {
                    inner.rx_queue_bytes = inner.rx_queue_bytes.saturating_sub(packet.len());
                    Poll::Ready(Some((addr, ttl, packet)))
                } else {
                    inner.wakers.push(cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(_) => {
                log::error!("[NET] UDP Endpoint poisoned in recv future - returning closed");
                Poll::Ready(None)
            }
        }
    }
}

/// 【設計書 6.2準拠】非同期UDP送信Future
///
/// イベントキューが満杯の場合はバックプレッシャーを適用し、
/// TxAvailableイベントで再ポーリングされるまで待機する。
pub struct UdpSendFuture<'a> {
    endpoint: &'a UdpEndpoint,
    data: &'a [u8],
    dst: UdpAddr,
}

impl<'a> Future for UdpSendFuture<'a> {
    type Output = Result<usize, NetworkError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // まずエンドポイントの状態を確認
        let (local_port, ttl) = match this.endpoint.inner.lock() {
            Ok(g) => {
                if g.closed {
                    return Poll::Ready(Err(NetworkError::ConnectionClosed));
                }
                (g.local_port, g.ttl)
            }
            Err(_) => return Poll::Ready(Err(NetworkError::LockPoisoned)),
        };

        // イベントキュー経由で非同期送信を試行
        let sent = match this.dst {
            UdpAddr::V4 { ip, port } => {
                crate::net::runtime::stack::send_udp_async(local_port, ip, port, this.data, ttl)
            }
            UdpAddr::V6 { ip, port } => {
                crate::net::runtime::stack::send_udp_v6_async(
                    local_port,
                    Ipv6Address::UNSPECIFIED,
                    ip,
                    port,
                    this.data,
                    ttl,
                )
            }
        };

        if sent {
            Poll::Ready(Ok(this.data.len()))
        } else {
            // イベントキュー満杯: Wakerを登録して待機
            if let Ok(mut inner) = this.endpoint.inner.lock() {
                inner.wakers.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

/// 【設計書 6.2準拠】ゼロコピー非同期UDP送信Future
///
/// PacketRefの所有権をスタックに移動して送信する。
/// データコピーが発生しないため高スループットに推奨。
pub struct UdpSendZeroCopyFuture {
    inner: Arc<PoisonLock<UdpEndpointInner>>,
    packet: Option<PacketRef>,
    dst: UdpAddr,
}

impl Future for UdpSendZeroCopyFuture {
    type Output = Result<(), NetworkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        let (local_port, ttl) = match this.inner.lock() {
            Ok(g) => {
                if g.closed {
                    return Poll::Ready(Err(NetworkError::ConnectionClosed));
                }
                (g.local_port, g.ttl)
            }
            Err(_) => return Poll::Ready(Err(NetworkError::LockPoisoned)),
        };

        if let Some(packet) = this.packet.take() {
            let data = packet.data();
            let sent = match this.dst {
                UdpAddr::V4 { ip, port } => {
                    crate::net::runtime::stack::send_udp_async(local_port, ip, port, data, ttl)
                }
                UdpAddr::V6 { ip, port } => {
                    crate::net::runtime::stack::send_udp_v6_async(
                        local_port,
                        Ipv6Address::UNSPECIFIED,
                        ip,
                        port,
                        data,
                        ttl,
                    )
                }
            };

            if sent {
                // パケット所有権解放（Drop時にプールに自動返却）
                Poll::Ready(Ok(()))
            } else {
                // イベントキュー満杯: パケットを戻して待機
                this.packet = Some(packet);
                if let Ok(mut inner) = this.inner.lock() {
                    inner.wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(NetworkError::TransmitFailed))
        }
    }
}

/// Maximum UDP sockets
const MAX_UDP_ENDPOINTS: usize = 1024;

/// UDP socket table
pub struct UdpEndpointTable {
    /// Sockets indexed by local port
    endpoints: PoisonLock<alloc::collections::BTreeMap<u16, Arc<PoisonLock<UdpEndpointInner>>>>,
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
