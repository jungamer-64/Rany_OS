// ============================================================================
// kernel/src/net/l4/socket/state.rs - L4 / ソケット / 状態
// ============================================================================
//! Internal socket state and protocol-specific entries.

use alloc::collections::VecDeque;
use core::ops::{Deref, DerefMut};

use crate::net::l4::tcp::TcpStats;
use crate::net::l4::types::{AcceptedConnection, EndpointAddr, EndpointError, SocketResult};
use crate::net::payload::packet_payload_from_segments;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use crate::sync::atomic_waker::AtomicWaker;
use kernel_api::resource::net::{PacketByteCount, PacketPayload, PacketPayloadFront};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpSocketState {
    Listening,
    Connecting,
    Connected,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpSocketState {
    Bound,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawSocketState {
    Open,
    Closed,
}

pub(crate) struct SocketCommon {
    pub local_addr: Option<EndpointAddr>,
    pub remote_addr: Option<EndpointAddr>,
    pub scope: InterfaceScope,
    pub last_ingress_if_id: Option<NetIfId>,
    pub recv_buffer_limit: usize,
    pub send_buffer_limit: usize,
    pub last_error: Option<EndpointError>,
    pub recv_waker: AtomicWaker,
    pub send_waker: AtomicWaker,
    pub connect_waker: AtomicWaker,
    pub accept_waker: AtomicWaker,
    pub priority: u8,
}

impl SocketCommon {
    pub const MAX_BUFFER_SIZE: usize = 65536;

    fn new() -> Self {
        Self {
            local_addr: None,
            remote_addr: None,
            scope: InterfaceScope::Any,
            last_ingress_if_id: None,
            recv_buffer_limit: Self::MAX_BUFFER_SIZE,
            send_buffer_limit: Self::MAX_BUFFER_SIZE,
            last_error: None,
            recv_waker: AtomicWaker::new(),
            send_waker: AtomicWaker::new(),
            connect_waker: AtomicWaker::new(),
            accept_waker: AtomicWaker::new(),
            priority: 0,
        }
    }
}

pub(crate) struct TcpSocketEntry {
    pub state: TcpSocketState,
    pub accept_queue: VecDeque<AcceptedConnection>,
    pub accept_backlog: usize,
    pub recv_payload_queue: VecDeque<QueuedPayload>,
    pub recv_payload_bytes: usize,
    pub send_buffer: TcpSendBuffer,
    pub nodelay: bool,
    pub urgent_pending: bool,
    pub stats: TcpStats,
}

pub(crate) struct QueuedPayload {
    payload: PacketPayload,
}

pub(crate) struct TcpSendBuffer {
    chunks: VecDeque<QueuedPayload>,
    len: usize,
}

impl QueuedPayload {
    pub fn new(payload: PacketPayload) -> Self {
        Self { payload }
    }

    fn remaining_len(&self) -> usize {
        self.payload.total_len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining_len() == 0
    }

    fn into_remaining_payload(self) -> Option<PacketPayload> {
        Some(self.payload)
    }

    fn take_front(&mut self, len: usize) -> Option<PacketPayload> {
        if len == 0 || len > self.remaining_len() {
            return None;
        }

        let count = PacketByteCount::new(len)?;
        let payload = core::mem::take(&mut self.payload);
        match payload.take_front(count).ok()? {
            PacketPayloadFront::Whole(front) => Some(front),
            PacketPayloadFront::Prefix { front, remainder } => {
                self.payload = remainder;
                Some(front)
            }
        }
    }
}

impl TcpSendBuffer {
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn clear(&mut self) {
        self.chunks.clear();
        self.len = 0;
    }

    fn push(&mut self, payload: PacketPayload, limit: usize) -> SocketResult<()> {
        let payload_len = payload.total_len();
        let available = limit.saturating_sub(self.len);
        if payload_len == 0 {
            return Ok(());
        }
        if payload_len > available {
            return Err(EndpointError::BufferFull);
        }
        self.len = self.len.saturating_add(payload_len);
        self.chunks.push_back(QueuedPayload::new(payload));
        Ok(())
    }

    fn trim_empty(&mut self) {
        while matches!(self.chunks.front(), Some(payload) if payload.is_empty()) {
            self.chunks.pop_front();
        }
    }

    fn take_segment_window(&mut self, max_len: usize) -> Option<PacketPayload> {
        if max_len == 0 || self.len == 0 {
            return None;
        }
        self.trim_empty();
        let take = self.len.min(max_len);
        let mut remaining = take;
        let mut segments = alloc::vec::Vec::new();

        while remaining > 0 {
            let front = self.chunks.front_mut()?;
            let front_take = remaining.min(front.remaining_len());
            let payload = front.take_front(front_take)?;
            segments.extend(payload.into_segments());
            remaining -= front_take;
            if front.is_empty() {
                self.chunks.pop_front();
            }
        }

        self.len = self.len.saturating_sub(take);
        Some(packet_payload_from_segments(segments))
    }
}

impl TcpSocketEntry {
    pub const DEFAULT_BACKLOG: usize = 128;

    pub fn new(state: TcpSocketState) -> Self {
        Self {
            state,
            accept_queue: VecDeque::with_capacity(Self::DEFAULT_BACKLOG),
            accept_backlog: Self::DEFAULT_BACKLOG,
            recv_payload_queue: VecDeque::new(),
            recv_payload_bytes: 0,
            send_buffer: TcpSendBuffer::new(),
            nodelay: false,
            urgent_pending: false,
            stats: TcpStats::default(),
        }
    }
}

pub(crate) struct UdpSocketEntry {
    pub state: UdpSocketState,
    pub pending_packets: VecDeque<(NetIfId, EndpointAddr, u8, PacketPayload)>,
    pub ttl: u8,
    pub token: Option<u64>,
}

impl UdpSocketEntry {
    pub fn new(state: UdpSocketState) -> Self {
        Self {
            state,
            pending_packets: VecDeque::with_capacity(16),
            ttl: 64,
            token: None,
        }
    }
}

pub(crate) struct RawSocketEntry {
    pub state: RawSocketState,
    pub pending_payloads: VecDeque<(NetIfId, PacketPayload)>,
}

impl RawSocketEntry {
    pub fn new(state: RawSocketState) -> Self {
        Self {
            state,
            pending_payloads: VecDeque::with_capacity(16),
        }
    }
}

pub(crate) enum SocketEntry {
    Tcp(TcpSocketEntry),
    Udp(UdpSocketEntry),
    Raw(RawSocketEntry),
}

pub(crate) struct SocketState {
    pub common: SocketCommon,
    pub entry: SocketEntry,
}

impl Deref for SocketState {
    type Target = SocketCommon;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for SocketState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

impl SocketState {
    pub const DEFAULT_BACKLOG: usize = TcpSocketEntry::DEFAULT_BACKLOG;

    pub fn new_tcp(state: TcpSocketState) -> Self {
        Self {
            common: SocketCommon::new(),
            entry: SocketEntry::Tcp(TcpSocketEntry::new(state)),
        }
    }

    pub fn new_udp() -> Self {
        Self {
            common: SocketCommon::new(),
            entry: SocketEntry::Udp(UdpSocketEntry::new(UdpSocketState::Bound)),
        }
    }

    pub fn new_raw() -> Self {
        Self {
            common: SocketCommon::new(),
            entry: SocketEntry::Raw(RawSocketEntry::new(RawSocketState::Open)),
        }
    }

    #[inline]
    pub fn is_tcp(&self) -> bool {
        matches!(self.entry, SocketEntry::Tcp(_))
    }

    #[inline]
    pub fn is_udp(&self) -> bool {
        matches!(self.entry, SocketEntry::Udp(_))
    }

    #[inline]
    pub fn is_raw(&self) -> bool {
        matches!(self.entry, SocketEntry::Raw(_))
    }

    #[inline]
    pub fn tcp(&self) -> Option<&TcpSocketEntry> {
        match &self.entry {
            SocketEntry::Tcp(tcp) => Some(tcp),
            _ => None,
        }
    }

    #[inline]
    pub fn tcp_mut(&mut self) -> Option<&mut TcpSocketEntry> {
        match &mut self.entry {
            SocketEntry::Tcp(tcp) => Some(tcp),
            _ => None,
        }
    }

    #[inline]
    pub fn udp(&self) -> Option<&UdpSocketEntry> {
        match &self.entry {
            SocketEntry::Udp(udp) => Some(udp),
            _ => None,
        }
    }

    #[inline]
    pub fn udp_mut(&mut self) -> Option<&mut UdpSocketEntry> {
        match &mut self.entry {
            SocketEntry::Udp(udp) => Some(udp),
            _ => None,
        }
    }

    #[inline]
    pub fn raw(&self) -> Option<&RawSocketEntry> {
        match &self.entry {
            SocketEntry::Raw(raw) => Some(raw),
            _ => None,
        }
    }

    #[inline]
    pub fn raw_mut(&mut self) -> Option<&mut RawSocketEntry> {
        match &mut self.entry {
            SocketEntry::Raw(raw) => Some(raw),
            _ => None,
        }
    }

    #[inline]
    pub fn tcp_state(&self) -> Option<TcpSocketState> {
        self.tcp().map(|tcp| tcp.state)
    }

    #[inline]
    pub fn udp_state(&self) -> Option<UdpSocketState> {
        self.udp().map(|udp| udp.state)
    }

    #[inline]
    pub fn raw_state(&self) -> Option<RawSocketState> {
        self.raw().map(|raw| raw.state)
    }

    #[inline]
    pub fn set_tcp_state(&mut self, state: TcpSocketState) -> SocketResult<()> {
        let Some(tcp) = self.tcp_mut() else {
            return Err(EndpointError::InvalidArgument);
        };
        tcp.state = state;
        Ok(())
    }

    #[inline]
    pub fn is_tcp_listening(&self) -> bool {
        matches!(self.tcp_state(), Some(TcpSocketState::Listening))
    }

    #[inline]
    pub fn is_tcp_closing_or_closed(&self) -> bool {
        matches!(
            self.tcp_state(),
            Some(TcpSocketState::Closing | TcpSocketState::Closed)
        )
    }

    #[inline]
    pub fn is_udp_bound(&self) -> bool {
        matches!(self.udp_state(), Some(UdpSocketState::Bound))
    }

    #[inline]
    pub fn is_raw_open(&self) -> bool {
        matches!(self.raw_state(), Some(RawSocketState::Open))
    }

    #[inline]
    pub fn mark_closed(&mut self) {
        match &mut self.entry {
            SocketEntry::Tcp(tcp) => {
                tcp.state = TcpSocketState::Closed;
                tcp.recv_payload_queue.clear();
                tcp.recv_payload_bytes = 0;
                tcp.send_buffer.clear();
            }
            SocketEntry::Udp(udp) => {
                udp.state = UdpSocketState::Closed;
                udp.pending_packets.clear();
            }
            SocketEntry::Raw(raw) => {
                raw.state = RawSocketState::Closed;
                raw.pending_payloads.clear();
            }
        }
    }

    #[inline]
    fn trim_empty_payloads(queue: &mut VecDeque<QueuedPayload>) {
        while matches!(queue.front(), Some(payload) if payload.is_empty()) {
            queue.pop_front();
        }
    }

    #[inline]
    pub fn set_urgent_pending(&mut self, pending: bool) {
        if let Some(tcp) = self.tcp_mut() {
            tcp.urgent_pending = pending;
        }
    }

    #[inline]
    pub fn recv_payload_bytes(&self) -> usize {
        self.tcp().map_or(0, |tcp| tcp.recv_payload_bytes)
    }

    #[inline]
    pub fn send_payload_bytes(&self) -> usize {
        self.tcp().map_or(0, |tcp| tcp.send_buffer.len())
    }

    #[inline]
    pub fn has_recv_data(&self) -> bool {
        self.recv_payload_bytes() > 0
    }

    #[inline]
    pub fn has_send_data(&self) -> bool {
        self.send_payload_bytes() > 0
    }

    #[inline]
    pub fn recv_payload(&mut self, max_len: Option<usize>) -> Option<PacketPayload> {
        let tcp = self.tcp_mut()?;
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        let payload = match max_len {
            Some(limit) => {
                let front = tcp.recv_payload_queue.pop_front()?;
                if front.remaining_len() > limit {
                    tcp.recv_payload_queue.push_front(front);
                    return None;
                }
                front.into_remaining_payload()?
            }
            None => tcp
                .recv_payload_queue
                .pop_front()?
                .into_remaining_payload()?,
        };

        tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_sub(payload.total_len());
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        if payload.total_len() > 0 {
            self.send_waker.wake();
        }

        Some(payload)
    }

    #[inline]
    pub fn send_payload(&mut self, payload: PacketPayload) -> SocketResult<()> {
        let limit = self.send_buffer_limit;
        let Some(tcp) = self.tcp_mut() else {
            return Err(EndpointError::InvalidArgument);
        };
        tcp.send_buffer.push(payload, limit)
    }

    #[inline]
    pub fn take_send_segment_window(&mut self, max_len: usize) -> Option<PacketPayload> {
        let tcp = self.tcp_mut()?;
        tcp.send_buffer.take_segment_window(max_len)
    }

    #[inline]
    pub fn push_recv_payload(&mut self, payload: PacketPayload) -> usize {
        let available = self
            .recv_buffer_limit
            .saturating_sub(self.recv_payload_bytes());
        if available == 0 {
            return 0;
        }

        if payload.total_len() > available {
            return 0;
        }

        let queued = payload;
        let len = queued.total_len();
        if len > 0 {
            let Some(tcp) = self.tcp_mut() else {
                return 0;
            };
            tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_add(len);
            tcp.recv_payload_queue.push_back(QueuedPayload::new(queued));
            Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

            self.recv_waker.wake();
        }
        len
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::net::payload::GeneratedPacketWriter;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    fn payload_bytes(data: &[u8]) -> PacketPayload {
        let mut writer = GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM)
            .expect("test payload allocation");
        writer
            .write_generated_bytes(data)
            .expect("test payload write succeeds");
        writer.finish().expect("test payload is exact")
    }

    #[cfg_attr(target_os = "linux", test)]
    #[cfg_attr(not(target_os = "linux"), test_case)]
    pub fn test_send_payload_rejects_partial_enqueue_without_slicing() {
        let mut state = SocketState::new_tcp(TcpSocketState::Connected);
        state.send_buffer_limit = 4;

        assert_eq!(
            state.send_payload(payload_bytes(b"abcde")),
            Err(EndpointError::BufferFull)
        );
        assert_eq!(state.send_payload_bytes(), 0);
        assert!(!state.has_send_data());

        state.send_buffer_limit = 5;
        assert_eq!(state.send_payload(payload_bytes(b"abcde")), Ok(()));
        assert_eq!(state.send_payload_bytes(), 5);
    }

    #[cfg_attr(target_os = "linux", test)]
    #[cfg_attr(not(target_os = "linux"), test_case)]
    pub fn test_take_send_segment_window_splits_front_payload() {
        let mut state = SocketState::new_tcp(TcpSocketState::Connected);
        assert_eq!(state.send_payload(payload_bytes(b"abcde")), Ok(()));

        let prefix = state
            .take_send_segment_window(4)
            .expect("front payload should be sliced as a byte stream");
        assert_eq!(prefix.total_len(), 4);
        assert_eq!(state.send_payload_bytes(), 1);

        let payload = state
            .take_send_segment_window(5)
            .expect("remaining byte should stay queued");
        assert_eq!(payload.total_len(), 1);
        assert_eq!(state.send_payload_bytes(), 0);
    }

    #[cfg_attr(target_os = "linux", test)]
    #[cfg_attr(not(target_os = "linux"), test_case)]
    pub fn test_recv_payload_limit_does_not_split_front_payload() {
        let mut state = SocketState::new_tcp(TcpSocketState::Connected);
        assert_eq!(state.push_recv_payload(payload_bytes(b"abcde")), 5);

        assert!(state.recv_payload(Some(4)).is_none());
        assert_eq!(state.recv_payload_bytes(), 5);

        let payload = state
            .recv_payload(Some(5))
            .expect("whole payload should be moved");
        assert_eq!(payload.total_len(), 5);
        assert_eq!(state.recv_payload_bytes(), 0);
    }
}
