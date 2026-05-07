// ============================================================================
// kernel/src/net/l4/socket/state.rs - L4 / ソケット / 状態
// ============================================================================
//! Internal socket state and protocol-specific entries.

use alloc::collections::VecDeque;
use core::ops::{Deref, DerefMut};

use crate::net::l4::tcp::TcpStats;
use crate::net::l4::tcp::congestion::CongestionAlgorithm;
use crate::net::l4::types::{AcceptedConnection, EndpointAddr, EndpointError, SocketResult};
use crate::net::payload::{PacketPayloadView, append_payload};
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use kernel_api::resource::net::PacketPayload;

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
    pub recv_waker: Option<core::task::Waker>,
    pub send_waker: Option<core::task::Waker>,
    pub connect_waker: Option<core::task::Waker>,
    pub accept_waker: Option<core::task::Waker>,
    pub priority: u8,
}

impl SocketCommon {
    pub const DEFAULT_BUFFER_SIZE: usize = 8192;
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
            recv_waker: None,
            send_waker: None,
            connect_waker: None,
            accept_waker: None,
            priority: 0,
        }
    }
}

pub(crate) struct TcpSocketEntry {
    pub state: TcpSocketState,
    pub accept_queue: VecDeque<AcceptedConnection>,
    pub accept_backlog: usize,
    pub recv_payload_queue: VecDeque<PacketPayload>,
    pub recv_payload_bytes: usize,
    pub send_payload_queue: VecDeque<PacketPayload>,
    pub send_payload_bytes: usize,
    pub nodelay: bool,
    pub urgent_pending: bool,
    pub congestion_algorithm: Option<CongestionAlgorithm>,
    pub stats: TcpStats,
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
            send_payload_queue: VecDeque::new(),
            send_payload_bytes: 0,
            nodelay: false,
            urgent_pending: false,
            congestion_algorithm: None,
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
    pub const DEFAULT_BUFFER_SIZE: usize = SocketCommon::DEFAULT_BUFFER_SIZE;
    pub const MAX_BUFFER_SIZE: usize = SocketCommon::MAX_BUFFER_SIZE;
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
    pub fn set_udp_state(&mut self, state: UdpSocketState) -> SocketResult<()> {
        let Some(udp) = self.udp_mut() else {
            return Err(EndpointError::InvalidArgument);
        };
        udp.state = state;
        Ok(())
    }

    #[inline]
    pub fn set_raw_state(&mut self, state: RawSocketState) -> SocketResult<()> {
        let Some(raw) = self.raw_mut() else {
            return Err(EndpointError::InvalidArgument);
        };
        raw.state = state;
        Ok(())
    }

    #[inline]
    pub fn is_tcp_listening(&self) -> bool {
        matches!(self.tcp_state(), Some(TcpSocketState::Listening))
    }

    #[inline]
    pub fn is_tcp_connecting(&self) -> bool {
        matches!(self.tcp_state(), Some(TcpSocketState::Connecting))
    }

    #[inline]
    pub fn is_tcp_connected(&self) -> bool {
        matches!(self.tcp_state(), Some(TcpSocketState::Connected))
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
                tcp.send_payload_queue.clear();
                tcp.send_payload_bytes = 0;
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
    fn trim_empty_payloads(queue: &mut VecDeque<PacketPayload>) {
        while matches!(queue.front(), Some(payload) if payload.is_empty()) {
            queue.pop_front();
        }
    }

    fn drain_send_prefix(queue: &mut VecDeque<PacketPayload>, len: usize) -> Option<PacketPayload> {
        if len == 0 {
            return Some(PacketPayload::default());
        }

        let mut remaining = len;
        let mut taken = PacketPayload::default();

        while remaining > 0 {
            let front = queue.pop_front()?;
            let front_len = front.total_len();
            if front_len <= remaining {
                append_payload(&mut taken, front);
                remaining -= front_len;
                continue;
            }

            let (prefix, remainder) =
                crate::net::payload::split_payload_prefix_owned(front, remaining)?;
            append_payload(&mut taken, prefix);
            if !remainder.is_empty() {
                queue.push_front(remainder);
            }
            remaining = 0;
        }

        Some(taken)
    }

    #[inline]
    pub fn set_urgent_pending(&mut self, pending: bool) {
        if let Some(tcp) = self.tcp_mut() {
            tcp.urgent_pending = pending;
        }
    }

    #[inline]
    pub fn has_urgent_pending(&self) -> bool {
        self.tcp().is_some_and(|tcp| tcp.urgent_pending)
    }

    #[inline]
    pub fn recv_payload_bytes(&self) -> usize {
        self.tcp().map_or(0, |tcp| tcp.recv_payload_bytes)
    }

    #[inline]
    pub fn send_payload_bytes(&self) -> usize {
        self.tcp().map_or(0, |tcp| tcp.send_payload_bytes)
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
    pub fn recv_from_buffer(&mut self, buf: &mut [u8]) -> usize {
        let Some(tcp) = self.tcp_mut() else {
            return 0;
        };

        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);
        let Some(front) = tcp.recv_payload_queue.pop_front() else {
            return 0;
        };

        let take = front.total_len().min(buf.len());
        let Some((taken, remainder)) = crate::net::payload::split_payload_prefix_owned(front, take)
        else {
            return 0;
        };

        let view = PacketPayloadView::new(&taken);
        let mut len = 0usize;
        view.for_each_chunk(|chunk| {
            if len == take {
                return;
            }
            let chunk_len = chunk.len().min(take - len);
            buf[len..len + chunk_len].copy_from_slice(&chunk[..chunk_len]);
            len += chunk_len;
        });

        if !remainder.is_empty() {
            tcp.recv_payload_queue.push_front(remainder);
        }
        tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_sub(len);
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        if len > 0 {
            if let Some(waker) = self.send_waker.take() {
                waker.wake();
            }
        }

        len
    }

    #[inline]
    pub fn recv_payload(&mut self, max_len: Option<usize>) -> Option<PacketPayload> {
        let tcp = self.tcp_mut()?;
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        let payload = match max_len {
            Some(limit) => {
                let front = tcp.recv_payload_queue.pop_front()?;
                let take = limit.min(front.total_len());
                let (taken, remainder) =
                    crate::net::payload::split_payload_prefix_owned(front, take)?;
                if !remainder.is_empty() {
                    tcp.recv_payload_queue.push_front(remainder);
                }
                taken
            }
            None => tcp.recv_payload_queue.pop_front()?,
        };

        tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_sub(payload.total_len());
        Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

        if payload.total_len() > 0 {
            if let Some(waker) = self.send_waker.take() {
                waker.wake();
            }
        }

        Some(payload)
    }

    #[inline]
    pub fn send_payload(&mut self, payload: PacketPayload) -> SocketResult<usize> {
        let available = self
            .send_buffer_limit
            .saturating_sub(self.send_payload_bytes());

        if available == 0 {
            return Err(EndpointError::BufferFull);
        }

        let queued = if payload.total_len() > available {
            let (queued, _) = crate::net::payload::split_payload_prefix_owned(payload, available)
                .ok_or(EndpointError::BufferFull)?;
            queued
        } else {
            payload
        };

        let len = queued.total_len();
        let Some(tcp) = self.tcp_mut() else {
            return Err(EndpointError::InvalidArgument);
        };
        tcp.send_payload_bytes = tcp.send_payload_bytes.saturating_add(len);
        tcp.send_payload_queue.push_back(queued);
        Ok(len)
    }

    #[inline]
    pub fn take_send_payload_prefix(&mut self, len: usize) -> Option<PacketPayload> {
        let tcp = self.tcp_mut()?;
        let taken = Self::drain_send_prefix(&mut tcp.send_payload_queue, len)?;
        tcp.send_payload_bytes = tcp.send_payload_bytes.saturating_sub(taken.total_len());
        Self::trim_empty_payloads(&mut tcp.send_payload_queue);
        Some(taken)
    }

    #[inline]
    pub fn push_send_payload_front(&mut self, payload: PacketPayload) {
        let len = payload.total_len();
        if let Some(tcp) = self.tcp_mut() {
            tcp.send_payload_bytes = tcp.send_payload_bytes.saturating_add(len);
            tcp.send_payload_queue.push_front(payload);
        }
    }

    #[inline]
    pub fn peek_send_byte(&self) -> Option<u8> {
        let tcp = self.tcp()?;
        let payload = tcp.send_payload_queue.front()?;
        PacketPayloadView::new(payload).first_byte()
    }

    #[inline]
    pub fn clear_tcp_payload_queues(&mut self) {
        if let Some(tcp) = self.tcp_mut() {
            tcp.recv_payload_queue.clear();
            tcp.recv_payload_bytes = 0;
            tcp.send_payload_queue.clear();
            tcp.send_payload_bytes = 0;
        }
    }

    #[inline]
    pub fn push_recv_payload(&mut self, payload: PacketPayload) -> usize {
        let available = self
            .recv_buffer_limit
            .saturating_sub(self.recv_payload_bytes());
        if available == 0 {
            return 0;
        }

        let queued = if payload.total_len() > available {
            match crate::net::payload::split_payload_prefix_owned(payload, available) {
                Some((payload, _)) => payload,
                None => return 0,
            }
        } else {
            payload
        };

        let len = queued.total_len();
        if len > 0 {
            let Some(tcp) = self.tcp_mut() else {
                return 0;
            };
            tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_add(len);
            tcp.recv_payload_queue.push_back(queued);
            Self::trim_empty_payloads(&mut tcp.recv_payload_queue);

            if let Some(waker) = self.recv_waker.take() {
                waker.wake();
            }
        }
        len
    }

    #[inline]
    pub fn notify_connected(&mut self) {
        if let Some(waker) = self.connect_waker.take() {
            waker.wake();
        }
    }
}
