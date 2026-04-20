// ============================================================================
// kernel/src/net/l4/socket/entry.rs - L4 / ソケット / エントリ
// ============================================================================
//! Shared socket handle backed by `Arc<PoisonLock<SocketState>>`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::net::datapath::mempool::PacketRef;
use crate::net::l4::types::{EndpointAddr, EndpointError, NEXT_SOCKET_ID, SocketId, SocketResult};
use crate::net::payload::split_payload_prefix_owned;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{
    RuntimeCommand, TransportCommand, enqueue_command_ignore_in, enqueue_command_in,
};
use crate::net::runtime::manager::NetIfId;
use crate::sync::poison_lock::PoisonLock;
use kernel_api::resource::net::PacketPayload;

use super::registry::SOCKET_REGISTRY;
use super::state::{SocketState, TcpSocketState};

fn register_socket(socket: &Socket) {
    if let Some(registry) = &*SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner()) {
        registry.register(socket.clone());
    }
}

pub struct Socket {
    socket_id: SocketId,
    runtime: NetRuntimeHandle,
    inner: Arc<PoisonLock<SocketState>>,
}

impl Socket {
    fn next_socket_id() -> SocketId {
        SocketId::from_raw(NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed))
    }

    fn notify_tcb_data_received(
        local: Option<EndpointAddr>,
        remote: Option<EndpointAddr>,
        pushed: usize,
    ) {
        if pushed == 0 {
            return;
        }

        if let (Some(local), Some(remote)) = (local, remote) {
            let _ = crate::net::l4::tcp::tcb::tcb_table().lookup_mut(local, remote, |tcb| {
                tcb.on_data_received(pushed as u32);
            });
        }
    }

    fn split_and_queue_payload(
        inner: &mut SocketState,
        payload: PacketPayload,
    ) -> (usize, Option<PacketPayload>) {
        let available = inner
            .recv_buffer_limit
            .saturating_sub(inner.recv_payload_bytes());
        if available == 0 {
            return (0, Some(payload));
        }

        let payload_len = payload.total_len();
        let (queued, remainder) = if payload_len > available {
            let Some((queued, remainder)) = split_payload_prefix_owned(payload, available) else {
                return (0, None);
            };
            (queued, (!remainder.is_empty()).then_some(remainder))
        } else {
            (payload, None)
        };

        let pushed = queued.total_len();
        if pushed > 0 {
            let Some(tcp) = inner.tcp_mut() else {
                return (0, Some(queued));
            };
            tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_add(pushed);
            tcp.recv_payload_queue.push_back(queued);
            while matches!(tcp.recv_payload_queue.front(), Some(segment) if segment.is_empty()) {
                tcp.recv_payload_queue.pop_front();
            }
        }

        (pushed, remainder)
    }

    pub fn new_tcp_in(runtime: NetRuntimeHandle, state: TcpSocketState) -> Self {
        Self {
            socket_id: Self::next_socket_id(),
            runtime,
            inner: Arc::new(PoisonLock::new(SocketState::new_tcp(state))),
        }
    }

    pub(crate) fn new_registered_tcp_in(runtime: NetRuntimeHandle, state: TcpSocketState) -> Self {
        let socket = Self::new_tcp_in(runtime, state);
        register_socket(&socket);
        socket
    }

    pub fn new_tcp_with_socket_id_in(
        socket_id: SocketId,
        runtime: NetRuntimeHandle,
        state: TcpSocketState,
    ) -> Self {
        Self {
            socket_id,
            runtime,
            inner: Arc::new(PoisonLock::new(SocketState::new_tcp(state))),
        }
    }

    pub fn new_udp_in(runtime: NetRuntimeHandle) -> Self {
        Self {
            socket_id: Self::next_socket_id(),
            runtime,
            inner: Arc::new(PoisonLock::new(SocketState::new_udp())),
        }
    }

    pub(crate) fn new_registered_udp_in(runtime: NetRuntimeHandle) -> Self {
        let socket = Self::new_udp_in(runtime);
        register_socket(&socket);
        socket
    }

    pub fn new_raw_in(runtime: NetRuntimeHandle) -> Self {
        Self {
            socket_id: Self::next_socket_id(),
            runtime,
            inner: Arc::new(PoisonLock::new(SocketState::new_raw())),
        }
    }

    pub(crate) fn new_registered_raw_in(runtime: NetRuntimeHandle) -> Self {
        let socket = Self::new_raw_in(runtime);
        register_socket(&socket);
        socket
    }

    #[inline(always)]
    pub const fn socket_id(&self) -> SocketId {
        self.socket_id
    }

    #[inline(always)]
    pub const fn runtime(&self) -> NetRuntimeHandle {
        self.runtime
    }

    #[inline]
    pub fn inner(&self) -> &Arc<PoisonLock<SocketState>> {
        &self.inner
    }

    #[inline]
    pub fn is_tcp(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_tcp()
    }

    #[inline]
    pub fn is_udp(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_udp()
    }

    #[inline]
    pub fn is_raw(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_raw()
    }

    #[inline]
    pub fn local_addr(&self) -> Option<EndpointAddr> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .local_addr
    }

    #[inline]
    pub fn remote_addr(&self) -> Option<EndpointAddr> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remote_addr
    }

    pub fn try_next_incoming(&self) -> SocketResult<(Socket, EndpointAddr, NetIfId)> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.is_tcp_listening() {
            return Err(EndpointError::InvalidStateTransition);
        }

        if let Some(conn) = inner.tcp_mut().and_then(|tcp| tcp.accept_queue.pop_front()) {
            let socket = Self::new_tcp_with_socket_id_in(
                conn.socket_id,
                self.runtime,
                TcpSocketState::Connected,
            );
            {
                let mut new_inner = socket.inner.lock().unwrap_or_else(|e| e.into_inner());
                new_inner.local_addr = Some(conn.local_addr);
                new_inner.remote_addr = Some(conn.remote_addr);
                new_inner.scope = crate::net::types::InterfaceScope::Pinned(conn.if_id);
                new_inner.last_ingress_if_id = Some(conn.if_id);
                if let Some(new_tcp) = new_inner.tcp_mut() {
                    new_tcp.nodelay = inner.tcp().is_some_and(|tcp| tcp.nodelay);
                }
                new_inner.priority = inner.priority;
            }

            register_socket(&socket);
            return Ok((socket, conn.remote_addr, conn.if_id));
        }

        Err(EndpointError::Timeout)
    }

    pub fn register_accept_waker(&self, waker: core::task::Waker) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accept_waker = Some(waker);
    }

    pub fn register_recv_waker(&self, waker: core::task::Waker) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_waker = Some(waker);
    }

    pub fn try_recv(&self, buf: &mut [u8]) -> SocketResult<usize> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !matches!(
            inner.tcp_state(),
            Some(TcpSocketState::Connected | TcpSocketState::Closing)
        ) {
            return Err(EndpointError::NotConnected);
        }

        let len = inner.recv_from_buffer(buf);
        if len > 0 {
            Ok(len)
        } else {
            Err(EndpointError::Timeout)
        }
    }

    pub fn push_payload(&self, payload: PacketPayload) -> usize {
        let (pushed, local, remote, waker) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let pushed = inner.push_recv_payload(payload);
            let local = inner.local_addr;
            let remote = inner.remote_addr;
            if pushed > 0 {
                if let Some(tcp) = inner.tcp_mut() {
                    tcp.stats.record_rx_segment(pushed);
                }
            }
            (pushed, local, remote, inner.recv_waker.take())
        };

        Self::notify_tcb_data_received(local, remote, pushed);
        if let Some(waker) = waker {
            waker.wake();
        }
        pushed
    }

    pub fn push_payload_with_remainder(
        &self,
        payload: PacketPayload,
    ) -> (usize, Option<PacketPayload>) {
        let (pushed, remainder, local, remote, waker) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let (pushed, remainder) = Self::split_and_queue_payload(&mut inner, payload);
            (
                pushed,
                remainder,
                inner.local_addr,
                inner.remote_addr,
                inner.recv_waker.take(),
            )
        };

        Self::notify_tcb_data_received(local, remote, pushed);
        if let Some(waker) = waker {
            waker.wake();
        }

        (pushed, remainder)
    }

    pub fn deliver_udp_packet(
        &self,
        if_id: NetIfId,
        addr: EndpointAddr,
        ttl: u8,
        packet: PacketRef,
    ) -> SocketResult<()> {
        self.deliver_udp_payload(if_id, addr, ttl, PacketPayload::single(packet))
    }

    pub fn deliver_udp_payload(
        &self,
        if_id: NetIfId,
        addr: EndpointAddr,
        ttl: u8,
        payload: PacketPayload,
    ) -> SocketResult<()> {
        let recv_waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.is_udp_bound() {
                return Err(EndpointError::NotConnected);
            }
            inner.last_ingress_if_id = Some(if_id);
            let Some(udp) = inner.udp_mut() else {
                return Err(EndpointError::InvalidArgument);
            };
            udp.ttl = ttl;
            udp.pending_packets.push_back((if_id, addr, ttl, payload));
            inner.recv_waker.take()
        };

        if let Some(waker) = recv_waker {
            waker.wake();
        }
        Ok(())
    }

    pub fn try_recv_raw_payload(&self) -> SocketResult<(PacketPayload, NetIfId)> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.is_raw_open() {
            return Err(EndpointError::NotConnected);
        }

        if let Some((if_id, payload)) = inner
            .raw_mut()
            .and_then(|raw| raw.pending_payloads.pop_front())
        {
            inner.last_ingress_if_id = Some(if_id);
            return Ok((payload, if_id));
        }

        Err(EndpointError::Timeout)
    }

    pub fn deliver_raw_payload(&self, if_id: NetIfId, payload: PacketPayload) -> SocketResult<()> {
        let recv_waker = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.is_raw_open() {
                return Err(EndpointError::NotConnected);
            }
            inner.last_ingress_if_id = Some(if_id);
            let Some(raw) = inner.raw_mut() else {
                return Err(EndpointError::InvalidArgument);
            };
            raw.pending_payloads.push_back((if_id, payload));
            inner.recv_waker.take()
        };

        if let Some(waker) = recv_waker {
            waker.wake();
        }
        Ok(())
    }

    pub fn try_recv_udp_payload(&self) -> SocketResult<(NetIfId, EndpointAddr, u8, PacketPayload)> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.is_udp_bound() {
            return Err(EndpointError::NotConnected);
        }

        if let Some((if_id, addr, ttl, payload)) = inner
            .udp_mut()
            .and_then(|udp| udp.pending_packets.pop_front())
        {
            inner.last_ingress_if_id = Some(if_id);
            return Ok((if_id, addr, ttl, payload));
        }

        Err(EndpointError::Timeout)
    }

    pub(crate) fn close_immediate(&self) -> SocketResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.mark_closed();

            if let Some(waker) = inner.recv_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.send_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.connect_waker.take() {
                waker.wake();
            }
            if let Some(waker) = inner.accept_waker.take() {
                waker.wake();
            }
        }

        enqueue_command_ignore_in(
            self.runtime,
            RuntimeCommand::Transport(TransportCommand::CloseSocket {
                socket_id: self.socket_id,
            }),
        );
        Ok(())
    }

    pub fn set_nodelay(&self, nodelay: bool) -> SocketResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let Some(tcp) = inner.tcp_mut() else {
                return Err(EndpointError::InvalidArgument);
            };
            tcp.nodelay = nodelay;
        }

        enqueue_command_in(
            self.runtime,
            RuntimeCommand::Transport(TransportCommand::SetTcpNoDelay {
                socket_id: self.socket_id,
                nodelay,
            }),
        )
    }

    pub fn set_priority(&self, priority: u8) -> SocketResult<()> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.priority = priority & 0x3F;
        }

        enqueue_command_in(
            self.runtime,
            RuntimeCommand::Transport(TransportCommand::SetSocketPriority {
                socket_id: self.socket_id,
                priority: priority & 0x3F,
            }),
        )
    }
}

impl Clone for Socket {
    fn clone(&self) -> Self {
        Self {
            socket_id: self.socket_id,
            runtime: self.runtime,
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::net::l4::socket::registry::init_socket_registry;
    use crate::net::runtime::default_runtime;

    #[cfg_attr(test, test_case)]
    pub fn test_new_registered_tcp_socket_registers_socket() {
        init_socket_registry();
        let socket = Socket::new_registered_tcp_in(default_runtime(), TcpSocketState::Connected);
        let registry = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
        assert!(
            registry
                .as_ref()
                .and_then(|it| it.get(socket.socket_id()))
                .is_some()
        );
    }
}
