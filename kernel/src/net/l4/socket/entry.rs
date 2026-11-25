// ============================================================================
// kernel/src/net/l4/socket/entry.rs - L4 / ソケット / エントリ
// ============================================================================
//! Socket value handle backed by registry-owned socket state.

use core::task::{Poll, Waker};

use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId, SocketResult};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::command::{RuntimeCommand, TransportCommand, try_enqueue_command_in};
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;
use kernel_api::resource::net::PacketPayload;

use super::state::{QueuedPayload, ReceivedDatagram, SocketState, TcpSocketState};

fn register_socket(socket: Socket, state: SocketState) {
    if socket
        .runtime
        .context()
        .sockets
        .register(socket, state)
        .is_err()
    {
        log::error!(
            "[NET] socket registry capacity exhausted while registering {:?}",
            socket.socket_id()
        );
    }
}

#[derive(Clone, Copy)]
pub struct Socket {
    socket_id: SocketId,
    runtime: NetRuntimeHandle,
}

impl Socket {
    fn next_socket_id_in(runtime: NetRuntimeHandle) -> SocketId {
        runtime
            .context()
            .sockets
            .generate_socket_id()
            .expect("socket id space exhausted")
    }

    pub(crate) const fn from_registered(socket_id: SocketId, runtime: NetRuntimeHandle) -> Self {
        Self { socket_id, runtime }
    }

    fn notify_tcb_data_received(runtime: NetRuntimeHandle, socket_id: SocketId, pushed: usize) {
        if pushed == 0 {
            return;
        }

        let _ = tcp_table_in(runtime).record_data_received_by_socket_id(socket_id, pushed as u32);
    }

    pub(in crate::net::l4) fn queue_tcp_receive(
        &self,
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
        if payload_len > available {
            return (0, Some(payload));
        }

        let queued = payload;
        let remainder = None;

        let pushed = queued.total_len();
        if pushed > 0 {
            let Some(retention) = super::retention_budget_in(self.runtime).try_charge(&queued)
            else {
                return (0, Some(queued));
            };
            let Some(tcp) = inner.tcp_mut() else {
                return (0, Some(queued));
            };
            tcp.recv_payload_bytes = tcp.recv_payload_bytes.saturating_add(pushed);
            tcp.recv_payload_queue
                .push_back(QueuedPayload::received(queued, retention));
            // LOOP_PROOF: mode=condition; reason=Each iteration removes one empty front segment from the exclusively borrowed receive deque until a nonempty segment or end.;
            while matches!(tcp.recv_payload_queue.front(), Some(segment) if segment.is_empty()) {
                tcp.recv_payload_queue.pop_front();
            }
        }

        (pushed, remainder)
    }

    pub fn new_tcp_in(runtime: NetRuntimeHandle, state: TcpSocketState) -> Self {
        let socket = Self::from_registered(Self::next_socket_id_in(runtime), runtime);
        register_socket(socket, SocketState::new_tcp(state));
        socket
    }

    pub(crate) fn new_registered_tcp_in(runtime: NetRuntimeHandle, state: TcpSocketState) -> Self {
        Self::new_tcp_in(runtime, state)
    }

    pub fn new_udp_in(runtime: NetRuntimeHandle) -> Self {
        let socket = Self::from_registered(Self::next_socket_id_in(runtime), runtime);
        register_socket(socket, SocketState::new_udp());
        socket
    }

    pub fn new_raw_in(runtime: NetRuntimeHandle) -> Self {
        let socket = Self::from_registered(Self::next_socket_id_in(runtime), runtime);
        register_socket(socket, SocketState::new_raw());
        socket
    }

    pub(crate) fn new_registered_raw_in(runtime: NetRuntimeHandle) -> Self {
        Self::new_raw_in(runtime)
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
    pub(crate) fn with_inner<R>(&self, f: impl FnOnce(&SocketState) -> R) -> Option<R> {
        self.runtime
            .context()
            .sockets
            .with_socket_state(self.socket_id, f)
    }

    #[inline]
    pub(crate) fn with_inner_mut<R>(&self, f: impl FnOnce(&mut SocketState) -> R) -> Option<R> {
        self.runtime
            .context()
            .sockets
            .with_socket_state_mut(self.socket_id, f)
    }

    #[inline]
    pub fn is_tcp(&self) -> bool {
        self.with_inner(SocketState::is_tcp).unwrap_or(false)
    }

    #[inline]
    pub fn is_udp(&self) -> bool {
        self.with_inner(SocketState::is_udp).unwrap_or(false)
    }

    #[inline]
    pub fn local_addr(&self) -> Option<EndpointAddr> {
        self.with_inner(|inner| inner.local_addr).flatten()
    }

    #[inline]
    pub fn remote_addr(&self) -> Option<EndpointAddr> {
        self.with_inner(|inner| inner.remote_addr).flatten()
    }

    pub(crate) fn prepare_passive_child(
        &self,
        local: EndpointAddr,
        remote: EndpointAddr,
        if_id: NetIfId,
    ) -> SocketResult<Self> {
        let (nodelay, priority) = self
            .with_inner(|inner| {
                let tcp = inner
                    .tcp()
                    .filter(|tcp| tcp.state == TcpSocketState::Listening)
                    .ok_or(EndpointError::InvalidStateTransition)?;
                if tcp.accept_queue.len() >= tcp.accept_backlog {
                    return Err(EndpointError::BufferFull);
                }
                Ok((tcp.nodelay, inner.priority))
            })
            .ok_or(EndpointError::NotFound)??;
        let registry = &self.runtime.context().sockets;
        let id = registry
            .generate_socket_id()
            .ok_or(EndpointError::ResourceExhausted)?;
        let mut state = SocketState::new_tcp(TcpSocketState::AwaitingAccept {
            listener: self.socket_id,
        });
        state.local_addr = Some(local);
        state.remote_addr = Some(remote);
        state.scope = crate::net::types::InterfaceScope::Pinned(if_id);
        state.priority = priority;
        if let Some(tcp) = state.tcp_mut() {
            tcp.nodelay = nodelay;
        }
        let child = Self::from_registered(id, self.runtime);
        registry.register(child, state)?;
        Ok(child)
    }

    pub(crate) fn publish_passive_child(&self, child: Self) -> SocketResult<()> {
        self.runtime
            .context()
            .sockets
            .publish_tcp_accept(self.socket_id, child.socket_id)
    }

    pub(crate) fn poll_accept(&self, waker: &Waker) -> Poll<SocketResult<(Self, EndpointAddr)>> {
        self.runtime
            .context()
            .sockets
            .poll_tcp_accept(self.socket_id, waker)
    }

    pub fn register_recv_waker(&self, waker: &core::task::Waker) {
        let _ = self.with_inner_mut(|inner| {
            inner.recv_waker.register(waker);
        });
    }

    pub fn push_payload(&self, payload: PacketPayload) -> usize {
        let Some(retention) = super::retention_budget_in(self.runtime).try_charge(&payload) else {
            return 0;
        };
        let Some(pushed) = self.with_inner_mut(|inner| {
            let pushed = inner.push_recv_payload(payload, retention);
            if pushed > 0
                && let Some(tcp) = inner.tcp_mut()
            {
                tcp.stats.record_rx_segment(pushed);
            }
            if pushed > 0 {
                Self::notify_tcb_data_received(self.runtime, self.socket_id, pushed);
                inner.recv_waker.wake();
            }
            pushed
        }) else {
            return 0;
        };

        pushed
    }

    pub fn try_push_payload(&self, payload: PacketPayload) -> Result<usize, PacketPayload> {
        let mut owner = Some(payload);
        let result = self.with_inner_mut(|inner| {
            let payload = owner.take().expect("TCP receive payload owner is present");
            let (pushed, remainder) = self.queue_tcp_receive(inner, payload);
            if let Some(remainder) = remainder {
                return Err(remainder);
            }
            if pushed > 0 {
                if let Some(tcp) = inner.tcp_mut() {
                    tcp.stats.record_rx_segment(pushed);
                }
                Self::notify_tcb_data_received(self.runtime, self.socket_id, pushed);
                inner.recv_waker.wake();
            }
            Ok(pushed)
        });
        match result {
            Some(result) => result,
            None => Err(owner.expect("missing socket preserves the payload owner")),
        }
    }

    pub fn deliver_udp_payload(
        &self,
        if_id: NetIfId,
        addr: EndpointAddr,
        ttl: u8,
        payload: PacketPayload,
    ) -> Result<(), (EndpointError, PacketPayload)> {
        let Some(retention) = super::retention_budget_in(self.runtime).try_charge(&payload) else {
            return Err((EndpointError::BufferFull, payload));
        };
        let mut owner = Some(payload);
        let mut charge = Some(retention);
        let result = self
            .with_inner_mut(|inner| {
                if !inner.is_udp_bound() {
                    return Err(EndpointError::NotConnected);
                }
                let Some(udp) = inner.udp_mut() else {
                    return Err(EndpointError::InvalidArgument);
                };
                udp.ttl = ttl;
                udp.pending_packets.push_back(ReceivedDatagram {
                    if_id,
                    source: addr,
                    ttl,
                    payload: owner.take().expect("accepted UDP payload owner is present"),
                    _retention: charge
                        .take()
                        .expect("accepted UDP payload charge is present"),
                });
                inner.recv_waker.wake();
                Ok(())
            })
            .unwrap_or(Err(EndpointError::NotFound));
        result.map_err(|error| {
            (
                error,
                owner.expect("rejected UDP delivery preserves the payload owner"),
            )
        })
    }

    pub fn try_recv_raw_payload(&self) -> SocketResult<(PacketPayload, NetIfId)> {
        self.with_inner_mut(|inner| {
            if !inner.is_raw_open() {
                return Err(EndpointError::NotConnected);
            }

            if let Some((if_id, payload, _retention)) = inner
                .raw_mut()
                .and_then(|raw| raw.pending_payloads.pop_front())
            {
                return Ok((payload, if_id));
            }

            Err(EndpointError::Timeout)
        })
        .unwrap_or(Err(EndpointError::NotFound))
    }

    pub fn deliver_raw_payload(&self, if_id: NetIfId, payload: PacketPayload) -> SocketResult<()> {
        let retention = super::retention_budget_in(self.runtime)
            .try_charge(&payload)
            .ok_or(EndpointError::BufferFull)?;
        self.with_inner_mut(|inner| {
            if !inner.is_raw_open() {
                return Err(EndpointError::NotConnected);
            }
            let Some(raw) = inner.raw_mut() else {
                return Err(EndpointError::InvalidArgument);
            };
            raw.pending_payloads.push_back((if_id, payload, retention));
            inner.recv_waker.wake();
            Ok(())
        })
        .unwrap_or(Err(EndpointError::NotFound))?;
        Ok(())
    }

    pub fn try_recv_udp_payload(&self) -> SocketResult<(NetIfId, EndpointAddr, u8, PacketPayload)> {
        self.with_inner_mut(|inner| {
            if !inner.is_udp_bound() {
                return Err(EndpointError::NotConnected);
            }

            if let Some(datagram) = inner
                .udp_mut()
                .and_then(|udp| udp.pending_packets.pop_front())
            {
                return Ok((
                    datagram.if_id,
                    datagram.source,
                    datagram.ttl,
                    datagram.payload,
                ));
            }

            Err(EndpointError::Timeout)
        })
        .unwrap_or(Err(EndpointError::NotFound))
    }

    pub(crate) fn close_immediate(&self) -> SocketResult<()> {
        let _ = self.with_inner_mut(|inner| {
            inner.mark_closed();

            inner.recv_waker.wake();
            inner.send_waker.wake();
            inner.connect_waker.wake();
            inner.accept_waker.wake();
        });

        try_enqueue_command_in(
            self.runtime,
            RuntimeCommand::Transport(TransportCommand::CloseSocket {
                socket_id: self.socket_id,
            }),
        )
        .map_err(|_| EndpointError::BufferFull)?;
        Ok(())
    }
}
