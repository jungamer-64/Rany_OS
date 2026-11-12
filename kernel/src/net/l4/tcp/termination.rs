// ============================================================================
// kernel/src/net/l4/tcp/termination.rs - L4 / TCP / 接続終了
// ============================================================================
//! TCP connection termination.
//!
//! A TCB ends on exactly one path: the one that removes it from the TCB table.
//! That path finishes the connection here, releasing its retransmit queue and
//! settling its socket by the ownership recorded in the socket state (see
//! `TcpSocketState`). Out-of-order permits and queued payloads are owned by the
//! TCB and return when the removed TCB is dropped.

use super::retransmit::retransmit_queue_remove;
use super::segment::TcpSegmentBuilder;
use super::tcb::{TcpConnectionState, TcpControlBlock, TcpControlBlockSnapshot};
use crate::net::l4::socket::{
    TcpConnectionEnd, TcpSocketState, lookup_socket_in, unregister_socket_in,
};
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::transport::tcp_table_in;

/// How a connection reached CLOSED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpTermination {
    /// The close sequence finished: our FIN was acknowledged in LAST-ACK, or
    /// TIME-WAIT / FIN-WAIT-2 expired.
    Completed,
    /// The peer reset a connection that had not completed its handshake.
    Refused,
    /// The peer reset a synchronized connection.
    Reset,
    /// Retransmission or the handshake gave up.
    TimedOut,
}

impl TcpTermination {
    const fn socket_error(self) -> Option<EndpointError> {
        match self {
            Self::Completed => None,
            Self::Refused => Some(EndpointError::ConnectionRefused),
            Self::Reset => Some(EndpointError::ConnectionReset),
            Self::TimedOut => Some(EndpointError::Timeout),
        }
    }
}

/// End the connection identified by its flow key. Returns false when another
/// path already removed the TCB.
pub(crate) fn terminate_connection_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    local: EndpointAddr,
    remote: EndpointAddr,
    termination: TcpTermination,
) -> bool {
    let Some(removed) = tcp_table_in(runtime).remove(if_id, local, remote) else {
        return false;
    };
    finish_connection_in(runtime, removed, termination);
    true
}

/// Finish a TCB the caller has removed from the table.
pub(crate) fn finish_connection_in(
    runtime: NetRuntimeHandle,
    removed: TcpControlBlock,
    termination: TcpTermination,
) {
    let tcb = TcpControlBlockSnapshot::from(&removed);
    drop(removed);
    retransmit_queue_remove(runtime, tcb.if_id, tcb.local, tcb.remote);
    settle_socket_in(runtime, tcb.socket_id, termination);
}

fn settle_socket_in(runtime: NetRuntimeHandle, socket_id: SocketId, termination: TcpTermination) {
    let Some(socket) = lookup_socket_in(runtime, socket_id) else {
        return;
    };
    let end = socket
        .with_inner_mut(|inner| inner.end_tcp_connection(termination.socket_error()))
        .unwrap_or(TcpConnectionEnd::NotConnection);
    if end == TcpConnectionEnd::Unregister {
        let _ = unregister_socket_in(runtime, socket_id);
    }
}

/// RFC 9293 Section 3.10.5 ABORT: a reset is sent from SYN-RECEIVED and the
/// states in which the peer may still send to us; CLOSING, LAST-ACK and
/// TIME-WAIT have no data left to reject and SYN-SENT has no peer state.
const fn abort_resets_peer(state: TcpConnectionState) -> bool {
    matches!(
        state,
        TcpConnectionState::SynReceived
            | TcpConnectionState::Established
            | TcpConnectionState::FinWait1
            | TcpConnectionState::FinWait2
            | TcpConnectionState::CloseWait
    )
}

/// Abort a TCB the caller has removed and whose socket the caller owns.
/// The reset `<SEQ=SND.NXT><CTL=RST>` is best effort: a segment that cannot
/// be built or queued leaves the peer to time out.
pub(crate) fn abort_connection_in(runtime: NetRuntimeHandle, removed: TcpControlBlock) {
    let tcb = TcpControlBlockSnapshot::from(&removed);
    drop(removed);
    retransmit_queue_remove(runtime, tcb.if_id, tcb.local, tcb.remote);
    if abort_resets_peer(tcb.state) {
        let reset = TcpSegmentBuilder::new(tcb.local.port(), tcb.remote.port())
            .seq(tcb.snd_nxt)
            .rst();
        super::tcp_rx::send_control_segment(runtime, tcb.if_id, tcb.local, tcb.remote, reset);
    }
}

/// Abort every TCB bound to `socket_id`: the connection of a connection
/// socket, or the embryonic passive opens of a listener.
pub(crate) fn abort_socket_connections_in(runtime: NetRuntimeHandle, socket_id: SocketId) {
    // LOOP_PROOF: mode=condition; reason=Each iteration removes one TCB bound to the socket id from the finite TCB table and stops when none remains.;
    while let Some(removed) = tcp_table_in(runtime).remove_by_socket_id(socket_id) {
        abort_connection_in(runtime, removed);
    }
}

/// Release a connection socket whose application handle is dropped without a
/// graceful close: the connection is aborted and the socket unregistered.
pub(crate) fn abort_connection_handle_in(runtime: NetRuntimeHandle, socket_id: SocketId) {
    if let Some(socket) = lookup_socket_in(runtime, socket_id) {
        // Closing the socket first leaves its unregistration to this handle
        // when a runtime path ends the TCB concurrently.
        let _ = socket.with_inner_mut(|inner| inner.end_tcp_connection(None));
    }
    abort_socket_connections_in(runtime, socket_id);
    let _ = unregister_socket_in(runtime, socket_id);
}

/// Release a listener: admission stops, every connection waiting in the
/// accept queue and every embryonic passive open is aborted, and the socket
/// is unregistered.
pub(crate) fn close_listener_in(runtime: NetRuntimeHandle, socket_id: SocketId) {
    let queued = lookup_socket_in(runtime, socket_id)
        .and_then(|socket| {
            socket.with_inner_mut(|inner| {
                let queued = inner
                    .tcp_mut()
                    .map(|tcp| core::mem::take(&mut tcp.accept_queue))
                    .unwrap_or_default();
                if inner.tcp().is_some() {
                    let _ = inner.set_tcp_state(TcpSocketState::Closed);
                }
                inner.accept_waker.wake();
                queued
            })
        })
        .unwrap_or_default();
    for connection in queued {
        if let Some(removed) = tcp_table_in(runtime).remove(
            connection.if_id,
            connection.local_addr,
            connection.remote_addr,
        ) {
            abort_connection_in(runtime, removed);
        }
    }
    abort_socket_connections_in(runtime, socket_id);
    let _ = unregister_socket_in(runtime, socket_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub fn abort_resets_peer_only_where_rfc_9293_sends_reset() {
        use TcpConnectionState::*;
        for state in [SynReceived, Established, FinWait1, FinWait2, CloseWait] {
            assert!(abort_resets_peer(state), "{state:?}");
        }
        for state in [Closed, Listen, SynSent, Closing, LastAck, TimeWait] {
            assert!(!abort_resets_peer(state), "{state:?}");
        }
    }
}
