//! # Endpoint Module - SPL/SAS Compliant Network Socket Implementation
//!
//! ## Design Philosophy
//! - Fine-grained locking: Arc<Mutex<SocketInner>> for per-socket locking
//! - RAII resource management: OwnedSocket for automatic close
//! - O(1) buffer operations: VecDeque for FIFO efficiency
//! - Read parallelization: RwLock for SocketManager concurrent reads
//! - State transition guards: Compile-time detection of invalid transitions
//! - Event-driven: NetworkEvent for protocol stack coordination

// Sub-module declarations
pub mod types;
pub mod event;
pub mod inner;
pub mod tcb;
pub mod retransmit;
pub mod segment;
pub mod manager;
pub mod socket;
pub mod futures;
pub mod handler;
pub mod tcp_rx;
#[cfg(test)]
mod tests;

// Re-exports: types
pub use types::{
    SocketFd, SocketType, SocketState, SocketError, SocketResult,
    SocketAddr, AcceptedConnection, NEXT_FD,
};

// Re-exports: event
pub use event::{
    NetworkEvent, NetworkEventQueue, EventWaitFuture,
    event_queue, send_event, send_event_ignore,
};

// Re-exports: inner
pub use inner::SocketInner;

// Re-exports: tcb
pub use tcb::{
    tcp_flags, TcpConnectionState, TcpControlBlockEntry, TcbTable,
    tcb_table, TCB_TABLE,
};

// Re-exports: retransmit
pub use retransmit::{
    UnackedSegment, RtoCalculator, RetransmitQueue,
    get_or_create_retransmit_queue, retransmit_queue_push,
    retransmit_queue_ack, retransmit_queue_remove,
    check_retransmit_timeouts,
};

// Re-exports: segment
pub use segment::{TcpSegmentBuilder, send_tcp_segment};

// Re-exports: manager
pub use manager::{
    SocketManager, SOCKET_MANAGER,
    init_socket_manager, socket_manager,
};

// Re-exports: socket
pub use socket::{
    Socket, OwnedSocket,
    create_tcp_socket, create_udp_socket, create_raw_socket,
    create_tcp_server, tcp_connect, udp_bind,
};

// Re-exports: futures
pub use futures::{
    RecvFuture, SendFuture, AcceptFuture, RecvFromFuture,
};

// Re-exports: handler
pub use handler::{
    EventHandleResult, NetworkEventHandler,
    init_network_event_handler,
};

// Re-exports: tcp_rx
pub use tcp_rx::{
    process_tcp_segment, network_event_task,
};