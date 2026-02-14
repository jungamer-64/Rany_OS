// ============================================================================
// kernel/src/net/endpoint.rs
// ============================================================================
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
pub mod congestion;
pub mod event;
pub mod flow_control;
pub mod futures;
pub mod handler;
pub mod inner;
pub mod manager;
pub mod retransmit;
pub mod segment;
pub mod socket;
pub mod tcb;
pub mod tcp_rx;
#[cfg(test)]
mod tests;
pub mod types;
pub mod window_scale;

// Re-exports: types
pub use types::{
    AcceptedConnection, SocketAddr, SocketError, SocketFd, SocketResult, SocketState, SocketType,
};

// Re-exports: event
pub use event::{EventWaitFuture, NetworkEvent, NetworkEventQueue, event_queue};

// Re-exports: inner

// Re-exports: tcb
pub use tcb::{TcbTable, TcpConnectionSnapshot, TcpConnectionState, TcpControlBlockEntry, tcb_table, tcp_flags};

// Re-exports: retransmit
pub use retransmit::{
    RetransmitQueue, RtoCalculator, UnackedSegment, check_retransmit_timeouts,
    get_or_create_retransmit_queue, retransmit_queue_ack, retransmit_queue_push,
    retransmit_queue_remove,
};

// Re-exports: segment
pub use segment::{TcpSegmentBuilder, send_tcp_segment};

// Re-exports: manager
pub use manager::{SocketManager, init_socket_manager, socket_manager};

// Re-exports: socket
pub use socket::{
    OwnedSocket, Socket, create_tcp_server, create_tcp_socket, create_tcp_socket_with_algorithm,
    create_udp_socket, open_tcp_connection, create_raw_socket,
};

// Re-exports: futures
pub use futures::{AcceptFuture, RecvFromFuture, RecvFuture, SendFuture};

// Re-exports: handler
pub use handler::{EventHandleResult, NetworkEventHandler, init_network_event_handler};

// Re-exports: tcp_rx
pub use tcp_rx::{network_event_task, process_tcp_segment};

// Re-exports: congestion
pub use congestion::{
    BbrController, BbrState, CongestionAlgorithm, CongestionController,
    CongestionControllerVariant, CongestionState, CubicController, DEFAULT_MSS, INITIAL_WINDOW,
    MIN_CWND,
};

// Re-exports: window_scale
pub use window_scale::{
    TcpOptionBuilder, TcpOptionParser, WindowScaleOption, TimestampsOption, SackOption,
    tcp_option_kind, MAX_WINDOW_SCALE, DEFAULT_WINDOW_SCALE,
};

// Re-exports: flow_control
