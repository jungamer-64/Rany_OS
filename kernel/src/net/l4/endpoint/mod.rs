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
pub mod ooo_queue;
pub mod retransmit;
pub mod segment;
pub mod socket;
pub mod tcb;
pub mod tcp_rx;
#[cfg(any(test, feature = "qemu-test-export"))]
mod tests;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
pub mod types;
pub mod window_scale;

// Re-exports: types
pub use types::{
    SocketAddr, SocketError, SocketFd,
};

// Re-exports: event

// Re-exports: inner

// Re-exports: tcb
pub use tcb::{TcpConnectionState, tcb_table};

// Re-exports: retransmit

// Re-exports: segment

// Re-exports: manager
pub use manager::{
    init_socket_manager, is_socket_manager_initialized, socket_manager,
};

// Re-exports: socket
pub use socket::{
    OwnedSocket, create_tcp_server, create_tcp_socket, create_raw_socket,
};

// Re-exports: futures

// Re-exports: handler

// Re-exports: tcp_rx

// Re-exports: congestion

// Re-exports: window_scale

// Re-exports: flow_control
