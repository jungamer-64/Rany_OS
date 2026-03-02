// ============================================================================
// kernel/src/net/endpoint.rs
// ============================================================================
//! # Endpoint Module - SPL/SAS Compliant Network Socket Implementation
//!
//! ## Design Philosophy
//! - Fine-grained locking: Arc<Mutex<EndpointInner>> for per-socket locking
//! - RAII resource management: OwnedEndpoint for automatic close
//! - O(1) buffer operations: VecDeque for FIFO efficiency
//! - Read parallelization: RwLock for EndpointManager concurrent reads
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
pub mod endpoint_core;
pub mod tcb;
pub mod tcp_rx;
pub mod timer_wheel;
#[cfg(any(test, feature = "qemu-test-export"))]
mod tests;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
pub mod types;
pub mod window_scale;

// Re-exports: types
pub use types::{
    EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointState, EndpointType,
    seq_before, seq_leq, seq_after, seq_geq,
    conn_key_hash,
};

// Re-exports: event
pub use event::NetworkEvent;

// Re-exports: inner

// Re-exports: tcb
pub use tcb::{TcpConnectionState, tcb_table};

// Re-exports: retransmit

// Re-exports: segment

// Re-exports: manager
pub use manager::{
    init_endpoint_manager, is_endpoint_manager_initialized, endpoint_manager,
};

// Re-exports: socket
pub use endpoint_core::{
    OwnedEndpoint, create_tcp_server, create_tcp_endpoint, create_udp_endpoint, create_raw_endpoint,
};

// Re-exports: futures

// Re-exports: handler

// Re-exports: tcp_rx

// Re-exports: congestion

// Re-exports: window_scale

// Re-exports: flow_control
