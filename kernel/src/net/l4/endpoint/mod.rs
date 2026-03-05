// ============================================================================
// kernel/src/net/l4/endpoint/mod.rs
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
//!
//! ## 責任分担
//!
//! ### 汎用ソケット基盤 (プロトコル非依存)
//! - `types`          — `EndpointFd`, `EndpointAddr`, `EndpointState` 等の基本型
//! - `endpoint_core`  — `Endpoint` / `OwnedEndpoint` (ソケットのライフサイクル管理)
//! - `inner`          — `EndpointInner` / `ProtocolState` (TCP/UDP排他状態)
//! - `manager`        — `EndpointManager` (FDテーブル・ポート管理)
//! - `event`          — `NetworkEvent` / イベントキュー
//!
//! ### TCP 固有サブモジュール
//! - `tcb`            — `TcpControlBlockEntry` / `TcbTable` (接続追跡テーブル)
//! - `tcp_rx`         — TCP受信パスのセグメント処理
//! - `segment`        — `TcpSegmentBuilder` (TCPパケット構築)
//! - `handler`        — `NetworkEventHandler` (イベント→プロトコル処理)
//! - `congestion`     — 輻輳制御 (NewReno / CUBIC / BBR)
//! - `flow_control`   — フロー制御
//! - `retransmit`     — 再送キュー管理
//! - `ooo_queue`      — Out-of-order セグメントキュー
//! - `window_scale`   — TCP Window Scaling (RFC 7323)
//! - `timer_wheel`    — タイマーホイール
//! - `futures`        — async TcpStream/TcpListener の Future 実装
#![allow(dead_code)]
// ── 汎用ソケット基盤 ───────────────────────────────────
pub mod types;
pub mod endpoint_core;
pub mod inner;
pub mod manager;
pub mod event;

// ── TCP 固有サブモジュール ──────────────────────────────
pub mod tcb;
pub mod tcp_rx;
pub mod segment;
pub mod handler;
pub mod congestion;
pub mod flow_control;
pub mod retransmit;
pub mod ooo_queue;
pub mod window_scale;
pub mod timer_wheel;
pub mod futures;

#[cfg(any(test, feature = "qemu-test-export"))]
mod tests;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// Re-exports: types
pub use types::{
    EndpointAddr, EndpointError, EndpointFd, EndpointState, EndpointType,
};

// Re-exports: tcb
pub use tcb::{TcpConnectionState, tcb_table};

// Re-exports: retransmit

// Re-exports: segment

// Re-exports: manager
pub use manager::{
    init_endpoint_manager, is_endpoint_manager_initialized, endpoint_manager,
};

// Re-exports: endpoint
pub use endpoint_core::{
    OwnedEndpoint, create_raw_endpoint, create_tcp_endpoint,
    create_tcp_server_async, create_udp_endpoint, create_udp_endpoint_bound,
};
// Re-exports: futures

// Re-exports: handler
pub use event::NetworkEvent;

// Re-exports: tcp_rx

// Re-exports: congestion

// Re-exports: window_scale

// Re-exports: flow_control
