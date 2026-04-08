// ============================================================================
// kernel/src/net/l4/endpoint/mod.rs
// ============================================================================
//! # Endpoint Module - SPL/SAS Compliant Network Socket Implementation
//!
//! ## Design Philosophy
//! - Fine-grained locking: Arc<Mutex<EndpointInner>> for per-socket locking
//! - Endpoint-centered resource management with test-only RAII helpers
//! - Payload-backed FIFO queues: packet ownership moves without eager flattening
//! - Read parallelization: RwLock for EndpointManager concurrent reads
//! - State transition guards: Compile-time detection of invalid transitions
//! - Event-driven: NetworkEvent for protocol stack coordination
//!
//! ## 責任分担
//!
//! ### 汎用ソケット基盤 (プロトコル非依存)
//! - `types`          — `EndpointFd`, `EndpointAddr`, `EndpointState` 等の基本型
//! - `endpoint_core`  — `Endpoint` (ソケットのライフサイクル管理)
//! - `inner`          — `EndpointInner` / `ProtocolState` (TCP/UDP排他状態)
//! - `manager`        — `EndpointManager` (FDテーブル・ポート管理)
//! - `event`          — `NetworkEvent` / イベントキュー
//! - `event_loop`     — 汎用イベント待機・バッチ処理タスク
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
// ALLOW: endpoint namespace still exposes several test-only/internal submodules while the L4 split is in progress.
#![allow(dead_code)]
// ── 汎用ソケット基盤 ───────────────────────────────────
pub mod endpoint_core;
pub mod event;
pub mod event_loop;
pub mod inner;
pub mod manager;
pub mod types;

// ── TCP 固有サブモジュール ──────────────────────────────
pub mod congestion;
pub mod flow_control;
pub mod handler;
pub mod ooo_queue;
pub mod retransmit;
pub mod segment;
pub mod tcb;
pub mod tcp_rx;
pub mod timer_wheel;
pub mod window_scale;

#[cfg(any(test, feature = "qemu-test-export"))]
mod async_tests;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
#[cfg(any(test, feature = "qemu-test-export"))]
mod tests;

// Re-exports: types
pub use types::{EndpointAddr, EndpointError, EndpointFd, EndpointState, EndpointType};

// Re-exports: tcb
pub use tcb::{TcpConnectionState, tcb_table};

// Re-exports: manager
pub use manager::{endpoint_manager, init_endpoint_manager, is_endpoint_manager_initialized};

// Re-exports: handler
pub use event::NetworkEvent;
