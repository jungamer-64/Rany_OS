// ============================================================================
// kernel/src/net/l4/mod.rs - L4 — トランスポート層
// ============================================================================
//! # L4 — トランスポート層
//!
//! TCP/UDPプロトコル実装とエンドポイント（ソケット）管理。

pub mod raw;
pub(crate) mod socket;
pub mod tcp;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod test_support;
pub(crate) mod types;
pub mod udp;

pub use types::{EndpointAddr, EndpointError};
