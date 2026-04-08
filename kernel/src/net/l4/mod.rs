//! # L4 — トランスポート層
//!
//! TCP/UDPプロトコル実装とエンドポイント（ソケット）管理。

pub mod endpoint;
pub mod tcp;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) mod test_support;
pub mod udp;
