// ============================================================================
// kernel/src/net/runtime/mod.rs - ランタイム統合
// ============================================================================
//! # ランタイム統合
//!
//! ネットワークスタックの実行、ブリッジ（NAT）、
//! マネージャー、タイムアウト管理。

pub mod bridge;
pub mod command;
pub(crate) mod command_handler;
pub mod command_loop;
pub mod context;
pub mod device;
pub(crate) mod entropy;
pub mod manager;
pub mod stack;
pub mod timeouts;
pub(crate) mod transport;

pub use context::{NetRuntimeContext, NetRuntimeHandle, create_runtime, default_runtime};

#[cfg(test)]
pub use context::reset_runtime_registry_for_tests;
