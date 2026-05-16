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
pub mod manager;
pub mod stack;
pub mod timeouts;

pub use context::{
    NetRuntimeContext, NetRuntimeHandle, NetRuntimeId, RuntimeAllocationError, create_runtime,
    default_runtime, default_runtime_context, list_runtimes, reset_runtime_registry_for_tests,
    runtime, set_default_runtime,
};
