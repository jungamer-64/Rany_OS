//! # ランタイム統合
//!
//! ネットワークスタックの実行、ブリッジ（NAT）、
//! マネージャー、タイムアウト管理。

pub mod bridge;
pub mod context;
pub mod device;
pub mod manager;
pub mod stack;
pub mod timeouts;

pub use context::{
    NetRuntimeContext, NetRuntimeHandle, NetRuntimeId, create_runtime, default_runtime,
    default_runtime_context, list_runtimes, runtime, set_default_runtime,
};
