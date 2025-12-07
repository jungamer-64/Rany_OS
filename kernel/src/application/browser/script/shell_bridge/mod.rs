// ============================================================================
// src/application/browser/script/shell_bridge/mod.rs - Shell Bridge Module
// ============================================================================
//!
//! ExoShell + RustScript 統合レイヤー
//!
//! このモジュールは、ExoShell（自作シェル）とRustScriptを統合し、
//! OSのコア機能（ファイルシステム、プロセス、ネットワーク、デバイスなど）への
//! ブリッジを提供する。
//!
//! ## モジュール構成
//! - `types`: 型定義（ShellCommandFn, AsyncState, TaskId等）
//! - `commands`: 同期コマンド実装
//! - `async_commands`: 非同期コマンド実装
//! - `executor`: 非同期タスク実行
//! - `completion`: 補完・ヘルプ機能
//! - `runtime`: ShellRuntimeの実装

pub mod types;
pub mod commands;
pub mod async_commands;
pub mod executor;
pub mod completion;
pub mod runtime;

// Re-exports
pub use types::{
    ValueConversion,
    conversion,
    ShellCommandFn,
    AsyncCommandFuture,
    AsyncShellCommandFn,
    AsyncState,
    TaskId,
    AsyncTask,
};

pub use executor::{
    AsyncExecutor,
    noop_waker,
};

pub use completion::{
    ShellCommand,
    CompletionHint,
    CompletionCategory,
    BUILTIN_FUNCTIONS,
    KEYWORDS,
    generate_help,
};

pub use runtime::ShellRuntime;
