// ============================================================================
// src/shell/mod.rs - ExoShell Module
// ============================================================================
//!
//! # ExoShell - Rust式REPLシェル
//!
//! ExoRustの設計思想に基づいたRust式REPL環境。
//! Unix互換コマンドではなく、型付きオブジェクトを直接操作する。
//!
//! ## 設計原則
//! - **型付きオブジェクト**: テキストストリームではなく構造体を直接操作
//! - **ゼロコピー**: SAS（単一アドレス空間）を活かしたポインタ渡し
//! - **Capability**: chmod/chown ではなく grant/revoke による権限管理
//! - **メソッドチェーン**: パイプラインではなくイテレータ操作
//!
//! ## 使用例
//! ```text
//! # ExoShell式
//! fs.entries("/home").filter("type == Directory").take(5)
//! net.config()
//! sys.info()
//! ```

#![allow(dead_code)]

pub mod async_shell;
pub mod exoshell;
pub mod graphical;

// Re-export ExoShell types
pub use exoshell::{ExoShell, ExoValue, Capability, CapOperation};

// Re-export graphical shell
pub use graphical::GraphicalShell;

// ============================================================================
// Removed: Legacy Shell implementation
// ============================================================================
// The classic Unix-style shell (Shell, ShellRunner, CommandResult, etc.)
// has been removed in favor of ExoShell.
// 
// If you need classic shell commands, use ExoShell's alias feature:
//   ls, cd, pwd, cat, mkdir, rm, ps, ifconfig, ping, etc.
// are still available as convenience aliases.
// ============================================================================
