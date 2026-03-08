// ============================================================================
// src/shell/exoshell/mod.rs - ExoShell Module Exports
// ============================================================================
//!
//! # ExoShell - Rust式REPL環境
//!
//! ExoRustの設計思想に基づいた新しいシェル環境。
//! Unix互換コマンドではなく、Rustの構文でOSリソースを直接操作する。

#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

// サブモジュール
pub mod buffer_view;
pub mod command;
pub mod display;
pub mod history;

pub mod frontend;

pub mod environment;
pub mod error;
pub mod namespaces;
pub mod parser;
pub mod shell;
pub mod types;

// Re-exports
pub use shell::ExoShell;

pub use types::*;

// ============================================================================
// Global ExoShell instance
// ============================================================================

use crate::sync::PoisonLock;

static EXOSHELL: PoisonLock<Option<ExoShell>> = PoisonLock::new(None);

/// ExoShellを初期化
///
/// ビルトイン名前空間をレジストリに登録し、グローバルシェルインスタンスを作成。
pub fn init() {
    // ビルトイン名前空間を先に登録
    namespaces::registry::register_builtin_namespaces();

    // シェルインスタンスを作成（レジストリから名前空間を取得）
    *EXOSHELL.lock().unwrap_or_else(|e| e.into_inner()) = Some(ExoShell::new());

    log::info!(
        "[EXOSHELL] ExoShell REPL initialized with {} namespaces\n",
        namespaces::registry::list_namespaces().len()
    );
}

/// ExoShellにアクセス（同期操作のみ）
pub fn with_exoshell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut ExoShell) -> R,
{
    let mut guard = EXOSHELL.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_exovalue_display() {
        let val = ExoValue::Int(42);
        assert_eq!(alloc::format!("{}", val), "42");

        let val = ExoValue::String(alloc::string::String::from("hello").into());
        assert_eq!(alloc::format!("{}", val), "hello");
    }

    #[test_case]
    fn test_namespace_registration() {
        let shell = ExoShell::new();
        assert!(shell.is_namespace("fs"));
        assert!(shell.is_namespace("cap"));
        assert!(shell.is_namespace("cell"));
        assert!(shell.is_namespace("net"));
        assert!(shell.is_namespace("sys"));
        assert!(shell.is_namespace("driver"));
    }
}
