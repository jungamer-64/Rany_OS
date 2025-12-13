// ============================================================================
// src/shell/exoshell/namespaces/mod.rs - Namespace module exports
// ============================================================================

pub mod cap;
pub mod driver;
pub mod fs;
pub mod net;
pub mod proc;
pub mod sys;

pub use cap::CapNamespace;
pub use driver::DriverNamespace;
pub use fs::FsNamespace;
pub use net::NetNamespace;
pub use proc::ProcNamespace;
pub use sys::SysNamespace;

use crate::shell::exoshell::types::ExoValue;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

/// Box化されたFuture (no_std環境でのasync trait用)
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// シェル名前空間トレイト
/// 新しい機能群を追加するためのインターフェース
pub trait ShellNamespace: Send + Sync {
    /// 名前空間の名称 (例: "fs", "net")
    fn name(&self) -> &str;

    /// メソッド呼び出し
    /// method: メソッド名
    /// args: 評価済みの引数リスト（所有権を持つ静的な ExoValue）
    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
    ) -> BoxFuture<'a, ExoValue<'static>>;
}
