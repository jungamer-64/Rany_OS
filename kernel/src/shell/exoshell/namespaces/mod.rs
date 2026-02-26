// ============================================================================
// src/shell/exoshell/namespaces/mod.rs - Namespace module exports
// ============================================================================

pub mod cap;
pub mod cell;
pub mod driver;
pub mod dynamic_driver;
pub mod fs;
pub mod net;
pub mod proc;
pub mod registry;
pub mod sys;
pub mod shell;
pub mod async_swapout;
pub mod reclaim;

pub use cap::CapNamespace;
pub use cell::CellNamespace;
pub use driver::DriverNamespace;
pub use fs::FsNamespace;
pub use net::NetNamespace;
pub use proc::ProcNamespace;
pub use sys::SysNamespace;
pub use shell::ShellControlNamespace;
pub use async_swapout::AsyncSwapoutNamespace;
pub use reclaim::ReclaimNamespace;

use crate::security::CapabilitySet;
use crate::shell::exoshell::types::ExoValue;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

/// Box化されたFuture (no_std環境でのasync trait用)
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// シェル名前空間トレイト
/// 新しい機能群を追加するためのインターフェース
/// 
/// ## Capability-based Security
/// メソッド呼び出し時に呼び出し元の CapabilitySet を明示的に渡す。
/// これにより主体IDベースの権限チェックではなく、トークンベースの
/// セキュリティモデルを実現する。
pub trait ShellNamespace: Send + Sync {
    /// 名前空間の名称 (例: "fs", "net")
    fn name(&self) -> &str;

    /// メソッド呼び出し
    /// 
    /// # Arguments
    /// * `method` - メソッド名
    /// * `args` - 評価済みの引数リスト
    /// * `caps` - 呼び出し元のケイパビリティセット
    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>>;
}
