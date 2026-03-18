// ============================================================================
// src/shell/exoshell/namespaces/mod.rs - Namespace module exports
// ============================================================================

pub mod cell;
pub mod domain;
pub mod driver;
pub mod log;
pub mod net;
pub mod registry;
pub mod sys;
pub mod task;

pub use cell::CellNamespace;
pub use domain::DomainNamespace;
pub use driver::DriverNamespace;
pub use log::LogNamespace;
pub use net::NetNamespace;
pub use sys::SysNamespace;
pub use task::TaskNamespace;

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
    /// 名前空間の名称 (例: "sys", "net")
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
