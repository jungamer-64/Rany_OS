// ============================================================================
// src/shell/exoshell/namespaces/dynamic_driver.rs - Dynamic Driver Namespace
// ============================================================================
//!
//! # 動的ドライバ名前空間
//!
//! ドライバロード後に自動生成される名前空間。
//! ドライバ固有のコマンドを提供する。
//!
//! ## 例
//! ```text
//! cell.load("/drivers/gpu.elf")
//! # -> gpu 名前空間が自動登録
//! gpu.info()
//! gpu.status()
//! ```

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::driver_registry::{self, DriverHandle};
use crate::shell::exoshell::types::ExoValue;

pub fn register_namespaces(driver_name: &str, handles: &[DriverHandle]) -> Vec<String> {
    use super::registry;

    let mut registered = Vec::new();
    for (index, handle) in handles.iter().enumerate() {
        let namespace_name = if index == 0 {
            String::from(driver_name)
        } else {
            format!("{}_{}", driver_name, index + 1)
        };
        registry::register_namespace(Arc::new(DynamicDriverNamespace::new(
            namespace_name.clone(),
            *handle,
        )));
        registered.push(namespace_name);
    }
    registered
}

/// ドライバ固有の名前空間
///
/// ドライバがロードされると、そのドライバ名に基づいて
/// この名前空間が自動的にレジストリに登録される。
pub struct DynamicDriverNamespace {
    /// ドライバ名（名前空間名としても使用）
    name: String,
    /// ドライバへのハンドル
    handle: DriverHandle,
}

impl DynamicDriverNamespace {
    /// 新しい動的ドライバ名前空間を作成
    pub fn new(name: String, handle: DriverHandle) -> Self {
        Self { name, handle }
    }

    /// ドライバ情報を取得
    fn info(&self) -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();

        let mut map = BTreeMap::new();
        map.insert(
            String::from("name"),
            ExoValue::String(Cow::Owned(self.name.clone())),
        );
        map.insert(
            String::from("handle_id"),
            ExoValue::Int(self.handle.index() as i64),
        );

        if let Some(state) = registry.state(self.handle) {
            map.insert(
                String::from("state"),
                ExoValue::String(Cow::Owned(format!("{:?}", state))),
            );
        }

        ExoValue::Map(map)
    }

    /// ドライバステータスを取得
    fn status(&self) -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();

        match registry.state(self.handle) {
            Some(state) => ExoValue::String(Cow::Owned(format!("{:?}", state))),
            None => ExoValue::Error(String::from("Driver not found")),
        }
    }

    /// ドライバを停止
    fn stop(&self) -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();

        match registry.stop(self.handle) {
            Ok(()) => ExoValue::String(Cow::Owned(format!(
                "Driver '{}' stopped successfully",
                self.name
            ))),
            Err(e) => ExoValue::Error(format!("Failed to stop driver: {:?}", e)),
        }
    }

    /// ドライバを再起動
    fn restart(&self) -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();

        // Stop then start
        if let Err(e) = registry.stop(self.handle) {
            return ExoValue::Error(format!("Failed to stop driver: {:?}", e));
        }

        match registry.start(self.handle) {
            Ok(()) => ExoValue::String(Cow::Owned(format!(
                "Driver '{}' restarted successfully",
                self.name
            ))),
            Err(e) => ExoValue::Error(format!("Failed to start driver: {:?}", e)),
        }
    }
}

impl ShellNamespace for DynamicDriverNamespace {
    fn name(&self) -> &str {
        &self.name
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        _args: &'a [ExoValue<'static>],
        _caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "info" => self.info(),
                "status" => self.status(),
                "stop" => self.stop(),
                "restart" => self.restart(),
                _ => ExoValue::Error(format!(
                    "Unknown method '{}.{}'\\nValid methods: info, status, stop, restart",
                    self.name, method
                )),
            }
        })
    }
}
