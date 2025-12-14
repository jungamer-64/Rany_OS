// ============================================================================
// src/shell/exoshell/namespaces/driver.rs - Driver Namespace
// ============================================================================
//!
//! # Driver Namespace
//!
//! Provides shell commands for driver management:
//! - `driver.list()` - List registered drivers
//! - `driver.load(path)` - Load driver from ELF file
//! - `driver.unload(id)` - Unload a driver
//! - `driver.status(id)` - Get driver status
//!
use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::driver_registry;
use crate::loader;
use crate::security::capability::CAP_SYS_MODULE;
use crate::shell::exoshell::types::ExoValue;
use alloc::boxed::Box;

/// ドライバ名前空間
pub struct DriverNamespace;

impl DriverNamespace {
    /// 登録済みドライバの一覧
    pub fn list() -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();
        let drivers = registry.list();

        let mut list = Vec::new();
        for (handle, name, dtype, state) in drivers {
            let mut map = BTreeMap::new();
            map.insert(String::from("id"), ExoValue::Int(handle.index() as i64));
            map.insert(String::from("name"), ExoValue::String(Cow::Owned(name)));
            map.insert(
                String::from("type"),
                ExoValue::String(Cow::Owned(format!("{:?}", dtype))),
            );
            map.insert(
                String::from("state"),
                ExoValue::String(Cow::Owned(format!("{:?}", state))),
            );
            list.push(ExoValue::Map(map));
        }

        ExoValue::Array(list)
    }

    /// ドライバの統計情報
    pub fn stats() -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();
        let mut map = BTreeMap::new();
        map.insert(
            String::from("total"),
            ExoValue::Int(registry.count() as i64),
        );
        map.insert(
            String::from("running"),
            ExoValue::Int(registry.running_count() as i64),
        );
        ExoValue::Map(map)
    }

    /// ドライバの状態を取得
    pub fn status(id: i64) -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();
        let handle = driver_registry::DriverHandle::from_index(id as usize);

        match registry.state(handle) {
            Some(state) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("id"), ExoValue::Int(id));
                map.insert(
                    String::from("state"),
                    ExoValue::String(Cow::Owned(format!("{:?}", state))),
                );
                if let Some(name) = registry.name(handle) {
                    map.insert(String::from("name"), ExoValue::String(Cow::Owned(name)));
                }
                ExoValue::Map(map)
            }
            None => ExoValue::Error(format!("Driver {} not found", id)),
        }
    }

    /// ファイルからドライバをロード
    /// Requires CAP_SYS_MODULE
    fn load_with_caps(path: &str, caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_MODULE) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_MODULE required"));
        }

        if path.is_empty() {
            return ExoValue::Error(String::from(
                "Path is required. Usage: driver.load(\"/path/to/driver.elf\")",
            ));
        }

        // ファイルからELFデータを読み込み
        let shell = match kernel_api::services::kernel().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };
        
        let elf_data = match shell.read_file(path) {
            Ok(data) => data,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        // ドライバ名をパスから抽出
        let driver_name = path
            .rsplit('/')
            .next()
            .unwrap_or("unknown")
            .trim_end_matches(".elf")
            .trim_end_matches(".driver");

        // ローダーでドライバをロード
        match loader::load_driver(driver_name, &elf_data, true) {
            Ok(handle) => {
                // 動的名前空間を自動登録
                use super::dynamic_driver::DynamicDriverNamespace;
                use super::registry;
                use alloc::sync::Arc;
                
                let dynamic_ns = Arc::new(DynamicDriverNamespace::new(
                    String::from(driver_name),
                    handle,
                ));
                registry::register_namespace(dynamic_ns);
                
                let mut map = BTreeMap::new();
                map.insert(String::from("success"), ExoValue::Bool(true));
                map.insert(
                    String::from("driver_id"),
                    ExoValue::Int(handle.index() as i64),
                );
                map.insert(
                    String::from("name"),
                    ExoValue::String(Cow::Owned(driver_name.into())),
                );
                map.insert(
                    String::from("message"),
                    ExoValue::String(Cow::Owned(format!(
                        "Driver '{}' loaded successfully with ID {}. Namespace '{}' registered.",
                        driver_name,
                        handle.index(),
                        driver_name
                    ))),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to load driver: {}", e)),
        }
    }

    /// ドライバをアンロード
    /// Requires CAP_SYS_MODULE
    fn unload_with_caps(id: i64, caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_MODULE) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_MODULE required"));
        }

        let handle = driver_registry::DriverHandle::from_index(id as usize);

        // まずドライバが存在するか確認
        let registry = driver_registry::driver_registry();
        if registry.state(handle).is_none() {
            return ExoValue::Error(format!("Driver {} not found", id));
        }

        // ドライバをアンロード
        match loader::unload_driver(handle) {
            Ok(()) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("success"), ExoValue::Bool(true));
                map.insert(String::from("driver_id"), ExoValue::Int(id));
                map.insert(
                    String::from("message"),
                    ExoValue::String(Cow::Owned(format!("Driver {} unloaded successfully", id))),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to unload driver {}: {}", id, e)),
        }
    }

    /// ドライバをライブアップデート
    /// Requires CAP_SYS_MODULE
    fn update_with_caps(id: i64, path: &str, caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_MODULE) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_MODULE required"));
        }

        if path.is_empty() {
             return ExoValue::Error(String::from("Path is required"));
        }

        let handle = driver_registry::DriverHandle::from_index(id as usize);
        
        // Find owning cell
        let cell_id = match loader::find_cell_by_driver(handle) {
            Some(id) => id,
            None => return ExoValue::Error(format!("Driver {} not found or not associated with a cell", id)),
        };

        // Read ELF
        let shell = match kernel_api::services::kernel().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };
        
        let elf_data = match shell.read_file(path) {
            Ok(data) => data,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        // Perform Update
        match loader::live_update_manager().perform_update(cell_id.as_u64(), &elf_data) {
             Ok(new_cell_id) => {
                 let mut map = BTreeMap::new();
                 map.insert(String::from("success"), ExoValue::Bool(true));
                 map.insert(String::from("old_driver_id"), ExoValue::Int(id));
                 map.insert(String::from("new_cell_id"), ExoValue::Int(new_cell_id as i64));
                 map.insert(
                     String::from("message"),
                     ExoValue::String(Cow::Owned(format!("Driver {} updated successfully. New Cell ID: {}", id, new_cell_id))),
                 );
                 ExoValue::Map(map)
             }
             Err(e) => ExoValue::Error(format!("Live update failed: {}", e)),
        }
    }
}

impl ShellNamespace for DriverNamespace {
    fn name(&self) -> &str {
        "driver"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "list" => Self::list(),
                "stats" => Self::stats(),
                "status" => {
                    let id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as i64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::status(id)
                }
                "load" => {
                    let path = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    Self::load_with_caps(path, caps)
                }
                "unload" => {
                    let id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as i64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::unload_with_caps(id, caps)
                }
                "update" => {
                    let id = args.get(0).and_then(|v| v.as_int()).unwrap_or(0);
                    let path = args.get(1).and_then(|v| v.as_str()).unwrap_or("");
                    Self::update_with_caps(id, path, caps)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'driver.{}'\nValid methods: list, stats, status, load, unload, update",
                    method
                )),
            }
        })
    }
}
