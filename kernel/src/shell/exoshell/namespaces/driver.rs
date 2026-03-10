// ============================================================================
// src/shell/exoshell/namespaces/driver.rs - Driver Namespace
// ============================================================================
//!
//! # Driver Namespace
//!
//! Provides shell commands for driver management:
//! - `driver.list()` - List registered drivers
//! - `driver.load(path)` - Compatibility alias for DriverDomain-based load
//! - `driver.unload(id)` - Compatibility alias for DriverDomain-based unload
//! - `driver.status(id)` - Get driver status
//!
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::driver_domain;
use crate::driver_domain::{DriverDomainId, hot_swap, lifecycle};
use crate::driver_registry::{self, DriverHandle};
use crate::security::capability::CAP_SYS_MODULE;
use crate::shell::exoshell::types::ExoValue;

/// ドライバ名前空間
pub struct DriverNamespace;

impl DriverNamespace {
    fn register_dynamic_namespaces(driver_name: &str, handles: &[DriverHandle]) -> Vec<String> {
        use super::dynamic_driver::DynamicDriverNamespace;
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

    fn resolve_driver_domain_id(id: i64) -> Result<DriverDomainId, String> {
        if id < 0 {
            return Err(String::from("Driver/DriverDomain id must be non-negative"));
        }

        let manager = driver_domain::driver_domain_manager();
        let handle = DriverHandle::from_index(id as usize);
        if driver_registry::driver_registry().state(handle).is_some() {
            return manager.find_by_driver_handle(handle).ok_or_else(|| {
                format!(
                    "Driver {} is not managed by a DriverDomain; use cell.* for canonical lifecycle operations",
                    id
                )
            });
        }

        let driver_domain_id = DriverDomainId::new(id as u64);
        manager
            .with_cell(driver_domain_id, |_| ())
            .map(|_| driver_domain_id)
            .map_err(|_| format!("Driver/DriverDomain {} not found", id))
    }

    /// 登録済みドライバの一覧
    pub fn list() -> ExoValue<'static> {
        let registry = driver_registry::driver_registry();
        let drivers = registry.list();
        let manager = driver_domain::driver_domain_manager();

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
            if let Some(driver_domain_id) = manager.find_by_driver_handle(handle) {
                map.insert(
                    String::from("driver_domain_id"),
                    ExoValue::Int(driver_domain_id.as_u64() as i64),
                );
            }
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
                if let Some(driver_domain_id) =
                    driver_domain::driver_domain_manager().find_by_driver_handle(handle)
                {
                    map.insert(
                        String::from("driver_domain_id"),
                        ExoValue::Int(driver_domain_id.as_u64() as i64),
                    );
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
                "Path is required. Usage: driver.load(\"/path/to/driver.elf\") or .drvpack",
            ));
        }

        // ファイルからELFデータを読み込み
        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        let elf_data = match shell.read_file_zero_copy(path) {
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

        // Canonical phase-3 path: artifact -> DriverDomain lifecycle -> DriverRegistry
        match lifecycle::create_and_start_default(driver_name, &elf_data, true) {
            Ok((driver_domain_id, handles)) => {
                let handle_list = handles
                    .iter()
                    .map(|handle| ExoValue::Int(handle.index() as i64))
                    .collect::<Vec<_>>();
                let namespace_list = Self::register_dynamic_namespaces(driver_name, &handles)
                    .into_iter()
                    .map(|namespace| ExoValue::String(Cow::Owned(namespace)))
                    .collect::<Vec<_>>();
                let primary_handle = handles
                    .first()
                    .map(|handle| ExoValue::Int(handle.index() as i64))
                    .unwrap_or(ExoValue::Nil);

                let mut map = BTreeMap::new();
                map.insert(String::from("success"), ExoValue::Bool(true));
                map.insert(String::from("driver_id"), primary_handle);
                map.insert(
                    String::from("driver_domain_id"),
                    ExoValue::Int(driver_domain_id.as_u64() as i64),
                );
                map.insert(String::from("driver_handles"), ExoValue::Array(handle_list));
                map.insert(String::from("namespaces"), ExoValue::Array(namespace_list));
                map.insert(
                    String::from("name"),
                    ExoValue::String(Cow::Owned(driver_name.into())),
                );
                map.insert(
                    String::from("message"),
                    ExoValue::String(Cow::Owned(format!(
                        "driver.load routed '{}' through DriverDomain lifecycle (id={})",
                        driver_name,
                        driver_domain_id.as_u64()
                    ))),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to load DriverDomain: {}", e)),
        }
    }

    /// ドライバをアンロード
    /// Requires CAP_SYS_MODULE
    fn unload_with_caps(id: i64, caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_MODULE) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_MODULE required"));
        }

        let driver_domain_id = match Self::resolve_driver_domain_id(id) {
            Ok(id) => id,
            Err(message) => return ExoValue::Error(message),
        };

        match lifecycle::unload(driver_domain_id) {
            Ok(()) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("success"), ExoValue::Bool(true));
                map.insert(String::from("driver_id"), ExoValue::Int(id));
                map.insert(
                    String::from("driver_domain_id"),
                    ExoValue::Int(driver_domain_id.as_u64() as i64),
                );
                map.insert(
                    String::from("message"),
                    ExoValue::String(Cow::Owned(format!(
                        "DriverDomain {} unloaded successfully",
                        driver_domain_id.as_u64()
                    ))),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!(
                "Failed to unload DriverDomain {}: {}",
                driver_domain_id.as_u64(),
                e
            )),
        }
    }

    /// ドライバをライブアップデート
    /// Requires CAP_SYS_MODULE
    fn update_with_caps(
        id: i64,
        path: &str,
        caps: &crate::security::CapabilitySet,
    ) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_MODULE) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_MODULE required"));
        }

        if path.is_empty() {
            return ExoValue::Error(String::from("Path is required"));
        }

        let driver_domain_id = match Self::resolve_driver_domain_id(id) {
            Ok(id) => id,
            Err(message) => return ExoValue::Error(message),
        };

        // Read ELF
        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        let elf_data = match shell.read_file_zero_copy(path) {
            Ok(data) => data,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        match hot_swap::hot_swap(driver_domain_id, &elf_data) {
            Ok(result) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("success"), ExoValue::Bool(true));
                map.insert(String::from("old_driver_id"), ExoValue::Int(id));
                map.insert(
                    String::from("driver_domain_id"),
                    ExoValue::Int(driver_domain_id.as_u64() as i64),
                );
                map.insert(
                    String::from("old_cell_id"),
                    ExoValue::Int(result.old_cell_id.as_u64() as i64),
                );
                map.insert(
                    String::from("new_cell_id"),
                    ExoValue::Int(result.new_cell_id.as_u64() as i64),
                );
                map.insert(
                    String::from("needs_rollback"),
                    ExoValue::Bool(result.needs_rollback),
                );
                map.insert(
                    String::from("message"),
                    ExoValue::String(Cow::Owned(format!(
                        "DriverDomain {} entered validation window after hot-swap",
                        driver_domain_id.as_u64()
                    ))),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("DriverDomain hot-swap failed: {}", e)),
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
