// ============================================================================
// src/shell/exoshell/namespaces/driver.rs - Driver Namespace
// ============================================================================
//!
//! # Driver Namespace
//!
//! Provides shell commands for driver inspection:
//! - `driver.list()` - List registered drivers
//! - `driver.stats()` - Driver statistics
//! - `driver.status(id)` - Get driver status
//!
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::driver_domain;
use crate::driver_registry::{self};
use crate::security::CapabilitySet;
use crate::security::capability::CAP_FOWNER;
use crate::shell::exoshell::types::ExoValue;

/// ドライバ名前空間
pub struct DriverNamespace;

impl DriverNamespace {
    fn require_fowner(caps: &CapabilitySet, op_name: &str) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(CAP_FOWNER) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires CAP_FOWNER",
                op_name
            )))
        }
    }

    /// 登録済みドライバの一覧
    pub fn list(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_fowner(caps, "driver.list") {
            return e;
        }
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
    pub fn stats(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_fowner(caps, "driver.stats") {
            return e;
        }
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
    pub fn status(id: i64, caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_fowner(caps, "driver.status") {
            return e;
        }
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
                "list" => Self::list(caps),
                "stats" => Self::stats(caps),
                "status" => {
                    let id = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::Int(n) => Some(*n as i64),
                            _ => None,
                        })
                        .unwrap_or(0);
                    Self::status(id, caps)
                }
                _ => ExoValue::Error(format!(
                    "Unknown method 'driver.{}'\nValid methods: list, stats, status\nUse cell.load/cell.unload/cell.swap for DriverDomain lifecycle operations",
                    method
                )),
            }
        })
    }
}
