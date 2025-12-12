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

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::exoshell::types::ExoValue;
use crate::driver_registry;
use crate::loader;

/// ドライバ名前空間
pub struct DriverNamespace;

impl DriverNamespace {
    /// 登録済みドライバの一覧
    pub fn list() -> ExoValue {
        let registry = driver_registry::driver_registry();
        let drivers = registry.list();
        
        let mut list = Vec::new();
        for (handle, name, dtype, state) in drivers {
            let mut map = BTreeMap::new();
            map.insert(String::from("id"), ExoValue::Int(handle.index() as i64));
            map.insert(String::from("name"), ExoValue::String(name));
            map.insert(String::from("type"), ExoValue::String(format!("{:?}", dtype)));
            map.insert(String::from("state"), ExoValue::String(format!("{:?}", state)));
            list.push(ExoValue::Map(map));
        }
        
        ExoValue::Array(list)
    }

    /// ドライバの統計情報
    pub fn stats() -> ExoValue {
        let registry = driver_registry::driver_registry();
        let mut map = BTreeMap::new();
        map.insert(String::from("total"), ExoValue::Int(registry.count() as i64));
        map.insert(String::from("running"), ExoValue::Int(registry.running_count() as i64));
        ExoValue::Map(map)
    }

    /// ドライバの状態を取得
    pub fn status(id: i64) -> ExoValue {
        let registry = driver_registry::driver_registry();
        let handle = driver_registry::DriverHandle::from_index(id as usize);
        
        match registry.state(handle) {
            Some(state) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("id"), ExoValue::Int(id));
                map.insert(String::from("state"), ExoValue::String(format!("{:?}", state)));
                if let Some(name) = registry.name(handle) {
                    map.insert(String::from("name"), ExoValue::String(name));
                }
                ExoValue::Map(map)
            }
            None => ExoValue::Error(format!("Driver {} not found", id)),
        }
    }

    /// ファイルからドライバをロード
    pub fn load(path: &str) -> ExoValue {
        if path.is_empty() {
            return ExoValue::Error(String::from("Path is required. Usage: driver.load(\"/path/to/driver.elf\")"));
        }

        // ファイルからELFデータを読み込み
        let elf_data = match crate::fs::memfs::read_file_content(path, "/") {
            Ok(data) => data,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {:?}", path, e)),
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
                let mut map = BTreeMap::new();
                map.insert(String::from("success"), ExoValue::Bool(true));
                map.insert(String::from("driver_id"), ExoValue::Int(handle.index() as i64));
                map.insert(String::from("name"), ExoValue::String(driver_name.into()));
                map.insert(String::from("message"), ExoValue::String(
                    format!("Driver '{}' loaded successfully with ID {}", driver_name, handle.index())
                ));
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to load driver: {}", e)),
        }
    }

    /// ドライバをアンロード
    pub fn unload(id: i64) -> ExoValue {
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
                map.insert(String::from("message"), ExoValue::String(
                    format!("Driver {} unloaded successfully", id)
                ));
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to unload driver {}: {}", id, e)),
        }
    }
}
