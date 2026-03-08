// ============================================================================
// src/shell/exoshell/namespaces/registry.rs - Dynamic Namespace Registry
// ============================================================================
//!
//! # 動的名前空間レジストリ
//!
//! ドライバやセルがロードされた際に、新しい名前空間を動的に登録するための
//! グローバルレジストリ。これにより `driver.load("gpu.elf")` 後に即座に
//! `gpu.info()` コマンドが利用可能になる。

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use super::ShellNamespace;

// ============================================================================
// Global Namespace Registry
// ============================================================================

/// グローバル名前空間レジストリ
static GLOBAL_REGISTRY: PoisonRwLock<BTreeMap<String, Arc<dyn ShellNamespace>>> =
    PoisonRwLock::new(BTreeMap::new());

// ============================================================================
// Public API
// ============================================================================

/// 名前空間を登録
pub fn register_namespace(namespace: Arc<dyn ShellNamespace>) {
    let name = namespace.name().to_string();
    GLOBAL_REGISTRY
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(name, namespace);
}

/// 名前空間の登録を解除
pub fn unregister_namespace(name: &str) -> Option<Arc<dyn ShellNamespace>> {
    GLOBAL_REGISTRY
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(name)
}

/// 登録されている全ての名前空間を取得
pub fn get_all_namespaces() -> BTreeMap<String, Arc<dyn ShellNamespace>> {
    GLOBAL_REGISTRY.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// 特定の名前空間を取得
pub fn get_namespace(name: &str) -> Option<Arc<dyn ShellNamespace>> {
    GLOBAL_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
        .cloned()
}

/// 名前空間が登録されているか確認
pub fn is_registered(name: &str) -> bool {
    GLOBAL_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(name)
}

/// 登録されている名前空間の一覧を取得
pub fn list_namespaces() -> alloc::vec::Vec<String> {
    GLOBAL_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect()
}

// ============================================================================
// Built-in Namespace Registration
// ============================================================================

/// ビルトイン名前空間を登録
pub fn register_builtin_namespaces() {
    use super::{
        AsyncSwapoutNamespace, CapNamespace, CellNamespace, DomainNamespace, DriverNamespace,
        FsNamespace, LogNamespace, Mlx5Namespace, NetNamespace, ReclaimNamespace,
        ShellControlNamespace, SysNamespace, TaskNamespace,
    };

    register_namespace(Arc::new(FsNamespace));
    register_namespace(Arc::new(NetNamespace));
    register_namespace(Arc::new(DomainNamespace));
    register_namespace(Arc::new(SysNamespace));
    register_namespace(Arc::new(CapNamespace));
    register_namespace(Arc::new(CellNamespace));
    register_namespace(Arc::new(DriverNamespace));
    register_namespace(Arc::new(ShellControlNamespace));
    register_namespace(Arc::new(TaskNamespace));
    register_namespace(Arc::new(LogNamespace));
    register_namespace(Arc::new(Mlx5Namespace));
    register_namespace(Arc::new(AsyncSwapoutNamespace));
    register_namespace(Arc::new(ReclaimNamespace));
}
