// ============================================================================
// src/shell/exoshell/namespaces/registry.rs - Dynamic Namespace Registry
// ============================================================================
//!
//! # 動的名前空間レジストリ
//!
//! ドライバやセルがロードされた際に、新しい名前空間を動的に登録するための
//! グローバルレジストリ。これにより `driver.load("gpu.elf")` 後に即座に
//! `gpu.info()` コマンドが利用可能になる。
//!
//! ## 設計思想
//! ExoRust のセル（Cell）アーキテクチャでは、機能拡張は動的に行われる。
//! シェルもこれに対応し、ハードコードされた名前空間だけでなく、
//! 実行時に追加された名前空間も利用できる必要がある。

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use spin::RwLock;

use super::ShellNamespace;

// ============================================================================
// Global Namespace Registry
// ============================================================================

/// グローバル名前空間レジストリ
/// 
/// RwLock を使用し、読み取りは並行可能、書き込みは排他的。
/// Arc でラップされた名前空間を保持し、複数のシェルインスタンスで共有可能。
static GLOBAL_REGISTRY: RwLock<BTreeMap<String, Arc<dyn ShellNamespace>>> = RwLock::new(BTreeMap::new());

// ============================================================================
// Public API
// ============================================================================

/// 名前空間を登録
/// 
/// # Arguments
/// * `namespace` - 登録する名前空間（Arc でラップされている必要あり）
/// 
/// # Example
/// ```ignore
/// let gpu_ns = Arc::new(GpuNamespace::new());
/// register_namespace(gpu_ns);
/// ```
pub fn register_namespace(namespace: Arc<dyn ShellNamespace>) {
    let name = namespace.name().to_string();
    GLOBAL_REGISTRY.write().insert(name, namespace);
}

/// 名前空間の登録を解除
/// 
/// # Returns
/// 解除された名前空間（存在した場合）
pub fn unregister_namespace(name: &str) -> Option<Arc<dyn ShellNamespace>> {
    GLOBAL_REGISTRY.write().remove(name)
}

/// 登録されている全ての名前空間を取得
/// 
/// シェルインスタンス生成時にコピーを取得するために使用。
pub fn get_all_namespaces() -> BTreeMap<String, Arc<dyn ShellNamespace>> {
    GLOBAL_REGISTRY.read().clone()
}

/// 特定の名前空間を取得
pub fn get_namespace(name: &str) -> Option<Arc<dyn ShellNamespace>> {
    GLOBAL_REGISTRY.read().get(name).cloned()
}

/// 名前空間が登録されているか確認
pub fn is_registered(name: &str) -> bool {
    GLOBAL_REGISTRY.read().contains_key(name)
}

/// 登録されている名前空間の一覧を取得
pub fn list_namespaces() -> alloc::vec::Vec<String> {
    GLOBAL_REGISTRY.read().keys().cloned().collect()
}

// ============================================================================
// Built-in Namespace Registration
// ============================================================================

/// ビルトイン名前空間を登録
/// 
/// シェルシステム初期化時に呼び出される。
pub fn register_builtin_namespaces() {
    use super::{CapNamespace, CellNamespace, DriverNamespace, FsNamespace, NetNamespace, ProcNamespace, SysNamespace, ShellControlNamespace, AsyncSwapoutNamespace, ReclaimNamespace};
    
    register_namespace(Arc::new(FsNamespace));
    register_namespace(Arc::new(NetNamespace));
    register_namespace(Arc::new(ProcNamespace));
    register_namespace(Arc::new(SysNamespace));
    register_namespace(Arc::new(CapNamespace));
    register_namespace(Arc::new(CellNamespace));
    register_namespace(Arc::new(DriverNamespace));
    register_namespace(Arc::new(ShellControlNamespace));
    // AsyncSwapout control namespace (tunable introspection and control)
    register_namespace(Arc::new(AsyncSwapoutNamespace));
    register_namespace(Arc::new(ReclaimNamespace));
}
