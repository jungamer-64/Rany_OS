//! セルのABIメタデータ構造
//!
//! 設計書セクション 3.4.1 参照

use std::collections::HashMap;

/// セルのABIメタデータ
#[derive(Serialize, Deserialize)]
pub struct CellMetadata {
    /// セル識別子
    pub cell_id: CellId,
    /// セマンティックバージョン
    pub abi_version: SemVer,
    /// 公開型のハッシュマップ (TypeId -> SHA-256の下位128bit)
    pub type_hashes: HashMap<TypeId, u128>,
    /// 依存セルとそのインターフェースハッシュ
    pub dependency_graph: Vec<DependencyEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct DependencyEntry {
    pub cell_id: CellId,
    /// バージョン制約 (e.g., ">=1.0.0, <2.0.0")
    pub required_version: VersionConstraint,
    /// 使用するインターフェースのハッシュ
    pub interface_hash: u128,
}

// 以下は型定義のプレースホルダー
pub struct CellId(pub u64);
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}
pub struct TypeId(pub u64);
pub struct VersionConstraint(pub String);
