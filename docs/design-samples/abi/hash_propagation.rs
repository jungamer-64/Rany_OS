//! 増分更新時のハッシュ伝播アルゴリズム
//!
//! 設計書セクション 3.4.2 参照

use std::collections::VecDeque;

/// 変更検出アルゴリズム
///
/// セルA → セルB → セルC の依存チェーンにおいて、
/// セルCの型定義が変更された場合の影響を検出する
pub fn propagate_hash_changes(changed_cell: CellId, graph: &DependencyGraph) -> Vec<CellId> {
    let mut affected = Vec::new();
    let mut queue = VecDeque::from([changed_cell]);

    while let Some(cell) = queue.pop_front() {
        for dependent in graph.dependents_of(cell) {
            if dependent.uses_types_from(cell) {
                affected.push(dependent.id);
                queue.push_back(dependent.id);
            }
        }
    }
    affected
}

// 以下は型定義のプレースホルダー
pub struct CellId(pub u64);
pub struct DependencyGraph {
    // 依存関係グラフのデータ
}

pub struct Dependent {
    pub id: CellId,
}

impl DependencyGraph {
    pub fn dependents_of(&self, _cell: CellId) -> impl Iterator<Item = Dependent> {
        std::iter::empty()
    }
}

impl Dependent {
    pub fn uses_types_from(&self, _cell: CellId) -> bool {
        false
    }
}
