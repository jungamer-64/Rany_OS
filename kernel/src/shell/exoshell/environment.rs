// ============================================================================
// kernel/src/shell/exoshell/environment.rs
// ============================================================================

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use crate::shell::exoshell::types::ExoValue;

/// 変数環境（スコープ対応）
pub struct Environment {
    /// スコープスタック (最後が現在のスコープ)
    scopes: Vec<BTreeMap<String, ExoValue<'static>>>,
}

impl Environment {
    /// 新しい環境を作成（グローバルスコープのみ）
    pub fn new() -> Self {
        let mut scopes = Vec::new();
        scopes.push(BTreeMap::new());
        Self { scopes }
    }

    /// 新しいスコープに入る
    pub fn push_scope(&mut self) {
        self.scopes.push(BTreeMap::new());
    }

    /// 現在のスコープから出る
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// 変数を定義（現在のスコープ）
    pub fn define(&mut self, name: impl Into<String>, value: ExoValue<'static>) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.into(), value);
        }
    }

    /// 変数を取得（内側から外側へ検索）
    pub fn get(&self, name: &str) -> Option<&ExoValue<'static>> {
        for scope in self.scopes.iter().rev() {
            if let Some(val) = scope.get(name) {
                return Some(val);
            }
        }
        None
    }

    /// 変数を更新（内側から外側へ検索）
    /// 存在しなければfalseを返す
    pub fn assign(&mut self, name: &str, value: ExoValue<'static>) -> bool {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.into(), value);
                return true;
            }
        }
        false
    }
    
    /// 全ての変数を取得（デバッグ用）
    pub fn get_all(&self) -> BTreeMap<String, ExoValue<'static>> {
        let mut result = BTreeMap::new();
        for scope in &self.scopes {
            for (k, v) in scope {
                result.insert(k.clone(), v.clone());
            }
        }
        result
    }
}
