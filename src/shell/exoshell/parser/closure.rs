// ============================================================================
// src/shell/exoshell/parser/closure.rs - Closure Expression Types
// ============================================================================

use alloc::string::String;
use alloc::vec::Vec;

/// 論理演算子
#[derive(Debug, Clone, PartialEq)]
pub enum LogicalOp {
    /// AND (&&)
    And,
    /// OR (||)
    Or,
}

/// クロージャ式の単一条件
/// 例: e.size > 1024 -> { field: "size", op: ">", value: "1024" }
#[derive(Debug, Clone)]
pub struct ClosureCondition {
    /// フィールド名（size, name, type など）
    pub field: String,
    /// 演算子（>, <, ==, contains など）
    pub op: String,
    /// 比較値
    pub value: String,
}

/// パースされたクロージャ式
/// 例: |e| e.size > 1024 && e.name contains "test"
#[derive(Debug, Clone)]
pub struct ClosureExpr {
    /// パラメータ名（e, item, x など）
    pub param: String,
    /// 条件のリスト
    pub conditions: Vec<ClosureCondition>,
    /// 条件間の論理演算子
    pub logical_op: LogicalOp,
}
