// ============================================================================
// src/shell/exoshell/parser/ast.rs - Abstract Syntax Tree
// ============================================================================
//!
//! # 抽象構文木 (AST)
//!
//! 式（Expression）を木構造で表現し、演算子優先順位を正しく処理。
//! 遅延評価やコンパイル時最適化の基盤となる。
//!
//! ## 演算子優先順位 (低→高)
//!
//! 1. `||` (論理OR)
//! 2. `&&` (論理AND)  
//! 3. `==`, `!=`, `<`, `<=`, `>`, `>=`, `contains` (比較)
//! 4. `+`, `-` (加減算)
//! 5. `*`, `/`, `%` (乗除算)
//! 6. `!`, `-` (単項演算子)
//!
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::exoshell::types::ExoValue;

// ============================================================================
// Expression AST
// ============================================================================

/// 抽象構文木 (AST) のノード
///
/// 式を木構造で表現し、演算子優先順位を正しく処理する。
///
/// # Example
///
/// `size > 1024 && name.contains("log")` は以下のように表現される:
///
/// ```text
///         Binary(And)
///        /          \
///   Binary(Gt)    MethodCall
///   /      \       /    \
/// Ident  Literal Ident  Literal
/// "size"  1024   "name"  "log"
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Expr<'a> {
    /// リテラル値 (数値、文字列、真偽値など)
    Literal(ExoValue<'a>),

    /// 識別子（変数参照）
    /// 例: `size`, `name`, `e`
    Ident(String),

    /// フィールドアクセス
    /// 例: `e.size`, `file.name`
    FieldAccess {
        object: Box<Expr<'a>>,
        field: String,
    },

    /// メソッド呼び出し
    /// 例: `name.contains("log")`, `list.filter(predicate)`
    MethodCall {
        object: Box<Expr<'a>>,
        method: String,
        args: Vec<Expr<'a>>,
    },

    /// 二項演算
    /// 例: `a + b`, `size > 1024`, `a && b`
    Binary {
        left: Box<Expr<'a>>,
        op: BinaryOp,
        right: Box<Expr<'a>>,
    },

    /// 単項演算
    /// 例: `!valid`, `-count`
    Unary { op: UnaryOp, operand: Box<Expr<'a>> },

    /// 括弧によるグループ化
    /// 例: `(a || b) && c`
    Group(Box<Expr<'a>>),

    /// クロージャ式（ラムダ）
    /// 例: `|e| e.size > 1024`
    Closure { param: String, body: Box<Expr<'a>> },

    /// 配列リテラル
    /// 例: `[1, 2, 3]`, `["a", "b"]`
    Array(Vec<Expr<'a>>),

    /// インデックスアクセス
    /// 例: `arr[0]`, `list[i]`
    Index {
        object: Box<Expr<'a>>,
        index: Box<Expr<'a>>,
    },

    /// マップリテラル
    /// 例: `{name: "foo", value: 42}`
    Map(Vec<(String, Expr<'a>)>),
}

// ============================================================================
// Binary Operators
// ============================================================================

/// 二項演算子
///
/// 優先順位順（低→高）で定義:
/// 1. Logical: Or, And
/// 2. Comparison: Eq, Ne, Lt, Le, Gt, Ge, Contains, StartsWith, EndsWith
/// 3. Additive: Add, Sub
/// 4. Multiplicative: Mul, Div, Mod
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    // -------------------------------------------------------------------------
    // Pipe operator (優先順位: 最低)
    // -------------------------------------------------------------------------
    /// Pipe: `a |> f()`
    Pipe,

    // -------------------------------------------------------------------------
    // Logical operators (優先順位: 低)
    // -------------------------------------------------------------------------
    /// Logical OR: `a || b`
    Or,
    /// Logical AND: `a && b`
    And,

    // -------------------------------------------------------------------------
    // Comparison operators (優先順位: 中)
    // -------------------------------------------------------------------------
    /// Equal: `a == b`
    Eq,
    /// Not equal: `a != b`
    Ne,
    /// Less than: `a < b`
    Lt,
    /// Less than or equal: `a <= b`
    Le,
    /// Greater than: `a > b`
    Gt,
    /// Greater than or equal: `a >= b`
    Ge,
    /// String contains: `name.contains("log")`
    Contains,
    /// String starts with: `name.starts_with("test")`
    StartsWith,
    /// String ends with: `name.ends_with(".rs")`
    EndsWith,

    // -------------------------------------------------------------------------
    // Arithmetic operators (優先順位: 高)
    // -------------------------------------------------------------------------
    /// Addition: `a + b`
    Add,
    /// Subtraction: `a - b`
    Sub,
    /// Multiplication: `a * b`
    Mul,
    /// Division: `a / b`
    Div,
    /// Modulo: `a % b`
    Mod,
}

impl BinaryOp {
    /// 演算子の優先順位を返す（数値が大きいほど優先順位が高い）
    ///
    /// 優先順位レベル:
    /// - 1: Or
    /// - 2: And
    /// - 3: Comparison (Eq, Ne, Lt, Le, Gt, Ge, Contains, StartsWith, EndsWith)
    /// - 4: Additive (Add, Sub)
    /// - 5: Multiplicative (Mul, Div, Mod)
    #[must_use]
    pub const fn precedence(self) -> u8 {
        match self {
            Self::Pipe => 0,
            Self::Or => 1,
            Self::And => 2,
            Self::Eq
            | Self::Ne
            | Self::Lt
            | Self::Le
            | Self::Gt
            | Self::Ge
            | Self::Contains
            | Self::StartsWith
            | Self::EndsWith => 3,
            Self::Add | Self::Sub => 4,
            Self::Mul | Self::Div | Self::Mod => 5,
        }
    }

    /// 演算子が左結合かどうか
    ///
    /// ほとんどの二項演算子は左結合（`a + b + c` = `(a + b) + c`）
    #[must_use]
    pub const fn is_left_associative(self) -> bool {
        true // 全て左結合
    }

    /// 文字列から BinaryOp への変換を試みる
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "|>" => Some(Self::Pipe),
            "||" => Some(Self::Or),
            "&&" => Some(Self::And),
            "==" => Some(Self::Eq),
            "!=" => Some(Self::Ne),
            "<" => Some(Self::Lt),
            "<=" => Some(Self::Le),
            ">" => Some(Self::Gt),
            ">=" => Some(Self::Ge),
            "contains" => Some(Self::Contains),
            "starts_with" => Some(Self::StartsWith),
            "ends_with" => Some(Self::EndsWith),
            "+" => Some(Self::Add),
            "-" => Some(Self::Sub),
            "*" => Some(Self::Mul),
            "/" => Some(Self::Div),
            "%" => Some(Self::Mod),
            _ => None,
        }
    }

    /// BinaryOp を文字列表現に変換
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pipe => "|>",
            Self::Or => "||",
            Self::And => "&&",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Contains => "contains",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
        }
    }
}

// ============================================================================
// Unary Operators
// ============================================================================

/// 単項演算子
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// Logical NOT: `!a`
    Not,
    /// Negation: `-a`
    Neg,
}

impl UnaryOp {
    /// 文字列から UnaryOp への変換を試みる
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "!" => Some(Self::Not),
            "-" => Some(Self::Neg),
            _ => None,
        }
    }

    /// UnaryOp を文字列表現に変換
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Not => "!",
            Self::Neg => "-",
        }
    }
}

// ============================================================================
// Helper Constructors
// ============================================================================

impl<'a> Expr<'a> {
    /// リテラル整数を作成
    #[inline]
    pub fn int(n: i64) -> Self {
        Self::Literal(ExoValue::Int(n))
    }

    /// リテラル浮動小数点を作成
    #[inline]
    pub fn float(f: f64) -> Self {
        Self::Literal(ExoValue::Float(f))
    }

    /// リテラル文字列を作成
    #[inline]
    pub fn string(s: impl Into<String>) -> Self {
        Self::Literal(ExoValue::String(Cow::Owned(s.into())))
    }

    /// リテラル真偽値を作成
    #[inline]
    pub fn bool(b: bool) -> Self {
        Self::Literal(ExoValue::Bool(b))
    }

    /// 識別子を作成
    #[inline]
    pub fn ident(name: impl Into<String>) -> Self {
        Self::Ident(name.into())
    }

    /// フィールドアクセスを作成
    #[inline]
    pub fn field(object: Expr<'a>, field: impl Into<String>) -> Self {
        Self::FieldAccess {
            object: Box::new(object),
            field: field.into(),
        }
    }

    /// 二項演算を作成
    #[inline]
    pub fn binary(left: Expr<'a>, op: BinaryOp, right: Expr<'a>) -> Self {
        Self::Binary {
            left: Box::new(left),
            op,
            right: Box::new(right),
        }
    }

    /// 単項演算を作成
    #[inline]
    pub fn unary(op: UnaryOp, operand: Expr<'a>) -> Self {
        Self::Unary {
            op,
            operand: Box::new(operand),
        }
    }

    /// グループ（括弧）を作成
    #[inline]
    pub fn group(inner: Expr<'a>) -> Self {
        Self::Group(Box::new(inner))
    }

    /// クロージャを作成
    #[inline]
    pub fn closure(param: impl Into<String>, body: Expr<'a>) -> Self {
        Self::Closure {
            param: param.into(),
            body: Box::new(body),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_op_precedence() {
        assert!(BinaryOp::Mul.precedence() > BinaryOp::Add.precedence());
        assert!(BinaryOp::Add.precedence() > BinaryOp::Gt.precedence());
        assert!(BinaryOp::Gt.precedence() > BinaryOp::And.precedence());
        assert!(BinaryOp::And.precedence() > BinaryOp::Or.precedence());
    }

    #[test]
    fn test_binary_op_from_str() {
        assert_eq!(BinaryOp::from_str("&&"), Some(BinaryOp::And));
        assert_eq!(BinaryOp::from_str("||"), Some(BinaryOp::Or));
        assert_eq!(BinaryOp::from_str(">"), Some(BinaryOp::Gt));
        assert_eq!(BinaryOp::from_str("invalid"), None);
    }

    #[test]
    fn test_expr_construction() {
        // size > 1024
        let expr = Expr::binary(Expr::ident("size"), BinaryOp::Gt, Expr::int(1024));

        match expr {
            Expr::Binary { left, op, right } => {
                assert_eq!(op, BinaryOp::Gt);
                assert!(matches!(*left, Expr::Ident(ref s) if s == "size"));
                assert!(matches!(*right, Expr::Literal(ExoValue::Int(1024))));
            }
            _ => panic!("Expected Binary expression"),
        }
    }
}
