// ============================================================================
// src/application/browser/script/ast.rs - Abstract Syntax Tree
// ============================================================================
//!
//! # 抽象構文木（AST）
//!
//! RustScriptの構文を表現するAST構造体の定義。

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// AST Root
// ============================================================================

/// プログラム全体を表すAST
#[derive(Debug, Clone)]
pub struct Ast {
    /// トップレベルの文
    pub statements: Vec<Stmt>,
}

impl Ast {
    pub fn new() -> Self {
        Self {
            statements: Vec::new(),
        }
    }

    pub fn push(&mut self, stmt: Stmt) {
        self.statements.push(stmt);
    }
}

impl Default for Ast {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Statements
// ============================================================================

/// 文（Statement）
#[derive(Debug, Clone)]
pub enum Stmt {
    /// 式文: `expr;`
    Expression(Expr),

    /// 変数宣言: `let x = expr;` or `let mut x = expr;`
    Let {
        name: String,
        mutable: bool,
        type_ann: Option<TypeAnnotation>,
        value: Option<Expr>,
    },

    /// 代入文: `x = expr;`
    Assign {
        target: Expr,
        value: Expr,
    },

    /// 複合代入: `x += expr;`
    CompoundAssign {
        target: Expr,
        op: BinaryOp,
        value: Expr,
    },

    /// ブロック: `{ stmts }`
    Block(Vec<Stmt>),

    /// if文: `if cond { ... } else { ... }`
    If {
        condition: Expr,
        then_branch: Box<Stmt>,
        else_branch: Option<Box<Stmt>>,
    },

    /// while文: `while cond { ... }`
    While {
        condition: Expr,
        body: Box<Stmt>,
    },

    /// for文: `for item in iter { ... }`
    For {
        variable: String,
        iterator: Expr,
        body: Box<Stmt>,
    },

    /// loop文: `loop { ... }`
    Loop(Box<Stmt>),

    /// 関数定義: `fn name(params) -> ret { body }`
    Function {
        name: String,
        params: Vec<FunctionParam>,
        return_type: Option<TypeAnnotation>,
        body: Box<Stmt>,
    },

    /// return文: `return expr;`
    Return(Option<Expr>),

    /// break文: `break;`
    Break,

    /// continue文: `continue;`
    Continue,

    /// 構造体定義: `struct Name { fields }`
    Struct {
        name: String,
        fields: Vec<StructField>,
    },

    /// impl ブロック: `impl Name { methods }`
    Impl {
        type_name: String,
        methods: Vec<Stmt>,
    },

    /// match文: `match expr { arms }`
    Match {
        value: Expr,
        arms: Vec<MatchArm>,
    },

    /// 空文
    Empty,
}

/// 関数パラメータ
#[derive(Debug, Clone)]
pub struct FunctionParam {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,
    pub mutable: bool,
}

/// 構造体フィールド
#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub type_ann: TypeAnnotation,
    pub public: bool,
}

/// matchアーム
#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Expr>,
    pub body: Expr,
}

/// パターン
#[derive(Debug, Clone)]
pub enum Pattern {
    /// ワイルドカード: `_`
    Wildcard,
    /// 識別子バインド: `x`
    Identifier(String),
    /// リテラルパターン: `42`, `"hello"`
    Literal(Expr),
    /// タプルパターン: `(a, b, c)`
    Tuple(Vec<Pattern>),
    /// 構造体パターン: `Point { x, y }`
    Struct {
        name: String,
        fields: Vec<(String, Pattern)>,
    },
    /// 列挙型パターン: `Some(x)`
    Enum {
        name: String,
        variant: String,
        fields: Vec<Pattern>,
    },
    /// 範囲パターン: `1..10`
    Range {
        start: Option<Box<Expr>>,
        end: Option<Box<Expr>>,
        inclusive: bool,
    },
    /// Orパターン: `a | b`
    Or(Vec<Pattern>),
}

// ============================================================================
// Expressions
// ============================================================================

/// 式（Expression）
#[derive(Debug, Clone)]
pub enum Expr {
    /// リテラル
    Literal(Literal),

    /// 識別子: `name`
    Identifier(String),

    /// 単項演算: `-x`, `!x`
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
    },

    /// 二項演算: `a + b`
    Binary {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },

    /// 関数呼び出し: `func(args)`
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },

    /// メソッド呼び出し: `obj.method(args)`
    MethodCall {
        object: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },

    /// フィールドアクセス: `obj.field`
    FieldAccess {
        object: Box<Expr>,
        field: String,
    },

    /// インデックスアクセス: `arr[index]`
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
    },

    /// 配列リテラル: `[1, 2, 3]`
    Array(Vec<Expr>),

    /// タプル: `(a, b, c)`
    Tuple(Vec<Expr>),

    /// 構造体リテラル: `Point { x: 1, y: 2 }`
    StructLit {
        name: String,
        fields: Vec<(String, Expr)>,
    },

    /// 範囲式: `1..10`, `1..=10`
    Range {
        start: Option<Box<Expr>>,
        end: Option<Box<Expr>>,
        inclusive: bool,
    },

    /// クロージャ: `|x, y| x + y` or `|x, y| { ... }`
    Closure {
        params: Vec<ClosureParam>,
        body: Box<Expr>,
    },

    /// ブロック式: `{ stmts; expr }`
    Block {
        statements: Vec<Stmt>,
        value: Option<Box<Expr>>,
    },

    /// if式: `if cond { a } else { b }`
    If {
        condition: Box<Expr>,
        then_branch: Box<Expr>,
        else_branch: Option<Box<Expr>>,
    },

    /// match式
    Match {
        value: Box<Expr>,
        arms: Vec<MatchArm>,
    },

    /// パス式: `std::io::println`
    Path(Vec<String>),

    /// 参照: `&expr`, `&mut expr`
    Ref {
        mutable: bool,
        expr: Box<Expr>,
    },

    /// デリファレンス: `*expr`
    Deref(Box<Expr>),

    /// キャスト: `expr as Type`
    Cast {
        expr: Box<Expr>,
        target_type: TypeAnnotation,
    },

    /// await式: `expr.await`
    Await(Box<Expr>),

    /// try式: `expr?`
    Try(Box<Expr>),
}

/// クロージャパラメータ
#[derive(Debug, Clone)]
pub struct ClosureParam {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,
}

// ============================================================================
// Literals
// ============================================================================

/// リテラル値
#[derive(Debug, Clone)]
pub enum Literal {
    /// 整数: `42`, `0xFF`, `0b1010`
    Integer(i64),
    /// 浮動小数点: `3.14`
    Float(f64),
    /// 文字列: `"hello"`
    String(String),
    /// ブール: `true`, `false`
    Bool(bool),
    /// nil
    Nil,
}

// ============================================================================
// Operators
// ============================================================================

/// 単項演算子
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// 負号: `-`
    Neg,
    /// 論理否定: `!`
    Not,
    /// ビット否定: `~` (Rustでは`!`だが区別のため)
    BitNot,
}

/// 二項演算子
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    // 算術
    Add,        // +
    Sub,        // -
    Mul,        // *
    Div,        // /
    Mod,        // %

    // 比較
    Eq,         // ==
    NotEq,      // !=
    Lt,         // <
    LtEq,       // <=
    Gt,         // >
    GtEq,       // >=

    // 論理
    And,        // &&
    Or,         // ||

    // ビット演算
    BitAnd,     // &
    BitOr,      // |
    BitXor,     // ^
    Shl,        // <<
    Shr,        // >>
}

impl BinaryOp {
    /// 演算子の優先順位を返す（高いほど優先）
    pub fn precedence(&self) -> u8 {
        match self {
            BinaryOp::Or => 1,
            BinaryOp::And => 2,
            BinaryOp::BitOr => 3,
            BinaryOp::BitXor => 4,
            BinaryOp::BitAnd => 5,
            BinaryOp::Eq | BinaryOp::NotEq => 6,
            BinaryOp::Lt | BinaryOp::LtEq | BinaryOp::Gt | BinaryOp::GtEq => 7,
            BinaryOp::Shl | BinaryOp::Shr => 8,
            BinaryOp::Add | BinaryOp::Sub => 9,
            BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => 10,
        }
    }
}

// ============================================================================
// Type Annotations
// ============================================================================

/// 型アノテーション
#[derive(Debug, Clone)]
pub enum TypeAnnotation {
    /// 単純型: `i32`, `String`
    Simple(String),

    /// ジェネリック型: `Vec<T>`, `Option<T>`
    Generic {
        name: String,
        params: Vec<TypeAnnotation>,
    },

    /// 配列型: `[T; N]`
    Array {
        element: Box<TypeAnnotation>,
        size: Option<usize>,
    },

    /// スライス型: `[T]`
    Slice(Box<TypeAnnotation>),

    /// タプル型: `(T1, T2, T3)`
    Tuple(Vec<TypeAnnotation>),

    /// 関数型: `fn(T1, T2) -> R`
    Function {
        params: Vec<TypeAnnotation>,
        return_type: Box<TypeAnnotation>,
    },

    /// 参照型: `&T`, `&mut T`
    Reference {
        mutable: bool,
        inner: Box<TypeAnnotation>,
    },

    /// オプション型: `T?` (sugar for Option<T>)
    Optional(Box<TypeAnnotation>),

    /// 推論型: `_`
    Inferred,
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_creation() {
        let mut ast = Ast::new();
        ast.push(Stmt::Expression(Expr::Literal(Literal::Integer(42))));
        assert_eq!(ast.statements.len(), 1);
    }

    #[test]
    fn test_binary_op_precedence() {
        assert!(BinaryOp::Mul.precedence() > BinaryOp::Add.precedence());
        assert!(BinaryOp::And.precedence() > BinaryOp::Or.precedence());
    }
}
