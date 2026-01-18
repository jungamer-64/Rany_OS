// ============================================================================
// src/shell/exoshell/parser/eval.rs - AST Evaluation Engine
// ============================================================================
//!
//! # AST 評価エンジン
//!
//! 抽象構文木 (AST) を評価して `ExoValue` に変換する。
//! フィルタ式やクロージャの評価に使用。

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use super::ast::{BinaryOp, Expr, UnaryOp};
use crate::shell::exoshell::types::*;

/// AST 評価コンテキスト
///
/// クロージャのパラメータなど、変数の解決に使用。
pub struct EvalContext<'a> {
    /// クロージャパラメータ名（例: "e"）
    pub param_name: Option<&'a str>,
    /// クロージャパラメータの値
    pub param_value: Option<&'a ExoValue<'a>>,
    /// 暗黙のターゲット（`size` などの識別子をフィールドとして検索する対象）
    pub target: Option<&'a ExoValue<'a>>,
}

impl<'a> EvalContext<'a> {
    /// 空のコンテキストを作成
    pub fn empty() -> Self {
        Self {
            param_name: None,
            param_value: None,
            target: None,
        }
    }

    /// クロージャコンテキストを作成
    pub fn with_param(name: &'a str, value: &'a ExoValue<'a>) -> Self {
        Self {
            param_name: Some(name),
            param_value: Some(value),
            target: None,
        }
    }

    /// ターゲットを持つコンテキストを作成（暗黙のフィールドアクセス用）
    pub fn with_target(value: &'a ExoValue<'a>) -> Self {
        Self {
            param_name: None,
            param_value: None,
            target: Some(value),
        }
    }
}

/// AST を評価 (最大深度チェック付き)
pub fn eval_expr<'a>(expr: &Expr<'a>, ctx: &EvalContext<'a>) -> ExoValue<'a> {
    eval_expr_with_depth(expr, ctx, 0)
}

fn eval_expr_with_depth<'a>(expr: &Expr<'a>, ctx: &EvalContext<'a>, depth: usize) -> ExoValue<'a> {
    if depth > 256 {
        return ExoValue::Error("Stack overflow: expression too complex".into());
    }

    match expr {
        // リテラル値はそのまま返す
        // リテラルがCow::Ownedなら、cloneしてもOwned。
        Expr::Literal(val) => val.clone(),

        // 識別子の解決
        Expr::Ident(name) => {
            // 1. 予約キーワード
            match name.as_str() {
                "true" => return ExoValue::Bool(true),
                "false" => return ExoValue::Bool(false),
                "nil" => return ExoValue::Nil,
                _ => {}
            }

            // 2. クロージャパラメータと一致するか
            if let (Some(param_name), Some(param_value)) = (ctx.param_name, ctx.param_value) {
                if name == param_name {
                    return param_value.clone();
                }
            }

            // 3. 暗黙のターゲットのフィールドとして検索
            if let Some(target) = ctx.target {
                let val = get_field(target, name);
                if !matches!(val, ExoValue::Error(_)) {
                    return val;
                }
            }

            ExoValue::Error(format!("Unknown identifier: '{}'", name))
        }

        // フィールドアクセス
        Expr::FieldAccess { object, field } => {
            let obj = eval_expr_with_depth(object, ctx, depth + 1);
            get_field(&obj, field)
        }

        // メソッド呼び出し
        Expr::MethodCall {
            object,
            method,
            args,
        } => {
            let obj = eval_expr_with_depth(object, ctx, depth + 1);
            let evaluated_args: Vec<ExoValue<'a>> = args
                .iter()
                .map(|arg| eval_expr_with_depth(arg, ctx, depth + 1))
                .collect();

            apply_method(&obj, method, &evaluated_args)
        }

        // 二項演算
        Expr::Binary { left, op, right } => {
            let l = eval_expr_with_depth(left, ctx, depth + 1);
            let r = eval_expr_with_depth(right, ctx, depth + 1);
            eval_binary_op(&l, *op, &r)
        }

        // 単項演算
        Expr::Unary { op, operand } => {
            let val = eval_expr_with_depth(operand, ctx, depth + 1);
            eval_unary_op(*op, &val)
        }

        // グループ（括弧）
        Expr::Group(inner) => eval_expr_with_depth(inner, ctx, depth + 1),

        // 配列リテラル
        Expr::Array(elements) => {
            let values: Vec<ExoValue<'a>> = elements
                .iter()
                .map(|e| eval_expr_with_depth(e, ctx, depth + 1))
                .collect();
            ExoValue::Array(values)
        }

        // インデックスアクセス
        Expr::Index { object, index } => {
            let obj = eval_expr_with_depth(object, ctx, depth + 1);
            let idx = eval_expr_with_depth(index, ctx, depth + 1);

            match (&obj, &idx) {
                (ExoValue::Array(arr), ExoValue::Int(i)) => {
                    let i = *i as usize;
                    if i < arr.len() {
                        arr[i].clone()
                    } else {
                        ExoValue::Error(format!("Index {} out of bounds (len={})", i, arr.len()))
                    }
                }
                (ExoValue::String(s), ExoValue::Int(i)) => {
                    let i = *i as usize;
                    if let Some(c) = s.chars().nth(i) {
                        ExoValue::String(Cow::Owned(c.to_string()))
                    } else {
                        ExoValue::Error(format!("String index {} out of bounds", i))
                    }
                }
                _ => ExoValue::Error(format!("Cannot index {:?} with {:?}", obj, idx)),
            }
        }

        // マップリテラル
        Expr::Map(pairs) => {
            let mut map = alloc::collections::BTreeMap::new();
            for (key, value_expr) in pairs.iter() {
                let value = eval_expr_with_depth(value_expr, ctx, depth + 1);
                map.insert(key.clone(), value);
            }
            ExoValue::Map(map)
        }

        // クロージャ（遅延評価のため、ここでは本体を評価しない）
        Expr::Closure { param, body: _ } => ExoValue::Error(format!(
            "Closure '|{}|' cannot be directly evaluated",
            param
        )),

        // 制御構造は eval.rs (コンテキストなし式評価) ではサポートしない
        // これらは shell.rs (ステートフル環境) で処理されるべき
        Expr::Block(_) | Expr::If { .. } | Expr::For { .. } => ExoValue::Error(
            "Control flow expressions are not supported in pure expression context".to_string()
        ),
    }
}

/// クロージャ式を評価（フィルタ等で使用）
pub fn eval_closure<'a>(closure: &'a Expr<'a>, item: &'a ExoValue<'a>) -> ExoValue<'a> {
    match closure {
        Expr::Closure { param, body } => {
            let ctx = EvalContext::with_param(param, item);
            eval_expr(body, &ctx)
        }
        // クロージャでない場合は通常の式として評価（ターゲットを設定）
        _ => {
            let ctx = EvalContext::with_target(item);
            eval_expr(closure, &ctx)
        }
    }
}

/// クロージャ式を真偽値として評価
pub fn eval_closure_as_bool<'a>(closure: &Expr<'a>, item: &ExoValue<'a>) -> bool {
    match eval_closure(closure, item) {
        ExoValue::Bool(b) => b,
        ExoValue::Int(n) => n != 0,
        ExoValue::String(s) => !s.is_empty(),
        ExoValue::Nil => false,
        ExoValue::Error(_) => false,
        _ => true,
    }
}

// ============================================================================
// Field Access
// ============================================================================

/// フィールドアクセス
pub fn get_field<'a>(value: &ExoValue<'a>, field: &str) -> ExoValue<'a> {
    match value {
        ExoValue::FileEntry(entry) => match field {
            "name" => ExoValue::String(Cow::Owned(entry.name.clone())),
            "path" => ExoValue::String(Cow::Owned(entry.path.clone())),
            "size" => ExoValue::Int(entry.size as i64),
            "type" => ExoValue::String(Cow::Owned(format!("{:?}", entry.file_type))),
            "owner" => ExoValue::String(Cow::Owned(entry.owner.clone())),
            "created" => ExoValue::Int(entry.created as i64),
            "modified" => ExoValue::Int(entry.modified as i64),
            "inode" => ExoValue::Int(entry.inode as i64),
            _ => ExoValue::Error(format!("FileEntry has no field '{}'", field)),
        },

        ExoValue::Domain(domain) => match field {
            "id" => ExoValue::Int(domain.id as i64),
            "name" => ExoValue::String(Cow::Owned(domain.name.clone())),
            "state" => ExoValue::String(Cow::Owned(format!("{:?}", domain.state))),
            "tasks" => ExoValue::Int(domain.tasks as i64),
            "memory" | "memory_kb" => ExoValue::Int(domain.memory_kb as i64),
            "rrefs" => ExoValue::Int(domain.rrefs as i64),
            "last_error" => domain
                .last_error
                .as_ref()
                .map(|e| ExoValue::String(Cow::Owned(e.clone())))
                .unwrap_or(ExoValue::Nil),
            _ => ExoValue::Error(format!("Domain has no field '{}'", field)),
        },

        ExoValue::NetConnection(conn) => match field {
            "protocol" => ExoValue::String(Cow::Owned(conn.protocol.clone())),
            "local_port" => ExoValue::Int(conn.local_port as i64),
            "remote_port" => ExoValue::Int(conn.remote_port as i64),
            "state" => ExoValue::String(Cow::Owned(conn.state.clone())),
            "rx_bytes" => ExoValue::Int(conn.rx_bytes as i64),
            "tx_bytes" => ExoValue::Int(conn.tx_bytes as i64),
            _ => ExoValue::Error(format!("NetConnection has no field '{}'", field)),
        },

        ExoValue::Capability(cap) => match field {
            "id" => ExoValue::Int(cap.id as i64),
            "resource" => ExoValue::String(Cow::Owned(cap.resource.clone())),
            "issuer" => ExoValue::String(Cow::Owned(cap.issuer.clone())),
            "delegatable" => ExoValue::Bool(cap.delegatable),
            _ => ExoValue::Error(format!("Capability has no field '{}'", field)),
        },

        ExoValue::Map(map) => map.get(field).cloned().unwrap_or(ExoValue::Nil),

        _ => ExoValue::Error(format!("Value does not support field access")),
    }
}

// ============================================================================
// Method Application
// ============================================================================

/// メソッド適用
fn apply_method<'a>(value: &ExoValue<'a>, method: &str, args: &[ExoValue<'a>]) -> ExoValue<'a> {
    match value {
        ExoValue::String(s) => apply_string_method(s, method, args),
        _ => ExoValue::Error(format!("Method '{}' not supported on this type", method)),
    }
}

/// 文字列メソッド
fn apply_string_method<'a>(s: &str, method: &str, args: &[ExoValue<'a>]) -> ExoValue<'a> {
    match method {
        "len" | "length" => ExoValue::Int(s.len() as i64),

        "contains" => {
            let pattern = args
                .first()
                .and_then(|v| match v {
                    ExoValue::String(p) => Some(p.as_ref()),
                    _ => None,
                })
                .unwrap_or("");
            ExoValue::Bool(s.contains(pattern))
        }

        "starts_with" => {
            let pattern = args
                .first()
                .and_then(|v| match v {
                    ExoValue::String(p) => Some(p.as_ref()),
                    _ => None,
                })
                .unwrap_or("");
            ExoValue::Bool(s.starts_with(pattern))
        }

        "ends_with" => {
            let pattern = args
                .first()
                .and_then(|v| match v {
                    ExoValue::String(p) => Some(p.as_ref()),
                    _ => None,
                })
                .unwrap_or("");
            ExoValue::Bool(s.ends_with(pattern))
        }

        "to_lower" | "lowercase" => ExoValue::String(Cow::Owned(s.to_ascii_lowercase())),
        "to_upper" | "uppercase" => ExoValue::String(Cow::Owned(s.to_ascii_uppercase())),

        _ => ExoValue::Error(format!("String has no method '{}'", method)),
    }
}

// ============================================================================
// Binary Operations
// ============================================================================

/// 二項演算の評価
pub fn eval_binary_op<'a>(left: &ExoValue<'a>, op: BinaryOp, right: &ExoValue<'a>) -> ExoValue<'a> {
    match op {
        // パイプ演算子（実際の評価は shell.rs で行う）
        BinaryOp::Pipe => {
            // パイプは eval.rs では評価できない（右辺を関数として扱う必要がある）
            // shell.rs の evaluate_expr で特別処理される
            ExoValue::Error("Pipe operator must be evaluated in shell context".into())
        }

        // 論理演算
        BinaryOp::And => eval_logical_and(left, right),
        BinaryOp::Or => eval_logical_or(left, right),

        // 比較演算
        BinaryOp::Eq => ExoValue::Bool(values_equal(left, right)),
        BinaryOp::Ne => ExoValue::Bool(!values_equal(left, right)),
        BinaryOp::Lt => eval_comparison(left, right, |a, b| a < b),
        BinaryOp::Le => eval_comparison(left, right, |a, b| a <= b),
        BinaryOp::Gt => eval_comparison(left, right, |a, b| a > b),
        BinaryOp::Ge => eval_comparison(left, right, |a, b| a >= b),

        // 文字列比較
        BinaryOp::Contains => eval_string_op(left, right, |s, p| s.contains(p)),
        BinaryOp::StartsWith => eval_string_op(left, right, |s, p| s.starts_with(p)),
        BinaryOp::EndsWith => eval_string_op(left, right, |s, p| s.ends_with(p)),

        // 算術演算
        BinaryOp::Add => eval_arithmetic(left, right, |a, b| a + b, |a, b| a + b),
        BinaryOp::Sub => eval_arithmetic(left, right, |a, b| a - b, |a, b| a - b),
        BinaryOp::Mul => eval_arithmetic(left, right, |a, b| a * b, |a, b| a * b),
        BinaryOp::Div => eval_division(left, right),
        BinaryOp::Mod => eval_modulo(left, right),
    }
}

/// 論理AND
fn eval_logical_and<'a>(left: &ExoValue<'a>, right: &ExoValue<'a>) -> ExoValue<'a> {
    let l = to_bool(left);
    if !l {
        return ExoValue::Bool(false);
    }
    ExoValue::Bool(to_bool(right))
}

/// 論理OR
fn eval_logical_or<'a>(left: &ExoValue<'a>, right: &ExoValue<'a>) -> ExoValue<'a> {
    let l = to_bool(left);
    if l {
        return ExoValue::Bool(true);
    }
    ExoValue::Bool(to_bool(right))
}

/// 値を真偽値に変換
fn to_bool(value: &ExoValue) -> bool {
    match value {
        ExoValue::Bool(b) => *b,
        ExoValue::Int(n) => *n != 0,
        ExoValue::Float(f) => *f != 0.0,
        ExoValue::String(s) => !s.is_empty(),
        ExoValue::Nil => false,
        ExoValue::Error(_) => false,
        _ => true,
    }
}

/// 値の等価比較
fn values_equal(left: &ExoValue, right: &ExoValue) -> bool {
    match (left, right) {
        (ExoValue::Int(a), ExoValue::Int(b)) => a == b,
        (ExoValue::Float(a), ExoValue::Float(b)) => (a - b).abs() < f64::EPSILON,
        (ExoValue::Int(a), ExoValue::Float(b)) | (ExoValue::Float(b), ExoValue::Int(a)) => {
            (*a as f64 - b).abs() < f64::EPSILON
        }
        (ExoValue::String(a), ExoValue::String(b)) => a == b,
        (ExoValue::Bool(a), ExoValue::Bool(b)) => a == b,
        (ExoValue::Nil, ExoValue::Nil) => true,
        _ => false,
    }
}

/// 数値比較
fn eval_comparison<F>(left: &ExoValue, right: &ExoValue, f: F) -> ExoValue<'static>
where
    F: Fn(f64, f64) -> bool,
{
    match (left, right) {
        (ExoValue::Int(a), ExoValue::Int(b)) => ExoValue::Bool(f(*a as f64, *b as f64)),
        (ExoValue::Float(a), ExoValue::Float(b)) => ExoValue::Bool(f(*a, *b)),
        (ExoValue::Int(a), ExoValue::Float(b)) => ExoValue::Bool(f(*a as f64, *b)),
        (ExoValue::Float(a), ExoValue::Int(b)) => ExoValue::Bool(f(*a, *b as f64)),
        _ => ExoValue::Error(format!("Cannot compare values")),
    }
}

/// 文字列演算
fn eval_string_op<F>(left: &ExoValue, right: &ExoValue, f: F) -> ExoValue<'static>
where
    F: Fn(&str, &str) -> bool,
{
    match (left, right) {
        (ExoValue::String(a), ExoValue::String(b)) => ExoValue::Bool(f(a, b)),
        _ => ExoValue::Error(format!("String operation requires string operands")),
    }
}

/// 算術演算
fn eval_arithmetic<Fi, Ff>(left: &ExoValue, right: &ExoValue, fi: Fi, ff: Ff) -> ExoValue<'static>
where
    Fi: Fn(i64, i64) -> i64,
    Ff: Fn(f64, f64) -> f64,
{
    match (left, right) {
        (ExoValue::Int(a), ExoValue::Int(b)) => ExoValue::Int(fi(*a, *b)),
        (ExoValue::Float(a), ExoValue::Float(b)) => ExoValue::Float(ff(*a, *b)),
        (ExoValue::Int(a), ExoValue::Float(b)) => ExoValue::Float(ff(*a as f64, *b)),
        (ExoValue::Float(a), ExoValue::Int(b)) => ExoValue::Float(ff(*a, *b as f64)),
        _ => ExoValue::Error(format!("Cannot perform arithmetic")),
    }
}

/// 除算（ゼロ除算チェック付き）
fn eval_division(left: &ExoValue, right: &ExoValue) -> ExoValue<'static> {
    match (left, right) {
        (ExoValue::Int(a), ExoValue::Int(b)) => {
            if *b == 0 {
                ExoValue::Error(format!("Division by zero"))
            } else {
                ExoValue::Int(a / b)
            }
        }
        (ExoValue::Float(a), ExoValue::Float(b)) => ExoValue::Float(a / b),
        (ExoValue::Int(a), ExoValue::Float(b)) => ExoValue::Float(*a as f64 / b),
        (ExoValue::Float(a), ExoValue::Int(b)) => ExoValue::Float(a / *b as f64),
        _ => ExoValue::Error(format!("Cannot divide")),
    }
}

/// 剰余演算
fn eval_modulo(left: &ExoValue, right: &ExoValue) -> ExoValue<'static> {
    match (left, right) {
        (ExoValue::Int(a), ExoValue::Int(b)) => {
            if *b == 0 {
                ExoValue::Error(format!("Modulo by zero"))
            } else {
                ExoValue::Int(a % b)
            }
        }
        (ExoValue::Float(a), ExoValue::Float(b)) => ExoValue::Float(a % b),
        (ExoValue::Int(a), ExoValue::Float(b)) => ExoValue::Float(*a as f64 % b),
        (ExoValue::Float(a), ExoValue::Int(b)) => ExoValue::Float(a % *b as f64),
        _ => ExoValue::Error(format!("Cannot compute modulo")),
    }
}

// ============================================================================
// Unary Operations
// ============================================================================

/// 単項演算の評価
pub fn eval_unary_op<'a>(op: UnaryOp, value: &ExoValue<'a>) -> ExoValue<'a> {
    match op {
        UnaryOp::Not => ExoValue::Bool(!to_bool(value)),
        UnaryOp::Neg => match value {
            ExoValue::Int(n) => ExoValue::Int(-n),
            ExoValue::Float(f) => ExoValue::Float(-f),
            _ => ExoValue::Error(format!("Cannot negate value")),
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::expr_parser::parse_expression;
    use super::*;

    #[test_case]
    fn test_eval_literal() {
        let expr = parse_expression("42").unwrap();
        let ctx = EvalContext::empty();
        let result = eval_expr(&expr, &ctx);
        assert!(matches!(result, ExoValue::Int(42)));
    }

    #[test_case]
    fn test_eval_comparison() {
        let expr = parse_expression("100 > 50").unwrap();
        let ctx = EvalContext::empty();
        let result = eval_expr(&expr, &ctx);
        assert!(matches!(result, ExoValue::Bool(true)));
    }

    #[test_case]
    fn test_eval_arithmetic() {
        let expr = parse_expression("10 + 5 * 2").unwrap();
        let ctx = EvalContext::empty();
        let result = eval_expr(&expr, &ctx);
        // Should be 10 + (5 * 2) = 20 due to operator precedence
        assert!(matches!(result, ExoValue::Int(20)));
    }

    #[test_case]
    fn test_eval_logical() {
        let expr = parse_expression("true && false").unwrap();
        let ctx = EvalContext::empty();
        let result = eval_expr(&expr, &ctx);
        assert!(matches!(result, ExoValue::Bool(false)));
    }
}

