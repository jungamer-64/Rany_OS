// ============================================================================
// src/application/browser/script/vm/ops.rs - Arithmetic and Comparison Operations
// ============================================================================
//!
//! 算術演算と比較演算のヘルパー関数。

use super::super::value::ScriptValue;
use super::super::{ErrorKind, ScriptError};

/// 加算演算
pub fn op_add(a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
    match (a, b) {
        (ScriptValue::Int(a), ScriptValue::Int(b)) => Ok(ScriptValue::Int(a + b)),
        (ScriptValue::Float(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a + b)),
        (ScriptValue::Int(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a as f64 + b)),
        (ScriptValue::Float(a), ScriptValue::Int(b)) => Ok(ScriptValue::Float(a + b as f64)),
        (ScriptValue::String(a), ScriptValue::String(b)) => {
            let mut result = a;
            result.push_str(&b);
            Ok(ScriptValue::String(result))
        }
        (ScriptValue::String(a), b) => {
            let mut result = a;
            result.push_str(&b.to_string_value());
            Ok(ScriptValue::String(result))
        }
        _ => Ok(ScriptValue::Nil),
    }
}

/// 減算演算
pub fn op_sub(a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
    match (a, b) {
        (ScriptValue::Int(a), ScriptValue::Int(b)) => Ok(ScriptValue::Int(a - b)),
        (ScriptValue::Float(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a - b)),
        (ScriptValue::Int(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a as f64 - b)),
        (ScriptValue::Float(a), ScriptValue::Int(b)) => Ok(ScriptValue::Float(a - b as f64)),
        _ => Ok(ScriptValue::Nil),
    }
}

/// 乗算演算
pub fn op_mul(a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
    match (a, b) {
        (ScriptValue::Int(a), ScriptValue::Int(b)) => Ok(ScriptValue::Int(a * b)),
        (ScriptValue::Float(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a * b)),
        (ScriptValue::Int(a), ScriptValue::Float(b)) => Ok(ScriptValue::Float(a as f64 * b)),
        (ScriptValue::Float(a), ScriptValue::Int(b)) => Ok(ScriptValue::Float(a * b as f64)),
        _ => Ok(ScriptValue::Nil),
    }
}

/// 除算演算
pub fn op_div(a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
    match (a, b) {
        (ScriptValue::Int(a), ScriptValue::Int(b)) => {
            if b == 0 {
                return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
            }
            Ok(ScriptValue::Int(a / b))
        }
        (ScriptValue::Float(a), ScriptValue::Float(b)) => {
            if b == 0.0 {
                return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
            }
            Ok(ScriptValue::Float(a / b))
        }
        (ScriptValue::Int(a), ScriptValue::Float(b)) => {
            if b == 0.0 {
                return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
            }
            Ok(ScriptValue::Float(a as f64 / b))
        }
        (ScriptValue::Float(a), ScriptValue::Int(b)) => {
            if b == 0 {
                return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
            }
            Ok(ScriptValue::Float(a / b as f64))
        }
        _ => Ok(ScriptValue::Nil),
    }
}

/// 剰余演算
pub fn op_mod(a: ScriptValue, b: ScriptValue) -> Result<ScriptValue, ScriptError> {
    match (a, b) {
        (ScriptValue::Int(a), ScriptValue::Int(b)) => {
            if b == 0 {
                return Err(ScriptError::new(ErrorKind::Runtime, "Division by zero", 0, 0));
            }
            Ok(ScriptValue::Int(a % b))
        }
        _ => Ok(ScriptValue::Nil),
    }
}

/// 等価比較
pub fn op_eq(a: &ScriptValue, b: &ScriptValue) -> bool {
    match (a, b) {
        (ScriptValue::Nil, ScriptValue::Nil) => true,
        (ScriptValue::Bool(a), ScriptValue::Bool(b)) => a == b,
        (ScriptValue::Int(a), ScriptValue::Int(b)) => a == b,
        (ScriptValue::Float(a), ScriptValue::Float(b)) => a == b,
        (ScriptValue::Int(a), ScriptValue::Float(b)) => *a as f64 == *b,
        (ScriptValue::Float(a), ScriptValue::Int(b)) => *a == *b as f64,
        (ScriptValue::String(a), ScriptValue::String(b)) => a == b,
        _ => false,
    }
}

/// 小なり比較
pub fn op_lt(a: &ScriptValue, b: &ScriptValue) -> bool {
    match (a, b) {
        (ScriptValue::Int(a), ScriptValue::Int(b)) => a < b,
        (ScriptValue::Float(a), ScriptValue::Float(b)) => a < b,
        (ScriptValue::Int(a), ScriptValue::Float(b)) => (*a as f64) < *b,
        (ScriptValue::Float(a), ScriptValue::Int(b)) => *a < (*b as f64),
        (ScriptValue::String(a), ScriptValue::String(b)) => a < b,
        _ => false,
    }
}
