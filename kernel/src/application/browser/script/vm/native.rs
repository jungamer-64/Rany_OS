// ============================================================================
// src/application/browser/script/vm/native.rs - Native Function Execution
// ============================================================================
//!
//! ネイティブ関数の実行。

use alloc::string::String;
use alloc::vec::Vec;

use super::super::value::{NativeFunctionId, ScriptValue};
use super::super::{ErrorKind, ScriptError};
use super::dom::DomOperation;
use super::ops;
use super::vm_core::VirtualMachine;

impl VirtualMachine {
    /// ネイティブ関数の実行
    pub(crate) fn call_native(
        &mut self,
        id: NativeFunctionId,
        args: Vec<ScriptValue>,
    ) -> Result<ScriptValue, ScriptError> {
        match id {
            NativeFunctionId::ConsoleLog => {
                // 実際のログ出力は実装依存
                let _msg = args
                    .iter()
                    .map(|v| v.to_string_value())
                    .collect::<Vec<_>>()
                    .join(" ");
                // ここでログを出力
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::ConsoleWarn => Ok(ScriptValue::Nil),
            NativeFunctionId::ConsoleError => Ok(ScriptValue::Nil),

            // DOM操作
            NativeFunctionId::DomGetElementById => {
                if let Some(ScriptValue::String(id)) = args.get(0) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::GetElementById(id.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomCreateElement => {
                if let Some(ScriptValue::String(tag)) = args.get(0) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::CreateElement(tag.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomSetText => {
                if let (Some(ScriptValue::Element(elem)), Some(ScriptValue::String(text))) =
                    (args.get(0), args.get(1))
                {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::SetText(elem.id, text.clone())));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomGetText => {
                if let Some(ScriptValue::Element(elem)) = args.get(0) {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::GetText(elem.id)));
                    }
                }
                Ok(ScriptValue::Nil)
            }
            NativeFunctionId::DomSetStyle => {
                if let (
                    Some(ScriptValue::Element(elem)),
                    Some(ScriptValue::String(prop)),
                    Some(ScriptValue::String(value)),
                ) = (args.get(0), args.get(1), args.get(2))
                {
                    if let Some(callback) = &self.dom_callback {
                        return Ok(callback(DomOperation::SetStyle(
                            elem.id,
                            prop.clone(),
                            value.clone(),
                        )));
                    }
                }
                Ok(ScriptValue::Nil)
            }

            // 文字列操作
            NativeFunctionId::StringLength => {
                if let Some(ScriptValue::String(s)) = args.get(0) {
                    Ok(ScriptValue::Int(s.len() as i64))
                } else {
                    Ok(ScriptValue::Int(0))
                }
            }
            NativeFunctionId::StringCharAt => {
                if let (Some(ScriptValue::String(s)), Some(ScriptValue::Int(i))) =
                    (args.get(0), args.get(1))
                {
                    let chars: Vec<char> = s.chars().collect();
                    let idx = *i as usize;
                    if idx < chars.len() {
                        Ok(ScriptValue::String(String::from(chars[idx])))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::StringSubstring => {
                if let (
                    Some(ScriptValue::String(s)),
                    Some(ScriptValue::Int(start)),
                    Some(ScriptValue::Int(end)),
                ) = (args.get(0), args.get(1), args.get(2))
                {
                    let start = *start as usize;
                    let end = *end as usize;
                    let chars: Vec<char> = s.chars().collect();
                    if start <= end && end <= chars.len() {
                        let sub: String = chars[start..end].iter().collect();
                        Ok(ScriptValue::String(sub))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }

            // 配列操作
            NativeFunctionId::ArrayLength => {
                if let Some(ScriptValue::Array(arr)) = args.get(0) {
                    Ok(ScriptValue::Int(arr.len() as i64))
                } else {
                    Ok(ScriptValue::Int(0))
                }
            }
            NativeFunctionId::ArrayPush => {
                if let (Some(ScriptValue::Array(arr)), Some(value)) = (args.get(0), args.get(1)) {
                    let mut new_arr = arr.clone();
                    new_arr.push(value.clone());
                    Ok(ScriptValue::Array(new_arr))
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::ArrayPop => {
                if let Some(ScriptValue::Array(arr)) = args.get(0) {
                    let mut new_arr = arr.clone();
                    let value = new_arr.pop().unwrap_or(ScriptValue::Nil);
                    Ok(value)
                } else {
                    Ok(ScriptValue::Nil)
                }
            }

            // 数学関数
            NativeFunctionId::MathAbs => match args.get(0) {
                Some(ScriptValue::Int(i)) => Ok(ScriptValue::Int(i.abs())),
                Some(ScriptValue::Float(f)) => {
                    Ok(ScriptValue::Float(if *f < 0.0 { -*f } else { *f }))
                }
                _ => Ok(ScriptValue::Nil),
            },
            NativeFunctionId::MathFloor => {
                if let Some(ScriptValue::Float(f)) = args.get(0) {
                    Ok(ScriptValue::Int(*f as i64))
                } else if let Some(ScriptValue::Int(i)) = args.get(0) {
                    Ok(ScriptValue::Int(*i))
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::MathMin => {
                if args.is_empty() {
                    return Ok(ScriptValue::Nil);
                }
                let mut min = args[0].clone();
                for arg in args.iter().skip(1) {
                    if ops::op_lt(arg, &min) {
                        min = arg.clone();
                    }
                }
                Ok(min)
            }
            NativeFunctionId::MathMax => {
                if args.is_empty() {
                    return Ok(ScriptValue::Nil);
                }
                let mut max = args[0].clone();
                for arg in args.iter().skip(1) {
                    if ops::op_lt(&max, arg) {
                        max = arg.clone();
                    }
                }
                Ok(max)
            }

            // 型変換
            NativeFunctionId::ParseInt => {
                if let Some(ScriptValue::String(s)) = args.get(0) {
                    if let Ok(i) = s.parse::<i64>() {
                        Ok(ScriptValue::Int(i))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::ParseFloat => {
                if let Some(ScriptValue::String(s)) = args.get(0) {
                    if let Ok(f) = s.parse::<f64>() {
                        Ok(ScriptValue::Float(f))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                } else {
                    Ok(ScriptValue::Nil)
                }
            }
            NativeFunctionId::ToString => {
                if let Some(value) = args.get(0) {
                    Ok(ScriptValue::String(value.to_string_value()))
                } else {
                    Ok(ScriptValue::String(String::new()))
                }
            }

            NativeFunctionId::TypeOf => {
                if let Some(value) = args.get(0) {
                    Ok(ScriptValue::String(String::from(value.type_name())))
                } else {
                    Ok(ScriptValue::String(String::from("undefined")))
                }
            }
            NativeFunctionId::Print => {
                let _msg = args
                    .iter()
                    .map(|v| v.to_string_value())
                    .collect::<Vec<_>>()
                    .join(" ");
                // 実際の出力は実装依存
                Ok(ScriptValue::Nil)
            }

            // その他は未実装としてNilを返す
            _ => Ok(ScriptValue::Nil),
        }
    }
}
