// ============================================================================
// src/application/browser/script/vm/methods.rs - Method Call Execution
// ============================================================================
//!
//! メソッド呼び出しの実行。

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::super::value::{IteratorValue, ScriptValue};
use super::super::ScriptError;
use super::dom::DomOperation;
use super::ops;
use super::vm_core::VirtualMachine;

impl VirtualMachine {
    /// メソッド呼び出し
    pub(crate) fn call_method(
        &mut self,
        receiver: ScriptValue,
        name: &str,
        args: Vec<ScriptValue>,
    ) -> Result<ScriptValue, ScriptError> {
        match receiver {
            ScriptValue::String(s) => match name {
                "len" | "length" => Ok(ScriptValue::Int(s.len() as i64)),
                "to_uppercase" => Ok(ScriptValue::String(s.to_uppercase())),
                "to_lowercase" => Ok(ScriptValue::String(s.to_lowercase())),
                "trim" => Ok(ScriptValue::String(String::from(s.trim()))),
                "contains" => {
                    if let Some(ScriptValue::String(substr)) = args.get(0) {
                        Ok(ScriptValue::Bool(s.contains(substr.as_str())))
                    } else {
                        Ok(ScriptValue::Bool(false))
                    }
                }
                "starts_with" => {
                    if let Some(ScriptValue::String(prefix)) = args.get(0) {
                        Ok(ScriptValue::Bool(s.starts_with(prefix.as_str())))
                    } else {
                        Ok(ScriptValue::Bool(false))
                    }
                }
                "ends_with" => {
                    if let Some(ScriptValue::String(suffix)) = args.get(0) {
                        Ok(ScriptValue::Bool(s.ends_with(suffix.as_str())))
                    } else {
                        Ok(ScriptValue::Bool(false))
                    }
                }
                "split" => {
                    if let Some(ScriptValue::String(delim)) = args.get(0) {
                        let parts: Vec<ScriptValue> = s
                            .split(delim.as_str())
                            .map(|p| ScriptValue::String(String::from(p)))
                            .collect();
                        Ok(ScriptValue::Array(parts))
                    } else {
                        Ok(ScriptValue::Array(vec![ScriptValue::String(s)]))
                    }
                }
                "replace" => {
                    if let (Some(ScriptValue::String(from)), Some(ScriptValue::String(to))) =
                        (args.get(0), args.get(1))
                    {
                        Ok(ScriptValue::String(s.replace(from.as_str(), to.as_str())))
                    } else {
                        Ok(ScriptValue::String(s))
                    }
                }
                _ => Ok(ScriptValue::Nil),
            },
            ScriptValue::Array(arr) => match name {
                "len" | "length" => Ok(ScriptValue::Int(arr.len() as i64)),
                "push" => {
                    let mut new_arr = arr.clone();
                    for arg in args {
                        new_arr.push(arg);
                    }
                    Ok(ScriptValue::Array(new_arr))
                }
                "pop" => {
                    let mut new_arr = arr.clone();
                    let value = new_arr.pop().unwrap_or(ScriptValue::Nil);
                    Ok(value)
                }
                "first" => Ok(arr.first().cloned().unwrap_or(ScriptValue::Nil)),
                "last" => Ok(arr.last().cloned().unwrap_or(ScriptValue::Nil)),
                "get" => {
                    if let Some(ScriptValue::Int(i)) = args.get(0) {
                        Ok(arr.get(*i as usize).cloned().unwrap_or(ScriptValue::Nil))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                }
                "contains" => {
                    if let Some(value) = args.get(0) {
                        Ok(ScriptValue::Bool(arr.iter().any(|v| ops::op_eq(v, value))))
                    } else {
                        Ok(ScriptValue::Bool(false))
                    }
                }
                "join" => {
                    let delim = args.get(0).and_then(|v| v.as_string()).unwrap_or(",");
                    let result: Vec<String> = arr.iter().map(|v| v.to_string_value()).collect();
                    Ok(ScriptValue::String(result.join(delim)))
                }
                "reverse" => {
                    let mut new_arr = arr.clone();
                    new_arr.reverse();
                    Ok(ScriptValue::Array(new_arr))
                }
                "iter" => Ok(ScriptValue::Iterator(IteratorValue::from_array(arr))),
                _ => Ok(ScriptValue::Nil),
            },
            ScriptValue::Object(obj) => match name {
                "keys" => {
                    let keys: Vec<ScriptValue> = obj
                        .keys()
                        .map(|k| ScriptValue::String(k.clone()))
                        .collect();
                    Ok(ScriptValue::Array(keys))
                }
                "values" => {
                    let values: Vec<ScriptValue> = obj.values().cloned().collect();
                    Ok(ScriptValue::Array(values))
                }
                "get" => {
                    if let Some(ScriptValue::String(key)) = args.get(0) {
                        Ok(obj.get(key).cloned().unwrap_or(ScriptValue::Nil))
                    } else {
                        Ok(ScriptValue::Nil)
                    }
                }
                "contains_key" | "has" => {
                    if let Some(ScriptValue::String(key)) = args.get(0) {
                        Ok(ScriptValue::Bool(obj.contains_key(key)))
                    } else {
                        Ok(ScriptValue::Bool(false))
                    }
                }
                _ => Ok(ScriptValue::Nil),
            },
            ScriptValue::Element(elem) => {
                // DOM要素のメソッドはDOMコールバック経由で処理
                if let Some(callback) = &self.dom_callback {
                    match name {
                        "set_text" => {
                            if let Some(ScriptValue::String(text)) = args.get(0) {
                                return Ok(callback(DomOperation::SetText(elem.id, text.clone())));
                            }
                        }
                        "get_text" => {
                            return Ok(callback(DomOperation::GetText(elem.id)));
                        }
                        "set_style" => {
                            if let (
                                Some(ScriptValue::String(prop)),
                                Some(ScriptValue::String(value)),
                            ) = (args.get(0), args.get(1))
                            {
                                return Ok(callback(DomOperation::SetStyle(
                                    elem.id,
                                    prop.clone(),
                                    value.clone(),
                                )));
                            }
                        }
                        "get_style" => {
                            if let Some(ScriptValue::String(prop)) = args.get(0) {
                                return Ok(callback(DomOperation::GetStyle(elem.id, prop.clone())));
                            }
                        }
                        "set_attribute" => {
                            if let (
                                Some(ScriptValue::String(name)),
                                Some(ScriptValue::String(value)),
                            ) = (args.get(0), args.get(1))
                            {
                                return Ok(callback(DomOperation::SetAttribute(
                                    elem.id,
                                    name.clone(),
                                    value.clone(),
                                )));
                            }
                        }
                        "get_attribute" => {
                            if let Some(ScriptValue::String(attr)) = args.get(0) {
                                return Ok(callback(DomOperation::GetAttribute(
                                    elem.id,
                                    attr.clone(),
                                )));
                            }
                        }
                        "add_class" => {
                            if let Some(ScriptValue::String(class)) = args.get(0) {
                                return Ok(callback(DomOperation::AddClass(elem.id, class.clone())));
                            }
                        }
                        "remove_class" => {
                            if let Some(ScriptValue::String(class)) = args.get(0) {
                                return Ok(callback(DomOperation::RemoveClass(
                                    elem.id,
                                    class.clone(),
                                )));
                            }
                        }
                        "on" => {
                            if let (
                                Some(ScriptValue::String(event)),
                                Some(ScriptValue::Function(f)),
                            ) = (args.get(0), args.get(1))
                            {
                                return Ok(callback(DomOperation::AddEventListener(
                                    elem.id,
                                    event.clone(),
                                    f.body_addr,
                                )));
                            }
                        }
                        _ => {}
                    }
                }
                Ok(ScriptValue::Nil)
            }
            ScriptValue::Range(r) => match name {
                "contains" => {
                    if let Some(ScriptValue::Int(v)) = args.get(0) {
                        Ok(ScriptValue::Bool(r.contains(*v)))
                    } else {
                        Ok(ScriptValue::Bool(false))
                    }
                }
                "iter" => Ok(ScriptValue::Iterator(r.to_iterator())),
                _ => Ok(ScriptValue::Nil),
            },
            _ => Ok(ScriptValue::Nil),
        }
    }
}
