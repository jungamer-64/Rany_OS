// ============================================================================
// src/application/browser/script/value.rs - Script Value System
// ============================================================================
//!
//! # スクリプト値システム
//!
//! RustScriptの実行時値を表現する型システム。
//! ExoShellのExoValueを参考に、DOM操作に特化した設計。

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::fmt::{self, Display};

// ============================================================================
// Script Value
// ============================================================================

/// スクリプトの実行時値
#[derive(Debug, Clone)]
pub enum ScriptValue {
    /// 空値
    Nil,

    /// 真偽値
    Bool(bool),

    /// 整数（i64）
    Int(i64),

    /// 浮動小数点（f64）
    Float(f64),

    /// 文字列
    String(String),

    /// 配列
    Array(Vec<ScriptValue>),

    /// オブジェクト（マップ）
    Object(BTreeMap<String, ScriptValue>),

    /// DOM要素への参照
    Element(ElementRef),

    /// 関数（クロージャ）
    Function(FunctionValue),

    /// ネイティブ関数
    NativeFunction(NativeFunction),

    /// イテレータ
    Iterator(IteratorValue),

    /// 範囲
    Range(RangeValue),

    /// エラー
    Error(String),
}

impl ScriptValue {
    // 型判定メソッド
    pub fn is_nil(&self) -> bool {
        matches!(self, ScriptValue::Nil)
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            ScriptValue::Nil => false,
            ScriptValue::Bool(b) => *b,
            ScriptValue::Int(i) => *i != 0,
            ScriptValue::Float(f) => *f != 0.0,
            ScriptValue::String(s) => !s.is_empty(),
            ScriptValue::Array(arr) => !arr.is_empty(),
            ScriptValue::Object(obj) => !obj.is_empty(),
            ScriptValue::Element(_) => true,
            ScriptValue::Function(_) => true,
            ScriptValue::NativeFunction(_) => true,
            ScriptValue::Iterator(_) => true,
            ScriptValue::Range(_) => true,
            ScriptValue::Error(_) => false,
        }
    }

    // 型変換メソッド
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ScriptValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            ScriptValue::Int(i) => Some(*i),
            ScriptValue::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            ScriptValue::Float(f) => Some(*f),
            ScriptValue::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            ScriptValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<ScriptValue>> {
        match self {
            ScriptValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, ScriptValue>> {
        match self {
            ScriptValue::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn as_element(&self) -> Option<&ElementRef> {
        match self {
            ScriptValue::Element(e) => Some(e),
            _ => None,
        }
    }

    pub fn to_string_value(&self) -> String {
        match self {
            ScriptValue::Nil => String::from("nil"),
            ScriptValue::Bool(b) => format!("{}", b),
            ScriptValue::Int(i) => format!("{}", i),
            ScriptValue::Float(f) => format!("{:.6}", f),
            ScriptValue::String(s) => s.clone(),
            ScriptValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| v.to_string_value()).collect();
                format!("[{}]", items.join(", "))
            }
            ScriptValue::Object(obj) => {
                let pairs: Vec<String> = obj.iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_string_value()))
                    .collect();
                format!("{{ {} }}", pairs.join(", "))
            }
            ScriptValue::Element(e) => format!("<Element #{}>", e.id),
            ScriptValue::Function(f) => format!("<Function {}>", f.name),
            ScriptValue::NativeFunction(f) => format!("<NativeFunction {}>", f.name),
            ScriptValue::Iterator(_) => String::from("<Iterator>"),
            ScriptValue::Range(r) => format!("{}..{}", r.start, r.end),
            ScriptValue::Error(e) => format!("Error: {}", e),
        }
    }

    /// 型名を取得
    pub fn type_name(&self) -> &'static str {
        match self {
            ScriptValue::Nil => "nil",
            ScriptValue::Bool(_) => "bool",
            ScriptValue::Int(_) => "int",
            ScriptValue::Float(_) => "float",
            ScriptValue::String(_) => "string",
            ScriptValue::Array(_) => "array",
            ScriptValue::Object(_) => "object",
            ScriptValue::Element(_) => "element",
            ScriptValue::Function(_) => "function",
            ScriptValue::NativeFunction(_) => "native_function",
            ScriptValue::Iterator(_) => "iterator",
            ScriptValue::Range(_) => "range",
            ScriptValue::Error(_) => "error",
        }
    }
}

impl Display for ScriptValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_value())
    }
}

impl Default for ScriptValue {
    fn default() -> Self {
        ScriptValue::Nil
    }
}

// ============================================================================
// DOM Element Reference
// ============================================================================

/// DOM要素への参照
#[derive(Debug, Clone)]
pub struct ElementRef {
    /// 要素ID（内部用）
    pub id: usize,
    /// 要素のタグ名
    pub tag_name: String,
    /// 要素のHTML id属性
    pub html_id: Option<String>,
    /// 要素のclass属性
    pub classes: Vec<String>,
}

impl ElementRef {
    pub fn new(id: usize, tag_name: &str) -> Self {
        Self {
            id,
            tag_name: String::from(tag_name),
            html_id: None,
            classes: Vec::new(),
        }
    }

    pub fn with_html_id(mut self, html_id: &str) -> Self {
        self.html_id = Some(String::from(html_id));
        self
    }

    pub fn with_classes(mut self, classes: Vec<String>) -> Self {
        self.classes = classes;
        self
    }
}

// ============================================================================
// Function Value
// ============================================================================

/// ユーザー定義関数
#[derive(Debug, Clone)]
pub struct FunctionValue {
    /// 関数名
    pub name: String,
    /// パラメータ名
    pub params: Vec<String>,
    /// 関数本体のバイトコード位置
    pub body_addr: usize,
    /// キャプチャされた変数（クロージャ用）
    pub captures: BTreeMap<String, ScriptValue>,
}

impl FunctionValue {
    pub fn new(name: &str, params: Vec<String>, body_addr: usize) -> Self {
        Self {
            name: String::from(name),
            params,
            body_addr,
            captures: BTreeMap::new(),
        }
    }

    pub fn closure(params: Vec<String>, body_addr: usize, captures: BTreeMap<String, ScriptValue>) -> Self {
        Self {
            name: String::from("<closure>"),
            params,
            body_addr,
            captures,
        }
    }
}

// ============================================================================
// Native Function
// ============================================================================

/// ネイティブ関数の識別子
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFunctionId {
    // Console
    ConsoleLog,
    ConsoleWarn,
    ConsoleError,

    // DOM操作
    DomGetElementById,
    DomGetElementsByClass,
    DomGetElementsByTag,
    DomCreateElement,
    DomAppendChild,
    DomRemoveChild,
    DomSetAttribute,
    DomGetAttribute,
    DomRemoveAttribute,
    DomSetText,
    DomGetText,
    DomSetHtml,
    DomGetHtml,
    DomSetStyle,
    DomGetStyle,
    DomAddClass,
    DomRemoveClass,
    DomToggleClass,
    DomHasClass,

    // イベント
    EventAddListener,
    EventRemoveListener,
    EventPreventDefault,
    EventStopPropagation,

    // タイマー
    SetTimeout,
    SetInterval,
    ClearTimeout,
    ClearInterval,

    // 文字列操作
    StringLength,
    StringCharAt,
    StringSubstring,
    StringIndexOf,
    StringSplit,
    StringReplace,
    StringToUpperCase,
    StringToLowerCase,
    StringTrim,
    StringStartsWith,
    StringEndsWith,
    StringContains,

    // 配列操作
    ArrayLength,
    ArrayPush,
    ArrayPop,
    ArrayShift,
    ArrayUnshift,
    ArraySlice,
    ArrayConcat,
    ArrayJoin,
    ArrayReverse,
    ArraySort,
    ArrayFind,
    ArrayFilter,
    ArrayMap,
    ArrayForEach,
    ArrayReduce,
    ArrayIncludes,
    ArrayIndexOf,

    // 数学関数
    MathAbs,
    MathFloor,
    MathCeil,
    MathRound,
    MathMin,
    MathMax,
    MathRandom,

    // 型変換
    ParseInt,
    ParseFloat,
    ToString,

    // その他
    TypeOf,
    Print,
}

/// ネイティブ関数
#[derive(Debug, Clone)]
pub struct NativeFunction {
    /// 関数名
    pub name: String,
    /// 関数ID
    pub id: NativeFunctionId,
    /// 引数の数（-1は可変長）
    pub arity: i32,
}

impl NativeFunction {
    pub fn new(name: &str, id: NativeFunctionId, arity: i32) -> Self {
        Self {
            name: String::from(name),
            id,
            arity,
        }
    }
}

// ============================================================================
// Iterator Value
// ============================================================================

/// イテレータ値
#[derive(Debug, Clone)]
pub struct IteratorValue {
    /// ソースの種類
    pub source: IteratorSource,
    /// 現在のインデックス
    pub index: usize,
}

/// イテレータのソース
#[derive(Debug, Clone)]
pub enum IteratorSource {
    /// 配列イテレータ
    Array(Vec<ScriptValue>),
    /// 範囲イテレータ
    Range(i64, i64),
    /// 文字列（文字イテレータ）
    String(String),
    /// オブジェクトキー
    ObjectKeys(Vec<String>),
    /// オブジェクト値
    ObjectValues(Vec<ScriptValue>),
    /// オブジェクトエントリ
    ObjectEntries(Vec<(String, ScriptValue)>),
}

impl IteratorValue {
    pub fn from_array(arr: Vec<ScriptValue>) -> Self {
        Self {
            source: IteratorSource::Array(arr),
            index: 0,
        }
    }

    pub fn from_range(start: i64, end: i64) -> Self {
        Self {
            source: IteratorSource::Range(start, end),
            index: 0,
        }
    }

    pub fn from_string(s: String) -> Self {
        Self {
            source: IteratorSource::String(s),
            index: 0,
        }
    }

    /// 次の値を取得
    pub fn next(&mut self) -> Option<ScriptValue> {
        match &self.source {
            IteratorSource::Array(arr) => {
                if self.index < arr.len() {
                    let value = arr[self.index].clone();
                    self.index += 1;
                    Some(value)
                } else {
                    None
                }
            }
            IteratorSource::Range(start, end) => {
                let current = *start + self.index as i64;
                if current < *end {
                    self.index += 1;
                    Some(ScriptValue::Int(current))
                } else {
                    None
                }
            }
            IteratorSource::String(s) => {
                let chars: Vec<char> = s.chars().collect();
                if self.index < chars.len() {
                    let c = chars[self.index];
                    self.index += 1;
                    Some(ScriptValue::String(String::from(c)))
                } else {
                    None
                }
            }
            IteratorSource::ObjectKeys(keys) => {
                if self.index < keys.len() {
                    let key = keys[self.index].clone();
                    self.index += 1;
                    Some(ScriptValue::String(key))
                } else {
                    None
                }
            }
            IteratorSource::ObjectValues(values) => {
                if self.index < values.len() {
                    let value = values[self.index].clone();
                    self.index += 1;
                    Some(value)
                } else {
                    None
                }
            }
            IteratorSource::ObjectEntries(entries) => {
                if self.index < entries.len() {
                    let (key, value) = entries[self.index].clone();
                    self.index += 1;
                    let mut arr = Vec::new();
                    arr.push(ScriptValue::String(key));
                    arr.push(value);
                    Some(ScriptValue::Array(arr))
                } else {
                    None
                }
            }
        }
    }
}

// ============================================================================
// Range Value
// ============================================================================

/// 範囲値
#[derive(Debug, Clone)]
pub struct RangeValue {
    /// 開始値
    pub start: i64,
    /// 終了値
    pub end: i64,
    /// 終了を含むか（`..=`）
    pub inclusive: bool,
}

impl RangeValue {
    pub fn new(start: i64, end: i64, inclusive: bool) -> Self {
        Self { start, end, inclusive }
    }

    pub fn contains(&self, value: i64) -> bool {
        if self.inclusive {
            value >= self.start && value <= self.end
        } else {
            value >= self.start && value < self.end
        }
    }

    pub fn to_iterator(&self) -> IteratorValue {
        let actual_end = if self.inclusive { self.end + 1 } else { self.end };
        IteratorValue::from_range(self.start, actual_end)
    }
}

// ============================================================================
// Script Type
// ============================================================================

/// スクリプトの型情報（静的解析用）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptType {
    /// 未知/任意の型
    Any,
    /// Nil型
    Nil,
    /// ブール型
    Bool,
    /// 整数型
    Int,
    /// 浮動小数点型
    Float,
    /// 文字列型
    String,
    /// 配列型
    Array(Box<ScriptType>),
    /// オブジェクト型
    Object,
    /// DOM要素型
    Element,
    /// 関数型
    Function {
        params: Vec<ScriptType>,
        return_type: Box<ScriptType>,
    },
    /// ユニオン型
    Union(Vec<ScriptType>),
    /// エラー型
    Error,
}

impl ScriptType {
    /// 2つの型が互換性があるか
    pub fn is_compatible(&self, other: &ScriptType) -> bool {
        if self == other {
            return true;
        }
        match (self, other) {
            (ScriptType::Any, _) | (_, ScriptType::Any) => true,
            (ScriptType::Int, ScriptType::Float) | (ScriptType::Float, ScriptType::Int) => true,
            (ScriptType::Union(types), other) => types.iter().any(|t| t.is_compatible(other)),
            (other, ScriptType::Union(types)) => types.iter().any(|t| other.is_compatible(t)),
            _ => false,
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_value_truthy() {
        assert!(!ScriptValue::Nil.is_truthy());
        assert!(!ScriptValue::Bool(false).is_truthy());
        assert!(ScriptValue::Bool(true).is_truthy());
        assert!(ScriptValue::Int(42).is_truthy());
        assert!(!ScriptValue::Int(0).is_truthy());
    }

    #[test]
    fn test_iterator() {
        let mut iter = IteratorValue::from_range(0, 3);
        assert_eq!(iter.next(), Some(ScriptValue::Int(0)));
        assert_eq!(iter.next(), Some(ScriptValue::Int(1)));
        assert_eq!(iter.next(), Some(ScriptValue::Int(2)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_range_contains() {
        let range = RangeValue::new(1, 5, false);
        assert!(!range.contains(0));
        assert!(range.contains(1));
        assert!(range.contains(4));
        assert!(!range.contains(5));

        let inclusive = RangeValue::new(1, 5, true);
        assert!(inclusive.contains(5));
    }
}
