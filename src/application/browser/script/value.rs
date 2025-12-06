// ============================================================================
// src/application/browser/script/value.rs - Script Value System
// ============================================================================
//!
//! # スクリプト値システム
//!
//! RustScriptの実行時値を表現する型システム。
//! ExoShellのExoValueと統合し、DOM操作とOS操作の両方をサポート。

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::fmt::{self, Display};

// ============================================================================
// OS Resource Types (ExoShellから統合)
// ============================================================================

/// ファイルシステムエントリ（構造化データ）
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub file_type: FileType,
    pub size: u64,
    pub owner: String,
    pub permissions: Permissions,
    pub created: u64,
    pub modified: u64,
    pub inode: u64,
}

impl FileEntry {
    pub fn new(name: String, path: String, file_type: FileType) -> Self {
        Self {
            name,
            path,
            file_type,
            size: 0,
            owner: String::new(),
            permissions: Permissions::default(),
            created: 0,
            modified: 0,
            inode: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Device,
    Socket,
    Pipe,
}

/// Capabilityベースのパーミッション
#[derive(Debug, Clone)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub delete: bool,
    pub grant: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
            delete: false,
            grant: false,
        }
    }
}

/// ネットワーク接続情報
#[derive(Debug, Clone)]
pub struct NetConnection {
    pub protocol: String,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub state: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl NetConnection {
    pub fn new(protocol: String, local_port: u16, remote_port: u16) -> Self {
        Self {
            protocol,
            local_addr: [0, 0, 0, 0],
            local_port,
            remote_addr: [0, 0, 0, 0],
            remote_port,
            state: String::from("NEW"),
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

/// プロセス情報
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub state: ProcessState,
    pub cpu_usage: f32,
    pub memory_kb: u64,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Blocked,
    Stopped,
    Zombie,
}

/// Capability（権限トークン）
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub id: u64,
    pub resource: String,
    pub operations: Vec<CapOperation>,
    pub issuer: String,
    pub expires: Option<u64>,
    pub delegatable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOperation {
    Read,
    Write,
    Execute,
    Delete,
    Grant,
    Revoke,
    Create,
    List,
}

// ============================================================================
// Display implementations for OS types
// ============================================================================

impl Display for FileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_char = match self.file_type {
            FileType::Directory => 'd',
            FileType::Symlink => 'l',
            FileType::Device => 'c',
            FileType::Socket => 's',
            FileType::Pipe => 'p',
            FileType::Regular => '-',
        };

        let perm_str = alloc::format!(
            "{}{}{}",
            if self.permissions.read { 'r' } else { '-' },
            if self.permissions.write { 'w' } else { '-' },
            if self.permissions.execute { 'x' } else { '-' }
        );

        write!(
            f,
            "{}{} {:>8} {} {}",
            type_char, perm_str, self.size, self.owner, self.name
        )
    }
}

impl Display for NetConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} [{}]",
            self.protocol,
            self.local_addr[0], self.local_addr[1], self.local_addr[2], self.local_addr[3],
            self.local_port,
            self.remote_addr[0], self.remote_addr[1], self.remote_addr[2], self.remote_addr[3],
            self.remote_port,
            self.state
        )
    }
}

impl Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_str = match self.state {
            ProcessState::Running => "R",
            ProcessState::Sleeping => "S",
            ProcessState::Blocked => "D",
            ProcessState::Stopped => "T",
            ProcessState::Zombie => "Z",
        };
        write!(
            f,
            "{:>5} {} {:>5.1}% {:>8}KB {}",
            self.pid, state_str, self.cpu_usage, self.memory_kb, self.name
        )
    }
}

impl Display for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cap#{} {} [{}] from {}",
            self.id,
            self.resource,
            self.operations.iter().map(|op| match op {
                CapOperation::Read => "R",
                CapOperation::Write => "W",
                CapOperation::Execute => "X",
                CapOperation::Delete => "D",
                CapOperation::Grant => "G",
                CapOperation::Revoke => "V",
                CapOperation::Create => "C",
                CapOperation::List => "L",
            }).collect::<Vec<_>>().join(""),
            self.issuer
        )
    }
}

// ============================================================================
// Script Value
// ============================================================================

/// スクリプトの実行時値
/// ExoShellのExoValueと統合された、OS全体で使用する値型
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

    /// バイト列（ゼロコピー対応）
    Bytes(Vec<u8>),

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

    // ========================================================================
    // OS Resource Types (ExoShellから統合)
    // ========================================================================

    /// ファイルエントリ
    FileEntry(FileEntry),

    /// ネットワーク接続
    NetConnection(NetConnection),

    /// プロセス情報
    Process(ProcessInfo),

    /// Capability（権限トークン）
    Capability(CapabilityToken),

    // ========================================================================
    // Async Types
    // ========================================================================

    /// Promise（非同期操作の結果）
    Promise(PromiseValue),

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
            ScriptValue::Bytes(b) => !b.is_empty(),
            ScriptValue::Array(arr) => !arr.is_empty(),
            ScriptValue::Object(obj) => !obj.is_empty(),
            ScriptValue::Element(_) => true,
            ScriptValue::Function(_) => true,
            ScriptValue::NativeFunction(_) => true,
            ScriptValue::Iterator(_) => true,
            ScriptValue::Range(_) => true,
            ScriptValue::FileEntry(_) => true,
            ScriptValue::NetConnection(_) => true,
            ScriptValue::Process(_) => true,
            ScriptValue::Capability(_) => true,
            ScriptValue::Promise(p) => p.is_fulfilled(),
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
            ScriptValue::Bytes(b) => format!("<{} bytes>", b.len()),
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
            ScriptValue::FileEntry(e) => format!("{}", e),
            ScriptValue::NetConnection(c) => format!("{}", c),
            ScriptValue::Process(p) => format!("{}", p),
            ScriptValue::Capability(cap) => format!("{}", cap),
            ScriptValue::Promise(p) => {
                match p.state {
                    PromiseState::Pending => format!("<Promise #{} pending>", p.task_id),
                    PromiseState::Fulfilled => {
                        let val = p.value.as_ref().map(|v| v.to_string_value()).unwrap_or_default();
                        format!("<Promise #{} fulfilled: {}>", p.task_id, val)
                    }
                    PromiseState::Rejected => {
                        let err = p.error.as_deref().unwrap_or("unknown");
                        format!("<Promise #{} rejected: {}>", p.task_id, err)
                    }
                }
            }
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
            ScriptValue::Bytes(_) => "bytes",
            ScriptValue::Array(_) => "array",
            ScriptValue::Object(_) => "object",
            ScriptValue::Element(_) => "element",
            ScriptValue::Function(_) => "function",
            ScriptValue::NativeFunction(_) => "native_function",
            ScriptValue::Iterator(_) => "iterator",
            ScriptValue::Range(_) => "range",
            ScriptValue::FileEntry(_) => "file_entry",
            ScriptValue::NetConnection(_) => "net_connection",
            ScriptValue::Process(_) => "process",
            ScriptValue::Capability(_) => "capability",
            ScriptValue::Promise(_) => "promise",
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
// Promise Value (Async Support)
// ============================================================================

/// Promiseの状態
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromiseState {
    /// 保留中
    Pending,
    /// 完了（成功）
    Fulfilled,
    /// 拒否（エラー）
    Rejected,
}

/// Promise値（非同期操作を表現）
#[derive(Debug, Clone)]
pub struct PromiseValue {
    /// タスクID
    pub task_id: u64,
    /// 状態
    pub state: PromiseState,
    /// 結果値（完了時）
    pub value: Option<Box<ScriptValue>>,
    /// エラーメッセージ（拒否時）
    pub error: Option<String>,
}

impl PromiseValue {
    /// 新しいPendingなPromiseを作成
    pub fn new(task_id: u64) -> Self {
        Self {
            task_id,
            state: PromiseState::Pending,
            value: None,
            error: None,
        }
    }

    /// 成功で解決
    pub fn resolve(mut self, value: ScriptValue) -> Self {
        self.state = PromiseState::Fulfilled;
        self.value = Some(Box::new(value));
        self
    }

    /// エラーで拒否
    pub fn reject(mut self, error: String) -> Self {
        self.state = PromiseState::Rejected;
        self.error = Some(error);
        self
    }

    /// 保留中かどうか
    pub fn is_pending(&self) -> bool {
        self.state == PromiseState::Pending
    }

    /// 完了したかどうか
    pub fn is_settled(&self) -> bool {
        self.state != PromiseState::Pending
    }

    /// 成功したかどうか
    pub fn is_fulfilled(&self) -> bool {
        self.state == PromiseState::Fulfilled
    }

    /// 拒否されたかどうか
    pub fn is_rejected(&self) -> bool {
        self.state == PromiseState::Rejected
    }

    /// 結果を取得（成功時のみ）
    pub fn get_value(&self) -> Option<&ScriptValue> {
        self.value.as_ref().map(|b| b.as_ref())
    }

    /// エラーを取得（拒否時のみ）
    pub fn get_error(&self) -> Option<&str> {
        self.error.as_deref()
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
        
        // ScriptValueはPartialEqを実装していないので、パターンマッチで確認
        match iter.next() {
            Some(ScriptValue::Int(0)) => {}
            _ => panic!("Expected Int(0)"),
        }
        match iter.next() {
            Some(ScriptValue::Int(1)) => {}
            _ => panic!("Expected Int(1)"),
        }
        match iter.next() {
            Some(ScriptValue::Int(2)) => {}
            _ => panic!("Expected Int(2)"),
        }
        assert!(iter.next().is_none());
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
