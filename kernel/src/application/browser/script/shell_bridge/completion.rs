// ============================================================================
// src/application/browser/script/shell_bridge/completion.rs - Completion Support
// ============================================================================
//!
//! シェル補完とヘルプ機能

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

use crate::application::browser::script::value::ScriptValue;

// ============================================================================
// Shell Command Wrapper
// ============================================================================

/// シェルコマンドのラッパー構造体
pub struct ShellCommand {
    pub name: String,
    pub args: Vec<ScriptValue>,
}

impl ShellCommand {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            args: Vec::new(),
        }
    }

    pub fn arg(mut self, value: ScriptValue) -> Self {
        self.args.push(value);
        self
    }

    /// コマンドをRustScript形式のコードに変換
    pub fn to_script(&self) -> String {
        let args_str: Vec<String> = self.args.iter()
            .map(|a| match a {
                ScriptValue::String(s) => format!("\"{}\"", s),
                ScriptValue::Int(i) => format!("{}", i),
                ScriptValue::Float(f) => format!("{}", f),
                ScriptValue::Bool(b) => format!("{}", b),
                _ => String::from("nil"),
            })
            .collect();
        
        format!("{}({})", self.name, args_str.join(", "))
    }
}

// ============================================================================
// Completion Hints
// ============================================================================

/// シェル補完のためのヒント情報
#[derive(Debug, Clone)]
pub struct CompletionHint {
    pub text: String,
    pub description: String,
    pub category: CompletionCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionCategory {
    Function,
    Variable,
    Path,
    Keyword,
}

// ============================================================================
// Builtin Functions List
// ============================================================================

/// 組み込み関数のリスト
pub const BUILTIN_FUNCTIONS: &[(&str, &str)] = &[
    ("fs_ls", "List directory contents"),
    ("fs_read", "Read file contents"),
    ("fs_write", "Write to file"),
    ("fs_stat", "Get file information"),
    ("fs_mkdir", "Create directory"),
    ("fs_rm", "Remove file or directory"),
    ("ps", "List processes"),
    ("net_config", "Show network configuration"),
    ("net_connections", "List network connections"),
    ("uptime", "Show system uptime"),
    ("memory_info", "Show memory information"),
    ("print", "Print value"),
    ("println", "Print value with newline"),
    ("type_of", "Get type name"),
    ("len", "Get length"),
];

/// キーワードのリスト
pub const KEYWORDS: &[&str] = &[
    "let", "fn", "if", "else", "for", "while", "return", "true", "false", "nil"
];

// ============================================================================
// Help Text
// ============================================================================

/// ヘルプメッセージを生成
pub fn generate_help() -> ScriptValue {
    let help_text = r#"ExoShell + RustScript - Integrated Shell Runtime

== File System ==
  fs_ls(path)           List directory contents
  fs_read(path)         Read file contents  
  fs_write(path, data)  Write to file
  fs_stat(path)         Get file information
  fs_mkdir(path)        Create directory
  fs_rm(path)           Remove file or directory

== Process Management ==
  ps()                  List running processes

== Network ==
  net_config()          Show network configuration
  net_connections()     List active connections

== System ==
  uptime()              Show system uptime
  memory_info()         Show memory usage

== Utilities ==
  print(value)          Print value
  println(value)        Print value with newline
  type_of(value)        Get type name
  len(value)            Get length

== Language Features ==
  let x = 42;           Variable declaration
  fn add(a, b) { a + b }  Function definition
  if cond { } else { }  Conditional
  for i in 0..10 { }    For loop
  while cond { }        While loop

== Async Operations ==
  fs_ls_async(path)     Async directory listing
  fs_read_async(path)   Async file read
  net_ping(ip, count)   Async ping
  sleep(ms)             Async sleep
  await promise         Wait for promise

== Special Variables ==
  $_ or _               Last result
  $PWD                  Current directory
"#;
    ScriptValue::String(help_text.to_string())
}
