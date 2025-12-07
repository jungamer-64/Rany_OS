// ============================================================================
// src/application/browser/script/mod.rs - RustScript Engine for Browser
// ============================================================================
//!
//! # RustScript - ブラウザ内Rustスクリプトエンジン
//!
//! JavaScriptの代わりにRust風構文でDOM操作を行うスクリプトエンジン。
//! ExoShellの設計思想を継承し、型安全なブラウザプログラミングを実現。
//!
//! ## 設計原則
//! 1. **型付きDOM**: 文字列ではなく構造化されたDOM操作
//! 2. **安全性**: メモリ安全なスクリプト実行
//! 3. **Rust構文**: 馴染みのあるRust風文法
//! 4. **イベント駆動**: クリック・入力などのイベントハンドリング
//!
//! ## 使用例
//! ```html
//! <script type="text/rustscript">
//! // DOM要素の取得と操作
//! let button = dom.get_element_by_id("myButton");
//! button.on_click(|| {
//!     let counter = dom.get_element_by_id("counter");
//!     let value: i32 = counter.text().parse();
//!     counter.set_text((value + 1).to_string());
//! });
//!
//! // スタイル変更
//! dom.get_element_by_id("title").style.color = "red";
//! </script>
//! ```

extern crate alloc;

pub mod lexer;
pub mod parser;
pub mod ast;
pub mod vm;
pub mod value;
pub mod dom_binding;
pub mod runtime;
pub mod shell_bridge;

// Re-exports
pub use lexer::{Lexer, Token, TokenKind};
pub use parser::Parser;
pub use ast::{Ast, Expr, Stmt};
pub use vm::{VirtualMachine, Instruction, ConstantPool};
pub use value::{ScriptValue, ScriptType};
pub use dom_binding::{DomBinding, DocumentNode};
pub use runtime::ScriptRuntime;
pub use shell_bridge::ShellRuntime;

use alloc::string::String;
use alloc::format;

/// スクリプトの実行結果型
pub type ScriptResult<T> = Result<T, ScriptError>;

/// スクリプトエラー
#[derive(Debug, Clone)]
pub struct ScriptError {
    /// エラーメッセージ
    pub message: String,
    /// 行番号
    pub line: usize,
    /// 列番号
    pub column: usize,
    /// エラー種別
    pub kind: ErrorKind,
}

/// エラー種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// 構文エラー
    Syntax,
    /// 型エラー
    Type,
    /// 未定義参照エラー
    Reference,
    /// 実行時エラー
    Runtime,
    /// DOM操作エラー
    Dom,
}

impl ScriptError {
    pub fn new(kind: ErrorKind, message: &str, line: usize, column: usize) -> Self {
        Self {
            message: String::from(message),
            line,
            column,
            kind,
        }
    }

    pub fn syntax(message: &str, line: usize, column: usize) -> Self {
        Self::new(ErrorKind::Syntax, message, line, column)
    }

    pub fn type_error(message: &str, line: usize, column: usize) -> Self {
        Self::new(ErrorKind::Type, message, line, column)
    }

    pub fn reference(message: &str, line: usize, column: usize) -> Self {
        Self::new(ErrorKind::Reference, message, line, column)
    }

    pub fn runtime(message: &str) -> Self {
        Self::new(ErrorKind::Runtime, message, 0, 0)
    }

    pub fn dom(message: &str) -> Self {
        Self::new(ErrorKind::Dom, message, 0, 0)
    }
}

impl core::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} at {}:{}: {}", self.kind, self.line, self.column, self.message)
    }
}

/// RustScriptエンジン
/// 
/// HTMLの`<script type="text/rustscript">`タグの内容を解析・実行する
pub struct RustScriptEngine {
    /// ランタイム
    runtime: ScriptRuntime,
}

impl RustScriptEngine {
    /// 新しいエンジンを作成
    pub fn new() -> Self {
        Self {
            runtime: ScriptRuntime::new(),
        }
    }

    /// DOMを初期化
    pub fn initialize_dom(&mut self, root: &DocumentNode) {
        self.runtime.initialize_dom(root);
    }

    /// スクリプトを実行
    pub fn execute(&mut self, source: &str) -> ScriptResult<ScriptValue> {
        self.runtime.execute(source)
    }

    /// グローバル変数を設定
    pub fn set_global(&mut self, name: &str, value: ScriptValue) {
        self.runtime.set_global(name, value);
    }

    /// グローバル変数を取得
    pub fn get_global(&self, name: &str) -> Option<&ScriptValue> {
        self.runtime.get_global(name)
    }

    /// イベントを発火
    pub fn dispatch_event(&mut self, event: runtime::Event) {
        self.runtime.dispatch_event(event);
    }

    /// イベントキューを処理
    pub fn process_events(&mut self) -> ScriptResult<()> {
        self.runtime.process_events()
    }

    /// タイマーを処理
    pub fn process_timers(&mut self, current_tick: u64) -> ScriptResult<()> {
        self.runtime.process_timers(current_tick)
    }

    /// DOMバインディングへの参照を取得
    pub fn dom(&mut self) -> &mut DomBinding {
        self.runtime.dom()
    }
}

impl Default for RustScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let _engine = RustScriptEngine::new();
        // エンジンが正常に作成されることを確認
    }

    #[test]
    fn test_simple_expression() {
        let mut engine = RustScriptEngine::new();
        let result = engine.execute("1 + 2");
        assert!(result.is_ok());
    }
}
