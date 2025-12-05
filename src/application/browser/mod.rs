// ============================================================================
// src/application/browser/mod.rs - Web Browser Engine
// ============================================================================
//!
//! # Webブラウザエンジン
//!
//! シンプルなHTML/CSSレンダリングエンジンとRustScriptスクリプトエンジンの実装。
//!
//! ## アーキテクチャ
//!
//! ```text
//! HTML String → [html.rs] → DOM Tree
//!                              ↓
//! CSS String  → [css.rs]  → Stylesheet
//!                              ↓
//!              [style.rs] → Style Tree (DOM + computed styles)
//!                              ↓
//!             [layout.rs] → Layout Tree (positions & sizes)
//!                              ↓
//!             [render.rs] → Display Commands → Screen
//! ```
//!
//! ## RustScript
//!
//! JavaScriptの代わりにRust風構文でDOMを操作するスクリプトエンジン。
//! `<script type="text/rustscript">` タグで使用可能。

extern crate alloc;

pub mod dom;
pub mod html;
pub mod css;
pub mod style;
pub mod layout;
pub mod render;
pub mod browser;
pub mod script;

// Re-exports
pub use dom::{Node, NodeType, ElementData};
pub use html::HtmlParser;
pub use css::{Stylesheet, Selector, Declaration, Value};
pub use style::{StyledNode, Display};
pub use layout::{LayoutBox, Dimensions, Rect as LayoutRect};
pub use render::{DisplayCommand, DisplayList};
pub use browser::Browser;
pub use script::{RustScriptEngine, ScriptRuntime, ScriptValue};
