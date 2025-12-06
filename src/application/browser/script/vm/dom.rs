// ============================================================================
// src/application/browser/script/vm/dom.rs - DOM Operations
// ============================================================================
//!
//! DOM操作の定義。

use alloc::string::String;

/// DOM操作
#[derive(Debug, Clone)]
pub enum DomOperation {
    GetElementById(String),
    GetElementsByClass(String),
    GetElementsByTag(String),
    CreateElement(String),
    AppendChild(usize, usize),
    RemoveChild(usize, usize),
    SetAttribute(usize, String, String),
    GetAttribute(usize, String),
    SetText(usize, String),
    GetText(usize),
    SetStyle(usize, String, String),
    GetStyle(usize, String),
    AddClass(usize, String),
    RemoveClass(usize, String),
    AddEventListener(usize, String, usize),
}
