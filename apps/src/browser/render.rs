// ============================================================================
// apps/src/browser/render.rs - Rendering Engine
// ============================================================================
//!
//! Rendering for the browser engine.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::string::String;
use alloc::vec::Vec;

use super::layout::{LayoutBox, Rect};
use super::css::CssColor;

/// Display list
pub type DisplayList = Vec<DisplayCommand>;

/// Display command
#[derive(Debug, Clone)]
pub enum DisplayCommand {
    SolidColor(CssColor, Rect),
    Text(String, CssColor, f32, f32, f32),  // text, color, x, y, font_size
    HorizontalRule(CssColor, f32, f32, f32), // color, x, y, width
}

/// Build display list from layout tree
pub fn build_display_list<'a>(_layout_root: &LayoutBox<'a>) -> DisplayList {
    Vec::new()
}

/// Paint display list to canvas
pub fn paint<'a>(_display_list: &DisplayList, _bounds: Rect) {
    // Stub - actual painting handled by browser.rs
}
