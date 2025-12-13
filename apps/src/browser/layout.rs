// ============================================================================
// apps/src/browser/layout.rs - Layout Engine
// ============================================================================
//!
//! Layout computation for the browser engine.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::vec::Vec;

use super::style::StyledNode;

/// Dimensions
#[derive(Debug, Clone, Copy, Default)]
pub struct Dimensions {
    pub content: Rect,
    pub padding: EdgeSizes,
    pub border: EdgeSizes,
    pub margin: EdgeSizes,
}

/// Rectangle
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Rect {
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }
}

/// Edge sizes
#[derive(Debug, Clone, Copy, Default)]
pub struct EdgeSizes {
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
    pub left: f32,
}

/// Layout Box
#[derive(Debug, Clone)]
pub struct LayoutBox<'a> {
    pub dimensions: Dimensions,
    pub box_type: BoxType<'a>,
    pub children: Vec<LayoutBox<'a>>,
}

/// Box type
#[derive(Debug, Clone)]
pub enum BoxType<'a> {
    BlockNode(&'a StyledNode<'a>),
    InlineNode(&'a StyledNode<'a>),
    AnonymousBlock,
}

/// Build layout tree from styled tree
pub fn layout_tree<'a>(style_root: &'a StyledNode, containing_block: Dimensions) -> LayoutBox<'a> {
    LayoutBox {
        dimensions: containing_block,
        box_type: BoxType::BlockNode(style_root),
        children: style_root
            .children
            .iter()
            .map(|child| layout_tree(child, Dimensions::default()))
            .collect(),
    }
}
