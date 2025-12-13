// ============================================================================
// apps/src/browser/style.rs - Style Tree
// ============================================================================
//!
//! Style tree computation for the browser engine.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::vec::Vec;

use super::css::Stylesheet;
use super::dom::Node;

/// Styled Node
#[derive(Debug, Clone)]
pub struct StyledNode<'a> {
    pub node: &'a Node,
    pub children: Vec<StyledNode<'a>>,
}

/// Build style tree from DOM and stylesheet
pub fn style_tree<'a>(root: &'a Node, _stylesheet: &Stylesheet) -> StyledNode<'a> {
    let children = root
        .children
        .iter()
        .map(|c| style_tree(c, _stylesheet))
        .collect();
    StyledNode {
        node: root,
        children,
    }
}
