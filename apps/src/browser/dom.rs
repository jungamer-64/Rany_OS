// ============================================================================
// apps/src/browser/dom.rs - DOM Types
// ============================================================================
//!
//! DOM Node representation for the browser engine.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// DOM Node
#[derive(Debug, Clone)]
pub struct Node {
    pub node_type: NodeType,
    pub children: Vec<Node>,
}

/// Node type
#[derive(Debug, Clone)]
pub enum NodeType {
    Element(ElementData),
    Text(String),
}

/// Element data
#[derive(Debug, Clone)]
pub struct ElementData {
    pub tag_name: String,
    pub attributes: BTreeMap<String, String>,
}

impl Node {
    /// Create new element node
    pub fn element(tag_name: &str, attrs: BTreeMap<String, String>, children: Vec<Node>) -> Self {
        Self {
            node_type: NodeType::Element(ElementData {
                tag_name: tag_name.to_string(),
                attributes: attrs,
            }),
            children,
        }
    }

    /// Create new text node
    pub fn text(text: &str) -> Self {
        Self {
            node_type: NodeType::Text(text.to_string()),
            children: Vec::new(),
        }
    }

    /// Find elements by tag name
    pub fn find_elements_by_tag(&self, tag: &str) -> Vec<&Node> {
        let mut result = Vec::new();
        self.find_elements_by_tag_recursive(tag, &mut result);
        result
    }

    fn find_elements_by_tag_recursive<'a>(&'a self, tag: &str, result: &mut Vec<&'a Node>) {
        if let NodeType::Element(data) = &self.node_type {
            if data.tag_name == tag {
                result.push(self);
            }
        }
        for child in &self.children {
            child.find_elements_by_tag_recursive(tag, result);
        }
    }

    /// Get inner text
    pub fn inner_text(&self) -> String {
        match &self.node_type {
            NodeType::Text(s) => s.clone(),
            NodeType::Element(_) => self.children.iter().map(|c| c.inner_text()).collect(),
        }
    }
}

use alloc::string::ToString;
