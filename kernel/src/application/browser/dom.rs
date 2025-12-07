// ============================================================================
// src/application/browser/dom.rs - DOM Tree Structure
// ============================================================================
//!
//! # DOM (Document Object Model)
//!
//! HTMLドキュメントをツリー構造で表現。

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

// ============================================================================
// Node Types
// ============================================================================

/// DOMノードの種類
#[derive(Debug, Clone, PartialEq)]
pub enum NodeType {
    /// テキストノード
    Text(String),
    /// 要素ノード
    Element(ElementData),
    /// コメントノード
    Comment(String),
    /// ドキュメントノード（ルート）
    Document,
}

/// 要素データ
#[derive(Debug, Clone, PartialEq)]
pub struct ElementData {
    /// タグ名（小文字）
    pub tag_name: String,
    /// 属性
    pub attributes: AttrMap,
}

/// 属性マップ
pub type AttrMap = BTreeMap<String, String>;

// ============================================================================
// DOM Node
// ============================================================================

/// DOMノード
#[derive(Debug, Clone)]
pub struct Node {
    /// ノードの種類
    pub node_type: NodeType,
    /// 子ノード
    pub children: Vec<Node>,
}

impl Node {
    /// テキストノードを作成
    pub fn text(data: String) -> Self {
        Self {
            node_type: NodeType::Text(data),
            children: Vec::new(),
        }
    }

    /// 要素ノードを作成
    pub fn elem(tag_name: String, attrs: AttrMap, children: Vec<Node>) -> Self {
        Self {
            node_type: NodeType::Element(ElementData {
                tag_name,
                attributes: attrs,
            }),
            children,
        }
    }

    /// コメントノードを作成
    pub fn comment(data: String) -> Self {
        Self {
            node_type: NodeType::Comment(data),
            children: Vec::new(),
        }
    }

    /// ドキュメントノードを作成
    pub fn document(children: Vec<Node>) -> Self {
        Self {
            node_type: NodeType::Document,
            children,
        }
    }

    /// 要素データを取得
    pub fn element_data(&self) -> Option<&ElementData> {
        match &self.node_type {
            NodeType::Element(data) => Some(data),
            _ => None,
        }
    }

    /// テキスト内容を取得
    pub fn text_content(&self) -> Option<&str> {
        match &self.node_type {
            NodeType::Text(s) => Some(s),
            _ => None,
        }
    }

    /// 要素かどうか
    pub fn is_element(&self) -> bool {
        matches!(self.node_type, NodeType::Element(_))
    }

    /// テキストかどうか
    pub fn is_text(&self) -> bool {
        matches!(self.node_type, NodeType::Text(_))
    }

    /// タグ名を取得（要素の場合）
    pub fn tag_name(&self) -> Option<&str> {
        self.element_data().map(|d| d.tag_name.as_str())
    }

    /// 属性を取得
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.element_data()
            .and_then(|d| d.attributes.get(name))
            .map(|s| s.as_str())
    }

    /// ID属性を取得
    pub fn id(&self) -> Option<&str> {
        self.get_attribute("id")
    }

    /// クラス属性を取得（スペース区切りのリスト）
    pub fn classes(&self) -> Vec<&str> {
        self.get_attribute("class")
            .map(|c| c.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// 子要素を追加
    pub fn append_child(&mut self, child: Node) {
        self.children.push(child);
    }

    /// すべての子孫テキストを結合
    pub fn inner_text(&self) -> String {
        let mut result = String::new();
        self.collect_text(&mut result);
        result
    }

    fn collect_text(&self, result: &mut String) {
        match &self.node_type {
            NodeType::Text(s) => result.push_str(s),
            _ => {
                for child in &self.children {
                    child.collect_text(result);
                }
            }
        }
    }

    /// 特定のタグ名の要素を検索
    pub fn find_elements_by_tag(&self, tag: &str) -> Vec<&Node> {
        let mut results = Vec::new();
        self.find_elements_by_tag_recursive(tag, &mut results);
        results
    }

    fn find_elements_by_tag_recursive<'a>(&'a self, tag: &str, results: &mut Vec<&'a Node>) {
        if let Some(t) = self.tag_name() {
            if t.eq_ignore_ascii_case(tag) {
                results.push(self);
            }
        }
        for child in &self.children {
            child.find_elements_by_tag_recursive(tag, results);
        }
    }

    /// IDで要素を検索
    pub fn find_element_by_id(&self, id: &str) -> Option<&Node> {
        if self.id() == Some(id) {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_element_by_id(id) {
                return Some(found);
            }
        }
        None
    }

    /// クラスで要素を検索
    pub fn find_elements_by_class(&self, class: &str) -> Vec<&Node> {
        let mut results = Vec::new();
        self.find_elements_by_class_recursive(class, &mut results);
        results
    }

    fn find_elements_by_class_recursive<'a>(&'a self, class: &str, results: &mut Vec<&'a Node>) {
        if self.classes().contains(&class) {
            results.push(self);
        }
        for child in &self.children {
            child.find_elements_by_class_recursive(class, results);
        }
    }
}

impl ElementData {
    /// 新しい要素データを作成
    pub fn new(tag_name: String) -> Self {
        Self {
            tag_name,
            attributes: BTreeMap::new(),
        }
    }

    /// 属性を設定
    pub fn set_attribute(&mut self, name: String, value: String) {
        self.attributes.insert(name, value);
    }
}

// ============================================================================
// Pretty Print (デバッグ用)
// ============================================================================

impl Node {
    /// DOMツリーを整形して文字列化
    pub fn pretty_print(&self, indent: usize) -> String {
        let mut result = String::new();
        let spaces = "  ".repeat(indent);

        match &self.node_type {
            NodeType::Document => {
                result.push_str("#document\n");
            }
            NodeType::Text(s) => {
                let text = s.trim();
                if !text.is_empty() {
                    result.push_str(&spaces);
                    result.push_str("\"");
                    result.push_str(text);
                    result.push_str("\"\n");
                }
            }
            NodeType::Element(data) => {
                result.push_str(&spaces);
                result.push('<');
                result.push_str(&data.tag_name);
                for (name, value) in &data.attributes {
                    result.push(' ');
                    result.push_str(name);
                    result.push_str("=\"");
                    result.push_str(value);
                    result.push('"');
                }
                result.push_str(">\n");
            }
            NodeType::Comment(s) => {
                result.push_str(&spaces);
                result.push_str("<!-- ");
                result.push_str(s);
                result.push_str(" -->\n");
            }
        }

        for child in &self.children {
            result.push_str(&child.pretty_print(indent + 1));
        }

        result
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_node() {
        let node = Node::text("Hello".into());
        assert!(node.is_text());
        assert_eq!(node.text_content(), Some("Hello"));
    }

    #[test]
    fn test_element_node() {
        let mut attrs = BTreeMap::new();
        attrs.insert("id".into(), "main".into());
        attrs.insert("class".into(), "container wide".into());

        let node = Node::elem("div".into(), attrs, vec![]);
        assert!(node.is_element());
        assert_eq!(node.tag_name(), Some("div"));
        assert_eq!(node.id(), Some("main"));
        assert_eq!(node.classes(), vec!["container", "wide"]);
    }

    #[test]
    fn test_inner_text() {
        let child1 = Node::text("Hello ".into());
        let child2 = Node::text("World".into());
        let parent = Node::elem("p".into(), BTreeMap::new(), vec![child1, child2]);
        assert_eq!(parent.inner_text(), "Hello World");
    }
}
