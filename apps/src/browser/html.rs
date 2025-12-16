// ============================================================================
// apps/src/browser/html.rs - HTML Parser
// ============================================================================
//!
//! HTML parsing for the browser engine.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::dom::{ElementData, Node, NodeType};

/// HTML Parser
pub struct HtmlParser {
    pos: usize,
    input: String,
}

impl HtmlParser {
    /// Parse HTML string into DOM tree
    pub fn parse(html: &str) -> Node {
        let mut parser = HtmlParser {
            pos: 0,
            input: html.to_string(),
        };
        let nodes = parser.parse_nodes();
        if nodes.len() == 1 {
            nodes.into_iter().next().unwrap()
        } else {
            Node::element("html", BTreeMap::new(), nodes)
        }
    }

    fn parse_nodes(&mut self) -> Vec<Node> {
        let mut nodes = Vec::new();
        loop {
            self.consume_whitespace();
            if self.eof() || self.starts_with("</") {
                break;
            }
            nodes.push(self.parse_node());
        }
        nodes
    }

    fn parse_node(&mut self) -> Node {
        if self.starts_with("<") {
            self.parse_element()
        } else {
            self.parse_text()
        }
    }

    fn parse_element(&mut self) -> Node {
        // Opening tag
        self.expect("<");
        let tag_name = self.parse_tag_name();
        let attrs = self.parse_attributes();
        self.expect(">");

        // Contents
        let children = self.parse_nodes();

        // Closing tag
        self.expect("</");
        self.parse_tag_name();
        self.expect(">");

        Node::element(&tag_name, attrs, children)
    }

    fn parse_text(&mut self) -> Node {
        let text = self.consume_while(|c| c != '<');
        Node::text(&text)
    }

    fn parse_tag_name(&mut self) -> String {
        self.consume_while(|c| c.is_alphanumeric())
    }

    fn parse_attributes(&mut self) -> BTreeMap<String, String> {
        let mut attrs = BTreeMap::new();
        loop {
            self.consume_whitespace();
            if self.next_char() == '>' || self.starts_with("/>") {
                break;
            }
            let (name, value) = self.parse_attr();
            attrs.insert(name, value);
        }
        attrs
    }

    fn parse_attr(&mut self) -> (String, String) {
        let name = self.parse_tag_name();
        // Some tags may have boolean attributes or malformed attributes. If
        // there is no `=` following the attribute name, return an empty
        // string as the value instead of panicking.
        if !self.starts_with("=") {
            return (name, String::new());
        }
        self.expect("=");
        let value = self.parse_attr_value();
        (name, value)
    }

    fn parse_attr_value(&mut self) -> String {
        // Support both quoted and unquoted attribute values. If input is
        // malformed we avoid panicking and return a best-effort string.
        if self.eof() {
            return String::new();
        }

        let open_quote = self.consume_char();

        // Quoted value
        if open_quote == '"' || open_quote == '\'' {
            let value = self.consume_while(|c| c != open_quote);
            // Consume closing quote if present
            if !self.eof() && self.next_char() == open_quote {
                self.consume_char();
            }
            return value;
        }

        // Unquoted value: consume until whitespace or closing tag
        let mut val = String::new();
        val.push(open_quote);
        val.push_str(&self.consume_while(|c| !c.is_whitespace() && c != '>'));
        val
    }

    fn consume_whitespace(&mut self) {
        self.consume_while(|c| c.is_whitespace());
    }

    fn consume_while<F>(&mut self, test: F) -> String
    where
        F: Fn(char) -> bool,
    {
        let mut result = String::new();
        while !self.eof() && test(self.next_char()) {
            result.push(self.consume_char());
        }
        result
    }

    fn consume_char(&mut self) -> char {
        let mut iter = self.input[self.pos..].char_indices();
        let (_, cur_char) = iter.next().unwrap();
        let (next_pos, _) = iter.next().unwrap_or((1, ' '));
        self.pos += next_pos;
        cur_char
    }

    fn next_char(&self) -> char {
        self.input[self.pos..].chars().next().unwrap_or('\0')
    }

    fn starts_with(&self, s: &str) -> bool {
        self.input[self.pos..].starts_with(s)
    }

    fn expect(&mut self, s: &str) {
        if self.starts_with(s) {
            self.pos += s.len();
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }
}

use alloc::string::ToString;
