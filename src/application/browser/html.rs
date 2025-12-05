// ============================================================================
// src/application/browser/html.rs - HTML Parser
// ============================================================================
//!
//! # HTMLパーサー
//!
//! HTML文字列をトークナイズし、DOMツリーを構築するステートマシン。

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::collections::BTreeMap;

use super::dom::{Node, AttrMap};

// ============================================================================
// Parser State
// ============================================================================

/// パーサーの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// データ（テキスト）
    Data,
    /// タグ開始
    TagOpen,
    /// 終了タグ開始
    EndTagOpen,
    /// タグ名
    TagName,
    /// 終了タグ名
    EndTagName,
    /// 自己終了タグ
    SelfClosingStartTag,
    /// 属性名の前
    BeforeAttributeName,
    /// 属性名
    AttributeName,
    /// 属性名の後
    AfterAttributeName,
    /// 属性値の前
    BeforeAttributeValue,
    /// 属性値（引用符なし）
    AttributeValueUnquoted,
    /// 属性値（ダブルクォート）
    AttributeValueDoubleQuoted,
    /// 属性値（シングルクォート）
    AttributeValueSingleQuoted,
    /// 属性値の後
    AfterAttributeValueQuoted,
    /// コメント開始
    MarkupDeclarationOpen,
    /// コメント開始ダッシュ
    CommentStart,
    /// コメント
    Comment,
    /// コメント終了ダッシュ
    CommentEndDash,
    /// コメント終了
    CommentEnd,
    /// DOCTYPE
    Doctype,
}

// ============================================================================
// HTML Parser
// ============================================================================

/// HTMLパーサー
pub struct HtmlParser {
    /// 入力文字列
    input: Vec<char>,
    /// 現在位置
    pos: usize,
    /// 現在の状態
    state: State,
}

impl HtmlParser {
    /// 新しいパーサーを作成
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
            state: State::Data,
        }
    }

    /// HTMLをパースしてDOMツリーを返す
    pub fn parse(input: &str) -> Node {
        let mut parser = HtmlParser::new(input);
        parser.parse_document()
    }

    /// 現在の文字を取得
    fn current_char(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    /// 次の文字を覗く
    fn peek_char(&self) -> Option<char> {
        self.input.get(self.pos + 1).copied()
    }

    /// 次の文字へ進む
    fn advance(&mut self) -> Option<char> {
        let c = self.current_char();
        self.pos += 1;
        c
    }

    /// EOFかどうか
    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// 空白をスキップ
    fn skip_whitespace(&mut self) {
        while let Some(c) = self.current_char() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// 特定の文字列で始まるか
    fn starts_with(&self, s: &str) -> bool {
        let remaining: String = self.input[self.pos..].iter().collect();
        remaining.starts_with(s)
    }

    /// 特定の文字列で始まるか（大文字小文字無視）
    fn starts_with_ignore_case(&self, s: &str) -> bool {
        let remaining: String = self.input[self.pos..].iter().collect();
        remaining.to_lowercase().starts_with(&s.to_lowercase())
    }

    /// ドキュメント全体をパース
    fn parse_document(&mut self) -> Node {
        let children = self.parse_nodes();
        Node::document(children)
    }

    /// ノードのリストをパース
    fn parse_nodes(&mut self) -> Vec<Node> {
        let mut nodes = Vec::new();

        loop {
            if self.eof() {
                break;
            }

            // 終了タグの開始を検出
            if self.starts_with("</") {
                break;
            }

            if let Some(node) = self.parse_node() {
                nodes.push(node);
            }
        }

        nodes
    }

    /// 単一ノードをパース
    fn parse_node(&mut self) -> Option<Node> {
        match self.current_char()? {
            '<' => self.parse_element_or_special(),
            _ => self.parse_text(),
        }
    }

    /// 要素または特殊構文をパース
    fn parse_element_or_special(&mut self) -> Option<Node> {
        // コメント
        if self.starts_with("<!--") {
            return self.parse_comment();
        }

        // DOCTYPE
        if self.starts_with_ignore_case("<!doctype") {
            return self.parse_doctype();
        }

        // 通常の要素
        self.parse_element()
    }

    /// テキストノードをパース
    fn parse_text(&mut self) -> Option<Node> {
        let mut text = String::new();

        while let Some(c) = self.current_char() {
            if c == '<' {
                break;
            }
            text.push(c);
            self.advance();
        }

        if text.is_empty() {
            None
        } else {
            // HTMLエンティティをデコード
            let decoded = self.decode_entities(&text);
            Some(Node::text(decoded))
        }
    }

    /// HTMLエンティティをデコード
    fn decode_entities(&self, text: &str) -> String {
        let mut result = String::new();
        let mut chars = text.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '&' {
                let mut entity = String::new();
                while let Some(&ec) = chars.peek() {
                    if ec == ';' {
                        chars.next();
                        break;
                    }
                    if ec.is_alphanumeric() || ec == '#' {
                        entity.push(ec);
                        chars.next();
                    } else {
                        break;
                    }
                }

                let decoded = match entity.as_str() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    "nbsp" => '\u{00A0}',
                    s if s.starts_with('#') => {
                        self.decode_numeric_entity(&s[1..]).unwrap_or('?')
                    }
                    _ => {
                        result.push('&');
                        result.push_str(&entity);
                        result.push(';');
                        continue;
                    }
                };
                result.push(decoded);
            } else {
                result.push(c);
            }
        }

        result
    }

    /// 数値エンティティをデコード
    fn decode_numeric_entity(&self, s: &str) -> Option<char> {
        let num = if s.starts_with('x') || s.starts_with('X') {
            u32::from_str_radix(&s[1..], 16).ok()?
        } else {
            s.parse().ok()?
        };
        char::from_u32(num)
    }

    /// コメントをパース
    fn parse_comment(&mut self) -> Option<Node> {
        // "<!--" をスキップ
        for _ in 0..4 {
            self.advance();
        }

        let mut comment = String::new();

        loop {
            if self.eof() {
                break;
            }

            if self.starts_with("-->") {
                for _ in 0..3 {
                    self.advance();
                }
                break;
            }

            if let Some(c) = self.advance() {
                comment.push(c);
            }
        }

        Some(Node::comment(comment))
    }

    /// DOCTYPEをパース（無視）
    fn parse_doctype(&mut self) -> Option<Node> {
        // ">" まで読み飛ばす
        while let Some(c) = self.advance() {
            if c == '>' {
                break;
            }
        }
        None
    }

    /// 要素をパース
    fn parse_element(&mut self) -> Option<Node> {
        // '<' をスキップ
        self.advance();

        // タグ名を取得
        let tag_name = self.parse_tag_name();
        if tag_name.is_empty() {
            return None;
        }

        // 属性を取得
        let attributes = self.parse_attributes();

        // 自己終了タグか
        let self_closing = self.current_char() == Some('/');
        if self_closing {
            self.advance();
        }

        // '>' をスキップ
        if self.current_char() == Some('>') {
            self.advance();
        }

        // Void elements（終了タグなし）
        let is_void = matches!(
            tag_name.as_str(),
            "area" | "base" | "br" | "col" | "embed" | "hr" | "img" | "input"
            | "link" | "meta" | "param" | "source" | "track" | "wbr"
        );

        let children = if self_closing || is_void {
            Vec::new()
        } else {
            // 特殊要素（rawテキスト）
            if matches!(tag_name.as_str(), "script" | "style") {
                self.parse_raw_text(&tag_name)
            } else {
                let children = self.parse_nodes();
                self.parse_end_tag(&tag_name);
                children
            }
        };

        Some(Node::elem(tag_name, attributes, children))
    }

    /// タグ名をパース
    fn parse_tag_name(&mut self) -> String {
        let mut name = String::new();

        while let Some(c) = self.current_char() {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                name.push(c.to_ascii_lowercase());
                self.advance();
            } else {
                break;
            }
        }

        name
    }

    /// 属性をパース
    fn parse_attributes(&mut self) -> AttrMap {
        let mut attrs = BTreeMap::new();

        loop {
            self.skip_whitespace();

            match self.current_char() {
                None | Some('>') | Some('/') => break,
                _ => {
                    if let Some((name, value)) = self.parse_attribute() {
                        attrs.insert(name, value);
                    }
                }
            }
        }

        attrs
    }

    /// 単一属性をパース
    fn parse_attribute(&mut self) -> Option<(String, String)> {
        // 属性名
        let name = self.parse_attribute_name();
        if name.is_empty() {
            return None;
        }

        self.skip_whitespace();

        // '=' があれば値を取得
        let value = if self.current_char() == Some('=') {
            self.advance();
            self.skip_whitespace();
            self.parse_attribute_value()
        } else {
            String::new()
        };

        Some((name, value))
    }

    /// 属性名をパース
    fn parse_attribute_name(&mut self) -> String {
        let mut name = String::new();

        while let Some(c) = self.current_char() {
            match c {
                '=' | '>' | '/' | '"' | '\'' | '<' => break,
                c if c.is_whitespace() => break,
                _ => {
                    name.push(c.to_ascii_lowercase());
                    self.advance();
                }
            }
        }

        name
    }

    /// 属性値をパース
    fn parse_attribute_value(&mut self) -> String {
        let quote = self.current_char();

        match quote {
            Some('"') | Some('\'') => {
                self.advance();
                let mut value = String::new();
                while let Some(c) = self.current_char() {
                    if Some(c) == quote {
                        self.advance();
                        break;
                    }
                    value.push(c);
                    self.advance();
                }
                self.decode_entities(&value)
            }
            _ => {
                // 引用符なし
                let mut value = String::new();
                while let Some(c) = self.current_char() {
                    if c.is_whitespace() || c == '>' || c == '/' {
                        break;
                    }
                    value.push(c);
                    self.advance();
                }
                self.decode_entities(&value)
            }
        }
    }

    /// 終了タグをパース
    fn parse_end_tag(&mut self, expected: &str) {
        if !self.starts_with("</") {
            return;
        }

        self.advance(); // '<'
        self.advance(); // '/'

        let tag_name = self.parse_tag_name();

        // 期待されるタグ名と一致するか（寛容）
        if !tag_name.eq_ignore_ascii_case(expected) {
            // 不一致でもスキップ
        }

        // '>' まで読み飛ばす
        while let Some(c) = self.current_char() {
            self.advance();
            if c == '>' {
                break;
            }
        }
    }

    /// <script> や <style> の生テキストをパース
    fn parse_raw_text(&mut self, tag_name: &str) -> Vec<Node> {
        let end_tag = alloc::format!("</{}", tag_name);
        let mut text = String::new();

        loop {
            if self.eof() {
                break;
            }

            if self.starts_with_ignore_case(&end_tag) {
                self.parse_end_tag(tag_name);
                break;
            }

            if let Some(c) = self.advance() {
                text.push(c);
            }
        }

        if text.is_empty() {
            Vec::new()
        } else {
            vec![Node::text(text)]
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_element() {
        let html = "<div>Hello</div>";
        let doc = HtmlParser::parse(html);
        
        assert_eq!(doc.children.len(), 1);
        let div = &doc.children[0];
        assert_eq!(div.tag_name(), Some("div"));
        assert_eq!(div.inner_text(), "Hello");
    }

    #[test]
    fn test_parse_attributes() {
        let html = r#"<a href="https://example.com" class="link">Click</a>"#;
        let doc = HtmlParser::parse(html);
        
        let a = &doc.children[0];
        assert_eq!(a.get_attribute("href"), Some("https://example.com"));
        assert_eq!(a.get_attribute("class"), Some("link"));
    }

    #[test]
    fn test_parse_nested() {
        let html = "<div><p>Text</p></div>";
        let doc = HtmlParser::parse(html);
        
        let div = &doc.children[0];
        assert_eq!(div.tag_name(), Some("div"));
        
        let p = &div.children[0];
        assert_eq!(p.tag_name(), Some("p"));
        assert_eq!(p.inner_text(), "Text");
    }

    #[test]
    fn test_parse_void_elements() {
        let html = "<br><img src='test.png'>";
        let doc = HtmlParser::parse(html);
        
        assert_eq!(doc.children.len(), 2);
        assert_eq!(doc.children[0].tag_name(), Some("br"));
        assert_eq!(doc.children[1].tag_name(), Some("img"));
    }

    #[test]
    fn test_decode_entities() {
        let html = "<p>&lt;hello&gt; &amp; &quot;world&quot;</p>";
        let doc = HtmlParser::parse(html);
        
        let p = &doc.children[0];
        assert_eq!(p.inner_text(), "<hello> & \"world\"");
    }
}
