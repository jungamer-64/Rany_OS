// ============================================================================
// src/application/browser/style.rs - Style Tree
// ============================================================================
//!
//! # スタイルツリー
//!
//! DOMツリーとCSSをマッチングさせ、各ノードの計算済みスタイルを決定。

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use super::dom::{Node, NodeType, ElementData};
use super::css::{Stylesheet, Rule, Selector, SimpleSelector, Declaration, Value, Color};

// ============================================================================
// Styled Node
// ============================================================================

/// スタイル付きノード
#[derive(Debug)]
pub struct StyledNode<'a> {
    /// 元のDOMノード
    pub node: &'a Node,
    /// 計算済みスタイル
    pub specified_values: PropertyMap,
    /// 子ノード
    pub children: Vec<StyledNode<'a>>,
}

/// プロパティマップ
pub type PropertyMap = BTreeMap<String, Value>;

// ============================================================================
// Display Type
// ============================================================================

/// 表示タイプ
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Display {
    /// ブロック
    Block,
    /// インライン
    Inline,
    /// インラインブロック
    InlineBlock,
    /// なし
    None,
}

impl<'a> StyledNode<'a> {
    /// display プロパティを取得
    pub fn display(&self) -> Display {
        match self.value("display") {
            Some(Value::Keyword(s)) => match s.as_str() {
                "block" => Display::Block,
                "none" => Display::None,
                "inline-block" => Display::InlineBlock,
                _ => Display::Inline,
            },
            _ => self.default_display(),
        }
    }

    /// デフォルトの display 値
    fn default_display(&self) -> Display {
        match &self.node.node_type {
            NodeType::Text(_) => Display::Inline,
            NodeType::Element(data) => {
                match data.tag_name.as_str() {
                    "div" | "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
                    | "header" | "footer" | "main" | "section" | "article"
                    | "nav" | "aside" | "ul" | "ol" | "li" | "table"
                    | "form" | "blockquote" | "pre" | "hr" => Display::Block,
                    "script" | "style" | "head" | "meta" | "link" | "title" => Display::None,
                    _ => Display::Inline,
                }
            }
            _ => Display::Block,
        }
    }

    /// プロパティ値を取得
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.specified_values.get(name)
    }

    /// プロパティ値を取得（デフォルト値付き）
    pub fn lookup(&self, name: &str, fallback: &str, default: &Value) -> Value {
        self.value(name)
            .or_else(|| self.value(fallback))
            .cloned()
            .unwrap_or_else(|| default.clone())
    }

    /// 色を取得
    pub fn color(&self, name: &str) -> Option<Color> {
        self.value(name).and_then(|v| v.to_color())
    }

    /// 長さをピクセルで取得
    pub fn length_px(&self, name: &str) -> f32 {
        self.value(name).map(|v| v.to_px()).unwrap_or(0.0)
    }
}

// ============================================================================
// Style Tree Construction
// ============================================================================

/// スタイルツリーを構築
pub fn style_tree<'a>(root: &'a Node, stylesheet: &'a Stylesheet) -> StyledNode<'a> {
    let default_styles = default_styles();
    style_node(root, stylesheet, &default_styles)
}

/// 単一ノードのスタイルを計算
fn style_node<'a>(
    node: &'a Node,
    stylesheet: &'a Stylesheet,
    parent_styles: &PropertyMap,
) -> StyledNode<'a> {
    // 継承可能なスタイルを親から取得
    let mut specified_values = inherited_properties(parent_styles);

    // CSSルールを適用
    match &node.node_type {
        NodeType::Element(elem) => {
            // ユーザーエージェントスタイル
            apply_ua_styles(&mut specified_values, elem);

            // CSSルールをマッチング
            let matching_rules = matching_rules(elem, stylesheet);
            for (_, rule) in matching_rules {
                for decl in &rule.declarations {
                    specified_values.insert(decl.name.clone(), decl.value.clone());
                }
            }

            // style属性（最優先）
            if let Some(style) = elem.attributes.get("style") {
                let inline = parse_inline_style(style);
                for (name, value) in inline {
                    specified_values.insert(name, value);
                }
            }
        }
        NodeType::Text(_) => {
            // テキストノードは親のスタイルを継承
        }
        _ => {}
    }

    // 子ノードを処理
    let children = node
        .children
        .iter()
        .map(|child| style_node(child, stylesheet, &specified_values))
        .collect();

    StyledNode {
        node,
        specified_values,
        children,
    }
}

/// デフォルトスタイル
fn default_styles() -> PropertyMap {
    let mut map = BTreeMap::new();
    map.insert("color".into(), Value::Color(Color::BLACK));
    map.insert("background-color".into(), Value::Color(Color::TRANSPARENT));
    map.insert("font-size".into(), Value::Length(16.0, super::css::Unit::Px));
    map
}

/// 継承可能なプロパティを抽出
fn inherited_properties(parent: &PropertyMap) -> PropertyMap {
    let inherited = [
        "color",
        "font-family",
        "font-size",
        "font-style",
        "font-weight",
        "line-height",
        "text-align",
        "visibility",
        "cursor",
    ];

    parent
        .iter()
        .filter(|(k, _)| inherited.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// ユーザーエージェントスタイルを適用
fn apply_ua_styles(styles: &mut PropertyMap, elem: &ElementData) {
    use super::css::Unit;

    match elem.tag_name.as_str() {
        "h1" => {
            styles.insert("font-size".into(), Value::Length(32.0, Unit::Px));
            styles.insert("font-weight".into(), Value::Keyword("bold".into()));
            styles.insert("margin-top".into(), Value::Length(21.0, Unit::Px));
            styles.insert("margin-bottom".into(), Value::Length(21.0, Unit::Px));
        }
        "h2" => {
            styles.insert("font-size".into(), Value::Length(24.0, Unit::Px));
            styles.insert("font-weight".into(), Value::Keyword("bold".into()));
            styles.insert("margin-top".into(), Value::Length(19.0, Unit::Px));
            styles.insert("margin-bottom".into(), Value::Length(19.0, Unit::Px));
        }
        "h3" => {
            styles.insert("font-size".into(), Value::Length(18.0, Unit::Px));
            styles.insert("font-weight".into(), Value::Keyword("bold".into()));
            styles.insert("margin-top".into(), Value::Length(18.0, Unit::Px));
            styles.insert("margin-bottom".into(), Value::Length(18.0, Unit::Px));
        }
        "p" => {
            styles.insert("margin-top".into(), Value::Length(16.0, Unit::Px));
            styles.insert("margin-bottom".into(), Value::Length(16.0, Unit::Px));
        }
        "a" => {
            styles.insert("color".into(), Value::Color(Color::new(0, 0, 238)));
            styles.insert("text-decoration".into(), Value::Keyword("underline".into()));
        }
        "strong" | "b" => {
            styles.insert("font-weight".into(), Value::Keyword("bold".into()));
        }
        "em" | "i" => {
            styles.insert("font-style".into(), Value::Keyword("italic".into()));
        }
        "ul" | "ol" => {
            styles.insert("margin-top".into(), Value::Length(16.0, Unit::Px));
            styles.insert("margin-bottom".into(), Value::Length(16.0, Unit::Px));
            styles.insert("padding-left".into(), Value::Length(40.0, Unit::Px));
        }
        "li" => {
            styles.insert("display".into(), Value::Keyword("list-item".into()));
        }
        "pre" | "code" => {
            styles.insert("font-family".into(), Value::Keyword("monospace".into()));
        }
        "hr" => {
            styles.insert("margin-top".into(), Value::Length(8.0, Unit::Px));
            styles.insert("margin-bottom".into(), Value::Length(8.0, Unit::Px));
            styles.insert("border-top".into(), Value::Length(1.0, Unit::Px));
        }
        _ => {}
    }
}

/// マッチするルールを取得
fn matching_rules<'a>(
    elem: &ElementData,
    stylesheet: &'a Stylesheet,
) -> Vec<(super::css::Specificity, &'a Rule)> {
    let mut matches = Vec::new();

    for rule in &stylesheet.rules {
        for selector in &rule.selectors {
            if matches_selector(elem, selector) {
                matches.push((selector.specificity(), rule));
                break; // 最も詳細なセレクタのみ
            }
        }
    }

    // 詳細度でソート
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches
}

/// セレクタがマッチするか
fn matches_selector(elem: &ElementData, selector: &Selector) -> bool {
    match selector {
        Selector::Simple(simple) => matches_simple_selector(elem, simple),
        Selector::Descendant(_, right) => {
            // 簡略化: 子孫セレクタは右側のみチェック
            matches_selector(elem, right)
        }
        Selector::Child(_, right) => {
            matches_selector(elem, right)
        }
    }
}

/// シンプルセレクタがマッチするか
fn matches_simple_selector(elem: &ElementData, selector: &SimpleSelector) -> bool {
    // ユニバーサルセレクタ
    if selector.universal {
        return true;
    }

    // タグ名
    if let Some(ref tag) = selector.tag_name {
        if tag != &elem.tag_name {
            return false;
        }
    }

    // ID
    if let Some(ref id) = selector.id {
        if elem.attributes.get("id") != Some(id) {
            return false;
        }
    }

    // クラス
    let elem_classes: Vec<&str> = elem
        .attributes
        .get("class")
        .map(|c| c.split_whitespace().collect())
        .unwrap_or_default();

    for class in &selector.classes {
        if !elem_classes.contains(&class.as_str()) {
            return false;
        }
    }

    true
}

/// インラインスタイルをパース
fn parse_inline_style(style: &str) -> Vec<(String, Value)> {
    let mut result = Vec::new();

    for declaration in style.split(';') {
        let parts: Vec<&str> = declaration.splitn(2, ':').collect();
        if parts.len() == 2 {
            let name = parts[0].trim().to_lowercase();
            let value_str = parts[1].trim();
            let value = parse_simple_value(value_str);
            result.push((name, value));
        }
    }

    result
}

/// 簡易的な値パーサー
fn parse_simple_value(s: &str) -> Value {
    // 16進数色
    if s.starts_with('#') {
        let hex = &s[1..];
        if hex.len() == 3 {
            let r = u8::from_str_radix(&hex[0..1], 16).unwrap_or(0) * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).unwrap_or(0) * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).unwrap_or(0) * 17;
            return Value::Color(Color::new(r, g, b));
        } else if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
            let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
            let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
            return Value::Color(Color::new(r, g, b));
        }
    }

    // 数値と単位
    if let Some(pos) = s.find(|c: char| !c.is_numeric() && c != '.' && c != '-') {
        if let Ok(num) = s[..pos].parse::<f32>() {
            let unit = &s[pos..].to_lowercase();
            return match unit.as_str() {
                "px" => Value::Length(num, super::css::Unit::Px),
                "em" => Value::Length(num, super::css::Unit::Em),
                "%" => Value::Percentage(num),
                _ => Value::Length(num, super::css::Unit::Px),
            };
        }
    }

    // 数値のみ
    if let Ok(num) = s.parse::<f32>() {
        return Value::Number(num);
    }

    // 名前付き色
    match s.to_lowercase().as_str() {
        "black" => Value::Color(Color::BLACK),
        "white" => Value::Color(Color::WHITE),
        "red" => Value::Color(Color::RED),
        "green" => Value::Color(Color::GREEN),
        "blue" => Value::Color(Color::BLUE),
        _ => Value::Keyword(String::from(s)),
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::html::HtmlParser;
    use super::super::css::CssParser;

    #[test]
    fn test_style_tree() {
        let html = "<div><p>Hello</p></div>";
        let css = "p { color: red; }";

        let dom = HtmlParser::parse(html);
        let stylesheet = CssParser::parse(css);
        let styled = style_tree(&dom, &stylesheet);

        // ルートはDocument
        assert_eq!(styled.children.len(), 1);
    }

    #[test]
    fn test_display() {
        let html = "<div></div>";
        let css = "";

        let dom = HtmlParser::parse(html);
        let stylesheet = CssParser::parse(css);
        let styled = style_tree(&dom, &stylesheet);

        let div = &styled.children[0];
        assert_eq!(div.display(), Display::Block);
    }
}
