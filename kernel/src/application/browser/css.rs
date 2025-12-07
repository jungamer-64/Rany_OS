// ============================================================================
// src/application/browser/css.rs - CSS Parser
// ============================================================================
//!
//! # CSSパーサー
//!
//! CSSルールセット（セレクタとプロパティ）のパーサー。

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

// ============================================================================
// CSS Types
// ============================================================================

/// スタイルシート
#[derive(Debug, Clone, Default)]
pub struct Stylesheet {
    /// ルールのリスト
    pub rules: Vec<Rule>,
}

/// CSSルール
#[derive(Debug, Clone)]
pub struct Rule {
    /// セレクタのリスト（カンマ区切り）
    pub selectors: Vec<Selector>,
    /// 宣言のリスト
    pub declarations: Vec<Declaration>,
}

/// セレクタ
#[derive(Debug, Clone, PartialEq)]
pub enum Selector {
    /// シンプルセレクタ
    Simple(SimpleSelector),
    /// 子孫セレクタ (A B)
    Descendant(Box<Selector>, Box<Selector>),
    /// 子セレクタ (A > B)
    Child(Box<Selector>, Box<Selector>),
}

/// シンプルセレクタ
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SimpleSelector {
    /// タグ名 (div, p, etc.)
    pub tag_name: Option<String>,
    /// ID (#main)
    pub id: Option<String>,
    /// クラス (.container, .wide)
    pub classes: Vec<String>,
    /// ユニバーサル (*)
    pub universal: bool,
}

/// CSS宣言
#[derive(Debug, Clone, PartialEq)]
pub struct Declaration {
    /// プロパティ名
    pub name: String,
    /// 値
    pub value: Value,
}

/// CSS値
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// キーワード (block, none, inherit)
    Keyword(String),
    /// 長さ (10px, 2em)
    Length(f32, Unit),
    /// 色 (#fff, rgb(255,0,0))
    Color(Color),
    /// パーセント (50%)
    Percentage(f32),
    /// 数値
    Number(f32),
}

/// 長さの単位
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Unit {
    Px,
    Em,
    Rem,
    Pt,
    Percent,
}

/// 色
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const BLACK: Color = Color::new(0, 0, 0);
    pub const WHITE: Color = Color::new(255, 255, 255);
    pub const RED: Color = Color::new(255, 0, 0);
    pub const GREEN: Color = Color::new(0, 128, 0);
    pub const BLUE: Color = Color::new(0, 0, 255);
    pub const TRANSPARENT: Color = Color::rgba(0, 0, 0, 0);
}

impl Default for Value {
    fn default() -> Self {
        Value::Keyword("initial".into())
    }
}

impl Value {
    /// ピクセル値を取得
    pub fn to_px(&self) -> f32 {
        match self {
            Value::Length(v, Unit::Px) => *v,
            Value::Length(v, Unit::Pt) => v * 1.333,
            Value::Length(v, Unit::Em) => v * 16.0, // デフォルトフォントサイズ
            Value::Length(v, Unit::Rem) => v * 16.0,
            Value::Number(v) => *v,
            _ => 0.0,
        }
    }

    /// 色を取得
    pub fn to_color(&self) -> Option<Color> {
        match self {
            Value::Color(c) => Some(*c),
            _ => None,
        }
    }
}

// ============================================================================
// Specificity
// ============================================================================

/// 詳細度 (ID数, クラス数, タグ数)
pub type Specificity = (usize, usize, usize);

impl Selector {
    /// 詳細度を計算
    pub fn specificity(&self) -> Specificity {
        match self {
            Selector::Simple(simple) => simple.specificity(),
            Selector::Descendant(a, b) | Selector::Child(a, b) => {
                let (a1, a2, a3) = a.specificity();
                let (b1, b2, b3) = b.specificity();
                (a1 + b1, a2 + b2, a3 + b3)
            }
        }
    }
}

impl SimpleSelector {
    pub fn specificity(&self) -> Specificity {
        let id_count = if self.id.is_some() { 1 } else { 0 };
        let class_count = self.classes.len();
        let tag_count = if self.tag_name.is_some() { 1 } else { 0 };
        (id_count, class_count, tag_count)
    }
}

// ============================================================================
// CSS Parser
// ============================================================================

/// CSSパーサー
pub struct CssParser {
    /// 入力文字列
    input: Vec<char>,
    /// 現在位置
    pos: usize,
}

impl CssParser {
    /// 新しいパーサーを作成
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    /// CSSをパース
    pub fn parse(input: &str) -> Stylesheet {
        let mut parser = CssParser::new(input);
        Stylesheet {
            rules: parser.parse_rules(),
        }
    }

    /// 現在の文字を取得
    fn current_char(&self) -> Option<char> {
        self.input.get(self.pos).copied()
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

    /// 空白とコメントをスキップ
    fn skip_whitespace(&mut self) {
        loop {
            // 空白をスキップ
            while let Some(c) = self.current_char() {
                if c.is_whitespace() {
                    self.advance();
                } else {
                    break;
                }
            }

            // コメントをスキップ
            if self.starts_with("/*") {
                self.advance();
                self.advance();
                while !self.eof() && !self.starts_with("*/") {
                    self.advance();
                }
                if !self.eof() {
                    self.advance();
                    self.advance();
                }
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

    /// ルールのリストをパース
    fn parse_rules(&mut self) -> Vec<Rule> {
        let mut rules = Vec::new();

        loop {
            self.skip_whitespace();
            if self.eof() {
                break;
            }

            // @ルール（無視）
            if self.current_char() == Some('@') {
                self.skip_at_rule();
                continue;
            }

            if let Some(rule) = self.parse_rule() {
                rules.push(rule);
            }
        }

        rules
    }

    /// @ルールをスキップ
    fn skip_at_rule(&mut self) {
        while let Some(c) = self.advance() {
            if c == ';' {
                break;
            }
            if c == '{' {
                let mut depth = 1;
                while depth > 0 {
                    match self.advance() {
                        Some('{') => depth += 1,
                        Some('}') => depth -= 1,
                        None => break,
                        _ => {}
                    }
                }
                break;
            }
        }
    }

    /// 単一ルールをパース
    fn parse_rule(&mut self) -> Option<Rule> {
        let selectors = self.parse_selectors();
        if selectors.is_empty() {
            return None;
        }

        self.skip_whitespace();

        if self.current_char() != Some('{') {
            return None;
        }
        self.advance();

        let declarations = self.parse_declarations();

        self.skip_whitespace();
        if self.current_char() == Some('}') {
            self.advance();
        }

        Some(Rule {
            selectors,
            declarations,
        })
    }

    /// セレクタのリストをパース
    fn parse_selectors(&mut self) -> Vec<Selector> {
        let mut selectors = Vec::new();

        loop {
            self.skip_whitespace();

            if self.eof() || self.current_char() == Some('{') {
                break;
            }

            if let Some(selector) = self.parse_selector() {
                selectors.push(selector);
            }

            self.skip_whitespace();

            if self.current_char() == Some(',') {
                self.advance();
            } else {
                break;
            }
        }

        // 詳細度でソート（降順）
        selectors.sort_by(|a, b| b.specificity().cmp(&a.specificity()));
        selectors
    }

    /// 単一セレクタをパース
    fn parse_selector(&mut self) -> Option<Selector> {
        let mut result = self.parse_simple_selector()?;

        loop {
            self.skip_whitespace();

            match self.current_char() {
                Some('>') => {
                    self.advance();
                    self.skip_whitespace();
                    let right = self.parse_simple_selector()?;
                    result = Selector::Child(Box::new(result), Box::new(right));
                }
                Some(c) if c != ',' && c != '{' && !c.is_whitespace() => {
                    let right = self.parse_simple_selector()?;
                    result = Selector::Descendant(Box::new(result), Box::new(right));
                }
                Some(c) if c.is_whitespace() => {
                    // 次の文字を確認
                    self.skip_whitespace();
                    if let Some(c) = self.current_char() {
                        if c != ',' && c != '{' && c != '>' {
                            let right = self.parse_simple_selector()?;
                            result = Selector::Descendant(Box::new(result), Box::new(right));
                            continue;
                        }
                    }
                    break;
                }
                _ => break,
            }
        }

        Some(result)
    }

    /// シンプルセレクタをパース
    fn parse_simple_selector(&mut self) -> Option<Selector> {
        let mut selector = SimpleSelector::default();

        loop {
            match self.current_char() {
                Some('#') => {
                    self.advance();
                    selector.id = Some(self.parse_identifier());
                }
                Some('.') => {
                    self.advance();
                    selector.classes.push(self.parse_identifier());
                }
                Some('*') => {
                    self.advance();
                    selector.universal = true;
                }
                Some(c) if c.is_alphabetic() || c == '-' || c == '_' => {
                    selector.tag_name = Some(self.parse_identifier());
                }
                _ => break,
            }
        }

        if selector.tag_name.is_none()
            && selector.id.is_none()
            && selector.classes.is_empty()
            && !selector.universal
        {
            None
        } else {
            Some(Selector::Simple(selector))
        }
    }

    /// 識別子をパース
    fn parse_identifier(&mut self) -> String {
        let mut name = String::new();

        while let Some(c) = self.current_char() {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                name.push(c);
                self.advance();
            } else {
                break;
            }
        }

        name.to_lowercase()
    }

    /// 宣言のリストをパース
    fn parse_declarations(&mut self) -> Vec<Declaration> {
        let mut declarations = Vec::new();

        loop {
            self.skip_whitespace();

            if self.eof() || self.current_char() == Some('}') {
                break;
            }

            if let Some(decl) = self.parse_declaration() {
                declarations.push(decl);
            }

            self.skip_whitespace();

            if self.current_char() == Some(';') {
                self.advance();
            }
        }

        declarations
    }

    /// 単一宣言をパース
    fn parse_declaration(&mut self) -> Option<Declaration> {
        let name = self.parse_identifier();
        if name.is_empty() {
            return None;
        }

        self.skip_whitespace();

        if self.current_char() != Some(':') {
            return None;
        }
        self.advance();

        self.skip_whitespace();

        let value = self.parse_value();

        Some(Declaration { name, value })
    }

    /// 値をパース
    fn parse_value(&mut self) -> Value {
        self.skip_whitespace();

        match self.current_char() {
            Some('#') => self.parse_color_hex(),
            Some(c) if c.is_numeric() || c == '-' || c == '.' => self.parse_length_or_number(),
            _ => self.parse_keyword_or_color(),
        }
    }

    /// 16進数色をパース
    fn parse_color_hex(&mut self) -> Value {
        self.advance(); // '#'

        let mut hex = String::new();
        while let Some(c) = self.current_char() {
            if c.is_ascii_hexdigit() {
                hex.push(c);
                self.advance();
            } else {
                break;
            }
        }

        let color = match hex.len() {
            3 => {
                // #RGB -> #RRGGBB
                let r = u8::from_str_radix(&hex[0..1], 16).unwrap_or(0) * 17;
                let g = u8::from_str_radix(&hex[1..2], 16).unwrap_or(0) * 17;
                let b = u8::from_str_radix(&hex[2..3], 16).unwrap_or(0) * 17;
                Color::new(r, g, b)
            }
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
                let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
                let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
                Color::new(r, g, b)
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
                let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
                let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
                let a = u8::from_str_radix(&hex[6..8], 16).unwrap_or(255);
                Color::rgba(r, g, b, a)
            }
            _ => Color::BLACK,
        };

        Value::Color(color)
    }

    /// 長さまたは数値をパース
    fn parse_length_or_number(&mut self) -> Value {
        let mut num_str = String::new();

        // 符号
        if self.current_char() == Some('-') {
            num_str.push('-');
            self.advance();
        }

        // 数値部分
        while let Some(c) = self.current_char() {
            if c.is_numeric() || c == '.' {
                num_str.push(c);
                self.advance();
            } else {
                break;
            }
        }

        let num: f32 = num_str.parse().unwrap_or(0.0);

        // 単位
        let mut unit_str = String::new();
        while let Some(c) = self.current_char() {
            if c.is_alphabetic() || c == '%' {
                unit_str.push(c);
                self.advance();
            } else {
                break;
            }
        }

        match unit_str.to_lowercase().as_str() {
            "px" => Value::Length(num, Unit::Px),
            "em" => Value::Length(num, Unit::Em),
            "rem" => Value::Length(num, Unit::Rem),
            "pt" => Value::Length(num, Unit::Pt),
            "%" => Value::Percentage(num),
            "" => Value::Number(num),
            _ => Value::Length(num, Unit::Px),
        }
    }

    /// キーワードまたは色名をパース
    fn parse_keyword_or_color(&mut self) -> Value {
        let keyword = self.parse_identifier();

        // 名前付き色
        let color = match keyword.as_str() {
            "black" => Some(Color::new(0, 0, 0)),
            "white" => Some(Color::new(255, 255, 255)),
            "red" => Some(Color::new(255, 0, 0)),
            "green" => Some(Color::new(0, 128, 0)),
            "blue" => Some(Color::new(0, 0, 255)),
            "yellow" => Some(Color::new(255, 255, 0)),
            "cyan" => Some(Color::new(0, 255, 255)),
            "magenta" => Some(Color::new(255, 0, 255)),
            "gray" | "grey" => Some(Color::new(128, 128, 128)),
            "silver" => Some(Color::new(192, 192, 192)),
            "maroon" => Some(Color::new(128, 0, 0)),
            "olive" => Some(Color::new(128, 128, 0)),
            "navy" => Some(Color::new(0, 0, 128)),
            "purple" => Some(Color::new(128, 0, 128)),
            "teal" => Some(Color::new(0, 128, 128)),
            "orange" => Some(Color::new(255, 165, 0)),
            "transparent" => Some(Color::TRANSPARENT),
            _ => None,
        };

        if let Some(c) = color {
            Value::Color(c)
        } else {
            Value::Keyword(keyword)
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
    fn test_parse_simple_rule() {
        let css = "div { color: red; }";
        let sheet = CssParser::parse(css);
        
        assert_eq!(sheet.rules.len(), 1);
        assert_eq!(sheet.rules[0].declarations.len(), 1);
        assert_eq!(sheet.rules[0].declarations[0].name, "color");
    }

    #[test]
    fn test_parse_selector() {
        let css = "#main .content p { font-size: 16px; }";
        let sheet = CssParser::parse(css);
        
        assert_eq!(sheet.rules.len(), 1);
    }

    #[test]
    fn test_parse_color_hex() {
        let css = "p { color: #ff0000; background: #fff; }";
        let sheet = CssParser::parse(css);
        
        let color = &sheet.rules[0].declarations[0].value;
        assert_eq!(*color, Value::Color(Color::new(255, 0, 0)));
    }

    #[test]
    fn test_specificity() {
        let mut parser = CssParser::new("#id");
        let selector = parser.parse_selector().unwrap();
        assert_eq!(selector.specificity(), (1, 0, 0));

        let mut parser = CssParser::new(".class");
        let selector = parser.parse_selector().unwrap();
        assert_eq!(selector.specificity(), (0, 1, 0));

        let mut parser = CssParser::new("div");
        let selector = parser.parse_selector().unwrap();
        assert_eq!(selector.specificity(), (0, 0, 1));
    }
}
