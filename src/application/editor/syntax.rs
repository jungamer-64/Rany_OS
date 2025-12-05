// ============================================================================
// src/application/editor/syntax.rs - Syntax Highlighting for Rust
// ============================================================================
//!
//! # Syntax Highlighter - Rust用シンタックスハイライト

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::graphics::Color;
use super::constants::*;

/// トークンの種類
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenType {
    /// 通常のテキスト
    Normal,
    /// キーワード
    Keyword,
    /// 型
    Type,
    /// 文字列リテラル
    String,
    /// コメント
    Comment,
    /// 数値
    Number,
    /// マクロ
    Macro,
}

/// ハイライトされたトークン
#[derive(Clone, Debug)]
pub struct Token {
    /// テキスト
    pub text: String,
    /// トークンの種類
    pub token_type: TokenType,
}

/// Rustキーワード
pub const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "yield",
];

/// Rust組み込み型
pub const RUST_TYPES: &[&str] = &[
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize",
    "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
    "String", "Vec", "Option", "Result", "Box", "Rc", "Arc", "Cell",
    "RefCell", "Mutex", "RwLock", "HashMap", "HashSet", "BTreeMap",
];

/// シンタックスハイライター
pub struct SyntaxHighlighter {
    /// 現在の状態（複数行コメント/文字列用）
    in_block_comment: bool,
    in_string: bool,
}

impl SyntaxHighlighter {
    /// 新しいハイライターを作成
    pub fn new() -> Self {
        Self {
            in_block_comment: false,
            in_string: false,
        }
    }

    /// 状態をリセット
    pub fn reset(&mut self) {
        self.in_block_comment = false;
        self.in_string = false;
    }

    /// 行をハイライト
    pub fn highlight_line(&mut self, line: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            // ブロックコメント中
            if self.in_block_comment {
                let start = i;
                while i < len {
                    if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                        i += 2;
                        self.in_block_comment = false;
                        break;
                    }
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Comment,
                });
                continue;
            }

            // 文字列中
            if self.in_string {
                let start = i;
                while i < len {
                    if chars[i] == '"' && (i == 0 || chars[i - 1] != '\\') {
                        i += 1;
                        self.in_string = false;
                        break;
                    }
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::String,
                });
                continue;
            }

            // 行コメント
            if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
                tokens.push(Token {
                    text: chars[i..].iter().collect(),
                    token_type: TokenType::Comment,
                });
                break;
            }

            // ブロックコメント開始
            if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
                self.in_block_comment = true;
                i += 2;
                let start = i - 2;
                while i < len {
                    if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                        i += 2;
                        self.in_block_comment = false;
                        break;
                    }
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Comment,
                });
                continue;
            }

            // 文字列
            if chars[i] == '"' {
                let start = i;
                i += 1;
                while i < len {
                    if chars[i] == '"' && chars[i - 1] != '\\' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if i >= len && chars.last() != Some(&'"') {
                    self.in_string = true;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::String,
                });
                continue;
            }

            // 文字リテラル
            if chars[i] == '\'' && i + 2 < len {
                let start = i;
                i += 1;
                if chars[i] == '\\' {
                    i += 2;
                } else {
                    i += 1;
                }
                if i < len && chars[i] == '\'' {
                    i += 1;
                    tokens.push(Token {
                        text: chars[start..i].iter().collect(),
                        token_type: TokenType::String,
                    });
                    continue;
                }
                // ライフタイム
                i = start + 1;
            }

            // 数値
            if chars[i].is_ascii_digit() || (chars[i] == '-' && i + 1 < len && chars[i + 1].is_ascii_digit()) {
                let start = i;
                if chars[i] == '-' {
                    i += 1;
                }
                // 16進数
                if i + 1 < len && chars[i] == '0' && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
                    i += 2;
                    while i < len && (chars[i].is_ascii_hexdigit() || chars[i] == '_') {
                        i += 1;
                    }
                }
                // 2進数
                else if i + 1 < len && chars[i] == '0' && (chars[i + 1] == 'b' || chars[i + 1] == 'B') {
                    i += 2;
                    while i < len && (chars[i] == '0' || chars[i] == '1' || chars[i] == '_') {
                        i += 1;
                    }
                }
                // 10進数・浮動小数点
                else {
                    while i < len && (chars[i].is_ascii_digit() || chars[i] == '_' || chars[i] == '.') {
                        i += 1;
                    }
                    // 指数部
                    if i < len && (chars[i] == 'e' || chars[i] == 'E') {
                        i += 1;
                        if i < len && (chars[i] == '+' || chars[i] == '-') {
                            i += 1;
                        }
                        while i < len && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                }
                // 型サフィックス
                let suffixes = ["u8", "u16", "u32", "u64", "u128", "usize", 
                               "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64"];
                for suffix in &suffixes {
                    let suffix_chars: Vec<char> = suffix.chars().collect();
                    if i + suffix_chars.len() <= len {
                        let slice: String = chars[i..i + suffix_chars.len()].iter().collect();
                        if slice == *suffix {
                            i += suffix_chars.len();
                            break;
                        }
                    }
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Number,
                });
                continue;
            }

            // 識別子・キーワード
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                
                // マクロ
                if i < len && chars[i] == '!' {
                    i += 1;
                    tokens.push(Token {
                        text: chars[start..i].iter().collect(),
                        token_type: TokenType::Macro,
                    });
                    continue;
                }
                
                // キーワード
                if RUST_KEYWORDS.contains(&word.as_str()) {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Keyword,
                    });
                    continue;
                }
                
                // 型
                if RUST_TYPES.contains(&word.as_str()) || word.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Type,
                    });
                    continue;
                }
                
                // 通常の識別子
                tokens.push(Token {
                    text: word,
                    token_type: TokenType::Normal,
                });
                continue;
            }

            // その他の文字
            let mut char_str = String::new();
            char_str.push(chars[i]);
            tokens.push(Token {
                text: char_str,
                token_type: TokenType::Normal,
            });
            i += 1;
        }

        tokens
    }

    /// トークンタイプに対応する色を取得
    pub fn color_for_token(token_type: TokenType) -> Color {
        match token_type {
            TokenType::Normal => TEXT_COLOR,
            TokenType::Keyword => KEYWORD_COLOR,
            TokenType::Type => TYPE_COLOR,
            TokenType::String => STRING_COLOR,
            TokenType::Comment => COMMENT_COLOR,
            TokenType::Number => NUMBER_COLOR,
            TokenType::Macro => MACRO_COLOR,
        }
    }
}

impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highlight_keyword() {
        let mut hl = SyntaxHighlighter::new();
        let tokens = hl.highlight_line("let x = 5;");
        assert!(tokens.len() > 0);
        assert_eq!(tokens[0].token_type, TokenType::Keyword);
    }

    #[test]
    fn test_highlight_comment() {
        let mut hl = SyntaxHighlighter::new();
        let tokens = hl.highlight_line("// comment");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Comment);
    }
}
