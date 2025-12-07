// ============================================================================
// src/application/browser/script/lexer.rs - RustScript Lexer
// ============================================================================
//!
//! # 字句解析器
//!
//! Rust風構文のトークン化を行う。

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

use super::{ScriptError, ErrorKind};

// ============================================================================
// Token Types
// ============================================================================

/// トークンの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    // リテラル
    Integer,
    Float,
    StringLit,
    True,
    False,
    Nil,

    // 識別子とキーワード
    Identifier,
    Let,
    Mut,
    Fn,
    If,
    Else,
    While,
    For,
    In,
    Return,
    Break,
    Continue,
    Loop,
    Match,
    Struct,
    Impl,
    SelfLower,      // self
    Pub,
    Move,           // move (クロージャ)
    Underscore,     // _

    // 演算子
    Plus,           // +
    Minus,          // -
    Star,           // *
    Slash,          // /
    Percent,        // %
    Eq,             // =
    EqEq,           // ==
    Ne,             // !=
    Lt,             // <
    Le,             // <=
    Gt,             // >
    Ge,             // >=
    And,            // &&
    Or,             // ||
    Bang,           // !
    Ampersand,      // &
    Pipe,           // |
    Caret,          // ^
    Tilde,          // ~
    Shl,            // <<
    Shr,            // >>
    PlusEq,         // +=
    MinusEq,        // -=
    StarEq,         // *=
    SlashEq,        // /=
    PercentEq,      // %=

    // 区切り記号
    LeftParen,      // (
    RightParen,     // )
    LeftBrace,      // {
    RightBrace,     // }
    LeftBracket,    // [
    RightBracket,   // ]
    Comma,          // ,
    Dot,            // .
    DotDot,         // ..
    DotDotEq,       // ..=
    Colon,          // :
    DoubleColon,    // ::
    Semicolon,      // ;
    Arrow,          // ->
    FatArrow,       // =>
    Question,       // ?

    // 特殊
    Eof,
    Newline,
    Comment,
}

/// トークン
#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub lexeme: String,
    pub line: usize,
    pub column: usize,
}

impl Token {
    pub fn new(kind: TokenKind, lexeme: &str, line: usize, column: usize) -> Self {
        Self {
            kind,
            lexeme: String::from(lexeme),
            line,
            column,
        }
    }

    pub fn eof(line: usize, column: usize) -> Self {
        Self::new(TokenKind::Eof, "", line, column)
    }
}

// ============================================================================
// Lexer
// ============================================================================

/// 字句解析器
pub struct Lexer<'a> {
    source: &'a str,
    chars: Vec<char>,
    pos: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    /// 新しいLexerを作成
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            chars: source.chars().collect(),
            pos: 0,
            line: 1,
            column: 1,
        }
    }

    /// ソースコードをトークン化
    pub fn tokenize(&mut self) -> Result<Vec<Token>, ScriptError> {
        let mut tokens = Vec::new();

        while !self.is_at_end() {
            self.skip_whitespace();
            
            if self.is_at_end() {
                break;
            }

            let token = self.scan_token()?;
            if token.kind != TokenKind::Comment && token.kind != TokenKind::Newline {
                tokens.push(token);
            }
        }

        tokens.push(Token::eof(self.line, self.column));
        Ok(tokens)
    }

    /// 次のトークンをスキャン
    fn scan_token(&mut self) -> Result<Token, ScriptError> {
        let start_line = self.line;
        let start_col = self.column;
        let c = self.advance();

        match c {
            // 単一文字トークン
            '(' => Ok(Token::new(TokenKind::LeftParen, "(", start_line, start_col)),
            ')' => Ok(Token::new(TokenKind::RightParen, ")", start_line, start_col)),
            '{' => Ok(Token::new(TokenKind::LeftBrace, "{", start_line, start_col)),
            '}' => Ok(Token::new(TokenKind::RightBrace, "}", start_line, start_col)),
            '[' => Ok(Token::new(TokenKind::LeftBracket, "[", start_line, start_col)),
            ']' => Ok(Token::new(TokenKind::RightBracket, "]", start_line, start_col)),
            ',' => Ok(Token::new(TokenKind::Comma, ",", start_line, start_col)),
            ';' => Ok(Token::new(TokenKind::Semicolon, ";", start_line, start_col)),
            '?' => Ok(Token::new(TokenKind::Question, "?", start_line, start_col)),
            '%' => Ok(Token::new(TokenKind::Percent, "%", start_line, start_col)),
            '^' => Ok(Token::new(TokenKind::Caret, "^", start_line, start_col)),

            // 1-2文字トークン
            '+' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::PlusEq, "+=", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Plus, "+", start_line, start_col))
                }
            }
            '-' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::MinusEq, "-=", start_line, start_col))
                } else if self.match_char('>') {
                    Ok(Token::new(TokenKind::Arrow, "->", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Minus, "-", start_line, start_col))
                }
            }
            '*' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::StarEq, "*=", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Star, "*", start_line, start_col))
                }
            }
            '/' => {
                if self.match_char('/') {
                    // 行コメント
                    while !self.is_at_end() && self.peek() != '\n' {
                        self.advance();
                    }
                    Ok(Token::new(TokenKind::Comment, "", start_line, start_col))
                } else if self.match_char('*') {
                    // ブロックコメント
                    while !self.is_at_end() {
                        if self.peek() == '*' && self.peek_next() == '/' {
                            self.advance();
                            self.advance();
                            break;
                        }
                        if self.peek() == '\n' {
                            self.line += 1;
                            self.column = 0;
                        }
                        self.advance();
                    }
                    Ok(Token::new(TokenKind::Comment, "", start_line, start_col))
                } else if self.match_char('=') {
                    Ok(Token::new(TokenKind::SlashEq, "/=", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Slash, "/", start_line, start_col))
                }
            }
            '=' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::EqEq, "==", start_line, start_col))
                } else if self.match_char('>') {
                    Ok(Token::new(TokenKind::FatArrow, "=>", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Eq, "=", start_line, start_col))
                }
            }
            '!' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::Ne, "!=", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Bang, "!", start_line, start_col))
                }
            }
            '<' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::Le, "<=", start_line, start_col))
                } else if self.match_char('<') {
                    Ok(Token::new(TokenKind::Shl, "<<", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Lt, "<", start_line, start_col))
                }
            }
            '>' => {
                if self.match_char('=') {
                    Ok(Token::new(TokenKind::Ge, ">=", start_line, start_col))
                } else if self.match_char('>') {
                    Ok(Token::new(TokenKind::Shr, ">>", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Gt, ">", start_line, start_col))
                }
            }
            '&' => {
                if self.match_char('&') {
                    Ok(Token::new(TokenKind::And, "&&", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Ampersand, "&", start_line, start_col))
                }
            }
            '|' => {
                if self.match_char('|') {
                    Ok(Token::new(TokenKind::Or, "||", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Pipe, "|", start_line, start_col))
                }
            }
            ':' => {
                if self.match_char(':') {
                    Ok(Token::new(TokenKind::DoubleColon, "::", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Colon, ":", start_line, start_col))
                }
            }
            '.' => {
                if self.match_char('.') {
                    Ok(Token::new(TokenKind::DotDot, "..", start_line, start_col))
                } else {
                    Ok(Token::new(TokenKind::Dot, ".", start_line, start_col))
                }
            }

            // 改行
            '\n' => {
                self.line += 1;
                self.column = 1;
                Ok(Token::new(TokenKind::Newline, "\n", start_line, start_col))
            }

            // 文字列リテラル
            '"' => self.scan_string(start_line, start_col),

            // 数値リテラル
            '0'..='9' => self.scan_number(c, start_line, start_col),

            // 識別子またはキーワード
            'a'..='z' | 'A'..='Z' | '_' => self.scan_identifier(c, start_line, start_col),

            _ => Err(ScriptError::syntax(
                &alloc::format!("Unexpected character: '{}'", c),
                start_line,
                start_col,
            )),
        }
    }

    /// 文字列リテラルをスキャン
    fn scan_string(&mut self, start_line: usize, start_col: usize) -> Result<Token, ScriptError> {
        let mut value = String::new();

        while !self.is_at_end() && self.peek() != '"' {
            let c = self.advance();
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else if c == '\\' && !self.is_at_end() {
                // エスケープシーケンス
                let escaped = self.advance();
                match escaped {
                    'n' => value.push('\n'),
                    't' => value.push('\t'),
                    'r' => value.push('\r'),
                    '\\' => value.push('\\'),
                    '"' => value.push('"'),
                    '0' => value.push('\0'),
                    _ => value.push(escaped),
                }
            } else {
                value.push(c);
            }
        }

        if self.is_at_end() {
            return Err(ScriptError::syntax("Unterminated string", start_line, start_col));
        }

        self.advance(); // closing "
        Ok(Token::new(TokenKind::StringLit, &value, start_line, start_col))
    }

    /// 数値リテラルをスキャン
    fn scan_number(&mut self, first: char, start_line: usize, start_col: usize) -> Result<Token, ScriptError> {
        let mut value = String::new();
        value.push(first);
        let mut is_float = false;

        // 16進数、8進数、2進数
        if first == '0' && !self.is_at_end() {
            match self.peek() {
                'x' | 'X' => {
                    value.push(self.advance());
                    while !self.is_at_end() && (self.peek().is_ascii_hexdigit() || self.peek() == '_') {
                        let c = self.advance();
                        if c != '_' {
                            value.push(c);
                        }
                    }
                    return Ok(Token::new(TokenKind::Integer, &value, start_line, start_col));
                }
                'o' | 'O' => {
                    value.push(self.advance());
                    while !self.is_at_end() && (self.peek() >= '0' && self.peek() <= '7' || self.peek() == '_') {
                        let c = self.advance();
                        if c != '_' {
                            value.push(c);
                        }
                    }
                    return Ok(Token::new(TokenKind::Integer, &value, start_line, start_col));
                }
                'b' | 'B' => {
                    value.push(self.advance());
                    while !self.is_at_end() && (self.peek() == '0' || self.peek() == '1' || self.peek() == '_') {
                        let c = self.advance();
                        if c != '_' {
                            value.push(c);
                        }
                    }
                    return Ok(Token::new(TokenKind::Integer, &value, start_line, start_col));
                }
                _ => {}
            }
        }

        // 整数部分
        while !self.is_at_end() && (self.peek().is_ascii_digit() || self.peek() == '_') {
            let c = self.advance();
            if c != '_' {
                value.push(c);
            }
        }

        // 小数部分
        if !self.is_at_end() && self.peek() == '.' && self.peek_next().is_ascii_digit() {
            is_float = true;
            value.push(self.advance()); // '.'
            while !self.is_at_end() && (self.peek().is_ascii_digit() || self.peek() == '_') {
                let c = self.advance();
                if c != '_' {
                    value.push(c);
                }
            }
        }

        // 指数部分
        if !self.is_at_end() && (self.peek() == 'e' || self.peek() == 'E') {
            is_float = true;
            value.push(self.advance());
            if !self.is_at_end() && (self.peek() == '+' || self.peek() == '-') {
                value.push(self.advance());
            }
            while !self.is_at_end() && self.peek().is_ascii_digit() {
                value.push(self.advance());
            }
        }

        let kind = if is_float { TokenKind::Float } else { TokenKind::Integer };
        Ok(Token::new(kind, &value, start_line, start_col))
    }

    /// 識別子またはキーワードをスキャン
    fn scan_identifier(&mut self, first: char, start_line: usize, start_col: usize) -> Result<Token, ScriptError> {
        let mut value = String::new();
        value.push(first);

        while !self.is_at_end() && (self.peek().is_ascii_alphanumeric() || self.peek() == '_') {
            value.push(self.advance());
        }

        let kind = match value.as_str() {
            "let" => TokenKind::Let,
            "mut" => TokenKind::Mut,
            "fn" => TokenKind::Fn,
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "while" => TokenKind::While,
            "for" => TokenKind::For,
            "in" => TokenKind::In,
            "return" => TokenKind::Return,
            "break" => TokenKind::Break,
            "continue" => TokenKind::Continue,
            "loop" => TokenKind::Loop,
            "match" => TokenKind::Match,
            "struct" => TokenKind::Struct,
            "impl" => TokenKind::Impl,
            "self" => TokenKind::SelfLower,
            "pub" => TokenKind::Pub,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "nil" => TokenKind::Nil,
            _ => TokenKind::Identifier,
        };

        Ok(Token::new(kind, &value, start_line, start_col))
    }

    // ヘルパーメソッド

    fn is_at_end(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> char {
        if self.is_at_end() {
            '\0'
        } else {
            self.chars[self.pos]
        }
    }

    fn peek_next(&self) -> char {
        if self.pos + 1 >= self.chars.len() {
            '\0'
        } else {
            self.chars[self.pos + 1]
        }
    }

    fn advance(&mut self) -> char {
        let c = self.chars[self.pos];
        self.pos += 1;
        self.column += 1;
        c
    }

    fn match_char(&mut self, expected: char) -> bool {
        if self.is_at_end() || self.peek() != expected {
            false
        } else {
            self.advance();
            true
        }
    }

    fn skip_whitespace(&mut self) {
        while !self.is_at_end() {
            match self.peek() {
                ' ' | '\t' | '\r' => {
                    self.advance();
                }
                _ => break,
            }
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
    fn test_simple_tokens() {
        let mut lexer = Lexer::new("let x = 42;");
        let tokens = lexer.tokenize().unwrap();
        
        assert_eq!(tokens[0].kind, TokenKind::Let);
        assert_eq!(tokens[1].kind, TokenKind::Identifier);
        assert_eq!(tokens[2].kind, TokenKind::Eq);
        assert_eq!(tokens[3].kind, TokenKind::Integer);
        assert_eq!(tokens[4].kind, TokenKind::Semicolon);
    }

    #[test]
    fn test_string_literal() {
        let mut lexer = Lexer::new(r#""hello world""#);
        let tokens = lexer.tokenize().unwrap();
        
        assert_eq!(tokens[0].kind, TokenKind::StringLit);
        assert_eq!(tokens[0].lexeme, "hello world");
    }
}
