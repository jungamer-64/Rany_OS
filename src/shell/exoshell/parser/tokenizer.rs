// ============================================================================
// src/shell/exoshell/parser/tokenizer.rs - Tokenizer
// ============================================================================

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// トークンの種類
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// 識別子（fs, entries, filter など）
    Ident(String),
    /// 文字列リテラル
    StringLit(String),
    /// 数値リテラル
    Number(i64),
    /// 浮動小数点リテラル
    Float(f64),
    /// ドット（メソッドチェーン）
    Dot,
    /// 開き括弧
    LParen,
    /// 閉じ括弧
    RParen,
    /// カンマ
    Comma,
    /// 比較演算子
    Operator(String),
    /// パイプ（クロージャ用）
    Pipe,
}

/// 簡易トークナイザー
pub struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        
        while self.pos < self.input.len() {
            self.skip_whitespace();
            
            if self.pos >= self.input.len() {
                break;
            }

            let c = self.peek().unwrap();

            match c {
                '.' => {
                    self.advance();
                    tokens.push(Token::Dot);
                }
                '(' => {
                    self.advance();
                    tokens.push(Token::LParen);
                }
                ')' => {
                    self.advance();
                    tokens.push(Token::RParen);
                }
                ',' => {
                    self.advance();
                    tokens.push(Token::Comma);
                }
                '|' => {
                    self.advance();
                    tokens.push(Token::Pipe);
                }
                '"' | '\'' => {
                    tokens.push(self.read_string(c));
                }
                '>' | '<' | '=' | '!' => {
                    tokens.push(self.read_operator());
                }
                c if c.is_ascii_digit() || c == '-' => {
                    tokens.push(self.read_number());
                }
                c if c.is_alphabetic() || c == '_' || c == '$' => {
                    tokens.push(self.read_ident());
                }
                _ => {
                    // 未知の文字はスキップ
                    self.advance();
                }
            }
        }
        
        tokens
    }

    fn read_string(&mut self, quote: char) -> Token {
        self.advance(); // skip opening quote
        let start = self.pos;
        
        while let Some(c) = self.peek() {
            if c == quote {
                let s = self.input[start..self.pos].to_string();
                self.advance(); // skip closing quote
                return Token::StringLit(s);
            }
            self.advance();
        }
        
        // 閉じクォートがない場合
        Token::StringLit(self.input[start..].to_string())
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos;
        let mut has_dot = false;
        
        // 負号
        if self.peek() == Some('-') {
            self.advance();
        }
        
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance();
            } else if c == '.' && !has_dot {
                has_dot = true;
                self.advance();
            } else {
                break;
            }
        }
        
        let s = &self.input[start..self.pos];
        if has_dot {
            Token::Float(s.parse().unwrap_or(0.0))
        } else {
            Token::Number(s.parse().unwrap_or(0))
        }
    }

    fn read_ident(&mut self) -> Token {
        let start = self.pos;
        
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '$' || c == '/' {
                self.advance();
            } else {
                break;
            }
        }
        
        Token::Ident(self.input[start..self.pos].to_string())
    }

    fn read_operator(&mut self) -> Token {
        let start = self.pos;
        
        while let Some(c) = self.peek() {
            if c == '>' || c == '<' || c == '=' || c == '!' {
                self.advance();
            } else {
                break;
            }
        }
        
        Token::Operator(self.input[start..self.pos].to_string())
    }
}
