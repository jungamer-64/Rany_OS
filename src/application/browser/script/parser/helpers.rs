// ============================================================================
// src/application/browser/script/parser/helpers.rs - Helper Methods
// ============================================================================
//!
//! パーサーのヘルパーメソッド（パターン、型注釈、引数など）

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

use crate::application::browser::script::lexer::{Token, TokenKind};
use crate::application::browser::script::ast::*;
use crate::application::browser::script::{ScriptError, ErrorKind};

use super::Parser;

// ============================================================================
// Helper Methods
// ============================================================================

impl Parser {
    /// パターンをパース
    pub(crate) fn parse_pattern(&mut self) -> Result<Pattern, ScriptError> {
        if self.check(TokenKind::Underscore) {
            self.advance();
            return Ok(Pattern::Wildcard);
        }

        if self.check(TokenKind::Integer) {
            let token = self.advance();
            let value = self.parse_integer(&token.lexeme)?;
            return Ok(Pattern::Literal(Expr::Literal(Literal::Integer(value))));
        }

        if self.check(TokenKind::StringLit) {
            let token = self.advance();
            let value = self.parse_string_literal(&token.lexeme);
            return Ok(Pattern::Literal(Expr::Literal(Literal::String(value))));
        }

        if self.check(TokenKind::True) {
            self.advance();
            return Ok(Pattern::Literal(Expr::Literal(Literal::Bool(true))));
        }

        if self.check(TokenKind::False) {
            self.advance();
            return Ok(Pattern::Literal(Expr::Literal(Literal::Bool(false))));
        }

        if self.check(TokenKind::LeftParen) {
            // タプルパターン
            self.advance();
            let mut patterns = Vec::new();
            if !self.check(TokenKind::RightParen) {
                loop {
                    patterns.push(self.parse_pattern()?);
                    if !self.check(TokenKind::Comma) {
                        break;
                    }
                    self.advance();
                }
            }
            self.expect(TokenKind::RightParen)?;
            return Ok(Pattern::Tuple(patterns));
        }

        // 識別子パターン
        if self.check(TokenKind::Identifier) {
            let token = self.advance();
            return Ok(Pattern::Identifier(token.lexeme.clone()));
        }

        Err(self.error("Expected pattern"))
    }

    /// 型注釈をパース
    pub(crate) fn parse_type_annotation(&mut self) -> Result<TypeAnnotation, ScriptError> {
        // 基本型
        if self.check(TokenKind::Identifier) {
            let token = self.advance();
            let name = token.lexeme.clone();

            // ジェネリック型
            if self.check(TokenKind::Lt) {
                self.advance();
                let mut params = Vec::new();
                loop {
                    params.push(self.parse_type_annotation()?);
                    if !self.check(TokenKind::Comma) {
                        break;
                    }
                    self.advance();
                }
                self.expect(TokenKind::Gt)?;
                return Ok(TypeAnnotation::Generic { name, params });
            }

            return Ok(TypeAnnotation::Simple(name));
        }

        // 配列型
        if self.check(TokenKind::LeftBracket) {
            self.advance();
            let element_type = self.parse_type_annotation()?;
            self.expect(TokenKind::RightBracket)?;
            return Ok(TypeAnnotation::Array {
                element: Box::new(element_type),
                size: None,
            });
        }

        // タプル型
        if self.check(TokenKind::LeftParen) {
            self.advance();
            let mut elements = Vec::new();
            if !self.check(TokenKind::RightParen) {
                loop {
                    elements.push(self.parse_type_annotation()?);
                    if !self.check(TokenKind::Comma) {
                        break;
                    }
                    self.advance();
                }
            }
            self.expect(TokenKind::RightParen)?;
            return Ok(TypeAnnotation::Tuple(elements));
        }

        // 参照型
        if self.check(TokenKind::Ampersand) {
            self.advance();
            let mutable = if self.check(TokenKind::Mut) {
                self.advance();
                true
            } else {
                false
            };
            let inner = self.parse_type_annotation()?;
            return Ok(TypeAnnotation::Reference {
                inner: Box::new(inner),
                mutable,
            });
        }

        // 関数型
        if self.check(TokenKind::Fn) {
            self.advance();
            self.expect(TokenKind::LeftParen)?;
            let mut params = Vec::new();
            if !self.check(TokenKind::RightParen) {
                loop {
                    params.push(self.parse_type_annotation()?);
                    if !self.check(TokenKind::Comma) {
                        break;
                    }
                    self.advance();
                }
            }
            self.expect(TokenKind::RightParen)?;

            let return_type = if self.check(TokenKind::Arrow) {
                self.advance();
                self.parse_type_annotation()?
            } else {
                TypeAnnotation::Simple(String::from("()"))
            };

            return Ok(TypeAnnotation::Function {
                params,
                return_type: Box::new(return_type),
            });
        }

        // Option型のシンタックスシュガー
        if self.check(TokenKind::Question) {
            self.advance();
            let inner = self.parse_type_annotation()?;
            return Ok(TypeAnnotation::Optional(Box::new(inner)));
        }

        Err(self.error("Expected type annotation"))
    }

    /// 関数パラメータをパース
    pub(crate) fn parse_function_params(&mut self) -> Result<Vec<FunctionParam>, ScriptError> {
        let mut params = Vec::new();

        if self.check(TokenKind::RightParen) {
            return Ok(params);
        }

        loop {
            // self参照
            if self.check(TokenKind::SelfLower) {
                self.advance();
                params.push(FunctionParam {
                    name: String::from("self"),
                    type_ann: None,
                    mutable: false,
                });
            } else if self.check(TokenKind::Ampersand) {
                // &self または &mut self
                self.advance();
                let is_mutable = if self.check(TokenKind::Mut) {
                    self.advance();
                    true
                } else {
                    false
                };
                self.expect(TokenKind::SelfLower)?;
                let name = if is_mutable {
                    String::from("&mut self")
                } else {
                    String::from("&self")
                };
                params.push(FunctionParam {
                    name,
                    type_ann: None,
                    mutable: is_mutable,
                });
            } else {
                // 通常のパラメータ
                let param_name = self.expect_identifier()?;
                self.expect(TokenKind::Colon)?;
                let type_annotation = Some(self.parse_type_annotation()?);

                // デフォルト値は無視（type_annに格納しない）
                if self.check(TokenKind::Eq) {
                    self.advance();
                    let _ = self.parse_expression()?;
                }

                params.push(FunctionParam {
                    name: param_name,
                    type_ann: type_annotation,
                    mutable: false,
                });
            }

            if !self.check(TokenKind::Comma) {
                break;
            }
            self.advance();
        }

        Ok(params)
    }

    /// 引数リストをパース
    pub(crate) fn parse_arguments(&mut self) -> Result<Vec<Expr>, ScriptError> {
        let mut args = Vec::new();

        if self.check(TokenKind::RightParen) {
            return Ok(args);
        }

        loop {
            args.push(self.parse_expression()?);
            if !self.check(TokenKind::Comma) {
                break;
            }
            self.advance();
        }

        Ok(args)
    }

    /// 整数をパース
    pub(crate) fn parse_integer(&self, s: &str) -> Result<i64, ScriptError> {
        let s = s.replace('_', "");
        if s.starts_with("0x") || s.starts_with("0X") {
            i64::from_str_radix(&s[2..], 16)
                .map_err(|_| self.error("Invalid hex integer"))
        } else if s.starts_with("0o") || s.starts_with("0O") {
            i64::from_str_radix(&s[2..], 8)
                .map_err(|_| self.error("Invalid octal integer"))
        } else if s.starts_with("0b") || s.starts_with("0B") {
            i64::from_str_radix(&s[2..], 2)
                .map_err(|_| self.error("Invalid binary integer"))
        } else {
            s.parse()
                .map_err(|_| self.error("Invalid integer"))
        }
    }

    /// 浮動小数点をパース
    pub(crate) fn parse_float(&self, s: &str) -> Result<f64, ScriptError> {
        let s = s.replace('_', "");
        s.parse()
            .map_err(|_| self.error("Invalid float"))
    }

    /// 文字列リテラルをパース（エスケープ処理）
    pub(crate) fn parse_string_literal(&self, s: &str) -> String {
        // 最初と最後のクォートを除去
        let s = if s.len() >= 2 {
            &s[1..s.len()-1]
        } else {
            s
        };

        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    chars.next();
                    match next {
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        '\\' => result.push('\\'),
                        '"' => result.push('"'),
                        '\'' => result.push('\''),
                        '0' => result.push('\0'),
                        _ => {
                            result.push('\\');
                            result.push(next);
                        }
                    }
                } else {
                    result.push('\\');
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    // ========================================================================
    // Token Utilities
    // ========================================================================

    /// 現在のトークンが指定した種類かチェック
    pub(crate) fn check(&self, kind: TokenKind) -> bool {
        if self.is_at_end() {
            return false;
        }
        self.peek().kind == kind
    }

    /// 次のトークンに進む
    pub(crate) fn advance(&mut self) -> Token {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }

    /// 現在のトークンを取得
    pub(crate) fn peek(&self) -> &Token {
        &self.tokens[self.current]
    }

    /// 直前のトークンを取得
    pub(crate) fn previous(&self) -> Token {
        self.tokens[self.current - 1].clone()
    }

    /// 終端に到達したかチェック
    pub(crate) fn is_at_end(&self) -> bool {
        self.current >= self.tokens.len() || self.peek().kind == TokenKind::Eof
    }

    /// 指定した種類のトークンを期待して消費
    pub(crate) fn expect(&mut self, kind: TokenKind) -> Result<Token, ScriptError> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            Err(self.error(&format!("Expected {:?}", kind)))
        }
    }

    /// 識別子を期待して消費
    pub(crate) fn expect_identifier(&mut self) -> Result<String, ScriptError> {
        if self.check(TokenKind::Identifier) {
            let token = self.advance();
            Ok(token.lexeme)
        } else {
            Err(self.error("Expected identifier"))
        }
    }

    /// 文終端子を消費
    pub(crate) fn consume_statement_terminator(&mut self) -> Result<(), ScriptError> {
        // セミコロンまたは改行を消費（省略可能）
        while self.check(TokenKind::Semicolon) || self.check(TokenKind::Newline) {
            self.advance();
        }
        Ok(())
    }

    /// エラーを生成
    pub(crate) fn error(&self, message: &str) -> ScriptError {
        let (line, column) = if self.is_at_end() {
            if self.tokens.is_empty() {
                (1, 1)
            } else {
                let last = &self.tokens[self.tokens.len() - 1];
                (last.line, last.column)
            }
        } else {
            let token = self.peek();
            (token.line, token.column)
        };
        ScriptError::new(ErrorKind::Syntax, message, line, column)
    }
}
