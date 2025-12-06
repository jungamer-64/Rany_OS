// ============================================================================
// src/application/browser/script/parser/mod.rs - Parser Module
// ============================================================================
//!
//! # パーサー
//!
//! RustScriptのトークン列からASTを構築するパーサー。
//! Pratt parsingによる演算子優先順位の処理を実装。
//!
//! ## モジュール構成
//! - `statements`: 文のパース
//! - `expressions`: 式のパース（Pratt Parsing）
//! - `helpers`: ヘルパーメソッド

extern crate alloc;

use alloc::vec::Vec;

use super::lexer::Token;
use super::ast::Ast;
use super::ScriptError;

mod statements;
mod expressions;
mod helpers;

// ============================================================================
// Parser
// ============================================================================

/// パーサー
pub struct Parser {
    /// トークン列
    tokens: Vec<Token>,
    /// 現在位置
    current: usize,
}

impl Parser {
    /// 新しいパーサーを作成
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, current: 0 }
    }

    /// パース
    pub fn parse(&mut self) -> Result<Ast, ScriptError> {
        use super::lexer::TokenKind;
        
        let mut statements = Vec::new();

        while !self.is_at_end() {
            // 空行をスキップ
            while self.check(TokenKind::Newline) || self.check(TokenKind::Semicolon) {
                self.advance();
            }

            if self.is_at_end() {
                break;
            }

            match self.parse_statement() {
                Ok(stmt) => statements.push(stmt),
                Err(e) => return Err(e),
            }
        }

        Ok(Ast { statements })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::lexer::Lexer;

    fn parse(source: &str) -> Result<Ast, ScriptError> {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    #[test]
    fn test_let_statement() {
        let ast = parse("let x = 42;").unwrap();
        assert_eq!(ast.statements.len(), 1);
    }

    #[test]
    fn test_function() {
        let ast = parse("fn add(a: i32, b: i32) -> i32 { a + b }").unwrap();
        assert_eq!(ast.statements.len(), 1);
    }

    #[test]
    fn test_if_expression() {
        let ast = parse("if x > 0 { 1 } else { -1 }").unwrap();
        assert_eq!(ast.statements.len(), 1);
    }
}
