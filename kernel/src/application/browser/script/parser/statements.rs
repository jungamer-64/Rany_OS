// ============================================================================
// src/application/browser/script/parser/statements.rs - Statement Parsing
// ============================================================================
//!
//! 文（Statement）のパース処理

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::application::browser::script::lexer::TokenKind;
use crate::application::browser::script::ast::*;
use crate::application::browser::script::{ScriptError};

use super::Parser;

// ============================================================================
// Statement Parsing Methods
// ============================================================================

impl Parser {
    /// 文をパース
    pub(crate) fn parse_statement(&mut self) -> Result<Stmt, ScriptError> {
        // 空文をスキップ
        while self.check(TokenKind::Newline) || self.check(TokenKind::Semicolon) {
            self.advance();
        }

        if self.is_at_end() {
            return Ok(Stmt::Empty);
        }

        // キーワードによる分岐
        if self.check(TokenKind::Let) {
            return self.parse_let_statement();
        }
        if self.check(TokenKind::Fn) {
            return self.parse_function_statement();
        }
        if self.check(TokenKind::If) {
            return self.parse_if_statement();
        }
        if self.check(TokenKind::While) {
            return self.parse_while_statement();
        }
        if self.check(TokenKind::For) {
            return self.parse_for_statement();
        }
        if self.check(TokenKind::Loop) {
            return self.parse_loop_statement();
        }
        if self.check(TokenKind::Return) {
            return self.parse_return_statement();
        }
        if self.check(TokenKind::Break) {
            self.advance();
            return Ok(Stmt::Break);
        }
        if self.check(TokenKind::Continue) {
            self.advance();
            return Ok(Stmt::Continue);
        }
        if self.check(TokenKind::Struct) {
            return self.parse_struct_statement();
        }
        if self.check(TokenKind::Impl) {
            return self.parse_impl_statement();
        }
        if self.check(TokenKind::Match) {
            let expr = self.parse_match_expression()?;
            return Ok(Stmt::Expression(expr));
        }
        if self.check(TokenKind::LeftBrace) {
            return self.parse_block_statement();
        }

        // 代入または式文
        self.parse_expression_or_assignment_statement()
    }

    /// let文
    pub(crate) fn parse_let_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Let)?;

        let mutable = self.check(TokenKind::Mut);
        if mutable {
            self.advance();
        }

        let pattern = self.parse_pattern()?;

        // 型注釈
        let type_annotation = if self.check(TokenKind::Colon) {
            self.advance();
            Some(self.parse_type_annotation()?)
        } else {
            None
        };

        // 初期化子
        let initializer = if self.check(TokenKind::Eq) {
            self.advance();
            Some(self.parse_expression()?)
        } else {
            None
        };

        self.consume_statement_terminator()?;

        // pattern を String に変換（単純な識別子の場合）
        let name = match pattern {
            Pattern::Identifier(s) => s,
            _ => return Err(ScriptError::syntax("let文では単純な識別子のみサポートされています", 0, 0)),
        };

        Ok(Stmt::Let {
            name,
            mutable,
            type_ann: type_annotation,
            value: initializer,
        })
    }

    /// 関数定義
    pub(crate) fn parse_function_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Fn)?;

        let name = self.expect_identifier()?;

        self.expect(TokenKind::LeftParen)?;
        let params = self.parse_function_params()?;
        self.expect(TokenKind::RightParen)?;

        // 戻り値の型
        let return_type = if self.check(TokenKind::Arrow) {
            self.advance();
            Some(self.parse_type_annotation()?)
        } else {
            None
        };

        // 関数本体
        let body = self.parse_block()?;

        Ok(Stmt::Function {
            name,
            params,
            return_type,
            body: Box::new(body),
        })
    }

    /// if文
    pub(crate) fn parse_if_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::If)?;

        let condition = self.parse_expression()?;
        let then_block = self.parse_block()?;

        let else_block = if self.check(TokenKind::Else) {
            self.advance();
            if self.check(TokenKind::If) {
                // else if
                Some(Box::new(self.parse_if_statement()?))
            } else {
                Some(Box::new(self.parse_block_statement()?))
            }
        } else {
            None
        };

        Ok(Stmt::If {
            condition,
            then_branch: Box::new(then_block),
            else_branch: else_block,
        })
    }

    /// while文
    pub(crate) fn parse_while_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::While)?;

        let condition = self.parse_expression()?;
        let body = self.parse_block()?;

        Ok(Stmt::While {
            condition,
            body: Box::new(body),
        })
    }

    /// for文
    pub(crate) fn parse_for_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::For)?;

        let pattern = self.parse_pattern()?;

        self.expect(TokenKind::In)?;

        let iterable = self.parse_expression()?;
        let body = self.parse_block()?;

        // pattern を String に変換
        let variable = match pattern {
            Pattern::Identifier(s) => s,
            _ => return Err(ScriptError::syntax("for文では単純な識別子のみサポートされています", 0, 0)),
        };

        Ok(Stmt::For {
            variable,
            iterator: iterable,
            body: Box::new(body),
        })
    }

    /// loop文
    pub(crate) fn parse_loop_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Loop)?;

        let body = self.parse_block()?;

        Ok(Stmt::Loop(Box::new(body)))
    }

    /// return文
    pub(crate) fn parse_return_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Return)?;

        let value = if self.is_at_end() || self.check(TokenKind::Semicolon) || self.check(TokenKind::Newline) || self.check(TokenKind::RightBrace) {
            None
        } else {
            Some(self.parse_expression()?)
        };

        self.consume_statement_terminator()?;

        Ok(Stmt::Return(value))
    }

    /// struct定義
    pub(crate) fn parse_struct_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Struct)?;

        let name = self.expect_identifier()?;

        self.expect(TokenKind::LeftBrace)?;

        let mut fields = Vec::new();
        while !self.check(TokenKind::RightBrace) && !self.is_at_end() {
            // コンマや改行をスキップ
            while self.check(TokenKind::Comma) || self.check(TokenKind::Newline) {
                self.advance();
            }

            if self.check(TokenKind::RightBrace) {
                break;
            }

            let field_name = self.expect_identifier()?;
            self.expect(TokenKind::Colon)?;
            let field_type = self.parse_type_annotation()?;

            fields.push(StructField {
                name: field_name,
                type_ann: field_type,
                public: false,
            });

            // コンマは省略可能
            if self.check(TokenKind::Comma) {
                self.advance();
            }
        }

        self.expect(TokenKind::RightBrace)?;

        Ok(Stmt::Struct { name, fields })
    }

    /// impl定義
    pub(crate) fn parse_impl_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Impl)?;

        let type_name = self.expect_identifier()?;

        self.expect(TokenKind::LeftBrace)?;

        let mut methods = Vec::new();
        while !self.check(TokenKind::RightBrace) && !self.is_at_end() {
            // 改行をスキップ
            while self.check(TokenKind::Newline) {
                self.advance();
            }

            if self.check(TokenKind::RightBrace) {
                break;
            }

            let method = self.parse_function_statement()?;
            methods.push(method);
        }

        self.expect(TokenKind::RightBrace)?;

        Ok(Stmt::Impl { type_name, methods })
    }

    /// ブロック文
    pub(crate) fn parse_block_statement(&mut self) -> Result<Stmt, ScriptError> {
        let block = self.parse_block()?;
        Ok(block)
    }

    /// ブロック
    pub(crate) fn parse_block(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::LeftBrace)?;

        let mut statements = Vec::new();
        while !self.check(TokenKind::RightBrace) && !self.is_at_end() {
            // 改行やセミコロンをスキップ
            while self.check(TokenKind::Newline) || self.check(TokenKind::Semicolon) {
                self.advance();
            }

            if self.check(TokenKind::RightBrace) {
                break;
            }

            statements.push(self.parse_statement()?);
        }

        self.expect(TokenKind::RightBrace)?;

        Ok(Stmt::Block(statements))
    }

    /// 式文または代入文
    pub(crate) fn parse_expression_or_assignment_statement(&mut self) -> Result<Stmt, ScriptError> {
        let expr = self.parse_expression()?;

        // 代入演算子をチェック
        if self.check(TokenKind::Eq) {
            self.advance();
            let value = self.parse_expression()?;
            self.consume_statement_terminator()?;
            return Ok(Stmt::Assign {
                target: expr,
                value,
            });
        }

        // 複合代入演算子
        let op = if self.check(TokenKind::PlusEq) {
            Some(BinaryOp::Add)
        } else if self.check(TokenKind::MinusEq) {
            Some(BinaryOp::Sub)
        } else if self.check(TokenKind::StarEq) {
            Some(BinaryOp::Mul)
        } else if self.check(TokenKind::SlashEq) {
            Some(BinaryOp::Div)
        } else if self.check(TokenKind::PercentEq) {
            Some(BinaryOp::Mod)
        } else {
            None
        };

        if let Some(op) = op {
            self.advance();
            let rhs = self.parse_expression()?;
            let value = Expr::Binary {
                left: Box::new(expr.clone()),
                op,
                right: Box::new(rhs),
            };
            self.consume_statement_terminator()?;
            return Ok(Stmt::Assign {
                target: expr,
                value,
            });
        }

        self.consume_statement_terminator()?;

        Ok(Stmt::Expression(expr))
    }
}
