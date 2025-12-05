// ============================================================================
// src/application/browser/script/parser.rs - Parser
// ============================================================================
//!
//! # パーサー
//!
//! RustScriptのトークン列からASTを構築するパーサー。
//! Pratt parsingによる演算子優先順位の処理を実装。

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use alloc::vec;

use super::lexer::{Token, TokenKind};
use super::ast::*;
use super::{ScriptError, ErrorKind};

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
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, current: 0 }
    }

    /// パース
    pub fn parse(&mut self) -> Result<Ast, ScriptError> {
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

    // ========================================================================
    // Statement Parsing
    // ========================================================================

    fn parse_statement(&mut self) -> Result<Stmt, ScriptError> {
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
    fn parse_let_statement(&mut self) -> Result<Stmt, ScriptError> {
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

        Ok(Stmt::Let {
            pattern,
            type_annotation,
            initializer,
            mutable,
        })
    }

    /// 関数定義
    fn parse_function_statement(&mut self) -> Result<Stmt, ScriptError> {
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
    fn parse_if_statement(&mut self) -> Result<Stmt, ScriptError> {
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
            then_block: Box::new(then_block),
            else_block,
        })
    }

    /// while文
    fn parse_while_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::While)?;

        let condition = self.parse_expression()?;
        let body = self.parse_block()?;

        Ok(Stmt::While {
            condition,
            body: Box::new(body),
        })
    }

    /// for文
    fn parse_for_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::For)?;

        let pattern = self.parse_pattern()?;

        self.expect(TokenKind::In)?;

        let iterable = self.parse_expression()?;
        let body = self.parse_block()?;

        Ok(Stmt::For {
            pattern,
            iterable,
            body: Box::new(body),
        })
    }

    /// loop文
    fn parse_loop_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Loop)?;

        let body = self.parse_block()?;

        Ok(Stmt::Loop {
            body: Box::new(body),
        })
    }

    /// return文
    fn parse_return_statement(&mut self) -> Result<Stmt, ScriptError> {
        self.expect(TokenKind::Return)?;

        let value = if self.is_at_end() || self.check(TokenKind::Semicolon) || self.check(TokenKind::Newline) || self.check(TokenKind::RightBrace) {
            None
        } else {
            Some(self.parse_expression()?)
        };

        self.consume_statement_terminator()?;

        Ok(Stmt::Return { value })
    }

    /// struct定義
    fn parse_struct_statement(&mut self) -> Result<Stmt, ScriptError> {
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
                type_annotation: field_type,
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
    fn parse_impl_statement(&mut self) -> Result<Stmt, ScriptError> {
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
    fn parse_block_statement(&mut self) -> Result<Stmt, ScriptError> {
        let block = self.parse_block()?;
        Ok(block)
    }

    /// ブロック
    fn parse_block(&mut self) -> Result<Stmt, ScriptError> {
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
    fn parse_expression_or_assignment_statement(&mut self) -> Result<Stmt, ScriptError> {
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

    // ========================================================================
    // Expression Parsing (Pratt Parsing)
    // ========================================================================

    fn parse_expression(&mut self) -> Result<Expr, ScriptError> {
        self.parse_or_expression()
    }

    fn parse_or_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_and_expression()?;

        while self.check(TokenKind::Or) {
            self.advance();
            let right = self.parse_and_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_and_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_comparison_expression()?;

        while self.check(TokenKind::And) {
            self.advance();
            let right = self.parse_comparison_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_comparison_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_bitwise_or_expression()?;

        loop {
            let op = if self.check(TokenKind::EqEq) {
                BinaryOp::Eq
            } else if self.check(TokenKind::Ne) {
                BinaryOp::Ne
            } else if self.check(TokenKind::Lt) {
                BinaryOp::Lt
            } else if self.check(TokenKind::Le) {
                BinaryOp::Le
            } else if self.check(TokenKind::Gt) {
                BinaryOp::Gt
            } else if self.check(TokenKind::Ge) {
                BinaryOp::Ge
            } else {
                break;
            };

            self.advance();
            let right = self.parse_bitwise_or_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_bitwise_or_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_bitwise_xor_expression()?;

        while self.check(TokenKind::Pipe) {
            self.advance();
            let right = self.parse_bitwise_xor_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::BitOr,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_bitwise_xor_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_bitwise_and_expression()?;

        while self.check(TokenKind::Caret) {
            self.advance();
            let right = self.parse_bitwise_and_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::BitXor,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_bitwise_and_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_shift_expression()?;

        while self.check(TokenKind::Ampersand) {
            self.advance();
            let right = self.parse_shift_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::BitAnd,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_shift_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_additive_expression()?;

        loop {
            let op = if self.check(TokenKind::Shl) {
                BinaryOp::Shl
            } else if self.check(TokenKind::Shr) {
                BinaryOp::Shr
            } else {
                break;
            };

            self.advance();
            let right = self.parse_additive_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_additive_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_multiplicative_expression()?;

        loop {
            let op = if self.check(TokenKind::Plus) {
                BinaryOp::Add
            } else if self.check(TokenKind::Minus) {
                BinaryOp::Sub
            } else {
                break;
            };

            self.advance();
            let right = self.parse_multiplicative_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_multiplicative_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_unary_expression()?;

        loop {
            let op = if self.check(TokenKind::Star) {
                BinaryOp::Mul
            } else if self.check(TokenKind::Slash) {
                BinaryOp::Div
            } else if self.check(TokenKind::Percent) {
                BinaryOp::Mod
            } else {
                break;
            };

            self.advance();
            let right = self.parse_unary_expression()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }

        Ok(expr)
    }

    fn parse_unary_expression(&mut self) -> Result<Expr, ScriptError> {
        if self.check(TokenKind::Minus) {
            self.advance();
            let operand = self.parse_unary_expression()?;
            return Ok(Expr::Unary {
                op: UnaryOp::Neg,
                operand: Box::new(operand),
            });
        }

        if self.check(TokenKind::Bang) {
            self.advance();
            let operand = self.parse_unary_expression()?;
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                operand: Box::new(operand),
            });
        }

        if self.check(TokenKind::Tilde) {
            self.advance();
            let operand = self.parse_unary_expression()?;
            return Ok(Expr::Unary {
                op: UnaryOp::BitNot,
                operand: Box::new(operand),
            });
        }

        self.parse_postfix_expression()
    }

    fn parse_postfix_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_primary_expression()?;

        loop {
            if self.check(TokenKind::LeftParen) {
                // 関数呼び出し
                self.advance();
                let args = self.parse_arguments()?;
                self.expect(TokenKind::RightParen)?;
                expr = Expr::Call {
                    function: Box::new(expr),
                    arguments: args,
                };
            } else if self.check(TokenKind::LeftBracket) {
                // インデックスアクセス
                self.advance();
                let index = self.parse_expression()?;
                self.expect(TokenKind::RightBracket)?;
                expr = Expr::Index {
                    object: Box::new(expr),
                    index: Box::new(index),
                };
            } else if self.check(TokenKind::Dot) {
                // フィールドアクセスまたはメソッド呼び出し
                self.advance();
                let name = self.expect_identifier()?;

                if self.check(TokenKind::LeftParen) {
                    // メソッド呼び出し
                    self.advance();
                    let args = self.parse_arguments()?;
                    self.expect(TokenKind::RightParen)?;
                    expr = Expr::MethodCall {
                        object: Box::new(expr),
                        method: name,
                        arguments: args,
                    };
                } else {
                    // フィールドアクセス
                    expr = Expr::FieldAccess {
                        object: Box::new(expr),
                        field: name,
                    };
                }
            } else if self.check(TokenKind::DoubleColon) {
                // 名前空間アクセス
                self.advance();
                let member = self.expect_identifier()?;
                expr = Expr::NamespaceAccess {
                    namespace: Box::new(expr),
                    member,
                };
            } else {
                break;
            }
        }

        Ok(expr)
    }

    fn parse_primary_expression(&mut self) -> Result<Expr, ScriptError> {
        // リテラル
        if self.check(TokenKind::Integer) {
            let token = self.advance();
            let value = self.parse_integer(&token.lexeme)?;
            return Ok(Expr::Literal(Literal::Int(value)));
        }

        if self.check(TokenKind::Float) {
            let token = self.advance();
            let value = self.parse_float(&token.lexeme)?;
            return Ok(Expr::Literal(Literal::Float(value)));
        }

        if self.check(TokenKind::StringLit) {
            let token = self.advance();
            let value = self.parse_string_literal(&token.lexeme);
            return Ok(Expr::Literal(Literal::String(value)));
        }

        if self.check(TokenKind::True) {
            self.advance();
            return Ok(Expr::Literal(Literal::Bool(true)));
        }

        if self.check(TokenKind::False) {
            self.advance();
            return Ok(Expr::Literal(Literal::Bool(false)));
        }

        if self.check(TokenKind::Nil) {
            self.advance();
            return Ok(Expr::Literal(Literal::Nil));
        }

        // 識別子
        if self.check(TokenKind::Identifier) {
            let token = self.advance();
            return Ok(Expr::Identifier(token.lexeme.clone()));
        }

        // セルフ参照
        if self.check(TokenKind::SelfLower) {
            self.advance();
            return Ok(Expr::SelfRef);
        }

        // 括弧式またはタプル
        if self.check(TokenKind::LeftParen) {
            self.advance();

            if self.check(TokenKind::RightParen) {
                // 空のタプル（ユニット）
                self.advance();
                return Ok(Expr::Tuple(Vec::new()));
            }

            let first = self.parse_expression()?;

            if self.check(TokenKind::Comma) {
                // タプル
                let mut elements = vec![first];
                while self.check(TokenKind::Comma) {
                    self.advance();
                    if self.check(TokenKind::RightParen) {
                        break;
                    }
                    elements.push(self.parse_expression()?);
                }
                self.expect(TokenKind::RightParen)?;
                return Ok(Expr::Tuple(elements));
            }

            self.expect(TokenKind::RightParen)?;
            return Ok(first);
        }

        // 配列
        if self.check(TokenKind::LeftBracket) {
            return self.parse_array_expression();
        }

        // ブロック式
        if self.check(TokenKind::LeftBrace) {
            return self.parse_block_expression();
        }

        // if式
        if self.check(TokenKind::If) {
            return self.parse_if_expression();
        }

        // match式
        if self.check(TokenKind::Match) {
            return self.parse_match_expression();
        }

        // クロージャ
        if self.check(TokenKind::Pipe) || self.check(TokenKind::Move) {
            return self.parse_closure_expression();
        }

        // 範囲演算子（開始値なし）
        if self.check(TokenKind::DotDot) || self.check(TokenKind::DotDotEq) {
            let inclusive = self.check(TokenKind::DotDotEq);
            self.advance();
            let end = self.parse_unary_expression()?;
            return Ok(Expr::Range {
                start: None,
                end: Some(Box::new(end)),
                inclusive,
            });
        }

        Err(self.error("Expected expression"))
    }

    /// 配列式
    fn parse_array_expression(&mut self) -> Result<Expr, ScriptError> {
        self.expect(TokenKind::LeftBracket)?;

        let mut elements = Vec::new();

        if !self.check(TokenKind::RightBracket) {
            loop {
                elements.push(self.parse_expression()?);

                if !self.check(TokenKind::Comma) {
                    break;
                }
                self.advance();

                if self.check(TokenKind::RightBracket) {
                    break;
                }
            }
        }

        self.expect(TokenKind::RightBracket)?;

        Ok(Expr::Array(elements))
    }

    /// ブロック式
    fn parse_block_expression(&mut self) -> Result<Expr, ScriptError> {
        let block = self.parse_block()?;
        Ok(Expr::Block(Box::new(block)))
    }

    /// if式
    fn parse_if_expression(&mut self) -> Result<Expr, ScriptError> {
        self.expect(TokenKind::If)?;

        let condition = self.parse_expression()?;
        let then_block = self.parse_block()?;

        let else_block = if self.check(TokenKind::Else) {
            self.advance();
            if self.check(TokenKind::If) {
                let else_if = self.parse_if_expression()?;
                Some(Box::new(Stmt::Expression(else_if)))
            } else {
                Some(Box::new(self.parse_block()?))
            }
        } else {
            None
        };

        Ok(Expr::If {
            condition: Box::new(condition),
            then_block: Box::new(then_block),
            else_block,
        })
    }

    /// match式
    fn parse_match_expression(&mut self) -> Result<Expr, ScriptError> {
        self.expect(TokenKind::Match)?;

        let value = self.parse_expression()?;

        self.expect(TokenKind::LeftBrace)?;

        let mut arms = Vec::new();
        while !self.check(TokenKind::RightBrace) && !self.is_at_end() {
            // 改行やコンマをスキップ
            while self.check(TokenKind::Newline) || self.check(TokenKind::Comma) {
                self.advance();
            }

            if self.check(TokenKind::RightBrace) {
                break;
            }

            let pattern = self.parse_pattern()?;

            // ガード条件
            let guard = if self.check(TokenKind::If) {
                self.advance();
                Some(self.parse_expression()?)
            } else {
                None
            };

            self.expect(TokenKind::FatArrow)?;

            let body = self.parse_expression()?;

            arms.push(MatchArm {
                pattern,
                guard,
                body,
            });

            // コンマは省略可能
            if self.check(TokenKind::Comma) {
                self.advance();
            }
        }

        self.expect(TokenKind::RightBrace)?;

        Ok(Expr::Match {
            value: Box::new(value),
            arms,
        })
    }

    /// クロージャ式
    fn parse_closure_expression(&mut self) -> Result<Expr, ScriptError> {
        let is_move = if self.check(TokenKind::Move) {
            self.advance();
            true
        } else {
            false
        };

        self.expect(TokenKind::Pipe)?;

        let mut params = Vec::new();
        if !self.check(TokenKind::Pipe) {
            loop {
                let name = self.expect_identifier()?;
                let type_annotation = if self.check(TokenKind::Colon) {
                    self.advance();
                    Some(self.parse_type_annotation()?)
                } else {
                    None
                };
                params.push(ClosureParam {
                    name,
                    type_annotation,
                });

                if !self.check(TokenKind::Comma) {
                    break;
                }
                self.advance();
            }
        }

        self.expect(TokenKind::Pipe)?;

        // 戻り値の型
        let return_type = if self.check(TokenKind::Arrow) {
            self.advance();
            Some(self.parse_type_annotation()?)
        } else {
            None
        };

        // 本体
        let body = if self.check(TokenKind::LeftBrace) {
            Expr::Block(Box::new(self.parse_block()?))
        } else {
            self.parse_expression()?
        };

        Ok(Expr::Closure {
            params,
            return_type,
            body: Box::new(body),
            is_move,
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// パターンをパース
    fn parse_pattern(&mut self) -> Result<Pattern, ScriptError> {
        if self.check(TokenKind::Underscore) {
            self.advance();
            return Ok(Pattern::Wildcard);
        }

        if self.check(TokenKind::Integer) {
            let token = self.advance();
            let value = self.parse_integer(&token.lexeme)?;
            return Ok(Pattern::Literal(Literal::Int(value)));
        }

        if self.check(TokenKind::StringLit) {
            let token = self.advance();
            let value = self.parse_string_literal(&token.lexeme);
            return Ok(Pattern::Literal(Literal::String(value)));
        }

        if self.check(TokenKind::True) {
            self.advance();
            return Ok(Pattern::Literal(Literal::Bool(true)));
        }

        if self.check(TokenKind::False) {
            self.advance();
            return Ok(Pattern::Literal(Literal::Bool(false)));
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

        if self.check(TokenKind::LeftBracket) {
            // 配列パターン
            self.advance();
            let mut patterns = Vec::new();
            if !self.check(TokenKind::RightBracket) {
                loop {
                    patterns.push(self.parse_pattern()?);
                    if !self.check(TokenKind::Comma) {
                        break;
                    }
                    self.advance();
                }
            }
            self.expect(TokenKind::RightBracket)?;
            return Ok(Pattern::Array(patterns));
        }

        // 識別子パターン
        if self.check(TokenKind::Identifier) {
            let token = self.advance();
            return Ok(Pattern::Identifier(token.lexeme.clone()));
        }

        Err(self.error("Expected pattern"))
    }

    /// 型注釈をパース
    fn parse_type_annotation(&mut self) -> Result<TypeAnnotation, ScriptError> {
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
            return Ok(TypeAnnotation::Array(Box::new(element_type)));
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
    fn parse_function_params(&mut self) -> Result<Vec<FunctionParam>, ScriptError> {
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
                    type_annotation: None,
                    default_value: None,
                });
            } else if self.check(TokenKind::Ampersand) {
                // &self または &mut self
                self.advance();
                let mutable = if self.check(TokenKind::Mut) {
                    self.advance();
                    true
                } else {
                    false
                };
                self.expect(TokenKind::SelfLower)?;
                let name = if mutable {
                    String::from("&mut self")
                } else {
                    String::from("&self")
                };
                params.push(FunctionParam {
                    name,
                    type_annotation: None,
                    default_value: None,
                });
            } else {
                // 通常のパラメータ
                let name = self.expect_identifier()?;
                self.expect(TokenKind::Colon)?;
                let type_annotation = Some(self.parse_type_annotation()?);

                let default_value = if self.check(TokenKind::Eq) {
                    self.advance();
                    Some(self.parse_expression()?)
                } else {
                    None
                };

                params.push(FunctionParam {
                    name,
                    type_annotation,
                    default_value,
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
    fn parse_arguments(&mut self) -> Result<Vec<Expr>, ScriptError> {
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
    fn parse_integer(&self, s: &str) -> Result<i64, ScriptError> {
        let s = s.replace("_", "");
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
    fn parse_float(&self, s: &str) -> Result<f64, ScriptError> {
        let s = s.replace("_", "");
        s.parse()
            .map_err(|_| self.error("Invalid float"))
    }

    /// 文字列リテラルをパース（エスケープ処理）
    fn parse_string_literal(&self, s: &str) -> String {
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

    fn check(&self, kind: TokenKind) -> bool {
        if self.is_at_end() {
            return false;
        }
        self.peek().kind == kind
    }

    fn advance(&mut self) -> Token {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.current]
    }

    fn previous(&self) -> Token {
        self.tokens[self.current - 1].clone()
    }

    fn is_at_end(&self) -> bool {
        self.current >= self.tokens.len() || self.peek().kind == TokenKind::Eof
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token, ScriptError> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            Err(self.error(&format!("Expected {:?}", kind)))
        }
    }

    fn expect_identifier(&mut self) -> Result<String, ScriptError> {
        if self.check(TokenKind::Identifier) {
            let token = self.advance();
            Ok(token.lexeme)
        } else {
            Err(self.error("Expected identifier"))
        }
    }

    fn consume_statement_terminator(&mut self) -> Result<(), ScriptError> {
        // セミコロンまたは改行を消費（省略可能）
        while self.check(TokenKind::Semicolon) || self.check(TokenKind::Newline) {
            self.advance();
        }
        Ok(())
    }

    fn error(&self, message: &str) -> ScriptError {
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
