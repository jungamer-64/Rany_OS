// ============================================================================
// src/application/browser/script/parser/expressions.rs - Expression Parsing
// ============================================================================
//!
//! 式（Expression）のパース処理
//! Pratt parsingによる演算子優先順位の処理を実装

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::vec;

use crate::application::browser::script::lexer::TokenKind;
use crate::application::browser::script::ast::*;
use crate::application::browser::script::{ScriptError};

use super::Parser;

// ============================================================================
// Expression Parsing Methods (Pratt Parsing)
// ============================================================================

impl Parser {
    /// 式をパース
    pub(crate) fn parse_expression(&mut self) -> Result<Expr, ScriptError> {
        self.parse_or_expression()
    }

    /// 論理OR式
    pub(crate) fn parse_or_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// 論理AND式
    pub(crate) fn parse_and_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// 比較式
    pub(crate) fn parse_comparison_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_bitwise_or_expression()?;

        loop {
            let op = if self.check(TokenKind::EqEq) {
                BinaryOp::Eq
            } else if self.check(TokenKind::Ne) {
                BinaryOp::NotEq
            } else if self.check(TokenKind::Lt) {
                BinaryOp::Lt
            } else if self.check(TokenKind::Le) {
                BinaryOp::LtEq
            } else if self.check(TokenKind::Gt) {
                BinaryOp::Gt
            } else if self.check(TokenKind::Ge) {
                BinaryOp::GtEq
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

    /// ビットOR式
    pub(crate) fn parse_bitwise_or_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// ビットXOR式
    pub(crate) fn parse_bitwise_xor_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// ビットAND式
    pub(crate) fn parse_bitwise_and_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// シフト式
    pub(crate) fn parse_shift_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// 加減算式
    pub(crate) fn parse_additive_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// 乗除算式
    pub(crate) fn parse_multiplicative_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// 単項式
    pub(crate) fn parse_unary_expression(&mut self) -> Result<Expr, ScriptError> {
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

    /// 後置式（呼び出し、インデックス、フィールドアクセス）
    pub(crate) fn parse_postfix_expression(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = self.parse_primary_expression()?;

        loop {
            if self.check(TokenKind::LeftParen) {
                // 関数呼び出し
                self.advance();
                let call_args = self.parse_arguments()?;
                self.expect(TokenKind::RightParen)?;
                expr = Expr::Call {
                    callee: Box::new(expr),
                    args: call_args,
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
                    let method_args = self.parse_arguments()?;
                    self.expect(TokenKind::RightParen)?;
                    expr = Expr::MethodCall {
                        object: Box::new(expr),
                        method: name,
                        args: method_args,
                    };
                } else {
                    // フィールドアクセス
                    expr = Expr::FieldAccess {
                        object: Box::new(expr),
                        field: name,
                    };
                }
            } else if self.check(TokenKind::DoubleColon) {
                // 名前空間アクセス (Pathとして扱う)
                self.advance();
                let member = self.expect_identifier()?;
                // 既存のPathに追加するか、新しいPathを作成
                match expr {
                    Expr::Path(mut segments) => {
                        segments.push(member);
                        expr = Expr::Path(segments);
                    }
                    Expr::Identifier(first) => {
                        expr = Expr::Path(vec![first, member]);
                    }
                    _ => {
                        // その他の式の場合はフィールドアクセスとして扱う
                        expr = Expr::FieldAccess {
                            object: Box::new(expr),
                            field: member,
                        };
                    }
                }
            } else {
                break;
            }
        }

        Ok(expr)
    }

    /// プライマリ式（リテラル、識別子、括弧など）
    pub(crate) fn parse_primary_expression(&mut self) -> Result<Expr, ScriptError> {
        // リテラル
        if self.check(TokenKind::Integer) {
            let token = self.advance();
            let value = self.parse_integer(&token.lexeme)?;
            return Ok(Expr::Literal(Literal::Integer(value)));
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
            return Ok(Expr::Identifier("self".into()));
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
    pub(crate) fn parse_array_expression(&mut self) -> Result<Expr, ScriptError> {
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
    pub(crate) fn parse_block_expression(&mut self) -> Result<Expr, ScriptError> {
        let block = self.parse_block()?;
        let statements = match block {
            Stmt::Block(stmts) => stmts,
            _ => vec![block],
        };
        Ok(Expr::Block {
            statements,
            value: None,
        })
    }

    /// if式
    pub(crate) fn parse_if_expression(&mut self) -> Result<Expr, ScriptError> {
        self.expect(TokenKind::If)?;

        let condition = self.parse_expression()?;
        let then_block = self.parse_block()?;

        let else_block = if self.check(TokenKind::Else) {
            self.advance();
            if self.check(TokenKind::If) {
                let else_if = self.parse_if_expression()?;
                Some(Box::new(else_if))
            } else {
                let else_stmt = self.parse_block()?;
                // Block文をBlock式に変換
                Some(Box::new(Expr::Block {
                    statements: match else_stmt {
                        Stmt::Block(stmts) => stmts,
                        _ => vec![else_stmt],
                    },
                    value: None,
                }))
            }
        } else {
            None
        };

        // then_blockをExprに変換
        let then_expr = Expr::Block {
            statements: match then_block {
                Stmt::Block(stmts) => stmts,
                _ => vec![then_block],
            },
            value: None,
        };

        Ok(Expr::If {
            condition: Box::new(condition),
            then_branch: Box::new(then_expr),
            else_branch: else_block,
        })
    }

    /// match式
    pub(crate) fn parse_match_expression(&mut self) -> Result<Expr, ScriptError> {
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
    pub(crate) fn parse_closure_expression(&mut self) -> Result<Expr, ScriptError> {
        let _is_move = if self.check(TokenKind::Move) {
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
                    type_ann: type_annotation,
                });

                if !self.check(TokenKind::Comma) {
                    break;
                }
                self.advance();
            }
        }

        self.expect(TokenKind::Pipe)?;

        // 戻り値の型（クロージャでは無視）
        if self.check(TokenKind::Arrow) {
            self.advance();
            let _ = self.parse_type_annotation()?;
        }

        // 本体
        let body = if self.check(TokenKind::LeftBrace) {
            let block_stmt = self.parse_block()?;
            Expr::Block {
                statements: match block_stmt {
                    Stmt::Block(stmts) => stmts,
                    _ => vec![block_stmt],
                },
                value: None,
            }
        } else {
            self.parse_expression()?
        };

        Ok(Expr::Closure {
            params,
            body: Box::new(body),
        })
    }
}
