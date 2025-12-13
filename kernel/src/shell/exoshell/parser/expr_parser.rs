// ============================================================================
// src/shell/exoshell/parser/expr_parser.rs - Expression Parser
// ============================================================================
//!
//! # 式パーサー (Recursive Descent Parser)
//!
//! 演算子優先順位を正しく処理する再帰下降パーサー。
//!
//! ## 文法 (BNF-like)
//!
//! ```text
//! expr        = or_expr
//! or_expr     = and_expr ("||" and_expr)*
//! and_expr    = compare_expr ("&&" compare_expr)*
//! compare_expr = add_expr (("<" | ">" | "==" | ...) add_expr)?
//! add_expr    = mul_expr (("+" | "-") mul_expr)*
//! mul_expr    = unary_expr (("*" | "/" | "%") unary_expr)*
//! unary_expr  = ("!" | "-")? postfix_expr
//! postfix_expr = primary ("." ident ("(" args ")")?)*
//! primary     = literal | ident | "(" expr ")" | "|" ident "|" expr
//! ```

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::ast::{BinaryOp, Expr, UnaryOp};
use super::error::ParseError;
use super::tokenizer::Token;
use crate::shell::exoshell::types::ExoValue;

// ============================================================================
// Expression Parser
// ============================================================================

/// 式パーサー
///
/// トークン列から AST (抽象構文木) を構築する再帰下降パーサー。
/// 演算子優先順位を正しく処理する。
pub struct ExprParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl ExprParser {
    /// 新しいパーサーを作成
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    /// 現在のトークンを覗き見る
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    /// 2つ先のトークンを覗き見る
    fn peek_next(&self) -> Option<&Token> {
        self.tokens.get(self.pos + 1)
    }

    /// 現在のトークンを消費して次へ進む
    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    /// 特定のトークンが現在位置にあるかチェックし、あれば消費
    fn match_token(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// 特定の演算子文字列がOperatorトークンとしてあるかチェックし、あれば消費
    fn match_operator(&mut self, op: &str) -> bool {
        if let Some(Token::Operator(s)) = self.peek() {
            if s == op {
                self.advance();
                return true;
            }
        }
        false
    }

    /// トークン列の終端かどうか
    fn is_at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// 式をパース
    ///
    /// トップレベルのエントリポイント。演算子優先順位を考慮して式を解析。
    pub fn parse_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        self.parse_pipe_expr()
    }

    // ========================================================================
    // Precedence Levels (低→高)
    // ========================================================================

    /// Level 0: パイプ式 (`a |> f()`)
    fn parse_pipe_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let mut left = self.parse_or_expr()?;

        while self.match_operator("|>") {
            let right = self.parse_or_expr()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: BinaryOp::Pipe,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Level 1: OR 式 (`a || b`)
    fn parse_or_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let mut left = self.parse_and_expr()?;

        while self.match_operator("||") {
            let right = self.parse_and_expr()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Level 2: AND 式 (`a && b`)
    fn parse_and_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let mut left = self.parse_compare_expr()?;

        while self.match_operator("&&") {
            let right = self.parse_compare_expr()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Level 3: 比較式 (`a > b`, `a == b`, `name.contains("log")`)
    fn parse_compare_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let left = self.parse_add_expr()?;

        // 比較演算子をチェック
        if let Some(Token::Operator(op_str)) = self.peek().cloned() {
            if let Some(op) = self.parse_comparison_op(&op_str) {
                self.advance();
                let right = self.parse_add_expr()?;
                return Ok(Expr::Binary {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                });
            }
        }

        // `contains`, `starts_with`, `ends_with` キーワード演算子
        if let Some(Token::Ident(kw)) = self.peek().cloned() {
            if let Some(op) = self.parse_keyword_op(&kw) {
                self.advance();
                let right = self.parse_add_expr()?;
                return Ok(Expr::Binary {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                });
            }
        }

        Ok(left)
    }

    /// 比較演算子を解析
    fn parse_comparison_op(&self, s: &str) -> Option<BinaryOp> {
        match s {
            "==" => Some(BinaryOp::Eq),
            "!=" => Some(BinaryOp::Ne),
            "<" => Some(BinaryOp::Lt),
            "<=" => Some(BinaryOp::Le),
            ">" => Some(BinaryOp::Gt),
            ">=" => Some(BinaryOp::Ge),
            _ => None,
        }
    }

    /// キーワード演算子を解析
    fn parse_keyword_op(&self, s: &str) -> Option<BinaryOp> {
        match s {
            "contains" => Some(BinaryOp::Contains),
            "starts_with" => Some(BinaryOp::StartsWith),
            "ends_with" => Some(BinaryOp::EndsWith),
            _ => None,
        }
    }

    /// Level 4: 加減算式 (`a + b`, `a - b`)
    fn parse_add_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let mut left = self.parse_mul_expr()?;

        loop {
            let op = if self.match_operator("+") {
                BinaryOp::Add
            } else if self.match_operator("-") {
                BinaryOp::Sub
            } else {
                break;
            };

            let right = self.parse_mul_expr()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Level 5: 乗除算式 (`a * b`, `a / b`, `a % b`)
    fn parse_mul_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let mut left = self.parse_unary_expr()?;

        loop {
            let op = if self.match_operator("*") {
                BinaryOp::Mul
            } else if self.match_operator("/") {
                BinaryOp::Div
            } else if self.match_operator("%") {
                BinaryOp::Mod
            } else {
                break;
            };

            let right = self.parse_unary_expr()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Level 6: 単項演算式 (`!a`, `-a`)
    fn parse_unary_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        // NOT 演算子
        if self.match_operator("!") {
            let operand = self.parse_unary_expr()?;
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                operand: Box::new(operand),
            });
        }

        // 負号（ただし数値リテラルの先頭でない場合）
        if self.match_operator("-") {
            let operand = self.parse_unary_expr()?;
            return Ok(Expr::Unary {
                op: UnaryOp::Neg,
                operand: Box::new(operand),
            });
        }

        self.parse_postfix_expr()
    }

    /// Level 7: 後置式（フィールドアクセス、メソッド呼び出し、インデックスアクセス）
    fn parse_postfix_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        let mut expr = self.parse_primary()?;

        loop {
            // `.field` または `.method(args)`
            if self.match_token(&Token::Dot) {
                if let Some(Token::Ident(name)) = self.peek().cloned() {
                    self.advance();

                    // メソッド呼び出し？
                    if self.match_token(&Token::LParen) {
                        let args = self.parse_args()?;
                        expr = Expr::MethodCall {
                            object: Box::new(expr),
                            method: name,
                            args,
                        };
                    } else {
                        // フィールドアクセス
                        expr = Expr::FieldAccess {
                            object: Box::new(expr),
                            field: name,
                        };
                    }
                } else {
                    return Err(ParseError::UnexpectedToken {
                        expected: "identifier after '.'".to_string(),
                        found: format!("{:?}", self.peek()),
                    });
                }
            }
            // `[index]` インデックスアクセス
            else if self.match_token(&Token::LBracket) {
                let index = self.parse_expr()?;
                if !self.match_token(&Token::RBracket) {
                    return Err(ParseError::UnexpectedToken {
                        expected: "']'".to_string(),
                        found: format!("{:?}", self.peek()),
                    });
                }
                expr = Expr::Index {
                    object: Box::new(expr),
                    index: Box::new(index),
                };
            } else {
                break;
            }
        }

        Ok(expr)
    }

    /// 基本式（リテラル、識別子、括弧、クロージャ）
    fn parse_primary(&mut self) -> Result<Expr<'static>, ParseError> {
        match self.peek().cloned() {
            // 数値リテラル
            Some(Token::Number(n)) => {
                self.advance();
                Ok(Expr::Literal(ExoValue::Int(n)))
            }

            // 浮動小数点リテラル
            Some(Token::Float(f)) => {
                self.advance();
                Ok(Expr::Literal(ExoValue::Float(f)))
            }

            // 文字列リテラル
            Some(Token::StringLit(s)) => {
                self.advance();
                Ok(Expr::string(s))
            }

            // 識別子
            Some(Token::Ident(name)) => {
                self.advance();

                // true/false キーワード
                match name.as_str() {
                    "true" => Ok(Expr::Literal(ExoValue::Bool(true))),
                    "false" => Ok(Expr::Literal(ExoValue::Bool(false))),
                    "nil" => Ok(Expr::Literal(ExoValue::Nil)),
                    _ => {
                        // 関数呼び出し？
                        if self.match_token(&Token::LParen) {
                            let args = self.parse_args()?;
                            Ok(Expr::MethodCall {
                                object: Box::new(Expr::Ident(String::new())),
                                method: name,
                                args,
                            })
                        } else {
                            Ok(Expr::Ident(name))
                        }
                    }
                }
            }

            // 括弧グループ: (expr)
            Some(Token::LParen) => {
                self.advance();
                let inner = self.parse_expr()?;
                if !self.match_token(&Token::RParen) {
                    return Err(ParseError::UnexpectedToken {
                        expected: "')'".to_string(),
                        found: format!("{:?}", self.peek()),
                    });
                }
                Ok(Expr::Group(Box::new(inner)))
            }

            // 配列リテラル: [expr, expr, ...]
            Some(Token::LBracket) => {
                self.advance();
                let mut elements = Vec::new();

                // 空配列チェック
                if !self.match_token(&Token::RBracket) {
                    // 最初の要素
                    elements.push(self.parse_expr()?);

                    // カンマ区切りで残りの要素
                    while self.match_token(&Token::Comma) {
                        // 末尾カンマ対応
                        if matches!(self.peek(), Some(Token::RBracket)) {
                            break;
                        }
                        elements.push(self.parse_expr()?);
                    }

                    if !self.match_token(&Token::RBracket) {
                        return Err(ParseError::UnexpectedToken {
                            expected: "']'".to_string(),
                            found: format!("{:?}", self.peek()),
                        });
                    }
                }

                Ok(Expr::Array(elements))
            }

            // マップリテラル: {key: value, ...}
            Some(Token::LBrace) => {
                self.advance();
                let mut pairs = Vec::new();

                // 空マップチェック
                if !self.match_token(&Token::RBrace) {
                    loop {
                        // キー（識別子または文字列）
                        let key = match self.peek().cloned() {
                            Some(Token::Ident(k)) => {
                                self.advance();
                                k
                            }
                            Some(Token::StringLit(k)) => {
                                self.advance();
                                k
                            }
                            _ => {
                                return Err(ParseError::UnexpectedToken {
                                    expected: "map key (identifier or string)".to_string(),
                                    found: format!("{:?}", self.peek()),
                                });
                            }
                        };

                        // コロン
                        if !self.match_token(&Token::Colon) {
                            return Err(ParseError::UnexpectedToken {
                                expected: "':'".to_string(),
                                found: format!("{:?}", self.peek()),
                            });
                        }

                        // 値
                        let value = self.parse_expr()?;
                        pairs.push((key, value));

                        // カンマまたは閉じ波括弧
                        if self.match_token(&Token::Comma) {
                            // 末尾カンマ対応
                            if matches!(self.peek(), Some(Token::RBrace)) {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    if !self.match_token(&Token::RBrace) {
                        return Err(ParseError::UnexpectedToken {
                            expected: "'}'".to_string(),
                            found: format!("{:?}", self.peek()),
                        });
                    }
                }

                Ok(Expr::Map(pairs))
            }

            // クロージャ: |e| expr
            Some(Token::Pipe) => {
                self.advance();

                // パラメータ名
                let param = if let Some(Token::Ident(name)) = self.peek().cloned() {
                    self.advance();
                    name
                } else {
                    return Err(ParseError::UnexpectedToken {
                        expected: "closure parameter".to_string(),
                        found: format!("{:?}", self.peek()),
                    });
                };

                // 閉じパイプ
                if !self.match_token(&Token::Pipe) {
                    return Err(ParseError::UnexpectedToken {
                        expected: "'|'".to_string(),
                        found: format!("{:?}", self.peek()),
                    });
                }

                // クロージャ本体
                let body = self.parse_expr()?;

                Ok(Expr::Closure {
                    param,
                    body: Box::new(body),
                })
            }

            Some(token) => Err(ParseError::UnexpectedToken {
                expected: "expression".to_string(),
                found: format!("{:?}", token),
            }),

            None => Err(ParseError::UnexpectedEof),
        }
    }

    /// 引数リストをパース
    fn parse_args(&mut self) -> Result<Vec<Expr<'static>>, ParseError> {
        let mut args = Vec::new();

        // 空の引数リスト
        if self.match_token(&Token::RParen) {
            return Ok(args);
        }

        // 最初の引数
        args.push(self.parse_expr()?);

        // カンマ区切りで追加の引数
        while self.match_token(&Token::Comma) {
            args.push(self.parse_expr()?);
        }

        // 閉じ括弧
        if !self.match_token(&Token::RParen) {
            return Err(ParseError::UnexpectedToken {
                expected: "')' or ','".to_string(),
                found: format!("{:?}", self.peek()),
            });
        }

        Ok(args)
    }
}

// ============================================================================
// Convenience Function
// ============================================================================

/// 文字列から直接式をパース
///
/// トークナイザと式パーサーを組み合わせて使用。
pub fn parse_expression(input: &str) -> Result<Expr<'static>, ParseError> {
    let mut tokenizer = super::tokenizer::Tokenizer::new(input);
    let tokens = tokenizer.tokenize();
    let mut parser = ExprParser::new(tokens);
    parser.parse_expr()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_literal() {
        let expr = parse_expression("42").unwrap();
        assert!(matches!(expr, Expr::Literal(ExoValue::Int(42))));
    }

    #[test]
    fn test_binary_comparison() {
        let expr = parse_expression("size > 1024").unwrap();
        match expr {
            Expr::Binary { left, op, right } => {
                assert!(matches!(*left, Expr::Ident(ref s) if s == "size"));
                assert_eq!(op, BinaryOp::Gt);
                assert!(matches!(*right, Expr::Literal(ExoValue::Int(1024))));
            }
            _ => panic!("Expected Binary expression"),
        }
    }

    #[test]
    fn test_complex_and_or() {
        // a && b || c は (a && b) || c としてパースされる
        let expr = parse_expression("a && b || c").unwrap();
        match expr {
            Expr::Binary {
                left,
                op: BinaryOp::Or,
                right,
            } => {
                assert!(matches!(
                    *left,
                    Expr::Binary {
                        op: BinaryOp::And,
                        ..
                    }
                ));
                assert!(matches!(*right, Expr::Ident(ref s) if s == "c"));
            }
            _ => panic!("Expected Or expression"),
        }
    }

    #[test]
    fn test_grouped_expression() {
        // (a || b) && c
        let expr = parse_expression("(a || b) && c").unwrap();
        match expr {
            Expr::Binary {
                left,
                op: BinaryOp::And,
                ..
            } => {
                assert!(matches!(*left, Expr::Group(_)));
            }
            _ => panic!("Expected And expression with grouped left"),
        }
    }
}
