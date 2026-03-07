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

use super::ast::{BinaryOp, Expr, Stmt, UnaryOp};
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
mod map_literal;
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

    /// 文をパース
    pub fn parse_stmt(&mut self) -> Result<Stmt<'static>, ParseError> {
        if self.match_token(&Token::Let) {
            self.parse_let_stmt()
        } else {
            self.parse_expr_stmt()
        }
    }

    /// Let文: `let name = expr`
    fn parse_let_stmt(&mut self) -> Result<Stmt<'static>, ParseError> {
        // パラメータ名
        let name = if let Some(Token::Ident(name)) = self.peek().cloned() {
            self.advance();
            name
        } else {
            return Err(ParseError::UnexpectedToken {
                expected: "variable name".to_string(),
                found: format!("{:?}", self.peek()),
            });
        };

        // `=`
        if !self.match_operator("=") {
            return Err(ParseError::UnexpectedToken {
                expected: "'='".to_string(),
                found: format!("{:?}", self.peek()),
            });
        }

        let value = self.parse_expr()?;

        Ok(Stmt::let_binding(name, value))
    }

    /// 式文またはコマンド文
    fn parse_expr_stmt(&mut self) -> Result<Stmt<'static>, ParseError> {
        let expr = self.parse_expr()?;

        // トップレベルの識別子のみの場合はコマンドとして扱う可能性があるが、
        // 現状は Expr として返し、Evaluator 側で処理するか、
        // ここで Stmt::Command に変換するか。
        // リファクタ案では `Command` を AST レベルでサポートする。

        match expr {
            // `cmd arg1 arg2` 形式はサポートしていない（Rust式ではない）。
            // しかし、 `help` や `exit` のような単独識別子はコマンドとして扱いたい。
            // また `cmd(arg)` 形式の MethodCall で object が空文字の場合もコマンド。
            Expr::Ident(name) => {
                if name == "break" {
                    Ok(Stmt::Break)
                } else if name == "continue" {
                    Ok(Stmt::Continue)
                } else {
                    Ok(Stmt::Command {
                        name,
                        args: Vec::new(),
                    })
                }
            }

            Expr::MethodCall {
                object,
                method,
                args,
            } => {
                // object が Ident("") の場合はグローバル関数呼び出し -> コマンド
                if let Expr::Ident(ref s) = *object {
                    if s.is_empty() {
                        return Ok(Stmt::Command { name: method, args });
                    }
                }
                Ok(Stmt::Expr(Box::new(Expr::MethodCall {
                    object,
                    method,
                    args,
                })))
            }

            _ => Ok(Stmt::Expr(Box::new(expr))),
        }
    }

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

    /// ブロック式のパース
    fn parse_block_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        self.advance(); // consume '{'
        let mut stmts = Vec::new();

        // 空ブロックチェック: {}
        if self.match_token(&Token::RBrace) {
            return Ok(Expr::Block(stmts));
        }

        while !self.match_token(&Token::RBrace) {
            if self.is_at_end() {
                return Err(ParseError::UnexpectedEof);
            }
            stmts.push(self.parse_stmt()?);
            // セミコロンは任意
            let _ = self.match_token(&Token::Semicolon);
        }

        Ok(Expr::Block(stmts))
    }

    /// If式のパース
    fn parse_if_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        self.advance(); // consume 'if'
        let cond = self.parse_expr()?;

        if self.peek() != Some(&Token::LBrace) {
            return Err(ParseError::UnexpectedToken {
                expected: "'{'".to_string(),
                found: format!("{:?}", self.peek()),
            });
        }
        let then_block = self.parse_block_expr()?;

        let else_block = if self.match_token(&Token::Else) {
            Some(Box::new(self.parse_else_branch()?))
        } else {
            None
        };

        Ok(Expr::If {
            cond: Box::new(cond),
            then_block: Box::new(then_block),
            else_block,
        })
    }

    fn parse_else_branch(&mut self) -> Result<Expr<'static>, ParseError> {
        if self.peek() == Some(&Token::If) {
            self.parse_if_expr()
        } else if self.peek() == Some(&Token::LBrace) {
            self.parse_block_expr()
        } else {
            Err(ParseError::UnexpectedToken {
                expected: "'{' or 'if'".to_string(),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    /// For式のパース
    fn parse_for_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        self.advance(); // consume 'for'

        // パラメータ名
        let param = if let Some(Token::Ident(name)) = self.peek().cloned() {
            self.advance();
            name
        } else {
            return Err(ParseError::UnexpectedToken {
                expected: "identifier".to_string(),
                found: format!("{:?}", self.peek()),
            });
        };

        // 'in'
        if !self.match_token(&Token::In) {
            return Err(ParseError::UnexpectedToken {
                expected: "'in'".to_string(),
                found: format!("{:?}", self.peek()),
            });
        }

        // イテラブル（配列など）
        let iterable = self.parse_expr()?;

        // 本体ブロック
        if self.peek() != Some(&Token::LBrace) {
            return Err(ParseError::UnexpectedToken {
                expected: "'{'".to_string(),
                found: format!("{:?}", self.peek()),
            });
        }
        let body = self.parse_block_expr()?;

        Ok(Expr::For {
            param,
            iterable: Box::new(iterable),
            body: Box::new(body),
        })
    }

    /// 基本式（リテラル、識別子、括弧、クロージャ、制御構文）
    fn parse_primary(&mut self) -> Result<Expr<'static>, ParseError> {
        match self.peek().cloned() {
            // If / For
            Some(Token::If) => self.parse_if_expr(),
            Some(Token::For) => self.parse_for_expr(),

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
            Some(Token::LBracket) => self.parse_array_literal(),

            // 波括弧: マップかブロックかを判定
            Some(Token::LBrace) => self.parse_brace_expr(),

            // クロージャ: |e| expr
            Some(Token::Pipe) => self.parse_closure(),

            Some(token) => Err(ParseError::UnexpectedToken {
                expected: "expression".to_string(),
                found: format!("{:?}", token),
            }),

            None => Err(ParseError::UnexpectedEof),
        }
    }

    /// 配列リテラル: [expr, expr, ...]
    fn parse_array_literal(&mut self) -> Result<Expr<'static>, ParseError> {
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

    /// 波括弧式: マップリテラルまたはブロック式
    fn parse_brace_expr(&mut self) -> Result<Expr<'static>, ParseError> {
        // Heuristic: look ahead for `ident`/`string` followed by `:` to detect map
        if self.peek_next().map_or(false, |t| {
            matches!(t, Token::Ident(_) | Token::StringLit(_))
        }) && self
            .tokens
            .get(self.pos + 2)
            .map_or(false, |t| matches!(t, Token::Colon))
        {
            self.parse_map_literal()
        } else {
            // parse as block
            self.parse_block_expr()
        }
    }
}

// ============================================================================
// Convenience Function
// ============================================================================

/// 文字列から直接文をパース
pub fn parse(input: &str) -> Result<Stmt<'static>, ParseError> {
    let mut tokenizer = super::tokenizer::Tokenizer::new(input);
    let tokens = tokenizer.tokenize();
    let mut parser = ExprParser::new(tokens);
    parser.parse_stmt()
}

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
mod tests;
