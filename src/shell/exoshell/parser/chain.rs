// ============================================================================
// src/shell/exoshell/parser/chain.rs - Method Chain Parser
// ============================================================================

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::tokenizer::Token;
use crate::shell::exoshell::types::ExoValue;

/// メソッド呼び出しの解析結果
#[derive(Debug, Clone)]
pub struct MethodCall {
    pub name: String,
    pub args: Vec<ExoValue>,
}

/// メソッドチェーンパーサ
pub struct ChainParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl ChainParser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos);
        self.pos += 1;
        token
    }

    /// メソッドチェーンを解析
    /// 例: "fs.entries('/').filter('size > 1024').first()"
    /// 戻り値: Vec<MethodCall>
    pub fn parse(&mut self) -> Vec<MethodCall> {
        let mut calls = Vec::new();
        
        while self.pos < self.tokens.len() {
            // 識別子を期待
            if let Some(Token::Ident(name)) = self.peek().cloned() {
                self.advance();
                
                let args = if self.peek() == Some(&Token::LParen) {
                    self.parse_args()
                } else {
                    Vec::new()
                };
                
                calls.push(MethodCall {
                    name,
                    args,
                });
                
                // ドットがあれば次のメソッドへ
                if self.peek() == Some(&Token::Dot) {
                    self.advance();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        calls
    }

    /// 引数リストを解析
    fn parse_args(&mut self) -> Vec<ExoValue> {
        let mut args = Vec::new();
        
        // '(' をスキップ
        if self.peek() == Some(&Token::LParen) {
            self.advance();
        }
        
        loop {
            match self.peek().cloned() {
                Some(Token::RParen) => {
                    self.advance();
                    break;
                }
                Some(Token::Comma) => {
                    self.advance();
                }
                Some(Token::StringLit(s)) => {
                    self.advance();
                    args.push(ExoValue::String(s));
                }
                Some(Token::Number(n)) => {
                    self.advance();
                    args.push(ExoValue::Int(n));
                }
                Some(Token::Float(f)) => {
                    self.advance();
                    args.push(ExoValue::Float(f));
                }
                Some(Token::Ident(s)) => {
                    self.advance();
                    // 演算子が続く場合は条件式として解釈
                    if let Some(Token::Operator(op)) = self.peek().cloned() {
                        self.advance();
                        if let Some(val) = self.advance().cloned() {
                            let rhs = match val {
                                Token::Number(n) => n.to_string(),
                                Token::Float(f) => f.to_string(),
                                Token::StringLit(s) => s,
                                _ => String::new(),
                            };
                            // 条件式を文字列として格納
                            args.push(ExoValue::String(alloc::format!("{} {} {}", s, op, rhs)));
                        }
                    } else {
                        args.push(ExoValue::String(s));
                    }
                }
                None => break,
                _ => {
                    self.advance();
                }
            }
        }
        
        args
    }
}
