use super::*;

impl ExprParser {

    /// マップリテラル: { key: value, ... }
    pub(super) fn parse_map_literal(&mut self) -> Result<Expr<'static>, ParseError> {
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

    /// クロージャ: |param| expr
    pub(super) fn parse_closure(&mut self) -> Result<Expr<'static>, ParseError> {
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

    /// 引数リストをパース
    pub(super) fn parse_args(&mut self) -> Result<Vec<Expr<'static>>, ParseError> {
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
