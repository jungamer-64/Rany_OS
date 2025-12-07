// ============================================================================
// src/shell/exoshell/parser/error.rs - Parse Error Types
// ============================================================================

use alloc::string::String;
use core::fmt::{self, Display};

/// パースエラーの種類
#[derive(Debug, Clone)]
pub enum ParseError {
    /// 文字列リテラルが閉じられていない
    UnterminatedString {
        position: usize,
        start_quote: char,
    },
    /// 予期しないトークン
    UnexpectedToken {
        expected: &'static str,
        found: String,
        position: usize,
    },
    /// 未知の名前空間
    UnknownNamespace {
        name: String,
    },
    /// 未知のメソッド
    UnknownMethod {
        namespace: String,
        method: String,
    },
    /// 引数の型が不正
    InvalidArgumentType {
        method: String,
        expected: &'static str,
        found: String,
    },
    /// 引数が不足
    MissingArgument {
        method: String,
        argument: &'static str,
    },
    /// 不正な数値
    InvalidNumber {
        value: String,
    },
    /// 不正なIPアドレス
    InvalidIpAddress {
        value: String,
    },
    /// 空の入力
    EmptyInput,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnterminatedString { position, start_quote } => {
                write!(f, "文字列が閉じられていません (位置 {}, 開始引用符: '{}')", position, start_quote)
            }
            ParseError::UnexpectedToken { expected, found, position } => {
                write!(f, "予期しないトークン: '{}' (期待: {}, 位置: {})", found, expected, position)
            }
            ParseError::UnknownNamespace { name } => {
                write!(f, "未知の名前空間: '{}'\n有効な名前空間: fs, net, proc, cap, sys", name)
            }
            ParseError::UnknownMethod { namespace, method } => {
                write!(f, "未知のメソッド: '{}.{}()'", namespace, method)
            }
            ParseError::InvalidArgumentType { method, expected, found } => {
                write!(f, "{}() の引数型が不正: 期待 {}, 実際 {}", method, expected, found)
            }
            ParseError::MissingArgument { method, argument } => {
                write!(f, "{}() に引数 '{}' がありません", method, argument)
            }
            ParseError::InvalidNumber { value } => {
                write!(f, "不正な数値: '{}'", value)
            }
            ParseError::InvalidIpAddress { value } => {
                write!(f, "不正なIPアドレス: '{}' (形式: x.x.x.x)", value)
            }
            ParseError::EmptyInput => {
                write!(f, "入力が空です")
            }
        }
    }
}
