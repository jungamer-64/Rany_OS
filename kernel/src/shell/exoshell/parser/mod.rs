// ============================================================================
// src/shell/exoshell/parser/mod.rs - Parser module exports
// ============================================================================

pub mod error;
pub mod tokenizer;
pub mod ast;
pub mod expr_parser;
pub mod eval;

pub use error::ParseError;
pub use tokenizer::{Token, Tokenizer};
pub use ast::{Expr, BinaryOp, UnaryOp};
pub use expr_parser::{ExprParser, parse_expression};
pub use eval::{EvalContext, eval_expr, eval_closure, eval_closure_as_bool};



