// ============================================================================
// src/shell/exoshell/parser/mod.rs - Parser module exports
// ============================================================================

pub mod ast;
pub mod error;
pub mod eval;
pub mod expr_parser;
pub mod tokenizer;

pub use ast::{BinaryOp, Expr, UnaryOp};
pub use error::ParseError;
pub use eval::{EvalContext, eval_closure, eval_closure_as_bool, eval_expr};
pub use expr_parser::{ExprParser, parse_expression};
pub use tokenizer::{Token, Tokenizer};
