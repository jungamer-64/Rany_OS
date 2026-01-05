// ============================================================================
// src/shell/exoshell/parser/mod.rs - Parser module exports
// ============================================================================

pub mod ast;
pub mod error;
pub mod eval;
pub mod expr_parser;
pub mod tokenizer;

pub use ast::{BinaryOp, Expr};
pub use error::ParseError;
pub use eval::eval_closure_as_bool;
pub use expr_parser::parse_expression;
