// rustc ICE reproduction case
// Bug: https://github.com/rust-lang/rust/issues/146398
//
// This triggers an ICE when rustc tries to render an error diagnostic
// that spans multiple files with certain character positions.

#![allow(dead_code)]

#[macro_use]
mod macros;

// Invoke the macro - this creates an unresolved import error
// The error diagnostic spans both macros.rs (definition) and this file (invocation)
impl_handler!("test_handler" => nonexistent_module);

fn main() {}
