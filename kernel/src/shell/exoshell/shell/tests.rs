use super::*;
use crate::shell::exoshell::parser::parse_expression;
use crate::task::block_on;
use crate::security::CapabilitySet;

#[test_case]
fn test_block_scoping() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::full());
    let expr = parse_expression("{ let x = 5; x }").unwrap();
    let val = block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(5));
    // x should not be visible after block
    assert!(shell.env.get("x").is_none());
}

#[test_case]
fn test_if_expression_evaluation() {
    let mut shell = ExoShell::new();
    let expr = parse_expression("if true { 1 } else { 2 }").unwrap();
    let val = crate::task::block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(1));
}

#[test_case]
fn test_for_expression_evaluation() {
    let mut shell = ExoShell::new();
    let expr = parse_expression("for i in [1,2,3] { i }").unwrap();
    let val = crate::task::block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(3));
    assert!(shell.env.get("i").is_none());
}

#[test_case]
fn test_else_if_chain() {
    let mut shell = ExoShell::new();
    let expr = parse_expression("if false { 1 } else if true { 2 } else { 3 }").unwrap();
    let val = crate::task::block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(2));
}

#[test_case]
fn test_break_in_loop() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("for i in [1,2,3] { if i == 2 { break } i }"));
    assert_eq!(val, ExoValue::Int(1));
}

#[test_case]
fn test_continue_in_loop() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("for i in [1,2,3] { if i == 2 { continue } i }"));
    assert_eq!(val, ExoValue::Int(3));
}

#[test_case]
fn test_break_outside_loop_error() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("break"));
    assert!(matches!(val, ExoValue::Error(_)));
}
