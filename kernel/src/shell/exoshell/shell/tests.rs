use super::*;
use crate::security::CapabilitySet;
use crate::shell::exoshell::parser::parse_expression;
use crate::task::block_on;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_block_scoping() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::full());
    let expr = parse_expression("{ let x = 5; x }").unwrap();
    let val = block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(5));
    // x should not be visible after block
    assert!(shell.env.get("x").is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_if_expression_evaluation() {
    let mut shell = ExoShell::new();
    let expr = parse_expression("if true { 1 } else { 2 }").unwrap();
    let val = crate::task::block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(1));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_for_expression_evaluation() {
    let mut shell = ExoShell::new();
    let expr = parse_expression("for i in [1,2,3] { i }").unwrap();
    let val = crate::task::block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(3));
    assert!(shell.env.get("i").is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_else_if_chain() {
    let mut shell = ExoShell::new();
    let expr = parse_expression("if false { 1 } else if true { 2 } else { 3 }").unwrap();
    let val = crate::task::block_on(shell.evaluate_expr(&expr));
    assert_eq!(val, ExoValue::Int(2));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_break_in_loop() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("for i in [1,2,3] { if i == 2 { break } i }"));
    assert_eq!(val, ExoValue::Int(1));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_continue_in_loop() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("for i in [1,2,3] { if i == 2 { continue } i }"));
    assert_eq!(val, ExoValue::Int(3));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_break_outside_loop_error() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("break"));
    assert!(matches!(val, ExoValue::Error(_)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_cell_list_namespace_call_returns_array() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("cell.list()"));
    assert!(matches!(val, ExoValue::Array(_)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_legacy_cell_command_syntax_is_rejected() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("cell list"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("Unknown") || s.contains("Command not found")),
        _ => panic!("expected error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_cell_inspect_artifact_missing_file_returns_error() {
    let mut shell = ExoShell::new();
    let val = crate::task::block_on(shell.eval("cell.inspect_artifact(\"/no/such/file.cell\")"));
    assert!(matches!(val, ExoValue::Error(_)));
}
