use super::*;

#[test_case]
fn test_simple_literal() {
    let expr = parse_expression("42").unwrap();
    assert!(matches!(expr, Expr::Literal(ExoValue::Int(42))));
}

#[test_case]
fn test_binary_comparison() {
    let expr = parse_expression("size > 1024").unwrap();
    match expr {
        Expr::Binary { left, op, right } => {
            assert!(matches!(*left, Expr::Ident(ref s) if s == "size"));
            assert_eq!(op, BinaryOp::Gt);
            assert!(matches!(*right, Expr::Literal(ExoValue::Int(1024))));
        }
        _ => panic!("Expected Binary expression"),
    }
}

#[test_case]
fn test_complex_and_or() {
    // a && b || c は (a && b) || c としてパースされる
    let expr = parse_expression("a && b || c").unwrap();
    match expr {
        Expr::Binary {
            left,
            op: BinaryOp::Or,
            right,
        } => {
            assert!(matches!(
                *left,
                Expr::Binary {
                    op: BinaryOp::And,
                    ..
                }
            ));
            assert!(matches!(*right, Expr::Ident(ref s) if s == "c"));
        }
        _ => panic!("Expected Or expression"),
    }
}

#[test_case]
fn test_grouped_expression() {
    // (a || b) && c
    let expr = parse_expression("(a || b) && c").unwrap();
    match expr {
        Expr::Binary {
            left,
            op: BinaryOp::And,
            ..
        } => {
            assert!(matches!(*left, Expr::Group(_)));
        }
        _ => panic!("Expected And expression with grouped left"),
    }
}

#[test_case]
fn test_parse_block_expression() {
    let expr = parse_expression("{ let x = 1; x }").unwrap();
    match expr {
        Expr::Block(stmts) => {
            assert_eq!(stmts.len(), 2);
        }
        _ => panic!("Expected Block expression"),
    }
}

#[test_case]
fn test_parse_if_expression() {
    let expr = parse_expression("if true { 1 } else { 2 }").unwrap();
    match expr {
        Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            assert!(matches!(*cond, Expr::Literal(ExoValue::Bool(true))));
            assert!(matches!(*then_block, Expr::Block(_)));
            assert!(else_block.is_some());
        }
        _ => panic!("Expected If expression"),
    }
}

#[test_case]
fn test_parse_for_expression() {
    let expr = parse_expression("for x in [1,2,3] { x }").unwrap();
    match expr {
        Expr::For {
            param,
            iterable,
            body,
        } => {
            assert_eq!(param, "x");
            assert!(matches!(*iterable, Expr::Array(_)));
            assert!(matches!(*body, Expr::Block(_)));
        }
        _ => panic!("Expected For expression"),
    }
}

#[test_case]
fn test_parse_break_statement() {
    let stmt = parse("break").unwrap();
    match stmt {
        Stmt::Break => {}
        _ => panic!("Expected Break statement"),
    }
}

#[test_case]
fn test_parse_continue_statement() {
    let stmt = parse("continue").unwrap();
    match stmt {
        Stmt::Continue => {}
        _ => panic!("Expected Continue statement"),
    }
}
