use super::*;
use crate::security::CapabilitySet;
use crate::security::capability::{CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_PTRACE};
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
    let mut shell = ExoShell::with_capabilities(CapabilitySet::full());
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
    let mut shell = ExoShell::with_capabilities(CapabilitySet::full());
    let val = crate::task::block_on(shell.eval("cell.inspect_artifact(\"/no/such/file.cell\")"));
    assert!(matches!(val, ExoValue::Error(_)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_driver_list_requires_cap_fowner() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("driver.list()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_FOWNER")),
        _ => panic!("expected CAP_FOWNER permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sys_cells_requires_cap_sys_ptrace() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("sys.cells()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_PTRACE")),
        _ => panic!("expected CAP_SYS_PTRACE permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sys_monitor_requires_cap_sys_admin() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("sys.monitor()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_ADMIN")),
        _ => panic!("expected CAP_SYS_ADMIN permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_cpu_lifecycle_operations_require_cap_sys_boot() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    for command in ["sys.cpu_online(1)", "sys.cpu_offline(1)"] {
        match block_on(shell.eval(command)) {
            ExoValue::Error(error) => assert!(error.contains("CAP_SYS_BOOT")),
            _ => panic!("expected CAP_SYS_BOOT permission error"),
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_cpu_lifecycle_capability_reaches_argument_validation() {
    let caps = CapabilitySet::with_permitted(CAP_SYS_BOOT);
    let mut shell = ExoShell::with_capabilities(caps);
    match block_on(shell.eval("sys.cpu_online(256)")) {
        ExoValue::Error(error) => {
            assert!(error.contains("between 0 and 255"));
            assert!(!error.contains("CAP_SYS_BOOT"));
        }
        _ => panic!("expected CPU id validation error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sys_thermal_requires_cap_sys_admin() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("sys.thermal()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_ADMIN")),
        _ => panic!("expected CAP_SYS_ADMIN permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sys_power_requires_cap_sys_admin() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("sys.power()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_ADMIN")),
        _ => panic!("expected CAP_SYS_ADMIN permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sys_monitor_with_cap_sys_admin_is_not_permission_denied() {
    let caps = CapabilitySet::with_permitted(CAP_SYS_ADMIN);
    let mut shell = ExoShell::with_capabilities(caps);
    let val = block_on(shell.eval("sys.monitor()"));
    if let ExoValue::Error(s) = val {
        assert!(
            !s.contains("CAP_SYS_ADMIN"),
            "CAP_SYS_ADMIN should allow sys.monitor"
        );
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_list_requires_cap_sys_ptrace() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("domain.list()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_PTRACE")),
        _ => panic!("expected CAP_SYS_PTRACE permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_info_allows_self_without_cap_sys_ptrace() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let self_id = crate::shell::runtime::current_domain_id();
    let cmd = alloc::format!("domain.info({})", self_id);
    let val = block_on(shell.eval(&cmd));

    match val {
        ExoValue::Domain(info) => assert_eq!(info.id, self_id),
        ExoValue::Error(s) => panic!("expected self domain info, got error: {}", s),
        _ => panic!("expected domain info for self"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_info_other_requires_cap_sys_ptrace() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let self_id = crate::shell::runtime::current_domain_id();
    let other_id = if self_id == 0 { 1 } else { 0 };
    let cmd = alloc::format!("domain.info({})", other_id);
    let val = block_on(shell.eval(&cmd));

    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_PTRACE")),
        _ => panic!("expected CAP_SYS_PTRACE permission error for other domain"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_observe_with_cap_sys_ptrace() {
    let caps = CapabilitySet::with_permitted(CAP_SYS_PTRACE);
    let mut shell = ExoShell::with_capabilities(caps);

    let list_val = block_on(shell.eval("domain.list()"));
    assert!(matches!(list_val, ExoValue::Array(_)));

    let self_id = crate::shell::runtime::current_domain_id();
    let other_id = if self_id == 0 { 1 } else { 0 };
    let cmd = alloc::format!("domain.info({})", other_id);
    let info_val = block_on(shell.eval(&cmd));

    if let ExoValue::Error(s) = info_val {
        assert!(
            !s.contains("CAP_SYS_PTRACE"),
            "CAP_SYS_PTRACE should allow observing other domains"
        );
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_net_interfaces_requires_cap_net_admin() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("net.interfaces()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_NET_ADMIN")),
        _ => panic!("expected CAP_NET_ADMIN permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_net_stats_requires_cap_net_admin() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("net.stats(0)"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_NET_ADMIN")),
        _ => panic!("expected CAP_NET_ADMIN permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_task_stats_requires_cap_sys_admin() {
    let mut shell = ExoShell::with_capabilities(CapabilitySet::empty());
    let val = block_on(shell.eval("task.stats()"));
    match val {
        ExoValue::Error(s) => assert!(s.contains("CAP_SYS_ADMIN")),
        _ => panic!("expected CAP_SYS_ADMIN permission error"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_task_stats_with_cap_sys_admin_is_not_permission_denied() {
    let caps = CapabilitySet::with_permitted(CAP_SYS_ADMIN);
    let mut shell = ExoShell::with_capabilities(caps);
    let val = block_on(shell.eval("task.stats()"));
    if let ExoValue::Error(s) = val {
        assert!(
            !s.contains("CAP_SYS_ADMIN"),
            "CAP_SYS_ADMIN should allow task.stats"
        );
    }
}
