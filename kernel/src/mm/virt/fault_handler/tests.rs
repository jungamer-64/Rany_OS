use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_error_code_parsing() {
    // Write fault, user mode, not present
    let code = PageFaultErrorCode::from_bits(0b0110);
    assert!(code.is_write());
    assert!(code.is_user());
    assert!(!code.is_present());
    assert!(!code.is_instruction_fetch());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_stack_access_detection() {
    // Valid stack address
    let stack_addr = VirtAddr::new(USER_STACK_TOP - 0x1000);
    assert!(is_potential_stack_access(stack_addr, stack_addr));

    // Below stack bottom
    let below = VirtAddr::new(USER_STACK_BOTTOM - 0x1000);
    assert!(!is_potential_stack_access(below, stack_addr));
}
