use super::*;


/// Requested capability descriptor used by `spawn_with_caps`.
#[derive(Debug, Clone, Copy)]
pub struct RequestedCap {
    pub cap: u64,
    pub expires: Option<u64>,
    pub delegatable: bool,
}

/// Check whether `parent_id` is allowed to grant `cap`.
pub(crate) fn validate_cap_request(parent_id: u64, cap: u64) -> bool {
    let mgr = crate::security::capability::manager();
    if mgr.has_capability(parent_id, crate::security::capability::CAP_SYS_ADMIN) {
        return true;
    }
    let caller_caps = mgr.get_capabilities(parent_id);
    if caller_caps.is_permitted(cap) {
        return true;
    }
    let grants = mgr.list_grants(parent_id);
    grants.iter().any(|t| t.cap == cap && t.delegatable)
}

/// Apply capability grants to `child_id`, rolling back on failure.
pub(crate) fn apply_cap_grants(
    parent_id: u64,
    child_id: u64,
    requested: &[RequestedCap],
) -> Result<Vec<u64>, ProcessError> {
    let mut created_tokens: Vec<u64> = Vec::new();
    for r in requested.iter() {
        match crate::security::capability::manager().grant_capability_with_opts(
            parent_id,
            child_id,
            r.cap,
            r.expires,
            r.delegatable,
        ) {
            Ok(token_id) => created_tokens.push(token_id),
            Err(_e) => {
                rollback_grants(parent_id, child_id, &created_tokens);
                return Err(ProcessError::PermissionDenied);
            }
        }
    }
    // Mark granted tokens as in-flight for the lifetime of the process.
    for t in &created_tokens {
        let _ = crate::security::capability::manager().increment_in_flight(*t);
    }
    Ok(created_tokens)
}

/// Revoke previously created grants and clear the child's capability set.
pub(crate) fn rollback_grants(parent_id: u64, child_id: u64, tokens: &[u64]) {
    for t in tokens {
        let _ = crate::security::capability::manager().revoke_grant(parent_id, *t, false);
    }
    crate::security::capability::manager().set_capabilities(child_id, crate::security::capability::CapabilitySet::empty());
}

/// Spawn a new process with requested capabilities applied atomically.
///
/// Validation: parent (current process) must be allowed to grant each requested
/// capability (either CAP_SYS_ADMIN, have it in permitted, or have a delegatable
/// grant). Returns the child PID and the list of created grant token ids.
pub fn spawn_with_caps(
    name: &str,
    requested: &[RequestedCap],
) -> Result<(ProcessId, Vec<u64>), ProcessError> {
    let parent = get_current_process();
    let parent_id = parent.as_u64();

    // Validate each requested cap
    for r in requested.iter() {
        if !validate_cap_request(parent_id, r.cap) {
            return Err(ProcessError::PermissionDenied);
        }
    }

    // Create the child process with explicit parent id
    let child = PROCESS_MANAGER.create(parent, name)?;

    // Apply grants
    let created_tokens = apply_cap_grants(parent_id, child.as_u64(), requested)?;

    Ok((child, created_tokens))
}

#[cfg(test)]
mod tests;

/// exit() 相当
pub fn exit(code: ExitCode) -> ! {
    let pid = get_current_process();
    let _ = PROCESS_MANAGER.exit(pid, code);
    loop {
        core::hint::spin_loop();
    }
}

/// waitpid() 相当
pub fn waitpid(pid: Option<ProcessId>) -> Result<(ProcessId, ExitCode), ProcessError> {
    let ppid = get_current_process();
    PROCESS_MANAGER.wait(ppid, pid)
}

/// getpid() 相当
pub fn getpid() -> ProcessId {
    get_current_process()
}

/// getppid() 相当
pub fn getppid() -> ProcessId {
    let pid = get_current_process();
    if let Some(process) = PROCESS_MANAGER.get(pid) {
        process.read().ppid
    } else {
        ProcessId::KERNEL
    }
}

/// getuid() 相当
pub fn getuid() -> UserId {
    let pid = get_current_process();
    if let Some(process) = PROCESS_MANAGER.get(pid) {
        process.read().credentials.uid
    } else {
        UserId::ROOT
    }
}

/// getgid() 相当
pub fn getgid() -> GroupId {
    let pid = get_current_process();
    if let Some(process) = PROCESS_MANAGER.get(pid) {
        process.read().credentials.gid
    } else {
        GroupId::ROOT
    }
}

/// 現在プロセスの memcg ID を取得
pub fn get_current_process_memcg_id() -> MemcgId {
    let pid = get_current_process();
    if let Some(process) = PROCESS_MANAGER.get(pid) {
        process.read().memcg_id
    } else {
        MemcgId::ROOT
    }
}

/// setpriority() 相当
pub fn setpriority(pid: ProcessId, priority: Priority) -> Result<(), ProcessError> {
    let process = PROCESS_MANAGER.get(pid).ok_or(ProcessError::NotFound)?;
    let mut p = process.write();
    p.priority = priority;
    Ok(())
}

/// getpriority() 相当
pub fn getpriority(pid: ProcessId) -> Result<Priority, ProcessError> {
    let process = PROCESS_MANAGER.get(pid).ok_or(ProcessError::NotFound)?;
    let p = process.read();
    Ok(p.priority)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test_case]
    fn test_process_creation() {
        let pid = PROCESS_MANAGER
            .create(ProcessId::INIT, "test_process")
            .unwrap();
        assert!(pid.as_u64() > 1);

        let process = PROCESS_MANAGER.get(pid).unwrap();
        let p = process.read();
        assert_eq!(p.name, "test_process");
        assert_eq!(p.state, ProcessState::Creating);
    }

    #[test_case]
    fn test_process_exit() {
        let pid = PROCESS_MANAGER
            .create(ProcessId::INIT, "exit_test")
            .unwrap();

        PROCESS_MANAGER
            .set_state(pid, ProcessState::Running)
            .unwrap();
        PROCESS_MANAGER.exit(pid, ExitCode::SUCCESS).unwrap();

        let process = PROCESS_MANAGER.get(pid).unwrap();
        let p = process.read();
        assert_eq!(p.state, ProcessState::Zombie);
        assert_eq!(p.exit_code, Some(ExitCode::SUCCESS));
    }
}

