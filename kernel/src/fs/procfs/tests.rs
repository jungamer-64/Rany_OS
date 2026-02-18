use super::*;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test_case]
    pub(super) fn test_procfs_read() {
        let fs = ProcFs::new();

        let version = fs.read("version").unwrap();
        assert!(version.contains("ExoRust"));
    }

    #[test_case]
    pub(super) fn test_procfs_directory() {
        let fs = ProcFs::new();

        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("version")));
        assert!(entries.contains(&String::from("meminfo")));
    }

    #[test_case]
    pub(super) fn test_process_entries() {
        let fs = ProcFs::new();

        fs.add_process(Pid::new(1234));

        let status = fs.read("1234/status").unwrap();
        assert!(status.contains("Pid:\t1234"));

        fs.remove_process(Pid::new(1234));
        assert!(fs.lookup("1234").is_err());
    }

    #[test_case]
    pub(super) fn test_proc_mem_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_proc").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_proc").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/mem", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_mem_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_proc_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_proc_stress").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/mem", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_maps_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_maps").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_maps").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/maps", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_maps_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_maps_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_maps_stress").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/maps", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_cmdline_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_cmdline").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_cmdline").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/cmdline", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_cmdline_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_cmdline_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_cmdline_stress").unwrap();

        // Caller gets permission to grant CAP_SYS_PTRACE
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_SYS_PTRACE));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_SYS_PTRACE, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/cmdline", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_fd_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_fd").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens fd directory using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/fd", target.as_u64());
        let handle = procfs().opendir_with_token(&path, Some(token)).expect("opendir should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_fd_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_fd_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd_stress").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/fd", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = procfs().opendir_with_token(&path, Some(tok)).expect("opendir should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_exe_open_with_token_reclaim() {
        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_exe").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_exe").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Target opens exe using token
        crate::task::process::set_current_process(target);
        let path = alloc::format!("{}/exe", target.as_u64());
        let handle = ProcFileHandle::open_with_token(&path, Some(token)).expect("open should succeed");
        assert_eq!(crate::security::capability::manager().in_flight_count(token), 1);

        // Issue revocation
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(target);
        drop(handle);

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_exe_revoke_reclaim_stress() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Setup caller and target domains
        let caller = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "caller_exe_stress").unwrap();
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_exe_stress").unwrap();

        // Caller gets permission to grant CAP_FOWNER
        crate::task::process::set_current_process(caller);
        crate::security::capability::manager().set_capabilities(caller.as_u64(), crate::security::capability::CapabilitySet::with_permitted(crate::security::capability::CAP_FOWNER));

        // Grant token to target
        let token = crate::security::capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), crate::security::capability::CAP_FOWNER, None, false)
            .unwrap();

        // Ensure procfs has an entry for the target
        procfs().add_process(Pid::new(target.as_u64() as u32));
        let path = alloc::format!("{}/exe", target.as_u64());

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let opened_barrier = opened_barrier.clone();
            let release_barrier = release_barrier.clone();
            let path = path.clone();
            let tok = token;
            let target_pid = target;

            threads.push(thread::spawn(move || {
                // Set thread's current process to target
                crate::task::process::set_current_process(target_pid);

                // Open and hold handle
                let handle = ProcFileHandle::open_with_token(&path, Some(tok)).expect("open should succeed");

                // Signal that this thread has opened and is holding the handle
                opened_barrier.wait();

                // Wait until main thread tells us to release
                release_barrier.wait();

                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().revoke_grant(caller.as_u64(), token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match crate::security::capability::manager().reclaim_token(token) {
            Err(crate::security::capability::CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();

        // Join workers
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(crate::security::capability::manager().in_flight_count(token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(caller);
        assert!(crate::security::capability::manager().reclaim_token(token).is_ok());
    }

    #[test_case]
    pub(super) fn test_proc_fd_listing_shows_open_handles() {
        // Create target process
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd_list").unwrap();

        // Make sure procfs entry exists
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Set current process to target and open a file
        crate::task::process::set_current_process(target);
        let handle = crate::service_impl::EXOKERNEL
            .fs_open_with_token("test_proc_fd_file", crate::OpenMode::Write, None)
            .expect("open should succeed");

        // Read fd dir
        let entries = procfs().readdir(&alloc::format!("{}/fd", target.as_u64())).expect("readdir should succeed");
        assert!(entries.contains(&handle.id().to_string()));

        // Close handle
        crate::service_impl::EXOKERNEL.fs_close(handle).expect("close should succeed");
    }
}


