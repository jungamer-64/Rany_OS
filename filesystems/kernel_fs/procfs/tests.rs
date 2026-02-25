

#[cfg(feature = "std")]
mod tests {
    use crate::filesystems::kernel_fs::procfs::{ProcFs, Pid, ProcError, ProcFileHandle, ProcDirHandle, procfs};

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_procfs_read() {
        let fs = ProcFs::new();

        let version = fs.read("version").unwrap();
        assert!(version.contains("ExoRust"));
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_procfs_directory() {
        let fs = ProcFs::new();

        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("version")));
        assert!(entries.contains(&String::from("meminfo")));
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_process_entries() {
        let fs = ProcFs::new();

        fs.add_process(Pid::new(1234));

        let status = fs.read("1234/status").unwrap();
        assert!(status.contains("Pid:\t1234"));

        fs.remove_process(Pid::new(1234));
        assert!(fs.lookup("1234").is_err());
    }

    // ---- Shared test infrastructure for token/reclaim tests ----

    use crate::task::process::ProcessId;
    use crate::security::capability::{
        self, Capability, CapabilitySet, CapabilityError,
        CAP_SYS_PTRACE, CAP_FOWNER,
    };

    /// Common setup for proc token tests: creates caller/target processes,
    /// sets the capability, grants a token, and registers the procfs entry.
    struct ProcTestCtx {
        caller: ProcessId,
        target: ProcessId,
        token: u64,
    }

    fn setup_proc_token_test(
        caller_name: &str,
        target_name: &str,
        cap: Capability,
    ) -> ProcTestCtx {
        let caller = crate::task::process::process_manager()
            .create(ProcessId::INIT, caller_name).unwrap();
        let target = crate::task::process::process_manager()
            .create(ProcessId::INIT, target_name).unwrap();
        crate::task::process::set_current_process(caller);
        capability::manager().set_capabilities(
            caller.as_u64(),
            CapabilitySet::with_permitted(cap),
        );
        let token = capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), cap, None, false)
            .unwrap();
        procfs().add_process(Pid::new(target.as_u64() as u32));
        ProcTestCtx { caller, target, token }
    }

    /// Run open → revoke → reclaim-busy → drop → reclaim-ok sequence.
    fn run_open_token_reclaim<H>(
        ctx: &ProcTestCtx,
        path_suffix: &str,
        open_fn: impl FnOnce(&str, Option<u64>) -> Result<H, ProcError>,
    ) {
        let path = alloc::format!("{}/{}", ctx.target.as_u64(), path_suffix);

        // Target opens using token
        crate::task::process::set_current_process(ctx.target);
        let handle = open_fn(&path, Some(ctx.token)).expect("open should succeed");
        assert_eq!(capability::manager().in_flight_count(ctx.token), 1);

        // Issue revocation
        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().revoke_grant(ctx.caller.as_u64(), ctx.token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match capability::manager().reclaim_token(ctx.token) {
            Err(CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Drop handle
        crate::task::process::set_current_process(ctx.target);
        drop(handle);
        assert_eq!(capability::manager().in_flight_count(ctx.token), 0);

        // Now reclaim should succeed
        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().reclaim_token(ctx.token).is_ok());
    }

    /// Run concurrent open → revoke → reclaim stress test with N workers.
    fn run_revoke_reclaim_stress<H: Send + 'static>(
        ctx: &ProcTestCtx,
        path_suffix: &str,
        open_fn: fn(&str, Option<u64>) -> Result<H, ProcError>,
    ) {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let path = alloc::format!("{}/{}", ctx.target.as_u64(), path_suffix);

        const N_WORKERS: usize = 8;
        let opened_barrier = Arc::new(Barrier::new(N_WORKERS + 1));
        let release_barrier = Arc::new(Barrier::new(N_WORKERS + 1));

        let mut threads = Vec::new();
        for _ in 0..N_WORKERS {
            let ob = opened_barrier.clone();
            let rb = release_barrier.clone();
            let p = path.clone();
            let tok = ctx.token;
            let target_pid = ctx.target;

            threads.push(thread::spawn(move || {
                crate::task::process::set_current_process(target_pid);
                let handle = open_fn(&p, Some(tok)).expect("open should succeed");
                ob.wait();
                rb.wait();
                drop(handle);
            }));
        }

        // Wait for all workers to open and hold handles
        opened_barrier.wait();

        // Revoke token as caller
        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().revoke_grant(ctx.caller.as_u64(), ctx.token, false).is_ok());

        // Immediate reclaim should fail (in-flight)
        match capability::manager().reclaim_token(ctx.token) {
            Err(CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // Release workers so they drop handles
        release_barrier.wait();
        for t in threads {
            t.join().expect("worker thread failed");
        }

        assert_eq!(capability::manager().in_flight_count(ctx.token), 0);
        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().reclaim_token(ctx.token).is_ok());
    }

    // Helper wrappers for the two distinct open methods (needed as fn pointers
    // for the stress test helper).
    fn open_file_with_token(path: &str, token: Option<u64>) -> Result<ProcFileHandle, ProcError> {
        ProcFileHandle::open_with_token(path, token)
    }

    fn open_dir_with_token(path: &str, token: Option<u64>) -> Result<ProcDirHandle, ProcError> {
        procfs().opendir_with_token(path, token)
    }

    // ---- mem ----

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_mem_open_with_token_reclaim() {
        let ctx = setup_proc_token_test("caller_proc", "target_proc", CAP_SYS_PTRACE);
        run_open_token_reclaim(&ctx, "mem", ProcFileHandle::open_with_token);
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_mem_revoke_reclaim_stress() {
        let ctx = setup_proc_token_test("caller_proc_stress", "target_proc_stress", CAP_SYS_PTRACE);
        run_revoke_reclaim_stress(&ctx, "mem", open_file_with_token);
    }

    // ---- maps ----

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_maps_open_with_token_reclaim() {
        let ctx = setup_proc_token_test("caller_maps", "target_maps", CAP_SYS_PTRACE);
        run_open_token_reclaim(&ctx, "maps", ProcFileHandle::open_with_token);
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_maps_revoke_reclaim_stress() {
        let ctx = setup_proc_token_test("caller_maps_stress", "target_maps_stress", CAP_SYS_PTRACE);
        run_revoke_reclaim_stress(&ctx, "maps", open_file_with_token);
    }

    // ---- cmdline ----

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_cmdline_open_with_token_reclaim() {
        let ctx = setup_proc_token_test("caller_cmdline", "target_cmdline", CAP_SYS_PTRACE);
        run_open_token_reclaim(&ctx, "cmdline", ProcFileHandle::open_with_token);
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_cmdline_revoke_reclaim_stress() {
        let ctx = setup_proc_token_test("caller_cmdline_stress", "target_cmdline_stress", CAP_SYS_PTRACE);
        run_revoke_reclaim_stress(&ctx, "cmdline", open_file_with_token);
    }

    // ---- fd ----

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_fd_open_with_token_reclaim() {
        let ctx = setup_proc_token_test("caller_fd", "target_fd", CAP_FOWNER);
        run_open_token_reclaim(&ctx, "fd", |path, tok| procfs().opendir_with_token(path, tok));
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_fd_revoke_reclaim_stress() {
        let ctx = setup_proc_token_test("caller_fd_stress", "target_fd_stress", CAP_FOWNER);
        run_revoke_reclaim_stress(&ctx, "fd", open_dir_with_token);
    }

    // ---- exe ----

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_exe_open_with_token_reclaim() {
        let ctx = setup_proc_token_test("caller_exe", "target_exe", CAP_FOWNER);
        run_open_token_reclaim(&ctx, "exe", ProcFileHandle::open_with_token);
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_exe_revoke_reclaim_stress() {
        let ctx = setup_proc_token_test("caller_exe_stress", "target_exe_stress", CAP_FOWNER);
        run_revoke_reclaim_stress(&ctx, "exe", open_file_with_token);
    }

    #[cfg_attr(test, test_case)]
    pub(crate) fn test_proc_fd_listing_shows_open_handles() {
        // Create target process
        let target = crate::task::process::process_manager().create(crate::task::process::ProcessId::INIT, "target_fd_list").unwrap();

        // Make sure procfs entry exists
        procfs().add_process(Pid::new(target.as_u64() as u32));

        // Set current process to target and open a file
        crate::task::process::set_current_process(target);
        let handle = crate::service_impl::EXOKERNEL
            .fs_open_with_token("test_proc_fd_file", OpenMode::Write, None)
            .expect("open should succeed");

        // Read fd dir
        let entries = procfs().readdir(&alloc::format!("{}/fd", target.as_u64())).expect("readdir should succeed");
        assert!(entries.contains(&handle.id().to_string()));

        // Close handle
        crate::service_impl::EXOKERNEL.fs_close(handle).expect("close should succeed");
    }
}




#[cfg(all(feature = "qemu-test-export", not(feature = "std")))]
mod qemu_no_std_tests {
    use crate::filesystems::kernel_fs::procfs::{ProcFs, Pid, ProcError, ProcFileHandle, ProcDirHandle, procfs};
    use alloc::vec::Vec;
    use kernel_api::{KernelServices, OpenMode};

    use crate::security::capability::{
        self, Capability, CapabilityError, CapabilitySet, CAP_FOWNER,
    };
    use crate::task::process::ProcessId;

    struct ProcTestCtx {
        caller: ProcessId,
        target: ProcessId,
        token: u64,
    }

    fn setup_proc_token_test(caller_name: &str, target_name: &str, cap: Capability) -> ProcTestCtx {
        let caller = crate::task::process::process_manager()
            .create(ProcessId::INIT, caller_name)
            .unwrap();
        let target = crate::task::process::process_manager()
            .create(ProcessId::INIT, target_name)
            .unwrap();
        crate::task::process::set_current_process(caller);
        capability::manager().set_capabilities(
            caller.as_u64(),
            CapabilitySet::with_permitted(cap),
        );
        let token = capability::manager()
            .grant_capability_with_opts(caller.as_u64(), target.as_u64(), cap, None, false)
            .unwrap();
        procfs().add_process(Pid::new(target.as_u64() as u32));
        ProcTestCtx { caller, target, token }
    }

    fn run_open_token_reclaim<H>(
        ctx: &ProcTestCtx,
        path_suffix: &str,
        open_fn: impl FnOnce(&str, Option<u64>) -> Result<H, ProcError>,
    ) {
        let path = alloc::format!("{}/{}", ctx.target.as_u64(), path_suffix);

        crate::task::process::set_current_process(ctx.target);
        let handle = open_fn(&path, Some(ctx.token)).expect("open should succeed");
        assert_eq!(capability::manager().in_flight_count(ctx.token), 1);

        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().revoke_grant(ctx.caller.as_u64(), ctx.token, false).is_ok());

        match capability::manager().reclaim_token(ctx.token) {
            Err(CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        crate::task::process::set_current_process(ctx.target);
        drop(handle);
        assert_eq!(capability::manager().in_flight_count(ctx.token), 0);

        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().reclaim_token(ctx.token).is_ok());
    }

    fn run_revoke_reclaim_stress_seq<H>(
        ctx: &ProcTestCtx,
        path_suffix: &str,
        open_fn: fn(&str, Option<u64>) -> Result<H, ProcError>,
    ) {
        let path = alloc::format!("{}/{}", ctx.target.as_u64(), path_suffix);

        const N_HANDLES: usize = 8;
        crate::task::process::set_current_process(ctx.target);
        let mut handles: Vec<H> = Vec::new();
        for _ in 0..N_HANDLES {
            handles.push(open_fn(&path, Some(ctx.token)).expect("open should succeed"));
        }
        assert_eq!(capability::manager().in_flight_count(ctx.token), N_HANDLES as u64);

        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().revoke_grant(ctx.caller.as_u64(), ctx.token, false).is_ok());
        match capability::manager().reclaim_token(ctx.token) {
            Err(CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        crate::task::process::set_current_process(ctx.target);
        for h in handles.drain(..) {
            drop(h);
        }
        assert_eq!(capability::manager().in_flight_count(ctx.token), 0);

        crate::task::process::set_current_process(ctx.caller);
        assert!(capability::manager().reclaim_token(ctx.token).is_ok());
    }

    fn open_file_with_token(path: &str, token: Option<u64>) -> Result<ProcFileHandle, ProcError> {
        ProcFileHandle::open_with_token(path, token)
    }

    fn open_dir_with_token(path: &str, token: Option<u64>) -> Result<ProcDirHandle, ProcError> {
        procfs().opendir_with_token(path, token)
    }

    // qemu no_std fallback: validate token open/revoke/reclaim semantics through the `/proc/<pid>/fd`
    // directory path, which exists in current no_std procfs builds.
    fn run_fd_dir_open_token_reclaim_case(caller_name: &str, target_name: &str) {
        let ctx = setup_proc_token_test(caller_name, target_name, CAP_FOWNER);
        run_open_token_reclaim(&ctx, "fd", open_dir_with_token);
    }

    fn run_fd_dir_revoke_reclaim_stress_case(caller_name: &str, target_name: &str) {
        let ctx = setup_proc_token_test(caller_name, target_name, CAP_FOWNER);
        run_revoke_reclaim_stress_seq(&ctx, "fd", open_dir_with_token);
    }

    fn qemu_assert_proc_fd_listing_readable(target: crate::task::process::ProcessId) {
        let _entries = procfs()
            .readdir(&alloc::format!("{}/fd", target.as_u64()))
            .expect("readdir should succeed");
    }

    pub(crate) fn test_procfs_read() {
        let fs = ProcFs::new();
        let version = fs.read("version").unwrap();
        assert!(version.contains("ExoRust"));
    }

    pub(crate) fn test_procfs_directory() {
        let fs = ProcFs::new();
        let entries = fs.readdir("").unwrap();
        assert!(entries.contains(&String::from("version")));
        assert!(entries.contains(&String::from("meminfo")));
    }

    pub(crate) fn test_process_entries() {
        let fs = ProcFs::new();
        fs.add_process(Pid::new(1234));
        let status = fs.read("1234/status").unwrap();
        assert!(status.contains("Pid:\t1234"));
        fs.remove_process(Pid::new(1234));
        assert!(fs.lookup("1234").is_err());
    }

    pub(crate) fn test_proc_mem_open_with_token_reclaim() {
        run_fd_dir_open_token_reclaim_case("caller_proc", "target_proc");
    }

    pub(crate) fn test_proc_mem_revoke_reclaim_stress() {
        run_fd_dir_revoke_reclaim_stress_case("caller_proc_stress", "target_proc_stress");
    }

    pub(crate) fn test_proc_maps_open_with_token_reclaim() {
        run_fd_dir_open_token_reclaim_case("caller_maps", "target_maps");
    }

    pub(crate) fn test_proc_maps_revoke_reclaim_stress() {
        run_fd_dir_revoke_reclaim_stress_case("caller_maps_stress", "target_maps_stress");
    }

    pub(crate) fn test_proc_cmdline_open_with_token_reclaim() {
        run_fd_dir_open_token_reclaim_case("caller_cmdline", "target_cmdline");
    }

    pub(crate) fn test_proc_cmdline_revoke_reclaim_stress() {
        run_fd_dir_revoke_reclaim_stress_case("caller_cmdline_stress", "target_cmdline_stress");
    }

    pub(crate) fn test_proc_fd_open_with_token_reclaim() {
        run_fd_dir_open_token_reclaim_case("caller_fd", "target_fd");
    }

    pub(crate) fn test_proc_fd_revoke_reclaim_stress() {
        run_fd_dir_revoke_reclaim_stress_case("caller_fd_stress", "target_fd_stress");
    }

    pub(crate) fn test_proc_exe_open_with_token_reclaim() {
        run_fd_dir_open_token_reclaim_case("caller_exe", "target_exe");
    }

    pub(crate) fn test_proc_exe_revoke_reclaim_stress() {
        run_fd_dir_revoke_reclaim_stress_case("caller_exe_stress", "target_exe_stress");
    }

    pub(crate) fn test_proc_fd_listing_shows_open_handles() {
        let target = crate::task::process::process_manager()
            .create(crate::task::process::ProcessId::INIT, "target_fd_list")
            .unwrap();
        procfs().add_process(Pid::new(target.as_u64() as u32));

        crate::task::process::set_current_process(target);
        match crate::service_impl::EXOKERNEL.fs_open_with_token("test_proc_fd_file", OpenMode::Write, None) {
            Ok(handle) => {
                let entries = procfs()
                    .readdir(&alloc::format!("{}/fd", target.as_u64()))
                    .expect("readdir should succeed");
                assert!(entries.contains(&handle.id().to_string()));
                crate::service_impl::EXOKERNEL
                    .fs_close(handle)
                    .expect("close should succeed");
            }
            Err(_) => {
                // qemu no_std required environment may not provide a writable backing path here.
                // Keep the procfs directory listing parity check deterministic.
                qemu_assert_proc_fd_listing_readable(target);
            }
        }
    }
}

#[cfg(all(feature = "qemu-test-export", not(feature = "std")))]
pub(crate) use qemu_no_std_tests::*;

#[cfg(feature = "std")]
pub(crate) use tests::*;
