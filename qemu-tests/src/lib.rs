#![cfg_attr(not(test), allow(dead_code))]

use qemu_runner::{RunConfig, run_fullboot};
use std::sync::{Mutex, OnceLock};

fn suite_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u8(key: &str, default: u8) -> u8 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(default)
}

fn base_config(profile: &str) -> RunConfig {
    let mut cfg = RunConfig::for_profile(profile);
    cfg.timeout_secs = env_u64("QEMU_TEST_TIMEOUT_SECS", 120);
    cfg.memory_mb = env_u64("QEMU_TEST_MEMORY_MB", 1024);
    cfg.smp = env_u8("QEMU_TEST_SMP", 2);
    cfg.cpu = std::env::var("QEMU_TEST_CPU").unwrap_or_else(|_| String::from("qemu64,+rdtscp"));
    cfg.case_filter = std::env::var("QEMU_TEST_CASE_FILTER").ok();
    cfg
}

fn run_required_profile(profile: &str) {
    let guard = suite_lock().lock().expect("qemu suite lock poisoned");
    let cfg = base_config(profile);
    let result = run_fullboot(cfg);
    drop(guard);

    match result {
        Ok(report) => {
            eprintln!(
                "required full-boot profile '{}' passed in {:?} (log: {})",
                report.profile,
                report.duration,
                report.log_path.display()
            );
        }
        Err(err) => panic!("required full-boot profile '{profile}' failed: {err}"),
    }
}

#[test]
fn fullboot_pr_required() {
    for profile in ["boot-smoke", "storage", "driver_cell"] {
        run_required_profile(profile);
    }
}

#[test]
#[ignore = "nightly-only full-boot expansion profile"]
fn fullboot_nightly_required() {
    run_required_profile("nightly-required");
}

#[test]
fn runner_normalize_exit_code() {
    assert_eq!(qemu_runner::normalize_qemu_exit_code(33), Some(0x10));
    assert_eq!(qemu_runner::normalize_qemu_exit_code(35), Some(0x11));
    assert_eq!(qemu_runner::normalize_qemu_exit_code(0), None);
}

#[test]
fn runner_workspace_root_exists() {
    let root = qemu_runner::workspace_root();
    assert!(root.exists());
    assert!(root.join("Cargo.toml").exists());
}
