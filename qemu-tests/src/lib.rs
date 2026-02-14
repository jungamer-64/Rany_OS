#![cfg_attr(not(test), allow(dead_code))]

use qemu_runner::{run_suite, RunConfig};
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

fn base_config(suite: &str) -> RunConfig {
    let mut cfg = RunConfig::for_suite(suite);
    cfg.timeout_secs = env_u64("QEMU_TEST_TIMEOUT_SECS", 60);
    cfg.memory_mb = env_u64("QEMU_TEST_MEMORY_MB", 512);
    cfg.smp = env_u8("QEMU_TEST_SMP", 1);
    cfg.cpu = std::env::var("QEMU_TEST_CPU").unwrap_or_else(|_| String::from("qemu64,+rdtscp"));
    cfg
}

fn run_required(suite: &str) {
    let guard = suite_lock().lock().expect("qemu suite lock poisoned");
    let cfg = base_config(suite);
    let result = run_suite(cfg);
    drop(guard);
    match result {
        Ok(report) => {
            eprintln!(
                "required suite '{}' passed in {:?} (log: {})",
                report.suite,
                report.duration,
                report.log_path.display()
            );
        }
        Err(err) => {
            panic!("required suite '{suite}' failed: {err}");
        }
    }
}

fn run_optional_pending() {
    let guard = suite_lock().lock().expect("qemu suite lock poisoned");
    let cfg = base_config("pending");
    let result = run_suite(cfg);
    drop(guard);
    match result {
        Ok(report) => {
            eprintln!(
                "pending suite passed in {:?} (log: {})",
                report.duration,
                report.log_path.display()
            );
        }
        Err(err) => {
            eprintln!("pending suite is non-blocking in migration mode: {err}");
        }
    }
}

#[test]
fn suite_core() {
    run_required("core");
}

#[test]
fn suite_drivers() {
    run_required("drivers");
}

#[test]
fn suite_fs() {
    run_required("fs");
}

#[test]
fn suite_kernel() {
    run_required("kernel");
}

#[test]
fn suite_tools() {
    run_required("tools");
}

#[test]
fn suite_pending() {
    run_optional_pending();
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
