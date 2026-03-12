#![cfg_attr(not(test), allow(dead_code))]

use qemu_runner::{RunConfig, run_fullboot};
use std::sync::{Mutex, OnceLock};

fn qemu_lock() -> &'static Mutex<()> {
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
    let default_timeout = if profile == "step9-heavy" {
        480
    } else if profile == "network" {
        600
    } else if profile == "nightly-required" {
        300
    } else if profile == "driver_domain" {
        240
    } else {
        120
    };
    cfg.timeout_secs = env_u64("QEMU_TEST_TIMEOUT_SECS", default_timeout);
    cfg.memory_mb = env_u64("QEMU_TEST_MEMORY_MB", 2048);
    cfg.smp = env_u8("QEMU_TEST_SMP", 4);
    cfg.cpu = std::env::var("QEMU_TEST_CPU").unwrap_or_else(|_| String::from("qemu64,+rdtscp"));
    cfg.case_filter = std::env::var("QEMU_TEST_CASE_FILTER").ok();
    cfg
}

fn run_required_profile(profile: &str) {
    let guard = qemu_lock().lock().expect("qemu lock poisoned");
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
    let only_profile = std::env::var("QEMU_TEST_PROFILE_ONLY").ok();
    let mut ran_any = false;
    // Keep PR-required set deterministic in current qemu_no_if fullboot runs.
    for profile in ["boot-smoke", "storage", "driver_domain", "iommu", "network"] {
        if let Some(only) = only_profile.as_deref() {
            if only != profile {
                continue;
            }
        }
        ran_any = true;
        run_required_profile(profile);
    }
    if !ran_any {
        panic!(
            "QEMU_TEST_PROFILE_ONLY={} did not match any profile in fullboot_pr_required",
            only_profile.unwrap_or_default()
        );
    }
}

#[test]
#[ignore = "nightly-only full-boot expansion profile"]
fn fullboot_nightly_required() {
    run_required_profile("nightly-required");
}

#[test]
#[ignore = "manual/nightly heavy profile for Step9 power-cut + dual-transport kgdb checks"]
fn fullboot_step9_heavy() {
    run_required_profile("step9-heavy");
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
