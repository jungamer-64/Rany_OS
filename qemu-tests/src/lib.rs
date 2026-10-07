#[cfg(test)]
use qemu_runner::{RunConfig, run_fullboot};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
fn qemu_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
fn base_config(profile: &str) -> RunConfig {
    let mut cfg = RunConfig::for_profile(profile);
    let default_timeout = if profile == "step9-heavy" {
        480
    } else if profile == "network" {
        600
    } else if matches!(profile, "nightly-required" | "cpu-hotplug-sparse") {
        300
    } else if profile == "driver_domain" {
        240
    } else {
        120
    };
    cfg.timeout_secs = env_u64("QEMU_TEST_TIMEOUT_SECS", default_timeout);
    cfg.memory_mb = env_u64("QEMU_TEST_MEMORY_MB", 2048);
    // These profiles require a particular firmware topology to exercise their
    // contract. Generic tier settings apply to the remaining profiles.
    if !matches!(profile, "mm" | "cpu-hotplug" | "cpu-hotplug-sparse") {
        cfg.smp = env_u16("QEMU_TEST_SMP", 4);
        cfg.max_cpus = env_u16("QEMU_TEST_MAX_CPUS", 4);
    }
    if profile != "cpu-hotplug-sparse" {
        cfg.cpu = std::env::var("QEMU_TEST_CPU").unwrap_or(cfg.cpu);
    }
    cfg.case_filter = std::env::var("QEMU_TEST_CASE_FILTER").ok();
    cfg
}

#[cfg(test)]
fn run_required_profile(profile: &str) {
    let guard = qemu_lock().lock().expect("qemu lock poisoned");
    let mut cfg = base_config(profile);
    let cpu_counts: &[u16] = if profile == "scheduler" {
        &[1, 4]
    } else {
        core::slice::from_ref(&cfg.smp)
    };
    let cpu_counts = cpu_counts.to_vec();
    for count in cpu_counts {
        cfg.smp = count;
        if profile == "scheduler" {
            cfg.max_cpus = count;
        }
        match run_fullboot(&cfg) {
            Ok(report) => eprintln!(
                "required full-boot profile '{}' SMP={} passed in {:?} (log: {})",
                report.profile,
                count,
                report.duration,
                report.log_path.display()
            ),
            Err(err) => panic!("required full-boot profile '{profile}' SMP={count} failed: {err}"),
        }
    }
    drop(guard);
}

#[test]
fn fullboot_pr_required() {
    let only_profile = std::env::var("QEMU_TEST_PROFILE_ONLY").ok();
    let mut ran_any = false;
    // Each profile owns its interrupt and topology requirements.
    for profile in [
        "boot-smoke",
        "scheduler",
        "storage",
        "driver_domain",
        "iommu",
        "network",
        "mm",
        "cpu-hotplug",
    ] {
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
#[ignore = "nightly-only sparse CPU add, blocked eject, and stable re-add profile"]
fn fullboot_nightly_cpu_hotplug() {
    run_required_profile("cpu-hotplug-sparse");
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
