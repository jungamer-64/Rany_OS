#![cfg_attr(not(test), allow(dead_code))]

use qemu_runner::{run_suite, RunConfig};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn run_pending(suite: &str) {
    let guard = suite_lock().lock().expect("qemu suite lock poisoned");
    let cfg = base_config(suite);
    let result = run_suite(cfg);
    drop(guard);
    match result {
        Ok(report) => {
            let pending_count = write_pending_summaries(&report)
                .unwrap_or_else(|err| panic!("pending summary generation failed: {err}"));
            eprintln!(
                "pending suite '{}' passed in {:?} (log: {}, pending_count: {})",
                report.suite,
                report.duration,
                report.log_path.display(),
                pending_count
            );
        }
        Err(err) => {
            panic!("pending suite '{suite}' failed: {err}");
        }
    }
}

fn run_runtime_pending(suite: &str) {
    let guard = suite_lock().lock().expect("qemu suite lock poisoned");
    let cfg = base_config(suite);
    let result = run_suite(cfg);
    drop(guard);
    match result {
        Ok(report) => {
            let (passed_count, failed_count, blocked_count) =
                write_kernel_runtime_pending_summaries(&report).unwrap_or_else(|err| {
                    panic!("kernel runtime pending summary generation failed: {err}")
                });
            eprintln!(
                "runtime pending suite '{}' passed in {:?} (log: {}, pass={}, fail={}, blocked={})",
                report.suite,
                report.duration,
                report.log_path.display(),
                passed_count,
                failed_count,
                blocked_count
            );
        }
        Err(err) => {
            panic!("runtime pending suite '{suite}' failed: {err}");
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
fn suite_graphics() {
    run_required("graphics");
}

#[test]
fn suite_tools() {
    run_required("tools");
}

#[test]
#[ignore = "pending suite is informational and non-blocking in CI"]
fn suite_pending() {
    run_pending("pending");
}

#[test]
#[ignore = "runtime pending suite is informational and non-blocking in CI"]
fn suite_kernel_runtime_pending() {
    run_runtime_pending("kernel_runtime_pending");
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

fn pending_list_path() -> std::path::PathBuf {
    qemu_runner::workspace_root()
        .join("scripts")
        .join("qemu_pending_cases.lst")
}

fn is_active_pending_line(line: &str) -> bool {
    !line.is_empty() && !line.starts_with('#')
}

fn collect_pending_items(path: &Path) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read '{}': {err}", path.display()))?;
    Ok(content
        .lines()
        .map(|line| line.trim())
        .filter(|line| is_active_pending_line(line))
        .map(std::string::ToString::to_string)
        .collect())
}

fn generated_at_utc() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("unix:{}", duration.as_secs()),
        Err(_) => String::from("unix:0"),
    }
}

fn json_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn parse_kernel_runtime_counts(log_path: &Path) -> Result<(u64, u64, u64), String> {
    let content = std::fs::read_to_string(log_path)
        .map_err(|err| format!("failed to read runtime pending log '{}': {err}", log_path.display()))?;

    for line in content.lines().rev() {
        let line = line.trim();
        if let Some((_, tail)) = line.split_once("kernel_runtime_pending counts ") {
            let mut passed_count: Option<u64> = None;
            let mut failed_count: Option<u64> = None;
            let mut blocked_count: Option<u64> = None;

            for token in tail.split_whitespace() {
                if let Some(value) = token.strip_prefix("pass=") {
                    passed_count = value.parse::<u64>().ok();
                    continue;
                }
                if let Some(value) = token.strip_prefix("fail=") {
                    failed_count = value.parse::<u64>().ok();
                    continue;
                }
                if let Some(value) = token.strip_prefix("blocked=") {
                    blocked_count = value.parse::<u64>().ok();
                }
            }

            if let (Some(passed_count), Some(failed_count), Some(blocked_count)) =
                (passed_count, failed_count, blocked_count)
            {
                return Ok((passed_count, failed_count, blocked_count));
            }
        }
    }

    Err(format!(
        "failed to find kernel runtime pending counts in '{}'",
        log_path.display()
    ))
}

fn write_pending_summaries(report: &qemu_runner::RunReport) -> Result<usize, String> {
    let list_path = pending_list_path();
    let pending_items = collect_pending_items(&list_path)?;
    let pending_count = pending_items.len();

    let log_dir = qemu_runner::workspace_root().join("target").join("qemu-logs");
    std::fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create pending summary directory '{}': {err}",
            log_dir.display()
        )
    })?;

    let generated_at = generated_at_utc();
    let txt_path = log_dir.join("pending-summary.txt");
    let json_path = log_dir.join("pending-summary.json");

    let mut text = String::new();
    text.push_str("suite: pending\n");
    text.push_str(&format!("pending_count: {pending_count}\n"));
    text.push_str(&format!("generated_at_utc: {generated_at}\n"));
    text.push_str(&format!("suite_log_path: {}\n", report.log_path.display()));
    text.push_str("pending_items:\n");
    if pending_items.is_empty() {
        text.push_str("- none\n");
    } else {
        for item in &pending_items {
            text.push_str("- ");
            text.push_str(item);
            text.push('\n');
        }
    }

    std::fs::write(&txt_path, text).map_err(|err| {
        format!(
            "failed to write pending text summary '{}': {err}",
            txt_path.display()
        )
    })?;

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"suite\": \"pending\",\n");
    json.push_str(&format!("  \"pending_count\": {pending_count},\n"));
    json.push_str("  \"pending_items\": [");
    if pending_items.is_empty() {
        json.push_str("],\n");
    } else {
        json.push('\n');
        for (index, item) in pending_items.iter().enumerate() {
            let comma = if index + 1 == pending_items.len() {
                ""
            } else {
                ","
            };
            json.push_str(&format!("    \"{}\"{comma}\n", json_escape(item)));
        }
        json.push_str("  ],\n");
    }
    json.push_str(&format!(
        "  \"suite_log_path\": \"{}\",\n",
        json_escape(&report.log_path.display().to_string())
    ));
    json.push_str(&format!(
        "  \"generated_at_utc\": \"{}\"\n",
        json_escape(&generated_at)
    ));
    json.push_str("}\n");

    std::fs::write(&json_path, json).map_err(|err| {
        format!(
            "failed to write pending json summary '{}': {err}",
            json_path.display()
        )
    })?;

    Ok(pending_count)
}

fn write_kernel_runtime_pending_summaries(
    report: &qemu_runner::RunReport,
) -> Result<(u64, u64, u64), String> {
    let (passed_count, failed_count, blocked_count) = parse_kernel_runtime_counts(&report.log_path)?;

    let log_dir = qemu_runner::workspace_root().join("target").join("qemu-logs");
    std::fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create runtime pending summary directory '{}': {err}",
            log_dir.display()
        )
    })?;

    let generated_at = generated_at_utc();
    let txt_path = log_dir.join("kernel-runtime-pending-summary.txt");
    let json_path = log_dir.join("kernel-runtime-pending-summary.json");

    let mut text = String::new();
    text.push_str("suite: kernel_runtime_pending\n");
    text.push_str(&format!("passed_count: {passed_count}\n"));
    text.push_str(&format!("failed_count: {failed_count}\n"));
    text.push_str(&format!("blocked_count: {blocked_count}\n"));
    text.push_str(&format!("generated_at_utc: {generated_at}\n"));
    text.push_str(&format!("suite_log_path: {}\n", report.log_path.display()));

    std::fs::write(&txt_path, text).map_err(|err| {
        format!(
            "failed to write runtime pending text summary '{}': {err}",
            txt_path.display()
        )
    })?;

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"suite\": \"kernel_runtime_pending\",\n");
    json.push_str(&format!("  \"passed_count\": {passed_count},\n"));
    json.push_str(&format!("  \"failed_count\": {failed_count},\n"));
    json.push_str(&format!("  \"blocked_count\": {blocked_count},\n"));
    json.push_str(&format!(
        "  \"suite_log_path\": \"{}\",\n",
        json_escape(&report.log_path.display().to_string())
    ));
    json.push_str(&format!(
        "  \"generated_at_utc\": \"{}\"\n",
        json_escape(&generated_at)
    ));
    json.push_str("}\n");

    std::fs::write(&json_path, json).map_err(|err| {
        format!(
            "failed to write runtime pending json summary '{}': {err}",
            json_path.display()
        )
    })?;

    Ok((passed_count, failed_count, blocked_count))
}
