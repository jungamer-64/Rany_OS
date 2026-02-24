use super::*;

fn write_counts_summary(
    report: &qemu_runner::RunReport,
    suite_name: &str,
    txt_name: &str,
    json_name: &str,
    passed_count: u64,
    failed_count: u64,
    blocked_count: u64,
) -> Result<RuntimePendingSummaryStats, String> {
    let log_dir = qemu_runner::workspace_root()
        .join("target")
        .join("qemu-logs");
    std::fs::create_dir_all(&log_dir).map_err(|err| {
        format!(
            "failed to create pending summary directory '{}': {err}",
            log_dir.display()
        )
    })?;

    let generated_at = generated_at_utc();
    let txt_path = log_dir.join(txt_name);
    let json_path = log_dir.join(json_name);

    let mut text = String::new();
    text.push_str(&format!("suite: {suite_name}\n"));
    text.push_str(&format!("passed_count: {passed_count}\n"));
    text.push_str(&format!("failed_count: {failed_count}\n"));
    text.push_str(&format!("blocked_count: {blocked_count}\n"));
    text.push_str(&format!("generated_at_utc: {generated_at}\n"));
    text.push_str(&format!("suite_log_path: {}\n", report.log_path.display()));

    std::fs::write(&txt_path, text).map_err(|err| {
        format!(
            "failed to write pending text summary '{}': {err}",
            txt_path.display()
        )
    })?;

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"suite\": \"{suite_name}\",\n"));
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
            "failed to write pending json summary '{}': {err}",
            json_path.display()
        )
    })?;

    Ok(RuntimePendingSummaryStats {
        passed_count,
        failed_count,
        blocked_count,
    })
}

pub(crate) fn write_kernel_runtime_pending_summaries(
    report: &qemu_runner::RunReport,
) -> Result<RuntimePendingSummaryStats, String> {
    let (passed_count, failed_count, blocked_count) =
        parse_kernel_runtime_counts(&report.log_path)?;
    write_counts_summary(
        report,
        "kernel_runtime_pending",
        "kernel-runtime-pending-summary.txt",
        "kernel-runtime-pending-summary.json",
        passed_count,
        failed_count,
        blocked_count,
    )
}
