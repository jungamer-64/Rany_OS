// ============================================================================
// kernel/src/shell/exoshell/namespaces/cell.rs - DriverCell Management Namespace
// ============================================================================

use alloc::format;
use alloc::string::{String, ToString};

use crate::driver_cell;
#[cfg(feature = "qemu-test-export")]
use crate::driver_cell::fault::{self, TestFaultKind};
use crate::driver_cell::hot_swap;
use crate::driver_cell::lifecycle;
use crate::driver_cell::DriverCellId;
use crate::shell::exoshell::parser::ParseError;
use crate::shell::exoshell::ExoValue;

pub struct CellNamespace;

impl CellNamespace {
    /// Dispatch methods for 'cell' namespace (DriverCell-first API)
    pub fn dispatch(method: &str, args: &[ExoValue<'static>]) -> ExoValue<'static> {
        match method {
            "list" => Self::dispatch_list(),
            "stats" => Self::dispatch_stats(args),
            "health" => Self::dispatch_health(args),
            "unload" => Self::dispatch_unload(args),
            "update" => Self::dispatch_update(args),
            "rollback" => Self::dispatch_rollback(args),
            "commit" => Self::dispatch_commit(args),
            #[cfg(feature = "qemu-test-export")]
            "debug_fault" => Self::dispatch_debug_fault(args),
            "reload" => ExoValue::Error(String::from(
                "reload() is not implemented for DriverCell API; use update()/rollback()/commit()",
            )),
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("cell"),
                    method: String::from(method),
                }
                .to_string()
                    + "\nValid methods: "
                    + valid_methods_help(),
            ),
        }
    }

    fn dispatch_list() -> ExoValue<'static> {
        let cells = driver_cell::driver_cell_manager().list_snapshots();
        let mut output = String::from(
            " DriverCell | Name                 | State      | LoaderCell | Drivers | HotSwap\n",
        );
        output.push_str(
            "-----------|----------------------|------------|------------|---------|---------\n",
        );

        for cell in cells {
            let loader_cell = cell
                .cell_id
                .map(|id| id.as_u64().to_string())
                .unwrap_or_else(|| "-".into());
            output.push_str(&format!(
                "{:10} | {:20} | {:10} | {:10} | {:7} | {:7}\n",
                cell.id.as_u64(),
                cell.name,
                cell.state,
                loader_cell,
                cell.driver_count,
                cell.hot_swap_state
            ));
        }
        ExoValue::String(output.into())
    }

    fn dispatch_stats(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };

        let manager = driver_cell::driver_cell_manager();
        let snap = match manager.with_cell(id, |cell| cell.snapshot()) {
            Ok(s) => s,
            Err(e) => return ExoValue::Error(format!("DriverCell {} not found: {}", id.as_u64(), e)),
        };

        let mut output = format!("DriverCell Stats: {}\n", snap.name);
        output.push_str(&format!("  DriverCell ID: {}\n", snap.id.as_u64()));
        output.push_str(&format!("  State: {}\n", snap.state));
        output.push_str(&format!("  HotSwap State: {}\n", snap.hot_swap_state));
        output.push_str(&format!(
            "  Loader Cell ID: {}\n",
            snap.cell_id
                .map(|c| c.as_u64().to_string())
                .unwrap_or_else(|| "-".into())
        ));
        output.push_str(&format!(
            "  Domain ID: {}\n",
            snap.domain_id
                .map(|d| d.as_u64().to_string())
                .unwrap_or_else(|| "-".into())
        ));
        output.push_str(&format!("  Drivers: {}\n", snap.driver_count));
        output.push_str(&format!("  Priority: {:?}\n", snap.priority));
        output.push_str(&format!("  CPU Limit: {}%\n", snap.cpu_limit_percent));
        output.push_str(&format!("  Memory Limit: {} bytes\n", snap.memory_limit_bytes));
        output.push_str(&format!("  NUMA Node: {:?}\n", snap.numa_node));
        output.push_str(&format!(
            "  Validation Deadline Tick: {}\n",
            snap.validation_deadline_tick
                .map(|t| t.to_string())
                .unwrap_or_else(|| "-".into())
        ));
        output.push_str(&format!(
            "  Last Health Failure: {}\n",
            snap.last_health_failure.unwrap_or_else(|| "-".into())
        ));
        output.push_str(&format!(
            "  Stats: starts={} stops={} faults={} restarts={} hot_swaps={}\n",
            snap.stats.start_count,
            snap.stats.stop_count,
            snap.stats.fault_count,
            snap.stats.restart_count,
            snap.stats.hot_swap_count
        ));

        if let Some(loader_cell_id) = snap.cell_id {
            crate::loader::with_registry(|r| {
                if let Some(cell) = r.get(loader_cell_id) {
                    output.push_str("  Loader Cell:\n");
                    output.push_str(&format!("    Base: {:#x}\n", cell.load_address));
                    output.push_str(&format!("    Size: {} bytes\n", cell.load_size));
                    output.push_str(&format!("    Registered Drivers: {}\n", cell.registered_drivers.len()));
                }
            });
        }

        ExoValue::String(output.into())
    }

    fn dispatch_health(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };

        match hot_swap::health_status(id) {
            Ok(h) => {
                let mut output = String::new();
                output.push_str("DriverCell Health\n");
                output.push_str(&format!("  DriverCell ID: {}\n", h.driver_cell_id.as_u64()));
                output.push_str(&format!("  State: {}\n", h.state));
                output.push_str(&format!("  HotSwap State: {}\n", h.hot_swap_state));
                output.push_str(&format!(
                    "  Loader Cell ID: {}\n",
                    h.loader_cell_id
                        .map(|c| c.as_u64().to_string())
                        .unwrap_or_else(|| "-".into())
                ));
                output.push_str(&format!("  Health Failed: {}\n", h.health_failed));
                output.push_str(&format!(
                    "  Validation Deadline Tick: {}\n",
                    h.validation_deadline_tick
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "-".into())
                ));
                output.push_str(&format!(
                    "  Last Health Failure: {}\n",
                    h.last_health_failure.unwrap_or_else(|| "-".into())
                ));
                ExoValue::String(output.into())
            }
            Err(e) => ExoValue::Error(format!("Failed to read health: {}", e)),
        }
    }

    fn dispatch_unload(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };

        match lifecycle::unload(id) {
            Ok(_) => ExoValue::String(
                format!("DriverCell {} unloaded successfully", id.as_u64()).into(),
            ),
            Err(e) => ExoValue::Error(format!("Failed to unload DriverCell {}: {}", id.as_u64(), e)),
        }
    }

    fn dispatch_update(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };

        let path = match args.get(1) {
            Some(ExoValue::String(s)) => s.as_ref(),
            _ => return ExoValue::Error(String::from("Usage: cell.update(driver_cell_id, path)")),
        };

        let shell = match kernel_api::services::kernel().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        let content = match shell.read_file_zero_copy(path) {
            Ok(c) => c,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        match hot_swap::hot_swap(id, &content) {
            Ok(result) => ExoValue::String(
                format!(
                    "DriverCell {} updated. old_loader_cell={} new_loader_cell={} needs_rollback={}",
                    id.as_u64(),
                    result.old_cell_id.as_u64(),
                    result.new_cell_id.as_u64(),
                    result.needs_rollback
                )
                .into(),
            ),
            Err(e) => ExoValue::Error(format!("Update failed: {}", e)),
        }
    }

    fn dispatch_rollback(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };
        match hot_swap::rollback(id) {
            Ok(()) => ExoValue::String(format!("DriverCell {} rollback completed", id.as_u64()).into()),
            Err(e) => ExoValue::Error(format!("Rollback failed: {}", e)),
        }
    }

    fn dispatch_commit(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };
        match hot_swap::commit(id) {
            Ok(()) => ExoValue::String(format!("DriverCell {} update committed", id.as_u64()).into()),
            Err(e) => ExoValue::Error(format!("Commit failed: {}", e)),
        }
    }

    #[cfg(feature = "qemu-test-export")]
    fn dispatch_debug_fault(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match parse_driver_cell_id(args) {
            Ok(id) => id,
            Err(e) => return ExoValue::Error(e),
        };

        let kind = match args.get(1) {
            None => TestFaultKind::Panic,
            Some(ExoValue::String(s)) => match TestFaultKind::parse(s.as_ref()) {
                Some(k) => k,
                None => {
                    return ExoValue::Error(String::from(
                        "Usage: cell.debug_fault(driver_cell_id, \"panic\"|\"timeout\"|\"other\")",
                    ))
                }
            },
            _ => {
                return ExoValue::Error(String::from(
                    "Usage: cell.debug_fault(driver_cell_id, \"panic\"|\"timeout\"|\"other\")",
                ))
            }
        };

        match fault::inject_test_fault(id, kind) {
            Ok(outcome) => {
                // Trigger the same polling path immediately to make manual QEMU observation deterministic.
                crate::loader::live_update::poll_pending_updates();
                hot_swap::poll_validation_windows();

                let last_health_failure = outcome
                    .last_health_failure_after
                    .clone()
                    .unwrap_or_else(|| String::from("-"));

                ExoValue::String(
                    format!(
                        "Injected {} fault into DriverCell {} => action={} state={} hot_swap={} consecutive_faults={} last_health_failure={}",
                        outcome.requested_kind,
                        id.as_u64(),
                        &outcome.action,
                        outcome.driver_cell_state_after,
                        outcome.hot_swap_state_after,
                        outcome.consecutive_faults_after,
                        last_health_failure
                    )
                    .into(),
                )
            }
            Err(e) => ExoValue::Error(format!("Failed to inject debug fault: {}", e)),
        }
    }
}

#[cfg(feature = "qemu-test-export")]
const fn valid_methods_help() -> &'static str {
    "list, stats, health, unload, update, rollback, commit, debug_fault"
}

#[cfg(not(feature = "qemu-test-export"))]
const fn valid_methods_help() -> &'static str {
    "list, stats, health, unload, update, rollback, commit"
}

fn parse_driver_cell_id(args: &[ExoValue<'static>]) -> Result<DriverCellId, String> {
    let raw_id = match args.first() {
        Some(ExoValue::Int(n)) if *n >= 0 => *n as u64,
        Some(ExoValue::String(s)) => s
            .parse::<u64>()
            .map_err(|_| String::from("Usage: cell.<method>(driver_cell_id, ...)"))?,
        _ => return Err(String::from("Usage: cell.<method>(driver_cell_id, ...)")),
    };
    Ok(DriverCellId::new(raw_id))
}
