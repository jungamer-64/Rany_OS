// ============================================================================
// kernel/src/shell/exoshell/namespaces/cell.rs - DriverCell Management Namespace
// ============================================================================

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::driver_domain;
#[cfg(feature = "qemu-test-export")]
use crate::driver_domain::fault::{self, TestFaultKind};
use crate::driver_domain::hot_swap::{self, HotSwapState};
use crate::driver_domain::lifecycle;
use crate::driver_domain::{DriverDomainId, DriverDomainSnapshot};
use crate::security::capability::{CAP_SYS_ADMIN, CAP_SYS_MODULE};
use crate::security::CapabilitySet;
use crate::shell::exoshell::types::ExoValue;

pub struct CellNamespace;

impl CellNamespace {
    fn valid_methods_help() -> &'static str {
        #[cfg(feature = "qemu-test-export")]
        {
            "list, info, graph, inspect_artifact, epoch_status, wait_quiescent, load, swap, update, unload, rollback, commit, stats, health, debug_fault"
        }
        #[cfg(not(feature = "qemu-test-export"))]
        {
            "list, info, graph, inspect_artifact, epoch_status, wait_quiescent, load, swap, update, unload, rollback, commit, stats, health"
        }
    }

    fn err_unknown_method(method: &str) -> ExoValue<'static> {
        ExoValue::Error(format!(
            "Unknown method 'cell.{}'. Valid: {}",
            method,
            Self::valid_methods_help()
        ))
    }

    fn vstr<S: Into<String>>(s: S) -> ExoValue<'static> {
        ExoValue::String(Cow::Owned(s.into()))
    }

    fn vint_u64(v: u64) -> ExoValue<'static> {
        ExoValue::Int(core::cmp::min(v, i64::MAX as u64) as i64)
    }

    fn vint_usize(v: usize) -> ExoValue<'static> {
        ExoValue::Int(core::cmp::min(v as u128, i64::MAX as u128) as i64)
    }

    fn opt_u64(v: Option<u64>) -> ExoValue<'static> {
        v.map(Self::vint_u64).unwrap_or(ExoValue::Nil)
    }

    fn opt_usize(v: Option<usize>) -> ExoValue<'static> {
        v.map(Self::vint_usize).unwrap_or(ExoValue::Nil)
    }

    fn opt_string(v: Option<String>) -> ExoValue<'static> {
        v.map(Self::vstr).unwrap_or(ExoValue::Nil)
    }

    fn opt_bool(v: Option<bool>) -> ExoValue<'static> {
        v.map(ExoValue::Bool).unwrap_or(ExoValue::Nil)
    }

    fn map_insert(map: &mut BTreeMap<String, ExoValue<'static>>, key: &str, val: ExoValue<'static>) {
        map.insert(String::from(key), val);
    }

    fn bool_from_value(v: &ExoValue<'static>) -> Option<bool> {
        match v {
            ExoValue::Bool(b) => Some(*b),
            ExoValue::Int(i) => Some(*i != 0),
            _ => None,
        }
    }

    fn require_cap(
        caps: &CapabilitySet,
        cap: crate::security::capability::Capability,
        op_name: &str,
    ) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(cap) {
            Ok(())
        } else {
            let cap_name = if cap == CAP_SYS_ADMIN {
                "CAP_SYS_ADMIN"
            } else if cap == CAP_SYS_MODULE {
                "CAP_SYS_MODULE"
            } else {
                "required capability"
            };
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires {}",
                op_name, cap_name
            )))
        }
    }

    fn resolve_driver_domain_id(arg: &ExoValue<'static>) -> Result<DriverDomainId, String> {
        match arg {
            ExoValue::Int(n) if *n >= 0 => Ok(DriverDomainId::new(*n as u64)),
            ExoValue::String(s) => {
                if let Ok(id) = s.parse::<u64>() {
                    Ok(DriverDomainId::new(id))
                } else {
                    Err(String::from("Expected driver_domain_id (int or numeric string)"))
                }
            }
            _ => Err(String::from("Expected driver_domain_id (int or numeric string)")),
        }
    }

    fn resolve_driver_domain_ref(args: &[ExoValue<'static>]) -> Result<DriverDomainId, ExoValue<'static>> {
        let Some(first) = args.first() else {
            return Err(ExoValue::Error(String::from(
                "Missing driver cell target (id or name)",
            )));
        };

        if let Ok(id) = Self::resolve_driver_domain_id(first) {
            return Ok(id);
        }

        let ExoValue::String(name) = first else {
            return Err(ExoValue::Error(String::from(
                "Expected driver cell target (id or name)",
            )));
        };

        driver_domain::driver_domain_manager()
            .find_by_name(name.as_ref())
            .ok_or_else(|| ExoValue::Error(format!("DriverCell '{}' not found", name)))
    }

    fn driver_domain_stats_map(stats: &crate::driver_domain::stats::DriverDomainStats) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        Self::map_insert(&mut map, "start_count", Self::vint_u64(stats.start_count as u64));
        Self::map_insert(&mut map, "stop_count", Self::vint_u64(stats.stop_count as u64));
        Self::map_insert(&mut map, "fault_count", Self::vint_u64(stats.fault_count as u64));
        Self::map_insert(&mut map, "restart_count", Self::vint_u64(stats.restart_count as u64));
        Self::map_insert(&mut map, "hot_swap_count", Self::vint_u64(stats.hot_swap_count as u64));
        ExoValue::Map(map)
    }

    fn driver_domain_snapshot_to_map(snap: &DriverDomainSnapshot) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        Self::map_insert(&mut map, "id", Self::vint_u64(snap.id.as_u64()));
        Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(snap.id.as_u64()));
        Self::map_insert(&mut map, "name", Self::vstr(snap.name.clone()));
        Self::map_insert(&mut map, "state", Self::vstr(format!("{}", snap.state)));
        Self::map_insert(
            &mut map,
            "hot_swap_state",
            Self::vstr(format!("{}", snap.hot_swap_state)),
        );
        Self::map_insert(
            &mut map,
            "loader_cell_id",
            Self::opt_u64(snap.cell_id.map(|c| c.as_u64())),
        );
        Self::map_insert(
            &mut map,
            "domain_id",
            Self::opt_u64(snap.domain_id.map(|d| d.as_u64())),
        );
        Self::map_insert(&mut map, "driver_count", Self::vint_usize(snap.driver_count));
        Self::map_insert(&mut map, "priority", Self::vstr(format!("{:?}", snap.priority)));
        Self::map_insert(
            &mut map,
            "cpu_limit_percent",
            Self::vint_u64(snap.cpu_limit_percent),
        );
        Self::map_insert(
            &mut map,
            "memory_limit_bytes",
            Self::vint_u64(snap.memory_limit_bytes),
        );
        Self::map_insert(&mut map, "numa_node", Self::opt_usize(snap.numa_node));
        Self::map_insert(&mut map, "created_at_tick", Self::vint_u64(snap.created_at));
        Self::map_insert(
            &mut map,
            "consecutive_faults",
            Self::vint_u64(snap.consecutive_faults as u64),
        );
        Self::map_insert(&mut map, "total_faults", Self::vint_u64(snap.total_faults as u64));
        Self::map_insert(
            &mut map,
            "restart_policy",
            Self::vstr(format!("{:?}", snap.restart_policy)),
        );
        Self::map_insert(
            &mut map,
            "validation_deadline_tick",
            Self::opt_u64(snap.validation_deadline_tick),
        );
        Self::map_insert(
            &mut map,
            "last_health_failure",
            Self::opt_string(snap.last_health_failure.clone()),
        );
        Self::map_insert(&mut map, "stats", Self::driver_domain_stats_map(&snap.stats));
        ExoValue::Map(map)
    }

    fn loader_cell_entry_to_map(cell: &crate::loader::CellEntry) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        let deps = cell
            .dependencies
            .iter()
            .map(|id| Self::vint_u64(id.as_u64()))
            .collect::<Vec<_>>();

        Self::map_insert(&mut map, "id", Self::vint_u64(cell.id.as_u64()));
        Self::map_insert(&mut map, "name", Self::vstr(cell.name.clone()));
        Self::map_insert(&mut map, "state", Self::vstr(format!("{:?}", cell.state)));
        Self::map_insert(
            &mut map,
            "base_address_hex",
            Self::vstr(format!("{:#x}", cell.load_address)),
        );
        Self::map_insert(&mut map, "size_bytes", Self::vint_usize(cell.load_size));
        Self::map_insert(
            &mut map,
            "entry_point_hex",
            cell.entry_point
                .map(|p| Self::vstr(format!("{:#x}", p)))
                .unwrap_or(ExoValue::Nil),
        );
        Self::map_insert(
            &mut map,
            "exports_count",
            Self::vint_usize(cell.exports.len()),
        );
        Self::map_insert(
            &mut map,
            "imports_count",
            Self::vint_usize(cell.imports.len()),
        );
        Self::map_insert(&mut map, "dependencies", ExoValue::Array(deps));
        Self::map_insert(&mut map, "is_safe", ExoValue::Bool(cell.is_safe));
        Self::map_insert(
            &mut map,
            "signature_verified",
            ExoValue::Bool(cell.signature_verified),
        );
        Self::map_insert(
            &mut map,
            "required_caps_hex",
            Self::vstr(format!("{:#x}", cell.required_caps)),
        );
        Self::map_insert(&mut map, "pkey", Self::opt_u64(cell.pkey.map(|p| p as u64)));
        ExoValue::Map(map)
    }

    fn parse_load_options(
        args: &[ExoValue<'static>],
    ) -> Result<(String, Option<String>, bool), ExoValue<'static>> {
        let path = match args.first() {
            Some(ExoValue::String(s)) => s.as_ref().to_string(),
            _ => {
                return Err(ExoValue::Error(String::from(
                    "Usage: cell.load(path, { name: \"...\", allow_unsafe: bool }?)",
                )))
            }
        };

        let mut name_override = None;
        let mut allow_unsafe = false;

        if let Some(opts) = args.get(1) {
            match opts {
                ExoValue::Map(map) => {
                    if let Some(v) = map.get("name") {
                        match v {
                            ExoValue::String(s) => name_override = Some(s.as_ref().to_string()),
                            _ => {
                                return Err(ExoValue::Error(String::from(
                                    "cell.load opts.name must be string",
                                )))
                            }
                        }
                    }
                    if let Some(v) = map.get("allow_unsafe") {
                        allow_unsafe = Self::bool_from_value(v).ok_or_else(|| {
                            ExoValue::Error(String::from(
                                "cell.load opts.allow_unsafe must be bool or int",
                            ))
                        })?;
                    }
                }
                _ => {
                    return Err(ExoValue::Error(String::from(
                        "cell.load second argument must be a map",
                    )))
                }
            }
        }

        Ok((path, name_override, allow_unsafe))
    }

    fn parse_epoch_wait_args(args: &[ExoValue<'static>]) -> Result<(u64, u64), ExoValue<'static>> {
        let target = match args.first() {
            Some(ExoValue::Int(n)) if *n >= 0 => *n as u64,
            Some(ExoValue::String(s)) => s.parse::<u64>().map_err(|_| {
                ExoValue::Error(String::from(
                    "Usage: cell.wait_quiescent(target_epoch, max_attempts?)",
                ))
            })?,
            _ => {
                return Err(ExoValue::Error(String::from(
                    "Usage: cell.wait_quiescent(target_epoch, max_attempts?)",
                )))
            }
        };

        let max_attempts = match args.get(1) {
            None => 100_000,
            Some(ExoValue::Int(n)) if *n >= 0 => *n as u64,
            Some(ExoValue::String(s)) => s.parse::<u64>().map_err(|_| {
                ExoValue::Error(String::from(
                    "cell.wait_quiescent max_attempts must be non-negative integer",
                ))
            })?,
            _ => {
                return Err(ExoValue::Error(String::from(
                    "cell.wait_quiescent max_attempts must be non-negative integer",
                )))
            }
        };

        Ok((target, max_attempts))
    }

    fn infer_name_from_path(path: &str) -> String {
        let base = path.rsplit('/').next().unwrap_or(path);
        base.trim_end_matches(".cell")
            .trim_end_matches(".elf")
            .trim_end_matches(".driver")
            .to_string()
    }

    fn parse_path_arg(args: &[ExoValue<'static>], idx: usize, usage: &str) -> Result<String, ExoValue<'static>> {
        match args.get(idx) {
            Some(ExoValue::String(s)) => Ok(s.as_ref().to_string()),
            _ => Err(ExoValue::Error(String::from(usage))),
        }
    }

    fn make_success_message_map(msg: String) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        Self::map_insert(&mut map, "success", ExoValue::Bool(true));
        Self::map_insert(&mut map, "message", Self::vstr(msg));
        ExoValue::Map(map)
    }

    fn health_status_map(id: DriverDomainId) -> ExoValue<'static> {
        match hot_swap::health_status(id) {
            Ok(h) => {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(h.driver_domain_id.as_u64()));
                Self::map_insert(&mut map, "state", Self::vstr(format!("{}", h.state)));
                Self::map_insert(
                    &mut map,
                    "hot_swap_state",
                    Self::vstr(format!("{}", h.hot_swap_state)),
                );
                Self::map_insert(
                    &mut map,
                    "loader_cell_id",
                    Self::opt_u64(h.loader_cell_id.map(|c| c.as_u64())),
                );
                Self::map_insert(&mut map, "health_failed", ExoValue::Bool(h.health_failed));
                Self::map_insert(
                    &mut map,
                    "validation_deadline_tick",
                    Self::opt_u64(h.validation_deadline_tick),
                );
                Self::map_insert(
                    &mut map,
                    "last_health_failure",
                    Self::opt_string(h.last_health_failure),
                );
                ExoValue::Map(map)
            }
            Err(e) => {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "error", Self::vstr(format!("{}", e)));
                ExoValue::Map(map)
            }
        }
    }

    fn pending_live_update_map(loader_cell_id: Option<crate::loader::CellId>) -> ExoValue<'static> {
        let Some(cid) = loader_cell_id else {
            return ExoValue::Nil;
        };
        let Some(p) = crate::loader::live_update::live_update_manager().pending_status(cid.as_u64()) else {
            return ExoValue::Nil;
        };
        let mut map = BTreeMap::new();
        Self::map_insert(&mut map, "old_cell_id", Self::vint_u64(p.old_cell_id));
        Self::map_insert(&mut map, "new_cell_id", Self::vint_u64(p.new_cell_id));
        Self::map_insert(&mut map, "started_at_tick", Self::vint_u64(p.started_at_tick));
        Self::map_insert(&mut map, "deadline_tick", Self::vint_u64(p.deadline_tick));
        Self::map_insert(&mut map, "health_failed", ExoValue::Bool(p.health_failed));
        ExoValue::Map(map)
    }

    fn dispatch_list() -> ExoValue<'static> {
        let cells = driver_domain::driver_domain_manager().list_snapshots();
        let list = cells
            .into_iter()
            .map(|snap| {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(snap.id.as_u64()));
                Self::map_insert(&mut map, "name", Self::vstr(snap.name));
                Self::map_insert(&mut map, "state", Self::vstr(format!("{}", snap.state)));
                Self::map_insert(
                    &mut map,
                    "hot_swap_state",
                    Self::vstr(format!("{}", snap.hot_swap_state)),
                );
                Self::map_insert(
                    &mut map,
                    "loader_cell_id",
                    Self::opt_u64(snap.cell_id.map(|c| c.as_u64())),
                );
                Self::map_insert(
                    &mut map,
                    "domain_id",
                    Self::opt_u64(snap.domain_id.map(|d| d.as_u64())),
                );
                Self::map_insert(&mut map, "driver_count", Self::vint_usize(snap.driver_count));
                Self::map_insert(
                    &mut map,
                    "validation_deadline_tick",
                    Self::opt_u64(snap.validation_deadline_tick),
                );
                ExoValue::Map(map)
            })
            .collect::<Vec<_>>();
        ExoValue::Array(list)
    }

    fn dispatch_info(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match Self::resolve_driver_domain_ref(args) {
            Ok(id) => id,
            Err(e) => return e,
        };

        let manager = driver_domain::driver_domain_manager();
        let snap = match manager.with_cell(id, |cell| cell.snapshot()) {
            Ok(s) => s,
            Err(e) => return ExoValue::Error(format!("DriverCell {} not found: {}", id.as_u64(), e)),
        };

        let loader_cell = snap.cell_id.and_then(|cid| {
            crate::loader::with_registry(|r| r.get(cid).map(Self::loader_cell_entry_to_map))
        });

        let mut live_update = BTreeMap::new();
        Self::map_insert(&mut live_update, "health", Self::health_status_map(id));
        Self::map_insert(
            &mut live_update,
            "pending",
            Self::pending_live_update_map(snap.cell_id),
        );

        let current_epoch = crate::epoch::current_epoch();
        let target_epoch = current_epoch.saturating_sub(1);
        let mut epoch_hint = BTreeMap::new();
        Self::map_insert(&mut epoch_hint, "current_epoch", Self::vint_u64(current_epoch));
        Self::map_insert(&mut epoch_hint, "target_epoch", Self::vint_u64(target_epoch));
        Self::map_insert(
            &mut epoch_hint,
            "all_cores_past_target",
            ExoValue::Bool(crate::epoch::all_cores_past_epoch(target_epoch)),
        );
        Self::map_insert(
            &mut epoch_hint,
            "live_update_epoch",
            Self::vint_u64(crate::loader::live_update::current_epoch()),
        );

        let mut out = BTreeMap::new();
        Self::map_insert(&mut out, "driver_domain", Self::driver_domain_snapshot_to_map(&snap));
        Self::map_insert(&mut out, "loader_cell", loader_cell.unwrap_or(ExoValue::Nil));
        Self::map_insert(&mut out, "live_update", ExoValue::Map(live_update));
        Self::map_insert(&mut out, "epoch_hint", ExoValue::Map(epoch_hint));
        ExoValue::Map(out)
    }

    fn dispatch_graph() -> ExoValue<'static> {
        let manager = driver_domain::driver_domain_manager();
        let (nodes, edges, node_count, edge_count) = crate::loader::with_registry(|r| {
            let mut nodes = Vec::new();
            let mut edges = Vec::new();
            let mut node_count = 0usize;
            let mut edge_count = 0usize;

            for cell in r.all_cells() {
                node_count += 1;
                let mut node = BTreeMap::new();
                Self::map_insert(&mut node, "cell_id", Self::vint_u64(cell.id.as_u64()));
                Self::map_insert(&mut node, "name", Self::vstr(cell.name.clone()));
                Self::map_insert(&mut node, "state", Self::vstr(format!("{:?}", cell.state)));
                Self::map_insert(
                    &mut node,
                    "base_address_hex",
                    Self::vstr(format!("{:#x}", cell.load_address)),
                );
                Self::map_insert(&mut node, "size_bytes", Self::vint_usize(cell.load_size));
                Self::map_insert(
                    &mut node,
                    "driver_count",
                    Self::vint_usize(cell.registered_drivers.len()),
                );
                Self::map_insert(&mut node, "is_safe", ExoValue::Bool(cell.is_safe));
                Self::map_insert(
                    &mut node,
                    "signature_verified",
                    ExoValue::Bool(cell.signature_verified),
                );
                Self::map_insert(
                    &mut node,
                    "required_caps_hex",
                    Self::vstr(format!("{:#x}", cell.required_caps)),
                );
                Self::map_insert(&mut node, "pkey", Self::opt_u64(cell.pkey.map(|p| p as u64)));
                Self::map_insert(
                    &mut node,
                    "driver_domain_id",
                    manager
                        .find_by_cell(cell.id)
                        .map(|id| Self::vint_u64(id.as_u64()))
                        .unwrap_or(ExoValue::Nil),
                );
                nodes.push(ExoValue::Map(node));

                for dep in &cell.dependencies {
                    edge_count += 1;
                    let mut edge = BTreeMap::new();
                    Self::map_insert(&mut edge, "from_cell_id", Self::vint_u64(cell.id.as_u64()));
                    Self::map_insert(&mut edge, "to_cell_id", Self::vint_u64(dep.as_u64()));
                    Self::map_insert(&mut edge, "kind", Self::vstr("loader_dependency"));
                    edges.push(ExoValue::Map(edge));
                }
            }

            (nodes, edges, node_count, edge_count)
        });

        let mut stats = BTreeMap::new();
        Self::map_insert(&mut stats, "node_count", Self::vint_usize(node_count));
        Self::map_insert(&mut stats, "edge_count", Self::vint_usize(edge_count));
        Self::map_insert(
            &mut stats,
            "driver_domain_count",
            Self::vint_usize(manager.count()),
        );

        let mut out = BTreeMap::new();
        Self::map_insert(&mut out, "nodes", ExoValue::Array(nodes));
        Self::map_insert(&mut out, "edges", ExoValue::Array(edges));
        Self::map_insert(&mut out, "stats", ExoValue::Map(stats));
        ExoValue::Map(out)
    }

    fn dispatch_inspect_artifact(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let path = match Self::parse_path_arg(args, 0, "Usage: cell.inspect_artifact(path)") {
            Ok(p) => p,
            Err(e) => return e,
        };

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        let content = match shell.read_file_zero_copy(&path) {
            Ok(c) => c,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        if content.len() < 4 || &content[..4] != b"\x7fELF" {
            return ExoValue::Error(format!("Artifact '{}' is not a valid ELF file", path));
        }

        let mut out = BTreeMap::new();
        let file_name = path.rsplit('/').next().unwrap_or(path.as_str()).to_string();
        Self::map_insert(&mut out, "path", Self::vstr(path.clone()));
        Self::map_insert(&mut out, "file_name", Self::vstr(file_name));

        let Some(deps) = crate::loader::type_id::extract_type_ids(&content) else {
            Self::map_insert(&mut out, "abi_metadata_present", ExoValue::Bool(false));
            Self::map_insert(&mut out, "verify_ok", ExoValue::Bool(false));
            Self::map_insert(&mut out, "cell_version", Self::vstr("0.0.0"));
            Self::map_insert(&mut out, "dependency_count", Self::vint_u64(0));
            Self::map_insert(&mut out, "dependencies", ExoValue::Array(Vec::new()));
            return ExoValue::Map(out);
        };

        let mut dep_vals = Vec::new();
        let mut all_compatible = true;
        for dep in deps.dependencies.iter() {
            let kernel = crate::loader::type_id::get_kernel_interface(&dep.interface);
            let mut m = BTreeMap::new();
            let (kernel_present, kernel_hash_hex, kernel_version, hash_match, version_compatible, compatible, error) =
                if let Some(info) = kernel {
                    let hash_match = info.hash == dep.hash;
                    let version_compatible = info.version.is_backward_compatible(&dep.min_version);
                    let compatible = hash_match && version_compatible;
                    let error = if compatible {
                        None
                    } else if !hash_match {
                        Some(String::from("hash_mismatch"))
                    } else {
                        Some(String::from("version_incompatible"))
                    };
                    (
                        Some(true),
                        Some(format!("{:#x}", info.hash)),
                        Some(format!("{}", info.version)),
                        Some(hash_match),
                        Some(version_compatible),
                        Some(compatible),
                        error,
                    )
                } else {
                    (
                        Some(false),
                        None,
                        None,
                        Some(false),
                        Some(false),
                        Some(false),
                        Some(String::from("kernel_interface_not_found")),
                    )
                };

            let compatible_flag = compatible.unwrap_or(false);
            all_compatible &= compatible_flag;

            Self::map_insert(&mut m, "interface", Self::vstr(dep.interface.clone()));
            Self::map_insert(&mut m, "required_hash_hex", Self::vstr(format!("{:#x}", dep.hash)));
            Self::map_insert(
                &mut m,
                "required_min_version",
                Self::vstr(format!("{}", dep.min_version)),
            );
            Self::map_insert(&mut m, "kernel_present", Self::opt_bool(kernel_present));
            Self::map_insert(&mut m, "kernel_hash_hex", Self::opt_string(kernel_hash_hex));
            Self::map_insert(&mut m, "kernel_version", Self::opt_string(kernel_version));
            Self::map_insert(&mut m, "hash_match", Self::opt_bool(hash_match));
            Self::map_insert(
                &mut m,
                "version_compatible",
                Self::opt_bool(version_compatible),
            );
            Self::map_insert(&mut m, "compatible", Self::opt_bool(compatible));
            Self::map_insert(&mut m, "error", Self::opt_string(error));
            dep_vals.push(ExoValue::Map(m));
        }

        let verify_ok = crate::loader::type_id::verify_cell_dependencies(&deps).is_ok() && all_compatible;

        Self::map_insert(&mut out, "abi_metadata_present", ExoValue::Bool(true));
        Self::map_insert(&mut out, "verify_ok", ExoValue::Bool(verify_ok));
        Self::map_insert(&mut out, "cell_version", Self::vstr(format!("{}", deps.cell_version)));
        Self::map_insert(
            &mut out,
            "dependency_count",
            Self::vint_usize(deps.dependencies.len()),
        );
        Self::map_insert(&mut out, "dependencies", ExoValue::Array(dep_vals));
        ExoValue::Map(out)
    }

    fn dispatch_epoch_status() -> ExoValue<'static> {
        let stats = crate::epoch::stats();
        let current_epoch = stats.current_epoch;
        let target_epoch = current_epoch.saturating_sub(1);

        let mut epoch = BTreeMap::new();
        Self::map_insert(&mut epoch, "current_epoch", Self::vint_u64(stats.current_epoch));
        Self::map_insert(
            &mut epoch,
            "deferred_queue_size",
            Self::vint_usize(stats.deferred_queue_size),
        );
        Self::map_insert(&mut epoch, "active_cores", Self::vint_usize(stats.active_cores));

        let mut validating_cells = Vec::new();
        for snap in driver_domain::driver_domain_manager().list_snapshots() {
            if snap.hot_swap_state != HotSwapState::Validating {
                continue;
            }
            let health_failed = hot_swap::health_status(snap.id)
                .map(|h| h.health_failed)
                .unwrap_or(false);
            let mut m = BTreeMap::new();
            Self::map_insert(&mut m, "driver_domain_id", Self::vint_u64(snap.id.as_u64()));
            Self::map_insert(&mut m, "name", Self::vstr(snap.name));
            Self::map_insert(
                &mut m,
                "loader_cell_id",
                Self::opt_u64(snap.cell_id.map(|c| c.as_u64())),
            );
            Self::map_insert(
                &mut m,
                "validation_deadline_tick",
                Self::opt_u64(snap.validation_deadline_tick),
            );
            Self::map_insert(&mut m, "health_failed", ExoValue::Bool(health_failed));
            validating_cells.push(ExoValue::Map(m));
        }

        let mut quiescent_check = BTreeMap::new();
        Self::map_insert(&mut quiescent_check, "target_epoch", Self::vint_u64(target_epoch));
        Self::map_insert(
            &mut quiescent_check,
            "all_cores_past",
            ExoValue::Bool(crate::epoch::all_cores_past_epoch(target_epoch)),
        );

        let mut out = BTreeMap::new();
        Self::map_insert(&mut out, "epoch", ExoValue::Map(epoch));
        Self::map_insert(
            &mut out,
            "live_update_epoch",
            Self::vint_u64(crate::loader::live_update::current_epoch()),
        );
        Self::map_insert(&mut out, "validating_cells", ExoValue::Array(validating_cells));
        Self::map_insert(&mut out, "quiescent_check", ExoValue::Map(quiescent_check));
        ExoValue::Map(out)
    }

    fn dispatch_wait_quiescent(
        args: &[ExoValue<'static>],
        caps: &CapabilitySet,
    ) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_ADMIN, "cell.wait_quiescent") {
            return e;
        }
        let (target_epoch, max_attempts) = match Self::parse_epoch_wait_args(args) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let reached = crate::epoch::wait_for_quiescent_state(target_epoch, max_attempts);
        let mut out = BTreeMap::new();
        Self::map_insert(&mut out, "target_epoch", Self::vint_u64(target_epoch));
        Self::map_insert(&mut out, "max_attempts", Self::vint_u64(max_attempts));
        Self::map_insert(&mut out, "reached", ExoValue::Bool(reached));
        Self::map_insert(
            &mut out,
            "current_epoch",
            Self::vint_u64(crate::epoch::current_epoch()),
        );
        ExoValue::Map(out)
    }

    fn dispatch_load(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_MODULE, "cell.load") {
            return e;
        }

        let (path, name_override, allow_unsafe) = match Self::parse_load_options(args) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let name = name_override.unwrap_or_else(|| Self::infer_name_from_path(&path));
        if name.is_empty() {
            return ExoValue::Error(String::from("Failed to infer cell name from path; specify opts.name"));
        }

        if driver_domain::driver_domain_manager().find_by_name(&name).is_some() {
            return ExoValue::Error(format!("DriverCell '{}' already exists", name));
        }

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        let content = match shell.read_file_zero_copy(&path) {
            Ok(c) => c,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        match lifecycle::create_and_start_default(&name, &content, allow_unsafe) {
            Ok((driver_domain_id, handles)) => {
                let handle_list = handles
                    .iter()
                    .map(|h| ExoValue::Int(core::cmp::min(h.index() as u64, i64::MAX as u64) as i64))
                    .collect::<Vec<_>>();
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "success", ExoValue::Bool(true));
                Self::map_insert(
                    &mut map,
                    "driver_domain_id",
                    Self::vint_u64(driver_domain_id.as_u64()),
                );
                Self::map_insert(&mut map, "driver_handles", ExoValue::Array(handle_list));
                Self::map_insert(&mut map, "name", Self::vstr(name.clone()));
                Self::map_insert(
                    &mut map,
                    "message",
                    Self::vstr(format!(
                        "DriverCell '{}' loaded and started (id={})",
                        name,
                        driver_domain_id.as_u64()
                    )),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("cell.load failed: {}", e)),
        }
    }

    fn dispatch_swap(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_MODULE, "cell.swap") {
            return e;
        }

        let id = match Self::resolve_driver_domain_ref(args) {
            Ok(id) => id,
            Err(e) => return e,
        };
        let path = match Self::parse_path_arg(args, 1, "Usage: cell.swap(id_or_name, path)") {
            Ok(p) => p,
            Err(e) => return e,
        };

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        let content = match shell.read_file_zero_copy(&path) {
            Ok(c) => c,
            Err(e) => return ExoValue::Error(format!("Failed to read file '{}': {}", path, e)),
        };

        match hot_swap::hot_swap(id, &content) {
            Ok(result) => {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "success", ExoValue::Bool(true));
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(id.as_u64()));
                Self::map_insert(
                    &mut map,
                    "old_loader_cell_id",
                    Self::vint_u64(result.old_cell_id.as_u64()),
                );
                Self::map_insert(
                    &mut map,
                    "new_loader_cell_id",
                    Self::vint_u64(result.new_cell_id.as_u64()),
                );
                Self::map_insert(
                    &mut map,
                    "duration_ticks",
                    Self::vint_u64(result.duration_ticks),
                );
                Self::map_insert(
                    &mut map,
                    "needs_rollback",
                    ExoValue::Bool(result.needs_rollback),
                );
                Self::map_insert(
                    &mut map,
                    "message",
                    Self::vstr(format!(
                        "DriverCell {} swapped: {} -> {}",
                        id.as_u64(),
                        result.old_cell_id.as_u64(),
                        result.new_cell_id.as_u64()
                    )),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("cell.swap failed: {}", e)),
        }
    }

    fn dispatch_unload(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_MODULE, "cell.unload") {
            return e;
        }
        let id = match Self::resolve_driver_domain_ref(args) {
            Ok(id) => id,
            Err(e) => return e,
        };
        match lifecycle::unload(id) {
            Ok(()) => {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "success", ExoValue::Bool(true));
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(id.as_u64()));
                Self::map_insert(
                    &mut map,
                    "message",
                    Self::vstr(format!("DriverCell {} unloaded successfully", id.as_u64())),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to unload DriverCell {}: {}", id.as_u64(), e)),
        }
    }

    fn dispatch_rollback(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_ADMIN, "cell.rollback") {
            return e;
        }
        let id = match Self::resolve_driver_domain_ref(args) {
            Ok(id) => id,
            Err(e) => return e,
        };
        match hot_swap::rollback(id) {
            Ok(()) => {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "success", ExoValue::Bool(true));
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(id.as_u64()));
                Self::map_insert(
                    &mut map,
                    "message",
                    Self::vstr(format!("DriverCell {} rollback completed", id.as_u64())),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Rollback failed: {}", e)),
        }
    }

    fn dispatch_commit(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_ADMIN, "cell.commit") {
            return e;
        }
        let id = match Self::resolve_driver_domain_ref(args) {
            Ok(id) => id,
            Err(e) => return e,
        };
        match hot_swap::commit(id) {
            Ok(()) => {
                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "success", ExoValue::Bool(true));
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(id.as_u64()));
                Self::map_insert(
                    &mut map,
                    "message",
                    Self::vstr(format!("DriverCell {} update committed", id.as_u64())),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Commit failed: {}", e)),
        }
    }

    #[cfg(feature = "qemu-test-export")]
    fn dispatch_debug_fault(args: &[ExoValue<'static>], caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_cap(caps, CAP_SYS_ADMIN, "cell.debug_fault") {
            return e;
        }
        let id = match Self::resolve_driver_domain_ref(args) {
            Ok(id) => id,
            Err(e) => return e,
        };

        let kind = match args.get(1) {
            None => TestFaultKind::Panic,
            Some(ExoValue::String(s)) => match TestFaultKind::parse(s.as_ref()) {
                Some(k) => k,
                None => {
                    return ExoValue::Error(String::from(
                        "Usage: cell.debug_fault(id_or_name, \"panic\"|\"timeout\"|\"other\")",
                    ))
                }
            },
            _ => {
                return ExoValue::Error(String::from(
                    "Usage: cell.debug_fault(id_or_name, \"panic\"|\"timeout\"|\"other\")",
                ))
            }
        };

        match fault::inject_test_fault(id, kind) {
            Ok(outcome) => {
                crate::loader::live_update::poll_pending_updates();
                hot_swap::poll_validation_windows();

                let mut map = BTreeMap::new();
                Self::map_insert(&mut map, "success", ExoValue::Bool(true));
                Self::map_insert(&mut map, "driver_domain_id", Self::vint_u64(id.as_u64()));
                Self::map_insert(
                    &mut map,
                    "requested_kind",
                    Self::vstr(format!("{}", outcome.requested_kind)),
                );
                Self::map_insert(&mut map, "action", Self::vstr(format!("{}", outcome.action)));
                Self::map_insert(
                    &mut map,
                    "driver_domain_state_after",
                    Self::vstr(format!("{}", outcome.driver_domain_state_after)),
                );
                Self::map_insert(
                    &mut map,
                    "hot_swap_state_after",
                    Self::vstr(format!("{}", outcome.hot_swap_state_after)),
                );
                Self::map_insert(
                    &mut map,
                    "consecutive_faults_after",
                    Self::vint_u64(outcome.consecutive_faults_after as u64),
                );
                Self::map_insert(
                    &mut map,
                    "last_health_failure_after",
                    Self::opt_string(outcome.last_health_failure_after),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("Failed to inject debug fault: {}", e)),
        }
    }
}

impl ShellNamespace for CellNamespace {
    fn name(&self) -> &str {
        "cell"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "list" => Self::dispatch_list(),
                "info" => Self::dispatch_info(args),
                "stats" => Self::dispatch_info(args),
                "health" => Self::dispatch_info(args),
                "graph" => Self::dispatch_graph(),
                "inspect_artifact" => Self::dispatch_inspect_artifact(args),
                "epoch_status" => Self::dispatch_epoch_status(),
                "wait_quiescent" => Self::dispatch_wait_quiescent(args, caps),
                "load" => Self::dispatch_load(args, caps),
                "swap" => Self::dispatch_swap(args, caps),
                "update" => Self::dispatch_swap(args, caps),
                "unload" => Self::dispatch_unload(args, caps),
                "rollback" => Self::dispatch_rollback(args, caps),
                "commit" => Self::dispatch_commit(args, caps),
                #[cfg(feature = "qemu-test-export")]
                "debug_fault" => Self::dispatch_debug_fault(args, caps),
                _ => Self::err_unknown_method(method),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver_domain::lifecycle::DriverDomainConfig;
    use futures::executor::block_on;

    #[test_case]
    fn test_list_returns_array() {
        let val = CellNamespace::dispatch_list();
        assert!(matches!(val, ExoValue::Array(_)));
    }

    #[test_case]
    fn test_resolve_driver_domain_id_numeric() {
        let v = ExoValue::Int(42);
        let id = CellNamespace::resolve_driver_domain_id(&v).unwrap();
        assert_eq!(id.as_u64(), 42);
    }

    #[test_case]
    fn test_resolve_driver_domain_ref_name_not_found() {
        let args = [CellNamespace::vstr("definitely_missing_driver_domain_name")];
        let res = CellNamespace::resolve_driver_domain_ref(&args);
        assert!(matches!(res, Err(ExoValue::Error(_))));
    }

    #[test_case]
    fn test_resolve_driver_domain_ref_name_exists() {
        let name = "cell_ns_test_exists";
        if let Some(existing) = crate::driver_domain::driver_domain_manager().find_by_name(name) {
            let _ = crate::driver_domain::driver_domain_manager().remove(existing);
        }

        let id = crate::driver_domain::lifecycle::create(&DriverDomainConfig::new(name)).unwrap();
        let args = [CellNamespace::vstr(name)];
        let resolved = CellNamespace::resolve_driver_domain_ref(&args).unwrap();
        assert_eq!(resolved.as_u64(), id.as_u64());

        let _ = crate::driver_domain::driver_domain_manager().remove(id);
    }

    #[test_case]
    fn test_wait_quiescent_requires_admin_cap() {
        let ns = CellNamespace;
        let caps = CapabilitySet::empty();
        let args = [ExoValue::Int(0)];
        let res = block_on(ns.call("wait_quiescent", &args, &caps));
        match res {
            ExoValue::Error(s) => assert!(s.contains("Permission denied")),
            _ => panic!("expected permission error"),
        }
    }

    #[test_case]
    fn test_wait_quiescent_returns_structured_map() {
        let ns = CellNamespace;
        let caps = CapabilitySet::full();
        let args = [ExoValue::Int(0), ExoValue::Int(1)];
        let res = block_on(ns.call("wait_quiescent", &args, &caps));
        match res {
            ExoValue::Map(m) => {
                assert!(m.contains_key("target_epoch"));
                assert!(m.contains_key("max_attempts"));
                assert!(m.contains_key("reached"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test_case]
    fn test_mutating_api_requires_module_cap() {
        let ns = CellNamespace;
        let caps = CapabilitySet::empty();
        let args = [CellNamespace::vstr("dummy"), CellNamespace::vstr("/tmp/x.cell")];
        let res = block_on(ns.call("swap", &args, &caps));
        match res {
            ExoValue::Error(s) => assert!(s.contains("CAP_SYS_MODULE")),
            _ => panic!("expected permission error"),
        }
    }

    #[test_case]
    fn test_update_alias_uses_same_permission_gate_as_swap() {
        let ns = CellNamespace;
        let caps = CapabilitySet::empty();
        let args = [CellNamespace::vstr("dummy"), CellNamespace::vstr("/tmp/x.cell")];
        let swap_res = block_on(ns.call("swap", &args, &caps));
        let update_res = block_on(ns.call("update", &args, &caps));
        assert_eq!(swap_res, update_res);
    }
}
