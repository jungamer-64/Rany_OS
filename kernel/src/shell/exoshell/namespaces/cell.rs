// ============================================================================
// kernel/src/shell/exoshell/namespaces/cell.rs - Cell Management Namespace
// ============================================================================
//
// Provides commands to manage loaded cells (hot-swappable components/drivers).
//

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::loader::{unload_cell, with_registry, CellId};
use crate::shell::exoshell::parser::ParseError;
use crate::shell::exoshell::ExoValue;

pub struct CellNamespace;

impl CellNamespace {
    /// Dispatch methods for 'cell' namespace
    pub fn dispatch(
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        match method {
            "list" => {
                let cells = with_registry(|r| r.list());
                let mut output = String::from(" ID | Name                 | Size   | Drivers \n");
                output.push_str("----|----------------------|--------|---------\n");

                for cell in cells {
                    output.push_str(&format!(
                        "{:3} | {:20} | {:6} | {:7} \n",
                        cell.id.as_u64(),
                        cell.name,
                        format_size(cell.size),
                        cell.driver_count
                    ));
                }
                ExoValue::String(output.into())
            }
            "stats" => {
                let id = match args.first() {
                    Some(ExoValue::Int(n)) => *n as u64,
                    Some(ExoValue::String(s)) => s.parse().unwrap_or(0),
                    _ => return ExoValue::Error(String::from("Usage: cell.stats(id)")),
                };

                with_registry(|r| {
                    if let Some(cell) = r.get(CellId::from_u64(id)) {
                        let mut output = format!("Cell Stats: {}\n", cell.name);
                        output.push_str(&format!("  ID: {}\n", cell.id.as_u64()));
                        output.push_str(&format!("  Base Address: {:#x}\n", cell.load_address));
                        output.push_str(&format!("  Size: {} bytes\n", cell.load_size));
                        output.push_str("  Exports:\n");
                        for (name, addr) in &cell.exports {
                            output.push_str(&format!("    - {}: {:#x}\n", name, addr));
                        }
                        output.push_str("  Registered Drivers:\n");
                        for handle in &cell.registered_drivers {
                             // Assuming we can resolve driver name from registry, but strictly we are in loader lock?
                             // Loader registry doesn't lock driver registry. Driver registry has its own lock.
                             // Safe to call driver_registry().name().
                             let name = crate::driver_registry::driver_registry().name(*handle).unwrap_or_default();
                             output.push_str(&format!("    - Handle {}: {}\n", handle.index(), name));
                        }
                        ExoValue::String(output.into())
                    } else {
                        ExoValue::Error(format!("Cell ID {} not found", id))
                    }
                })
            }
            "unload" => {
                let id = match args.first() {
                    Some(ExoValue::Int(n)) => *n as u64,
                    Some(ExoValue::String(s)) => s.parse().unwrap_or(0),
                    _ => return ExoValue::Error(String::from("Usage: cell.unload(id)")),
                };

                if id == 0 {
                    return ExoValue::Error(String::from("Cannot unload Kernel cell (ID 0)"));
                }

                match unload_cell(CellId::from_u64(id)) {
                    Ok(_) => ExoValue::String(format!("Cell {} unloaded successfully", id).into()),
                    Err(e) => ExoValue::Error(format!("Failed to unload cell {}: {:?}", id, e)),
                }
            }
            "reload" => {
                ExoValue::Error(String::from("reload() is not yet implemented"))
            }
            _ => ExoValue::Error(
                ParseError::UnknownMethod {
                    namespace: String::from("cell"),
                    method: String::from(method),
                }
                .to_string()
                    + "\nValid methods: list, stats, unload, reload",
            ),
        }
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} MB", bytes / 1024 / 1024)
    }
}
