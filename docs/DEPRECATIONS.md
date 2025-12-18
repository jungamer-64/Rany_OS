# Deprecations and Migration Guide

This document lists symbols that have been marked deprecated and recommended migration paths. It's intended to help reviewers and integrators migrate away from legacy APIs gradually.

## Kernel

- `kernel/src/application/mod.rs`
  - `AppHandle` ✅ **deprecated**
    - Migration: Use `crate::domain_system::DomainId` and the canonical domain APIs.
  - `app_count()` ✅ **deprecated**
    - Migration: Use `domain_count()`.

- `kernel/src/lib.rs` (test shim)
  - `crate::task::current_tick()` ✅ **deprecated**
    - Migration: Use `crate::task::timer::current_tick()` directly in tests/benches.

- `kernel/src/io/log.rs`
  - `LOG_AGGREGATOR_PRIORITY`, `AGGREGATOR_STARTED`, `spawn_log_aggregator()` ✅ **deprecated**
    - Migration: Aggregation is performed from the executor idle loop. Use `kick_serial_tx()` to request aggregation from non-idle contexts.
  - `io_log_info!`, `io_log_warn!`, `io_log_debug!`, `io_log_error!` ✅ **deprecated**
    - Migration: Use `log::info!`, `log::warn!`, `log::debug!`, `log::error!`.

- `kernel/src/io/hid/mod.rs`
  - Compatibility aliases (`InputKeyCode`, `InputKeyEvent`, `InputKeyState`, `InputModifiers`) ✅ **deprecated**
    - Migration: Use `KeyCode`, `KeyEvent`, `KeyState`, `Modifiers` directly.
  - `has_key_event()` ✅ **deprecated**
    - Migration: Use `keyboard::has_event()` or the `KeyboardStream` async API.
  - Internal polling shims (`poll_key_char`, `poll_key_event`, `poll_input_event`) ✅ **deprecated**
    - Migration: Use `KeyboardStream` and the async stream APIs.

- `kernel/src/io/ahci_atapi.rs`
  - Re-export of `ahci_driver::atapi` ✅ **deprecated**
    - Migration: Use `ahci_driver::atapi` directly.

- `kernel/src/io/mod.rs`
  - `parse_dmar_table()` ✅ **deprecated**
    - Migration: Call `acpi::dmar::parse_dmar` directly.

- `kernel/src/shell/graphical/render.rs`
  - `redraw_input_only()` ✅ **deprecated**
    - Migration: Use `redraw_input_line()`.

- `kernel/src/kernel_content.rs`
  - `pub use serial_driver::serial_print(ln)` ✅ **deprecated** (prefer kernel logging APIs)
    - Migration: Use `crate::io::log::early_print` or `log` macros once available.

## Drivers

- `drivers/pci` (`drivers/pci/src/lib.rs`)
  - `LegacyPciAccessor` ✅ **deprecated**
  - `get_legacy_accessor()` ✅ **deprecated**
    - Migration: Use the new `pci_driver` ECAM-based APIs (`EcamAccess`, `PciBusScanner`, etc.).

- `drivers/serial` (`drivers/serial/src/lib.rs`)
  - `serial_print!`, `serial_println!` macros ✅ **deprecated**
    - Migration: Use `crate::io::log::early_print` or the `log` crate for structured logging.

## Notes

- These deprecations are intentionally incremental and conservative — each change adds a `#[deprecated]` attribute and helpful migration notes. The aim is to show compile-time warnings and give downstream code time to migrate.
- Workspace-level full builds may still fail due to unrelated driver compile issues (e.g. `drivers/nvme`). Deprecation commits are small and intended to be low-risk.

If you want, I can:

- Continue deprecating additional kernel-level compatibility shims (low-risk) ✅
- Start deprecating driver-level compatibility re-exports more aggressively (riskier; may require driver fixes) ⚠️

Which would you prefer next? (kernel-only / include-drivers)
