# Deprecations and Migration Guide

This document lists symbols that have been marked deprecated and recommended migration paths. It's intended to help reviewers and integrators migrate away from legacy APIs gradually.

## Kernel

- `kernel/src/application/mod.rs`
  - `AppHandle` ✅ **deprecated**
    - Migration: Use `crate::domain_system::DomainId` and the canonical domain APIs.
  - `app_count()` ✅ **deprecated**
    - Migration: Use `domain_count()`.

- `kernel/src/lib.rs` (test shim)
  - `crate::task::current_tick()` ❌ **removed** (was deprecated)
    - Migration: Use `crate::task::timer::current_tick()` directly in tests/benches.

- `kernel/src/fs/mod.rs` (fs alias)
  - `vfs` alias ❌ **removed**
    - Replacement: Use `fs_abstraction` directly to make the optional layer explicit.
  - `Fat32FileSystem` alias ❌ **removed**
    - Replacement: Use `filesystems::fat32::Fat32FileSystem` or `fs_abstraction` directly.

- `kernel/src/io/log.rs`
  - `LOG_AGGREGATOR_PRIORITY`, `AGGREGATOR_STARTED`, `spawn_log_aggregator()` ✅ **deprecated**
    - Migration: Aggregation is performed from the executor idle loop. Use `kick_serial_tx()` to request aggregation from non-idle contexts.
  - `io_log_info!`, `io_log_warn!`, `io_log_debug!`, `io_log_error!` ✅ **deprecated**
    - Migration: Use `log::info!`, `log::warn!`, `log::debug!`, `log::error!`.

- `kernel/src/graphics/global.rs`
  - `with_console` ❌ **removed**
    - Migration: Use `crate::console::with_console(console_id, f)` or `crate::console::write()` and ConsoleManager APIs.

- `kernel/src/io/hid/mod.rs`
  - Compatibility aliases (`InputKeyCode`, `InputKeyEvent`, `InputKeyState`, `InputModifiers`) ✅ **deprecated**
    - Migration: Use `KeyCode`, `KeyEvent`, `KeyState`, `Modifiers` directly.
  - `has_key_event()` ✅ **deprecated**
    - Migration: Use `keyboard::has_event()` or the `KeyboardStream` async API.
  - `MouseBtn`, `MouseEvt` ✅ **deprecated**
    - Migration: Use `MouseButton` and `MouseEvent` directly.
  - PS/2 helpers (`get_key_event`, `get_modifiers`, `get_mouse_event`) ❌ **removed**
    - Migration: Prefer `KeyboardStream` or unified HID driver APIs; use `keyboard::take_stream()` or `keyboard::has_event()` instead.
  - Internal polling shims (`poll_key_char`, `poll_key_event`, `poll_input_event`) ✅ **deprecated**
    - Migration: Use `KeyboardStream` and the async stream APIs.
  - PS/2 alias types (`Ps2DeviceType`, `Ps2KeyCode`, `Ps2KeyEvent`, `Ps2Modifiers`) ✅ **deprecated**
    - Migration: Use generic `KeyCode`, `KeyEvent`, `DeviceType`, `Modifiers` or `hid_driver` types directly.
  - Mouse polling helpers (`has_mouse_event`, `poll_mouse_event`) ✅ **deprecated**
    - Migration: Use event-driven `MouseEvent` streams or `mouse::has_event()`.
  - HID extension traits (`KeyCodeExt`, `KeyEventExt`) ✅ **deprecated**
    - Migration: Bring traits into scope from `hid_driver` directly (e.g., `use hid_driver::KeyEventExt`).  - `ModifierState` re-export ✅ **deprecated**
    - Migration: Use `hid_driver::ModifierState` directly.
  - `IsrSafeWaker` re-export ✅ **deprecated**
    - Migration: Use `hid_driver::IsrSafeWaker` directly.

- `kernel/src/io/hid/keyboard.rs`
  - `keyboard()` ✅ **deprecated**
    - Migration: Acquire a `KeyboardStream` via `take_stream()` or initialize the keyboard via `crate::io::hid::keyboard_init()`.
  - `init()` ✅ **deprecated**
    - Migration: Use `crate::io::hid::keyboard_init()` or initialize via the PS/2 controller API.
  - `handle_keyboard_interrupt()` ✅ **deprecated**
    - Migration: Use the PS/2 controller's `keyboard_interrupt_handler` or register the handler on the controller.
  - `take_stream_or_panic()` ✅ **deprecated**
    - Migration: Use `take_stream()` and handle `StreamAlreadyTaken` errors; avoid panics in production code.

- IO-level re-exports (deprecated to propagate HID deprecations to `crate::io` namespace)
  - `io::get_key_event` ❌ **removed**
    - Migration: Use `KeyboardStream` or `keyboard::has_event()` instead.
  - `io::get_modifiers` ❌ **removed**
    - Migration: Use `keyboard` APIs or `KeyboardStream` instead.
  - `io::get_mouse_event` ❌ **removed**
    - Migration: Use `MouseEvent` streams or `mouse::poll_event` instead.
  - `io::handle_keyboard_interrupt` ✅ **deprecated**
    - Migration: Register the PS/2 driver's interrupt handler via the DriverRegistry or use `keyboard_interrupt_handler` directly.
  - `io::keyboard` ✅ **deprecated**
    - Migration: Acquire a `KeyboardStream` via `crate::io::hid::keyboard::take_stream()` or call `crate::io::hid::keyboard_init()`.
  - `io::keyboard_init` ✅ **deprecated**
    - Migration: Prefer `crate::io::hid::keyboard_init()` or registering the PS/2 driver via `driver_registry::register_driver`.
  - `io::ps2_init` ❌ **removed**
    - Migration: Register the PS/2 driver with `driver_registry::register_driver(Box::new(Ps2Driver::new()))` or call `crate::io::hid::ps2::init()` directly.
  - `io::ps2_ports` ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::ports` or `Ps2Controller` APIs directly.
  - `io::ps2_status` ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::status` or `ps2::status` directly.
  - `io::set_leds` ✅ **deprecated**
    - Migration: Use `crate::io::hid::ps2::set_leds` or `Ps2Controller::set_leds` instead.
  - `ps2_commands` (hid top-level re-export) ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::commands` directly or prefer `Ps2Controller` APIs instead of top-level re-exports.
  - `io::ps2_commands` ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::commands` or `Ps2Controller` APIs instead.
  - `ps2_kbd_commands` ✅ **deprecated**
    - Migration: Use `crate::io::hid::ps2::kbd_commands` or `Ps2Controller` helpers instead.
  - `io::ps2_kbd_commands` ✅ **deprecated**
    - Migration: Use `crate::io::hid::ps2::kbd_commands` or `Ps2Controller` helpers instead.
  - `ps2_mouse_commands` ✅ **deprecated**
    - Migration: Use `crate::io::hid::ps2::mouse_commands` or `Ps2Controller` helpers instead.
  - `io::ps2_mouse_commands` ✅ **deprecated**
    - Migration: Use `crate::io::hid::ps2::mouse_commands` or `Ps2Controller` helpers instead.

## Notes

- `kernel/src/io/ahci_atapi.rs`
  - Re-export of `ahci_driver::atapi` ✅ **deprecated**
    - Migration: Use `ahci_driver::atapi` directly.

- `kernel/src/io/virtio/net.rs`
  - `notify_addr` field ✅ **deprecated**
    - Migration: Prefer transport-level notify configuration and the `notify` methods on the virtio transport; use interrupt-driven notifications instead of per-queue MMIO `notify_addr` where possible.

- `kernel/src/net` (TCP/Socket APIs)
  - POSIX-style socket compatibility methods (e.g., `Socket::bind`, `Socket::connect`, `Socket::listen`, `Socket::accept`, `TcpStream::connect`, `TcpListener::bind`/`accept`) ❌ **removed**
    - Removal: These compatibility wrappers have been removed; migrate to the async-first APIs: `set_local_addr()`, `open_connection()`, `start_listening()`/`next_connection()`, and `dial()`/`TcpStream::dial()`.

- `kernel/src/io/mod.rs`
  - `parse_dmar_table()` ✅ **deprecated**
    - Migration: Call `acpi::dmar::parse_dmar` directly.

- `kernel/src/shell/graphical/render.rs`
  - `redraw_input_only()` ✅ **deprecated**
    - Migration: Use `redraw_input_line()`.

- `kernel/src/kernel_content.rs`
  - `pub use serial_driver::serial_print(ln)` ❌ **removed** (prefer kernel logging APIs)
    - Replacement: Use `crate::io::log::early_print` or `log` macros once available.

- `kernel/src/task/executor.rs`
  - `TASK_STORE` (legacy global task store) ✅ **deprecated**
    - Migration: Use per-core task stores (`PER_CORE_STORES`) and the per-core APIs; avoid using the global `TASK_STORE`.

## Drivers

- `drivers/pci` (`drivers/pci/src/lib.rs`)
  - `LegacyPciAccessor` ❌ **removed** (was deprecated)
    - Migration: Use `pci_driver::EcamAccess` or the new PCI APIs instead. The internal helper remains in `drivers/pci::legacy` but is no longer publicly re-exported.
  - `get_legacy_accessor()` ❌ **removed** (was deprecated)
    - Migration: Prefer `pci_driver` accessors or ECAM APIs; for internal debugging use `drivers::pci::legacy::get_legacy_accessor` if necessary.

- `drivers/serial` (`drivers/serial/src/lib.rs`)
  - `serial_print!`, `serial_println!` macros ❌ **removed**
    - Replacement: Use `crate::io::log::early_print` or the `log` crate for structured logging.
  - `serial1()` ❌ **removed**
    - Replacement: Use `crate::io::log::early_print` or `log::info!`/`log::debug!` instead of using the `AsyncSerialPort` global.
  - `init()` ❌ **removed** (was deprecated)
    - Replacement: Register the serial driver with `driver_registry::register_driver(Box::new(SerialDriver::new()))` and let the DriverRegistry perform initialization.
  - `handle_interrupt()` ❌ **removed**
    - Replacement: Prefer driver-registered interrupt handling via the DriverRegistry or the driver's interrupt methods; use `serial::dispatch_interrupt()` for direct dispatch in low-level code.

## Notes

- These deprecations are intentionally incremental and conservative — each change adds a `#[deprecated]` attribute and helpful migration notes. The aim is to show compile-time warnings and give downstream code time to migrate.
- Workspace-level full builds may still fail due to unrelated driver compile issues (e.g. `drivers/nvme`). Deprecation commits are small and intended to be low-risk.

If you want, I can:

- Continue deprecating additional kernel-level compatibility shims (low-risk) ✅
- Start deprecating driver-level compatibility re-exports more aggressively (riskier; may require driver fixes) ⚠️

Which would you prefer next? (kernel-only / include-drivers)
