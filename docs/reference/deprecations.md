# 廃止済み API と移行ガイド

- Status: Reference
- Audience: deprecated symbol の移行を進める実装者、レビュー担当者、integrator
- Related: [ドキュメントハブ](../README.md), [API リファレンス](api-reference.md), [アーキテクチャ概要](../architecture.md)

This document lists symbols that have been marked deprecated and recommended migration paths. It is intended to help reviewers and integrators migrate away from legacy APIs gradually.

## Kernel

- Former kernel-side application lifecycle module
  - `AppHandle` ❌ **removed**
    - Migration: Use `crate::domain::DomainId` and the canonical domain APIs.
  - `app_count()` ❌ **removed**
    - Migration: Use `domain_count()`.

- `kernel/src/task/timer.rs`
  - `crate::task::timer::*` ❌ **removed**
    - Migration: Use the canonical root-level task time APIs directly, e.g. `crate::task::current_tick()`, `crate::task::sleep_ms()`, `crate::task::handle_timer_interrupt()`, `crate::task::process_pending_timer_wakers()`.

- `kernel/src/fs/mod.rs` (fs alias)
  - Legacy filesystem aliases ❌ **removed**
    - Replacement: Use `crate::fs::block::*` for shared block I/O or `crate::fs::{DirEntry, FileMode, FileType, OpenFlags}` for the local filesystem model.
  - Legacy on-disk parser helpers ✅ **deprecated**
    - Migration: Use the active parser APIs directly instead of compatibility aliases.

- `kernel/src/io/log.rs`
  - `LOG_AGGREGATOR_PRIORITY`, `AGGREGATOR_STARTED`, `spawn_log_aggregator()` ❌ **removed**
    - Migration: Aggregation is performed from the executor idle loop. Use `kick_serial_tx()` to request aggregation from non-idle contexts.
  - `io_log_info!`, `io_log_warn!`, `io_log_debug!`, `io_log_error!` ❌ **removed**
    - Migration: Use `log::info!`, `log::warn!`, `log::debug!`, `log::error!`.

- `kernel/src/graphics/global.rs`
  - `with_console` ❌ **removed**
    - Migration: Use `crate::console::with_console(console_id, f)` or `crate::console::write()` and ConsoleManager APIs.

- `kernel/src/io/hid/mod.rs`
  - Compatibility aliases (`InputKeyCode`, `InputKeyEvent`, `InputKeyState`, `InputModifiers`) ❌ **removed**
    - Migration: Use `KeyCode`, `KeyEvent`, `KeyState`, `Modifiers` directly.
  - `has_key_event()` ❌ **removed**
    - Migration: Use `keyboard::has_event()` or the `KeyboardStream` async API.
  - `MouseBtn`, `MouseEvt` ❌ **removed**
    - Migration: Use `MouseButton` and `MouseEvent` directly.
  - PS/2 helpers (`get_key_event`, `get_modifiers`, `get_mouse_event`) ❌ **removed**
    - Migration: Prefer `KeyboardStream` or unified HID driver APIs; use `keyboard::take_stream()` or `keyboard::has_event()` instead.
  - `drivers/hid` PS/2 convenience accessors (`ps2::get_key_event`, `ps2::get_mouse_event`, `ps2::get_modifiers`) ❌ **removed**
    - Migration: Use `KeyboardStream` (via `crate::io::hid::keyboard::take_stream()`), `MouseHandler::pop_event()`, or driver-level APIs instead.
  - Internal polling shims (`poll_key_char`, `poll_key_event`, `poll_input_event`) ✅ **deprecated**
    - Migration: Use `KeyboardStream` and the async stream APIs.
  - PS/2 alias types (`Ps2DeviceType`, `Ps2KeyCode`, `Ps2KeyEvent`, `Ps2Modifiers`) ✅ **deprecated**
    - Migration: Use generic `KeyCode`, `KeyEvent`, `DeviceType`, `Modifiers` or `hid_driver` types directly.
  - Mouse polling helpers (`has_mouse_event`, `poll_mouse_event`) ❌ **removed**
    - Migration: Use event-driven `MouseEvent` streams or query the global `MOUSE` under an interrupts-disabled section, e.g. `x86_64::instructions::interrupts::without_interrupts(|| crate::io::hid::mouse::MOUSE.lock().poll_event())`.
  - HID extension traits (`KeyCodeExt`, `KeyEventExt`) and `StreamAlreadyTaken` re-export ❌ **removed**
    - Migration: Bring traits into scope from `hid_driver::keyboard` directly (e.g., `use hid_driver::keyboard::KeyEventExt`) and use `hid_driver::StreamAlreadyTaken` for stream-acquisition errors.
  - `set_leds` top-level re-export ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::set_leds(scroll, num, caps)` directly or call `Ps2Controller::set_keyboard_leds(...)`.
  - `ModifierState` re-export ✅ **deprecated**
    - Migration: Use `hid_driver::ModifierState` directly.
  - `IsrSafeWaker` re-export ✅ **deprecated**
    - Migration: Use `hid_driver::IsrSafeWaker` directly.

- `kernel/src/io/hid/keyboard.rs`
  - `keyboard()` ✅ **deprecated**
    - Migration: Acquire a `KeyboardStream` via `take_stream()` or initialize the keyboard via `crate::io::hid::keyboard_init()`.
  - `init()` ✅ **deprecated**
    - Migration: Use `crate::io::hid::keyboard_init()` or initialize via the PS/2 controller API.
  - `handle_keyboard_interrupt()` ❌ **removed** (was deprecated)
    - Migration: Use `take_stream()` and register the PS/2 driver's handler via the DriverRegistry or call `crate::io::hid::ps2::keyboard_interrupt_handler()`. This avoids using the removed convenience wrapper.
  - `take_stream_or_panic()` ✅ **deprecated**
    - Migration: Use `take_stream()` and handle `StreamAlreadyTaken` errors; avoid panics in production code.

- IO-level re-exports (deprecated to propagate HID deprecations to `crate::io` namespace)
  - `io::get_key_event` ❌ **removed**
    - Migration: Use `KeyboardStream` or `keyboard::has_event()` instead.
  - `io::get_modifiers` ❌ **removed**
    - Migration: Use `keyboard` APIs or `KeyboardStream` instead.
  - `io::get_mouse_event` ❌ **removed**
    - Migration: Use `MouseEvent` streams or `mouse::poll_event` instead.
  - `io::handle_keyboard_interrupt` ❌ **removed** (was deprecated)
    - Migration: Register the PS/2 driver's interrupt handler via the DriverRegistry (preferred) or call `keyboard_interrupt_handler` directly.
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
  - `io::set_leds` ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::set_leds` or `Ps2Controller::set_keyboard_leds` instead.
  - `ps2_commands` (hid top-level re-export) ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::commands` directly or prefer `Ps2Controller` APIs instead of top-level re-exports.
  - `io::ps2_commands` ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::commands` or `Ps2Controller` APIs instead.
  - `ps2::kbd_commands` ❌ **removed**
    - Migration: Prefer `Ps2Controller` helper methods instead of raw keyboard command constants.
  - `io::ps2::kbd_commands` ❌ **removed**
    - Migration: Prefer `Ps2Controller` helper methods instead of raw keyboard command constants.
  - `ps2_mouse_commands` ❌ **removed**
    - Migration: Prefer `Ps2Controller` helper methods instead of raw mouse command constants.
  - `io::ps2_mouse_commands` ❌ **removed**
    - Migration: Prefer `Ps2Controller` helper methods instead of raw mouse command constants.

## Notes

- `kernel/src/io/ahci_atapi.rs`
  - Re-export of `ahci_driver::atapi` ✅ **deprecated** (marked deprecated in `drivers/ahci` on 2026-01-17)
    - Migration: Use `ahci_driver::atapi` directly.

- `kernel/src/net/drivers/virtio/mod.rs`
  - `notify_addr` field ✅ **deprecated**
    - Migration: Prefer transport-level notify configuration and the `notify` methods on the virtio transport; use interrupt-driven notifications instead of per-queue MMIO `notify_addr` where possible.

- `kernel/src/net` (TCP/Socket APIs)
  - 旧トップレベル `crate::net::*` 直下ネットワークAPI / 再エクスポート ❌ **removed**
    - Replacement: 新階層へ移行 (`crate::net::api::{shell,diag}`, `crate::net::runtime::{stack,manager,bridge}`, `crate::net::l2/l3/l4`, `crate::net::services`, `crate::net::security`, `crate::net::datapath`, `crate::net::drivers`)。
    - 代表例:
      - `crate::net::get_network_config` -> `crate::net::api::shell::get_network_config`
      - `crate::net::get_network_stats` -> `crate::net::api::shell::get_network_stats`
      - `crate::net::send_icmp_echo` -> `crate::net::api::shell::enqueue_icmp_echo` (sync版は削除済み)
      - `crate::net::get_arp_cache` -> `crate::net::api::shell::get_arp_cache`
  - POSIX-style socket compatibility methods (e.g., `Socket::bind`, `Socket::connect`, `Socket::listen`, `Socket::accept`, `TcpStream::connect`, `TcpListener::bind`/`accept`) ❌ **removed**
    - Removal: These compatibility wrappers have been removed; migrate to the typed async APIs: `TcpStream::dial()` / `TcpStream::dial_scoped()`, `TcpListener::listen_on()` / `TcpListener::listen_on_scoped()`, `TcpListener::next_connection()`, and `UdpEndpoint::new()` / `UdpEndpoint::new_in()`.
  - `TcpListener::new` ❌ **removed** (was deprecated)
    - Migration: Use `TcpListener::listen_on(addr)`.
  - Legacy TCP processor / control-block internals ❌ **removed**
    - Migration: TCP state is now owned by `l4::endpoint` (`tcb_table + endpoint handler + network_event_task`). Public callers should use `TcpStream` / `TcpListener`; internal tests should target `TcpControlBlockEntry`, endpoint fixtures, or `TcpSegmentBuilder`.
  - Packet-oriented TCP KAPI helpers ❌ **removed**
    - Migration: Use stream/listener-oriented TCP KAPI: `net_tcp_connect`, `net_tcp_listen`, `net_tcp_accept`, `net_tcp_close_stream`, `net_tcp_close_listener`, `net_tcp_read`, `net_tcp_write`.
  - Legacy shared TCP KAPI endpoint type ❌ **removed**
    - Migration: Use `NetSocketAddr`, `TcpStreamHandle`, `TcpListenerHandle`, and `TcpChunk`. `Packet` / `RawEndpointHandle` remain available only for RAW endpoint operations.
  - UDP legacy bind wrappers (`UdpSocketTable::bind`, `UdpProcessor::bind`) ❌ **removed**
    - Migration: Use the token-aware API: `UdpSocketTable::bind_with_token(port, Some(token))`. For the no-token case use `UdpSocketTable::bind_with_token(port, None)` or the stack helper `bind_udp(port)`/`bind_udp_with_token(port, token)` as appropriate.

- `kernel/src/net/services/dhcp`
  - Default-runtime wrappers (`init()`, `init_v6()`, `legacy_v4_client_lock()`, `legacy_v6_client_lock()`) ❌ **removed**
    - Migration: Use runtime-aware APIs. DHCPv4 no longer exposes a singleton client lock; register/configure an interface and call `ensure_interface_runtime(if_id, config)`, then use `primary_v4_client_in(runtime)` or `interface_v4_client_in(runtime, if_id)`. DHCPv6 callers should use `init_v6_in(runtime, mac)` and `primary_v6_client_lock_in(runtime)`. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.
  - DHCPv4 compatibility singleton (`init_in(runtime, mac)`, `legacy_v4_client_lock_in(runtime)`) ❌ **removed**
    - Migration: Seed DHCP state through the per-interface runtime registry with `ensure_interface_runtime(if_id, config)` and read state via `primary_v4_client_in(runtime)` / `interface_v4_client_in(runtime, if_id)`.
  - DHCPv6 accessor `legacy_v6_client_lock_in(runtime)` ❌ **renamed**
    - Migration: Use `primary_v6_client_lock_in(runtime)`.

- `kernel/src/{net/drivers/virtio,integration/virtio_blk,console/virtio_console,console/virtio_input,mm/virtio_balloon}`
  - Zero-index compatibility wrappers (`init_virtio_*()`, `init_virtio_*_for_device()`, `init_virtio_*_with_transport()`, `get_virtio_*_device()`, `handle_virtio_*_interrupt()`, `with_virtio_net()`) ❌ **removed**
    - Migration: Use the explicit multi-device variants `*_at_index(index)` / `*_for_device_at_index(index, ...)` / `*_with_transport_at_index(index, ...)` / `get_virtio_*_device_at_index(index)` / `handle_virtio_*_interrupt_for_index(index)` / `with_virtio_net_at_index(index, ...)`. For the former default behavior, pass `0`.

- `kernel/src/graphics/virtio_gpu/gpu_impl/graphics_manager.rs`
  - Global GPU convenience wrappers (`init_virtio_gpu()`, `init_virtio_gpu_for_device()`, `get_virtio_gpu_device()`, `handle_virtio_gpu_interrupt()`) ❌ **removed**
    - Migration: Use `gpu_impl::init(transport, iommu_device_id)` and interact through `graphics_manager()` / `GraphicsManager` APIs instead of the removed global singleton helpers.

- `kernel/src/net/api/dhcp.rs`
  - Default-runtime wrappers (`get_dhcp_state()`, `list_dhcp_states()`, `dhcp_state()`, `dhcp_renew()`, `dhcp_release()`, `dhcp_discover()`, `dhcp_last_declined()`, `dhcp_last_released()`) ❌ **removed**
    - Migration: Use the runtime-aware variants `get_dhcp_state_in(runtime, if_id)`, `list_dhcp_states_in(runtime)`, `dhcp_state_in(runtime)`, `dhcp_renew_in(runtime)`, `dhcp_release_in(runtime)`, `dhcp_discover_in(runtime)`, `dhcp_last_declined_in(runtime)`, `dhcp_last_released_in(runtime)`. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.

- `kernel/src/net/api/connections.rs`
  - Default-runtime wrappers (`get_arp_cache()`, `enqueue_arp_cache_insert()`, `get_udp_endpoints()`, `get_tcp_connections()`) ❌ **removed**
    - Migration: Use `get_arp_cache_in(runtime)`, `enqueue_arp_cache_insert_in(runtime, ip, mac)`, `get_udp_endpoints_in(runtime)`, `get_tcp_connections_in(runtime)`. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.

- `kernel/src/net/api/diagnostics.rs`
  - Default-runtime wrappers (`network_snapshot()`, `network_recent_events(limit)`) ❌ **removed**
    - Migration: Use `network_snapshot_in(runtime)` and `network_recent_events_in(runtime, limit)`. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.

- `kernel/src/net/api/firewall.rs`
  - Default-runtime wrappers (`firewall_enable()`, `firewall_disable()`, `firewall_status()`, `firewall_list_rules()`, `firewall_stats()`, `firewall_add_rule(...)`, `firewall_remove_rule(id)`, `firewall_clear_rules()`, `firewall_set_default_policy(direction, action)`) ❌ **removed**
    - Migration: Use the runtime-aware `*_in(runtime, ...)` variants and pass `crate::net::runtime::default_runtime()` explicitly for default-runtime callers.

- `kernel/src/net/api/icmp.rs`
  - Default-runtime wrappers (`enqueue_icmp_echo()`, `ping()`, `ping_with_timeout()`) ❌ **removed**
    - Migration: Use `enqueue_icmp_echo_in(runtime, target, seq)`, `ping_in(runtime, target, seq)`, and `ping_with_timeout_in(runtime, target, seq, timeout_us)`. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.

- `kernel/src/net/api/config.rs`
  - Default-runtime wrappers (`primary_interface_config_snapshot()`, `aggregate_network_stats_snapshot()`, `get_interface_config(if_id)`, `list_interface_configs()`, `get_interface_stats(if_id)`, `list_interface_stats()`, `list_interfaces()`) ❌ **removed**
    - Migration: Use the runtime-aware `*_in(runtime, ...)` variants and pass `crate::net::runtime::default_runtime()` explicitly for default-runtime callers.
  - Internal default-runtime helpers (`primary_interface_id()`, `get_interface_config_from_runtime()`, `list_interface_configs_from_runtime()`, `get_interface_stats_without_stack()`, `list_interface_stats_with_stack()`, `list_interfaces_from_runtime()`, `primary_interface_config_snapshot_sync()`, `aggregate_network_stats_snapshot_sync()`, `list_interface_stats_sync()`) ❌ **removed**
    - Migration: Use the corresponding `*_in(runtime, ...)` helper or sync variant and thread the runtime handle through internal callers.

- `kernel/src/io/mod.rs`
  - `parse_dmar_table()` ❌ **removed**
    - Migration: Call `acpi::dmar::parse_dmar` directly.

- `kernel/src/io/pci/mod.rs`
  - Top-level legacy config helpers (`io::pci::{pci_read, pci_read8, pci_read16, pci_write}`) ❌ **removed**
    - Migration: Use `crate::io::pci::legacy::{pci_read, pci_read8, pci_read16, pci_write}` explicitly, or migrate to ECAM-based accessors where possible.

- `crate::drivers::virtio`
  - `BlkVringDesc` ❌ **removed**
    - Migration: Use `virtio_driver::virtqueue::VringDesc` directly.

- `kernel/src/mm/virt/address_space.rs`
  - `ProcessAddressSpace` / `fork()` / `exec()` / ASID 管理 ❌ **removed**
    - Migration: Use `crate::sas::MemoryRegion`, global higher-half mappings, and `domain::create_domain()` + loader.

- `kernel/src/mm/virt/cow.rs`
  - Copy-on-write fault handling ❌ **removed**
    - Migration: Active ExoRust memory management is SAS-only; no per-process CoW path is maintained.

- `filesystems/kernel_fs/fs_abstraction.rs`
  - Legacy filesystem model ❌ **removed**
    - Migration: Use `filesystems/kernel_fs/fs_model.rs` and the `crate::fs::*` re-exports.
  - `VfsUnixFileMode` ❌ **removed**
    - Migration: Use `kernel_fs::FileMode` directly.

- `kernel/src/shell/graphical/render.rs`
  - `redraw_input_only()` ✅ **deprecated**
    - Migration: Use `redraw_input_line()`.

- `kernel/src/kernel_content.rs`
  - `pub use serial_driver::serial_print(ln)` ❌ **removed** (prefer kernel logging APIs)
    - Replacement: Use `crate::io::log::early_print` or `log` macros once available.

- `kernel/src/net/api/icmp.rs`
  - `send_icmp_echo()` ❌ **removed** (was deprecated)
    - Migration: Use `enqueue_icmp_echo_in(runtime, target, seq)` or `ping_in(runtime, target, seq)` instead. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.

- `kernel/src/net/api/diagnostics.rs`
  - `dns_resolve()` ❌ **removed** (was deprecated)
    - Migration: Use `crate::net::services::dns` for DNS resolution.

- `kernel/src/diag/accessors.rs`
  - `with_profiler()` ❌ **removed** (was deprecated)
    - Migration: Use `crate::profiler::profiler().cpu` instead.

- `kernel/src/heap/oom.rs`
  - `register_domain()`, `unregister_domain()`, `update_memory_usage()`, `register_simple()` ❌ **removed** (were deprecated stubs)
    - Migration: Use `crate::domain::quota::quota_manager()` directly. The quota manager is the authoritative source for domain memory tracking.
  - `DomainMemoryInfo` / `list_domains()` ❌ **removed**
    - Migration: Use `crate::domain::list_domain_snapshots()` plus `crate::domain::quota::quota_manager().get_stats(...)` when you need per-domain memory data.

- `kernel/src/net/services/dns/mod.rs`
  - `client()` ❌ **removed**
    - Migration: Use high-level DNS helpers such as `init()`, `set_ipv4_servers()`, `set_ipv6_servers()`, `resolve_ipv4()`, `build_tcp_query()`, and `cleanup_cache()` instead of locking the singleton directly.

- `kernel/src/io/iommu/runtime/command/queue.rs`
  - `CommandQueue::submit_sync()` ❌ **removed**
    - Migration: Use `submit(kind)?.wait_blocking()` for simple blocking callers, or `submit_sync_with_worker()` when the current thread must also drive queue progress.

- `interfaces/kernel_api/src/services.rs`
  - `KernelServices::fs_open()` ❌ **removed**
    - Migration: Use `KernelServices::fs_open_with_token(path, mode, None)` or pass a validated grant token when tracking delegated ownership is required.
  - `KernelServices::nvme_open_direct()` ❌ **removed**
    - Migration: Use `KernelServices::nvme_open_direct_with_token(device_id, start_block, block_count, None)` or pass a validated DMA grant token for delegated opens.

- `kernel/src/task/executor.rs`
  - `TASK_STORE` (legacy global task store) ❌ **removed**
    - Migration: Per-core task stores (`PER_CORE_STORES`) are used exclusively; all legacy TASK_STORE references have been cleaned up.

- `kernel/src/qemu_tests/wave8_net_tests.rs`
  - IOMMU compatibility exports (`iommu_wave2_*`, `iommu_wave5_*`, `iommu_amd_wave*`) ❌ **removed**
    - Migration: Use the canonical IOMMU full-boot suite via `crate::test::integration::test_iommu()` or call the underlying testkit entry points in `crate::io::iommu::qemu_tests::{wave2, wave3, group_tests, amd}` directly when extending coverage.

## Drivers

- `drivers/pci` (`drivers/pci/src/lib.rs`)
  - `LegacyPciAccessor` ❌ **removed** (was deprecated)
    - Migration: Use `pci_driver::EcamAccess` or the new PCI APIs instead. The internal helper remains in `drivers/pci::legacy` but is no longer publicly re-exported.
  - `get_legacy_accessor()` ❌ **no longer publicly re-exported (internal)**
    - Migration: Prefer `pci_driver` accessors or ECAM APIs; the helper remains internal (`drivers::pci::legacy::get_legacy_accessor`) for in-repo use and is not intended for external callers.
  - Top-level legacy config helpers (`pci_read`, `pci_read8`, `pci_read16`, `pci_write`) ❌ **removed**
    - Migration: Use explicit module paths such as `pci_driver::legacy::pci_read16(...)` / `pci_driver::legacy::pci_write(...)`, or migrate to ECAM-based accessors where possible.

- `drivers/pci` (`drivers/pci/src/types.rs`)
  - `BdfAddress::legacy_address(offset)` ❌ **removed**
    - Migration: Prefer `pci_driver::legacy::LegacyPciAccessor` / `ConfigSpaceAccessor` methods for legacy config-space access, or use `BdfAddress::ecam_offset(register)` for ECAM-based callers.

- `drivers/serial` (`drivers/serial/src/lib.rs`)
  - `serial_print!`, `serial_println!` macros ❌ **removed**
    - Replacement: Use `crate::io::log::early_print` or the `log` crate for structured logging.
  - `serial1()` ❌ **removed**
    - Replacement: Use `crate::io::log::early_print` or `log::info!`/`log::debug!` instead of using the `AsyncSerialPort` global.
  - `init()` ❌ **removed** (was deprecated)
    - Replacement: Register the serial driver with `driver_registry::register_driver(Box::new(SerialDriver::new()))` and let the DriverRegistry perform initialization.
  - `handle_interrupt()` ❌ **removed**
    - Replacement: Prefer driver-registered interrupt handling via the DriverRegistry or the driver's interrupt methods; use `serial::dispatch_interrupt()` for direct dispatch in low-level code.

- `drivers/hid` (`drivers/hid/src/lib.rs`)
  - `KeyEvent::{modifiers, shift, ctrl, alt, caps_lock}` ❌ **removed**
    - Migration: Read the public fields directly (`event.modifiers`, `event.modifiers.shift`, など) instead of compatibility getters.

- `drivers/hid` (`drivers/hid/src/ps2/mod.rs`)
  - `ps2::{kbd_commands, mouse_commands}` re-exports ❌ **removed**
    - Migration: Prefer `Ps2Controller` helper methods over raw PS/2 keyboard/mouse command constants.

- Legacy filesystem crates
  - Repository / workspace surface ❌ **removed**
    - Migration: Use `kernel_api::block_io::*` for shared block transport and `kernel_fs::*` for local filesystem types.

- `interfaces/kernel_api` (`interfaces/kernel_api/src/resource/system.rs`)
  - `KernelSystemInfo` ❌ **removed**
    - Migration: Use `SystemInfo` directly.

- `drivers/usb/xhci` (`drivers/usb/src/xhci/mod.rs`)
  - `CmdBuilder` ❌ **removed**
    - Migration: Use `xhci::command::CommandBuilder` explicitly for command TRBs, or `xhci::CommandBuilder` for the ring-manager builder.

- `drivers/nvme` (`drivers/nvme/src/driver.rs`)
  - `nvme_driver::driver` compatibility module ❌ **removed**
    - Migration: Import concrete modules directly (`nvme_driver::queue`, `nvme_driver::polling_driver`, `nvme_driver::async_io`, `nvme_driver::global`, `nvme_driver::commands`).
  - Re-exported convenience APIs (e.g., `queue::CompletionQueue`, `QueuePair`, `SubmissionQueue`, `per_core::NvmeQueueStats`, `per_core::PerCoreNvmeQueue`, `polling_driver::NvmeDriverStats`, `NvmePollingDriver`, `async_io::{async_read, async_write, ReadFuture, WriteFuture}`, `error::NvmeError`, `global::{get_stats, init, poll, poll_batch}`, `scheduler::{register_with_io_scheduler, NvmePollHandler}`, `commands::{NvmeCommand, NvmeCompletion}`) ❌ **removed**
    - Migration: Import the specific types from `nvme_driver` module paths directly (for example, `nvme_driver::queue::CompletionQueue`, `nvme_driver::async_io::ReadFuture`, `nvme_driver::global::init`). These re-exports are removed as of 2026-01-17; update any usage to import from `nvme_driver` directly.

## Notes（全般）

- These deprecations are intentionally incremental and conservative — each change adds a `#[deprecated]` attribute and helpful migration notes. The aim is to show compile-time warnings and give downstream code time to migrate.
- Workspace-level full builds may still fail due to unrelated driver compile issues (e.g. `drivers/nvme`). Deprecation commits are small and intended to be low-risk.

## 2026-03-15 更新サマリー

### 削除済み（呼び出し元なしのため完全削除）
- `KernelServices::fs_open()` — `fs_open_with_token(path, mode, None)` に移行
- `KernelServices::nvme_open_direct()` — `nvme_open_direct_with_token(device_id, start_block, block_count, None)` に移行
- 旧 service 実装 root は `crate::kapi::*` に移行
- 旧 runtime bridge root は `crate::resource_registry::*` に移行
- `drivers::hid::KeyEvent` compatibility getters — public fields / `Modifiers` fields に移行
- `pci_driver::{pci_read, pci_read8, pci_read16, pci_write}` top-level legacy config helpers — `pci_driver::legacy::*` に移行
- `io::pci::{pci_read, pci_read8, pci_read16, pci_write}` top-level legacy config helpers — `io::pci::legacy::*` に移行
- `pci_driver::BdfAddress::legacy_address()` — `LegacyPciAccessor` / `ecam_offset()` に移行
- `io::hid::{KeyCodeExt, KeyEventExt, StreamAlreadyTaken}` compatibility re-exports — canonical `hid_driver` paths に移行
- `io::hid::set_leds` top-level re-export — `io::hid::ps2::set_leds(...)` / `Ps2Controller::set_keyboard_leds(...)` に移行
- `nvme_driver::driver` compatibility module — concrete NVMe submodules に移行
- `kernel_api::resource::system::KernelSystemInfo` — `kernel_api::resource::system::SystemInfo` に移行
- `io::virtio::BlkVringDesc` — `virtio_driver::virtqueue::VringDesc` に移行
- `ProcessAddressSpace` / `fork()` / `exec()` / CoW path — `crate::sas::MemoryRegion` + `domain::create_domain()` に移行
- `kernel_fs::VfsUnixFileMode` — `kernel_fs::FileMode` に移行
- `xhci::CmdBuilder` — `xhci::command::CommandBuilder` / `xhci::CommandBuilder` に移行
- `heap::oom::{DomainMemoryInfo, list_domains}` legacy compatibility path — `crate::domain` + `quota_manager()` に移行
- `net::services::dns::client()` — high-level DNS helpers / shared Arc-backed runtime access に移行
- `iommu::runtime::command::CommandQueue::submit_sync()` — `submit(...).wait_blocking()` / `submit_sync_with_worker()` に移行
- `io::virtio::net::VirtioNetDevice::submit_tx()` — `send_async()` / `enqueue_send_zero_copy()` / `NetDevicePort::submit_tx()` に移行
- `net::services::dhcp::{init, init_v6, legacy_v4_client_lock, legacy_v6_client_lock}` — runtime-aware `*_in(...)` APIs に移行
- `net::api::dhcp::{get_dhcp_state, list_dhcp_states, dhcp_state, dhcp_renew, dhcp_release, dhcp_discover, dhcp_last_declined, dhcp_last_released}` — runtime-aware `*_in(...)` APIs に移行
- `net::api::connections::{get_arp_cache, enqueue_arp_cache_insert, get_udp_endpoints, get_tcp_connections}` — runtime-aware `*_in(...)` APIs に移行
- `net::api::diagnostics::{network_snapshot, network_recent_events}` — runtime-aware `*_in(...)` APIs に移行
- `net::api::firewall::{firewall_enable, firewall_disable, firewall_status, firewall_list_rules, firewall_stats, firewall_add_rule, firewall_remove_rule, firewall_clear_rules, firewall_set_default_policy}` — runtime-aware `*_in(...)` APIs に移行
- `net::api::icmp::{enqueue_icmp_echo, ping, ping_with_timeout}` — runtime-aware `*_in(...)` APIs に移行
- `net::api::config::{primary_interface_config_snapshot, aggregate_network_stats_snapshot, get_interface_config, list_interface_configs, get_interface_stats, list_interface_stats, list_interfaces}` — runtime-aware `*_in(...)` APIs に移行
- `hid_driver::ps2::{kbd_commands, mouse_commands}` re-exports — `Ps2Controller` helper methods に移行

## 2026-03-04 更新サマリー

以下の deprecated 項目を一括整理しました:

### 削除済み（呼び出し元なしのため完全削除）
- `send_icmp_echo()` — `enqueue_icmp_echo()` / `ping()` に移行
- `dns_resolve()` — `crate::net::services::dns` に移行
- `with_profiler()` — `crate::profiler::profiler().cpu` に移行
- OOM killer の deprecated スタブ: `register_domain()`, `unregister_domain()`, `update_memory_usage()`, `register_simple()` — `crate::domain::quota::quota_manager()` に移行

### 呼び出し元を移行
- テスト `test_send_icmp_fallback_zero_copy` の `send_icmp_echo()` → `enqueue_icmp_echo()` に更新

### 新規モジュール
- `kernel/src/net/api/shell.rs` — テスト/シェルから参照される `api::shell` ファサードモジュールを作成（`config`, `icmp`, `dhcp`, `diagnostics` の公開関数を集約）

### コメント整理
- `executor.rs` の旧 `TASK_STORE` 参照コメントを per-core ストアの表記に更新

### 残存する deprecated 項目（呼び出し元あり、要段階的移行）
- `Ipv4Header::compute_checksum()`, `update_checksum()`, `verify_checksum()` ❌ **removed**
- `notify_addr` フィールド — virtio transport で現役使用中
- IO scheduler の `#[allow(deprecated)]` — 内部パターン互換性のため保持

## 関連文書

- [../README.md](../README.md)
- [api-reference.md](api-reference.md)
- [../architecture.md](../architecture.md)
