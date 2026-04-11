# 廃止済み API と移行ガイド

- Status: Reference
- Audience: deprecated symbol の移行を進める実装者、レビュー担当者、integrator
- Related: [ドキュメントハブ](../README.md), [API リファレンス](api-reference.md), [Network Core Reference](network-core.md), [アーキテクチャ概要](../architecture.md)

This document lists deprecated symbols and recent removals that still matter for active migration work. It is intended to help reviewers and integrators align in-tree code with the current canonical surface.

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
  - Mouse polling helpers (`has_mouse_event`, `poll_mouse_event`) ❌ **removed**
    - Migration: Use event-driven `MouseEvent` streams or query the global `MOUSE` under an interrupts-disabled section, e.g. `x86_64::instructions::interrupts::without_interrupts(|| crate::io::hid::mouse::MOUSE.lock().poll_event())`.
  - HID extension traits (`KeyCodeExt`, `KeyEventExt`) and `StreamAlreadyTaken` re-export ❌ **removed**
    - Migration: Bring traits into scope from `hid_driver::keyboard` directly (e.g., `use hid_driver::keyboard::KeyEventExt`) and use `hid_driver::StreamAlreadyTaken` for stream-acquisition errors.
  - `set_leds` top-level re-export ❌ **removed**
    - Migration: Use `crate::io::hid::ps2::set_leds(scroll, num, caps)` directly or call `Ps2Controller::set_keyboard_leds(...)`.

- `kernel/src/io/hid/keyboard.rs`
  - `handle_keyboard_interrupt()` ❌ **removed** (was deprecated)
    - Migration: Use `take_stream()` and register the PS/2 driver's handler via the DriverRegistry or call `crate::io::hid::ps2::keyboard_interrupt_handler()`. This avoids using the removed convenience wrapper.

- IO-level re-exports (deprecated to propagate HID deprecations to `crate::io` namespace)
  - `io::get_key_event` ❌ **removed**
    - Migration: Use `KeyboardStream` or `keyboard::has_event()` instead.
  - `io::get_modifiers` ❌ **removed**
    - Migration: Use `keyboard` APIs or `KeyboardStream` instead.
  - `io::get_mouse_event` ❌ **removed**
    - Migration: Use `MouseEvent` streams or `mouse::poll_event` instead.
  - `io::handle_keyboard_interrupt` ❌ **removed** (was deprecated)
    - Migration: Register the PS/2 driver's interrupt handler via the DriverRegistry (preferred) or call `keyboard_interrupt_handler` directly.
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

## Network

- `kernel/src/net` (TCP/Socket APIs)
  - Note: この節は core network surface に関わる deprecated / removed API だけを扱います。便宜的な naming や非正規 surface は canonical docs の対象外です。
  - Note: ここに残る旧シンボル名は migration 履歴のために保持しています。現行の canonical surface は `TcpConnection` / `TcpAcceptor` と payload-native DNS/TLS API（`*_payload` 系）です。
  - `interfaces/kernel_api::resource::net` の method-based TCP/RAW wrappers (`TcpConnection::connect`, `TcpConnection::recv_payload`, `TcpConnection::send_payload`, `TcpAcceptor::listen_on`, `TcpAcceptor::accept`, `TcpAcceptor::poll_accept`, `RawEndpoint::open`, `RawEndpoint::recv_payload`, `RawEndpoint::send_payload`) ❌ **removed**
    - Migration: Use the handle-first module functions `tcp_connection_dial(...)`, `tcp_acceptor_bind(...)`, `tcp_acceptor_next_connection(...)`, `tcp_connection_recv_payload(&connection)`, `tcp_connection_send_payload(&connection, payload)`, `raw_endpoint_open(...)`, `raw_endpoint_recv_payload(&endpoint)`, and `raw_endpoint_send_payload(&endpoint, payload)`.
  - `interfaces/kernel_api::services::KernelServices` legacy open/accept/raw names (`net_open_tcp_stream`, `net_open_tcp_listener`, `net_tcp_acceptor_accept`, `net_close_tcp_stream`, `net_close_tcp_listener`, `net_open_raw_endpoint`, `net_close_raw_endpoint`, `net_raw_recv_payload`, `net_raw_send_payload`) ❌ **removed**
    - Migration: Use `net_tcp_connection_dial`, `net_tcp_acceptor_bind`, `net_tcp_acceptor_next_connection`, `net_tcp_connection_close`, `net_tcp_acceptor_close`, `net_raw_endpoint_open`, `net_raw_endpoint_close`, `net_raw_endpoint_recv_payload`, and `net_raw_endpoint_send_payload`.
  - 旧トップレベル `crate::net::*` 直下ネットワークAPI / 再エクスポート ❌ **removed**
    - Replacement: 新階層へ移行 (`crate::net::api::{shell,diag}`, `crate::net::runtime::{stack,manager,bridge}`, `crate::net::l2/l3/l4`, `crate::net::services`, `crate::net::security`, `crate::net::datapath`, `crate::net::drivers`)。
    - 代表例:
      - `crate::net::get_network_config` -> `crate::net::api::shell::get_network_config`
      - `crate::net::get_network_stats` -> `crate::net::api::shell::get_network_stats`
      - `crate::net::send_icmp_echo` -> `crate::net::api::shell::enqueue_icmp_echo` (sync版は削除済み)
      - `crate::net::get_arp_cache` -> `crate::net::api::shell::get_arp_cache`
  - Legacy TCP processor / control-block internals ❌ **removed**
    - Migration: TCP state is now owned by `l4::endpoint` (`tcb_table + endpoint handler + network_event_task`). Public callers should use the active typed endpoints and packet-backed payload surfaces; internal tests should target `TcpControlBlockEntry`, endpoint fixtures, or `TcpSegmentBuilder`.
  - UDP legacy bind wrappers (`UdpSocketTable::bind`, `UdpProcessor::bind`) ❌ **removed**
    - Migration: Use the token-aware API: `UdpSocketTable::bind_with_token(port, Some(token))`. For the no-token case use `UdpSocketTable::bind_with_token(port, None)` or the stack helper `bind_udp(port)`/`bind_udp_with_token(port, token)` as appropriate.
  - `UdpEndpoint::bind_registered_with_token_in(runtime, scope, port, token)` ❌ **removed**
    - Migration: Use `UdpEndpoint::bind_in(runtime, scope, port, token)`.
  - `kernel/src/net/security/tls/connection::TlsConnection` の byte-slice / `Vec<u8>` TLS record APIs (`process_incoming(&[u8])`, `encrypt_application_data(&[u8])`, `send_early_data(&[u8])`, `get_rejected_early_data()`, `build_key_update_response()`, `close()`) ❌ **removed**
    - Migration: Use the packet-backed APIs `process_incoming_payload(&payload)`, `encrypt_application_payload(&payload)`, `send_early_data_payload(&payload)`, `get_rejected_early_data_payload()`, `build_key_update_response_payload()`, and `close_payload()`.
  - TLS handshake record builders returning `Vec<u8>` (`build_client_key_exchange()`, `build_client_key_exchange_rsa()`, `build_change_cipher_spec()`, `build_client_finished_tls12()`, `build_client_finished_tls13()`) ❌ **removed**
    - Migration: Use the payload-native builders `build_client_key_exchange_payload()`, `build_client_key_exchange_rsa_payload()`, `build_change_cipher_spec_payload()`, `build_client_finished_tls12_payload()`, and `build_client_finished_tls13_payload()`.
  - TLS copy helpers (`vec_from_payload()`, `packet_payload_from_slice()`, `packet_payload_from_parts()`, `span_from_bytes()`) ❌ **removed**
    - Migration: Operate on `PacketPayloadView`, `PayloadSpan`, and `PacketPayloadBuilder` directly at each call site. Do not reintroduce TLS-local payload flatten/build helpers.
  - TLS subtree `read_vec()`-based parser / record paths ❌ **removed**
    - Migration: Parse TLS records and handshake payloads from `PacketPayloadView`, `PacketPayloadCursor`, `PayloadSpan`, or fixed-capacity TLS scratch without `Vec<u8>` flatten helpers.
  - TLS / RSA owned-buffer crypto helpers (`aes_gcm_encrypt`, `aes_gcm_decrypt`, `chacha20_poly1305_encrypt`, `chacha20_poly1305_decrypt`, `aes_cbc_encrypt`, `aes_cbc_decrypt`, `tls_add_padding`, `compute_tls_mac`, `rsa_pkcs1_encrypt`, `mgf1`, `hash_compute`, `BigUint::to_be_bytes`, `BigUint::to_be_bytes_padded`) ❌ **removed**
    - Migration: Use the in-place / buffer-out APIs `aes_gcm_encrypt_into`, `aes_gcm_decrypt_into`, `chacha20_poly1305_*_in_place`, `aes_cbc_*_in_place`, `tls_add_padding_in_place`, `compute_tls_mac_into`, `rsa_pkcs1_encrypt_into`, `mgf1_into`, `hash_compute_into`, `BigUint::write_be_bytes`, and `BigUint::write_be_bytes_padded`.
  - `TlsConfig` / `SessionCache` の `Vec<String>` / `String` / `VecDeque` surface (`with_server_name(&str) -> TlsConfig`, `with_alpn(&[&str]) -> TlsConfig`, dynamic session cache) ❌ **removed**
    - Migration: Use the fixed-capacity API: `with_server_name(&str) -> Result<TlsConfig, TlsConfigError>`, `with_alpn(&[&str]) -> Result<TlsConfig, TlsConfigError>`, `ArrayVec`-backed `TlsConfig`, and fixed-capacity `SessionCache`.
  - Legacy payload builder name `build_client_hello()` ❌ **removed**
    - Migration: Use `build_client_hello_payload()`.
  - TLS helper accessors exposing raw transcript bytes (`handshake_messages_ref()`) ❌ **removed**
    - Migration: Verify transcript progress through state, emitted payload records, or transcript-hash-based helpers instead of byte accumulation snapshots.
  - IPv6 copy-based quoted-packet / timeout paths (`packet_from_bytes` / `payload_from_bytes` rebuild in the IPv6 receive path) ❌ **removed**
    - Migration: Keep quoted packets packet-backed and pass `PacketPayload` directly into ICMPv6 builders and reassembly results.
  - IPv4 copy-based quoted/original-packet rebuild paths (`packet_from_bytes` rebuild in the IPv4 receive / ingress path) ❌ **removed**
    - Migration: `Ipv4ProcessResult::ReassemblyTimeout` / `UnknownProtocol` now carry `PacketPayload` directly. Keep quoted/original packets packet-backed through ICMP error generation.
  - Stale endpoint event branch `NetworkEvent::ApplyIpv6Address` in handler-side fallback dispatch ❌ **removed**
    - Migration: `endpoint/event.rs` is the source of truth. Use the active DHCPv6 lease application event `DhcpV6ApplyLease` instead of reviving removed handler-only variants.
  - Dead NAT ICMP bridge events (`NatIcmpTimeExceeded`, `NatIcmpDestUnreachable`) ❌ **removed**
    - Migration: Emit packet-backed ICMP errors directly from the active runtime path instead of queueing byte-owned NAT compatibility events.

- `kernel/src/net/services/dhcp`
  - Default-runtime wrappers (`init()`, `init_v6()`, `legacy_v4_client_lock()`, `legacy_v6_client_lock()`) ❌ **removed**
    - Migration: Use runtime-aware APIs. DHCPv4 no longer exposes a singleton client lock; register/configure an interface and call `ensure_interface_runtime(if_id, config)`, then use `primary_v4_client_in(runtime)` or `interface_v4_client_in(runtime, if_id)`. DHCPv6 callers should use `init_v6_in(runtime, mac)` and `primary_v6_client_lock_in(runtime)`. Default-runtime callers should pass `crate::net::runtime::default_runtime()` explicitly.
  - DHCPv4 compatibility singleton (`init_in(runtime, mac)`, `legacy_v4_client_lock_in(runtime)`) ❌ **removed**
    - Migration: Seed DHCP state through the per-interface runtime registry with `ensure_interface_runtime(if_id, config)` and read state via `primary_v4_client_in(runtime)` / `interface_v4_client_in(runtime, if_id)`.
  - DHCPv6 accessor `legacy_v6_client_lock_in(runtime)` ❌ **renamed**
    - Migration: Use `primary_v6_client_lock_in(runtime)`.
  - `payload_span_to_vec()` と `NetworkEvent::DhcpApplyLease { hostname: Vec<u8> }` / `NetworkEvent::DhcpV6ApplyLease { domain_search: Vec<String> }` ❌ **removed**
    - Migration: Keep lease metadata packet-backed. Use `Option<PayloadSpan>` for DHCPv4 hostname/domain and `Vec<DnsNameOwned>` for DHCPv6 domain-search payloads.
  - DHCP send helpers that rebuilt payloads from raw byte slices (`build_stack_payload()`, `enqueue_v6_send_bytes()`) ❌ **removed**
    - Migration: For app-originated outbound packets, write directly into the final `PacketPayloadBuilder` and pass the built payload to the runtime send path.

- `kernel/src/net/services/{dns,mdns}`
  - PTR query helper return types `ptr_ipv4_query_name() -> String` / `ptr_ipv6_query_name() -> String` ❌ **removed**
    - Migration: Use packet-backed `DnsNameOwned` values and pass `DnsNameView`/`DnsNameOwned` through cache lookup and transport paths instead of stringifying reverse-query names.
  - mDNS send helper `build_stack_payload()` and payload-path string decode/encode round-trips ❌ **removed**
    - Migration: Build outbound queries/responses directly from `DnsNameOwned` label spans and keep payload-path question/answer names packet-backed.

- `kernel/src/net/runtime/bridge/mlx5_bridge.rs`
  - TX diagnostic preview helper `payload_preview_bytes()` ❌ **removed**
    - Migration: Log segment layout metadata instead of linearizing packet bytes on the TX path.

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
    - Migration: Use high-level DNS helpers such as `init()`, `set_ipv4_servers()`, `set_ipv6_servers()`, `resolve_ipv4()`, `resolve_mx()`, `resolve_ptr_ipv6()`, `build_tcp_query_payload()`, and `cleanup_cache()` instead of locking the singleton directly.
  - `DnsRecordData::Raw(Vec<u8>)` ❌ **removed**
    - Migration: Use `DnsRecordData::Raw(PayloadSpan)` and explicitly materialize bytes only at the call site that actually needs them.
  - byte-slice DNS response parsers (`parse_response(&[u8], ...)`, `parse_tcp_response(&[u8], ...)`) ❌ **removed**
    - Migration: Use `parse_response_payload(&payload, ...)` and `parse_tcp_response_payload(&payload, ...)`.
  - owned-string DNS record variants (`DnsRecord.name: String`, `DnsRecordData::Name(String)`, `DnsRecordData::TXT(String)`, `DnsRecordData::MX(_, String)`, `DnsRecordData::SRV { target: String, .. }`) ❌ **removed**
    - Migration: Use `DnsNameView`, `DnsTxtView`, and `PayloadSpan`-backed record data. Materialize `String` only at the outermost consumer that needs text.
  - `DnsCache` / mDNS cache の raw `String` key ownership ❌ **removed**
    - Migration: Use `DnsNameOwned` as the canonical owned cache key for packet-backed DNS/mDNS names. Convert to text only for shell / diagnostics / tests.
  - `Vec<DnsRecord>` response/cache ownership (`parse_* -> Vec<DnsRecord>`, `DnsCacheEntry.records-only` cache entries) ❌ **removed**
    - Migration: Use `DnsResponseView { payload, records }` and cache response payload ownership alongside record metadata.
  - `PacketRef`-only TX callback / queue / driver submit path (`TransmitFn`, runtime device queue, `NetDevicePort::submit_tx(PacketRef, ...)`) ❌ **removed**
    - Migration: Use `PacketPayload` as the canonical TX unit. Single-segment frames should pass `PacketPayload::single(packet)`; scatter-gather send paths should forward `PacketPayload::Chain` unchanged.

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

## Ledger Notes

- This ledger tracks live migration targets and recent removals that still affect in-tree contributors.
- Fully removed symbols may stay listed when the migration path is still useful for active cleanup; stale historical notes are intentionally dropped instead of preserved here.

## 関連文書

- [../README.md](../README.md)
- [api-reference.md](api-reference.md)
- [../architecture.md](../architecture.md)
