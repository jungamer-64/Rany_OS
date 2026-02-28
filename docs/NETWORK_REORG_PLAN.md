# Network Reorganization Result (`kernel/src/net` + `kernel/src/io/virtio/net`)

## Scope

- Target:
  - `kernel/src/net`
  - `kernel/src/io/virtio/net`
- Policy:
  - destructive migration (no compatibility re-export layer)
  - `mod.rs`-based normal module resolution
  - remove `#[path = "..."]` from network trees

## Final Namespace Policy

- Root `crate::net::mod.rs` is declaration-focused only.
- Public namespaces:
  - `crate::net::l2::{ethernet, arp, igmp}`
  - `crate::net::l3::{ipv4, ipv6, icmp, icmpv6, ndp}`
  - `crate::net::l4::{tcp, udp, endpoint}`
  - `crate::net::services::{dhcp, dns, mdns}`
  - `crate::net::security::{tls, x509, rsa, ecdh}`
  - `crate::net::datapath::{mempool, zero_copy, adaptive_polling, optimization, checksum_offload}`
  - `crate::net::runtime::{stack, manager, bridge, timeouts}`
  - `crate::net::drivers::virtio_registry`
  - `crate::net::api::{shell, diag}`
  - `crate::net::obs::{counters, trace, snapshot}`

## Implemented Layout

### `kernel/src/net`

- `api/`, `obs/`, `l2/`, `l3/`, `l4/`, `services/`, `security/`, `datapath/`, `runtime/`, `drivers/`, `tests/` were created and wired.
- Existing protocol/data-path/runtime code was migrated under these directories with `git mv`.
- `foo.rs` + `foo/` collisions were removed by converting colliding modules to `foo/mod.rs`.

### `kernel/src/io/virtio/net`

- Converted to directory module:
  - `mod.rs`
  - `features.rs`
  - `queue.rs`
  - `device/{mod,tx,rx,irq,mac,registry}.rs`
  - `device/dma/{mod,buffer,poller,stats}.rs`
- Legacy `device_impl` / `dma_helpers` references were removed.

## API Mapping Applied

- `crate::net::get_network_config` -> `crate::net::api::shell::get_network_config`
- `crate::net::get_network_stats` -> `crate::net::api::shell::get_network_stats`
- `crate::net::send_icmp_echo` -> `crate::net::api::shell::send_icmp_echo`
- `crate::net::get_arp_cache` -> `crate::net::api::shell::get_arp_cache`
- Driver/bridge/stack callsites were updated to `crate::net::runtime::*` / `crate::net::l4::endpoint::*`.

## Validation

- `cargo check -p rany_kernel`: **pass**
- `rg -n "#\\[path\\s*=\\s*\\\"" kernel/src/net kernel/src/io/virtio/net -g '*.rs'`: **0 matches**
- `rg -n "crate::net::(ipv4|tcp|udp|dhcp|dns|mdns|tls|mempool|stack)::" kernel/src`: **0 matches**
- same-name file/dir collision check (`foo.rs` and `foo/`): **0 collisions**

### Current Test Status

- `cargo test -p rany_kernel net -- --nocapture`: process ended with `SIGSEGV`
- `cargo test -p rany_kernel io::virtio::net -- --nocapture`: process ended with `SIGSEGV`

These failures occur during test execution phase (after successful build) and require runtime test debugging separate from the structural refactor.
