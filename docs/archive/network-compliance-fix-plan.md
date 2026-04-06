# Network Compliance Fix Plan

> Archive note: この文書は履歴資料です。現行仕様の正本ではありません。まず [docs/README](../README.md) と [archive index](README.md) を参照してください。

## Summary
- Bring the live network stack into conformance with design 4.2, 5.4, 6.1, and 6.2 in one pass: ISR-safe event delivery, framework-contained `unsafe`, hybrid adaptive polling, and true end-to-end zero-copy.
- Use immediate replacement for the Rust network KAPI. Do not keep the current handle plus `Packet`/`TcpChunk` surface.
- Apply zero-copy to TCP, UDP, raw endpoints, and IP reassembly. Reassembled payloads stay chained; they must not be flattened into `Vec<u8>`.

## Public API and ABI changes
- In `interfaces/kernel_api`, move the shared `AsyncRead`, `AsyncWrite`, and `TcpError` traits/types out of `kernel/src/net/l4/tcp` and make them the canonical public stream traits.
- Remove `Packet`, `TcpChunk`, `TcpStreamHandle`, `TcpListenerHandle`, and `RawEndpointHandle` from the public Rust network API.
- Extend `PacketRef` with header-prepend support: add `headroom()` and `retreat(size)` and require allocators to reserve 128 bytes of headroom for L2/L3/L4 headers.
- Add one shared payload model:
  - `PacketChain { segments: Vec<PacketRef>, total_len: usize }`
  - `PacketPayload = Single(PacketRef) | Chain(PacketChain)`
  - Replace the existing internal `zero_copy::PacketChain` with this one shared type.
- Add concrete public wrappers `TcpStream`, `TcpListener`, and `RawEndpoint`.
  - `TcpStream` implements public `AsyncRead`/`AsyncWrite` and also exposes `recv_payload()` and `send_payload(PacketPayload)`.
  - `TcpListener` exposes `listen_on(...)` and `accept() -> TcpStream`.
  - `RawEndpoint` exposes `recv_payload()` and `send_payload(...)`.
- Replace the `KernelServices` network surface with object-oriented backend methods:
  - `net_open_tcp_stream`
  - `net_open_tcp_listener`
  - `net_tcp_listener_accept`
  - `net_tcp_stream_recv_payload`
  - `net_tcp_stream_send_payload`
  - `net_close_tcp_stream`
  - `net_close_tcp_listener`
  - `net_open_raw_endpoint`
  - `net_raw_recv_payload`
  - `net_raw_send_payload`
  - `net_close_raw_endpoint`
- Add `AbiNetPortRegistrationV2` with `set_interrupts_enabled(opaque, enabled) -> i32`.
  - Keep `AbiNetPortRuntimeV1`; ISR safety is handled by the runtime implementation, not by a new runtime callback.
  - Keep V1 registration loading support, but V1 ports stay interrupt-driven only.

## Implementation changes
- Runtime and IRQ safety:
  - Make `NetPortRuntime::schedule_event()` context-aware: if `in_interrupt_context()` is true, it must route to the ISR-safe queue path and only use `wake_from_isr`; otherwise use the normal wake path.
  - Remove the live-path split between `schedule_event()` and `enqueue_event_from_isr()` so VirtIO and `mlx5` share the same safe entry.
- Adaptive polling:
  - Put the canonical polling controller in `net/runtime/device` and make it standard per-port runtime state.
  - Add `NetDevicePort::set_interrupts_enabled(bool)` for native drivers.
  - Each `NetDeviceHandle` gets a `poll_worker` task that runs `driver.poll()` in `Hybrid/BusyPoll` and returns to interrupt mode on idle.
  - VirtIO implements interrupt suppression by setting and clearing `VRING_AVAIL_F_NO_INTERRUPT` on RX/TX queues while still ACKing ISR status.
  - `mlx5` implements interrupt suppression by using the existing CQ/EQ arm logic and its polling state instead of leaving CQ rearm always on.
  - Retire `net/datapath/adaptive_polling::PacketBuffer`; keep only policy logic that is reused by the runtime controller.
- Zero-copy datapath:
  - Replace packet-carrying `Vec<u8>` storage and events with `PacketPayload` or `PacketRef` in TCP, UDP, raw send/recv, retransmit, and reassembly.
  - `EndpointInner` stops owning byte `recv_buffer` and `send_buffer`; it owns packet queues. Partial consumption is tracked by mutating queued `PacketRef`s with `advance()` and `retreat()`-based header prepend.
  - TCP RX delivers payload objects directly to the stream queue. `AsyncRead::poll_read()` copies only when the caller requests bytes; zero-copy reads return owned payloads.
  - TCP TX uses one payload queue for both byte-write and zero-copy-write paths. Byte writes may allocate a `PacketRef` once at the API boundary, but the live path after enqueue stays ownership-based.
  - Replace `TcpSegmentBuilder`’s `Vec<u8>` assembly with in-place header writing into `PacketRef` headroom. For chained payloads, prepend a header segment and send via the shared payload abstraction without flattening.
  - Retransmit queues store packet-backed payloads, not `Vec<u8>`. Reassembly emits `PacketPayload::Chain`, not `ReassembledPacket { data: Vec<u8> }`.
  - UDP delivery and raw endpoint send/recv stay packet-backed for both IPv4 and IPv6; remove all `.to_vec()` and `VecDeque<u8>` staging from those paths.
- Unsafe boundary:
  - Move `PacketRef` backing construction and raw storage access out of `net/datapath/mempool` into a single low-level module under `kernel/src/io/dma`.
  - `net/datapath/mempool` becomes a safe facade over that module.
  - Move `mlx5` CQ/EQ raw polling behind safe driver methods so `net/runtime/bridge/mlx5_bridge` contains no networking `unsafe`.
  - Higher layers (`net/runtime`, `net/l4`, public KAPI wrappers) must use safe APIs only.

## Test plan
- Repair the stale network tests first:
  - replace the old listener-field assertion with a current listener-state assertion
  - restore or rename the family-guard helper test to current helper names
- Add unit tests for:
  - ISR-context `schedule_event()` routing to deferred wake
  - `TcpStream` zero-copy send/receive on the non-fragmented path
  - reassembly round-trip using `PacketPayload::Chain`
  - UDP IPv4/IPv6 delivery without payload copying
  - adaptive polling transitions and interrupt suppression for both VirtIO and `mlx5`
  - ABI V2 negotiation, with ABI V1 falling back to interrupt-driven behavior
- Validation commands:
  - `cargo test -p rany_kernel`
  - `QEMU_TEST_PROFILE_ONLY=network cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture`

## Assumptions and defaults
- Immediate replacement is required: no compatibility shim for the old Rust network KAPI.
- Full zero-copy includes IP reassembly, so chained payloads are part of both internal and public network data types.
- Standalone driver support is upgraded with ABI V2; ABI V1 remains loadable only as an interrupt-driven fallback until migrated.
- `AsyncRead` and `AsyncWrite` remain the ergonomic stream API, but the compliant fast path is the payload-owning API; any remaining byte copies must be caller-opt-in at the wrapper boundary only.
