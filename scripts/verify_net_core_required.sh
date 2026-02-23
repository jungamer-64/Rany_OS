#!/usr/bin/env bash
set -euo pipefail

# Validates NET core stack deterministic required wiring (90 cases) for suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET_EXPORT_FILE="$ROOT_DIR/kernel/src/net/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in "$NET_EXPORT_FILE" "$KERNEL_WRAPPER_FILE" "$KERNEL_SUITE_FILE" "$PENDING_FILE"; do
  if [[ ! -f "$required_file" ]]; then
    echo "[verify_net_core_required] missing file: $required_file" >&2
    exit 1
  fi
done

required_groups=(
  "net_core_adaptive_polling_exports"
  "net_core_mempool_exports"
  "net_core_zero_copy_exports"
  "net_core_ethernet_exports"
  "net_core_arp_exports"
  "net_core_icmp_exports"
  "net_core_udp_exports"
  "net_core_ipv4_exports"
  "net_core_icmpv6_exports"
  "net_core_stack_exports"
  "net_core_ipv6_exports"
  "net_core_ndp_exports"
  "net_core_tcp_exports"
)

cases=(
  "adaptive_polling_polling_mode_default"
  "adaptive_polling_ring_buffer"
  "adaptive_polling_network_stats"
  "mempool_mempool_poisoned_alloc_fails"
  "mempool_mempool_stats"
  "zero_copy_pool_id"
  "zero_copy_sg_list"
  "zero_copy_packet_chain"
  "ethernet_mac_address"
  "ethernet_ether_type"
  "arp_arp_cache"
  "arp_arp_packet"
  "icmp_icmp_type"
  "icmp_echo_builder"
  "udp_udp_packet"
  "udp_udp_socket_poisoned_methods_return_defaults"
  "udp_bind_with_token_reclaim"
  "udp_udp_recv_future_poisoned_returns_closed"
  "udp_udp_processor_poisoned_bind_and_process"
  "ipv4_ipv4_address"
  "ipv4_subnet"
  "ipv4_fragment_key"
  "ipv4_fragment_buffer_basic"
  "ipv4_fragment_reassembly_simple"
  "ipv4_pmtu_cache_basic"
  "ipv4_pmtu_cache_update_smaller"
  "ipv4_pmtu_cache_minimum"
  "icmpv6_icmpv6_type_from_u8"
  "icmpv6_icmpv6_type_classification"
  "icmpv6_echo_reply_build_and_verify"
  "icmpv6_echo_request_build_and_verify"
  "icmpv6_processor_echo_request"
  "icmpv6_processor_echo_disabled"
  "icmpv6_processor_checksum_error"
  "icmpv6_ndp_delegation"
  "icmpv6_header_size"
  "stack_network_stack_creation"
  "stack_network_stack_poisoned_runtime_apis_fail"
  "stack_send_udp_fallback_zero_copy"
  "stack_send_icmp_fallback_zero_copy"
  "stack_redirect_cache_basic"
  "stack_redirect_cache_expiry"
  "stack_redirect_cache_cleanup"
  "stack_redirect_cache_eviction"
  "ipv6_unspecified"
  "ipv6_loopback"
  "ipv6_multicast"
  "ipv6_link_local"
  "ipv6_global"
  "ipv6_eui64"
  "ipv6_solicited_node"
  "ipv6_multicast_mac"
  "ipv6_header_size"
  "ipv6_packet_parse_valid"
  "ipv6_packet_parse_wrong_version"
  "ipv6_packet_parse_too_short"
  "ipv6_packet_mut_build"
  "ipv6_skip_no_extension_headers"
  "ipv6_skip_hop_by_hop"
  "ipv6_skip_fragment_header"
  "ipv6_pseudo_header_checksum"
  "ipv6_display_loopback"
  "ipv6_display_link_local"
  "ipv6_display_all_nodes"
  "ipv6_display_full"
  "ipv6_from_u64_pair"
  "ndp_neighbor_cache_basic"
  "ndp_neighbor_cache_update"
  "ndp_neighbor_cache_expiry"
  "ndp_parse_slla_option"
  "ndp_parse_prefix_info_option"
  "ndp_build_ns"
  "ndp_build_na"
  "ndp_build_rs"
  "ndp_multicast_mac"
  "ndp_resolve_multicast"
  "ndp_ns_processing"
  "tcp_ipv4_addr"
  "tcp_socket_addr"
  "tcp_tcp_state"
  "tcp_process_with_packet_zero_copy"
  "tcp_can_send_respects_cwnd_bytes"
  "tcp_send_buffer_bytes_decrement_on_flush"
  "tcp_three_way_handshake"
  "tcp_retransmit_on_timeout"
  "tcp_connect_future_wakes_on_established"
  "tcp_record_sent_packet_updates_tcb"
  "tcp_ack_segments_removes_unacked_and_reduces_outstanding"
  "tcp_accept_future_returns_on_push_connection"
  "tcp_connect_timeout_expires"
)

violations=0

for group in "${required_groups[@]}"; do
  if ! rg -q "$group" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_core_required] missing required suite group '$group' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${cases[@]}"; do
  export_fn="${case_name}_smoke"
  wrapper_fn="net_core_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\(" "$NET_EXPORT_FILE"; then
    echo "[verify_net_core_required] missing export '${export_fn}' in ${NET_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_net_core_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_core_required] missing suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

group_count=$(rg -n "^fn test_net_core_.*_exports\(\) -> bool" "$KERNEL_SUITE_FILE" | wc -l | tr -d " ")
if [[ "$group_count" != "13" ]]; then
  echo "[verify_net_core_required] expected 13 net_core group fns, got $group_count"
  violations=$((violations + 1))
fi

wrapper_count=$(rg -n "^pub fn net_core_.*_smoke\(" "$KERNEL_WRAPPER_FILE" | wc -l | tr -d " ")
if [[ "$wrapper_count" != "90" ]]; then
  echo "[verify_net_core_required] expected 90 net_core wrappers, got $wrapper_count"
  violations=$((violations + 1))
fi

if ! rg -q "NET core stack deterministic set \(90 cases\) is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_net_core_required] missing net-core promotion marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "NET core stack residual monitored cases: none" "$PENDING_FILE"; then
  echo "[verify_net_core_required] missing net-core residual-none marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_core_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_core_required] PASS"
