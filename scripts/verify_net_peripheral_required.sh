#!/usr/bin/env bash
set -euo pipefail

# Validates NET peripheral deterministic required wiring (67 cases) for suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET_EXPORT_ROOT="$ROOT_DIR/kernel/src/net/qemu_tests"
NET_EXPORT_FILE="$ROOT_DIR/kernel/src/net/qemu_tests.rs"
KERNEL_WRAPPER_ROOT="$ROOT_DIR/kernel/src/qemu_tests"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_path in "$NET_EXPORT_ROOT" "$NET_EXPORT_FILE" "$KERNEL_WRAPPER_ROOT" "$KERNEL_WRAPPER_FILE" "$KERNEL_SUITE_ROOT" "$PENDING_FILE"; do
  if [[ ! -e "$required_path" ]]; then
    echo "[verify_net_peripheral_required] missing path: $required_path" >&2
    exit 1
  fi
done

violations=0

required_groups=(
  "net_peripheral_dhcp_v4_exports"
  "net_peripheral_dhcp_v6_exports"
  "net_peripheral_dns_exports"
  "net_peripheral_mdns_exports"
  "net_peripheral_igmp_exports"
  "net_peripheral_driver_bridge_exports"
)

phase_b_original_cases=(
  "test_zero_copy_via_bridge"
  "test_routing_and_nat"
  "test_nat_inbound_roundtrip_is_protocol_scoped"
  "test_nat_gc_expires_idle_entries"
  "test_zero_copy_via_bridge_v6"
  "test_per_interface_bridge_stats_are_separated"
  "test_register_virtio_port_is_idempotent_and_records_mapping"
  "test_register_virtio_port_prefers_vnet0_as_primary"
  "test_virtio_transmit_interface_argument"
)

all_cases=(
  "dhcp_v4:check_timeout_poisoned_state_reset_skips"
  "dhcp_v4:build_request_renewal_uses_ciaddr_and_omits_serverid_requestedip"
  "dhcp_v4:build_request_requesting_includes_serverid_and_requestedip"
  "dhcp_v4:build_discover_reuse_xid_on_retransmit"
  "dhcp_v4:build_discover_state_lock_poison_returns_err"
  "dhcp_v4:process_response_chaddr_mismatch"
  "dhcp_v4:process_response_offer_missing_serverid_returns_err"
  "dhcp_v4:process_response_siaddr_serverid_mismatch"
  "dhcp_v4:process_response_ack_requesting_mismatch"
  "dhcp_v4:process_response_ack_renewal_success"
  "dhcp_v4:build_decline_and_build_release_contents"
  "dhcp_v4:release_clears_lease_and_sets_last_released"
  "dhcp_v4:parse_t1_t2_and_timeout_transitions"
  "dhcp_v4:offer_probe_and_decline_flow"
  "dhcp_v4:runtime_api_lastfields_smoke"
  "dhcp_v6:build_solicit_min_size"
  "dhcp_v6:parse_reply_with_iaaddr"
  "dhcp_v6:build_request_min_size"
  "dhcp_v6:bound_to_renewing_and_rebinding_transitions"
  "dhcp_v6:handle_packet_stores_server_addr_and_duid"
  "dhcp_v6:advertise_triggers_request_and_requesting_state"
  "dhcp_v6:requesting_retransmit_exhaustion_goes_to_init"
  "dhcp_v6:solicit_advertise_request_reply_complete_flow"
  "dhcp_v6:renew_uses_known_server_address_for_dst"
  "dns:primary_server_poisoned_returns_none"
  "dns:dns_header_truncated_flag"
  "dns:dns_header_not_truncated"
  "dns:build_tcp_query"
  "dns:needs_tcp_fallback_truncated"
  "dns:needs_tcp_fallback_512_bytes"
  "dns:needs_tcp_fallback_normal"
  "dns:tcp_message_length"
  "mdns:constants"
  "mdns:multicast_mac"
  "mdns:mdns_service_new"
  "mdns:encode_decode_dns_name"
  "mdns:build_query"
  "mdns:build_response"
  "mdns:process_query_for_our_hostname"
  "mdns:process_query_for_other_hostname"
  "mdns:process_response_updates_cache"
  "mdns:cleanup_expired"
  "mdns:invalid_packet_too_short"
  "mdns:names_equal_case_insensitive"
  "mdns:dns_name_compression"
  "mdns:encode_dns_name_label_too_long"
  "mdns:roundtrip_query_response"
  "igmp:igmp_type_conversion"
  "igmp:multicast_validation"
  "igmp:join_group"
  "igmp:join_invalid_address"
  "igmp:leave_group"
  "igmp:leave_nonmember"
  "igmp:igmp_checksum"
  "igmp:build_report"
  "igmp:build_leave"
  "igmp:multicast_ip_to_mac"
  "igmp:process_general_query"
  "igmp:report_suppression"
  "driver_bridge:zero_copy_via_bridge"
  "driver_bridge:routing_and_nat"
  "driver_bridge:nat_inbound_roundtrip_is_protocol_scoped"
  "driver_bridge:nat_gc_expires_idle_entries"
  "driver_bridge:zero_copy_via_bridge_v6"
  "driver_bridge:per_interface_bridge_stats_are_separated"
  "driver_bridge:register_virtio_port_is_idempotent_and_records_mapping"
  "driver_bridge:register_virtio_port_prefers_vnet0_as_primary"
  "driver_bridge:virtio_transmit_interface_argument"
)

for group in "${required_groups[@]}"; do
  if ! rg -q "$group" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_peripheral_required] missing suite group $group under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

for item in "${all_cases[@]}"; do
  module_slug="${item%%:*}"
  short_case="${item#*:}"
  export_fn="${module_slug}_${short_case}_smoke"
  wrapper_fn="net_peripheral_${module_slug}_${short_case}_smoke"

  if ! rg -q "pub fn ${export_fn}\(" "$NET_EXPORT_FILE" "$NET_EXPORT_ROOT"; then
    echo "[verify_net_peripheral_required] missing export ${export_fn} under kernel/src/net/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT"; then
    echo "[verify_net_peripheral_required] missing wrapper ${wrapper_fn} under kernel/src/qemu_tests*"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_peripheral_required] missing suite wiring ${wrapper_fn} under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

group_count=$(rg -n "^fn test_net_peripheral_.*_exports\(\) -> bool|^pub\(crate\) fn test_net_peripheral_.*_exports\(\) -> bool" "$KERNEL_SUITE_ROOT" | wc -l | tr -d " ")
if [[ "$group_count" != "6" ]]; then
  echo "[verify_net_peripheral_required] expected 6 net_peripheral group fns, got $group_count"
  violations=$((violations + 1))
fi

wrapper_count=$(rg -n "^pub fn net_peripheral_.*_smoke\(" "$KERNEL_WRAPPER_FILE" "$KERNEL_WRAPPER_ROOT" | wc -l | tr -d " ")
if [[ "$wrapper_count" != "67" ]]; then
  echo "[verify_net_peripheral_required] expected 67 net_peripheral wrappers, got $wrapper_count"
  violations=$((violations + 1))
fi

export_count=$(rg -n "^pub fn (dhcp_v4|dhcp_v6|dns|mdns|igmp|driver_bridge)_.*_smoke\(" "$NET_EXPORT_FILE" "$NET_EXPORT_ROOT" | wc -l | tr -d " ")
if [[ "$export_count" != "67" ]]; then
  echo "[verify_net_peripheral_required] expected 67 net_peripheral exports, got $export_count"
  violations=$((violations + 1))
fi

phase_a_marker="NET peripheral Phase A deterministic set (58 cases) is promoted to required suite_kernel"
phase_b_residual_marker="NET peripheral Phase B residual monitored cases (driver_bridge, list-only):"
final_marker="NET peripheral deterministic set (67 cases) is promoted to required suite_kernel"
final_residual_marker="NET peripheral residual monitored cases: none"

if rg -Fq "$final_marker" "$PENDING_FILE"; then
  if ! rg -Fq "$final_residual_marker" "$PENDING_FILE"; then
    echo "[verify_net_peripheral_required] final residual-none marker missing in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
  for t in "${phase_b_original_cases[@]}"; do
    if rg -q "\b${t}\b" "$PENDING_FILE"; then
      echo "[verify_net_peripheral_required] promoted driver_bridge case still listed in pending tracker: $t"
      violations=$((violations + 1))
    fi
  done
else
  # Phase A intermediate state is allowed while Phase B is not yet promoted.
  if ! rg -Fq "$phase_a_marker" "$PENDING_FILE"; then
    echo "[verify_net_peripheral_required] missing Phase A marker or final marker in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
  if ! rg -Fq "$phase_b_residual_marker" "$PENDING_FILE"; then
    echo "[verify_net_peripheral_required] missing driver_bridge Phase B residual marker in ${PENDING_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_peripheral_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_peripheral_required] PASS"
