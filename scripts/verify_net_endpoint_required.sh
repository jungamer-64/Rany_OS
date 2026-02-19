#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests/wave8_net_tests/net_endpoint_tests.rs"
ENDPOINT_ROOT="$ROOT_DIR/kernel/src/net/endpoint"
KERNEL_SUITE_ROOT="$ROOT_DIR/qemu-suites/kernel/src"
KERNEL_SUITE_MAIN="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required in "$WRAPPER_FILE" "$ENDPOINT_ROOT" "$KERNEL_SUITE_ROOT" "$KERNEL_SUITE_MAIN" "$PENDING_FILE"; do
  if [[ ! -e "$required" ]]; then
    echo "[verify_net_endpoint_required] missing: $required" >&2
    exit 1
  fi
done

violations=0

# Endpoint qemu-test-export roots
for f in \
  "$ROOT_DIR/kernel/src/net/endpoint.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/congestion.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/congestion/default_and_tests.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/flow_control.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/futures.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/handler.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/inner.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/retransmit.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/segment.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/socket.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/tcb.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/types.rs" \
  "$ROOT_DIR/kernel/src/net/endpoint/window_scale.rs"
do
  if ! rg -q '^\s*pub mod qemu_tests\s*(;|\{)' "$f"; then
    echo "[verify_net_endpoint_required] missing qemu_tests module export in ${f#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

suite_groups=(
  "net_endpoint_congestion_default_exports"
  "net_endpoint_congestion_variant_exports"
  "net_endpoint_congestion_core_exports"
  "net_endpoint_flow_control_exports"
  "net_endpoint_futures_exports"
  "net_endpoint_handler_exports"
  "net_endpoint_inner_exports"
  "net_endpoint_retransmit_exports"
  "net_endpoint_segment_exports"
  "net_endpoint_socket_exports"
  "net_endpoint_tcb_exports"
  "net_endpoint_core_exports"
  "net_endpoint_types_exports"
  "net_endpoint_window_scale_exports"
)

for group in "${suite_groups[@]}"; do
  if ! rg -q "${group}" "$KERNEL_SUITE_MAIN"; then
    echo "[verify_net_endpoint_required] missing run_suite group '${group}' in ${KERNEL_SUITE_MAIN#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
  if ! rg -q "fn test_${group}\(" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_endpoint_required] missing group function test_${group} under ${KERNEL_SUITE_ROOT#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi
done

wrappers=(
  "net_endpoint_congestion_default_cubic_initial_state_smoke"
  "net_endpoint_congestion_default_cubic_slow_start_smoke"
  "net_endpoint_congestion_default_cubic_root_smoke"
  "net_endpoint_congestion_default_cubic_fast_recovery_smoke"
  "net_endpoint_congestion_default_bbr_initial_state_smoke"
  "net_endpoint_congestion_default_bbr_startup_growth_smoke"
  "net_endpoint_congestion_default_bbr_rt_prop_tracking_smoke"
  "net_endpoint_congestion_default_bbr_available_window_smoke"
  "net_endpoint_congestion_default_bbr_bdp_calculation_smoke"
  "net_endpoint_congestion_default_bbr_startup_to_drain_smoke"
  "net_endpoint_congestion_variant_variant_from_algorithm_smoke"
  "net_endpoint_congestion_variant_variant_with_mss_smoke"
  "net_endpoint_congestion_variant_variant_newreno_ack_delegation_smoke"
  "net_endpoint_congestion_variant_variant_cubic_ack_delegation_smoke"
  "net_endpoint_congestion_variant_variant_bbr_ack_delegation_smoke"
  "net_endpoint_congestion_variant_variant_timeout_delegation_smoke"
  "net_endpoint_congestion_variant_variant_reset_delegation_smoke"
  "net_endpoint_congestion_variant_variant_available_window_smoke"
  "net_endpoint_congestion_variant_variant_fast_retransmit_newreno_smoke"
  "net_endpoint_congestion_variant_variant_default_smoke"
  "net_endpoint_congestion_core_initial_state_smoke"
  "net_endpoint_congestion_core_slow_start_growth_smoke"
  "net_endpoint_congestion_core_transition_to_congestion_avoidance_smoke"
  "net_endpoint_congestion_core_fast_retransmit_smoke"
  "net_endpoint_congestion_core_timeout_smoke"
  "net_endpoint_congestion_core_available_window_smoke"
  "net_endpoint_flow_control_initial_state_smoke"
  "net_endpoint_flow_control_receive_data_smoke"
  "net_endpoint_flow_control_consume_data_smoke"
  "net_endpoint_flow_control_zero_window_smoke"
  "net_endpoint_flow_control_sws_avoidance_smoke"
  "net_endpoint_flow_control_peer_zero_window_smoke"
  "net_endpoint_flow_control_probe_timing_smoke"
  "net_endpoint_futures_sendfuture_wakes_on_send_smoke"
  "net_endpoint_futures_recv_packet_zero_copy_via_owned_socket_smoke"
  "net_endpoint_futures_tcp_packet_stream_multiple_packets_smoke"
  "net_endpoint_futures_udp_packet_stream_delivered_smoke"
  "net_endpoint_handler_handle_tx_available_requeues_dataready_smoke"
  "net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke"
  "net_endpoint_inner_socket_state_transitions_smoke"
  "net_endpoint_inner_vecdeque_buffer_smoke"
  "net_endpoint_retransmit_rto_calculator_initial_smoke"
  "net_endpoint_retransmit_rto_calculator_update_smoke"
  "net_endpoint_retransmit_rto_calculator_backoff_smoke"
  "net_endpoint_retransmit_retransmit_queue_push_and_ack_smoke"
  "net_endpoint_retransmit_retransmit_queue_timeout_smoke"
  "net_endpoint_retransmit_retransmit_queue_retransmit_smoke"
  "net_endpoint_retransmit_retransmit_queue_process_sack_smoke"
  "net_endpoint_retransmit_seq_comparison_smoke"
  "net_endpoint_segment_tcp_segment_builder_smoke"
  "net_endpoint_segment_tcp_segment_with_data_smoke"
  "net_endpoint_segment_tcp_segment_with_options_smoke"
  "net_endpoint_segment_tcp_message_length_field_for_checksum_smoke"
  "net_endpoint_socket_owned_socket_raii_smoke"
  "net_endpoint_tcb_tcp_connection_state_smoke"
  "net_endpoint_tcb_tcp_control_block_entry_smoke"
  "net_endpoint_tcb_tcp_flags_smoke"
  "net_endpoint_core_accepted_connection_smoke"
  "net_endpoint_core_socket_new_with_fd_smoke"
  "net_endpoint_core_socket_accept_empty_queue_smoke"
  "net_endpoint_core_socket_accept_with_connection_smoke"
  "net_endpoint_core_accept_backlog_limit_smoke"
  "net_endpoint_types_socket_fd_smoke"
  "net_endpoint_types_socket_addr_smoke"
  "net_endpoint_window_scale_window_scale_disabled_smoke"
  "net_endpoint_window_scale_window_scale_enabled_smoke"
  "net_endpoint_window_scale_advertised_window_smoke"
  "net_endpoint_window_scale_option_builder_smoke"
  "net_endpoint_window_scale_option_parser_smoke"
)

for fn_name in "${wrappers[@]}"; do
  if ! rg -q "pub fn ${fn_name}\(" "$WRAPPER_FILE"; then
    echo "[verify_net_endpoint_required] missing wrapper '${fn_name}' in ${WRAPPER_FILE#"$ROOT_DIR"/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${fn_name}" "$KERNEL_SUITE_ROOT"; then
    echo "[verify_net_endpoint_required] missing suite wiring for '${fn_name}'"
    violations=$((violations + 1))
  fi
done

if ! rg -q 'NET endpoint deterministic set \(69 cases\) is promoted to required suite_kernel' "$PENDING_FILE"; then
  echo "[verify_net_endpoint_required] missing NET endpoint promotion marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if ! rg -q 'NET endpoint residual monitored cases: none' "$PENDING_FILE"; then
  echo "[verify_net_endpoint_required] missing NET endpoint residual none marker in ${PENDING_FILE#"$ROOT_DIR"/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_endpoint_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_endpoint_required] PASS"
