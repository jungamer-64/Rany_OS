#!/usr/bin/env bash
set -euo pipefail

# Validates NET endpoint deterministic required wiring (68 cases) for suite_kernel.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENDPOINT_EXPORT_FILE="$ROOT_DIR/kernel/src/net/endpoint/qemu_tests.rs"
KERNEL_WRAPPER_FILE="$ROOT_DIR/kernel/src/qemu_tests.rs"
KERNEL_SUITE_FILE="$ROOT_DIR/qemu-suites/kernel/src/main.rs"
PENDING_FILE="$ROOT_DIR/scripts/qemu_pending_cases.lst"

for required_file in \
  "$ENDPOINT_EXPORT_FILE" \
  "$KERNEL_WRAPPER_FILE" \
  "$KERNEL_SUITE_FILE" \
  "$PENDING_FILE"
do
  if [[ ! -f "$required_file" ]]; then
    echo "[verify_net_endpoint_required] missing file: $required_file" >&2
    exit 1
  fi
done

required_groups=(
  "net_endpoint_congestion_core_exports"
  "net_endpoint_congestion_cubic_exports"
  "net_endpoint_congestion_bbr_exports"
  "net_endpoint_congestion_variant_exports"
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

cases=(
  "congestion_core_initial_state"
  "congestion_core_slow_start_growth"
  "congestion_core_transition_to_congestion_avoidance"
  "congestion_core_fast_retransmit"
  "congestion_core_timeout"
  "congestion_core_available_window"
  "congestion_cubic_initial_state"
  "congestion_cubic_slow_start"
  "congestion_cubic_root"
  "congestion_cubic_fast_recovery"
  "congestion_bbr_initial_state"
  "congestion_bbr_startup_growth"
  "congestion_bbr_rt_prop_tracking"
  "congestion_bbr_available_window"
  "congestion_bbr_bdp_calculation"
  "congestion_bbr_startup_to_drain"
  "congestion_variant_from_algorithm"
  "congestion_variant_with_mss"
  "congestion_variant_newreno_ack_delegation"
  "congestion_variant_cubic_ack_delegation"
  "congestion_variant_bbr_ack_delegation"
  "congestion_variant_timeout_delegation"
  "congestion_variant_reset_delegation"
  "congestion_variant_available_window"
  "congestion_variant_fast_retransmit_newreno"
  "congestion_variant_default"
  "flow_control_initial_state"
  "flow_control_receive_data"
  "flow_control_consume_data"
  "flow_control_zero_window"
  "flow_control_sws_avoidance"
  "flow_control_peer_zero_window"
  "flow_control_probe_timing"
  "futures_sendfuture_wakes_on_send"
  "futures_recv_packet_zero_copy_via_owned_socket"
  "futures_tcp_packet_stream_multiple_packets"
  "futures_udp_packet_stream_delivered"
  "handler_handle_tx_available_requeues_dataready"
  "handler_handle_data_ready_retry_when_no_device"
  "inner_socket_state_transitions"
  "inner_vecdeque_buffer"
  "retransmit_rto_calculator_initial"
  "retransmit_rto_calculator_update"
  "retransmit_rto_calculator_backoff"
  "retransmit_retransmit_queue_push_and_ack"
  "retransmit_retransmit_queue_timeout"
  "retransmit_retransmit_queue_retransmit"
  "retransmit_seq_comparison"
  "segment_tcp_segment_builder"
  "segment_tcp_segment_with_data"
  "segment_tcp_segment_with_options"
  "segment_tcp_message_length_field_for_checksum"
  "socket_owned_socket_raii"
  "tcb_tcp_connection_state"
  "tcb_tcp_control_block_entry"
  "tcb_tcp_flags"
  "core_accepted_connection"
  "core_socket_new_with_fd"
  "core_socket_accept_empty_queue"
  "core_socket_accept_with_connection"
  "core_accept_backlog_limit"
  "types_socket_fd"
  "types_socket_addr"
  "window_scale_disabled"
  "window_scale_enabled"
  "window_scale_advertised_window"
  "window_scale_option_builder"
  "window_scale_option_parser"
)

violations=0

for group in "${required_groups[@]}"; do
  if ! rg -q "$group" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_endpoint_required] missing required suite group '$group' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi
done

for case_name in "${cases[@]}"; do
  export_fn="${case_name}_smoke"
  wrapper_fn="net_endpoint_${case_name}_smoke"

  if ! rg -q "pub fn ${export_fn}\\(" "$ENDPOINT_EXPORT_FILE"; then
    echo "[verify_net_endpoint_required] missing export '${export_fn}' in ${ENDPOINT_EXPORT_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "pub fn ${wrapper_fn}\\(" "$KERNEL_WRAPPER_FILE"; then
    echo "[verify_net_endpoint_required] missing wrapper '${wrapper_fn}' in ${KERNEL_WRAPPER_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

  if ! rg -q "${wrapper_fn}" "$KERNEL_SUITE_FILE"; then
    echo "[verify_net_endpoint_required] missing suite wiring '${wrapper_fn}' in ${KERNEL_SUITE_FILE#$ROOT_DIR/}"
    violations=$((violations + 1))
  fi

done

if ! rg -q "NET endpoint deterministic set \(68 cases\) is promoted to required suite_kernel" "$PENDING_FILE"; then
  echo "[verify_net_endpoint_required] missing endpoint promotion marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if ! rg -q "NET endpoint residual monitored cases: none" "$PENDING_FILE"; then
  echo "[verify_net_endpoint_required] missing endpoint residual-none marker in ${PENDING_FILE#$ROOT_DIR/}"
  violations=$((violations + 1))
fi

if [[ "$violations" -gt 0 ]]; then
  echo "[verify_net_endpoint_required] FAIL: found $violations issues"
  exit 1
fi

echo "[verify_net_endpoint_required] PASS"
