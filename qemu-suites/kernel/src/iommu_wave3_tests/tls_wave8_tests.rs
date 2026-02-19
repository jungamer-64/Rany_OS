use super::*;


pub(crate) fn test_net_tls_wave8_phase_e_exports() -> bool {
    run_check(
        "net_tls_wave8_generate_random_not_all_zeros_smoke",
        rany_os::qemu_tests::net_tls_wave8_generate_random_not_all_zeros_smoke,
    ) && run_check(
        "net_tls_wave8_generate_random_different_calls_smoke",
        rany_os::qemu_tests::net_tls_wave8_generate_random_different_calls_smoke,
    ) && run_check(
        "net_tls_wave8_sha384_empty_smoke",
        rany_os::qemu_tests::net_tls_wave8_sha384_empty_smoke,
    ) && run_check(
        "net_tls_wave8_sha384_abc_smoke",
        rany_os::qemu_tests::net_tls_wave8_sha384_abc_smoke,
    ) && run_check(
        "net_tls_wave8_hmac_sha384_rfc4231_case1_smoke",
        rany_os::qemu_tests::net_tls_wave8_hmac_sha384_rfc4231_case1_smoke,
    ) && run_check(
        "net_tls_wave8_hmac_sha384_rfc4231_case2_smoke",
        rany_os::qemu_tests::net_tls_wave8_hmac_sha384_rfc4231_case2_smoke,
    )
}

pub(crate) fn test_net_tls_wave8_phase_f_exports() -> bool {
    run_check(
        "net_tls_wave8_der_parse_tag_length_smoke",
        rany_os::qemu_tests::net_tls_wave8_der_parse_tag_length_smoke,
    ) && run_check(
        "net_tls_wave8_der_parse_integer_smoke",
        rany_os::qemu_tests::net_tls_wave8_der_parse_integer_smoke,
    ) && run_check(
        "net_tls_wave8_der_parse_sequence_smoke",
        rany_os::qemu_tests::net_tls_wave8_der_parse_sequence_smoke,
    ) && run_check(
        "net_tls_wave8_x509_parse_self_signed_smoke",
        rany_os::qemu_tests::net_tls_wave8_x509_parse_self_signed_smoke,
    ) && run_check(
        "net_tls_wave8_x509_extract_rsa_pubkey_smoke",
        rany_os::qemu_tests::net_tls_wave8_x509_extract_rsa_pubkey_smoke,
    ) && run_check(
        "net_tls_wave8_x509_signature_algorithm_oid_smoke",
        rany_os::qemu_tests::net_tls_wave8_x509_signature_algorithm_oid_smoke,
    ) && run_check(
        "net_tls_wave8_rsa_modexp_small_smoke",
        rany_os::qemu_tests::net_tls_wave8_rsa_modexp_small_smoke,
    ) && run_check(
        "net_tls_wave8_rsa_modexp_medium_smoke",
        rany_os::qemu_tests::net_tls_wave8_rsa_modexp_medium_smoke,
    ) && run_check(
        "net_tls_wave8_rsa_pkcs1_verify_smoke",
        rany_os::qemu_tests::net_tls_wave8_rsa_pkcs1_verify_smoke,
    ) && run_check(
        "net_tls_wave8_rsa_pkcs1_verify_bad_sig_smoke",
        rany_os::qemu_tests::net_tls_wave8_rsa_pkcs1_verify_bad_sig_smoke,
    ) && run_check(
        "net_tls_wave8_rsa_biguint_mul_div_smoke",
        rany_os::qemu_tests::net_tls_wave8_rsa_biguint_mul_div_smoke,
    )
}

pub(crate) fn test_net_ecdh_exports() -> bool {
    run_check(
        "net_ecdh_x25519_key_exchange_symmetry_smoke",
        rany_os::qemu_tests::net_ecdh_x25519_key_exchange_symmetry_smoke,
    ) && run_check(
        "net_ecdh_x25519_public_key_length_smoke",
        rany_os::qemu_tests::net_ecdh_x25519_public_key_length_smoke,
    ) && run_check(
        "net_ecdh_x25519_group_smoke",
        rany_os::qemu_tests::net_ecdh_x25519_group_smoke,
    ) && run_check(
        "net_ecdh_group_from_named_group_smoke",
        rany_os::qemu_tests::net_ecdh_group_from_named_group_smoke,
    ) && run_check(
        "net_ecdh_x25519_reject_invalid_peer_key_smoke",
        rany_os::qemu_tests::net_ecdh_x25519_reject_invalid_peer_key_smoke,
    ) && run_check(
        "net_ecdh_x25519_rfc7748_vector_smoke",
        rany_os::qemu_tests::net_ecdh_x25519_rfc7748_vector_smoke,
    )
}

pub(crate) fn test_net_ecdh_phase_b_exports() -> bool {
    run_check(
        "net_ecdh_p256_key_exchange_symmetry_smoke",
        rany_os::qemu_tests::net_ecdh_p256_key_exchange_symmetry_smoke,
    ) && run_check(
        "net_ecdh_p256_public_key_length_smoke",
        rany_os::qemu_tests::net_ecdh_p256_public_key_length_smoke,
    ) && run_check(
        "net_ecdh_p256_reject_invalid_peer_key_smoke",
        rany_os::qemu_tests::net_ecdh_p256_reject_invalid_peer_key_smoke,
    ) && run_check(
        "net_ecdh_group_from_named_group_p256_smoke",
        rany_os::qemu_tests::net_ecdh_group_from_named_group_p256_smoke,
    ) && run_check(
        "net_ecdh_p256_point_on_curve_smoke",
        rany_os::qemu_tests::net_ecdh_p256_point_on_curve_smoke,
    ) && run_check(
        "net_ecdh_p256_scalar_mul_base_smoke",
        rany_os::qemu_tests::net_ecdh_p256_scalar_mul_base_smoke,
    )
}

pub(crate) fn test_iommu_wave5_canonical_exports() -> bool {
    run_check(
        "iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke,
    ) && run_check(
        "iommu_wave5_map_for_device_respects_dma_mask_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_map_for_device_respects_dma_mask_canonical_smoke,
    ) && run_check(
        "iommu_wave5_api_security_notifier_registration_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_api_security_notifier_registration_canonical_smoke,
    ) && run_check(
        "iommu_wave5_qi_metrics_pressure_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_qi_metrics_pressure_canonical_smoke,
    ) && run_check(
        "iommu_wave5_map_for_device_async_and_unmap_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_map_for_device_async_and_unmap_canonical_smoke,
    )
}

pub(crate) fn test_kernel_driver_cell_exports() -> bool {
    run_check(
        "driver_cell_state_default_is_created_smoke",
        rany_os::qemu_tests::driver_cell_state_default_is_created_smoke,
    ) && run_check(
        "driver_cell_state_transitions_are_valid_smoke",
        rany_os::qemu_tests::driver_cell_state_transitions_are_valid_smoke,
    ) && run_check(
        "driver_cell_state_faulted_smoke",
        rany_os::qemu_tests::driver_cell_state_faulted_smoke,
    ) && run_check(
        "driver_cell_id_equality_smoke",
        rany_os::qemu_tests::driver_cell_id_equality_smoke,
    ) && run_check(
        "driver_cell_id_ordering_smoke",
        rany_os::qemu_tests::driver_cell_id_ordering_smoke,
    ) && run_check(
        "driver_cell_restart_policy_never_smoke",
        rany_os::qemu_tests::driver_cell_restart_policy_never_smoke,
    ) && run_check(
        "driver_cell_restart_policy_on_panic_defaults_smoke",
        rany_os::qemu_tests::driver_cell_restart_policy_on_panic_defaults_smoke,
    ) && run_check(
        "driver_cell_restart_policy_always_smoke",
        rany_os::qemu_tests::driver_cell_restart_policy_always_smoke,
    ) && run_check(
        "driver_cell_fault_kind_variants_smoke",
        rany_os::qemu_tests::driver_cell_fault_kind_variants_smoke,
    ) && run_check(
        "driver_cell_stats_initial_values_smoke",
        rany_os::qemu_tests::driver_cell_stats_initial_values_smoke,
    ) && run_check(
        "driver_cell_stats_default_smoke",
        rany_os::qemu_tests::driver_cell_stats_default_smoke,
    ) && run_check(
        "driver_cell_stats_record_start_smoke",
        rany_os::qemu_tests::driver_cell_stats_record_start_smoke,
    ) && run_check(
        "driver_cell_stats_record_stop_smoke",
        rany_os::qemu_tests::driver_cell_stats_record_stop_smoke,
    ) && run_check(
        "driver_cell_stats_record_fault_smoke",
        rany_os::qemu_tests::driver_cell_stats_record_fault_smoke,
    ) && run_check(
        "driver_cell_stats_record_restart_smoke",
        rany_os::qemu_tests::driver_cell_stats_record_restart_smoke,
    ) && run_check(
        "driver_cell_stats_record_hot_swap_smoke",
        rany_os::qemu_tests::driver_cell_stats_record_hot_swap_smoke,
    ) && run_check(
        "driver_cell_error_not_found_smoke",
        rany_os::qemu_tests::driver_cell_error_not_found_smoke,
    ) && run_check(
        "driver_cell_error_invalid_state_smoke",
        rany_os::qemu_tests::driver_cell_error_invalid_state_smoke,
    ) && run_check(
        "driver_cell_global_stats_new_smoke",
        rany_os::qemu_tests::driver_cell_global_stats_new_smoke,
    ) && run_check(
        "driver_cell_global_stats_tracking_smoke",
        rany_os::qemu_tests::driver_cell_global_stats_tracking_smoke,
    )
}

pub(crate) fn report_iommu_wave2_runtime_readiness() -> bool {
    serial_write_str("[qemu-suite] kernel info iommu_wave2 runtime_ready=");
    if rany_os::memory::is_initialized() {
        serial_write_str("1\n");
    } else {
        serial_write_str("0\n");
    }
    true
}

pub(crate) fn serial_write_str(s: &str) {
    for b in s.bytes() {
        serial_write_byte(b);
    }
}

pub(crate) fn serial_write_byte(byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") byte,
            options(nostack, nomem, preserves_flags)
        );
    }
}

pub(crate) struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial_write_str(s);
        Ok(())
    }
}

pub(crate) fn suite_fail_trap() -> ! {
    #[cfg(not(target_os = "uefi"))]
    {
        exit_qemu(0x11)
    }
    #[cfg(target_os = "uefi")]
    {
        loop {
            core::hint::spin_loop();
        }
    }
}

#[cfg(not(target_os = "uefi"))]
pub(crate) fn exit_qemu(code: u32) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xf4u16,
            in("eax") code,
            options(nostack, nomem, preserves_flags)
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

pub(crate) fn test_net_endpoint_congestion_default_exports() -> bool {
    run_check(
        "net_endpoint_congestion_default_cubic_initial_state_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_cubic_initial_state_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_cubic_slow_start_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_cubic_slow_start_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_cubic_root_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_cubic_root_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_cubic_fast_recovery_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_cubic_fast_recovery_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_bbr_initial_state_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_bbr_initial_state_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_bbr_startup_growth_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_bbr_startup_growth_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_bbr_rt_prop_tracking_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_bbr_rt_prop_tracking_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_bbr_available_window_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_bbr_available_window_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_bbr_bdp_calculation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_bbr_bdp_calculation_smoke,
    ) && run_check(
        "net_endpoint_congestion_default_bbr_startup_to_drain_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_default_bbr_startup_to_drain_smoke,
    )
}

pub(crate) fn test_net_endpoint_congestion_variant_exports() -> bool {
    run_check(
        "net_endpoint_congestion_variant_variant_from_algorithm_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_from_algorithm_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_with_mss_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_with_mss_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_newreno_ack_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_newreno_ack_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_cubic_ack_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_cubic_ack_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_bbr_ack_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_bbr_ack_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_timeout_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_timeout_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_reset_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_reset_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_available_window_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_available_window_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_fast_retransmit_newreno_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_fast_retransmit_newreno_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_variant_default_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_variant_default_smoke,
    )
}

pub(crate) fn test_net_endpoint_congestion_core_exports() -> bool {
    run_check(
        "net_endpoint_congestion_core_initial_state_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_core_initial_state_smoke,
    ) && run_check(
        "net_endpoint_congestion_core_slow_start_growth_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_core_slow_start_growth_smoke,
    ) && run_check(
        "net_endpoint_congestion_core_transition_to_congestion_avoidance_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_core_transition_to_congestion_avoidance_smoke,
    ) && run_check(
        "net_endpoint_congestion_core_fast_retransmit_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_core_fast_retransmit_smoke,
    ) && run_check(
        "net_endpoint_congestion_core_timeout_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_core_timeout_smoke,
    ) && run_check(
        "net_endpoint_congestion_core_available_window_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_core_available_window_smoke,
    )
}

pub(crate) fn test_net_endpoint_flow_control_exports() -> bool {
    run_check(
        "net_endpoint_flow_control_initial_state_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_initial_state_smoke,
    ) && run_check(
        "net_endpoint_flow_control_receive_data_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_receive_data_smoke,
    ) && run_check(
        "net_endpoint_flow_control_consume_data_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_consume_data_smoke,
    ) && run_check(
        "net_endpoint_flow_control_zero_window_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_zero_window_smoke,
    ) && run_check(
        "net_endpoint_flow_control_sws_avoidance_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_sws_avoidance_smoke,
    ) && run_check(
        "net_endpoint_flow_control_peer_zero_window_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_peer_zero_window_smoke,
    ) && run_check(
        "net_endpoint_flow_control_probe_timing_smoke",
        rany_os::qemu_tests::net_endpoint_flow_control_probe_timing_smoke,
    )
}

pub(crate) fn test_net_endpoint_futures_exports() -> bool {
    run_check(
        "net_endpoint_futures_sendfuture_wakes_on_send_smoke",
        rany_os::qemu_tests::net_endpoint_futures_sendfuture_wakes_on_send_smoke,
    ) && run_check(
        "net_endpoint_futures_recv_packet_zero_copy_via_owned_socket_smoke",
        rany_os::qemu_tests::net_endpoint_futures_recv_packet_zero_copy_via_owned_socket_smoke,
    ) && run_check(
        "net_endpoint_futures_tcp_packet_stream_multiple_packets_smoke",
        rany_os::qemu_tests::net_endpoint_futures_tcp_packet_stream_multiple_packets_smoke,
    ) && run_check(
        "net_endpoint_futures_udp_packet_stream_delivered_smoke",
        rany_os::qemu_tests::net_endpoint_futures_udp_packet_stream_delivered_smoke,
    )
}

pub(crate) fn test_net_endpoint_handler_exports() -> bool {
    run_check(
        "net_endpoint_handler_handle_tx_available_requeues_dataready_smoke",
        rany_os::qemu_tests::net_endpoint_handler_handle_tx_available_requeues_dataready_smoke,
    ) && run_check(
        "net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke",
        rany_os::qemu_tests::net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke,
    )
}

pub(crate) fn test_net_endpoint_inner_exports() -> bool {
    run_check(
        "net_endpoint_inner_socket_state_transitions_smoke",
        rany_os::qemu_tests::net_endpoint_inner_socket_state_transitions_smoke,
    ) && run_check(
        "net_endpoint_inner_vecdeque_buffer_smoke",
        rany_os::qemu_tests::net_endpoint_inner_vecdeque_buffer_smoke,
    )
}

pub(crate) fn test_net_endpoint_retransmit_exports() -> bool {
    run_check(
        "net_endpoint_retransmit_rto_calculator_initial_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_rto_calculator_initial_smoke,
    ) && run_check(
        "net_endpoint_retransmit_rto_calculator_update_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_rto_calculator_update_smoke,
    ) && run_check(
        "net_endpoint_retransmit_rto_calculator_backoff_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_rto_calculator_backoff_smoke,
    ) && run_check(
        "net_endpoint_retransmit_retransmit_queue_push_and_ack_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_retransmit_queue_push_and_ack_smoke,
    ) && run_check(
        "net_endpoint_retransmit_retransmit_queue_timeout_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_retransmit_queue_timeout_smoke,
    ) && run_check(
        "net_endpoint_retransmit_retransmit_queue_retransmit_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_retransmit_queue_retransmit_smoke,
    ) && run_check(
        "net_endpoint_retransmit_retransmit_queue_process_sack_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_retransmit_queue_process_sack_smoke,
    ) && run_check(
        "net_endpoint_retransmit_seq_comparison_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_seq_comparison_smoke,
    )
}

pub(crate) fn test_net_endpoint_segment_exports() -> bool {
    run_check(
        "net_endpoint_segment_tcp_segment_builder_smoke",
        rany_os::qemu_tests::net_endpoint_segment_tcp_segment_builder_smoke,
    ) && run_check(
        "net_endpoint_segment_tcp_segment_with_data_smoke",
        rany_os::qemu_tests::net_endpoint_segment_tcp_segment_with_data_smoke,
    ) && run_check(
        "net_endpoint_segment_tcp_segment_with_options_smoke",
        rany_os::qemu_tests::net_endpoint_segment_tcp_segment_with_options_smoke,
    ) && run_check(
        "net_endpoint_segment_tcp_message_length_field_for_checksum_smoke",
        rany_os::qemu_tests::net_endpoint_segment_tcp_message_length_field_for_checksum_smoke,
    )
}

pub(crate) fn test_net_endpoint_socket_exports() -> bool {
    run_check(
        "net_endpoint_socket_owned_socket_raii_smoke",
        rany_os::qemu_tests::net_endpoint_socket_owned_socket_raii_smoke,
    )
}

pub(crate) fn test_net_endpoint_tcb_exports() -> bool {
    run_check(
        "net_endpoint_tcb_tcp_connection_state_smoke",
        rany_os::qemu_tests::net_endpoint_tcb_tcp_connection_state_smoke,
    ) && run_check(
        "net_endpoint_tcb_tcp_control_block_entry_smoke",
        rany_os::qemu_tests::net_endpoint_tcb_tcp_control_block_entry_smoke,
    ) && run_check(
        "net_endpoint_tcb_tcp_flags_smoke",
        rany_os::qemu_tests::net_endpoint_tcb_tcp_flags_smoke,
    )
}

pub(crate) fn test_net_endpoint_core_exports() -> bool {
    run_check(
        "net_endpoint_core_accepted_connection_smoke",
        rany_os::qemu_tests::net_endpoint_core_accepted_connection_smoke,
    ) && run_check(
        "net_endpoint_core_socket_new_with_fd_smoke",
        rany_os::qemu_tests::net_endpoint_core_socket_new_with_fd_smoke,
    ) && run_check(
        "net_endpoint_core_socket_accept_empty_queue_smoke",
        rany_os::qemu_tests::net_endpoint_core_socket_accept_empty_queue_smoke,
    ) && run_check(
        "net_endpoint_core_socket_accept_with_connection_smoke",
        rany_os::qemu_tests::net_endpoint_core_socket_accept_with_connection_smoke,
    ) && run_check(
        "net_endpoint_core_accept_backlog_limit_smoke",
        rany_os::qemu_tests::net_endpoint_core_accept_backlog_limit_smoke,
    )
}

pub(crate) fn test_net_endpoint_types_exports() -> bool {
    run_check(
        "net_endpoint_types_socket_fd_smoke",
        rany_os::qemu_tests::net_endpoint_types_socket_fd_smoke,
    ) && run_check(
        "net_endpoint_types_socket_addr_smoke",
        rany_os::qemu_tests::net_endpoint_types_socket_addr_smoke,
    )
}

pub(crate) fn test_net_endpoint_window_scale_exports() -> bool {
    run_check(
        "net_endpoint_window_scale_window_scale_disabled_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_window_scale_disabled_smoke,
    ) && run_check(
        "net_endpoint_window_scale_window_scale_enabled_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_window_scale_enabled_smoke,
    ) && run_check(
        "net_endpoint_window_scale_advertised_window_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_advertised_window_smoke,
    ) && run_check(
        "net_endpoint_window_scale_option_builder_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_option_builder_smoke,
    ) && run_check(
        "net_endpoint_window_scale_option_parser_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_option_parser_smoke,
    )
}
