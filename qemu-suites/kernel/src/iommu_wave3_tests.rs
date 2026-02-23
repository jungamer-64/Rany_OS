use super::*;

mod tls_wave8_tests;
pub(crate) use tls_wave8_tests::*;
pub(crate) fn test_iommu_wave3_pasid_exports() -> bool {
    run_check(
        "iommu_wave3_pasid_table_alloc_free_smoke",
        rany_os::qemu_tests::iommu_wave3_pasid_table_alloc_free_smoke,
    ) && run_check(
        "iommu_wave3_pasid_table_multi_domain_smoke",
        rany_os::qemu_tests::iommu_wave3_pasid_table_multi_domain_smoke,
    ) && run_check(
        "iommu_wave3_pasid_table_exhaustion_smoke",
        rany_os::qemu_tests::iommu_wave3_pasid_table_exhaustion_smoke,
    )
}

pub(crate) fn test_iommu_wave3_core_structures_exports() -> bool {
    run_check(
        "iommu_wave3_mapping_slab_insert_lookup_remove_smoke",
        rany_os::qemu_tests::iommu_wave3_mapping_slab_insert_lookup_remove_smoke,
    ) && run_check(
        "iommu_wave3_mapping_slab_overlap_detection_smoke",
        rany_os::qemu_tests::iommu_wave3_mapping_slab_overlap_detection_smoke,
    ) && run_check(
        "iommu_wave3_zombie_queue_basic_smoke",
        rany_os::qemu_tests::iommu_wave3_zombie_queue_basic_smoke,
    ) && run_check(
        "iommu_wave3_zombie_queue_failed_cleanup_smoke",
        rany_os::qemu_tests::iommu_wave3_zombie_queue_failed_cleanup_smoke,
    ) && run_check(
        "iommu_wave3_pri_fuel_processing_smoke",
        rany_os::qemu_tests::iommu_wave3_pri_fuel_processing_smoke,
    )
}

pub(crate) fn test_iommu_wave4_amd_exports() -> bool {
    run_check(
        "iommu_amd_wave0_alias_devids_for_device_dedup_smoke",
        rany_os::qemu_tests::iommu_amd_wave0_alias_devids_for_device_dedup_smoke,
    ) && run_check(
        "iommu_amd_wave0_alias_devids_for_device_no_match_smoke",
        rany_os::qemu_tests::iommu_amd_wave0_alias_devids_for_device_no_match_smoke,
    ) && run_check(
        "iommu_amd_wave0_ivhd_flags_for_device_combined_smoke",
        rany_os::qemu_tests::iommu_amd_wave0_ivhd_flags_for_device_combined_smoke,
    ) && run_check(
        "iommu_amd_wave0_ivhd_flags_for_device_acpi_hid_smoke",
        rany_os::qemu_tests::iommu_amd_wave0_ivhd_flags_for_device_acpi_hid_smoke,
    ) && run_check(
        "iommu_amd_wave0_map_ivmd_ranges_exclusion_splits_smoke",
        rany_os::qemu_tests::iommu_amd_wave0_map_ivmd_ranges_exclusion_splits_smoke,
    ) && run_check(
        "iommu_amd_wave0_map_for_device_rejects_exclusion_range_smoke",
        rany_os::qemu_tests::iommu_amd_wave0_map_for_device_rejects_exclusion_range_smoke,
    )
}

pub(crate) fn test_iommu_wave5_amd_exports() -> bool {
    // Wave5 required set:
    // - AMD Wave1 residual parity smokes (5)
    // - AMD Wave5 interrupt remapping smokes (6)
    run_check(
        "iommu_amd_wave1_cmdqueue_map_unmap_with_domain_smoke",
        rany_os::qemu_tests::iommu_amd_wave1_cmdqueue_map_unmap_with_domain_smoke,
    ) && run_check(
        "iommu_amd_wave1_map_device_nonblocking_smoke",
        rany_os::qemu_tests::iommu_amd_wave1_map_device_nonblocking_smoke,
    ) && run_check(
        "iommu_amd_wave1_dma_mask_respects_32bit_limit_smoke",
        rany_os::qemu_tests::iommu_amd_wave1_dma_mask_respects_32bit_limit_smoke,
    ) && run_check(
        "iommu_amd_wave1_security_notifier_dispatch_smoke",
        rany_os::qemu_tests::iommu_amd_wave1_security_notifier_dispatch_smoke,
    ) && run_check(
        "iommu_amd_wave1_cmdqueue_pressure_smoke",
        rany_os::qemu_tests::iommu_amd_wave1_cmdqueue_pressure_smoke,
    ) && run_check(
        "iommu_amd_wave5_irt_entry_construction_smoke",
        rany_os::qemu_tests::iommu_amd_wave5_irt_entry_construction_smoke,
    ) && run_check(
        "iommu_amd_wave5_irt_alloc_free_smoke",
        rany_os::qemu_tests::iommu_amd_wave5_irt_alloc_free_smoke,
    ) && run_check(
        "iommu_amd_wave5_irt_exhaustion_smoke",
        rany_os::qemu_tests::iommu_amd_wave5_irt_exhaustion_smoke,
    ) && run_check(
        "iommu_amd_wave5_irt_invalidation_cmd_format_smoke",
        rany_os::qemu_tests::iommu_amd_wave5_irt_invalidation_cmd_format_smoke,
    ) && run_check(
        "iommu_amd_wave5_map_interrupt_returns_handle_smoke",
        rany_os::qemu_tests::iommu_amd_wave5_map_interrupt_returns_handle_smoke,
    ) && run_check(
        "iommu_amd_wave5_get_remap_msi_message_format_smoke",
        rany_os::qemu_tests::iommu_amd_wave5_get_remap_msi_message_format_smoke,
    )
}

pub(crate) fn test_graphics_framebuffer_wave6_phase_a_exports() -> bool {
    run_check(
        "graphics_wave6_draw_image_32bit_bgra_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_32bit_bgra_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_image_24bit_bgr_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_24bit_bgr_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_write_bgr_run_small_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_small_mmio_smoke,
    ) && run_check(
        "graphics_wave6_write_bgr_run_large_mmio_full_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_large_mmio_full_smoke,
    ) && run_check(
        "graphics_wave6_write_bgr_run_large_mmio_full_unaligned_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_large_mmio_full_unaligned_smoke,
    ) && run_check(
        "graphics_wave6_write_bgr_run_small_mmio_pairs_aligned_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_small_mmio_pairs_aligned_smoke,
    ) && run_check(
        "graphics_wave6_write_bgr_run_small_mmio_generic_unaligned_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_small_mmio_generic_unaligned_smoke,
    ) && run_check(
        "graphics_wave6_draw_hline_32bit_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_hline_32bit_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_text_space_32bit_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_text_space_32bit_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_line_matches_naive_32bit_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_line_matches_naive_32bit_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_line_matches_naive_24bit_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_line_matches_naive_24bit_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_text_space_24bit_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_text_space_24bit_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_image_32bit_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_32bit_mmio_smoke,
    ) && run_check(
        "graphics_wave6_draw_image_24bit_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_24bit_mmio_smoke,
    ) && run_check(
        "graphics_wave6_draw_image_32bit_mmio_rgba_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_32bit_mmio_rgba_smoke,
    ) && run_check(
        "graphics_wave6_write_bytes_mmio_alignment_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bytes_mmio_alignment_smoke,
    ) && run_check(
        "graphics_wave6_write_opaque_run_24bit_even_odd_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_write_opaque_run_24bit_even_odd_mmio_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgra_basic_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgra_basic_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgra_scalar_random_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgra_scalar_random_smoke,
    ) && run_check(
        "graphics_wave6_draw_image_bgra_stream_matches_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_bgra_stream_matches_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_fill_rect_32bit_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_fill_rect_32bit_mmio_smoke,
    ) && run_check(
        "graphics_wave6_dirty_rect_tracking_smoke",
        rany_os::qemu_tests::graphics_wave6_dirty_rect_tracking_smoke,
    ) && run_check(
        "graphics_wave6_dirty_rect_flush_only_marked_area_smoke",
        rany_os::qemu_tests::graphics_wave6_dirty_rect_flush_only_marked_area_smoke,
    ) && run_check(
        "graphics_wave6_draw_text_partial_left_clip_32bit_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_text_partial_left_clip_32bit_backbuffer_smoke,
    )
}

pub(crate) fn test_graphics_framebuffer_wave6_phase_b_exports() -> bool {
    run_check(
        "graphics_wave6_write_bgr_run_large_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_large_mmio_smoke,
    ) && run_check(
        "graphics_wave6_write_bgr_run_large_smoke",
        rany_os::qemu_tests::graphics_wave6_write_bgr_run_large_smoke,
    ) && run_check(
        "graphics_wave6_draw_image_24bit_rgb888_backbuffer_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_image_24bit_rgb888_backbuffer_smoke,
    ) && run_check(
        "graphics_wave6_draw_hline_24bit_rgb888_mmio_smoke",
        rany_os::qemu_tests::graphics_wave6_draw_hline_24bit_rgb888_mmio_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgra_ssse3_matches_scalar_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgra_ssse3_matches_scalar_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgra_avx2_matches_scalar_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgra_avx2_matches_scalar_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgr24_avx2_matches_scalar_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgr24_avx2_matches_scalar_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgr24_ssse3_matches_scalar_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgr24_ssse3_matches_scalar_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgra_neon_matches_scalar_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgra_neon_matches_scalar_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgr24_neon_matches_scalar_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgr24_neon_matches_scalar_smoke,
    ) && run_check(
        "graphics_wave6_pack_rgba_to_bgr24_neon_matches_scalar_rgb_smoke",
        rany_os::qemu_tests::graphics_wave6_pack_rgba_to_bgr24_neon_matches_scalar_rgb_smoke,
    ) && run_check(
        "graphics_wave6_packer_env_override_no_std_smoke",
        rany_os::qemu_tests::graphics_wave6_packer_env_override_no_std_smoke,
    )
}

pub(crate) fn test_graphics_framebuffer_wave6_bench_exports() -> bool {
    run_check(
        "graphics_wave6_bench_draw_image_bulk_smoke",
        rany_os::qemu_tests::graphics_wave6_bench_draw_image_bulk_smoke,
    ) && run_check(
        "graphics_wave6_bench_draw_image_24bit_bulk_smoke",
        rany_os::qemu_tests::graphics_wave6_bench_draw_image_24bit_bulk_smoke,
    ) && run_check(
        "graphics_wave6_bench_draw_image_rgba_bulk_smoke",
        rany_os::qemu_tests::graphics_wave6_bench_draw_image_rgba_bulk_smoke,
    ) && run_check(
        "graphics_wave6_bench_draw_hline_bulk_smoke",
        rany_os::qemu_tests::graphics_wave6_bench_draw_hline_bulk_smoke,
    ) && run_check(
        "graphics_wave6_bench_draw_text_bulk_smoke",
        rany_os::qemu_tests::graphics_wave6_bench_draw_text_bulk_smoke,
    )
}

pub(crate) fn test_mm_wave7_async_swapout_exports() -> bool {
    run_check(
        "mm_wave7_buffer_pool_4k_basic_smoke",
        rany_os::qemu_tests::mm_wave7_buffer_pool_4k_basic_smoke,
    ) && run_check(
        "mm_wave7_buffer_pool_2m_basic_smoke",
        rany_os::qemu_tests::mm_wave7_buffer_pool_2m_basic_smoke,
    )
}

pub(crate) fn test_mm_wave7_async_swapout_phase_d_exports() -> bool {
    run_check(
        "mm_wave7_enqueue_override_forces_error_smoke",
        rany_os::qemu_tests::mm_wave7_enqueue_override_forces_error_smoke,
    ) && run_check(
        "mm_wave7_token_exhaustion_rolls_back_pending_smoke",
        rany_os::qemu_tests::mm_wave7_token_exhaustion_rolls_back_pending_smoke,
    ) && run_check(
        "mm_wave7_token_bucket_clamp_smoke",
        rany_os::qemu_tests::mm_wave7_token_bucket_clamp_smoke,
    ) && run_check(
        "mm_wave7_runtime_tunable_roundtrip_smoke",
        rany_os::qemu_tests::mm_wave7_runtime_tunable_roundtrip_smoke,
    )
}

pub(crate) fn test_mm_wave7_async_swapout_phase_e_exports() -> bool {
    run_check(
        "mm_wave7_memcg_concurrent_swapout_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_memcg_concurrent_swapout_canonical_smoke,
    ) && run_check(
        "mm_wave7_async_swapout_concurrent_dedup_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_async_swapout_concurrent_dedup_canonical_smoke,
    )
}

pub(crate) fn test_mm_wave7_async_swapout_phase_f_exports() -> bool {
    run_check(
        "mm_wave7_async_swapout_stress_concurrency_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_async_swapout_stress_concurrency_canonical_smoke,
    ) && run_check(
        "mm_wave7_async_swapout_heavy_stress_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_async_swapout_heavy_stress_canonical_smoke,
    )
}

pub(crate) fn test_mm_wave7_page_reclaim_exports() -> bool {
    run_check(
        "mm_wave7_watermarks_calculation_smoke",
        rany_os::qemu_tests::mm_wave7_watermarks_calculation_smoke,
    ) && run_check(
        "mm_wave7_pressure_level_smoke",
        rany_os::qemu_tests::mm_wave7_pressure_level_smoke,
    ) && run_check(
        "mm_wave7_mglru_list_add_smoke",
        rany_os::qemu_tests::mm_wave7_mglru_list_add_smoke,
    ) && run_check(
        "mm_wave7_blocked_unsafe_requeues_victim_smoke",
        rany_os::qemu_tests::mm_wave7_blocked_unsafe_requeues_victim_smoke,
    ) && run_check(
        "mm_wave7_blocked_unsafe_requeues_anonymous_dirty_victim_smoke",
        rany_os::qemu_tests::mm_wave7_blocked_unsafe_requeues_anonymous_dirty_victim_smoke,
    ) && run_check(
        "mm_wave7_file_backed_clean_reclaims_with_unsafe_disabled_smoke",
        rany_os::qemu_tests::mm_wave7_file_backed_clean_reclaims_with_unsafe_disabled_smoke,
    ) && run_check(
        "mm_wave7_async_success_clears_pending_and_accounts_success_smoke",
        rany_os::qemu_tests::mm_wave7_async_success_clears_pending_and_accounts_success_smoke,
    ) && run_check(
        "mm_wave7_async_failure_requeues_and_clears_pending_smoke",
        rany_os::qemu_tests::mm_wave7_async_failure_requeues_and_clears_pending_smoke,
    )
}

pub(crate) fn test_mm_wave7_page_reclaim_phase_b_exports() -> bool {
    run_check(
        "mm_wave7_file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled_smoke",
        rany_os::qemu_tests::mm_wave7_file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled_smoke,
    ) && run_check(
        "mm_wave7_file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled_smoke",
        rany_os::qemu_tests::mm_wave7_file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled_smoke,
    ) && run_check(
        "mm_wave7_file_backed_dirty_without_backing_requeues_with_unsafe_disabled_smoke",
        rany_os::qemu_tests::mm_wave7_file_backed_dirty_without_backing_requeues_with_unsafe_disabled_smoke,
    ) && run_check(
        "mm_wave7_notsupported_anonymous_dirty_requeues_without_writeback_skipped_smoke",
        rany_os::qemu_tests::mm_wave7_notsupported_anonymous_dirty_requeues_without_writeback_skipped_smoke,
    ) && run_check(
        "mm_wave7_notsupported_file_dirty_falls_back_without_writeback_skipped_on_success_smoke",
        rany_os::qemu_tests::mm_wave7_notsupported_file_dirty_falls_back_without_writeback_skipped_on_success_smoke,
    ) && run_check(
        "mm_wave7_notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure_smoke",
        rany_os::qemu_tests::mm_wave7_notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure_smoke,
    )
}

pub(crate) fn test_mm_wave7_page_reclaim_phase_c_exports() -> bool {
    run_check(
        "mm_wave7_already_pending_does_not_count_writeback_skipped_smoke",
        rany_os::qemu_tests::mm_wave7_already_pending_does_not_count_writeback_skipped_smoke,
    ) && run_check(
        "mm_wave7_already_pending_without_registered_pending_requeues_smoke",
        rany_os::qemu_tests::mm_wave7_already_pending_without_registered_pending_requeues_smoke,
    ) && run_check(
        "mm_wave7_already_pending_without_registered_pending_requeues_once_in_direct_reclaim_smoke",
        rany_os::qemu_tests::mm_wave7_already_pending_without_registered_pending_requeues_once_in_direct_reclaim_smoke,
    ) && run_check(
        "mm_wave7_queuefull_does_not_count_writeback_skipped_smoke",
        rany_os::qemu_tests::mm_wave7_queuefull_does_not_count_writeback_skipped_smoke,
    )
}

pub(crate) fn test_net_tls_wave8_phase_a_exports() -> bool {
    run_check(
        "net_tls_wave8_hmac_sha256_rfc4231_case1_smoke",
        rany_os::qemu_tests::net_tls_wave8_hmac_sha256_rfc4231_case1_smoke,
    ) && run_check(
        "net_tls_wave8_hmac_sha256_rfc4231_case2_smoke",
        rany_os::qemu_tests::net_tls_wave8_hmac_sha256_rfc4231_case2_smoke,
    ) && run_check(
        "net_tls_wave8_hmac_sha256_rfc4231_case3_smoke",
        rany_os::qemu_tests::net_tls_wave8_hmac_sha256_rfc4231_case3_smoke,
    ) && run_check(
        "net_tls_wave8_hkdf_rfc5869_case1_extract_smoke",
        rany_os::qemu_tests::net_tls_wave8_hkdf_rfc5869_case1_extract_smoke,
    ) && run_check(
        "net_tls_wave8_hkdf_rfc5869_case1_expand_smoke",
        rany_os::qemu_tests::net_tls_wave8_hkdf_rfc5869_case1_expand_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_rfc8439_block_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_rfc8439_block_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_rfc8439_encrypt_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_rfc8439_encrypt_smoke,
    ) && run_check(
        "net_tls_wave8_poly1305_rfc8439_smoke",
        rany_os::qemu_tests::net_tls_wave8_poly1305_rfc8439_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_poly1305_rfc8439_encrypt_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_poly1305_rfc8439_encrypt_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_poly1305_rfc8439_decrypt_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_poly1305_rfc8439_decrypt_smoke,
    ) && run_check(
        "net_tls_wave8_aes_gcm_roundtrip_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_gcm_roundtrip_smoke,
    ) && run_check(
        "net_tls_wave8_aes_gcm_auth_failure_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_gcm_auth_failure_smoke,
    ) && run_check(
        "net_tls_wave8_aes_ctr_roundtrip_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_ctr_roundtrip_smoke,
    ) && run_check(
        "net_tls_wave8_gf128_mul_zero_smoke",
        rany_os::qemu_tests::net_tls_wave8_gf128_mul_zero_smoke,
    ) && run_check(
        "net_tls_wave8_gf_mul_basic_smoke",
        rany_os::qemu_tests::net_tls_wave8_gf_mul_basic_smoke,
    )
}

pub(crate) fn test_net_tls_wave8_phase_b1_exports() -> bool {
    run_check(
        "net_tls_wave8_tls13_early_secret_no_psk_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_early_secret_no_psk_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_handshake_secret_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_handshake_secret_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_master_secret_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_master_secret_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_derive_secret_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_derive_secret_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_derive_traffic_keys_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_derive_traffic_keys_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_finished_key_and_verify_data_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_finished_key_and_verify_data_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_full_key_schedule_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_full_key_schedule_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_hkdf_expand_label_rfc8446_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_hkdf_expand_label_rfc8446_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_key_schedule_chain_consistency_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_key_schedule_chain_consistency_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_finished_round_trip_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_finished_round_trip_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_initial_state_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_initial_state_smoke,
    )
}

pub(crate) fn test_net_tls_wave8_phase_b2_exports() -> bool {
    run_check(
        "net_tls_wave8_tls13_client_hello_key_share_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_client_hello_key_share_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_client_hello_supported_versions_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_client_hello_supported_versions_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_client_hello_psk_modes_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_client_hello_psk_modes_smoke,
    ) && run_check(
        "net_tls_wave8_tls13_strip_content_type_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls13_strip_content_type_smoke,
    )
}

pub(crate) fn test_net_tls_wave8_phase_c_exports() -> bool {
    run_check(
        "net_tls_wave8_hmac_sha256_long_key_smoke",
        rany_os::qemu_tests::net_tls_wave8_hmac_sha256_long_key_smoke,
    ) && run_check(
        "net_tls_wave8_hkdf_extract_empty_salt_smoke",
        rany_os::qemu_tests::net_tls_wave8_hkdf_extract_empty_salt_smoke,
    ) && run_check(
        "net_tls_wave8_hkdf_expand_zero_length_smoke",
        rany_os::qemu_tests::net_tls_wave8_hkdf_expand_zero_length_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_poly1305_auth_failure_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_poly1305_auth_failure_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_poly1305_roundtrip_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_poly1305_roundtrip_smoke,
    ) && run_check(
        "net_tls_wave8_chacha20_poly1305_empty_plaintext_smoke",
        rany_os::qemu_tests::net_tls_wave8_chacha20_poly1305_empty_plaintext_smoke,
    ) && run_check(
        "net_tls_wave8_aes_gcm_256_roundtrip_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_gcm_256_roundtrip_smoke,
    ) && run_check(
        "net_tls_wave8_aes_gcm_corrupted_ciphertext_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_gcm_corrupted_ciphertext_smoke,
    ) && run_check(
        "net_tls_wave8_aes_gcm_empty_plaintext_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_gcm_empty_plaintext_smoke,
    ) && run_check(
        "net_tls_wave8_aes_key_expansion_smoke",
        rany_os::qemu_tests::net_tls_wave8_aes_key_expansion_smoke,
    ) && run_check(
        "net_tls_wave8_derive_master_secret_length_smoke",
        rany_os::qemu_tests::net_tls_wave8_derive_master_secret_length_smoke,
    ) && run_check(
        "net_tls_wave8_derive_key_block_length_smoke",
        rany_os::qemu_tests::net_tls_wave8_derive_key_block_length_smoke,
    ) && run_check(
        "net_tls_wave8_derive_master_secret_deterministic_smoke",
        rany_os::qemu_tests::net_tls_wave8_derive_master_secret_deterministic_smoke,
    ) && run_check(
        "net_tls_wave8_derive_master_secret_differs_with_input_smoke",
        rany_os::qemu_tests::net_tls_wave8_derive_master_secret_differs_with_input_smoke,
    ) && run_check(
        "net_tls_wave8_tls12_prf_deterministic_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls12_prf_deterministic_smoke,
    ) && run_check(
        "net_tls_wave8_tls12_prf_different_labels_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls12_prf_different_labels_smoke,
    ) && run_check(
        "net_tls_wave8_hkdf_expand_label_length_smoke",
        rany_os::qemu_tests::net_tls_wave8_hkdf_expand_label_length_smoke,
    ) && run_check(
        "net_tls_wave8_hkdf_expand_label_different_labels_smoke",
        rany_os::qemu_tests::net_tls_wave8_hkdf_expand_label_different_labels_smoke,
    ) && run_check(
        "net_tls_wave8_cipher_suite_helpers_smoke",
        rany_os::qemu_tests::net_tls_wave8_cipher_suite_helpers_smoke,
    ) && run_check(
        "net_tls_wave8_base64_decode_smoke",
        rany_os::qemu_tests::net_tls_wave8_base64_decode_smoke,
    ) && run_check(
        "net_tls_wave8_tls_version_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls_version_smoke,
    ) && run_check(
        "net_tls_wave8_cipher_suite_defaults_smoke",
        rany_os::qemu_tests::net_tls_wave8_cipher_suite_defaults_smoke,
    ) && run_check(
        "net_tls_wave8_tls_version_ordering_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls_version_ordering_smoke,
    )
}

pub(crate) fn test_net_tls_wave8_phase_d_exports() -> bool {
    run_check(
        "net_tls_wave8_tls_connection_initial_state_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls_connection_initial_state_smoke,
    ) && run_check(
        "net_tls_wave8_tls_connection_client_hello_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls_connection_client_hello_smoke,
    ) && run_check(
        "net_tls_wave8_tls_connection_encrypt_not_established_smoke",
        rany_os::qemu_tests::net_tls_wave8_tls_connection_encrypt_not_established_smoke,
    ) && run_check(
        "net_tls_wave8_process_handshake_multiple_messages_smoke",
        rany_os::qemu_tests::net_tls_wave8_process_handshake_multiple_messages_smoke,
    ) && run_check(
        "net_tls_wave8_process_handshake_truncated_header_smoke",
        rany_os::qemu_tests::net_tls_wave8_process_handshake_truncated_header_smoke,
    )
}
