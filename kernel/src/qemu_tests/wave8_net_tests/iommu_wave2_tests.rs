pub fn iommu_wave2_security_notifier_registration_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_security_notifier_registration_smoke()
}

pub fn iommu_wave2_security_event_types_are_copy_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_security_event_types_are_copy_smoke()
}

pub fn iommu_wave2_fault_summary_from_fault_record_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_fault_summary_from_fault_record_smoke()
}

pub fn iommu_wave2_isolation_decision_default_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_isolation_decision_default_smoke()
}

pub fn iommu_wave2_identity_mapping_disabled_by_default_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_identity_mapping_disabled_by_default_smoke()
}

pub fn iommu_wave2_iova_not_equal_phys_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_iova_not_equal_phys_smoke()
}

pub fn iommu_wave2_domain_type_not_passthrough_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_domain_type_not_passthrough_smoke()
}

pub fn iommu_wave2_mapping_iova_phys_distinct_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_mapping_iova_phys_distinct_smoke()
}

pub fn iommu_wave2_process_page_requests_poisoned_returns_empty_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_process_page_requests_poisoned_returns_empty_smoke()
}

pub fn iommu_wave2_create_domain_poisoned_returns_hw_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_create_domain_poisoned_returns_hw_error_smoke()
}

pub fn iommu_wave2_isolate_faulting_device_poisoned_attempts_isolation_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_isolate_faulting_device_poisoned_attempts_isolation_smoke()
}

pub fn iommu_wave2_domain_map_poisoned_returns_none_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_domain_map_poisoned_returns_none_smoke()
}

pub fn iommu_wave2_get_domain_for_device_poisoned_returns_hw_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_get_domain_for_device_poisoned_returns_hw_error_smoke()
}

pub fn iommu_wave2_set_domain_numa_poisoned_returns_hw_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_set_domain_numa_poisoned_returns_hw_error_smoke()
}

pub fn iommu_wave2_init_iova_poisoned_proceeds_with_best_effort_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_init_iova_poisoned_proceeds_with_best_effort_smoke()
}

pub fn iommu_wave2_init_interrupt_remapping_poisoned_proceeds_with_best_effort_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_init_interrupt_remapping_poisoned_proceeds_with_best_effort_smoke(
    )
}

pub fn iommu_wave2_enable_queued_invalidation_poisoned_returns_hw_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_enable_queued_invalidation_poisoned_returns_hw_error_smoke()
}

pub fn iommu_wave2_submit_invalidation_poisoned_returns_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_submit_invalidation_poisoned_returns_error_smoke()
}

pub fn iommu_wave2_qi_wait_sync_poisoned_returns_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_qi_wait_sync_poisoned_returns_error_smoke()
}

pub fn iommu_wave2_qi_wait_async_poisoned_returns_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_qi_wait_async_poisoned_returns_error_smoke()
}

pub fn iommu_wave3_scalable_mode_pasid0_fault_resolution_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_scalable_mode_pasid0_fault_resolution_smoke()
}

pub fn iommu_wave3_mapping_slab_insert_lookup_remove_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_mapping_slab_insert_lookup_remove_smoke()
}

pub fn iommu_wave3_mapping_slab_overlap_detection_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_mapping_slab_overlap_detection_smoke()
}

pub fn iommu_wave3_zombie_queue_basic_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_zombie_queue_basic_smoke()
}

pub fn iommu_wave3_zombie_queue_failed_cleanup_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_zombie_queue_failed_cleanup_smoke()
}

pub fn iommu_wave3_pri_fuel_processing_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_pri_fuel_processing_smoke()
}

pub fn iommu_wave3_pasid_table_alloc_free_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_pasid_table_alloc_free_smoke()
}

pub fn iommu_wave3_pasid_table_multi_domain_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_pasid_table_multi_domain_smoke()
}

pub fn iommu_wave3_pasid_table_exhaustion_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_pasid_table_exhaustion_smoke()
}

pub fn iommu_wave3_scalable_mode_detach_cleans_pasid_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_scalable_mode_detach_cleans_pasid_smoke()
}

pub fn iommu_wave3_scalable_mode_attach_detach_cycle_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3_scalable_mode_attach_detach_cycle_smoke()
}

pub fn iommu_wave2_group_creation_basic_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_creation_basic_smoke()
}

pub fn iommu_wave2_group_multifunction_same_group_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_multifunction_same_group_smoke()
}

pub fn iommu_wave2_group_acs_isolated_separation_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_acs_isolated_separation_smoke()
}

pub fn iommu_wave2_group_non_acs_bridge_shared_group_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_non_acs_bridge_shared_group_smoke()
}

pub fn iommu_wave2_group_non_acs_chain_promotes_highest_nonisolated_bridge_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_non_acs_chain_promotes_highest_nonisolated_bridge_smoke()
}

pub fn iommu_wave2_group_topology_gap_conservative_fallback_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_topology_gap_conservative_fallback_smoke()
}

pub fn iommu_wave2_group_reuse_for_same_group_devices_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_reuse_for_same_group_devices_smoke()
}

pub fn iommu_wave2_group_poisoned_lock_returns_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_poisoned_lock_returns_error_smoke()
}

pub fn iommu_wave2_group_full_flow_discovery_to_attach_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_full_flow_discovery_to_attach_smoke()
}

pub fn iommu_wave2_group_shared_domain_multi_device_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_shared_domain_multi_device_smoke()
}

pub fn iommu_wave2_group_device_detach_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_device_detach_smoke()
}

pub fn iommu_wave2_group_poisoned_device_to_group_returns_error_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_group_poisoned_device_to_group_returns_error_smoke()
}

pub fn iommu_wave2_ats_enable_disable_lifecycle_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_ats_enable_disable_lifecycle_smoke()
}

pub fn iommu_wave2_ats_block_untrusted_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_ats_block_untrusted_smoke()
}

pub fn iommu_wave2_ats_detach_disables_ats_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_ats_detach_disables_ats_smoke()
}

pub fn iommu_wave5_map_for_device_respects_dma_mask_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_map_for_device_respects_dma_mask_canonical_smoke()
}

pub fn iommu_wave5_api_security_notifier_registration_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_api_security_notifier_registration_canonical_smoke()
}

pub fn iommu_wave5_qi_metrics_pressure_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_qi_metrics_pressure_canonical_smoke()
}

pub fn iommu_wave5_map_for_device_async_and_unmap_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_map_for_device_async_and_unmap_canonical_smoke()
}

pub fn iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_cmdqueue_map_unmap_with_domain_canonical_smoke()
}

pub fn iommu_wave5_cmdqueue_map_unmap_with_domain_residual_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_cmdqueue_map_unmap_with_domain_residual_smoke()
}

// Compat alias: retained for deprecated residual entrypoint.
pub fn iommu_wave5_map_for_device_async_and_unmap_residual_smoke() -> bool {
    iommu_wave5_map_for_device_async_and_unmap_canonical_smoke()
}

// Compat alias: legacy wave2 residual wrapper.
// Required suite does not use this wrapper; it forwards to the Wave5 canonical wrapper.
pub fn iommu_wave2_cmdqueue_map_unmap_with_domain_smoke() -> bool {
    iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke()
}

// Compat alias: legacy wave2 residual wrapper.
// Required suite does not use this wrapper; it forwards to the Wave5 canonical wrapper.
pub fn iommu_wave2_cmdqueue_map_device_nonblocking_smoke() -> bool {
    iommu_wave5_map_for_device_async_and_unmap_canonical_smoke()
}

// Compat alias: legacy wave2 residual wrapper.
// Required suite does not use this wrapper; it forwards to the Wave5 canonical wrapper.
pub fn iommu_wave2_dma_mask_respects_32bit_limit_smoke() -> bool {
    iommu_wave5_map_for_device_respects_dma_mask_canonical_smoke()
}

// Compat alias: legacy wave2 residual wrapper.
// Required suite does not use this wrapper; it forwards to the Wave5 canonical wrapper.
pub fn iommu_wave2_controller_security_notifier_dispatch_smoke() -> bool {
    iommu_wave5_api_security_notifier_registration_canonical_smoke()
}

// Compat alias: legacy wave2 residual wrapper.
// Required suite does not use this wrapper; it forwards to the Wave5 canonical wrapper.
pub fn iommu_wave2_qi_metrics_pressure_smoke() -> bool {
    iommu_wave5_qi_metrics_pressure_canonical_smoke()
}

pub fn iommu_amd_wave0_alias_devids_for_device_dedup_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave0_alias_devids_for_device_dedup_smoke()
}

pub fn iommu_amd_wave0_alias_devids_for_device_no_match_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave0_alias_devids_for_device_no_match_smoke()
}

pub fn iommu_amd_wave0_ivhd_flags_for_device_combined_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave0_ivhd_flags_for_device_combined_smoke()
}

pub fn iommu_amd_wave0_ivhd_flags_for_device_acpi_hid_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave0_ivhd_flags_for_device_acpi_hid_smoke()
}

pub fn iommu_amd_wave0_map_ivmd_ranges_exclusion_splits_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave0_map_ivmd_ranges_exclusion_splits_smoke()
}

pub fn iommu_amd_wave0_map_for_device_rejects_exclusion_range_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave0_map_for_device_rejects_exclusion_range_smoke()
}

pub fn iommu_amd_wave1_cmdqueue_map_unmap_with_domain_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave1_cmdqueue_map_unmap_with_domain_smoke()
}

pub fn iommu_amd_wave1_map_device_nonblocking_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave1_map_device_nonblocking_smoke()
}

pub fn iommu_amd_wave1_dma_mask_respects_32bit_limit_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave1_dma_mask_respects_32bit_limit_smoke()
}

pub fn iommu_amd_wave1_security_notifier_dispatch_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave1_security_notifier_dispatch_smoke()
}

pub fn iommu_amd_wave1_cmdqueue_pressure_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave1_cmdqueue_pressure_smoke()
}

pub fn iommu_amd_wave5_irt_entry_construction_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave5_irt_entry_construction_smoke()
}

pub fn iommu_amd_wave5_irt_alloc_free_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave5_irt_alloc_free_smoke()
}

pub fn iommu_amd_wave5_irt_exhaustion_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave5_irt_exhaustion_smoke()
}

pub fn iommu_amd_wave5_irt_invalidation_cmd_format_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave5_irt_invalidation_cmd_format_smoke()
}

pub fn iommu_amd_wave5_map_interrupt_returns_handle_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave5_map_interrupt_returns_handle_smoke()
}

pub fn iommu_amd_wave5_get_remap_msi_message_format_smoke() -> bool {
    crate::io::iommu::qemu_tests::amd_wave5_get_remap_msi_message_format_smoke()
}

// ── Wave 9: session-3 graphics optimisation regression ──────────────

pub fn graphics_wave9_draw_circle_symmetric_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_circle_symmetric_smoke()
}

pub fn graphics_wave9_fill_circle_no_gaps_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_fill_circle_no_gaps_smoke()
}

pub fn graphics_wave9_draw_rect_outline_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_rect_outline_smoke()
}

pub fn graphics_wave9_draw_line_steep_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_line_steep_smoke()
}

pub fn graphics_wave9_draw_text_24bit_single_pass_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_text_24bit_single_pass_smoke()
}

pub fn graphics_wave9_draw_char_8x16_24bit_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_char_8x16_24bit_smoke()
}

pub fn graphics_wave9_draw_image_rgb565_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_image_rgb565_mmio_smoke()
}

pub fn graphics_wave9_write_opaque_run_32bit_simd_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_write_opaque_run_32bit_simd_smoke()
}

pub fn graphics_wave9_draw_text_rgb565_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_text_rgb565_mmio_smoke()
}

pub fn graphics_wave9_draw_char_8x16_rgb565_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave9_draw_char_8x16_rgb565_smoke()
}
