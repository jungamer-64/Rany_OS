#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 64 * 1024 * 1024;

#[repr(align(4096))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAlloc;

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let size = layout.size();
        if size == 0 {
            return layout.align() as *mut u8;
        }

        let base = unsafe { core::ptr::addr_of_mut!(HEAP.0) as usize };
        loop {
            let cur = NEXT.load(Ordering::Relaxed);
            let cur_addr = base.saturating_add(cur);
            let aligned_addr = (cur_addr + align_mask) & !align_mask;
            let Some(end_addr) = aligned_addr.checked_add(size) else {
                return core::ptr::null_mut();
            };
            let Some(end_off) = end_addr.checked_sub(base) else {
                return core::ptr::null_mut();
            };
            if end_off > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if NEXT
                .compare_exchange(cur, end_off, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return aligned_addr as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    serial_write_str("[qemu-suite] kernel alloc_error\n");
    serial_write_str("[qemu-suite] kernel fail\n");
    suite_fail_trap()
}

// The kernel library expects these linker symbols in full kernel builds.
// For qemu suite linkage we provide harmless stubs.
#[unsafe(no_mangle)]
static __eh_frame_start: u8 = 0;
#[unsafe(no_mangle)]
static __eh_frame_end: u8 = 0;
#[unsafe(no_mangle)]
static __tls_start: u8 = 0;
#[unsafe(no_mangle)]
static __tls_end: u8 = 0;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_write_str("[qemu-suite] kernel panic\n");
    serial_write_str("[qemu-suite] kernel panic info: ");
    let mut writer = SerialWriter;
    let _ = fmt::write(&mut writer, format_args!("{info}"));
    serial_write_str("\n");
    serial_write_str("[qemu-suite] kernel fail\n");
    suite_fail_trap()
}

fn run_suite() -> bool {
    run_check("smoke_kernel_abi", smoke_kernel_abi)
        && run_check("kernel_error_exports", test_kernel_error_exports)
        && run_check("loader_crypto_exports", test_loader_crypto_exports)
        && run_check("loader_metadata_exports", test_loader_metadata_exports)
        && run_check("loader_live_update_exports", test_loader_live_update_exports)
        && run_check("loader_elf_exports", test_loader_elf_exports)
        && run_check(
            "iommu_wave2_runtime_readiness",
            report_iommu_wave2_runtime_readiness,
        )
        && run_check("iommu_cmdqueue_exports", test_iommu_cmdqueue_exports)
        && run_check("iommu_wave2_core_exports", test_iommu_wave2_core_exports)
        && run_check("iommu_wave2_poison_exports", test_iommu_wave2_poison_exports)
        && run_check(
            "iommu_wave2_grouping_exports",
            test_iommu_wave2_grouping_exports,
        )
        && run_check(
            "iommu_wave2_ats_pri_exports",
            test_iommu_wave2_ats_pri_exports,
        )
        && run_check(
            "iommu_wave3_scalable_exports",
            test_iommu_wave3_scalable_exports,
        )
        && run_check(
            "iommu_wave3_pasid_exports",
            test_iommu_wave3_pasid_exports,
        )
        && run_check(
            "iommu_wave3_core_structures_exports",
            test_iommu_wave3_core_structures_exports,
        )
        && run_check(
            "iommu_wave4_amd_exports",
            test_iommu_wave4_amd_exports,
        )
        && run_check(
            "iommu_wave5_amd_exports",
            test_iommu_wave5_amd_exports,
        )
        && run_check(
            "graphics_framebuffer_wave6_phase_a_exports",
            test_graphics_framebuffer_wave6_phase_a_exports,
        )
        && run_check(
            "graphics_framebuffer_wave6_phase_b_exports",
            test_graphics_framebuffer_wave6_phase_b_exports,
        )
        && run_check(
            "mm_wave7_async_swapout_exports",
            test_mm_wave7_async_swapout_exports,
        )
        && run_check(
            "mm_wave7_async_swapout_phase_d_exports",
            test_mm_wave7_async_swapout_phase_d_exports,
        )
        && run_check(
            "mm_wave7_page_reclaim_exports",
            test_mm_wave7_page_reclaim_exports,
        )
        && run_check(
            "mm_wave7_page_reclaim_phase_b_exports",
            test_mm_wave7_page_reclaim_phase_b_exports,
        )
        && run_check(
            "mm_wave7_page_reclaim_phase_c_exports",
            test_mm_wave7_page_reclaim_phase_c_exports,
        )
        && run_check(
            "iommu_wave5_canonical_exports",
            test_iommu_wave5_canonical_exports,
        )
        && run_check(
            "iommu_wave5_residual_exports",
            test_iommu_wave5_residual_exports,
        )
        && run_check(
            "net_tls_wave8_phase_a_exports",
            test_net_tls_wave8_phase_a_exports,
        )
        && run_check(
            "net_tls_wave8_phase_b1_exports",
            test_net_tls_wave8_phase_b1_exports,
        )
        && run_check(
            "net_tls_wave8_phase_b2_exports",
            test_net_tls_wave8_phase_b2_exports,
        )
        && run_check(
            "net_tls_wave8_phase_c_exports",
            test_net_tls_wave8_phase_c_exports,
        )
        && run_check(
            "net_tls_wave8_phase_d_exports",
            test_net_tls_wave8_phase_d_exports,
        )
        && run_check(
            "net_tls_wave8_phase_e_exports",
            test_net_tls_wave8_phase_e_exports,
        )
        && run_check(
            "net_tls_wave8_phase_f_exports",
            test_net_tls_wave8_phase_f_exports,
        )
        && run_check(
            "net_ecdh_exports",
            test_net_ecdh_exports,
        )
        && run_check(
            "net_ecdh_phase_b_exports",
            test_net_ecdh_phase_b_exports,
        )
        && run_check("kernel_integration_exports", test_kernel_integration_exports)
        && run_check(
            "graphics_framebuffer_wave9_exports",
            test_graphics_framebuffer_wave9_exports,
        )
}

fn run_check(name: &str, f: fn() -> bool) -> bool {
    serial_write_str("[qemu-suite] kernel case ");
    serial_write_str(name);
    serial_write_str(" ... ");
    if f() {
        serial_write_str("ok\n");
        true
    } else {
        serial_write_str("fail\n");
        false
    }
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial_write_str("[qemu-suite] kernel start\n");

    // Migration baseline check: verify shared utility path still behaves.
    if run_suite() {
        serial_write_str("[qemu-suite] kernel pass\n");
        exit_qemu(0x10);
    }

    serial_write_str("[qemu-suite] kernel fail\n");
    suite_fail_trap()
}

#[cfg(target_os = "uefi")]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_write_str("[qemu-suite] kernel start\n");

    if run_suite() {
        serial_write_str("[qemu-suite] kernel pass\n");
        return 0;
    }

    serial_write_str("[qemu-suite] kernel fail\n");
    1
}

fn smoke_kernel_abi() -> bool {
    let cmdline = "a=1 b=2 run_integration=storage";
    cmdline.contains("run_integration=storage")
}

fn test_kernel_error_exports() -> bool {
    rany_os::qemu_tests::error_conversion_smoke() && rany_os::qemu_tests::error_display_smoke()
}

fn test_loader_crypto_exports() -> bool {
    rany_os::qemu_tests::loader_sha256_empty_smoke()
        && rany_os::qemu_tests::loader_sha256_abc_smoke()
        && rany_os::qemu_tests::loader_sha256_streaming_smoke()
        && rany_os::qemu_tests::loader_ed25519_invalid_public_key_smoke()
        && rany_os::qemu_tests::loader_ed25519_signature_format_smoke()
        && rany_os::qemu_tests::loader_ed25519_rfc8032_vector1_smoke()
}

fn test_loader_metadata_exports() -> bool {
    rany_os::qemu_tests::loader_type_id_const_hash_smoke()
        && rany_os::qemu_tests::loader_type_id_semver_compatibility_smoke()
        && rany_os::qemu_tests::loader_signature_default_smoke()
        && rany_os::qemu_tests::loader_signature_well_formed_smoke()
        && rany_os::qemu_tests::loader_signature_verifier_dev_mode_smoke()
        && rany_os::qemu_tests::loader_signature_verifier_production_mode_smoke()
}

fn test_loader_live_update_exports() -> bool {
    rany_os::qemu_tests::loader_live_update_request_tracker_smoke()
        && rany_os::qemu_tests::loader_live_update_request_tracker_drain_smoke()
        && rany_os::qemu_tests::loader_live_update_per_core_epoch_smoke()
}

fn test_loader_elf_exports() -> bool {
    rany_os::qemu_tests::loader_elf_empty_data_returns_error_smoke()
        && rany_os::qemu_tests::loader_elf_invalid_magic_returns_error_smoke()
        && rany_os::qemu_tests::loader_elf_max_size_constants_smoke()
        && rany_os::qemu_tests::loader_elf_wrong_elf_class_smoke()
        && rany_os::qemu_tests::loader_elf_wrong_endianness_smoke()
        && rany_os::qemu_tests::loader_elf_wx_flags_smoke()
        && rany_os::qemu_tests::loader_elf_rela_extraction_smoke()
        && rany_os::qemu_tests::loader_elf_symbol_extraction_smoke()
        && rany_os::qemu_tests::loader_elf_aslr_offset_generation_smoke()
        && rany_os::qemu_tests::loader_elf_aslr_enable_disable_smoke()
        && rany_os::qemu_tests::loader_elf_get_string_zero_copy_smoke()
}

fn test_kernel_integration_exports() -> bool {
    rany_os::qemu_tests::kernel_async_swapout_sim_smoke()
}

fn test_graphics_framebuffer_wave9_exports() -> bool {
    run_check(
        "graphics_wave9_draw_circle_symmetric_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_circle_symmetric_smoke,
    ) && run_check(
        "graphics_wave9_fill_circle_no_gaps_smoke",
        rany_os::qemu_tests::graphics_wave9_fill_circle_no_gaps_smoke,
    ) && run_check(
        "graphics_wave9_draw_rect_outline_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_rect_outline_smoke,
    ) && run_check(
        "graphics_wave9_draw_line_steep_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_line_steep_smoke,
    ) && run_check(
        "graphics_wave9_draw_text_24bit_single_pass_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_text_24bit_single_pass_smoke,
    ) && run_check(
        "graphics_wave9_draw_char_8x16_24bit_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_char_8x16_24bit_smoke,
    ) && run_check(
        "graphics_wave9_draw_image_rgb565_mmio_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_image_rgb565_mmio_smoke,
    ) && run_check(
        "graphics_wave9_write_opaque_run_32bit_simd_smoke",
        rany_os::qemu_tests::graphics_wave9_write_opaque_run_32bit_simd_smoke,
    ) && run_check(
        "graphics_wave9_draw_text_rgb565_mmio_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_text_rgb565_mmio_smoke,
    ) && run_check(
        "graphics_wave9_draw_char_8x16_rgb565_smoke",
        rany_os::qemu_tests::graphics_wave9_draw_char_8x16_rgb565_smoke,
    )
}

fn test_iommu_cmdqueue_exports() -> bool {
    run_check(
        "iommu_cmdqueue_reclaim_completed_slot_smoke",
        rany_os::qemu_tests::iommu_cmdqueue_reclaim_completed_slot_smoke,
    ) && run_check(
        "iommu_cmdqueue_cancel_queued_command_smoke",
        rany_os::qemu_tests::iommu_cmdqueue_cancel_queued_command_smoke,
    ) && run_check(
        "iommu_cmdqueue_drop_triggers_cancel_smoke",
        rany_os::qemu_tests::iommu_cmdqueue_drop_triggers_cancel_smoke,
    ) && run_check(
        "iommu_cmdqueue_process_up_to_respects_fuel_smoke",
        rany_os::qemu_tests::iommu_cmdqueue_process_up_to_respects_fuel_smoke,
    ) && run_check(
        "iommu_cmdqueue_fuel_shim_basic_smoke",
        rany_os::qemu_tests::iommu_cmdqueue_fuel_shim_basic_smoke,
    ) && run_check(
        "iommu_cmdqueue_metrics_counts_smoke",
        rany_os::qemu_tests::iommu_cmdqueue_metrics_counts_smoke,
    )
}

fn test_iommu_wave2_core_exports() -> bool {
    run_check(
        "iommu_wave2_device_id_smoke",
        rany_os::qemu_tests::iommu_wave2_device_id_smoke,
    ) && run_check(
        "iommu_wave2_sl_pte_smoke",
        rany_os::qemu_tests::iommu_wave2_sl_pte_smoke,
    ) && run_check(
        "iommu_wave2_iommu_domain_smoke",
        rany_os::qemu_tests::iommu_wave2_iommu_domain_smoke,
    ) && run_check(
        "iommu_wave2_map_rollback_hidden_mapping_smoke",
        rany_os::qemu_tests::iommu_wave2_map_rollback_hidden_mapping_smoke,
    ) && run_check(
        "iommu_wave2_map_rollback_hidden_mapping_amd_smoke",
        rany_os::qemu_tests::iommu_wave2_map_rollback_hidden_mapping_amd_smoke,
    ) && run_check(
        "iommu_wave2_map_rollback_superpage_2mb_collision_smoke",
        rany_os::qemu_tests::iommu_wave2_map_rollback_superpage_2mb_collision_smoke,
    ) && run_check(
        "iommu_wave2_create_domain_with_numa_hint_smoke",
        rany_os::qemu_tests::iommu_wave2_create_domain_with_numa_hint_smoke,
    ) && run_check(
        "iommu_wave2_iova_allocator_basic_smoke",
        rany_os::qemu_tests::iommu_wave2_iova_allocator_basic_smoke,
    ) && run_check(
        "iommu_wave2_map_for_dma_alloc_non_identity_smoke",
        rany_os::qemu_tests::iommu_wave2_map_for_dma_alloc_non_identity_smoke,
    ) && run_check(
        "iommu_wave2_unmap_reclaims_empty_tables_smoke",
        rany_os::qemu_tests::iommu_wave2_unmap_reclaims_empty_tables_smoke,
    ) && run_check(
        "iommu_wave2_unmap_partial_keeps_tables_smoke",
        rany_os::qemu_tests::iommu_wave2_unmap_partial_keeps_tables_smoke,
    ) && run_check(
        "iommu_wave2_unmap_mixed_superpages_smoke",
        rany_os::qemu_tests::iommu_wave2_unmap_mixed_superpages_smoke,
    ) && run_check(
        "iommu_wave2_page_table_scope_commit_preserves_counts_smoke",
        rany_os::qemu_tests::iommu_wave2_page_table_scope_commit_preserves_counts_smoke,
    ) && run_check(
        "iommu_wave2_page_table_scope_drop_rolls_back_parent_smoke",
        rany_os::qemu_tests::iommu_wave2_page_table_scope_drop_rolls_back_parent_smoke,
    ) && run_check(
        "iommu_wave2_security_notifier_registration_smoke",
        rany_os::qemu_tests::iommu_wave2_security_notifier_registration_smoke,
    ) && run_check(
        "iommu_wave2_security_event_types_are_copy_smoke",
        rany_os::qemu_tests::iommu_wave2_security_event_types_are_copy_smoke,
    ) && run_check(
        "iommu_wave2_fault_summary_from_fault_record_smoke",
        rany_os::qemu_tests::iommu_wave2_fault_summary_from_fault_record_smoke,
    ) && run_check(
        "iommu_wave2_isolation_decision_default_smoke",
        rany_os::qemu_tests::iommu_wave2_isolation_decision_default_smoke,
    ) && run_check(
        "iommu_wave2_identity_mapping_disabled_by_default_smoke",
        rany_os::qemu_tests::iommu_wave2_identity_mapping_disabled_by_default_smoke,
    ) && run_check(
        "iommu_wave2_iova_not_equal_phys_smoke",
        rany_os::qemu_tests::iommu_wave2_iova_not_equal_phys_smoke,
    ) && run_check(
        "iommu_wave2_domain_type_not_passthrough_smoke",
        rany_os::qemu_tests::iommu_wave2_domain_type_not_passthrough_smoke,
    ) && run_check(
        "iommu_wave2_mapping_iova_phys_distinct_smoke",
        rany_os::qemu_tests::iommu_wave2_mapping_iova_phys_distinct_smoke,
    )
}

fn test_iommu_wave2_poison_exports() -> bool {
    run_check(
        "iommu_wave2_process_page_requests_poisoned_returns_empty_smoke",
        rany_os::qemu_tests::iommu_wave2_process_page_requests_poisoned_returns_empty_smoke,
    ) && run_check(
        "iommu_wave2_create_domain_poisoned_returns_hw_error_smoke",
        rany_os::qemu_tests::iommu_wave2_create_domain_poisoned_returns_hw_error_smoke,
    ) && run_check(
        "iommu_wave2_isolate_faulting_device_poisoned_attempts_isolation_smoke",
        rany_os::qemu_tests::iommu_wave2_isolate_faulting_device_poisoned_attempts_isolation_smoke,
    ) && run_check(
        "iommu_wave2_domain_map_poisoned_returns_none_smoke",
        rany_os::qemu_tests::iommu_wave2_domain_map_poisoned_returns_none_smoke,
    ) && run_check(
        "iommu_wave2_get_domain_for_device_poisoned_returns_hw_error_smoke",
        rany_os::qemu_tests::iommu_wave2_get_domain_for_device_poisoned_returns_hw_error_smoke,
    ) && run_check(
        "iommu_wave2_set_domain_numa_poisoned_returns_hw_error_smoke",
        rany_os::qemu_tests::iommu_wave2_set_domain_numa_poisoned_returns_hw_error_smoke,
    ) && run_check(
        "iommu_wave2_init_iova_poisoned_proceeds_with_best_effort_smoke",
        rany_os::qemu_tests::iommu_wave2_init_iova_poisoned_proceeds_with_best_effort_smoke,
    ) && run_check(
        "iommu_wave2_init_interrupt_remapping_poisoned_proceeds_with_best_effort_smoke",
        rany_os::qemu_tests::iommu_wave2_init_interrupt_remapping_poisoned_proceeds_with_best_effort_smoke,
    ) && run_check(
        "iommu_wave2_enable_queued_invalidation_poisoned_returns_hw_error_smoke",
        rany_os::qemu_tests::iommu_wave2_enable_queued_invalidation_poisoned_returns_hw_error_smoke,
    ) && run_check(
        "iommu_wave2_submit_invalidation_poisoned_returns_error_smoke",
        rany_os::qemu_tests::iommu_wave2_submit_invalidation_poisoned_returns_error_smoke,
    ) && run_check(
        "iommu_wave2_qi_wait_sync_poisoned_returns_error_smoke",
        rany_os::qemu_tests::iommu_wave2_qi_wait_sync_poisoned_returns_error_smoke,
    ) && run_check(
        "iommu_wave2_qi_wait_async_poisoned_returns_error_smoke",
        rany_os::qemu_tests::iommu_wave2_qi_wait_async_poisoned_returns_error_smoke,
    )
}

fn test_iommu_wave2_grouping_exports() -> bool {
    run_check(
        "iommu_wave2_group_creation_basic_smoke",
        rany_os::qemu_tests::iommu_wave2_group_creation_basic_smoke,
    ) && run_check(
        "iommu_wave2_group_multifunction_same_group_smoke",
        rany_os::qemu_tests::iommu_wave2_group_multifunction_same_group_smoke,
    ) && run_check(
        "iommu_wave2_group_acs_isolated_separation_smoke",
        rany_os::qemu_tests::iommu_wave2_group_acs_isolated_separation_smoke,
    ) && run_check(
        "iommu_wave2_group_reuse_for_same_group_devices_smoke",
        rany_os::qemu_tests::iommu_wave2_group_reuse_for_same_group_devices_smoke,
    ) && run_check(
        "iommu_wave2_group_poisoned_lock_returns_error_smoke",
        rany_os::qemu_tests::iommu_wave2_group_poisoned_lock_returns_error_smoke,
    ) && run_check(
        "iommu_wave2_group_full_flow_discovery_to_attach_smoke",
        rany_os::qemu_tests::iommu_wave2_group_full_flow_discovery_to_attach_smoke,
    ) && run_check(
        "iommu_wave2_group_shared_domain_multi_device_smoke",
        rany_os::qemu_tests::iommu_wave2_group_shared_domain_multi_device_smoke,
    ) && run_check(
        "iommu_wave2_group_device_detach_smoke",
        rany_os::qemu_tests::iommu_wave2_group_device_detach_smoke,
    ) && run_check(
        "iommu_wave2_group_poisoned_device_to_group_returns_error_smoke",
        rany_os::qemu_tests::iommu_wave2_group_poisoned_device_to_group_returns_error_smoke,
    )
}

fn test_iommu_wave2_ats_pri_exports() -> bool {
    run_check(
        "iommu_wave2_ats_enable_disable_lifecycle_smoke",
        rany_os::qemu_tests::iommu_wave2_ats_enable_disable_lifecycle_smoke,
    ) && run_check(
        "iommu_wave2_ats_block_untrusted_smoke",
        rany_os::qemu_tests::iommu_wave2_ats_block_untrusted_smoke,
    ) && run_check(
        "iommu_wave2_ats_detach_disables_ats_smoke",
        rany_os::qemu_tests::iommu_wave2_ats_detach_disables_ats_smoke,
    )
}

fn test_iommu_wave3_scalable_exports() -> bool {
    // Wave3 scalable group:
    // - PASID0 fault resolution is deterministic baseline.
    // - detach/attach cycle checks are promoted from pending Phase B;
    //   if flakiness is observed, demote these two checks back to pending monitoring.
    run_check(
        "iommu_wave3_scalable_mode_pasid0_fault_resolution_smoke",
        rany_os::qemu_tests::iommu_wave3_scalable_mode_pasid0_fault_resolution_smoke,
    ) && run_check(
        "iommu_wave3_scalable_mode_detach_cleans_pasid_smoke",
        rany_os::qemu_tests::iommu_wave3_scalable_mode_detach_cleans_pasid_smoke,
    ) && run_check(
        "iommu_wave3_scalable_mode_attach_detach_cycle_smoke",
        rany_os::qemu_tests::iommu_wave3_scalable_mode_attach_detach_cycle_smoke,
    )
}

fn test_iommu_wave3_pasid_exports() -> bool {
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

fn test_iommu_wave3_core_structures_exports() -> bool {
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

fn test_iommu_wave4_amd_exports() -> bool {
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

fn test_iommu_wave5_amd_exports() -> bool {
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

fn test_graphics_framebuffer_wave6_phase_a_exports() -> bool {
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

fn test_graphics_framebuffer_wave6_phase_b_exports() -> bool {
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

fn test_mm_wave7_async_swapout_exports() -> bool {
    run_check(
        "mm_wave7_buffer_pool_4k_basic_smoke",
        rany_os::qemu_tests::mm_wave7_buffer_pool_4k_basic_smoke,
    ) && run_check(
        "mm_wave7_buffer_pool_2m_basic_smoke",
        rany_os::qemu_tests::mm_wave7_buffer_pool_2m_basic_smoke,
    )
}

fn test_mm_wave7_async_swapout_phase_d_exports() -> bool {
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

fn test_mm_wave7_page_reclaim_exports() -> bool {
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

fn test_mm_wave7_page_reclaim_phase_b_exports() -> bool {
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

fn test_mm_wave7_page_reclaim_phase_c_exports() -> bool {
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

fn test_net_tls_wave8_phase_a_exports() -> bool {
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

fn test_net_tls_wave8_phase_b1_exports() -> bool {
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

fn test_net_tls_wave8_phase_b2_exports() -> bool {
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


fn test_net_tls_wave8_phase_c_exports() -> bool {
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

fn test_net_tls_wave8_phase_d_exports() -> bool {
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

fn test_net_tls_wave8_phase_e_exports() -> bool {
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

fn test_net_tls_wave8_phase_f_exports() -> bool {
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

fn test_net_ecdh_exports() -> bool {
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

fn test_net_ecdh_phase_b_exports() -> bool {
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

fn test_iommu_wave5_canonical_exports() -> bool {
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
    )
}

fn test_iommu_wave5_residual_exports() -> bool {
    run_check(
        "iommu_wave5_map_for_device_async_and_unmap_residual_smoke",
        rany_os::qemu_tests::iommu_wave5_map_for_device_async_and_unmap_residual_smoke,
    )
}

fn report_iommu_wave2_runtime_readiness() -> bool {
    serial_write_str("[qemu-suite] kernel info iommu_wave2 runtime_ready=");
    if rany_os::memory::is_initialized() {
        serial_write_str("1\n");
    } else {
        serial_write_str("0\n");
    }
    true
}

fn serial_write_str(s: &str) {
    for b in s.bytes() {
        serial_write_byte(b);
    }
}

fn serial_write_byte(byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3f8u16,
            in("al") byte,
            options(nostack, nomem, preserves_flags)
        );
    }
}

struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial_write_str(s);
        Ok(())
    }
}

fn suite_fail_trap() -> ! {
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
fn exit_qemu(code: u32) -> ! {
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
