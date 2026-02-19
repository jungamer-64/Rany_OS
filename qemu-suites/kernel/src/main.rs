#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

mod iommu_wave3_tests;
use iommu_wave3_tests::*;
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
        && run_check(
            "kernel_driver_cell_exports",
            test_kernel_driver_cell_exports,
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
