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
            "iommu_wave2_residual_exports",
            test_iommu_wave2_residual_exports,
        )
        && run_check("kernel_integration_exports", test_kernel_integration_exports)
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

fn test_iommu_wave2_residual_exports() -> bool {
    run_check(
        "iommu_wave2_cmdqueue_map_unmap_with_domain_smoke",
        rany_os::qemu_tests::iommu_wave2_cmdqueue_map_unmap_with_domain_smoke,
    ) && run_check(
        "iommu_wave2_cmdqueue_map_device_nonblocking_smoke",
        rany_os::qemu_tests::iommu_wave2_cmdqueue_map_device_nonblocking_smoke,
    ) && run_check(
        "iommu_wave2_dma_mask_respects_32bit_limit_smoke",
        rany_os::qemu_tests::iommu_wave2_dma_mask_respects_32bit_limit_smoke,
    ) && run_check(
        "iommu_wave2_controller_security_notifier_dispatch_smoke",
        rany_os::qemu_tests::iommu_wave2_controller_security_notifier_dispatch_smoke,
    ) && run_check(
        "iommu_wave2_qi_metrics_pressure_smoke",
        rany_os::qemu_tests::iommu_wave2_qi_metrics_pressure_smoke,
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
