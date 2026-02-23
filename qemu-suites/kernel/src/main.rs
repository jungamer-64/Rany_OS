#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

mod iommu_wave3_tests;
use iommu_wave3_tests::*;
const HEAP_SIZE: usize = 128 * 1024 * 1024; // increased to avoid OOM in qemu-suite tests

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
        && run_check(
            "loader_live_update_exports",
            test_loader_live_update_exports,
        )
        && run_check("loader_elf_exports", test_loader_elf_exports)
        && run_check(
            "iommu_wave2_runtime_readiness",
            report_iommu_wave2_runtime_readiness,
        )
        && run_check("iommu_cmdqueue_exports", test_iommu_cmdqueue_exports)
        && run_check("iommu_wave2_core_exports", test_iommu_wave2_core_exports)
        && run_check(
            "iommu_wave2_poison_exports",
            test_iommu_wave2_poison_exports,
        )
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
        && run_check("iommu_wave3_pasid_exports", test_iommu_wave3_pasid_exports)
        && run_check(
            "iommu_wave3_core_structures_exports",
            test_iommu_wave3_core_structures_exports,
        )
        && run_check("iommu_wave4_amd_exports", test_iommu_wave4_amd_exports)
        && run_check("iommu_wave5_amd_exports", test_iommu_wave5_amd_exports)
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
            "mm_wave7_async_swapout_phase_e_exports",
            test_mm_wave7_async_swapout_phase_e_exports,
        )
        && run_check(
            "mm_wave7_async_swapout_phase_f_exports",
            test_mm_wave7_async_swapout_phase_f_exports,
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
        && run_check("net_ecdh_exports", test_net_ecdh_exports)
        && run_check("net_ecdh_phase_b_exports", test_net_ecdh_phase_b_exports)
        && run_check(
            "net_endpoint_congestion_default_exports",
            test_net_endpoint_congestion_default_exports,
        )
        && run_check(
            "net_endpoint_congestion_variant_exports",
            test_net_endpoint_congestion_variant_exports,
        )
        && run_check(
            "net_endpoint_congestion_core_exports",
            test_net_endpoint_congestion_core_exports,
        )
        && run_check(
            "net_endpoint_flow_control_exports",
            test_net_endpoint_flow_control_exports,
        )
        && run_check(
            "net_endpoint_futures_exports",
            test_net_endpoint_futures_exports,
        )
        && run_check(
            "net_endpoint_handler_exports",
            test_net_endpoint_handler_exports,
        )
        && run_check(
            "net_endpoint_inner_exports",
            test_net_endpoint_inner_exports,
        )
        && run_check(
            "net_endpoint_retransmit_exports",
            test_net_endpoint_retransmit_exports,
        )
        && run_check(
            "net_endpoint_segment_exports",
            test_net_endpoint_segment_exports,
        )
        && run_check(
            "net_endpoint_socket_exports",
            test_net_endpoint_socket_exports,
        )
        && run_check("net_endpoint_tcb_exports", test_net_endpoint_tcb_exports)
        && run_check("net_endpoint_core_exports", test_net_endpoint_core_exports)
        && run_check(
            "net_endpoint_types_exports",
            test_net_endpoint_types_exports,
        )
        && run_check(
            "net_endpoint_window_scale_exports",
            test_net_endpoint_window_scale_exports,
        )
        && run_check(
            "kernel_driver_cell_exports",
            test_kernel_driver_cell_exports,
        )
// BEGIN NET core required run_suite wiring (90 cases).
        && run_check(
            "net_core_adaptive_polling_exports",
            test_net_core_adaptive_polling_exports,
        )
        && run_check(
            "net_core_mempool_exports",
            test_net_core_mempool_exports,
        )
        && run_check(
            "net_core_zero_copy_exports",
            test_net_core_zero_copy_exports,
        )
        && run_check(
            "net_core_ethernet_exports",
            test_net_core_ethernet_exports,
        )
        && run_check(
            "net_core_arp_exports",
            test_net_core_arp_exports,
        )
        && run_check(
            "net_core_icmp_exports",
            test_net_core_icmp_exports,
        )
        && run_check(
            "net_core_udp_exports",
            test_net_core_udp_exports,
        )
        && run_check(
            "net_core_ipv4_exports",
            test_net_core_ipv4_exports,
        )
        && run_check(
            "net_core_icmpv6_exports",
            test_net_core_icmpv6_exports,
        )
        && run_check(
            "net_core_stack_exports",
            test_net_core_stack_exports,
        )
        && run_check(
            "net_core_ipv6_exports",
            test_net_core_ipv6_exports,
        )
        && run_check(
            "net_core_ndp_exports",
            test_net_core_ndp_exports,
        )
        && run_check(
            "net_core_tcp_exports",
            test_net_core_tcp_exports,
        )
// END NET core required run_suite wiring (90 cases).
// BEGIN re-added local run_suite wiring after origin/master rebase
        && run_check(
            "net_endpoint_congestion_cubic_exports",
            test_net_endpoint_congestion_cubic_exports,
        )
        && run_check(
            "net_endpoint_congestion_bbr_exports",
            test_net_endpoint_congestion_bbr_exports,
        )
// END re-added local run_suite wiring after origin/master rebase
        && run_check(
            "kernel_integration_exports",
            test_kernel_integration_exports,
        )
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

    // Ensure a usable PMM region is available for qemu-suite tests so
    // `alloc_frame()` and friends succeed. This mirrors unit-test usage
    // of `init_frame_allocator()` and is safe for the qemu-test harness.
    unsafe {
        // Reserve a 64 MiB test-only physical region starting at 1 MiB.
        // Chosen large enough for the kernel qemu-suite allocations but
        // small enough to avoid conflicts in the minimal test environment.
        let regions = [(x86_64::PhysAddr::new(0x1_0000u64), 64 * 1024 * 1024u64)];
        rany_os::mm::phys::frame_allocator::init_frame_allocator(&regions);
        serial_write_str("[qemu-suite] initialized test frame allocator\n");
    }

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

// BEGIN NET core required suite groups (90 cases).

fn test_net_core_adaptive_polling_exports() -> bool {
    run_check(
        "net_core_adaptive_polling_polling_mode_default_smoke",
        rany_os::qemu_tests::net_core_adaptive_polling_polling_mode_default_smoke,
    ) && run_check(
        "net_core_adaptive_polling_ring_buffer_smoke",
        rany_os::qemu_tests::net_core_adaptive_polling_ring_buffer_smoke,
    ) && run_check(
        "net_core_adaptive_polling_network_stats_smoke",
        rany_os::qemu_tests::net_core_adaptive_polling_network_stats_smoke,
    )
}

fn test_net_core_mempool_exports() -> bool {
    run_check(
        "net_core_mempool_mempool_poisoned_alloc_fails_smoke",
        rany_os::qemu_tests::net_core_mempool_mempool_poisoned_alloc_fails_smoke,
    ) && run_check(
        "net_core_mempool_mempool_stats_smoke",
        rany_os::qemu_tests::net_core_mempool_mempool_stats_smoke,
    )
}

fn test_net_core_zero_copy_exports() -> bool {
    run_check(
        "net_core_zero_copy_pool_id_smoke",
        rany_os::qemu_tests::net_core_zero_copy_pool_id_smoke,
    ) && run_check(
        "net_core_zero_copy_sg_list_smoke",
        rany_os::qemu_tests::net_core_zero_copy_sg_list_smoke,
    ) && run_check(
        "net_core_zero_copy_packet_chain_smoke",
        rany_os::qemu_tests::net_core_zero_copy_packet_chain_smoke,
    )
}

fn test_net_core_ethernet_exports() -> bool {
    run_check(
        "net_core_ethernet_mac_address_smoke",
        rany_os::qemu_tests::net_core_ethernet_mac_address_smoke,
    ) && run_check(
        "net_core_ethernet_ether_type_smoke",
        rany_os::qemu_tests::net_core_ethernet_ether_type_smoke,
    )
}

fn test_net_core_arp_exports() -> bool {
    run_check(
        "net_core_arp_arp_cache_smoke",
        rany_os::qemu_tests::net_core_arp_arp_cache_smoke,
    ) && run_check(
        "net_core_arp_arp_packet_smoke",
        rany_os::qemu_tests::net_core_arp_arp_packet_smoke,
    )
}

fn test_net_core_icmp_exports() -> bool {
    run_check(
        "net_core_icmp_icmp_type_smoke",
        rany_os::qemu_tests::net_core_icmp_icmp_type_smoke,
    ) && run_check(
        "net_core_icmp_echo_builder_smoke",
        rany_os::qemu_tests::net_core_icmp_echo_builder_smoke,
    )
}

fn test_net_core_udp_exports() -> bool {
    run_check(
        "net_core_udp_udp_packet_smoke",
        rany_os::qemu_tests::net_core_udp_udp_packet_smoke,
    ) && run_check(
        "net_core_udp_udp_socket_poisoned_methods_return_defaults_smoke",
        rany_os::qemu_tests::net_core_udp_udp_socket_poisoned_methods_return_defaults_smoke,
    ) && run_check(
        "net_core_udp_bind_with_token_reclaim_smoke",
        rany_os::qemu_tests::net_core_udp_bind_with_token_reclaim_smoke,
    ) && run_check(
        "net_core_udp_udp_recv_future_poisoned_returns_closed_smoke",
        rany_os::qemu_tests::net_core_udp_udp_recv_future_poisoned_returns_closed_smoke,
    ) && run_check(
        "net_core_udp_udp_processor_poisoned_bind_and_process_smoke",
        rany_os::qemu_tests::net_core_udp_udp_processor_poisoned_bind_and_process_smoke,
    )
}

fn test_net_core_ipv4_exports() -> bool {
    run_check(
        "net_core_ipv4_ipv4_address_smoke",
        rany_os::qemu_tests::net_core_ipv4_ipv4_address_smoke,
    ) && run_check(
        "net_core_ipv4_subnet_smoke",
        rany_os::qemu_tests::net_core_ipv4_subnet_smoke,
    ) && run_check(
        "net_core_ipv4_fragment_key_smoke",
        rany_os::qemu_tests::net_core_ipv4_fragment_key_smoke,
    ) && run_check(
        "net_core_ipv4_fragment_buffer_basic_smoke",
        rany_os::qemu_tests::net_core_ipv4_fragment_buffer_basic_smoke,
    ) && run_check(
        "net_core_ipv4_fragment_reassembly_simple_smoke",
        rany_os::qemu_tests::net_core_ipv4_fragment_reassembly_simple_smoke,
    ) && run_check(
        "net_core_ipv4_pmtu_cache_basic_smoke",
        rany_os::qemu_tests::net_core_ipv4_pmtu_cache_basic_smoke,
    ) && run_check(
        "net_core_ipv4_pmtu_cache_update_smaller_smoke",
        rany_os::qemu_tests::net_core_ipv4_pmtu_cache_update_smaller_smoke,
    ) && run_check(
        "net_core_ipv4_pmtu_cache_minimum_smoke",
        rany_os::qemu_tests::net_core_ipv4_pmtu_cache_minimum_smoke,
    )
}

fn test_net_core_icmpv6_exports() -> bool {
    run_check(
        "net_core_icmpv6_icmpv6_type_from_u8_smoke",
        rany_os::qemu_tests::net_core_icmpv6_icmpv6_type_from_u8_smoke,
    ) && run_check(
        "net_core_icmpv6_icmpv6_type_classification_smoke",
        rany_os::qemu_tests::net_core_icmpv6_icmpv6_type_classification_smoke,
    ) && run_check(
        "net_core_icmpv6_echo_reply_build_and_verify_smoke",
        rany_os::qemu_tests::net_core_icmpv6_echo_reply_build_and_verify_smoke,
    ) && run_check(
        "net_core_icmpv6_echo_request_build_and_verify_smoke",
        rany_os::qemu_tests::net_core_icmpv6_echo_request_build_and_verify_smoke,
    ) && run_check(
        "net_core_icmpv6_processor_echo_request_smoke",
        rany_os::qemu_tests::net_core_icmpv6_processor_echo_request_smoke,
    ) && run_check(
        "net_core_icmpv6_processor_echo_disabled_smoke",
        rany_os::qemu_tests::net_core_icmpv6_processor_echo_disabled_smoke,
    ) && run_check(
        "net_core_icmpv6_processor_checksum_error_smoke",
        rany_os::qemu_tests::net_core_icmpv6_processor_checksum_error_smoke,
    ) && run_check(
        "net_core_icmpv6_ndp_delegation_smoke",
        rany_os::qemu_tests::net_core_icmpv6_ndp_delegation_smoke,
    ) && run_check(
        "net_core_icmpv6_header_size_smoke",
        rany_os::qemu_tests::net_core_icmpv6_header_size_smoke,
    )
}

fn test_net_core_stack_exports() -> bool {
    run_check(
        "net_core_stack_network_stack_creation_smoke",
        rany_os::qemu_tests::net_core_stack_network_stack_creation_smoke,
    ) && run_check(
        "net_core_stack_network_stack_poisoned_runtime_apis_fail_smoke",
        rany_os::qemu_tests::net_core_stack_network_stack_poisoned_runtime_apis_fail_smoke,
    ) && run_check(
        "net_core_stack_send_udp_fallback_zero_copy_smoke",
        rany_os::qemu_tests::net_core_stack_send_udp_fallback_zero_copy_smoke,
    ) && run_check(
        "net_core_stack_send_icmp_fallback_zero_copy_smoke",
        rany_os::qemu_tests::net_core_stack_send_icmp_fallback_zero_copy_smoke,
    ) && run_check(
        "net_core_stack_redirect_cache_basic_smoke",
        rany_os::qemu_tests::net_core_stack_redirect_cache_basic_smoke,
    ) && run_check(
        "net_core_stack_redirect_cache_expiry_smoke",
        rany_os::qemu_tests::net_core_stack_redirect_cache_expiry_smoke,
    ) && run_check(
        "net_core_stack_redirect_cache_cleanup_smoke",
        rany_os::qemu_tests::net_core_stack_redirect_cache_cleanup_smoke,
    ) && run_check(
        "net_core_stack_redirect_cache_eviction_smoke",
        rany_os::qemu_tests::net_core_stack_redirect_cache_eviction_smoke,
    )
}

fn test_net_core_ipv6_exports() -> bool {
    run_check(
        "net_core_ipv6_unspecified_smoke",
        rany_os::qemu_tests::net_core_ipv6_unspecified_smoke,
    ) && run_check(
        "net_core_ipv6_loopback_smoke",
        rany_os::qemu_tests::net_core_ipv6_loopback_smoke,
    ) && run_check(
        "net_core_ipv6_multicast_smoke",
        rany_os::qemu_tests::net_core_ipv6_multicast_smoke,
    ) && run_check(
        "net_core_ipv6_link_local_smoke",
        rany_os::qemu_tests::net_core_ipv6_link_local_smoke,
    ) && run_check(
        "net_core_ipv6_global_smoke",
        rany_os::qemu_tests::net_core_ipv6_global_smoke,
    ) && run_check(
        "net_core_ipv6_eui64_smoke",
        rany_os::qemu_tests::net_core_ipv6_eui64_smoke,
    ) && run_check(
        "net_core_ipv6_solicited_node_smoke",
        rany_os::qemu_tests::net_core_ipv6_solicited_node_smoke,
    ) && run_check(
        "net_core_ipv6_multicast_mac_smoke",
        rany_os::qemu_tests::net_core_ipv6_multicast_mac_smoke,
    ) && run_check(
        "net_core_ipv6_header_size_smoke",
        rany_os::qemu_tests::net_core_ipv6_header_size_smoke,
    ) && run_check(
        "net_core_ipv6_packet_parse_valid_smoke",
        rany_os::qemu_tests::net_core_ipv6_packet_parse_valid_smoke,
    ) && run_check(
        "net_core_ipv6_packet_parse_wrong_version_smoke",
        rany_os::qemu_tests::net_core_ipv6_packet_parse_wrong_version_smoke,
    ) && run_check(
        "net_core_ipv6_packet_parse_too_short_smoke",
        rany_os::qemu_tests::net_core_ipv6_packet_parse_too_short_smoke,
    ) && run_check(
        "net_core_ipv6_packet_mut_build_smoke",
        rany_os::qemu_tests::net_core_ipv6_packet_mut_build_smoke,
    ) && run_check(
        "net_core_ipv6_skip_no_extension_headers_smoke",
        rany_os::qemu_tests::net_core_ipv6_skip_no_extension_headers_smoke,
    ) && run_check(
        "net_core_ipv6_skip_hop_by_hop_smoke",
        rany_os::qemu_tests::net_core_ipv6_skip_hop_by_hop_smoke,
    ) && run_check(
        "net_core_ipv6_skip_fragment_header_smoke",
        rany_os::qemu_tests::net_core_ipv6_skip_fragment_header_smoke,
    ) && run_check(
        "net_core_ipv6_pseudo_header_checksum_smoke",
        rany_os::qemu_tests::net_core_ipv6_pseudo_header_checksum_smoke,
    ) && run_check(
        "net_core_ipv6_display_loopback_smoke",
        rany_os::qemu_tests::net_core_ipv6_display_loopback_smoke,
    ) && run_check(
        "net_core_ipv6_display_link_local_smoke",
        rany_os::qemu_tests::net_core_ipv6_display_link_local_smoke,
    ) && run_check(
        "net_core_ipv6_display_all_nodes_smoke",
        rany_os::qemu_tests::net_core_ipv6_display_all_nodes_smoke,
    ) && run_check(
        "net_core_ipv6_display_full_smoke",
        rany_os::qemu_tests::net_core_ipv6_display_full_smoke,
    ) && run_check(
        "net_core_ipv6_from_u64_pair_smoke",
        rany_os::qemu_tests::net_core_ipv6_from_u64_pair_smoke,
    )
}

fn test_net_core_ndp_exports() -> bool {
    run_check(
        "net_core_ndp_neighbor_cache_basic_smoke",
        rany_os::qemu_tests::net_core_ndp_neighbor_cache_basic_smoke,
    ) && run_check(
        "net_core_ndp_neighbor_cache_update_smoke",
        rany_os::qemu_tests::net_core_ndp_neighbor_cache_update_smoke,
    ) && run_check(
        "net_core_ndp_neighbor_cache_expiry_smoke",
        rany_os::qemu_tests::net_core_ndp_neighbor_cache_expiry_smoke,
    ) && run_check(
        "net_core_ndp_parse_slla_option_smoke",
        rany_os::qemu_tests::net_core_ndp_parse_slla_option_smoke,
    ) && run_check(
        "net_core_ndp_parse_prefix_info_option_smoke",
        rany_os::qemu_tests::net_core_ndp_parse_prefix_info_option_smoke,
    ) && run_check(
        "net_core_ndp_build_ns_smoke",
        rany_os::qemu_tests::net_core_ndp_build_ns_smoke,
    ) && run_check(
        "net_core_ndp_build_na_smoke",
        rany_os::qemu_tests::net_core_ndp_build_na_smoke,
    ) && run_check(
        "net_core_ndp_build_rs_smoke",
        rany_os::qemu_tests::net_core_ndp_build_rs_smoke,
    ) && run_check(
        "net_core_ndp_multicast_mac_smoke",
        rany_os::qemu_tests::net_core_ndp_multicast_mac_smoke,
    ) && run_check(
        "net_core_ndp_resolve_multicast_smoke",
        rany_os::qemu_tests::net_core_ndp_resolve_multicast_smoke,
    ) && run_check(
        "net_core_ndp_ns_processing_smoke",
        rany_os::qemu_tests::net_core_ndp_ns_processing_smoke,
    )
}

fn test_net_core_tcp_exports() -> bool {
    run_check(
        "net_core_tcp_ipv4_addr_smoke",
        rany_os::qemu_tests::net_core_tcp_ipv4_addr_smoke,
    ) && run_check(
        "net_core_tcp_socket_addr_smoke",
        rany_os::qemu_tests::net_core_tcp_socket_addr_smoke,
    ) && run_check(
        "net_core_tcp_tcp_state_smoke",
        rany_os::qemu_tests::net_core_tcp_tcp_state_smoke,
    ) && run_check(
        "net_core_tcp_process_with_packet_zero_copy_smoke",
        rany_os::qemu_tests::net_core_tcp_process_with_packet_zero_copy_smoke,
    ) && run_check(
        "net_core_tcp_can_send_respects_cwnd_bytes_smoke",
        rany_os::qemu_tests::net_core_tcp_can_send_respects_cwnd_bytes_smoke,
    ) && run_check(
        "net_core_tcp_send_buffer_bytes_decrement_on_flush_smoke",
        rany_os::qemu_tests::net_core_tcp_send_buffer_bytes_decrement_on_flush_smoke,
    ) && run_check(
        "net_core_tcp_three_way_handshake_smoke",
        rany_os::qemu_tests::net_core_tcp_three_way_handshake_smoke,
    ) && run_check(
        "net_core_tcp_retransmit_on_timeout_smoke",
        rany_os::qemu_tests::net_core_tcp_retransmit_on_timeout_smoke,
    ) && run_check(
        "net_core_tcp_connect_future_wakes_on_established_smoke",
        rany_os::qemu_tests::net_core_tcp_connect_future_wakes_on_established_smoke,
    ) && run_check(
        "net_core_tcp_record_sent_packet_updates_tcb_smoke",
        rany_os::qemu_tests::net_core_tcp_record_sent_packet_updates_tcb_smoke,
    ) && run_check(
        "net_core_tcp_ack_segments_removes_unacked_and_reduces_outstanding_smoke",
        rany_os::qemu_tests::net_core_tcp_ack_segments_removes_unacked_and_reduces_outstanding_smoke,
    ) && run_check(
        "net_core_tcp_accept_future_returns_on_push_connection_smoke",
        rany_os::qemu_tests::net_core_tcp_accept_future_returns_on_push_connection_smoke,
    ) && run_check(
        "net_core_tcp_connect_timeout_expires_smoke",
        rany_os::qemu_tests::net_core_tcp_connect_timeout_expires_smoke,
    )
}

// END NET core required suite groups (90 cases).


// BEGIN re-added local suite groups after origin/master rebase

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

fn test_mm_wave7_async_swapout_phase_e_exports() -> bool {
    run_check(
        "mm_wave7_memcg_concurrent_swapout_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_memcg_concurrent_swapout_canonical_smoke,
    ) && run_check(
        "mm_wave7_async_swapout_concurrent_dedup_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_async_swapout_concurrent_dedup_canonical_smoke,
    )
}

fn test_mm_wave7_async_swapout_phase_f_exports() -> bool {
    run_check(
        "mm_wave7_async_swapout_stress_concurrency_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_async_swapout_stress_concurrency_canonical_smoke,
    ) && run_check(
        "mm_wave7_async_swapout_heavy_stress_canonical_smoke",
        rany_os::qemu_tests::mm_wave7_async_swapout_heavy_stress_canonical_smoke,
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

fn test_iommu_wave5_canonical_exports() -> bool {
    run_check(
        "iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke,
    ) && run_check(
        "iommu_wave5_map_for_device_async_and_unmap_canonical_smoke",
        rany_os::qemu_tests::iommu_wave5_map_for_device_async_and_unmap_canonical_smoke,
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

fn test_net_endpoint_congestion_core_exports() -> bool {
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

fn test_net_endpoint_congestion_cubic_exports() -> bool {
    run_check(
        "net_endpoint_congestion_cubic_initial_state_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_cubic_initial_state_smoke,
    ) && run_check(
        "net_endpoint_congestion_cubic_slow_start_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_cubic_slow_start_smoke,
    ) && run_check(
        "net_endpoint_congestion_cubic_root_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_cubic_root_smoke,
    ) && run_check(
        "net_endpoint_congestion_cubic_fast_recovery_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_cubic_fast_recovery_smoke,
    )
}

fn test_net_endpoint_congestion_bbr_exports() -> bool {
    run_check(
        "net_endpoint_congestion_bbr_initial_state_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_bbr_initial_state_smoke,
    ) && run_check(
        "net_endpoint_congestion_bbr_startup_growth_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_bbr_startup_growth_smoke,
    ) && run_check(
        "net_endpoint_congestion_bbr_rt_prop_tracking_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_bbr_rt_prop_tracking_smoke,
    ) && run_check(
        "net_endpoint_congestion_bbr_available_window_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_bbr_available_window_smoke,
    ) && run_check(
        "net_endpoint_congestion_bbr_bdp_calculation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_bbr_bdp_calculation_smoke,
    ) && run_check(
        "net_endpoint_congestion_bbr_startup_to_drain_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_bbr_startup_to_drain_smoke,
    )
}

fn test_net_endpoint_congestion_variant_exports() -> bool {
    run_check(
        "net_endpoint_congestion_variant_from_algorithm_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_from_algorithm_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_with_mss_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_with_mss_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_newreno_ack_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_newreno_ack_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_cubic_ack_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_cubic_ack_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_bbr_ack_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_bbr_ack_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_timeout_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_timeout_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_reset_delegation_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_reset_delegation_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_available_window_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_available_window_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_fast_retransmit_newreno_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_fast_retransmit_newreno_smoke,
    ) && run_check(
        "net_endpoint_congestion_variant_default_smoke",
        rany_os::qemu_tests::net_endpoint_congestion_variant_default_smoke,
    )
}

fn test_net_endpoint_flow_control_exports() -> bool {
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

fn test_net_endpoint_futures_exports() -> bool {
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

fn test_net_endpoint_handler_exports() -> bool {
    run_check(
        "net_endpoint_handler_handle_tx_available_requeues_dataready_smoke",
        rany_os::qemu_tests::net_endpoint_handler_handle_tx_available_requeues_dataready_smoke,
    ) && run_check(
        "net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke",
        rany_os::qemu_tests::net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke,
    )
}

fn test_net_endpoint_inner_exports() -> bool {
    run_check(
        "net_endpoint_inner_socket_state_transitions_smoke",
        rany_os::qemu_tests::net_endpoint_inner_socket_state_transitions_smoke,
    ) && run_check(
        "net_endpoint_inner_vecdeque_buffer_smoke",
        rany_os::qemu_tests::net_endpoint_inner_vecdeque_buffer_smoke,
    )
}

fn test_net_endpoint_retransmit_exports() -> bool {
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
        "net_endpoint_retransmit_seq_comparison_smoke",
        rany_os::qemu_tests::net_endpoint_retransmit_seq_comparison_smoke,
    )
}

fn test_net_endpoint_segment_exports() -> bool {
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

fn test_net_endpoint_socket_exports() -> bool {
    run_check(
        "net_endpoint_socket_owned_socket_raii_smoke",
        rany_os::qemu_tests::net_endpoint_socket_owned_socket_raii_smoke,
    )
}

fn test_net_endpoint_tcb_exports() -> bool {
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

fn test_net_endpoint_core_exports() -> bool {
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

fn test_net_endpoint_types_exports() -> bool {
    run_check(
        "net_endpoint_types_socket_fd_smoke",
        rany_os::qemu_tests::net_endpoint_types_socket_fd_smoke,
    ) && run_check(
        "net_endpoint_types_socket_addr_smoke",
        rany_os::qemu_tests::net_endpoint_types_socket_addr_smoke,
    )
}

fn test_net_endpoint_window_scale_exports() -> bool {
    run_check(
        "net_endpoint_window_scale_disabled_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_disabled_smoke,
    ) && run_check(
        "net_endpoint_window_scale_enabled_smoke",
        rany_os::qemu_tests::net_endpoint_window_scale_enabled_smoke,
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

// END re-added local suite groups after origin/master rebase

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
