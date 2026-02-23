use crate::error::{KernelError, MemoryError};
use crate::loader::{ed25519, elf, live_update, sha256, signature, type_id};
use alloc::collections::{BTreeSet, VecDeque};
use alloc::sync::Arc;
use core::fmt::Write;
use core::sync::atomic::Ordering;

mod wave8_net_tests;
pub use wave8_net_tests::*;
struct FixedBuf {
    buf: [u8; 96],
    len: usize,
}

impl FixedBuf {
    const fn new() -> Self {
        Self {
            buf: [0; 96],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Write for FixedBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let end = self.len.saturating_add(bytes.len());
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

pub fn error_conversion_smoke() -> bool {
    let mem_err = MemoryError::OutOfMemory;
    let kernel_err: KernelError = mem_err.into();
    matches!(kernel_err, KernelError::Memory(MemoryError::OutOfMemory))
}

pub fn error_display_smoke() -> bool {
    let err = KernelError::Memory(MemoryError::OutOfMemory);
    let mut writer = FixedBuf::new();
    if core::fmt::write(&mut writer, format_args!("{}", err)).is_err() {
        return false;
    }
    writer.as_str() == "Memory error: out of memory"
}

pub fn loader_sha256_empty_smoke() -> bool {
    let hash = sha256::compute(b"");
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    hash == expected
}

pub fn loader_sha256_abc_smoke() -> bool {
    let hash = sha256::compute(b"abc");
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    hash == expected
}

pub fn loader_sha256_streaming_smoke() -> bool {
    let mut hasher = sha256::Sha256::new();
    hasher.update(b"hello ");
    hasher.update(b"world");
    let streaming_hash = hasher.finalize();
    let direct_hash = sha256::compute(b"hello world");
    streaming_hash == direct_hash
}

pub fn loader_ed25519_invalid_public_key_smoke() -> bool {
    let zero_key = [0u8; 32];
    !ed25519::is_valid_public_key(&zero_key)
}

pub fn loader_ed25519_signature_format_smoke() -> bool {
    let dummy_key = [0u8; 32];
    let dummy_message = [0u8; 32];
    let dummy_sig = [0u8; 64];
    !ed25519::verify(&dummy_key, &dummy_message, &dummy_sig)
}

pub fn loader_ed25519_rfc8032_vector1_smoke() -> bool {
    let public_key: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let message: &[u8] = b"";
    let signature: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    ed25519::verify_message(&public_key, message, &signature)
}

pub fn loader_type_id_const_hash_smoke() -> bool {
    let hash1 = type_id::const_hash(b"test");
    let hash2 = type_id::const_hash(b"test");
    let hash3 = type_id::const_hash(b"different");
    hash1 == hash2 && hash1 != hash3
}

pub fn loader_type_id_semver_compatibility_smoke() -> bool {
    let v1_0_0 = type_id::SemVer::new(1, 0, 0);
    let v1_1_0 = type_id::SemVer::new(1, 1, 0);
    let v2_0_0 = type_id::SemVer::new(2, 0, 0);
    v1_1_0.is_backward_compatible(&v1_0_0)
        && !v1_0_0.is_backward_compatible(&v1_1_0)
        && !v2_0_0.is_backward_compatible(&v1_0_0)
}

pub fn loader_signature_default_smoke() -> bool {
    let sig = signature::CellSignature::default();
    sig.version == 1 && !sig.contains_unsafe && sig.uses_framework_only
}

pub fn loader_signature_well_formed_smoke() -> bool {
    let mut sig = signature::CellSignature::default();
    if sig.is_well_formed() {
        return false;
    }
    sig.signature = alloc::vec![0u8; 64];
    sig.public_key = [1u8; 32];
    sig.is_well_formed()
}

pub fn loader_signature_verifier_dev_mode_smoke() -> bool {
    let mut verifier = signature::SignatureVerifier::new();
    verifier.set_dev_mode(true);

    let mut sig = signature::CellSignature::default();
    sig.compiler_version = "dev".into();

    verifier.verify(&sig, &[]).is_ok() && verifier.stats().dev_mode_bypasses == 1
}

pub fn loader_signature_verifier_production_mode_smoke() -> bool {
    let mut verifier = signature::SignatureVerifier::production();
    let mut sig = signature::CellSignature::default();
    sig.compiler_version = "dev".into();
    verifier.verify(&sig, &[]) == Err(signature::VerificationError::MalformedSignature)
}

pub fn loader_live_update_request_tracker_smoke() -> bool {
    let tracker = live_update::RequestTracker::new();
    if !tracker.begin_request() {
        return false;
    }
    if tracker.active_count() != 1 {
        return false;
    }
    tracker.end_request();
    tracker.active_count() == 0
}

pub fn loader_live_update_request_tracker_drain_smoke() -> bool {
    let tracker = live_update::RequestTracker::new();
    if !tracker.begin_request() {
        return false;
    }
    tracker.end_request();
    tracker.wait_for_drain();
    tracker.active_count() == 0 && !tracker.begin_request()
}

pub fn loader_live_update_per_core_epoch_smoke() -> bool {
    let epoch = live_update::PerCoreEpoch::new();
    epoch.local_epoch.load(Ordering::Relaxed) == 0
        && !epoch.in_critical_section.load(Ordering::Relaxed)
}

pub fn loader_elf_empty_data_returns_error_smoke() -> bool {
    elf::qemu_smoke_empty_data_returns_error()
}

pub fn loader_elf_invalid_magic_returns_error_smoke() -> bool {
    elf::qemu_smoke_invalid_magic_returns_error()
}

pub fn loader_elf_max_size_constants_smoke() -> bool {
    elf::qemu_smoke_max_size_constants()
}

pub fn loader_elf_wrong_elf_class_smoke() -> bool {
    elf::qemu_smoke_wrong_elf_class()
}

pub fn loader_elf_wrong_endianness_smoke() -> bool {
    elf::qemu_smoke_wrong_endianness()
}

pub fn loader_elf_wx_flags_smoke() -> bool {
    elf::qemu_smoke_wx_flags()
}

pub fn loader_elf_rela_extraction_smoke() -> bool {
    elf::qemu_smoke_rela_extraction()
}

pub fn loader_elf_symbol_extraction_smoke() -> bool {
    elf::qemu_smoke_symbol_extraction()
}

pub fn loader_elf_aslr_offset_generation_smoke() -> bool {
    elf::qemu_smoke_aslr_offset_generation()
}

pub fn loader_elf_aslr_enable_disable_smoke() -> bool {
    elf::qemu_smoke_aslr_enable_disable()
}

pub fn loader_elf_get_string_zero_copy_smoke() -> bool {
    elf::qemu_smoke_get_string_zero_copy()
}

pub fn kernel_async_swapout_sim_smoke() -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SwapKind {
        File,
        Anon,
    }

    #[derive(Clone, Copy)]
    struct SwapEntry {
        frame: usize,
        kind: SwapKind,
    }

    struct SimulationState {
        queue: VecDeque<SwapEntry>,
        pending: BTreeSet<usize>,
        file_queue_count: usize,
        queue_len_max: usize,
        tokens: usize,
        enqueue_success: usize,
        enqueue_failures: usize,
        processed: usize,
    }

    impl SimulationState {
        fn new(capacity: usize) -> Self {
            Self {
                queue: VecDeque::new(),
                pending: BTreeSet::new(),
                file_queue_count: 0,
                queue_len_max: 0,
                tokens: capacity,
                enqueue_success: 0,
                enqueue_failures: 0,
                processed: 0,
            }
        }
    }

    let channel_size: usize = 512;
    let batch_size: usize = 16;
    let reserved_file_slots: usize = channel_size / 8;
    let token_bucket_capacity: usize = channel_size / 4;

    let mut state = SimulationState::new(token_bucket_capacity);
    let mut rng_seed = 0x1234_5678_9abc_def0u64;
    let mut rng = || {
        rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng_seed
    };

    let start = crate::time::precise_time_nanos();
    for _ in 0..400 {
        let burst = ((rng() % 5) + 1) as usize;
        for _ in 0..burst {
            let frame = (rng() % 10_000) as usize;
            if state.pending.contains(&frame) {
                continue;
            }
            let kind = if rng() % 2 == 0 {
                SwapKind::File
            } else {
                SwapKind::Anon
            };
            let q_len = state.queue.len();
            let can_enqueue = if kind == SwapKind::File {
                q_len < channel_size
                    && (state.tokens > 0
                        || q_len < channel_size.saturating_sub(reserved_file_slots))
            } else {
                q_len < channel_size
            };

            if can_enqueue {
                if kind == SwapKind::File && state.tokens > 0 {
                    state.tokens -= 1;
                }
                state.queue.push_back(SwapEntry { frame, kind });
                state.pending.insert(frame);
                if kind == SwapKind::File {
                    state.file_queue_count += 1;
                }
                let len = state.queue.len();
                if len > state.queue_len_max {
                    state.queue_len_max = len;
                }
                state.enqueue_success += 1;
            } else {
                state.enqueue_failures += 1;
            }
        }

        for _ in 0..batch_size {
            if let Some(entry) = state.queue.pop_front() {
                state.pending.remove(&entry.frame);
                if entry.kind == SwapKind::File && state.file_queue_count > 0 {
                    state.file_queue_count -= 1;
                }
                state.processed += 1;
            } else {
                break;
            }
        }
    }

    while let Some(entry) = state.queue.pop_front() {
        state.pending.remove(&entry.frame);
        if entry.kind == SwapKind::File && state.file_queue_count > 0 {
            state.file_queue_count -= 1;
        }
        state.processed += 1;
    }

    let elapsed = crate::time::precise_time_nanos().saturating_sub(start);
    let _ = elapsed;

    state.processed == state.enqueue_success
        && state.enqueue_success > 0
        && state.pending.is_empty()
        && state.file_queue_count == 0
}

pub fn mm_wave7_buffer_pool_4k_basic_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_buffer_pool_4k_basic_smoke()
}

pub fn mm_wave7_buffer_pool_2m_basic_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_buffer_pool_2m_basic_smoke()
}

pub fn mm_wave7_enqueue_override_forces_error_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_enqueue_override_forces_error_smoke()
}

pub fn mm_wave7_token_exhaustion_rolls_back_pending_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_token_exhaustion_rolls_back_pending_smoke()
}

pub fn mm_wave7_token_bucket_clamp_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_token_bucket_clamp_smoke()
}

pub fn mm_wave7_runtime_tunable_roundtrip_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_runtime_tunable_roundtrip_smoke()
}

pub fn mm_wave7_memcg_concurrent_swapout_canonical_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_memcg_concurrent_swapout_canonical_smoke()
}

pub fn mm_wave7_async_swapout_concurrent_dedup_canonical_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_async_swapout_concurrent_dedup_canonical_smoke()
}

pub fn mm_wave7_async_swapout_stress_concurrency_canonical_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_async_swapout_stress_concurrency_canonical_smoke()
}

pub fn mm_wave7_async_swapout_heavy_stress_canonical_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_async_swapout_heavy_stress_canonical_smoke(
    )
}

pub fn mm_wave7_bench_enqueue_pool_effect_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_bench_enqueue_pool_effect_smoke()
}

pub fn mm_wave7_bench_buffer_pool_2m_reuse_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_bench_buffer_pool_2m_reuse_smoke()
}

pub fn mm_wave7_bench_buffer_pool_1g_reuse_smoke() -> bool {
    crate::mm::reclaim::async_swapout::qemu_tests::wave7_bench_buffer_pool_1g_reuse_smoke()
}

pub fn mm_wave7_watermarks_calculation_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_watermarks_calculation_smoke()
}

pub fn mm_wave7_pressure_level_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_pressure_level_smoke()
}

pub fn mm_wave7_mglru_list_add_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_mglru_list_add_smoke()
}

pub fn mm_wave7_blocked_unsafe_requeues_victim_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_blocked_unsafe_requeues_victim_smoke()
}

pub fn mm_wave7_blocked_unsafe_requeues_anonymous_dirty_victim_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_blocked_unsafe_requeues_anonymous_dirty_victim_smoke()
}

pub fn mm_wave7_file_backed_clean_reclaims_with_unsafe_disabled_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_file_backed_clean_reclaims_with_unsafe_disabled_smoke()
}

pub fn mm_wave7_async_success_clears_pending_and_accounts_success_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_async_success_clears_pending_and_accounts_success_smoke()
}

pub fn mm_wave7_async_failure_requeues_and_clears_pending_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_async_failure_requeues_and_clears_pending_smoke()
}

pub fn mm_wave7_file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled_smoke() -> bool
{
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_file_backed_dirty_reclaims_on_writeback_success_with_unsafe_disabled_smoke()
}

pub fn mm_wave7_file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled_smoke() -> bool
{
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_file_backed_dirty_requeues_on_writeback_failure_with_unsafe_disabled_smoke()
}

pub fn mm_wave7_file_backed_dirty_without_backing_requeues_with_unsafe_disabled_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_file_backed_dirty_without_backing_requeues_with_unsafe_disabled_smoke()
}

pub fn mm_wave7_notsupported_anonymous_dirty_requeues_without_writeback_skipped_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_notsupported_anonymous_dirty_requeues_without_writeback_skipped_smoke()
}

pub fn mm_wave7_notsupported_file_dirty_falls_back_without_writeback_skipped_on_success_smoke()
-> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_notsupported_file_dirty_falls_back_without_writeback_skipped_on_success_smoke()
}

pub fn mm_wave7_notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure_smoke()
-> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_notsupported_file_dirty_requeues_and_counts_writeback_skipped_on_failure_smoke()
}

pub fn mm_wave7_already_pending_does_not_count_writeback_skipped_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_already_pending_does_not_count_writeback_skipped_smoke()
}

pub fn mm_wave7_already_pending_without_registered_pending_requeues_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_already_pending_without_registered_pending_requeues_smoke()
}

pub fn mm_wave7_already_pending_without_registered_pending_requeues_once_in_direct_reclaim_smoke()
-> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_already_pending_without_registered_pending_requeues_once_in_direct_reclaim_smoke()
}

pub fn mm_wave7_queuefull_does_not_count_writeback_skipped_smoke() -> bool {
    crate::mm::reclaim::page_reclaim::qemu_tests::wave7_queuefull_does_not_count_writeback_skipped_smoke()
}

pub fn driver_cell_state_default_is_created_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_state_default_is_created_smoke()
}

pub fn driver_cell_state_transitions_are_valid_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_state_transitions_are_valid_smoke()
}

pub fn driver_cell_state_faulted_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_state_faulted_smoke()
}

pub fn driver_cell_id_equality_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_id_equality_smoke()
}

pub fn driver_cell_id_ordering_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_id_ordering_smoke()
}

pub fn driver_cell_restart_policy_never_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_restart_policy_never_smoke()
}

pub fn driver_cell_restart_policy_on_panic_defaults_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_restart_policy_on_panic_defaults_smoke()
}

pub fn driver_cell_restart_policy_always_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_restart_policy_always_smoke()
}

pub fn driver_cell_fault_kind_variants_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_fault_kind_variants_smoke()
}

pub fn driver_cell_stats_initial_values_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_initial_values_smoke()
}

pub fn driver_cell_stats_default_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_default_smoke()
}

pub fn driver_cell_stats_record_start_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_record_start_smoke()
}

pub fn driver_cell_stats_record_stop_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_record_stop_smoke()
}

pub fn driver_cell_stats_record_fault_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_record_fault_smoke()
}

pub fn driver_cell_stats_record_restart_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_record_restart_smoke()
}

pub fn driver_cell_stats_record_hot_swap_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_stats_record_hot_swap_smoke()
}

pub fn driver_cell_error_not_found_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_error_not_found_smoke()
}

pub fn driver_cell_error_invalid_state_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_error_invalid_state_smoke()
}

pub fn driver_cell_global_stats_new_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_global_stats_new_smoke()
}

pub fn driver_cell_global_stats_tracking_smoke() -> bool {
    crate::driver_cell::qemu_tests::driver_cell_global_stats_tracking_smoke()
}

pub fn net_ecdh_x25519_key_exchange_symmetry_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_x25519_key_exchange_symmetry_smoke()
}

pub fn net_ecdh_x25519_public_key_length_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_x25519_public_key_length_smoke()
}

pub fn net_ecdh_x25519_group_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_x25519_group_smoke()
}

pub fn net_ecdh_group_from_named_group_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_group_from_named_group_smoke()
}

pub fn net_ecdh_x25519_reject_invalid_peer_key_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_x25519_reject_invalid_peer_key_smoke()
}

pub fn net_ecdh_x25519_rfc7748_vector_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_x25519_rfc7748_vector_smoke()
}

pub fn net_ecdh_p256_key_exchange_symmetry_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_key_exchange_symmetry_smoke()
}

pub fn net_ecdh_p256_public_key_length_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_public_key_length_smoke()
}

pub fn net_ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_reject_invalid_peer_key_smoke()
}

pub fn net_ecdh_group_from_named_group_p256_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_group_from_named_group_p256_smoke()
}

pub fn net_ecdh_p256_point_on_curve_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_point_on_curve_smoke()
}

pub fn net_ecdh_p256_scalar_mul_base_smoke() -> bool {
    crate::net::ecdh::qemu_tests::ecdh_p256_scalar_mul_base_smoke()
}

pub fn net_tls_wave8_hmac_sha256_rfc4231_case1_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_hmac_sha256_rfc4231_case1_smoke()
}

pub fn net_tls_wave8_hmac_sha256_rfc4231_case2_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_hmac_sha256_rfc4231_case2_smoke()
}

pub fn net_tls_wave8_hmac_sha256_rfc4231_case3_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_hmac_sha256_rfc4231_case3_smoke()
}

pub fn net_tls_wave8_hkdf_rfc5869_case1_extract_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_hkdf_rfc5869_case1_extract_smoke()
}

pub fn net_tls_wave8_hkdf_rfc5869_case1_expand_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_hkdf_rfc5869_case1_expand_smoke()
}

pub fn net_tls_wave8_chacha20_rfc8439_block_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_chacha20_rfc8439_block_smoke()
}

pub fn net_tls_wave8_chacha20_rfc8439_encrypt_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_chacha20_rfc8439_encrypt_smoke()
}

pub fn net_tls_wave8_poly1305_rfc8439_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_poly1305_rfc8439_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_rfc8439_encrypt_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_chacha20_poly1305_rfc8439_encrypt_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_rfc8439_decrypt_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_chacha20_poly1305_rfc8439_decrypt_smoke()
}

pub fn net_tls_wave8_aes_gcm_roundtrip_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_aes_gcm_roundtrip_smoke()
}

pub fn net_tls_wave8_aes_gcm_auth_failure_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_aes_gcm_auth_failure_smoke()
}

pub fn net_tls_wave8_aes_ctr_roundtrip_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_aes_ctr_roundtrip_smoke()
}

pub fn net_tls_wave8_gf128_mul_zero_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_gf128_mul_zero_smoke()
}

pub fn net_tls_wave8_gf_mul_basic_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_gf_mul_basic_smoke()
}

pub fn net_tls_wave8_tls13_early_secret_no_psk_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_tls13_early_secret_no_psk_smoke()
}

pub fn net_tls_wave8_tls13_handshake_secret_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_tls13_handshake_secret_smoke()
}

pub fn net_tls_wave8_tls13_master_secret_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_tls13_master_secret_smoke()
}

pub fn net_tls_wave8_tls13_derive_secret_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_tls13_derive_secret_smoke()
}

pub fn net_tls_wave8_tls13_derive_traffic_keys_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_tls13_derive_traffic_keys_smoke()
}

pub fn net_tls_wave8_tls13_finished_key_and_verify_data_smoke() -> bool {
    crate::net::tls::qemu_tests::wave8_tls_tls13_finished_key_and_verify_data_smoke()
}

// BEGIN NET core required wrappers (90 cases)

pub fn net_core_adaptive_polling_polling_mode_default_smoke() -> bool {
    crate::net::qemu_tests::adaptive_polling_polling_mode_default_smoke()
}

pub fn net_core_adaptive_polling_ring_buffer_smoke() -> bool {
    crate::net::qemu_tests::adaptive_polling_ring_buffer_smoke()
}

pub fn net_core_adaptive_polling_network_stats_smoke() -> bool {
    crate::net::qemu_tests::adaptive_polling_network_stats_smoke()
}

pub fn net_core_mempool_mempool_poisoned_alloc_fails_smoke() -> bool {
    crate::net::qemu_tests::mempool_mempool_poisoned_alloc_fails_smoke()
}

pub fn net_core_mempool_mempool_stats_smoke() -> bool {
    crate::net::qemu_tests::mempool_mempool_stats_smoke()
}

pub fn net_core_zero_copy_pool_id_smoke() -> bool {
    crate::net::qemu_tests::zero_copy_pool_id_smoke()
}

pub fn net_core_zero_copy_sg_list_smoke() -> bool {
    crate::net::qemu_tests::zero_copy_sg_list_smoke()
}

pub fn net_core_zero_copy_packet_chain_smoke() -> bool {
    crate::net::qemu_tests::zero_copy_packet_chain_smoke()
}

pub fn net_core_ethernet_mac_address_smoke() -> bool {
    crate::net::qemu_tests::ethernet_mac_address_smoke()
}

pub fn net_core_ethernet_ether_type_smoke() -> bool {
    crate::net::qemu_tests::ethernet_ether_type_smoke()
}

pub fn net_core_arp_arp_cache_smoke() -> bool {
    crate::net::qemu_tests::arp_arp_cache_smoke()
}

pub fn net_core_arp_arp_packet_smoke() -> bool {
    crate::net::qemu_tests::arp_arp_packet_smoke()
}

pub fn net_core_icmp_icmp_type_smoke() -> bool {
    crate::net::qemu_tests::icmp_icmp_type_smoke()
}

pub fn net_core_icmp_echo_builder_smoke() -> bool {
    crate::net::qemu_tests::icmp_echo_builder_smoke()
}

pub fn net_core_udp_udp_packet_smoke() -> bool {
    crate::net::qemu_tests::udp_udp_packet_smoke()
}

pub fn net_core_udp_udp_socket_poisoned_methods_return_defaults_smoke() -> bool {
    crate::net::qemu_tests::udp_udp_socket_poisoned_methods_return_defaults_smoke()
}

pub fn net_core_udp_bind_with_token_reclaim_smoke() -> bool {
    crate::net::qemu_tests::udp_bind_with_token_reclaim_smoke()
}

pub fn net_core_udp_udp_recv_future_poisoned_returns_closed_smoke() -> bool {
    crate::net::qemu_tests::udp_udp_recv_future_poisoned_returns_closed_smoke()
}

pub fn net_core_udp_udp_processor_poisoned_bind_and_process_smoke() -> bool {
    crate::net::qemu_tests::udp_udp_processor_poisoned_bind_and_process_smoke()
}

pub fn net_core_ipv4_ipv4_address_smoke() -> bool {
    crate::net::qemu_tests::ipv4_ipv4_address_smoke()
}

pub fn net_core_ipv4_subnet_smoke() -> bool {
    crate::net::qemu_tests::ipv4_subnet_smoke()
}

pub fn net_core_ipv4_fragment_key_smoke() -> bool {
    crate::net::qemu_tests::ipv4_fragment_key_smoke()
}

pub fn net_core_ipv4_fragment_buffer_basic_smoke() -> bool {
    crate::net::qemu_tests::ipv4_fragment_buffer_basic_smoke()
}

pub fn net_core_ipv4_fragment_reassembly_simple_smoke() -> bool {
    crate::net::qemu_tests::ipv4_fragment_reassembly_simple_smoke()
}

pub fn net_core_ipv4_pmtu_cache_basic_smoke() -> bool {
    crate::net::qemu_tests::ipv4_pmtu_cache_basic_smoke()
}

pub fn net_core_ipv4_pmtu_cache_update_smaller_smoke() -> bool {
    crate::net::qemu_tests::ipv4_pmtu_cache_update_smaller_smoke()
}

pub fn net_core_ipv4_pmtu_cache_minimum_smoke() -> bool {
    crate::net::qemu_tests::ipv4_pmtu_cache_minimum_smoke()
}

pub fn net_core_icmpv6_icmpv6_type_from_u8_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_icmpv6_type_from_u8_smoke()
}

pub fn net_core_icmpv6_icmpv6_type_classification_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_icmpv6_type_classification_smoke()
}

pub fn net_core_icmpv6_echo_reply_build_and_verify_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_echo_reply_build_and_verify_smoke()
}

pub fn net_core_icmpv6_echo_request_build_and_verify_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_echo_request_build_and_verify_smoke()
}

pub fn net_core_icmpv6_processor_echo_request_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_processor_echo_request_smoke()
}

pub fn net_core_icmpv6_processor_echo_disabled_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_processor_echo_disabled_smoke()
}

pub fn net_core_icmpv6_processor_checksum_error_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_processor_checksum_error_smoke()
}

pub fn net_core_icmpv6_ndp_delegation_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_ndp_delegation_smoke()
}

pub fn net_core_icmpv6_header_size_smoke() -> bool {
    crate::net::qemu_tests::icmpv6_header_size_smoke()
}

pub fn net_core_stack_network_stack_creation_smoke() -> bool {
    crate::net::qemu_tests::stack_network_stack_creation_smoke()
}

pub fn net_core_stack_network_stack_poisoned_runtime_apis_fail_smoke() -> bool {
    crate::net::qemu_tests::stack_network_stack_poisoned_runtime_apis_fail_smoke()
}

pub fn net_core_stack_send_udp_fallback_zero_copy_smoke() -> bool {
    crate::net::qemu_tests::stack_send_udp_fallback_zero_copy_smoke()
}

pub fn net_core_stack_send_icmp_fallback_zero_copy_smoke() -> bool {
    crate::net::qemu_tests::stack_send_icmp_fallback_zero_copy_smoke()
}

pub fn net_core_stack_redirect_cache_basic_smoke() -> bool {
    crate::net::qemu_tests::stack_redirect_cache_basic_smoke()
}

pub fn net_core_stack_redirect_cache_expiry_smoke() -> bool {
    crate::net::qemu_tests::stack_redirect_cache_expiry_smoke()
}

pub fn net_core_stack_redirect_cache_cleanup_smoke() -> bool {
    crate::net::qemu_tests::stack_redirect_cache_cleanup_smoke()
}

pub fn net_core_stack_redirect_cache_eviction_smoke() -> bool {
    crate::net::qemu_tests::stack_redirect_cache_eviction_smoke()
}

pub fn net_core_ipv6_unspecified_smoke() -> bool {
    crate::net::qemu_tests::ipv6_unspecified_smoke()
}

pub fn net_core_ipv6_loopback_smoke() -> bool {
    crate::net::qemu_tests::ipv6_loopback_smoke()
}

pub fn net_core_ipv6_multicast_smoke() -> bool {
    crate::net::qemu_tests::ipv6_multicast_smoke()
}

pub fn net_core_ipv6_link_local_smoke() -> bool {
    crate::net::qemu_tests::ipv6_link_local_smoke()
}

pub fn net_core_ipv6_global_smoke() -> bool {
    crate::net::qemu_tests::ipv6_global_smoke()
}

pub fn net_core_ipv6_eui64_smoke() -> bool {
    crate::net::qemu_tests::ipv6_eui64_smoke()
}

pub fn net_core_ipv6_solicited_node_smoke() -> bool {
    crate::net::qemu_tests::ipv6_solicited_node_smoke()
}

pub fn net_core_ipv6_multicast_mac_smoke() -> bool {
    crate::net::qemu_tests::ipv6_multicast_mac_smoke()
}

pub fn net_core_ipv6_header_size_smoke() -> bool {
    crate::net::qemu_tests::ipv6_header_size_smoke()
}

pub fn net_core_ipv6_packet_parse_valid_smoke() -> bool {
    crate::net::qemu_tests::ipv6_packet_parse_valid_smoke()
}

pub fn net_core_ipv6_packet_parse_wrong_version_smoke() -> bool {
    crate::net::qemu_tests::ipv6_packet_parse_wrong_version_smoke()
}

pub fn net_core_ipv6_packet_parse_too_short_smoke() -> bool {
    crate::net::qemu_tests::ipv6_packet_parse_too_short_smoke()
}

pub fn net_core_ipv6_packet_mut_build_smoke() -> bool {
    crate::net::qemu_tests::ipv6_packet_mut_build_smoke()
}

pub fn net_core_ipv6_skip_no_extension_headers_smoke() -> bool {
    crate::net::qemu_tests::ipv6_skip_no_extension_headers_smoke()
}

pub fn net_core_ipv6_skip_hop_by_hop_smoke() -> bool {
    crate::net::qemu_tests::ipv6_skip_hop_by_hop_smoke()
}

pub fn net_core_ipv6_skip_fragment_header_smoke() -> bool {
    crate::net::qemu_tests::ipv6_skip_fragment_header_smoke()
}

pub fn net_core_ipv6_pseudo_header_checksum_smoke() -> bool {
    crate::net::qemu_tests::ipv6_pseudo_header_checksum_smoke()
}

pub fn net_core_ipv6_display_loopback_smoke() -> bool {
    crate::net::qemu_tests::ipv6_display_loopback_smoke()
}

pub fn net_core_ipv6_display_link_local_smoke() -> bool {
    crate::net::qemu_tests::ipv6_display_link_local_smoke()
}

pub fn net_core_ipv6_display_all_nodes_smoke() -> bool {
    crate::net::qemu_tests::ipv6_display_all_nodes_smoke()
}

pub fn net_core_ipv6_display_full_smoke() -> bool {
    crate::net::qemu_tests::ipv6_display_full_smoke()
}

pub fn net_core_ipv6_from_u64_pair_smoke() -> bool {
    crate::net::qemu_tests::ipv6_from_u64_pair_smoke()
}

pub fn net_core_ndp_neighbor_cache_basic_smoke() -> bool {
    crate::net::qemu_tests::ndp_neighbor_cache_basic_smoke()
}

pub fn net_core_ndp_neighbor_cache_update_smoke() -> bool {
    crate::net::qemu_tests::ndp_neighbor_cache_update_smoke()
}

pub fn net_core_ndp_neighbor_cache_expiry_smoke() -> bool {
    crate::net::qemu_tests::ndp_neighbor_cache_expiry_smoke()
}

pub fn net_core_ndp_parse_slla_option_smoke() -> bool {
    crate::net::qemu_tests::ndp_parse_slla_option_smoke()
}

pub fn net_core_ndp_parse_prefix_info_option_smoke() -> bool {
    crate::net::qemu_tests::ndp_parse_prefix_info_option_smoke()
}

pub fn net_core_ndp_build_ns_smoke() -> bool {
    crate::net::qemu_tests::ndp_build_ns_smoke()
}

pub fn net_core_ndp_build_na_smoke() -> bool {
    crate::net::qemu_tests::ndp_build_na_smoke()
}

pub fn net_core_ndp_build_rs_smoke() -> bool {
    crate::net::qemu_tests::ndp_build_rs_smoke()
}

pub fn net_core_ndp_multicast_mac_smoke() -> bool {
    crate::net::qemu_tests::ndp_multicast_mac_smoke()
}

pub fn net_core_ndp_resolve_multicast_smoke() -> bool {
    crate::net::qemu_tests::ndp_resolve_multicast_smoke()
}

pub fn net_core_ndp_ns_processing_smoke() -> bool {
    crate::net::qemu_tests::ndp_ns_processing_smoke()
}

pub fn net_core_tcp_ipv4_addr_smoke() -> bool {
    crate::net::qemu_tests::tcp_ipv4_addr_smoke()
}

pub fn net_core_tcp_socket_addr_smoke() -> bool {
    crate::net::qemu_tests::tcp_socket_addr_smoke()
}

pub fn net_core_tcp_tcp_state_smoke() -> bool {
    crate::net::qemu_tests::tcp_tcp_state_smoke()
}

pub fn net_core_tcp_process_with_packet_zero_copy_smoke() -> bool {
    crate::net::qemu_tests::tcp_process_with_packet_zero_copy_smoke()
}

pub fn net_core_tcp_can_send_respects_cwnd_bytes_smoke() -> bool {
    crate::net::qemu_tests::tcp_can_send_respects_cwnd_bytes_smoke()
}

pub fn net_core_tcp_send_buffer_bytes_decrement_on_flush_smoke() -> bool {
    crate::net::qemu_tests::tcp_send_buffer_bytes_decrement_on_flush_smoke()
}

pub fn net_core_tcp_three_way_handshake_smoke() -> bool {
    crate::net::qemu_tests::tcp_three_way_handshake_smoke()
}

pub fn net_core_tcp_retransmit_on_timeout_smoke() -> bool {
    crate::net::qemu_tests::tcp_retransmit_on_timeout_smoke()
}

pub fn net_core_tcp_connect_future_wakes_on_established_smoke() -> bool {
    crate::net::qemu_tests::tcp_connect_future_wakes_on_established_smoke()
}

pub fn net_core_tcp_record_sent_packet_updates_tcb_smoke() -> bool {
    crate::net::qemu_tests::tcp_record_sent_packet_updates_tcb_smoke()
}

pub fn net_core_tcp_ack_segments_removes_unacked_and_reduces_outstanding_smoke() -> bool {
    crate::net::qemu_tests::tcp_ack_segments_removes_unacked_and_reduces_outstanding_smoke()
}

pub fn net_core_tcp_accept_future_returns_on_push_connection_smoke() -> bool {
    crate::net::qemu_tests::tcp_accept_future_returns_on_push_connection_smoke()
}

pub fn net_core_tcp_connect_timeout_expires_smoke() -> bool {
    crate::net::qemu_tests::tcp_connect_timeout_expires_smoke()
}

// END NET core required wrappers (90 cases)

// BEGIN re-added local QEMU wrappers after origin/master rebase

pub fn kernel_net_bridge_zero_copy_integration_smoke() -> bool {
    use crate::net::driver_bridge;
    use crate::net::ipv4::{IpProtocol, Ipv4Address, Ipv4PacketMut};
    use crate::net::tcp::{
        Ipv4Addr as TcpIpv4Addr, SocketAddr as TcpSocketAddr, TcpControlBlock, TcpState,
    };
    use crate::net::{self, VirtioNetHeader, mempool, stack};
    use crate::sync::PoisonLock;

    let _ = mempool::init_net_mempool(4);

    let mut config = net::NetworkConfig::default();
    config.ipv4.address = Ipv4Address::new([127, 0, 0, 1]);
    stack::init(config);

    let local = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 1000);
    let remote = TcpSocketAddr::new(TcpIpv4Addr::new(127, 0, 0, 1), 2000);

    let mut tcb = TcpControlBlock::new(local);
    tcb.remote_addr = Some(remote);
    tcb.state = TcpState::Established;
    tcb.rcv_nxt = 1;
    let tcb_arc = Arc::new(PoisonLock::new(tcb));

    match stack::stack().lock() {
        Ok(mut guard) => {
            if let Some(ref mut s) = *guard {
                s.insert_test_tcp_connection(local, remote, tcb_arc.clone());
            } else {
                return false;
            }
        }
        Err(_) => return false,
    }

    let header_size = VirtioNetHeader::SIZE;
    let payload = b"hello";
    let tcp_len = 20 + payload.len();
    let eth_total_len = 14 + 20 + tcp_len;

    let mut packet = match mempool::alloc_packet() {
        Some(packet) => packet,
        None => return false,
    };
    let buf = packet.data_mut();
    let needed = header_size + eth_total_len;
    if buf.len() < needed {
        return false;
    }

    for b in &mut buf[0..header_size] {
        *b = 0;
    }

    let eth_off = header_size;
    buf[eth_off..eth_off + 6].copy_from_slice(&[0xff; 6]);
    buf[eth_off + 6..eth_off + 12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    buf[eth_off + 12..eth_off + 14].copy_from_slice(&[0x08, 0x00]);

    let ip_off = eth_off + 14;
    if let Some(mut ipv4_mut) = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]) {
        ipv4_mut
            .init_header()
            .set_source(Ipv4Address::new([127, 0, 0, 1]))
            .set_destination(Ipv4Address::new([127, 0, 0, 1]))
            .set_protocol(IpProtocol::Tcp)
            .set_identification(1);
    } else {
        return false;
    }

    let tcp_off = ip_off + 20;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&2000u16.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&1000u16.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
    let data_off_flags = (5u16 << 12).to_be_bytes();
    buf[tcp_off + 12..tcp_off + 14].copy_from_slice(&data_off_flags);
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
    buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

    if let Some(mut ipv4_mut) = Ipv4PacketMut::new(&mut buf[ip_off..ip_off + 20]) {
        ipv4_mut.finalize(tcp_len);
    } else {
        return false;
    }

    packet.set_len(header_size + eth_total_len);
    driver_bridge::process_received_packet_zero_copy(packet, header_size, eth_total_len);
    driver_bridge::check_batch_timeout(100_000, 1);

    if let Ok(guard) = tcb_arc.lock() {
        if guard.recv_buffer.is_empty() {
            return false;
        }
        if let Some(first) = guard.recv_buffer.front() {
            first.data() == payload
        } else {
            false
        }
    } else {
        false
    }
}

pub fn kernel_bench_framebuffer_smoke() -> bool {
    use crate::graphics::image::Image;
    use crate::graphics::{Color, Framebuffer, FramebufferInfo, PixelFormat};

    let width = 800u32;
    let height = 600u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    let size = info.size();
    let back = alloc::vec![0u32; (size / 4) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img_opaque = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));
    let img_alpha = Image::filled(width, height, Color::with_alpha(64, 128, 192, 128));

    for _ in 0..10 {
        fb.draw_image(&img_opaque, 0, 0);
    }
    for _ in 0..10 {
        fb.draw_image(&img_alpha, 0, 0);
    }
    for _ in 0..100 {
        fb.draw_text(
            10,
            10,
            "Hello, RanyOS Benchmark!",
            Color::WHITE,
            Color::BLACK,
        );
    }
    for i in 0..1000 {
        fb.draw_line(0, 0, width as i32, (i % height) as i32, Color::RED);
    }

    true
}

pub fn graphics_wave6_draw_image_32bit_bgra_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_32bit_bgra_backbuffer_smoke()
}

pub fn graphics_wave6_draw_image_24bit_bgr_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_24bit_bgr_backbuffer_smoke()
}

pub fn graphics_wave6_write_bgr_run_small_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_small_mmio_smoke()
}

pub fn graphics_wave6_write_bgr_run_large_mmio_full_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_large_mmio_full_smoke()
}

pub fn graphics_wave6_write_bgr_run_large_mmio_full_unaligned_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_large_mmio_full_unaligned_smoke()
}

pub fn graphics_wave6_write_bgr_run_small_mmio_pairs_aligned_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_small_mmio_pairs_aligned_smoke()
}

pub fn graphics_wave6_write_bgr_run_small_mmio_generic_unaligned_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_small_mmio_generic_unaligned_smoke(
    )
}

pub fn graphics_wave6_draw_hline_32bit_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_hline_32bit_backbuffer_smoke()
}

pub fn graphics_wave6_draw_text_space_32bit_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_text_space_32bit_backbuffer_smoke()
}

pub fn graphics_wave6_draw_line_matches_naive_32bit_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_line_matches_naive_32bit_backbuffer_smoke()
}

pub fn graphics_wave6_draw_line_matches_naive_24bit_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_line_matches_naive_24bit_backbuffer_smoke()
}

pub fn graphics_wave6_draw_text_space_24bit_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_text_space_24bit_backbuffer_smoke()
}

pub fn graphics_wave6_draw_image_32bit_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_32bit_mmio_smoke()
}

pub fn graphics_wave6_draw_image_24bit_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_24bit_mmio_smoke()
}

pub fn graphics_wave6_draw_image_32bit_mmio_rgba_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_32bit_mmio_rgba_smoke()
}

pub fn graphics_wave6_write_bytes_mmio_alignment_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bytes_mmio_alignment_smoke()
}

pub fn graphics_wave6_write_opaque_run_24bit_even_odd_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_opaque_run_24bit_even_odd_mmio_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgra_basic_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgra_basic_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgra_scalar_random_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgra_scalar_random_smoke()
}

pub fn graphics_wave6_draw_image_bgra_stream_matches_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_bgra_stream_matches_backbuffer_smoke(
    )
}

pub fn graphics_wave6_fill_rect_32bit_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_fill_rect_32bit_mmio_smoke()
}

pub fn graphics_wave6_dirty_rect_tracking_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_dirty_rect_tracking_smoke()
}

pub fn graphics_wave6_dirty_rect_flush_only_marked_area_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_dirty_rect_flush_only_marked_area_smoke()
}

pub fn graphics_wave6_draw_text_partial_left_clip_32bit_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_text_partial_left_clip_32bit_backbuffer_smoke(
    )
}

pub fn graphics_wave6_write_bgr_run_large_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_large_mmio_smoke()
}

pub fn graphics_wave6_write_bgr_run_large_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_write_bgr_run_large_smoke()
}

pub fn graphics_wave6_draw_image_24bit_rgb888_backbuffer_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_image_24bit_rgb888_backbuffer_smoke()
}

pub fn graphics_wave6_draw_hline_24bit_rgb888_mmio_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_draw_hline_24bit_rgb888_mmio_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgra_ssse3_matches_scalar_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgra_ssse3_matches_scalar_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgra_avx2_matches_scalar_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgra_avx2_matches_scalar_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgr24_avx2_matches_scalar_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgr24_avx2_matches_scalar_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgr24_ssse3_matches_scalar_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgr24_ssse3_matches_scalar_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgra_neon_matches_scalar_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgra_neon_matches_scalar_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgr24_neon_matches_scalar_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgr24_neon_matches_scalar_smoke()
}

pub fn graphics_wave6_pack_rgba_to_bgr24_neon_matches_scalar_rgb_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_pack_rgba_to_bgr24_neon_matches_scalar_rgb_smoke(
    )
}

pub fn graphics_wave6_packer_env_override_no_std_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_packer_env_override_no_std_smoke()
}

pub fn iommu_cmdqueue_reclaim_completed_slot_smoke() -> bool {
    crate::io::iommu::qemu_tests::cmdqueue_reclaim_completed_slot_smoke()
}

pub fn iommu_cmdqueue_cancel_queued_command_smoke() -> bool {
    crate::io::iommu::qemu_tests::cmdqueue_cancel_queued_command_smoke()
}

pub fn iommu_cmdqueue_drop_triggers_cancel_smoke() -> bool {
    crate::io::iommu::qemu_tests::cmdqueue_drop_triggers_cancel_smoke()
}

pub fn iommu_cmdqueue_process_up_to_respects_fuel_smoke() -> bool {
    crate::io::iommu::qemu_tests::cmdqueue_process_up_to_respects_fuel_smoke()
}

pub fn iommu_cmdqueue_fuel_shim_basic_smoke() -> bool {
    crate::io::iommu::qemu_tests::cmdqueue_fuel_shim_basic_smoke()
}

pub fn iommu_cmdqueue_metrics_counts_smoke() -> bool {
    crate::io::iommu::qemu_tests::cmdqueue_metrics_counts_smoke()
}

pub fn iommu_wave2_device_id_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_device_id_smoke()
}

pub fn iommu_wave2_sl_pte_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_sl_pte_smoke()
}

pub fn iommu_wave2_iommu_domain_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_iommu_domain_smoke()
}

pub fn iommu_wave2_map_rollback_hidden_mapping_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_map_rollback_hidden_mapping_smoke()
}

pub fn iommu_wave2_map_rollback_hidden_mapping_amd_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_map_rollback_hidden_mapping_amd_smoke()
}

pub fn iommu_wave2_map_rollback_superpage_2mb_collision_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_map_rollback_superpage_2mb_collision_smoke()
}

pub fn iommu_wave2_create_domain_with_numa_hint_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_create_domain_with_numa_hint_smoke()
}

pub fn iommu_wave2_iova_allocator_basic_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_iova_allocator_basic_smoke()
}

pub fn iommu_wave2_map_for_dma_alloc_non_identity_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_map_for_dma_alloc_non_identity_smoke()
}

pub fn iommu_wave2_unmap_reclaims_empty_tables_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_unmap_reclaims_empty_tables_smoke()
}

pub fn iommu_wave2_unmap_partial_keeps_tables_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_unmap_partial_keeps_tables_smoke()
}

pub fn iommu_wave2_unmap_mixed_superpages_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_unmap_mixed_superpages_smoke()
}

pub fn iommu_wave2_page_table_scope_commit_preserves_counts_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_page_table_scope_commit_preserves_counts_smoke()
}

pub fn iommu_wave2_page_table_scope_drop_rolls_back_parent_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave2_page_table_scope_drop_rolls_back_parent_smoke()
}

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

pub fn iommu_wave2_cmdqueue_map_unmap_with_domain_smoke() -> bool {
    iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke()
}

pub fn iommu_wave2_cmdqueue_map_device_nonblocking_smoke() -> bool {
    iommu_wave5_map_for_device_async_and_unmap_canonical_smoke()
}

pub fn iommu_wave2_dma_mask_respects_32bit_limit_smoke() -> bool {
    iommu_wave5_map_for_device_respects_dma_mask_canonical_smoke()
}

pub fn iommu_wave2_controller_security_notifier_dispatch_smoke() -> bool {
    iommu_wave5_api_security_notifier_registration_canonical_smoke()
}

pub fn iommu_wave2_qi_metrics_pressure_smoke() -> bool {
    iommu_wave5_qi_metrics_pressure_canonical_smoke()
}

pub fn iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_cmdqueue_map_unmap_with_domain_canonical_smoke()
}

pub fn iommu_wave5_map_for_device_async_and_unmap_canonical_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave5_map_for_device_async_and_unmap_canonical_smoke()
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

pub fn iommu_wave5_cmdqueue_map_unmap_with_domain_residual_smoke() -> bool {
    iommu_wave5_cmdqueue_map_unmap_with_domain_canonical_smoke()
}

pub fn iommu_wave5_map_for_device_async_and_unmap_residual_smoke() -> bool {
    iommu_wave5_map_for_device_async_and_unmap_canonical_smoke()
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

pub fn net_endpoint_congestion_core_initial_state_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_core_initial_state_smoke()
}

pub fn net_endpoint_congestion_core_slow_start_growth_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_core_slow_start_growth_smoke()
}

pub fn net_endpoint_congestion_core_transition_to_congestion_avoidance_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_core_transition_to_congestion_avoidance_smoke()
}

pub fn net_endpoint_congestion_core_fast_retransmit_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_core_fast_retransmit_smoke()
}

pub fn net_endpoint_congestion_core_timeout_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_core_timeout_smoke()
}

pub fn net_endpoint_congestion_core_available_window_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_core_available_window_smoke()
}

pub fn net_endpoint_congestion_cubic_initial_state_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_cubic_initial_state_smoke()
}

pub fn net_endpoint_congestion_cubic_slow_start_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_cubic_slow_start_smoke()
}

pub fn net_endpoint_congestion_cubic_root_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_cubic_root_smoke()
}

pub fn net_endpoint_congestion_cubic_fast_recovery_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_cubic_fast_recovery_smoke()
}

pub fn net_endpoint_congestion_bbr_initial_state_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_bbr_initial_state_smoke()
}

pub fn net_endpoint_congestion_bbr_startup_growth_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_bbr_startup_growth_smoke()
}

pub fn net_endpoint_congestion_bbr_rt_prop_tracking_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_bbr_rt_prop_tracking_smoke()
}

pub fn net_endpoint_congestion_bbr_available_window_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_bbr_available_window_smoke()
}

pub fn net_endpoint_congestion_bbr_bdp_calculation_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_bbr_bdp_calculation_smoke()
}

pub fn net_endpoint_congestion_bbr_startup_to_drain_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_bbr_startup_to_drain_smoke()
}

pub fn net_endpoint_congestion_variant_from_algorithm_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_from_algorithm_smoke()
}

pub fn net_endpoint_congestion_variant_with_mss_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_with_mss_smoke()
}

pub fn net_endpoint_congestion_variant_newreno_ack_delegation_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_newreno_ack_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_cubic_ack_delegation_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_cubic_ack_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_bbr_ack_delegation_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_bbr_ack_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_timeout_delegation_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_timeout_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_reset_delegation_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_reset_delegation_smoke()
}

pub fn net_endpoint_congestion_variant_available_window_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_available_window_smoke()
}

pub fn net_endpoint_congestion_variant_fast_retransmit_newreno_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_fast_retransmit_newreno_smoke()
}

pub fn net_endpoint_congestion_variant_default_smoke() -> bool {
    crate::net::endpoint::qemu_tests::congestion_variant_default_smoke()
}

pub fn net_endpoint_flow_control_initial_state_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_initial_state_smoke()
}

pub fn net_endpoint_flow_control_receive_data_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_receive_data_smoke()
}

pub fn net_endpoint_flow_control_consume_data_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_consume_data_smoke()
}

pub fn net_endpoint_flow_control_zero_window_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_zero_window_smoke()
}

pub fn net_endpoint_flow_control_sws_avoidance_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_sws_avoidance_smoke()
}

pub fn net_endpoint_flow_control_peer_zero_window_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_peer_zero_window_smoke()
}

pub fn net_endpoint_flow_control_probe_timing_smoke() -> bool {
    crate::net::endpoint::qemu_tests::flow_control_probe_timing_smoke()
}

pub fn net_endpoint_futures_sendfuture_wakes_on_send_smoke() -> bool {
    crate::net::endpoint::qemu_tests::futures_sendfuture_wakes_on_send_smoke()
}

pub fn net_endpoint_futures_recv_packet_zero_copy_via_owned_socket_smoke() -> bool {
    crate::net::endpoint::qemu_tests::futures_recv_packet_zero_copy_via_owned_socket_smoke()
}

pub fn net_endpoint_futures_tcp_packet_stream_multiple_packets_smoke() -> bool {
    crate::net::endpoint::qemu_tests::futures_tcp_packet_stream_multiple_packets_smoke()
}

pub fn net_endpoint_futures_udp_packet_stream_delivered_smoke() -> bool {
    crate::net::endpoint::qemu_tests::futures_udp_packet_stream_delivered_smoke()
}

pub fn net_endpoint_handler_handle_tx_available_requeues_dataready_smoke() -> bool {
    crate::net::endpoint::qemu_tests::handler_handle_tx_available_requeues_dataready_smoke()
}

pub fn net_endpoint_handler_handle_data_ready_retry_when_no_device_smoke() -> bool {
    crate::net::endpoint::qemu_tests::handler_handle_data_ready_retry_when_no_device_smoke()
}

pub fn net_endpoint_inner_socket_state_transitions_smoke() -> bool {
    crate::net::endpoint::qemu_tests::inner_socket_state_transitions_smoke()
}

pub fn net_endpoint_inner_vecdeque_buffer_smoke() -> bool {
    crate::net::endpoint::qemu_tests::inner_vecdeque_buffer_smoke()
}

pub fn net_endpoint_retransmit_rto_calculator_initial_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_rto_calculator_initial_smoke()
}

pub fn net_endpoint_retransmit_rto_calculator_update_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_rto_calculator_update_smoke()
}

pub fn net_endpoint_retransmit_rto_calculator_backoff_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_rto_calculator_backoff_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_push_and_ack_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_retransmit_queue_push_and_ack_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_timeout_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_retransmit_queue_timeout_smoke()
}

pub fn net_endpoint_retransmit_retransmit_queue_retransmit_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_retransmit_queue_retransmit_smoke()
}

pub fn net_endpoint_retransmit_seq_comparison_smoke() -> bool {
    crate::net::endpoint::qemu_tests::retransmit_seq_comparison_smoke()
}

pub fn net_endpoint_segment_tcp_segment_builder_smoke() -> bool {
    crate::net::endpoint::qemu_tests::segment_tcp_segment_builder_smoke()
}

pub fn net_endpoint_segment_tcp_segment_with_data_smoke() -> bool {
    crate::net::endpoint::qemu_tests::segment_tcp_segment_with_data_smoke()
}

pub fn net_endpoint_segment_tcp_segment_with_options_smoke() -> bool {
    crate::net::endpoint::qemu_tests::segment_tcp_segment_with_options_smoke()
}

pub fn net_endpoint_segment_tcp_message_length_field_for_checksum_smoke() -> bool {
    crate::net::endpoint::qemu_tests::segment_tcp_message_length_field_for_checksum_smoke()
}

pub fn net_endpoint_socket_owned_socket_raii_smoke() -> bool {
    crate::net::endpoint::qemu_tests::socket_owned_socket_raii_smoke()
}

pub fn net_endpoint_tcb_tcp_connection_state_smoke() -> bool {
    crate::net::endpoint::qemu_tests::tcb_tcp_connection_state_smoke()
}

pub fn net_endpoint_tcb_tcp_control_block_entry_smoke() -> bool {
    crate::net::endpoint::qemu_tests::tcb_tcp_control_block_entry_smoke()
}

pub fn net_endpoint_tcb_tcp_flags_smoke() -> bool {
    crate::net::endpoint::qemu_tests::tcb_tcp_flags_smoke()
}

pub fn net_endpoint_core_accepted_connection_smoke() -> bool {
    crate::net::endpoint::qemu_tests::core_accepted_connection_smoke()
}

pub fn net_endpoint_core_socket_new_with_fd_smoke() -> bool {
    crate::net::endpoint::qemu_tests::core_socket_new_with_fd_smoke()
}

pub fn net_endpoint_core_socket_accept_empty_queue_smoke() -> bool {
    crate::net::endpoint::qemu_tests::core_socket_accept_empty_queue_smoke()
}

pub fn net_endpoint_core_socket_accept_with_connection_smoke() -> bool {
    crate::net::endpoint::qemu_tests::core_socket_accept_with_connection_smoke()
}

pub fn net_endpoint_core_accept_backlog_limit_smoke() -> bool {
    crate::net::endpoint::qemu_tests::core_accept_backlog_limit_smoke()
}

pub fn net_endpoint_types_socket_fd_smoke() -> bool {
    crate::net::endpoint::qemu_tests::types_socket_fd_smoke()
}

pub fn net_endpoint_types_socket_addr_smoke() -> bool {
    crate::net::endpoint::qemu_tests::types_socket_addr_smoke()
}

pub fn net_endpoint_window_scale_disabled_smoke() -> bool {
    crate::net::endpoint::qemu_tests::window_scale_disabled_smoke()
}

pub fn net_endpoint_window_scale_enabled_smoke() -> bool {
    crate::net::endpoint::qemu_tests::window_scale_enabled_smoke()
}

pub fn net_endpoint_window_scale_advertised_window_smoke() -> bool {
    crate::net::endpoint::qemu_tests::window_scale_advertised_window_smoke()
}

pub fn net_endpoint_window_scale_option_builder_smoke() -> bool {
    crate::net::endpoint::qemu_tests::window_scale_option_builder_smoke()
}

pub fn net_endpoint_window_scale_option_parser_smoke() -> bool {
    crate::net::endpoint::qemu_tests::window_scale_option_parser_smoke()
}

// END re-added local QEMU wrappers after origin/master rebase
