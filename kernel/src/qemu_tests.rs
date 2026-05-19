use crate::crypto::{ed25519, sha256};
use crate::error::{KernelError, MemoryError};
use crate::loader::{elf, live_update, signature, type_id};
use core::fmt::Write;
use core::sync::atomic::Ordering;

mod wave8_net_tests;
pub use wave8_net_tests::*;
mod boot_runtime_suite;
pub use boot_runtime_suite::*;
mod storage_fs_tests;
pub use storage_fs_tests::*;
mod network_runtime_suite;
pub use network_runtime_suite::*;
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

pub fn driver_domain_state_default_is_created_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_state_default_is_created_smoke()
}

pub fn driver_domain_state_transitions_are_valid_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_state_transitions_are_valid_smoke()
}

pub fn driver_domain_state_faulted_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_state_faulted_smoke()
}

pub fn driver_domain_id_equality_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_id_equality_smoke()
}

pub fn driver_domain_id_ordering_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_id_ordering_smoke()
}

pub fn driver_domain_restart_policy_never_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_restart_policy_never_smoke()
}

pub fn driver_domain_restart_policy_on_panic_defaults_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_restart_policy_on_panic_defaults_smoke()
}

pub fn driver_domain_restart_policy_always_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_restart_policy_always_smoke()
}

pub fn driver_domain_fault_kind_variants_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_fault_kind_variants_smoke()
}

pub fn driver_domain_restart_policy_retry_boundary_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_restart_policy_retry_boundary_smoke()
}

pub fn driver_domain_restart_policy_backoff_cap_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_restart_policy_backoff_cap_smoke()
}

pub fn driver_domain_stats_initial_values_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_initial_values_smoke()
}

pub fn driver_domain_stats_default_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_default_smoke()
}

pub fn driver_domain_stats_record_start_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_record_start_smoke()
}

pub fn driver_domain_stats_record_stop_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_record_stop_smoke()
}

pub fn driver_domain_stats_record_fault_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_record_fault_smoke()
}

pub fn driver_domain_stats_record_restart_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_record_restart_smoke()
}

pub fn driver_domain_stats_record_hot_swap_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_stats_record_hot_swap_smoke()
}

pub fn driver_domain_error_not_found_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_error_not_found_smoke()
}

pub fn driver_domain_error_invalid_state_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_error_invalid_state_smoke()
}

pub fn driver_domain_global_stats_new_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_global_stats_new_smoke()
}

pub fn driver_domain_global_stats_tracking_smoke() -> bool {
    crate::driver_domain::qemu_tests::driver_domain_global_stats_tracking_smoke()
}

pub fn net_ecdh_x25519_key_exchange_symmetry_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_x25519_key_exchange_symmetry_smoke()
}

pub fn net_ecdh_x25519_public_key_length_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_x25519_public_key_length_smoke()
}

pub fn net_ecdh_x25519_group_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_x25519_group_smoke()
}

pub fn net_ecdh_group_from_named_group_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_group_from_named_group_smoke()
}

pub fn net_ecdh_x25519_reject_invalid_peer_key_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_x25519_reject_invalid_peer_key_smoke()
}

pub fn net_ecdh_x25519_rfc7748_vector_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_x25519_rfc7748_vector_smoke()
}

pub fn net_ecdh_p256_key_exchange_symmetry_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_key_exchange_symmetry_smoke()
}

pub fn net_ecdh_p256_public_key_length_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_public_key_length_smoke()
}

pub fn net_ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_reject_invalid_peer_key_smoke()
}

pub fn net_ecdh_group_from_named_group_p256_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_group_from_named_group_p256_smoke()
}

pub fn net_ecdh_p256_point_on_curve_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_point_on_curve_smoke()
}

pub fn net_ecdh_p256_scalar_mul_base_smoke() -> bool {
    crate::net::security::ecdh::qemu_tests::ecdh_p256_scalar_mul_base_smoke()
}

pub fn net_tls_wave8_hmac_sha256_rfc4231_case1_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hmac_sha256_rfc4231_case1_smoke()
}

pub fn net_tls_wave8_hmac_sha256_rfc4231_case2_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hmac_sha256_rfc4231_case2_smoke()
}

pub fn net_tls_wave8_hmac_sha256_rfc4231_case3_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hmac_sha256_rfc4231_case3_smoke()
}

pub fn net_tls_wave8_hkdf_rfc5869_case1_extract_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hkdf_rfc5869_case1_extract_smoke()
}

pub fn net_tls_wave8_hkdf_rfc5869_case1_expand_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hkdf_rfc5869_case1_expand_smoke()
}

pub fn net_tls_wave8_chacha20_rfc8439_block_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_rfc8439_block_smoke()
}

pub fn net_tls_wave8_chacha20_rfc8439_encrypt_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_rfc8439_encrypt_smoke()
}

pub fn net_tls_wave8_poly1305_rfc8439_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_poly1305_rfc8439_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_rfc8439_encrypt_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_poly1305_rfc8439_encrypt_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_rfc8439_decrypt_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_poly1305_rfc8439_decrypt_smoke()
}

pub fn net_tls_wave8_aes_gcm_roundtrip_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_roundtrip_smoke()
}

pub fn net_tls_wave8_aes_gcm_auth_failure_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_auth_failure_smoke()
}

pub fn net_tls_wave8_aes_ctr_roundtrip_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_ctr_roundtrip_smoke()
}

pub fn net_tls_wave8_gf128_mul_zero_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_gf128_mul_zero_smoke()
}

pub fn net_tls_wave8_gf_mul_basic_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_gf_mul_basic_smoke()
}

pub fn net_tls_wave8_tls13_early_secret_no_psk_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_early_secret_no_psk_smoke()
}

pub fn net_tls_wave8_tls13_handshake_secret_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_handshake_secret_smoke()
}

pub fn net_tls_wave8_tls13_master_secret_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_master_secret_smoke()
}

pub fn net_tls_wave8_tls13_derive_secret_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_derive_secret_smoke()
}

pub fn net_tls_wave8_tls13_derive_traffic_keys_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_derive_traffic_keys_smoke()
}

pub fn net_tls_wave8_tls13_finished_key_and_verify_data_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_finished_key_and_verify_data_smoke()
}

pub fn sync_lockfree_spsc_basic_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::spsc_basic_smoke()
}

pub fn sync_lockfree_mpsc_basic_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::mpsc_basic_smoke()
}

pub fn sync_lockfree_mpmc_basic_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::mpmc_basic_smoke()
}

pub fn sync_lockfree_mpmc_try_operations_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::mpmc_try_operations_smoke()
}

pub fn sync_lockfree_index_stack_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::lock_free_index_stack_smoke()
}

pub fn sync_lockfree_backoff_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::backoff_smoke()
}

pub fn sync_lockfree_seqlock_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::seqlock_smoke()
}

pub fn sync_lockfree_bounded_channel_static_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::bounded_channel_static_smoke()
}

pub fn sync_lockfree_bounded_channel_new_leak_smoke() -> bool {
    crate::sync::lockfree::qemu_tests::bounded_channel_new_leak_smoke()
}
