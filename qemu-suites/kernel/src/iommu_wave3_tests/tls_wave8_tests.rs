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
    )
}

pub(crate) fn test_iommu_wave5_residual_exports() -> bool {
    run_check(
        "iommu_wave5_map_for_device_async_and_unmap_residual_smoke",
        rany_os::qemu_tests::iommu_wave5_map_for_device_async_and_unmap_residual_smoke,
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
