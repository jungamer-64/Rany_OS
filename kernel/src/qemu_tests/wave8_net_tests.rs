use super::*;

mod net_endpoint_tests;
pub use net_endpoint_tests::*;
mod net_peripheral_tests;
pub use net_peripheral_tests::*;
pub fn net_tls_wave8_tls13_full_key_schedule_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_full_key_schedule_smoke()
}

pub fn net_tls_wave8_tls13_hkdf_expand_label_rfc8446_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_hkdf_expand_label_rfc8446_smoke()
}

pub fn net_tls_wave8_tls13_key_schedule_chain_consistency_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_key_schedule_chain_consistency_smoke()
}

pub fn net_tls_wave8_tls13_finished_round_trip_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_finished_round_trip_smoke()
}

pub fn net_tls_wave8_tls13_initial_state_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_initial_state_smoke()
}

pub fn net_tls_wave8_tls13_client_hello_key_share_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_client_hello_key_share_smoke()
}

pub fn net_tls_wave8_tls13_client_hello_supported_versions_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_client_hello_supported_versions_smoke()
}

pub fn net_tls_wave8_tls13_client_hello_psk_modes_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_client_hello_psk_modes_smoke()
}

pub fn net_tls_wave8_tls13_strip_content_type_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls13_strip_content_type_smoke()
}

pub fn net_tls_wave8_hmac_sha256_long_key_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hmac_sha256_long_key_smoke()
}

pub fn net_tls_wave8_hkdf_extract_empty_salt_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hkdf_extract_empty_salt_smoke()
}

pub fn net_tls_wave8_hkdf_expand_zero_length_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hkdf_expand_zero_length_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_auth_failure_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_poly1305_auth_failure_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_roundtrip_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_poly1305_roundtrip_smoke()
}

pub fn net_tls_wave8_chacha20_poly1305_empty_plaintext_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_chacha20_poly1305_empty_plaintext_smoke()
}

pub fn net_tls_wave8_aes_gcm_256_roundtrip_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_256_roundtrip_smoke()
}

pub fn net_tls_wave8_aes_gcm_corrupted_ciphertext_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_corrupted_ciphertext_smoke()
}

pub fn net_tls_wave8_aes_gcm_empty_plaintext_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_empty_plaintext_smoke()
}

pub fn net_tls_wave8_aes_gcm_key_in_place_roundtrip_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_key_in_place_roundtrip_smoke()
}

pub fn net_tls_wave8_aes_gcm_key_invalid_nonce_len_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_key_invalid_nonce_len_smoke()
}

pub fn net_tls_wave8_aes_gcm_key_auth_failure_preserves_output_buffer_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_gcm_key_auth_failure_preserves_output_buffer_smoke()
}

pub fn net_tls_wave8_aes_key_expansion_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_aes_key_expansion_smoke()
}

pub fn net_tls_wave8_derive_master_secret_length_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_derive_master_secret_length_smoke()
}

pub fn net_tls_wave8_derive_key_block_length_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_derive_key_block_length_smoke()
}

pub fn net_tls_wave8_derive_master_secret_deterministic_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_derive_master_secret_deterministic_smoke()
}

pub fn net_tls_wave8_derive_master_secret_differs_with_input_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_derive_master_secret_differs_with_input_smoke()
}

pub fn net_tls_wave8_tls12_prf_deterministic_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls12_prf_deterministic_smoke()
}

pub fn net_tls_wave8_tls12_prf_different_labels_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls12_prf_different_labels_smoke()
}

pub fn net_tls_wave8_hkdf_expand_label_length_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hkdf_expand_label_length_smoke()
}

pub fn net_tls_wave8_hkdf_expand_label_different_labels_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hkdf_expand_label_different_labels_smoke()
}

pub fn net_tls_wave8_cipher_suite_helpers_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_cipher_suite_helpers_smoke()
}

pub fn net_tls_wave8_base64_decode_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_base64_decode_smoke()
}

pub fn net_tls_wave8_tls_version_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls_version_smoke()
}

pub fn net_tls_wave8_cipher_suite_defaults_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_cipher_suite_defaults_smoke()
}

pub fn net_tls_wave8_tls_version_ordering_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls_version_ordering_smoke()
}

pub fn net_tls_wave8_tls_connection_initial_state_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls_connection_initial_state_smoke()
}

pub fn net_tls_wave8_tls_connection_client_hello_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls_connection_client_hello_smoke()
}

pub fn net_tls_wave8_tls_connection_encrypt_not_established_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_tls_connection_encrypt_not_established_smoke()
}

pub fn net_tls_wave8_process_handshake_multiple_messages_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_process_handshake_multiple_messages_smoke()
}

pub fn net_tls_wave8_process_handshake_truncated_header_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_process_handshake_truncated_header_smoke()
}

pub fn net_tls_wave8_generate_random_not_all_zeros_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_generate_random_not_all_zeros_smoke()
}

pub fn net_tls_wave8_generate_random_different_calls_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_generate_random_different_calls_smoke()
}

// ========================================================================
// Wave8 Phase E: SHA-384 + P-256 ECDH テスト（P-256 wrapperは互換維持）
// ========================================================================

pub fn net_tls_wave8_sha384_empty_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_sha384_empty_smoke()
}

pub fn net_tls_wave8_sha384_abc_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_sha384_abc_smoke()
}

pub fn net_tls_wave8_hmac_sha384_rfc4231_case1_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hmac_sha384_rfc4231_case1_smoke()
}

pub fn net_tls_wave8_hmac_sha384_rfc4231_case2_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_hmac_sha384_rfc4231_case2_smoke()
}

pub fn net_tls_wave8_p256_point_on_curve_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_p256_point_on_curve_smoke()
}

pub fn net_tls_wave8_p256_scalar_mul_base_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_p256_scalar_mul_base_smoke()
}

pub fn net_tls_wave8_ecdh_p256_key_exchange_symmetry_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_ecdh_p256_key_exchange_symmetry_smoke()
}

pub fn net_tls_wave8_ecdh_p256_public_key_length_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_ecdh_p256_public_key_length_smoke()
}

pub fn net_tls_wave8_ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_ecdh_p256_reject_invalid_peer_key_smoke()
}

pub fn net_tls_wave8_ecdh_group_from_named_group_p256_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_ecdh_group_from_named_group_p256_smoke()
}

// ========================================================================
// Wave8 Phase F: X.509 DERパース + RSA署名検証テスト
// ========================================================================

pub fn net_tls_wave8_der_parse_tag_length_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_der_parse_tag_length_smoke()
}

pub fn net_tls_wave8_der_parse_integer_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_der_parse_integer_smoke()
}

pub fn net_tls_wave8_der_parse_sequence_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_der_parse_sequence_smoke()
}

pub fn net_tls_wave8_x509_parse_self_signed_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_x509_parse_self_signed_smoke()
}

pub fn net_tls_wave8_x509_extract_rsa_pubkey_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_x509_extract_rsa_pubkey_smoke()
}

pub fn net_tls_wave8_x509_signature_algorithm_oid_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_x509_signature_algorithm_oid_smoke()
}

pub fn net_tls_wave8_rsa_modexp_small_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_rsa_modexp_small_smoke()
}

pub fn net_tls_wave8_rsa_modexp_medium_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_rsa_modexp_medium_smoke()
}

pub fn net_tls_wave8_rsa_pkcs1_verify_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_rsa_pkcs1_verify_smoke()
}

pub fn net_tls_wave8_rsa_pkcs1_verify_bad_sig_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_rsa_pkcs1_verify_bad_sig_smoke()
}

pub fn net_tls_wave8_rsa_biguint_mul_div_smoke() -> bool {
    crate::net::security::tls::qemu_tests::wave8_tls_rsa_biguint_mul_div_smoke()
}

pub fn kernel_net_stack_glue_zero_copy_integration_smoke() -> bool {
    crate::net::runtime::bridge::tests::qemu_zero_copy_via_bridge_smoke()
}

pub fn kernel_net_stack_glue_zero_copy_integration_v6_smoke() -> bool {
    crate::net::runtime::bridge::tests::qemu_zero_copy_via_bridge_v6_smoke()
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

pub fn graphics_wave6_bench_draw_image_bulk_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_bench_draw_image_bulk_smoke()
}

pub fn graphics_wave6_bench_draw_image_24bit_bulk_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_bench_draw_image_24bit_bulk_smoke()
}

pub fn graphics_wave6_bench_draw_image_rgba_bulk_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_bench_draw_image_rgba_bulk_smoke()
}

pub fn graphics_wave6_bench_draw_hline_bulk_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_bench_draw_hline_bulk_smoke()
}

pub fn graphics_wave6_bench_draw_text_bulk_smoke() -> bool {
    crate::graphics::framebuffer::qemu_tests::wave6_bench_draw_text_bulk_smoke()
}

pub fn iommu_cmdqueue_reclaim_completed_slot_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3::cmdqueue_reclaim_completed_slot_smoke()
}

pub fn iommu_cmdqueue_cancel_queued_command_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3::cmdqueue_cancel_queued_command_smoke()
}

pub fn iommu_cmdqueue_drop_triggers_cancel_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3::cmdqueue_drop_triggers_cancel_smoke()
}

pub fn iommu_cmdqueue_process_up_to_respects_fuel_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3::cmdqueue_process_up_to_respects_fuel_smoke()
}

pub fn iommu_cmdqueue_fuel_shim_basic_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3::cmdqueue_fuel_shim_basic_smoke()
}

pub fn iommu_cmdqueue_metrics_counts_smoke() -> bool {
    crate::io::iommu::qemu_tests::wave3::cmdqueue_metrics_counts_smoke()
}
