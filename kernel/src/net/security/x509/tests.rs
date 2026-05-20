// ============================================================================
// kernel/src/net/security/x509/tests.rs - span-backed X.509 tests
// ============================================================================

use super::*;

fn der_payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
    let mut packet = crate::net::payload::alloc_packet_with_headroom(data.len(), 0)
        .expect("test payload allocation succeeds");
    packet.data_mut().copy_from_slice(data);
    kernel_api::resource::net::PacketPayload::single(packet)
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_basic_tlv() {
    let payload = der_payload(&[0x02, 0x01, 0x2A]);
    let mut cursor = StrictDerCursor::new(PayloadSpanRef::from_payload(&payload));
    let tlv = cursor.read_tlv().expect("read integer TLV");

    assert_eq!(tlv.tag, 0x02);
    assert!(tlv.value.eq_bytes(&[0x2A]));
    assert!(cursor.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_long_length_sequence() {
    let mut data = [0u8; 131];
    data[0] = 0x30;
    data[1] = 0x81;
    data[2] = 0x80;
    let payload = der_payload(&data);
    let mut cursor = StrictDerCursor::new(PayloadSpanRef::from_payload(&payload));
    let seq = cursor.read_sequence().expect("read sequence");

    assert_eq!(seq.value.total_len(), 128);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_nested_sequence() {
    let payload = der_payload(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    let mut cursor = StrictDerCursor::new(PayloadSpanRef::from_payload(&payload));
    let content = cursor.read_sequence().expect("read sequence").value;
    let mut inner = StrictDerCursor::new(content);

    assert!(
        inner
            .read_integer()
            .expect("first integer")
            .eq_bytes(&[0x01])
    );
    assert!(
        inner
            .read_integer()
            .expect("second integer")
            .eq_bytes(&[0x02])
    );
    assert!(inner.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_bitstring_strips_unused_count() {
    let payload = der_payload(&[0x03, 0x03, 0x00, 0xAA, 0xBB]);
    let mut cursor = StrictDerCursor::new(PayloadSpanRef::from_payload(&payload));

    assert!(
        cursor
            .read_bitstring()
            .expect("bit string")
            .eq_bytes(&[0xAA, 0xBB])
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_rejects_invalid_input() {
    let empty = der_payload(&[]);
    assert!(
        StrictDerCursor::new(PayloadSpanRef::from_payload(&empty))
            .read_tlv()
            .is_none()
    );

    let overlong = der_payload(&[0x30, 0xFF]);
    assert!(
        StrictDerCursor::new(PayloadSpanRef::from_payload(&overlong))
            .read_sequence()
            .is_none()
    );

    let not_sequence = der_payload(&[0x02, 0x01, 0x00]);
    assert!(
        StrictDerCursor::new(PayloadSpanRef::from_payload(&not_sequence))
            .read_sequence()
            .is_none()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_rejects_non_canonical_lengths_and_high_tag_number() {
    let overlong_short = der_payload(&[0x02, 0x81, 0x7F]);
    let leading_zero_length = der_payload(&[0x30, 0x82, 0x00, 0x80]);
    let high_tag_number = der_payload(&[0x1F, 0x01, 0x00]);

    assert!(
        StrictDerCursor::new(PayloadSpanRef::from_payload(&overlong_short))
            .read_tlv()
            .is_none()
    );
    assert!(
        StrictDerCursor::new(PayloadSpanRef::from_payload(&leading_zero_length))
            .read_tlv()
            .is_none()
    );
    assert!(
        StrictDerCursor::new(PayloadSpanRef::from_payload(&high_tag_number))
            .read_tlv()
            .is_none()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_time_rejects_trailing_bytes_invalid_dates_and_pre_unix_dates() {
    let utc_trailing = der_payload(b"250101000000Z0");
    let generalized_trailing = der_payload(b"20250101000000Z0");
    let feb_31 = der_payload(b"250231000000Z");
    let non_leap_feb_29 = der_payload(b"230229000000Z");
    let pre_unix = der_payload(b"491231235959Z");

    assert!(parse_time_value(0x17, PayloadSpanRef::from_payload(&utc_trailing)).is_none());
    assert!(parse_time_value(0x18, PayloadSpanRef::from_payload(&generalized_trailing)).is_none());
    assert!(parse_time_value(0x17, PayloadSpanRef::from_payload(&feb_31)).is_none());
    assert!(parse_time_value(0x17, PayloadSpanRef::from_payload(&non_leap_feb_29)).is_none());
    assert!(parse_time_value(0x17, PayloadSpanRef::from_payload(&pre_unix)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_basic_fields() {
    let payload = test_cert_payload();
    let cert = X509Parser::parse_certificate(PayloadSpanRef::from_payload(&payload))
        .expect("parse test cert");

    assert_eq!(
        cert.signature_algorithm,
        SignatureAlgorithmId::Sha256WithRsa
    );
    assert!(cert.signature_value.eq_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]));
    assert_eq!(cert.raw_tbs.total_len(), 129);
    assert!(span_eq(cert.issuer_raw, cert.subject_raw));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_extracts_owned_rsa_spki() {
    let payload = test_cert_payload();
    let cert = X509Parser::parse_certificate(PayloadSpanRef::from_payload(&payload))
        .expect("parse test cert");

    match cert.subject_public_key_info {
        SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
            assert_eq!(modulus.len(), 8);
            assert!(modulus.iter().all(|byte| *byte == 0xFF));
            assert_eq!(exponent.as_slice(), &[0x01, 0x00, 0x01]);
        }
        _ => panic!("expected RSA SPKI"),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_signature_algorithm_oid_mapping_is_span_backed() {
    let sha256 = der_payload(OID_SHA256_WITH_RSA);
    let ecdsa = der_payload(OID_ECDSA_WITH_SHA384);
    let unknown = der_payload(&[0x01, 0x02, 0x03]);

    assert_eq!(
        parse_signature_algorithm_id(PayloadSpanRef::from_payload(&sha256)),
        SignatureAlgorithmId::Sha256WithRsa
    );
    assert_eq!(
        parse_signature_algorithm_id(PayloadSpanRef::from_payload(&ecdsa)),
        SignatureAlgorithmId::EcdsaWithSha384
    );
    assert_eq!(
        parse_signature_algorithm_id(PayloadSpanRef::from_payload(&unknown)),
        SignatureAlgorithmId::Unknown
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_signature_algorithm_rejects_unsupported_parameters() {
    let rsa_bad_null = der_payload(&[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x01, 0x00,
    ]);
    let ecdsa_with_null = der_payload(&[
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x05, 0x00,
    ]);
    let rsa_pss = der_payload(&[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
    ]);

    assert!(parse_signature_algorithm(PayloadSpanRef::from_payload(&rsa_bad_null)).is_none());
    assert!(parse_signature_algorithm(PayloadSpanRef::from_payload(&ecdsa_with_null)).is_none());
    assert!(parse_signature_algorithm(PayloadSpanRef::from_payload(&rsa_pss)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_rejects_signature_algorithm_mismatch() {
    let mut der = TEST_CERT_DER;
    let mut seen = 0usize;
    for index in 0..der.len().saturating_sub(OID_SHA256_WITH_RSA.len()) {
        if der[index..].starts_with(OID_SHA256_WITH_RSA) {
            seen += 1;
            if seen == 2 {
                der[index + OID_SHA256_WITH_RSA.len() - 1] = 0x0C;
                break;
            }
        }
    }
    assert_eq!(seen, 2);

    let payload = der_payload(&der);
    assert!(X509Parser::parse_certificate(PayloadSpanRef::from_payload(&payload)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_rejects_invalid_input() {
    let empty = der_payload(&[]);
    let not_sequence = der_payload(&[0x02, 0x01, 0x00]);
    let truncated = der_payload(&[0x30, 0x03, 0x02, 0x01]);

    assert!(X509Parser::parse_certificate(PayloadSpanRef::from_payload(&empty)).is_none());
    assert!(X509Parser::parse_certificate(PayloadSpanRef::from_payload(&not_sequence)).is_none());
    assert!(X509Parser::parse_certificate(PayloadSpanRef::from_payload(&truncated)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_rejects_outer_trailing_bytes() {
    let mut der = [0u8; TEST_CERT_DER.len() + 1];
    der[..TEST_CERT_DER.len()].copy_from_slice(&TEST_CERT_DER);
    let payload = der_payload(&der);

    assert!(X509Parser::parse_certificate(PayloadSpanRef::from_payload(&payload)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_rejects_malformed_validity() {
    let mut der = TEST_CERT_DER;
    der[47] = 0x13;
    let payload = der_payload(&der);

    assert!(X509Parser::parse_certificate(PayloadSpanRef::from_payload(&payload)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_extensions_rejects_unsupported_critical_extension() {
    let payload = der_payload(&[
        0xA3, 0x0E, 0x30, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x01, 0x01, 0xFF, 0x04,
        0x00,
    ]);
    let mut cursor = StrictDerCursor::new(PayloadSpanRef::from_payload(&payload));

    assert!(parse_extensions(&mut cursor).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_extensions_rejects_name_constraints() {
    let payload = der_payload(&[
        0xA3, 0x0B, 0x30, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x1D, 0x1E, 0x04, 0x00,
    ]);
    let mut cursor = StrictDerCursor::new(PayloadSpanRef::from_payload(&payload));

    assert!(parse_extensions(&mut cursor).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_key_usage_and_eku_parse_required_bits() {
    let key_usage = der_payload(&[0x03, 0x02, 0x00, 0xA4]);
    let parsed = parse_key_usage(PayloadSpanRef::from_payload(&key_usage)).expect("key usage");

    assert!(parsed.digital_signature);
    assert!(parsed.key_encipherment);
    assert!(parsed.key_cert_sign);

    let eku = der_payload(&[
        0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    ]);
    assert!(
        parse_extended_key_usage(PayloadSpanRef::from_payload(&eku))
            .expect("extended key usage")
            .server_auth
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_san_dns_and_ip_matching() {
    let dns = der_payload(&[
        0x30, 0x0D, 0x82, 0x0B, b'E', b'X', b'A', b'M', b'P', b'L', b'E', b'.', b'C', b'O', b'M',
    ]);
    let ip = der_payload(&[0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1]);

    assert!(match_hostname_in_san(
        PayloadSpanRef::from_payload(&dns),
        "example.com"
    ));
    assert!(!match_hostname_in_san(
        PayloadSpanRef::from_payload(&dns),
        "other.example.com"
    ));
    assert!(match_hostname_in_san(
        PayloadSpanRef::from_payload(&ip),
        "127.0.0.1"
    ));
    assert!(!match_hostname_in_san(
        PayloadSpanRef::from_payload(&ip),
        "127.0.0.2"
    ));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_chain_link_rejects_ca_path_len_violation() {
    let name = der_payload(&[0x30, 0x00]);
    let sig = der_payload(&[]);
    let span = PayloadSpanRef::from_payload(&name);
    let sig_span = PayloadSpanRef::from_payload(&sig);
    let intermediate = X509Certificate {
        raw_tbs: span,
        signature_algorithm: SignatureAlgorithmId::Sha256WithRsa,
        issuer_raw: span,
        subject_raw: span,
        subject_public_key_info: SubjectPublicKeyInfo::Unknown,
        signature_value: sig_span,
        not_before: 0,
        not_after: u64::MAX,
        is_ca: true,
        path_len_constraint: None,
        san_raw: None,
        key_usage: None,
        extended_key_usage: None,
    };
    let root = X509Certificate {
        raw_tbs: span,
        signature_algorithm: SignatureAlgorithmId::Sha256WithRsa,
        issuer_raw: span,
        subject_raw: span,
        subject_public_key_info: SubjectPublicKeyInfo::Unknown,
        signature_value: sig_span,
        not_before: 0,
        not_after: u64::MAX,
        is_ca: true,
        path_len_constraint: Some(0),
        san_raw: None,
        key_usage: Some(KeyUsage {
            digital_signature: false,
            key_encipherment: false,
            key_cert_sign: true,
        }),
        extended_key_usage: None,
    };

    assert!(verify_chain_links(&[intermediate, root]).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_validate_certificate_chain_requires_trust_anchor() {
    let payload = test_cert_payload();
    let chain = [PayloadSpanRef::from_payload(&payload)];
    let cert = X509Parser::parse_certificate(chain[0]).expect("test certificate parses");
    let context = X509VerificationContext {
        now_unix: cert.not_before,
        server_name: None,
        trusted_roots: &[],
        allow_subject_cn_fallback: false,
    };

    assert!(
        CertificatePolicy::Tls13ServerAuth(context)
            .verify_chain(&chain)
            .is_none()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_validate_certificate_chain_accepts_trusted_anchor() {
    let payload = test_cert_payload();
    let span = PayloadSpanRef::from_payload(&payload);
    let chain = [span];
    let trusted = [span];
    let cert = X509Parser::parse_certificate(span).expect("test certificate parses");

    assert!(
        CertificatePolicy::Tls13ServerAuth(X509VerificationContext {
            now_unix: cert.not_before,
            server_name: Some("Test"),
            trusted_roots: &trusted,
            allow_subject_cn_fallback: true,
        })
        .verify_chain(&chain)
        .is_some()
    );
    assert!(
        CertificatePolicy::Tls13ServerAuth(X509VerificationContext {
            now_unix: cert.not_before,
            server_name: Some("example.com"),
            trusted_roots: &trusted,
            allow_subject_cn_fallback: true,
        })
        .verify_chain(&chain)
        .is_none()
    );
    assert!(
        CertificatePolicy::Tls13ServerAuth(X509VerificationContext {
            now_unix: cert.not_before,
            server_name: Some("Test"),
            trusted_roots: &trusted,
            allow_subject_cn_fallback: false,
        })
        .verify_chain(&chain)
        .is_none()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_tls13_server_auth_rejects_leaf_without_digital_signature_key_usage() {
    let payload = test_cert_payload();
    let span = PayloadSpanRef::from_payload(&payload);
    let mut leaf = X509Parser::parse_certificate(span).expect("test certificate parses");
    leaf.key_usage = Some(KeyUsage {
        digital_signature: false,
        key_encipherment: true,
        key_cert_sign: false,
    });

    assert!(!leaf.key_usage.expect("key usage").digital_signature);
    assert!(validate_tls13_leaf_usage(&leaf).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_validate_certificate_chain_rejects_empty_chain() {
    assert!(
        CertificatePolicy::Tls13ServerAuth(X509VerificationContext {
            now_unix: 0,
            server_name: None,
            trusted_roots: &[],
            allow_subject_cn_fallback: false,
        })
        .verify_chain(&[])
        .is_none()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_wildcard_matching() {
    assert!(match_wildcard(b"*.google.com", "www.google.com"));
    assert!(!match_wildcard(b"*.google.com", "google.com"));
    assert!(!match_wildcard(b"*.google.com", "a.b.google.com"));
    assert!(match_wildcard(b"www.google.com", "www.google.com"));
    assert!(!match_wildcard(b"google.com", "www.google.com"));
}
