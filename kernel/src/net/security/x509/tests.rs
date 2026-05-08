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
    let mut cursor = DerCursor::new(PayloadSpanRef::from_payload(&payload));
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
    let mut cursor = DerCursor::new(PayloadSpanRef::from_payload(&payload));
    let seq = cursor.read_sequence().expect("read sequence");

    assert_eq!(seq.value.total_len(), 128);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_der_cursor_nested_sequence() {
    let payload = der_payload(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    let mut cursor = DerCursor::new(PayloadSpanRef::from_payload(&payload));
    let content = cursor.read_sequence().expect("read sequence").value;
    let mut inner = DerCursor::new(content);

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
    let mut cursor = DerCursor::new(PayloadSpanRef::from_payload(&payload));

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
        DerCursor::new(PayloadSpanRef::from_payload(&empty))
            .read_tlv()
            .is_none()
    );

    let overlong = der_payload(&[0x30, 0xFF]);
    assert!(
        DerCursor::new(PayloadSpanRef::from_payload(&overlong))
            .read_sequence()
            .is_none()
    );

    let not_sequence = der_payload(&[0x02, 0x01, 0x00]);
    assert!(
        DerCursor::new(PayloadSpanRef::from_payload(&not_sequence))
            .read_sequence()
            .is_none()
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_parse_x509_certificate_basic_fields() {
    let payload = test_cert_payload();
    let cert =
        parse_x509_certificate(PayloadSpanRef::from_payload(&payload)).expect("parse test cert");

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
    let cert =
        parse_x509_certificate(PayloadSpanRef::from_payload(&payload)).expect("parse test cert");

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
fn test_parse_x509_certificate_rejects_invalid_input() {
    let empty = der_payload(&[]);
    let not_sequence = der_payload(&[0x02, 0x01, 0x00]);
    let truncated = der_payload(&[0x30, 0x03, 0x02, 0x01]);

    assert!(parse_x509_certificate(PayloadSpanRef::from_payload(&empty)).is_none());
    assert!(parse_x509_certificate(PayloadSpanRef::from_payload(&not_sequence)).is_none());
    assert!(parse_x509_certificate(PayloadSpanRef::from_payload(&truncated)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_validate_certificate_chain_requires_trust_anchor() {
    let payload = test_cert_payload();
    let chain = [PayloadSpanRef::from_payload(&payload)];

    assert!(validate_certificate_chain(&chain, None, &[]).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_validate_certificate_chain_accepts_trusted_anchor() {
    let payload = test_cert_payload();
    let span = PayloadSpanRef::from_payload(&payload);
    let chain = [span];
    let trusted = [span];

    assert!(validate_certificate_chain(&chain, Some("Test"), &trusted).is_some());
    assert!(validate_certificate_chain(&chain, Some("example.com"), &trusted).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_validate_certificate_chain_rejects_empty_chain() {
    assert!(validate_certificate_chain(&[], None, &[]).is_none());
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
