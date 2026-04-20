// ============================================================================
// kernel/src/net/security/tls/tests/connection.rs - セキュリティ / TLS / テスト / 接続
// ============================================================================

use super::super::protocol::ContentType;
use super::super::{
    TlsBytes, TlsConfig, TlsConnection, TlsError, TlsState,
    tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished,
};

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> TlsBytes<16384> {
    let view = crate::net::payload::PacketPayloadView::new(payload);
    let mut bytes = TlsBytes::<16384>::new();
    bytes
        .set_filled_len(view.total_len())
        .expect("test payload fits fixed TLS buffer");
    let copied = view.copy_range(0, bytes.as_mut_slice());
    bytes
        .set_filled_len(copied)
        .expect("copied test payload length stays in bounds");
    bytes
}

/// Find a TLS extension (0x00, ext_lo) in a ClientHello record.
/// Returns the offset within the payload (after record header) where the type was found.
fn find_extension_in_hello(hello: &[u8], ext_lo: u8) -> Option<usize> {
    let payload = &hello[5..];
    for i in 0..payload.len().saturating_sub(1) {
        if payload[i] == 0x00 && payload[i + 1] == ext_lo {
            return Some(i);
        }
    }
    None
}

/// TLS handshake parser should reject truncated handshake headers
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_handshake_truncated_header() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = [2u8, 0, 0];
    let result = conn.process_handshake(&data);
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

/// TLS connection state machine: initial state
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_connection_initial_state() {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    assert_eq!(conn.state(), TlsState::Initial);
    assert!(conn.negotiated_version().is_none());
}

/// TLS connection: build ClientHello
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_connection_client_hello() {
    let config = TlsConfig::new()
        .with_server_name("example.com")
        .expect("test server name fits fixed TLS capacity");
    let mut conn = TlsConnection::new(config);

    let hello = payload_bytes(&conn.build_client_hello_payload());

    assert_eq!(hello[0], ContentType::Handshake as u8);
    assert_eq!(hello[1], 0x03);
    assert_eq!(hello[2], 0x01);
    assert_eq!(conn.state(), TlsState::ClientHelloSent);
}

/// TLS connection: encrypt fails when not established
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_connection_encrypt_not_established() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let result = conn.encrypt(b"hello");
    assert!(matches!(result, Err(TlsError::NotConnected)));
}

/// TLS handshake parser should handle multiple handshake messages in one record
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_handshake_multiple_messages() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished();
    let result = conn.process_handshake(&data);
    assert!(result.is_ok());
    assert_eq!(conn.state(), TlsState::Established);
    assert_eq!(conn.handshake_transcript_len(), data.len());
}

/// Finished(len=0) is invalid for TLS 1.2 and must be rejected.
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_handshake_finished_without_verify_data_rejected() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);

    let data = [20u8, 0, 0, 0];
    let result = conn.process_handshake(&data);
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

/// TLS 1.3: ClientHello should include KeyShare extension
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_client_hello_key_share() {
    let config = TlsConfig::new()
        .with_server_name("example.com")
        .expect("test server name fits fixed TLS capacity");
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());

    assert!(conn.has_local_ecdh_keypair());
    assert!(conn.has_transcript_hash());
    assert_eq!(hello[0], ContentType::Handshake as u8);
    assert!(
        find_extension_in_hello(&hello, 0x33).is_some(),
        "KeyShare extension not found in ClientHello",
    );
}

/// TLS 1.3: Supported Versions extension should list both TLS 1.3 and 1.2
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_client_hello_supported_versions() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());
    let payload = &hello[5..];

    let sv_pos = find_extension_in_hello(&hello, 0x2B)
        .expect("Supported Versions extension not found in ClientHello");
    if sv_pos + 8 < payload.len() {
        let ext_len = ((payload[sv_pos + 2] as usize) << 8) | payload[sv_pos + 3] as usize;
        let versions_len = payload[sv_pos + 4] as usize;
        assert!(
            versions_len >= 4,
            "Expected at least 2 versions in supported_versions",
        );
        assert_eq!(ext_len, versions_len + 1);
    }
}

/// TLS 1.3: PSK Key Exchange Modes extension present
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_client_hello_psk_modes() {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());

    assert!(
        find_extension_in_hello(&hello, 0x2D).is_some(),
        "PSK Key Exchange Modes extension not found in ClientHello",
    );
}

/// TLS 1.3: strip_content_type helper
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_strip_content_type() {
    let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17];
    let result = TlsConnection::tls13_strip_content_type(&data);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);

    let data2 = [0x48, 0x65, 0x17, 0x00, 0x00];
    let result2 = TlsConnection::tls13_strip_content_type(&data2);
    assert!(result2.is_some());
    assert_eq!(result2.unwrap(), &[0x48, 0x65]);

    let data3 = [0x16];
    let result3 = TlsConnection::tls13_strip_content_type(&data3);
    assert!(result3.is_some());
    assert!(result3.unwrap().is_empty());

    let data4 = [0x00, 0x00, 0x00];
    let result4 = TlsConnection::tls13_strip_content_type(&data4);
    assert!(result4.is_none());
}

/// TLS 1.3: is_tls13 flag starts false
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_initial_state() {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    assert!(!conn.is_tls13());
    assert!(!conn.needs_client_finished());
}
