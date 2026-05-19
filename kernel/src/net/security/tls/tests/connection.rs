// ============================================================================
// kernel/src/net/security/tls/tests/connection.rs - TLS 1.3 connection tests
// ============================================================================

use super::super::protocol::ContentType;
use super::super::{ExperimentalTlsConnection, TlsBytes, TlsConfig, TlsError, TlsState};

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> TlsBytes<16384> {
    let view = crate::net::payload::PacketPayloadView::new(payload);
    let mut bytes = TlsBytes::<16384>::new();
    bytes
        .set_filled_len(view.total_len())
        .expect("test payload fits fixed TLS buffer");
    let mut copied = 0usize;
    view.for_each_chunk(|chunk| {
        let take = chunk.len().min(view.total_len() - copied);
        bytes.as_mut_storage()[copied..copied + take].copy_from_slice(&chunk[..take]);
        copied += take;
    });
    bytes
        .set_filled_len(copied)
        .expect("copied test payload length stays in bounds");
    bytes
}

fn handshake_payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
    test_payload(data)
}

fn test_payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
    let mut writer = crate::net::payload::GeneratedPacketWriter::new(
        data.len(),
        kernel_api::resource::net::DEFAULT_PACKET_HEADROOM,
    )
    .expect("test payload allocation succeeds");
    writer
        .write_bytes(data)
        .expect("test payload write succeeds");
    writer.finish().expect("test payload is exact")
}

fn find_extension_in_hello(hello: &[u8], ext_lo: u8) -> Option<usize> {
    let payload = &hello[5..];
    for i in 0..payload.len().saturating_sub(1) {
        if payload[i] == 0x00 && payload[i + 1] == ext_lo {
            return Some(i);
        }
    }
    None
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_handshake_truncated_header() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");

    let data = [2u8, 0, 0];
    let result = conn.process_handshake(handshake_payload(&data));
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_connection_initial_state() {
    let config = TlsConfig::new();
    let conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    assert_eq!(conn.state(), TlsState::Initial);
    assert!(conn.negotiated_version().is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_connection_client_hello() {
    let config = TlsConfig::new()
        .with_server_name("example.com")
        .expect("test server name fits fixed TLS capacity");
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");

    let hello = payload_bytes(&conn.build_client_hello_payload());

    assert_eq!(hello[0], ContentType::Handshake as u8);
    assert_eq!(hello[1], 0x03);
    assert_eq!(hello[2], 0x01);
    assert_eq!(conn.state(), TlsState::ClientHelloSent);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls_connection_encrypt_not_established() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    let result = conn.encrypt(b"hello");
    assert!(matches!(result, Err(TlsError::NotConnected)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_incoming_payload_accepts_multiple_plain_records() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    let records = [
        ContentType::Alert as u8,
        0x03,
        0x03,
        0,
        2,
        1,
        0,
        ContentType::Alert as u8,
        0x03,
        0x03,
        0,
        2,
        1,
        0,
    ];

    let plaintext = conn
        .process_incoming_payload(test_payload(&records))
        .expect("concatenated TLS records should be processed one by one");

    assert!(plaintext.is_empty());
    assert_eq!(conn.state(), TlsState::Closed);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_incoming_payload_keeps_partial_record_buffered() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    let first_fragment = [ContentType::Alert as u8, 0x03, 0x03, 0, 2, 1];
    let second_fragment = [0];

    let pending_plaintext = conn
        .process_incoming_payload(test_payload(&first_fragment))
        .expect("partial TLS record should stay buffered");
    assert!(pending_plaintext.is_empty());
    assert_ne!(conn.state(), TlsState::Closed);

    let plaintext = conn
        .process_incoming_payload(test_payload(&second_fragment))
        .expect("second fragment should complete the buffered TLS record");
    assert!(plaintext.is_empty());
    assert_eq!(conn.state(), TlsState::Closed);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_process_handshake_finished_without_verify_data_rejected() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");

    let data = [20u8, 0, 0, 0];
    let result = conn.process_handshake(handshake_payload(&data));
    assert!(matches!(result, Err(TlsError::DecodeError)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_client_hello_key_share() {
    let config = TlsConfig::new()
        .with_server_name("example.com")
        .expect("test server name fits fixed TLS capacity");
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    let hello = payload_bytes(&conn.build_client_hello_payload());

    assert_eq!(hello[0], ContentType::Handshake as u8);
    assert!(
        find_extension_in_hello(&hello, 0x33).is_some(),
        "KeyShare extension not found in ClientHello",
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_client_hello_supported_versions_only_offer_tls13() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    let hello = payload_bytes(&conn.build_client_hello_payload());
    let payload = &hello[5..];

    let sv_pos = find_extension_in_hello(&hello, 0x2B)
        .expect("Supported Versions extension not found in ClientHello");
    let ext_len = ((payload[sv_pos + 2] as usize) << 8) | payload[sv_pos + 3] as usize;
    let versions_len = payload[sv_pos + 4] as usize;
    assert_eq!(versions_len, 2);
    assert_eq!(ext_len, versions_len + 1);
    assert_eq!(&payload[sv_pos + 5..sv_pos + 7], &[0x03, 0x04]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_client_hello_has_no_resumption_modes() {
    let config = TlsConfig::new();
    let mut conn =
        ExperimentalTlsConnection::new(config).expect("test TLS connection entropy is available");
    let hello = payload_bytes(&conn.build_client_hello_payload());

    assert!(find_extension_in_hello(&hello, 0x2D).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_tls13_strip_content_type() {
    fn payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
        let mut writer = crate::net::payload::GeneratedPacketWriter::new(data.len(), 0).unwrap();
        writer.write_bytes(data).unwrap();
        writer.finish().unwrap()
    }

    assert_eq!(
        ExperimentalTlsConnection::tls13_split_content_type_payload(&payload(&[
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17,
        ])),
        Some((0x17, 5))
    );
    assert_eq!(
        ExperimentalTlsConnection::tls13_split_content_type_payload(&payload(&[
            0x48, 0x65, 0x17, 0x00, 0x00,
        ])),
        Some((0x17, 2))
    );
    assert_eq!(
        ExperimentalTlsConnection::tls13_split_content_type_payload(&payload(&[0x16])),
        Some((0x16, 0))
    );
    assert_eq!(
        ExperimentalTlsConnection::tls13_split_content_type_payload(&payload(&[0x00, 0x00, 0x00])),
        None
    );
}
