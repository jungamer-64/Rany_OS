// ============================================================================
// kernel/src/net/security/tls/qemu_tests/connection.rs - セキュリティ / TLS / QEMUテスト / 接続
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
        .expect("qemu TLS payload fits fixed test buffer");
    let mut copied = 0usize;
    view.for_each_chunk(|chunk| {
        if copied == view.total_len() {
            return;
        }
        let take = chunk.len().min(view.total_len() - copied);
        bytes.as_mut_slice()[copied..copied + take].copy_from_slice(&chunk[..take]);
        copied += take;
    });
    bytes
        .set_filled_len(copied)
        .expect("copied qemu TLS payload length stays in bounds");
    bytes
}

fn handshake_payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
    if builder.push_bytes(data).is_none() {
        return kernel_api::resource::net::PacketPayload::default();
    }
    builder.build()
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

pub fn wave8_tls_tls_connection_initial_state_smoke() -> bool {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    conn.state() == TlsState::Initial && conn.negotiated_version().is_none()
}

pub fn wave8_tls_tls_connection_client_hello_smoke() -> bool {
    let config = match TlsConfig::new().with_server_name("example.com") {
        Ok(config) => config,
        Err(_) => return false,
    };
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());
    hello.len() >= 3
        && hello[0] == ContentType::Handshake as u8
        && hello[1] == 0x03
        && hello[2] == 0x01
        && conn.state() == TlsState::ClientHelloSent
}

pub fn wave8_tls_tls_connection_encrypt_not_established_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    matches!(conn.encrypt(b"hello"), Err(TlsError::NotConnected))
}

pub fn wave8_tls_process_handshake_multiple_messages_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let data = tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished();
    conn.process_handshake(handshake_payload(&data)).is_ok()
        && conn.state() == TlsState::Established
        && conn.handshake_transcript_len() == data.len()
}

pub fn wave8_tls_process_handshake_truncated_header_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let data = [2u8, 0, 0];
    matches!(
        conn.process_handshake(handshake_payload(&data)),
        Err(TlsError::DecodeError)
    )
}

pub fn wave8_tls_tls13_initial_state_smoke() -> bool {
    let config = TlsConfig::new();
    let conn = TlsConnection::new(config);
    !conn.is_tls13() && !conn.needs_client_finished()
}

pub fn wave8_tls_tls13_client_hello_key_share_smoke() -> bool {
    let config = match TlsConfig::new().with_server_name("example.com") {
        Ok(config) => config,
        Err(_) => return false,
    };
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());

    conn.has_local_ecdh_keypair()
        && conn.has_transcript_hash()
        && hello.first().copied() == Some(ContentType::Handshake as u8)
        && find_extension_in_hello(&hello, 0x33).is_some()
}

pub fn wave8_tls_tls13_client_hello_supported_versions_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());
    let Some(hello_payload) = hello.get(5..) else {
        return false;
    };
    let Some(sv_pos) = find_extension_in_hello(&hello, 0x2B) else {
        return false;
    };
    if sv_pos + 8 >= hello_payload.len() {
        return false;
    }

    let ext_len = ((hello_payload[sv_pos + 2] as usize) << 8) | hello_payload[sv_pos + 3] as usize;
    let versions_len = hello_payload[sv_pos + 4] as usize;
    versions_len >= 4 && ext_len == versions_len + 1
}

pub fn wave8_tls_tls13_client_hello_psk_modes_smoke() -> bool {
    let config = TlsConfig::new();
    let mut conn = TlsConnection::new(config);
    let hello = payload_bytes(&conn.build_client_hello_payload());
    find_extension_in_hello(&hello, 0x2D).is_some()
}

pub fn wave8_tls_tls13_strip_content_type_smoke() -> bool {
    let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17];
    let data2 = [0x48, 0x65, 0x17, 0x00, 0x00];
    let data3 = [0x16];
    let data4 = [0x00, 0x00, 0x00];

    let case1 = matches!(TlsConnection::tls13_strip_content_type(&data), Some(v) if v == &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    let case2 =
        matches!(TlsConnection::tls13_strip_content_type(&data2), Some(v) if v == &[0x48, 0x65]);
    let case3 = matches!(TlsConnection::tls13_strip_content_type(&data3), Some(v) if v.is_empty());
    let case4 = TlsConnection::tls13_strip_content_type(&data4).is_none();

    case1 && case2 && case3 && case4
}
