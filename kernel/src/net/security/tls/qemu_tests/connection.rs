// ============================================================================
// kernel/src/net/security/tls/qemu_tests/connection.rs - TLS 1.3 connection smokes
// ============================================================================

use super::super::connection::TlsConnectionCore;
use super::super::protocol::ContentType;
use super::super::{TlsBytes, TlsClientConfig, TlsError, TlsHandshake, TlsTrustAnchors};
use crate::net::payload::PayloadSpanRef;

fn payload_bytes(payload: &kernel_api::resource::net::PacketPayload) -> TlsBytes<16384> {
    let view = crate::net::payload::PacketPayloadView::new(payload);
    let mut bytes = TlsBytes::<16384>::new();
    bytes
        .set_filled_len(view.total_len())
        .expect("qemu TLS payload fits fixed test buffer");
    let mut copied = 0usize;
    view.for_each_chunk(|chunk| {
        let take = chunk.len().min(view.total_len() - copied);
        bytes.as_mut_storage()[copied..copied + take].copy_from_slice(&chunk[..take]);
        copied += take;
    });
    bytes
        .set_filled_len(copied)
        .expect("copied qemu TLS payload length stays in bounds");
    bytes
}

fn handshake_payload(data: &[u8]) -> kernel_api::resource::net::PacketPayload {
    let Some(mut writer) = crate::net::payload::GeneratedPacketWriter::new(
        data.len(),
        kernel_api::resource::net::DEFAULT_PACKET_HEADROOM,
    ) else {
        return kernel_api::resource::net::PacketPayload::default();
    };
    if writer.write_generated_bytes(data).is_none() {
        return kernel_api::resource::net::PacketPayload::default();
    }
    writer
        .finish()
        .unwrap_or_else(kernel_api::resource::net::PacketPayload::default)
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

pub fn wave8_tls_tls_handshake_start_smoke() -> bool {
    let config = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits");
    TlsHandshake::start(config).is_ok()
}

pub fn wave8_tls_tls_handshake_client_hello_smoke() -> bool {
    let Ok(config) = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
    else {
        return false;
    };
    let Ok((_handshake, client_hello)) = TlsHandshake::start(config) else {
        return false;
    };
    let hello = payload_bytes(&client_hello);
    hello.len() >= 3
        && hello[0] == ContentType::Handshake as u8
        && hello[1] == 0x03
        && hello[2] == 0x01
}

pub fn wave8_tls_tls_handshake_surface_smoke() -> bool {
    let config = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits");
    TlsHandshake::start(config).is_ok()
}

pub fn wave8_tls_tls13_coalesced_application_records_smoke() -> bool {
    TlsConnectionCore::tls13_coalesced_application_records_smoke()
}

pub fn wave8_tls_process_handshake_truncated_header_smoke() -> bool {
    let config = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits");
    let Ok(mut conn) = TlsConnectionCore::new(config) else {
        return false;
    };
    let data = [2u8, 0, 0];
    matches!(
        {
            let payload = handshake_payload(&data);
            conn.process_handshake(PayloadSpanRef::from_payload(&payload))
        },
        Err(TlsError::DecodeError)
    )
}

pub fn wave8_tls_tls13_handshake_start_smoke() -> bool {
    wave8_tls_tls_handshake_start_smoke()
}

pub fn wave8_tls_tls13_client_hello_key_share_smoke() -> bool {
    let Ok(config) = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
    else {
        return false;
    };
    let Ok((_handshake, client_hello)) = TlsHandshake::start(config) else {
        return false;
    };
    let hello = payload_bytes(&client_hello);

    hello.first().copied() == Some(ContentType::Handshake as u8)
        && find_extension_in_hello(&hello, 0x33).is_some()
}

pub fn wave8_tls_tls13_client_hello_supported_versions_smoke() -> bool {
    let config = TlsClientConfig::for_server_name("example.com", TlsTrustAnchors::empty())
        .expect("test server name fits");
    let Ok((_handshake, client_hello)) = TlsHandshake::start(config) else {
        return false;
    };
    let hello = payload_bytes(&client_hello);
    let Some(hello_payload) = hello.get(5..) else {
        return false;
    };
    let Some(sv_pos) = find_extension_in_hello(&hello, 0x2B) else {
        return false;
    };
    if sv_pos + 7 > hello_payload.len() {
        return false;
    }

    let ext_len = ((hello_payload[sv_pos + 2] as usize) << 8) | hello_payload[sv_pos + 3] as usize;
    let versions_len = hello_payload[sv_pos + 4] as usize;
    versions_len == 2
        && ext_len == versions_len + 1
        && hello_payload[sv_pos + 5] == 0x03
        && hello_payload[sv_pos + 6] == 0x04
}

pub fn wave8_tls_tls13_strip_content_type_smoke() -> bool {
    fn payload(data: &[u8]) -> Option<kernel_api::resource::net::PacketPayload> {
        let mut writer = crate::net::payload::GeneratedPacketWriter::new(data.len(), 0)?;
        writer.write_generated_bytes(data)?;
        writer.finish()
    }

    let case1 = payload(&[0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17])
        .and_then(|payload| TlsConnectionCore::tls13_split_content_type_payload(&payload))
        .map(|inner| (inner.content_type_wire(), inner.content_len()))
        == Some((0x17, 5));
    let case2 = payload(&[0x48, 0x65, 0x17, 0x00, 0x00])
        .and_then(|payload| TlsConnectionCore::tls13_split_content_type_payload(&payload))
        .map(|inner| (inner.content_type_wire(), inner.content_len()))
        == Some((0x17, 2));
    let case3 = payload(&[0x16])
        .and_then(|payload| TlsConnectionCore::tls13_split_content_type_payload(&payload))
        .map(|inner| (inner.content_type_wire(), inner.content_len()))
        == Some((0x16, 0));
    let case4 = payload(&[0x00, 0x00, 0x00])
        .and_then(|payload| TlsConnectionCore::tls13_split_content_type_payload(&payload))
        .is_none();

    case1 && case2 && case3 && case4
}
