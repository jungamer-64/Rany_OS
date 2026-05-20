// ============================================================================
// kernel/src/net/security/tls/connection/client_hello.rs - TLS 1.3 ClientHello
// ============================================================================

use super::state::TlsHandshakeProgress;
use super::{
    ContentType, GeneratedPacketWriter, HandshakeType, PacketPayload,
    TLS_CLIENT_HELLO_SCRATCH_CAPACITY, TLS_EXTENSION_SCRATCH_CAPACITY, TlsBytes, TlsConnectionCore,
    TlsError, TlsResult,
};
use crate::net::security::tls::crypto::{SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE};
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

impl TlsConnectionCore {
    pub(super) fn hash_len(&self) -> usize {
        if self
            .negotiation
            .selected()
            .is_ok_and(|selected| selected.cipher().uses_sha384())
        {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        }
    }

    fn init_transcript_hash(&mut self) {
        self.transcript.initialize();
    }

    pub(crate) fn build_client_hello_payload(&mut self) -> TlsResult<PacketPayload> {
        self.init_transcript_hash();

        let mut hello = TlsBytes::<TLS_CLIENT_HELLO_SCRATCH_CAPACITY>::new();
        if hello.append_slice(&[0x03, 0x03]).is_none()
            || hello
                .append_slice(self.negotiation.client_random.as_bytes())
                .is_none()
            || hello.push_byte(0).is_none()
            || hello
                .append_be_u16((self.config.cipher_suites.len() * 2) as u16)
                .is_none()
        {
            return Err(TlsError::DecodeError);
        }

        for cipher in &self.config.cipher_suites {
            if hello.append_be_u16(cipher.wire()).is_none() {
                return Err(TlsError::DecodeError);
            }
        }

        if hello.append_slice(&[0x01, 0x00]).is_none() {
            return Err(TlsError::DecodeError);
        }

        let mut extensions = TlsBytes::<TLS_EXTENSION_SCRATCH_CAPACITY>::new();
        if self.append_extensions(&mut extensions).is_none()
            || hello.append_be_u16(extensions.len() as u16).is_none()
            || hello.append_slice(extensions.as_slice()).is_none()
        {
            return Err(TlsError::DecodeError);
        }

        let mut message = TlsBytes::<TLS_CLIENT_HELLO_SCRATCH_CAPACITY>::new();
        if message
            .push_byte(HandshakeType::ClientHello as u8)
            .is_none()
            || message.append_be_u24(hello.len()).is_none()
            || message.append_slice(hello.as_slice()).is_none()
        {
            return Err(TlsError::DecodeError);
        }

        self.append_transcript_bytes(message.as_slice())
            .expect("client hello transcript append");

        let record_header = [
            ContentType::Handshake as u8,
            0x03,
            0x01,
            (message.len() >> 8) as u8,
            message.len() as u8,
        ];

        self.negotiation.progress = TlsHandshakeProgress::ClientHelloSent;
        let Some(mut writer) = GeneratedPacketWriter::new(
            record_header.len().saturating_add(message.len()),
            DEFAULT_PACKET_HEADROOM,
        ) else {
            return Err(TlsError::DecodeError);
        };
        if writer.write_bytes(&record_header).is_none()
            || writer.write_bytes(message.as_slice()).is_none()
        {
            return Err(TlsError::DecodeError);
        }
        writer.finish().ok_or(TlsError::DecodeError)
    }

    fn append_supported_versions_ext<const N: usize>(&self, ext: &mut TlsBytes<N>) -> Option<()> {
        ext.push_byte(2)?;
        ext.append_slice(&[0x03, 0x04])
    }

    fn append_tls13_key_share<const N: usize>(&self, extensions: &mut TlsBytes<N>) -> Option<()> {
        let keypair = &self.handshake_secrets.local_ecdh_keypair;
        let pubkey_bytes = keypair.public_key_bytes();
        let group_id = keypair.group().to_named_group();
        let entry_len = 2 + 2 + pubkey_bytes.len();
        let mut ext = TlsBytes::<128>::new();
        ext.append_be_u16(entry_len as u16)?;
        ext.append_be_u16(group_id)?;
        ext.append_be_u16(pubkey_bytes.len() as u16)?;
        ext.append_slice(pubkey_bytes.as_slice())?;
        extensions.append_slice(&[0, 51])?;
        extensions.append_be_u16(ext.len() as u16)?;
        extensions.append_slice(ext.as_slice())
    }

    fn append_extensions<const N: usize>(&self, extensions: &mut TlsBytes<N>) -> Option<()> {
        let name_bytes = self.config.server_name.as_bytes();
        let mut ext = TlsBytes::<512>::new();
        let list_len = name_bytes.len() + 3;
        ext.append_be_u16(list_len as u16)?;
        ext.push_byte(0)?;
        ext.append_be_u16(name_bytes.len() as u16)?;
        ext.append_slice(name_bytes)?;
        extensions.append_slice(&[0, 0])?;
        extensions.append_be_u16(ext.len() as u16)?;
        extensions.append_slice(ext.as_slice())?;

        let mut groups = TlsBytes::<128>::new();
        groups.append_be_u16((self.config.named_groups.len() * 2) as u16)?;
        for group in &self.config.named_groups {
            groups.append_be_u16(group.wire())?;
        }
        extensions.append_slice(&[0, 10])?;
        extensions.append_be_u16(groups.len() as u16)?;
        extensions.append_slice(groups.as_slice())?;

        let mut signatures = TlsBytes::<128>::new();
        signatures.append_be_u16((self.config.signature_schemes.len() * 2) as u16)?;
        for scheme in &self.config.signature_schemes {
            signatures.append_be_u16(scheme.wire())?;
        }
        extensions.append_slice(&[0, 13])?;
        extensions.append_be_u16(signatures.len() as u16)?;
        extensions.append_slice(signatures.as_slice())?;

        let mut versions = TlsBytes::<8>::new();
        self.append_supported_versions_ext(&mut versions)?;
        extensions.append_slice(&[0, 43])?;
        extensions.append_be_u16(versions.len() as u16)?;
        extensions.append_slice(versions.as_slice())?;

        self.append_tls13_key_share(extensions)?;

        if !self.config.alpn_protocols.is_empty() {
            let mut protos = TlsBytes::<512>::new();
            for proto in &self.config.alpn_protocols {
                protos.push_byte(proto.len() as u8)?;
                protos.append_slice(proto.as_bytes())?;
            }
            let mut ext = TlsBytes::<512>::new();
            ext.append_be_u16(protos.len() as u16)?;
            ext.append_slice(protos.as_slice())?;
            extensions.append_slice(&[0, 16])?;
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }
        Some(())
    }
}
