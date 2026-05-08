// ============================================================================
// kernel/src/net/security/tls/connection/handshake/server_hello.rs
// ============================================================================

use super::super::{CipherSuite, PayloadSpanRef, TlsConnection, TlsState, TlsVersion, ecdh};
use crate::net::security::tls::error::{TlsError, TlsResult};

impl TlsConnection {
    pub(super) fn process_server_hello(&mut self, data: PayloadSpanRef<'_>) -> TlsResult<()> {
        if data.total_len() < 38 {
            return Err(TlsError::DecodeError);
        }

        let legacy_version = data.read_u16_be(0).ok_or(TlsError::DecodeError)?;
        if legacy_version != 0x0303 {
            return Err(TlsError::VersionMismatch);
        }
        self.negotiation.server_random = data.read_array::<32>(2).ok_or(TlsError::DecodeError)?;

        let session_id_len = data.read_u8(34).ok_or(TlsError::DecodeError)? as usize;
        let cipher_offset = 35usize
            .checked_add(session_id_len)
            .ok_or(TlsError::DecodeError)?;
        if cipher_offset + 3 > data.total_len() {
            return Err(TlsError::DecodeError);
        }

        let cipher_wire = data
            .read_u16_be(cipher_offset)
            .ok_or(TlsError::DecodeError)?;
        let cipher = CipherSuite::from_wire(cipher_wire).ok_or(TlsError::UnsupportedCipherSuite)?;
        if data.read_u8(cipher_offset + 2) != Some(0) {
            return Err(TlsError::DecodeError);
        }

        let ext_offset = cipher_offset + 3;
        let server_key_share = Self::parse_server_hello_extensions(data, ext_offset)?;

        self.negotiation.negotiated_version = Some(TlsVersion::TLS_1_3);
        self.negotiation.negotiated_cipher = Some(cipher);

        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];
        if self.negotiation.server_random == HRR_RANDOM {
            return self.process_hello_retry_request(cipher);
        }

        self.handle_tls13_hello(cipher, server_key_share)
    }

    fn parse_server_hello_extensions<'a>(
        data: PayloadSpanRef<'a>,
        ext_offset: usize,
    ) -> TlsResult<Option<(u16, PayloadSpanRef<'a>)>> {
        if ext_offset + 2 > data.total_len() {
            return Err(TlsError::HandshakeFailure);
        }
        let extensions_len = data.read_u16_be(ext_offset).ok_or(TlsError::DecodeError)? as usize;
        let mut offset = ext_offset + 2;
        let extensions_end = offset
            .checked_add(extensions_len)
            .ok_or(TlsError::DecodeError)?;
        if extensions_end > data.total_len() {
            return Err(TlsError::DecodeError);
        }

        let mut saw_tls13 = false;
        let mut server_key_share = None;
        while offset < extensions_end {
            if offset + 4 > extensions_end {
                return Err(TlsError::DecodeError);
            }
            let ext_type = data.read_u16_be(offset).ok_or(TlsError::DecodeError)?;
            let ext_len = data.read_u16_be(offset + 2).ok_or(TlsError::DecodeError)? as usize;
            let body_offset = offset + 4;
            let next = body_offset
                .checked_add(ext_len)
                .ok_or(TlsError::DecodeError)?;
            if next > extensions_end {
                return Err(TlsError::DecodeError);
            }

            match ext_type {
                43 if ext_len == 2 => {
                    if data.read_u16_be(body_offset) == Some(TlsVersion::WIRE) {
                        saw_tls13 = true;
                    }
                }
                51 if ext_len >= 2 => {
                    let group = data.read_u16_be(body_offset).ok_or(TlsError::DecodeError)?;
                    if ext_len > 2 {
                        if ext_len < 4 {
                            return Err(TlsError::DecodeError);
                        }
                        let key_len =
                            data.read_u16_be(body_offset + 2)
                                .ok_or(TlsError::DecodeError)? as usize;
                        if 4 + key_len != ext_len {
                            return Err(TlsError::DecodeError);
                        }
                        let key_share = data
                            .slice(body_offset + 4, key_len)
                            .ok_or(TlsError::DecodeError)?;
                        server_key_share = Some((group, key_share));
                    }
                }
                _ => {}
            }
            offset = next;
        }

        if !saw_tls13 {
            return Err(TlsError::VersionMismatch);
        }
        Ok(server_key_share)
    }

    fn handle_tls13_hello(
        &mut self,
        _cipher: CipherSuite,
        server_key_share: Option<(u16, PayloadSpanRef<'_>)>,
    ) -> TlsResult<()> {
        let (group_id, server_pubkey) = server_key_share.ok_or(TlsError::HandshakeFailure)?;
        let group =
            ecdh::EcdhGroup::from_named_group(group_id).ok_or(TlsError::UnsupportedCipherSuite)?;
        let local_keypair = self
            .handshake_secrets
            .local_ecdh_keypair
            .as_ref()
            .ok_or(TlsError::HandshakeFailure)?;
        if local_keypair.group() != group {
            return Err(TlsError::HandshakeFailure);
        }

        let peer_key = server_pubkey
            .read_prefix::<128>(server_pubkey.total_len())
            .ok_or(TlsError::DecodeError)?;
        let shared_secret = local_keypair
            .shared_secret(peer_key.as_slice())
            .map_err(|_| TlsError::CryptoError)?;

        Self::set_tls_bytes(
            &mut self.handshake_secrets.pre_master_secret,
            shared_secret.as_slice(),
        )?;
        self.negotiation.state = TlsState::ServerHelloReceived;
        Ok(())
    }

    pub(super) fn process_hello_retry_request(&mut self, cipher: CipherSuite) -> TlsResult<()> {
        self.transcript
            .replace_with_message_hash(cipher.uses_sha384());
        self.negotiation.negotiated_cipher = Some(cipher);
        self.negotiation.state = TlsState::HelloRetryReceived;
        Ok(())
    }

    pub fn build_client_hello_retry(&mut self) -> Option<kernel_api::resource::net::PacketPayload> {
        if self.negotiation.state != TlsState::HelloRetryReceived {
            return None;
        }
        if let Some(ref keypair) = self.handshake_secrets.local_ecdh_keypair {
            if let Ok(new_keypair) = ecdh::EcdhKeyPair::generate(keypair.group()) {
                self.handshake_secrets.local_ecdh_keypair = Some(new_keypair);
            }
        }
        self.negotiation.state = TlsState::ClientHelloSent;
        Some(self.build_client_hello_payload())
    }
}
