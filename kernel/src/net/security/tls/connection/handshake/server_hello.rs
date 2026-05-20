// ============================================================================
// kernel/src/net/security/tls/connection/handshake/server_hello.rs
// ============================================================================

use super::super::state::{SelectedTls13Parameters, TlsHandshakeProgress, TlsServerRandom};
use super::super::{PayloadSpanRef, TlsConnectionCore, ecdh};
use crate::net::security::tls::TlsVersion;
use crate::net::security::tls::error::{TlsError, TlsResult};

impl TlsConnectionCore {
    pub(super) fn process_server_hello(&mut self, data: PayloadSpanRef<'_>) -> TlsResult<()> {
        if data.total_len() < 38 {
            return Err(TlsError::DecodeError);
        }

        let legacy_version = data.read_u16_be(0).ok_or(TlsError::DecodeError)?;
        if legacy_version != 0x0303 {
            return Err(TlsError::VersionMismatch);
        }
        self.negotiation.server_random =
            TlsServerRandom::new(data.read_array::<32>(2).ok_or(TlsError::DecodeError)?);

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
        let cipher = self.config.cipher_suites.negotiate_wire(cipher_wire)?;
        if data.read_u8(cipher_offset + 2) != Some(0) {
            return Err(TlsError::DecodeError);
        }

        let ext_offset = cipher_offset + 3;
        let server_key_share = Self::parse_server_hello_extensions(data, ext_offset)?;

        let selected = SelectedTls13Parameters::new(cipher);

        if self.negotiation.server_random.is_hello_retry_request() {
            return self.process_hello_retry_request(selected);
        }

        self.handle_tls13_hello(selected, server_key_share)
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
                            .subspan(body_offset + 4, key_len)
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
        selected: SelectedTls13Parameters,
        server_key_share: Option<(u16, PayloadSpanRef<'_>)>,
    ) -> TlsResult<()> {
        let (group_id, server_pubkey) = server_key_share.ok_or(TlsError::HandshakeFailure)?;
        let group =
            ecdh::EcdhGroup::from_named_group(group_id).ok_or(TlsError::UnsupportedCipherSuite)?;
        let local_keypair = &self.handshake_secrets.local_ecdh_keypair;
        if local_keypair.group() != group {
            return Err(TlsError::HandshakeFailure);
        }

        let peer_key = server_pubkey
            .read_fixed_bytes::<128>(server_pubkey.total_len())
            .ok_or(TlsError::DecodeError)?;
        let shared_secret = local_keypair
            .shared_secret(peer_key.as_slice())
            .map_err(|_| TlsError::CryptoError)?;

        self.handshake_secrets
            .set_pre_master_secret(shared_secret.as_slice())?;
        self.negotiation.progress = TlsHandshakeProgress::ServerHelloReceived(selected);
        Ok(())
    }

    pub(super) fn process_hello_retry_request(
        &mut self,
        selected: SelectedTls13Parameters,
    ) -> TlsResult<()> {
        self.transcript
            .replace_with_message_hash(selected.cipher().uses_sha384());
        self.negotiation.progress = TlsHandshakeProgress::HelloRetryPending(selected);
        Ok(())
    }

    pub(crate) fn build_client_hello_retry(
        &mut self,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        if !self.negotiation.progress.is_hello_retry_pending() {
            return Err(TlsError::UnexpectedMessage);
        }
        let group = self.handshake_secrets.local_ecdh_keypair.group();
        if let Ok(new_keypair) = ecdh::EcdhKeyPair::generate(group) {
            self.handshake_secrets.local_ecdh_keypair = new_keypair;
        }
        self.negotiation.progress = TlsHandshakeProgress::ClientHelloSent;
        self.build_client_hello_payload()
    }
}
