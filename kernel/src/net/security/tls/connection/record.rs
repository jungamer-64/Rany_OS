// ============================================================================
// kernel/src/net/security/tls/connection/record.rs - TLS 1.3 record layer
// ============================================================================

use super::{
    AlertDescription, CipherSuite, ContentType, TlsConnectionCore, GeneratedPacketWriter,
    HandshakeType, PacketPayload, PacketPayloadView, PayloadSpanRef, TlsBytes, TlsError, TlsResult,
    append_payload,
};
use super::state::{NegotiatedTlsParameters, TlsConnectionPhase};
use crate::net::security::tls::crypto::{
    AesGcmKey, SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, chacha20_poly1305_tag_chunks,
    chacha20_xor_chunks_in_place, tls13_derive_traffic_keys, tls13_derive_traffic_keys_sha384,
};
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

const TLS13_MAX_PLAINTEXT_LEN: usize = 16 * 1024;
const TLS13_MAX_CIPHERTEXT_LEN: usize = TLS13_MAX_PLAINTEXT_LEN + 256;

#[derive(Clone, Copy)]
struct TlsPlaintextLen(usize);

impl TlsPlaintextLen {
    fn new(len: usize) -> TlsResult<Self> {
        (len <= TLS13_MAX_PLAINTEXT_LEN)
            .then_some(Self(len))
            .ok_or(TlsError::RecordTooLarge)
    }

    const fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy)]
struct TlsCiphertextLen(usize);

impl TlsCiphertextLen {
    fn new(len: usize) -> TlsResult<Self> {
        (len <= TLS13_MAX_CIPHERTEXT_LEN)
            .then_some(Self(len))
            .ok_or(TlsError::RecordTooLarge)
    }

    const fn get(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy)]
struct TlsRecordHeader {
    content_type: ContentType,
    body_len: TlsCiphertextLen,
}

impl TlsRecordHeader {
    fn parse(bytes: [u8; 5]) -> TlsResult<Self> {
        Ok(Self {
            content_type: ContentType::from_u8(bytes[0]).ok_or(TlsError::UnexpectedMessage)?,
            body_len: TlsCiphertextLen::new(u16::from_be_bytes([bytes[3], bytes[4]]) as usize)?,
        })
    }

    fn total_len(self) -> TlsResult<usize> {
        5usize
            .checked_add(self.body_len.get())
            .ok_or(TlsError::DecodeError)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Tls13InnerPlaintext {
    content_type: ContentType,
    content_len: usize,
}

impl Tls13InnerPlaintext {
    const fn new(content_type: ContentType, content_len: usize) -> Self {
        Self {
            content_type,
            content_len,
        }
    }

    const fn content_type(self) -> ContentType {
        self.content_type
    }

    pub(crate) const fn content_len(self) -> usize {
        self.content_len
    }
}

fn constant_time_tag_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

impl TlsConnectionCore {
    pub(super) fn set_tls_bytes<const N: usize>(
        slot: &mut TlsBytes<N>,
        data: &[u8],
    ) -> TlsResult<()> {
        slot.set(data).ok_or(TlsError::DecodeError)
    }

    pub(super) fn tls13_record_aad(len: usize) -> [u8; 5] {
        let len_bytes = (len as u16).to_be_bytes();
        [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ]
    }

    pub(super) fn encrypt_aead_payload_owned(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        mut plaintext: PacketPayload,
    ) -> TlsResult<(PacketPayload, [u8; 16])> {
        let ciphertext_len = plaintext.total_len();
        let tag = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_xor_chunks_in_place(&key_arr, nonce, 1, |visitor| {
                crate::net::payload::for_each_payload_window_chunk_mut(
                    &mut plaintext,
                    0,
                    ciphertext_len,
                    |chunk| visitor(chunk),
                );
            });
            let poly_key_block =
                crate::net::security::tls::crypto::chacha20::chacha20_block(&key_arr, 0, nonce);
            let mut poly_key = [0u8; 32];
            poly_key.copy_from_slice(&poly_key_block[..32]);
            chacha20_poly1305_tag_chunks(&poly_key, aad, ciphertext_len, |visitor| {
                PayloadSpanRef::from_payload(&plaintext).for_each_chunk(visitor)
            })
            .ok_or(TlsError::CryptoError)?
        } else {
            let key = AesGcmKey::new(key).ok_or(TlsError::CryptoError)?;
            key.xor_chunks_in_place(nonce, |visitor| {
                crate::net::payload::for_each_payload_window_chunk_mut(
                    &mut plaintext,
                    0,
                    ciphertext_len,
                    |chunk| visitor(chunk),
                );
            })
            .map_err(|_| TlsError::CryptoError)?;
            key.tag_for_ciphertext_chunks(nonce, aad, ciphertext_len, |visitor| {
                PayloadSpanRef::from_payload(&plaintext).for_each_chunk(visitor)
            })
            .map_err(|_| TlsError::CryptoError)?
        };
        Ok((plaintext, tag))
    }

    pub(super) fn transcript_len(&self) -> usize {
        self.transcript.len()
    }

    pub(super) fn append_transcript_bytes(&mut self, data: &[u8]) -> TlsResult<()> {
        self.transcript.update(data);
        Ok(())
    }

    pub(super) fn append_transcript_span(&mut self, data: PayloadSpanRef<'_>) -> TlsResult<()> {
        data.for_each_chunk(|chunk| self.transcript.update(chunk));
        Ok(())
    }

    pub(super) fn transcript_hash_sha256(&self) -> [u8; SHA256_OUTPUT_SIZE] {
        self.transcript.current_sha256()
    }

    pub(super) fn transcript_hash_sha384(&self) -> [u8; SHA384_OUTPUT_SIZE] {
        self.transcript.current_sha384()
    }

    pub(super) fn tls13_reads_handshake_records(&self) -> bool {
        self.negotiation.phase.reads_handshake_records()
    }

    pub(super) fn decrypt_tls13_record_payload(
        &mut self,
        payload: &mut PacketPayload,
        body_offset: usize,
        record_len: usize,
    ) -> TlsResult<Tls13InnerPlaintext> {
        let cipher = self.negotiation.negotiated.cipher()?.cipher();
        if record_len < 16 {
            return Err(TlsError::DecodeError);
        }

        let ciphertext_len = record_len - 16;
        let tag = PayloadSpanRef::from_range(payload, body_offset + ciphertext_len, 16)
            .ok_or(TlsError::DecodeError)?
            .read_array::<16>(0)
            .ok_or(TlsError::DecodeError)?;

        let (key, iv, seq, is_handshake) = if self.tls13_reads_handshake_records() {
            (
                &self.tls13.hs_read_key,
                &self.tls13.hs_read_iv,
                self.tls13.hs_read_seq.current()?,
                true,
            )
        } else {
            (
                &self.record.read_key,
                &self.record.read_iv,
                self.record.read_seq.current()?,
                false,
            )
        };
        if key.is_empty() || iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let (nonce, aad) = Self::build_tls13_nonce_and_aad(iv.as_slice(), seq, record_len);
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key.as_slice()[..32]);
            let poly_key_block =
                crate::net::security::tls::crypto::chacha20::chacha20_block(&key_arr, 0, &nonce);
            let mut poly_key = [0u8; 32];
            poly_key.copy_from_slice(&poly_key_block[..32]);
            let expected =
                chacha20_poly1305_tag_chunks(&poly_key, &aad, ciphertext_len, |visitor| {
                    PayloadSpanRef::from_range(payload, body_offset, ciphertext_len)
                        .expect("validated TLS ciphertext window")
                        .for_each_chunk(visitor)
                })
                .ok_or(TlsError::DecryptError)?;
            if !constant_time_tag_eq(&expected, &tag) {
                return Err(TlsError::DecryptError);
            }
            chacha20_xor_chunks_in_place(&key_arr, &nonce, 1, |visitor| {
                crate::net::payload::for_each_payload_window_chunk_mut(
                    payload,
                    body_offset,
                    ciphertext_len,
                    |chunk| visitor(chunk),
                );
            });
        } else {
            let key = AesGcmKey::new(key.as_slice()).ok_or(TlsError::CryptoError)?;
            key.verify_ciphertext_chunks(
                &nonce,
                &aad,
                ciphertext_len,
                |visitor| {
                    PayloadSpanRef::from_range(payload, body_offset, ciphertext_len)
                        .expect("validated TLS ciphertext window")
                        .for_each_chunk(visitor)
                },
                &tag,
            )
            .map_err(|_| TlsError::DecryptError)?;
            key.xor_chunks_in_place(&nonce, |visitor| {
                crate::net::payload::for_each_payload_window_chunk_mut(
                    payload,
                    body_offset,
                    ciphertext_len,
                    |chunk| visitor(chunk),
                );
            })
            .map_err(|_| TlsError::DecryptError)?;
        }

        if is_handshake {
            self.tls13.hs_read_seq.advance()?;
        } else {
            self.record.read_seq.advance()?;
        }
        let decrypted = PayloadSpanRef::from_range(payload, body_offset, ciphertext_len)
            .ok_or(TlsError::DecodeError)?;
        Self::tls13_split_content_type_span(decrypted).ok_or(TlsError::DecodeError)
    }

    pub(super) fn consume_tls_record_payload(
        &mut self,
        record: &mut PacketPayload,
        record_offset: usize,
        plaintext: &mut PacketPayload,
    ) -> TlsResult<bool> {
        let record_span = PayloadSpanRef::from_range(
            record,
            record_offset,
            record.total_len().saturating_sub(record_offset),
        )
        .ok_or(TlsError::DecodeError)?;
        let header = record_span
            .read_array::<5>(0)
            .ok_or(TlsError::DecodeError)?;
        let header = TlsRecordHeader::parse(header)?;
        let record_len = header.body_len.get();
        let body_offset = record_offset.checked_add(5).ok_or(TlsError::DecodeError)?;
        let body = PayloadSpanRef::from_range(record, body_offset, record_len)
            .ok_or(TlsError::DecodeError)?;

        match header.content_type {
            ContentType::Handshake => self.process_handshake(body)?,
            ContentType::Alert => self.handle_alert_payload(body)?,
            ContentType::ApplicationData => {
                let inner = self.decrypt_tls13_record_payload(record, body_offset, record_len)?;
                let inner_span = PayloadSpanRef::from_range(record, body_offset, inner.content_len())
                    .ok_or(TlsError::DecodeError)?;
                match inner.content_type() {
                    ContentType::ApplicationData => {
                        let owned = crate::net::payload::clone_payload_window_owned(
                            record,
                            body_offset,
                            inner.content_len(),
                        )
                        .ok_or(TlsError::DecodeError)?;
                        append_payload(plaintext, owned);
                    }
                    ContentType::Handshake => {
                        if self.negotiation.phase.is_established() {
                            self.tls13_process_post_handshake(inner_span)?;
                        } else {
                            self.process_handshake(inner_span)?;
                        }
                    }
                    ContentType::Alert => self.handle_alert_payload(inner_span)?,
                }
            }
        }
        Ok(false)
    }

    pub fn process_incoming_payload(&mut self, payload: PacketPayload) -> TlsResult<PacketPayload> {
        self.record.ingress.push(payload);
        let mut plaintext = PacketPayload::default();
        let mut ingress = core::mem::take(&mut self.record.ingress);

        loop {
            let view = PacketPayloadView::new(ingress.payload());
            let consumed = ingress.cursor();
            let remaining = view.total_len().saturating_sub(consumed);
            if remaining < 5 {
                break;
            }
            let header = view
                .read_array::<5>(consumed)
                .ok_or(TlsError::DecodeError)?;
            let header = TlsRecordHeader::parse(header)?;
            let total_len = header.total_len()?;
            if remaining < total_len {
                break;
            }

            let record_consumed =
                self.consume_tls_record_payload(ingress.payload_mut(), consumed, &mut plaintext)?;
            if record_consumed {
                ingress.clear();
                self.record.ingress = ingress;
                return Ok(plaintext);
            }
            ingress.advance(total_len).ok_or(TlsError::DecodeError)?;
        }
        ingress.compact_consumed().ok_or(TlsError::DecodeError)?;
        self.record.ingress = ingress;
        Ok(plaintext)
    }

    pub(super) fn handle_alert_payload(&mut self, payload: PayloadSpanRef<'_>) -> TlsResult<()> {
        if payload.total_len() != 2 {
            return Err(TlsError::DecodeError);
        }
        let description = payload.read_u8(1).ok_or(TlsError::DecodeError)?;
        if description == AlertDescription::CloseNotify as u8 {
            self.negotiation.phase = TlsConnectionPhase::closed();
        } else {
            self.negotiation.phase = TlsConnectionPhase::failed();
            return Err(TlsError::Alert(description));
        }
        Ok(())
    }

    pub(super) fn dispatch_tls13_inner_content(
        &mut self,
        decrypted: PacketPayload,
        plaintext: &mut PacketPayload,
    ) -> TlsResult<()> {
        if let Some(inner) = Self::tls13_split_content_type_payload(&decrypted) {
            match inner.content_type() {
                ContentType::ApplicationData => {
                    let inner_payload =
                        crate::net::payload::move_payload_window_owned(
                            decrypted,
                            0,
                            inner.content_len(),
                        )
                        .ok_or(TlsError::DecodeError)?;
                    append_payload(plaintext, inner_payload);
                }
                ContentType::Handshake => {
                    let inner_payload =
                        crate::net::payload::move_payload_window_owned(
                            decrypted,
                            0,
                            inner.content_len(),
                        )
                        .ok_or(TlsError::DecodeError)?;
                    if self.negotiation.phase.is_established() {
                        let inner_data = PayloadSpanRef::from_payload(&inner_payload);
                        self.tls13_process_post_handshake(inner_data)?;
                    } else {
                        self.process_handshake(PayloadSpanRef::from_payload(&inner_payload))?;
                    }
                }
                ContentType::Alert => {
                    let inner_payload =
                        crate::net::payload::move_payload_window_owned(
                            decrypted,
                            0,
                            inner.content_len(),
                        )
                        .ok_or(TlsError::DecodeError)?;
                    self.handle_alert_payload(PayloadSpanRef::from_payload(&inner_payload))?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn build_tls13_nonce_and_aad(
        iv: &[u8],
        seq: u64,
        data_len: usize,
    ) -> ([u8; 12], [u8; 5]) {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv[..12]);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        (nonce, Self::tls13_record_aad(data_len))
    }

    pub(super) fn tls13_encrypt_record(
        &mut self,
        inner_plaintext: &[u8],
        is_handshake: bool,
    ) -> TlsResult<PacketPayload> {
        let mut writer = GeneratedPacketWriter::new(inner_plaintext.len(), DEFAULT_PACKET_HEADROOM)
            .ok_or(TlsError::DecodeError)?;
        writer
            .write_bytes(inner_plaintext)
            .ok_or(TlsError::DecodeError)?;
        let payload = writer.finish().ok_or(TlsError::DecodeError)?;
        self.tls13_encrypt_owned_inner(payload, is_handshake)
    }

    pub(super) fn tls13_encrypt_owned_inner(
        &mut self,
        inner_plaintext: PacketPayload,
        is_handshake: bool,
    ) -> TlsResult<PacketPayload> {
        let plaintext_len = TlsPlaintextLen::new(inner_plaintext.total_len())?.get();
        let cipher = self.negotiation.negotiated.cipher()?.cipher();
        let (key, iv, seq) = if is_handshake {
            (
                &self.tls13.hs_write_key,
                &self.tls13.hs_write_iv,
                self.tls13.hs_write_seq.current()?,
            )
        } else {
            (
                &self.record.write_key,
                &self.record.write_iv,
                self.record.write_seq.current()?,
            )
        };
        if key.is_empty() || iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv.as_slice()[..12]);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = TlsCiphertextLen::new(plaintext_len + 16)?.get();
        let aad = Self::tls13_record_aad(encrypted_len);
        let (ciphertext, auth_tag) = Self::encrypt_aead_payload_owned(
            cipher,
            key.as_slice(),
            &nonce,
            &aad,
            inner_plaintext,
        )?;

        if is_handshake {
            self.tls13.hs_write_seq.advance()?;
        } else {
            self.record.write_seq.advance()?;
        }

        let encrypted_len_bytes = (encrypted_len as u16).to_be_bytes();
        let record_header = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            encrypted_len_bytes[0],
            encrypted_len_bytes[1],
        ];
        let mut record = {
            let mut writer =
                GeneratedPacketWriter::new(record_header.len(), DEFAULT_PACKET_HEADROOM)
                    .ok_or(TlsError::DecodeError)?;
            writer
                .write_bytes(&record_header)
                .ok_or(TlsError::DecodeError)?;
            writer.finish().ok_or(TlsError::DecodeError)?
        };
        append_payload(&mut record, ciphertext);
        let mut tag_writer = GeneratedPacketWriter::new(auth_tag.len(), DEFAULT_PACKET_HEADROOM)
            .ok_or(TlsError::DecodeError)?;
        tag_writer
            .write_bytes(&auth_tag)
            .ok_or(TlsError::DecodeError)?;
        append_payload(
            &mut record,
            tag_writer.finish().ok_or(TlsError::DecodeError)?,
        );
        Ok(record)
    }

    pub(crate) fn tls13_encrypt_application_payload(
        &mut self,
        mut payload: PacketPayload,
    ) -> TlsResult<PacketPayload> {
        let mut content_type =
            GeneratedPacketWriter::new(1, DEFAULT_PACKET_HEADROOM).ok_or(TlsError::DecodeError)?;
        content_type
            .write_bytes(&[ContentType::ApplicationData as u8])
            .ok_or(TlsError::DecodeError)?;
        append_payload(
            &mut payload,
            content_type.finish().ok_or(TlsError::DecodeError)?,
        );
        self.tls13_encrypt_owned_inner(payload, false)
    }

    pub(crate) fn tls13_split_content_type_payload(
        decrypted: &PacketPayload,
    ) -> Option<Tls13InnerPlaintext> {
        Self::tls13_split_content_type_span(PayloadSpanRef::from_payload(decrypted))
    }

    pub(crate) fn tls13_split_content_type_span(
        span: PayloadSpanRef<'_>,
    ) -> Option<Tls13InnerPlaintext> {
        for i in (0..span.total_len()).rev() {
            let byte = span.byte_at(i)?;
            if byte != 0 {
                return Some(Tls13InnerPlaintext::new(ContentType::from_u8(byte)?, i));
            }
        }
        None
    }

    pub(crate) fn tls13_process_post_handshake(
        &mut self,
        data: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        let mut offset = 0usize;
        while offset < data.total_len() {
            if data.total_len() - offset < 4 {
                return Err(TlsError::DecodeError);
            }
            let msg_type = data.read_u8(offset).ok_or(TlsError::DecodeError)?;
            let length = data.read_u24_be(offset + 1).ok_or(TlsError::DecodeError)? as usize;
            let body_start = offset + 4;
            let body_end = body_start + length;
            if body_end > data.total_len() {
                return Err(TlsError::DecodeError);
            }
            let payload = data
                .subspan(body_start, length)
                .ok_or(TlsError::DecodeError)?;
            if msg_type == 24 {
                self.tls13_process_key_update(payload)?;
            }
            offset = body_end;
        }
        Ok(())
    }

    pub(super) fn tls13_process_key_update(&mut self, data: PayloadSpanRef<'_>) -> TlsResult<()> {
        let request_update = data.read_u8(0).ok_or(TlsError::DecodeError)?;
        let cipher = self.negotiation.negotiated.cipher()?.cipher();
        let key_len = cipher.key_len();
        let hash_len = if cipher.uses_sha384() {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        };

        let mut new_server_secret = [0u8; 48];
        if cipher.uses_sha384() {
            let mut old_secret = [0u8; 48];
            old_secret.copy_from_slice(&self.tls13.server_app_traffic_secret);
            crate::net::security::tls::crypto::hkdf_expand_label_sha384(
                &old_secret,
                b"traffic upd",
                b"",
                &mut new_server_secret[..hash_len],
            );
        } else {
            let mut old_secret = [0u8; 32];
            old_secret.copy_from_slice(&self.tls13.server_app_traffic_secret[..32]);
            crate::net::security::tls::crypto::hkdf_expand_label(
                &old_secret,
                b"traffic upd",
                b"",
                &mut new_server_secret[..hash_len],
            );
        }
        self.tls13.server_app_traffic_secret = new_server_secret;

        let mut new_read_key = [0u8; 32];
        let mut new_read_iv = [0u8; 12];
        if cipher.uses_sha384() {
            tls13_derive_traffic_keys_sha384(
                &new_server_secret,
                &mut new_read_key[..key_len],
                &mut new_read_iv,
            );
        } else {
            let mut secret32 = [0u8; 32];
            secret32.copy_from_slice(&new_server_secret[..32]);
            tls13_derive_traffic_keys(&secret32, &mut new_read_key[..key_len], &mut new_read_iv);
        }
        Self::set_tls_bytes(&mut self.record.read_key, &new_read_key[..key_len])?;
        Self::set_tls_bytes(&mut self.record.read_iv, &new_read_iv)?;
        self.record.read_seq.reset();

        if request_update == 1 {
            self.tls13.key_update_response.require();
        }
        Ok(())
    }

    pub(super) fn take_key_update_response_payload(&mut self) -> TlsResult<Option<PacketPayload>> {
        if !self.tls13.key_update_response.take_required() {
            return Ok(None);
        }
        if !self.negotiation.phase.is_established() {
            return Err(TlsError::NotConnected);
        }
        let inner = [
            HandshakeType::KeyUpdate as u8,
            0,
            0,
            1,
            0,
            ContentType::Handshake as u8,
        ];
        Ok(Some(self.tls13_encrypt_record(&inner, false)?))
    }

    pub(super) fn send_close_notify(&mut self) -> TlsResult<PacketPayload> {
        if self.record.write_key.is_empty() {
            return Err(TlsError::NotConnected);
        }
        let inner = [
            1,
            AlertDescription::CloseNotify as u8,
            ContentType::Alert as u8,
        ];
        let record = self.tls13_encrypt_record(&inner, false)?;
        self.negotiation.phase = TlsConnectionPhase::closing();
        Ok(record)
    }

    #[cfg(feature = "qemu-test-export")]
    pub(crate) fn tls13_coalesced_application_records_smoke() -> bool {
        fn payload(data: &[u8]) -> Option<PacketPayload> {
            let mut writer = GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM)?;
            writer.write_bytes(data)?;
            writer.finish()
        }

        fn payload_matches(payload: &PacketPayload, expected: &[u8]) -> bool {
            let view = PacketPayloadView::new(payload);
            if view.total_len() != expected.len() {
                return false;
            }

            let mut offset = 0usize;
            let mut matches = true;
            view.for_each_chunk(|chunk| {
                let end = offset + chunk.len();
                if expected.get(offset..end) != Some(chunk) {
                    matches = false;
                }
                offset = end;
            });
            matches && offset == expected.len()
        }

        let Ok(mut conn) = Self::new(super::TlsClientConfig::new()) else {
            return false;
        };
        let key = [0x11; 16];
        let iv = [0x22; 12];
        if Self::set_tls_bytes(&mut conn.record.read_key, &key).is_err()
            || Self::set_tls_bytes(&mut conn.record.write_key, &key).is_err()
            || Self::set_tls_bytes(&mut conn.record.read_iv, &iv).is_err()
            || Self::set_tls_bytes(&mut conn.record.write_iv, &iv).is_err()
        {
            return false;
        }
        let Ok(cipher) = conn
            .config
            .cipher_suites
            .negotiate_wire(CipherSuite::TLS_AES_128_GCM_SHA256.wire())
        else {
            return false;
        };
        conn.negotiation.negotiated = NegotiatedTlsParameters::tls13(cipher);
        conn.negotiation.phase = TlsConnectionPhase::established();

        let Some(alpha) = payload(b"alpha") else {
            return false;
        };
        let Some(beta) = payload(b"beta") else {
            return false;
        };
        let Ok(mut first) = conn.tls13_encrypt_application_payload(alpha) else {
            return false;
        };
        let Ok(second) = conn.tls13_encrypt_application_payload(beta) else {
            return false;
        };
        append_payload(&mut first, second);

        let Ok(plaintext) = conn.process_incoming_payload(first) else {
            return false;
        };
        payload_matches(&plaintext, b"alphabeta") && matches!(conn.record.read_seq.current(), Ok(2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payload(data: &[u8]) -> PacketPayload {
        let mut writer = GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM)
            .expect("test payload allocation succeeds");
        writer
            .write_bytes(data)
            .expect("test payload write succeeds");
        writer.finish().expect("test payload is exact")
    }

    fn payload_matches(payload: &PacketPayload, expected: &[u8]) -> bool {
        let view = PacketPayloadView::new(payload);
        if view.total_len() != expected.len() {
            return false;
        }

        let mut offset = 0;
        let mut matches = true;
        view.for_each_chunk(|chunk| {
            let end = offset + chunk.len();
            if expected.get(offset..end) != Some(chunk) {
                matches = false;
            }
            offset = end;
        });
        matches && offset == expected.len()
    }

    fn establish_loopback_record_keys(conn: &mut TlsConnectionCore) {
        let key = [0x11; 16];
        let iv = [0x22; 12];
        TlsConnectionCore::set_tls_bytes(&mut conn.record.read_key, &key)
            .expect("read key fits");
        TlsConnectionCore::set_tls_bytes(&mut conn.record.write_key, &key)
            .expect("write key fits");
        TlsConnectionCore::set_tls_bytes(&mut conn.record.read_iv, &iv)
            .expect("read iv fits");
        TlsConnectionCore::set_tls_bytes(&mut conn.record.write_iv, &iv)
            .expect("write iv fits");
        conn.negotiation.negotiated = NegotiatedTlsParameters::tls13(
            conn.config
                .cipher_suites
                .negotiate_wire(CipherSuite::TLS_AES_128_GCM_SHA256.wire())
                .expect("default cipher suite is offered"),
        );
        conn.negotiation.phase = TlsConnectionPhase::established();
    }

    #[test]
    fn encrypted_application_records_are_processed_from_one_ingress_payload() {
        let config = super::super::TlsClientConfig::new();
        let mut conn = TlsConnectionCore::new(config)
            .expect("test TLS connection entropy is available");
        establish_loopback_record_keys(&mut conn);

        let mut first = conn
            .tls13_encrypt_application_payload(test_payload(b"alpha"))
            .expect("first record encrypts");
        let second = conn
            .tls13_encrypt_application_payload(test_payload(b"beta"))
            .expect("second record encrypts");
        append_payload(&mut first, second);

        let plaintext = conn
            .process_incoming_payload(first)
            .expect("coalesced encrypted records decrypt");

        assert!(payload_matches(&plaintext, b"alphabeta"));
        assert!(matches!(conn.record.read_seq.current(), Ok(2)));
    }
}
