// ============================================================================
// kernel/src/net/security/tls/connection/record.rs - TLS 1.3 record layer
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
use super::state::SelectedTls13Parameters;
use super::state::{TlsHandshakeProgress, TlsRecordEpoch};
use super::{
    AlertDescription, ContentType, GeneratedPacketWriter, HandshakeType, KeyUpdateRequest,
    PacketPayload, PacketPayloadView, PayloadRange, PayloadSpanMut, PayloadSpanRef, TlsBytes,
    TlsConnectionCore, TlsError, TlsResult, append_payload,
};
use crate::net::security::tls::crypto::aes_gcm::AesGcmKey;
use crate::net::security::tls::crypto::hkdf::{
    hkdf_expand_label, hkdf_expand_label_sha384, tls13_derive_traffic_keys,
    tls13_derive_traffic_keys_sha384,
};
use crate::net::security::tls::crypto::material::{AeadNonce, AeadTag, TlsAeadKey};
use crate::net::security::tls::crypto::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, chacha20_poly1305_tag_chunks,
    chacha20_xor_chunks_in_place,
};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketByteCount};

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
            content_type: ContentType::parse_wire(bytes[0]).ok_or(TlsError::UnexpectedMessage)?,
            body_len: TlsCiphertextLen::new(u16::from_be_bytes([bytes[3], bytes[4]]) as usize)?,
        })
    }

    fn total_len(self) -> TlsResult<PacketByteCount> {
        let total_len = 5usize
            .checked_add(self.body_len.get())
            .ok_or(TlsError::DecodeError)?;
        PacketByteCount::new(total_len).ok_or(TlsError::DecodeError)
    }
}

pub(super) struct TlsRecordPacket {
    payload: PacketPayload,
    header: TlsRecordHeader,
}

pub(super) struct TlsRecordBody<'a> {
    span: PayloadSpanRef<'a>,
}

#[derive(Clone, Copy)]
struct TlsEncryptedRecordBody {
    body: PayloadRange,
    ciphertext: PayloadRange,
    tag: PayloadRange,
}

pub(super) struct TlsEncryptedRecordPayload {
    payload: PacketPayload,
    body: TlsEncryptedRecordBody,
}

impl<'a> TlsRecordBody<'a> {
    const fn span(self) -> PayloadSpanRef<'a> {
        self.span
    }
}

impl TlsEncryptedRecordBody {
    fn from_record_body(
        payload: &PacketPayload,
        body_offset: usize,
        body_len: usize,
    ) -> TlsResult<Self> {
        if body_len < 16 {
            return Err(TlsError::DecodeError);
        }
        let ciphertext_len = body_len - 16;
        let tag_offset = body_offset
            .checked_add(ciphertext_len)
            .ok_or(TlsError::DecodeError)?;
        let body =
            PayloadRange::checked(payload, body_offset, body_len).ok_or(TlsError::DecodeError)?;
        let ciphertext = PayloadRange::checked(payload, body_offset, ciphertext_len)
            .ok_or(TlsError::DecodeError)?;
        let tag = PayloadRange::checked(payload, tag_offset, 16).ok_or(TlsError::DecodeError)?;
        Ok(Self {
            body,
            ciphertext,
            tag,
        })
    }
}

impl TlsEncryptedRecordPayload {
    fn tag(&self) -> TlsResult<AeadTag> {
        Ok(AeadTag::new(
            self.body
                .tag
                .span(&self.payload)
                .ok_or(TlsError::DecodeError)?
                .read_array::<16>(0)
                .ok_or(TlsError::DecodeError)?,
        ))
    }

    fn ciphertext_span(&self) -> TlsResult<PayloadSpanRef<'_>> {
        self.body
            .ciphertext
            .span(&self.payload)
            .ok_or(TlsError::DecryptError)
    }

    fn ciphertext_span_mut(&mut self) -> TlsResult<PayloadSpanMut<'_>> {
        PayloadSpanMut::from_range(&mut self.payload, self.body.ciphertext)
            .ok_or(TlsError::DecryptError)
    }

    fn plaintext_span(&self, inner: Tls13InnerPlaintext) -> TlsResult<PayloadSpanRef<'_>> {
        PayloadRange::checked(&self.payload, self.body.body.offset(), inner.content_len())
            .and_then(|range| PayloadSpanRef::from_range(&self.payload, range))
            .ok_or(TlsError::DecodeError)
    }

    fn into_plaintext_payload(self, inner: Tls13InnerPlaintext) -> TlsResult<PacketPayload> {
        let range =
            PayloadRange::checked(&self.payload, self.body.body.offset(), inner.content_len())
                .ok_or(TlsError::DecodeError)?;
        crate::net::payload::OwnedPayloadWindow::from_range(self.payload, range)
            .and_then(|window| window.into_payload().ok())
            .ok_or(TlsError::DecodeError)
    }
}

impl TlsRecordPacket {
    const HEADER_LEN: usize = 5;

    pub(super) fn ready_len(
        payload: &PacketPayload,
    ) -> TlsResult<Option<kernel_api::resource::net::PacketByteCount>> {
        let view = PacketPayloadView::new(payload);
        if view.total_len() < Self::HEADER_LEN {
            return Ok(None);
        }
        let header = view.read_array::<5>(0).ok_or(TlsError::DecodeError)?;
        let header = TlsRecordHeader::parse(header)?;
        let total_len = header.total_len()?;
        if view.total_len() < total_len.get() {
            return Ok(None);
        }
        Ok(Some(total_len))
    }

    pub(super) fn parse(payload: PacketPayload) -> TlsResult<Self> {
        let view = PacketPayloadView::new(&payload);
        let header = view.read_array::<5>(0).ok_or(TlsError::DecodeError)?;
        let header = TlsRecordHeader::parse(header)?;
        if header.total_len()?.get() != view.total_len() {
            return Err(TlsError::DecodeError);
        }
        Ok(Self { payload, header })
    }

    const fn header(&self) -> TlsRecordHeader {
        self.header
    }

    fn body(&self) -> TlsResult<TlsRecordBody<'_>> {
        let range =
            PayloadRange::checked(&self.payload, Self::HEADER_LEN, self.header.body_len.get())
                .ok_or(TlsError::DecodeError)?;
        let span = PayloadSpanRef::from_range(&self.payload, range).ok_or(TlsError::DecodeError)?;
        Ok(TlsRecordBody { span })
    }

    fn into_payload(self) -> PacketPayload {
        self.payload
    }

    fn into_encrypted_payload(self) -> TlsResult<TlsEncryptedRecordPayload> {
        let body = TlsEncryptedRecordBody::from_record_body(
            &self.payload,
            Self::HEADER_LEN,
            self.header.body_len.get(),
        )?;
        Ok(TlsEncryptedRecordPayload {
            payload: self.payload,
            body,
        })
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

    pub(crate) const fn content_type_wire(self) -> u8 {
        self.content_type as u8
    }

    pub(crate) const fn content_len(self) -> usize {
        self.content_len
    }
}

fn constant_time_tag_eq(a: AeadTag, b: AeadTag) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a.as_bytes()[i] ^ b.as_bytes()[i];
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
        key: TlsAeadKey<'_>,
        nonce: AeadNonce,
        aad: &[u8],
        mut plaintext: PacketPayload,
    ) -> TlsResult<(PacketPayload, AeadTag)> {
        let ciphertext_len = plaintext.total_len();
        let tag = match key {
            TlsAeadKey::ChaCha20Poly1305(key) => {
                let key_arr = *key.as_bytes();
                let mut ciphertext = PayloadSpanMut::whole(&mut plaintext);
                chacha20_xor_chunks_in_place(&key_arr, nonce.as_bytes(), 1, |visitor| {
                    ciphertext.for_each_chunk_mut(|chunk| visitor(chunk));
                });
                let poly_key_block = crate::net::security::tls::crypto::chacha20::chacha20_block(
                    &key_arr,
                    0,
                    nonce.as_bytes(),
                );
                let mut poly_key = [0u8; 32];
                poly_key.copy_from_slice(&poly_key_block[..32]);
                chacha20_poly1305_tag_chunks(&poly_key, aad, ciphertext_len, |visitor| {
                    PayloadSpanRef::from_payload(&plaintext).for_each_chunk(visitor)
                })
                .ok_or(TlsError::CryptoError)?
            }
            TlsAeadKey::Aes128Gcm(key) => {
                let key = AesGcmKey::new(key.as_bytes()).ok_or(TlsError::CryptoError)?;
                let mut ciphertext = PayloadSpanMut::whole(&mut plaintext);
                key.xor_chunks_in_place(nonce.as_bytes(), |visitor| {
                    ciphertext.for_each_chunk_mut(|chunk| visitor(chunk));
                })
                .map_err(|_| TlsError::CryptoError)?;
                key.tag_for_ciphertext_chunks(nonce.as_bytes(), aad, ciphertext_len, |visitor| {
                    PayloadSpanRef::from_payload(&plaintext).for_each_chunk(visitor)
                })
                .map_err(|_| TlsError::CryptoError)?
            }
            TlsAeadKey::Aes256Gcm(key) => {
                let key = AesGcmKey::new(key.as_bytes()).ok_or(TlsError::CryptoError)?;
                let mut ciphertext = PayloadSpanMut::whole(&mut plaintext);
                key.xor_chunks_in_place(nonce.as_bytes(), |visitor| {
                    ciphertext.for_each_chunk_mut(|chunk| visitor(chunk));
                })
                .map_err(|_| TlsError::CryptoError)?;
                key.tag_for_ciphertext_chunks(nonce.as_bytes(), aad, ciphertext_len, |visitor| {
                    PayloadSpanRef::from_payload(&plaintext).for_each_chunk(visitor)
                })
                .map_err(|_| TlsError::CryptoError)?
            }
        };
        Ok((plaintext, AeadTag::new(tag)))
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
        self.negotiation.progress.reads_handshake_records()
    }

    pub(super) fn decrypt_tls13_record_payload(
        &mut self,
        encrypted: &mut TlsEncryptedRecordPayload,
    ) -> TlsResult<Tls13InnerPlaintext> {
        let cipher = self.negotiation.selected()?.cipher().cipher();
        let record_len = encrypted.body.body.total_len();
        let ciphertext_len = encrypted.body.ciphertext.total_len();
        let tag = encrypted.tag()?;

        let (key, iv, seq, epoch) = if self.tls13_reads_handshake_records() {
            (
                &self.tls13.hs_read_key,
                &self.tls13.hs_read_iv,
                self.tls13.hs_read_seq.current()?,
                TlsRecordEpoch::Handshake,
            )
        } else {
            (
                &self.record.read_key,
                &self.record.read_iv,
                self.record.read_seq.current()?,
                TlsRecordEpoch::Application,
            )
        };
        if key.is_empty() || iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let aead_key = TlsAeadKey::from_cipher_suite(cipher, key.as_slice())?;
        let (nonce, aad) = Self::build_tls13_nonce_and_aad(iv.as_slice(), seq, record_len)?;
        if let TlsAeadKey::ChaCha20Poly1305(key) = aead_key {
            let key_arr = *key.as_bytes();
            let poly_key_block = crate::net::security::tls::crypto::chacha20::chacha20_block(
                &key_arr,
                0,
                nonce.as_bytes(),
            );
            let mut poly_key = [0u8; 32];
            poly_key.copy_from_slice(&poly_key_block[..32]);
            let expected =
                chacha20_poly1305_tag_chunks(&poly_key, &aad, ciphertext_len, |visitor| {
                    encrypted
                        .ciphertext_span()
                        .expect("validated TLS ciphertext bounds")
                        .for_each_chunk(visitor)
                })
                .ok_or(TlsError::DecryptError)?;
            if !constant_time_tag_eq(AeadTag::new(expected), tag) {
                return Err(TlsError::DecryptError);
            }
            let mut ciphertext = encrypted.ciphertext_span_mut()?;
            chacha20_xor_chunks_in_place(&key_arr, nonce.as_bytes(), 1, |visitor| {
                ciphertext.for_each_chunk_mut(|chunk| visitor(chunk));
            });
        } else {
            let key = match aead_key {
                TlsAeadKey::Aes128Gcm(key) => AesGcmKey::new(key.as_bytes()),
                TlsAeadKey::Aes256Gcm(key) => AesGcmKey::new(key.as_bytes()),
                TlsAeadKey::ChaCha20Poly1305(_) => None,
            }
            .ok_or(TlsError::CryptoError)?;
            key.verify_ciphertext_chunks(
                nonce.as_bytes(),
                &aad,
                ciphertext_len,
                |visitor| {
                    encrypted
                        .ciphertext_span()
                        .expect("validated TLS ciphertext bounds")
                        .for_each_chunk(visitor)
                },
                tag.as_bytes(),
            )
            .map_err(|_| TlsError::DecryptError)?;
            let mut ciphertext = encrypted.ciphertext_span_mut()?;
            key.xor_chunks_in_place(nonce.as_bytes(), |visitor| {
                ciphertext.for_each_chunk_mut(|chunk| visitor(chunk));
            })
            .map_err(|_| TlsError::DecryptError)?;
        }

        if epoch == TlsRecordEpoch::Handshake {
            self.tls13.hs_read_seq.advance()?;
        } else {
            self.record.read_seq.advance()?;
        }
        let decrypted = encrypted.ciphertext_span()?;
        Self::tls13_split_content_type_span(decrypted).ok_or(TlsError::DecodeError)
    }

    pub(super) fn consume_tls_record_payload(
        &mut self,
        record: TlsRecordPacket,
        plaintext: &mut PacketPayload,
    ) -> TlsResult<()> {
        let header = record.header();

        match header.content_type {
            ContentType::Handshake => self.process_handshake(record.body()?.span())?,
            ContentType::Alert => self.handle_alert_payload(record.body()?.span())?,
            ContentType::ApplicationData => {
                let mut encrypted = record.into_encrypted_payload()?;
                let inner = self.decrypt_tls13_record_payload(&mut encrypted)?;
                match inner.content_type() {
                    ContentType::ApplicationData => {
                        let owned = encrypted.into_plaintext_payload(inner)?;
                        append_payload(plaintext, owned);
                    }
                    ContentType::Handshake => {
                        let inner_span = encrypted.plaintext_span(inner)?;
                        if self.negotiation.progress.is_established() {
                            self.tls13_process_post_handshake(inner_span)?;
                        } else {
                            self.process_handshake(inner_span)?;
                        }
                    }
                    ContentType::Alert => {
                        let inner_span = encrypted.plaintext_span(inner)?;
                        self.handle_alert_payload(inner_span)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn process_incoming_payload(&mut self, payload: PacketPayload) -> TlsResult<PacketPayload> {
        self.record.ingress.push(payload);
        let mut plaintext = PacketPayload::default();

        loop {
            let Some(record) = self.record.ingress.pop_ready_record()? else {
                break;
            };
            self.consume_tls_record_payload(record, &mut plaintext)?;
        }
        Ok(plaintext)
    }

    pub(super) fn handle_alert_payload(&mut self, payload: PayloadSpanRef<'_>) -> TlsResult<()> {
        if payload.total_len() != 2 {
            return Err(TlsError::DecodeError);
        }
        let description_wire = payload.read_u8(1).ok_or(TlsError::DecodeError)?;
        match AlertDescription::parse_wire(description_wire) {
            Some(AlertDescription::CloseNotify) => {
                self.negotiation.progress = TlsHandshakeProgress::Closed;
            }
            None => {
                self.negotiation.progress = TlsHandshakeProgress::Failed;
                return Err(TlsError::Alert(description_wire));
            }
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
                    let range = PayloadRange::checked(&decrypted, 0, inner.content_len())
                        .ok_or(TlsError::DecodeError)?;
                    let inner_payload =
                        crate::net::payload::OwnedPayloadWindow::from_range(decrypted, range)
                            .and_then(|window| window.into_payload().ok())
                            .ok_or(TlsError::DecodeError)?;
                    append_payload(plaintext, inner_payload);
                }
                ContentType::Handshake => {
                    let range = PayloadRange::checked(&decrypted, 0, inner.content_len())
                        .ok_or(TlsError::DecodeError)?;
                    let inner_payload =
                        crate::net::payload::OwnedPayloadWindow::from_range(decrypted, range)
                            .and_then(|window| window.into_payload().ok())
                            .ok_or(TlsError::DecodeError)?;
                    if self.negotiation.progress.is_established() {
                        let inner_data = PayloadSpanRef::from_payload(&inner_payload);
                        self.tls13_process_post_handshake(inner_data)?;
                    } else {
                        self.process_handshake(PayloadSpanRef::from_payload(&inner_payload))?;
                    }
                }
                ContentType::Alert => {
                    let range = PayloadRange::checked(&decrypted, 0, inner.content_len())
                        .ok_or(TlsError::DecodeError)?;
                    let inner_payload =
                        crate::net::payload::OwnedPayloadWindow::from_range(decrypted, range)
                            .and_then(|window| window.into_payload().ok())
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
    ) -> TlsResult<(AeadNonce, [u8; 5])> {
        Ok((
            AeadNonce::from_iv_and_sequence(iv, seq)?,
            Self::tls13_record_aad(data_len),
        ))
    }

    pub(super) fn tls13_encrypt_record(
        &mut self,
        inner_plaintext: &[u8],
        epoch: TlsRecordEpoch,
    ) -> TlsResult<PacketPayload> {
        let mut writer = GeneratedPacketWriter::new(inner_plaintext.len(), DEFAULT_PACKET_HEADROOM)
            .ok_or(TlsError::DecodeError)?;
        writer
            .write_bytes(inner_plaintext)
            .ok_or(TlsError::DecodeError)?;
        let payload = writer.finish().ok_or(TlsError::DecodeError)?;
        self.tls13_encrypt_owned_inner(payload, epoch)
    }

    pub(super) fn tls13_encrypt_owned_inner(
        &mut self,
        inner_plaintext: PacketPayload,
        epoch: TlsRecordEpoch,
    ) -> TlsResult<PacketPayload> {
        let plaintext_len = TlsPlaintextLen::new(inner_plaintext.total_len())?.get();
        let cipher = self.negotiation.selected()?.cipher().cipher();
        let (key, iv, seq) = if epoch == TlsRecordEpoch::Handshake {
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

        let encrypted_len = TlsCiphertextLen::new(plaintext_len + 16)?.get();
        let aead_key = TlsAeadKey::from_cipher_suite(cipher, key.as_slice())?;
        let (nonce, aad) = Self::build_tls13_nonce_and_aad(iv.as_slice(), seq, encrypted_len)?;
        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload_owned(aead_key, nonce, &aad, inner_plaintext)?;

        if epoch == TlsRecordEpoch::Handshake {
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
            .write_bytes(auth_tag.as_bytes())
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
        self.tls13_encrypt_owned_inner(payload, TlsRecordEpoch::Application)
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
                return Some(Tls13InnerPlaintext::new(ContentType::parse_wire(byte)?, i));
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
        let request_update =
            KeyUpdateRequest::parse_wire(data.read_u8(0).ok_or(TlsError::DecodeError)?)
                .ok_or(TlsError::DecodeError)?;
        let cipher = self.negotiation.selected()?.cipher().cipher();
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
            hkdf_expand_label_sha384(
                &old_secret,
                b"traffic upd",
                b"",
                &mut new_server_secret[..hash_len],
            );
        } else {
            let mut old_secret = [0u8; 32];
            old_secret.copy_from_slice(&self.tls13.server_app_traffic_secret[..32]);
            hkdf_expand_label(
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

        if matches!(request_update, KeyUpdateRequest::UpdateRequested) {
            self.tls13.key_update_response.require();
        }
        Ok(())
    }

    pub(super) fn take_key_update_response_payload(&mut self) -> TlsResult<Option<PacketPayload>> {
        if !self.tls13.key_update_response.take_required() {
            return Ok(None);
        }
        if !self.negotiation.progress.is_established() {
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
        Ok(Some(self.tls13_encrypt_record(
            &inner,
            TlsRecordEpoch::Application,
        )?))
    }

    pub(super) fn send_close_notify(&mut self) -> TlsResult<PacketPayload> {
        if self.record.write_key.is_empty() {
            return Err(TlsError::NotConnected);
        }
        let inner = [
            1,
            AlertDescription::CloseNotify.wire(),
            ContentType::Alert as u8,
        ];
        let record = self.tls13_encrypt_record(&inner, TlsRecordEpoch::Application)?;
        self.negotiation.progress = TlsHandshakeProgress::Closing(self.negotiation.selected()?);
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

        let Ok(config) = crate::net::security::tls::TlsClientConfig::for_server_name(
            "example.com",
            crate::net::security::tls::TlsTrustAnchors::empty(),
        ) else {
            return false;
        };
        let Ok(mut conn) = Self::new(config) else {
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
            .negotiate_wire(crate::net::security::tls::CipherSuite::TLS_AES_128_GCM_SHA256.wire())
        else {
            return false;
        };
        conn.negotiation.progress =
            TlsHandshakeProgress::Established(SelectedTls13Parameters::new(cipher));

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
    use alloc::vec::Vec;
    use kernel_api::resource::net::PacketChain;

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

    fn single_packet_payload_from_payloads(payloads: &[&PacketPayload]) -> PacketPayload {
        let total_len = payloads.iter().map(|payload| payload.total_len()).sum();
        let mut writer = GeneratedPacketWriter::new(total_len, DEFAULT_PACKET_HEADROOM)
            .expect("test coalesced packet allocation succeeds");
        for payload in payloads {
            PacketPayloadView::new(payload).for_each_chunk(|chunk| {
                writer
                    .write_bytes(chunk)
                    .expect("test coalesced packet write succeeds");
            });
        }
        writer.finish().expect("test coalesced packet is exact")
    }

    fn collect_payload_bytes(payload: &PacketPayload, bytes: &mut Vec<u8>) {
        PacketPayloadView::new(payload).for_each_chunk(|chunk| {
            bytes.extend_from_slice(chunk);
        });
    }

    fn fragmented_payload_from_bytes(bytes: &[u8], cuts: &[usize]) -> PacketPayload {
        let mut start = 0usize;
        let mut segments = Vec::new();
        for &cut in cuts {
            assert!(start < cut && cut <= bytes.len());
            segments.extend(test_payload(&bytes[start..cut]).into_segments());
            start = cut;
        }
        if start < bytes.len() {
            segments.extend(test_payload(&bytes[start..]).into_segments());
        }
        PacketPayload::chain(PacketChain::from_segments(segments))
    }

    fn establish_loopback_record_keys(conn: &mut TlsConnectionCore) {
        let key = [0x11; 16];
        let iv = [0x22; 12];
        TlsConnectionCore::set_tls_bytes(&mut conn.record.read_key, &key).expect("read key fits");
        TlsConnectionCore::set_tls_bytes(&mut conn.record.write_key, &key).expect("write key fits");
        TlsConnectionCore::set_tls_bytes(&mut conn.record.read_iv, &iv).expect("read iv fits");
        TlsConnectionCore::set_tls_bytes(&mut conn.record.write_iv, &iv).expect("write iv fits");
        let selected = SelectedTls13Parameters::new(
            conn.config
                .cipher_suites
                .negotiate_wire(
                    crate::net::security::tls::CipherSuite::TLS_AES_128_GCM_SHA256.wire(),
                )
                .expect("default cipher suite is offered"),
        );
        conn.negotiation.progress = TlsHandshakeProgress::Established(selected);
    }

    #[test]
    fn encrypted_application_records_are_processed_from_one_ingress_payload() {
        let config = super::super::TlsClientConfig::for_server_name(
            "example.com",
            super::super::TlsTrustAnchors::empty(),
        )
        .expect("test server name fits");
        let mut conn =
            TlsConnectionCore::new(config).expect("test TLS connection entropy is available");
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

    #[test]
    fn encrypted_records_inside_one_packet_ref_split_without_copy_fallback() {
        let config = super::super::TlsClientConfig::for_server_name(
            "example.com",
            super::super::TlsTrustAnchors::empty(),
        )
        .expect("test server name fits");
        let mut conn =
            TlsConnectionCore::new(config).expect("test TLS connection entropy is available");
        establish_loopback_record_keys(&mut conn);

        let first = conn
            .tls13_encrypt_application_payload(test_payload(b"alpha"))
            .expect("first record encrypts");
        let second = conn
            .tls13_encrypt_application_payload(test_payload(b"beta"))
            .expect("second record encrypts");
        let coalesced = single_packet_payload_from_payloads(&[&first, &second]);

        let plaintext = conn
            .process_incoming_payload(coalesced)
            .expect("same-packet records split through PacketPayload::take_front");

        assert!(payload_matches(&plaintext, b"alphabeta"));
        assert!(matches!(conn.record.read_seq.current(), Ok(2)));
    }

    #[test]
    fn encrypted_record_body_and_tag_windows_cross_packet_segments() {
        let config = super::super::TlsClientConfig::for_server_name(
            "example.com",
            super::super::TlsTrustAnchors::empty(),
        )
        .expect("test server name fits");
        let mut conn =
            TlsConnectionCore::new(config).expect("test TLS connection entropy is available");
        establish_loopback_record_keys(&mut conn);

        let encrypted = conn
            .tls13_encrypt_application_payload(test_payload(b"segmented-window"))
            .expect("record encrypts");
        let mut bytes = Vec::new();
        collect_payload_bytes(&encrypted, &mut bytes);
        assert!(bytes.len() > 24);
        let fragmented = fragmented_payload_from_bytes(&bytes, &[6, bytes.len() - 8]);

        let plaintext = conn
            .process_incoming_payload(fragmented)
            .expect("segmented body and tag decrypt");

        assert!(payload_matches(&plaintext, b"segmented-window"));
        assert!(matches!(conn.record.read_seq.current(), Ok(1)));
    }
}
