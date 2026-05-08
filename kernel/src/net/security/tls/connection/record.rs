// ============================================================================
// kernel/src/net/security/tls/connection/record.rs - セキュリティ / TLS / 接続 / レコード処理
// ============================================================================

use super::{
    AlertDescription, AlertLevel, CipherSuite, ContentType, PacketPayload, PacketPayloadView,
    PayloadRange, PayloadSpanRef, SessionTicket, TlsBytes, TlsConnection, TlsError, TlsResult,
    TlsState, append_payload,
};
use crate::net::security::tls::crypto::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, aes_gcm_decrypt_into, aes_gcm_encrypt_into,
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place, hkdf_expand_label,
    hkdf_expand_label_sha384, tls13_derive_traffic_keys, tls13_derive_traffic_keys_sha384,
};

impl TlsConnection {
    pub(super) fn set_tls_bytes<const N: usize>(
        slot: &mut TlsBytes<N>,
        data: &[u8],
    ) -> TlsResult<()> {
        slot.set(data).ok_or(TlsError::DecodeError)
    }

    pub(super) fn tls12_aad(seq: u64, content_type: u8, len: usize) -> [u8; 13] {
        let seq_bytes = seq.to_be_bytes();
        let len_bytes = (len as u16).to_be_bytes();
        [
            seq_bytes[0],
            seq_bytes[1],
            seq_bytes[2],
            seq_bytes[3],
            seq_bytes[4],
            seq_bytes[5],
            seq_bytes[6],
            seq_bytes[7],
            content_type,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ]
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

    pub(super) fn encrypt_aead_payload(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> TlsResult<(kernel_api::resource::net::PacketPayload, [u8; 16])> {
        let mut packet = crate::net::payload::alloc_packet_with_headroom(plaintext.len(), 0)
            .ok_or(TlsError::DecodeError)?;
        if !plaintext.is_empty() {
            packet.data_mut()[..plaintext.len()].copy_from_slice(plaintext);
        }
        let mut tag = [0u8; 16];
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_encrypt_in_place(
                &key_arr,
                nonce,
                aad,
                &mut packet.data_mut()[..plaintext.len()],
                &mut tag,
            );
        } else {
            aes_gcm_encrypt_into(
                key,
                nonce,
                aad,
                plaintext,
                &mut packet.data_mut()[..plaintext.len()],
                &mut tag,
            )
            .map_err(|_| TlsError::CryptoError)?;
        }
        Ok((PacketPayload::single(packet), tag))
    }

    pub(super) fn decrypt_aead_payload(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let mut packet = crate::net::payload::alloc_packet_with_headroom(ciphertext.len(), 0)
            .ok_or(TlsError::DecodeError)?;
        if !ciphertext.is_empty() {
            packet.data_mut()[..ciphertext.len()].copy_from_slice(ciphertext);
        }
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_decrypt_in_place(
                &key_arr,
                nonce,
                aad,
                &mut packet.data_mut()[..ciphertext.len()],
                tag,
            )
            .map_err(|_| TlsError::DecryptError)?;
        } else {
            aes_gcm_decrypt_into(
                key,
                nonce,
                aad,
                ciphertext,
                &mut packet.data_mut()[..ciphertext.len()],
                tag,
            )
            .map_err(|_| TlsError::DecryptError)?;
        }
        Ok(PacketPayload::single(packet))
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

    pub(super) fn append_transcript_parts(&mut self, parts: &[&[u8]]) -> TlsResult<()> {
        for part in parts {
            if !part.is_empty() {
                self.transcript.update(part);
            }
        }
        Ok(())
    }

    pub(super) fn replace_transcript_bytes(&mut self, data: &[u8]) -> TlsResult<()> {
        self.transcript.set_bytes(data);
        Ok(())
    }

    pub(super) fn transcript_hash_sha256(&self) -> [u8; SHA256_OUTPUT_SIZE] {
        self.transcript.current_sha256()
    }

    pub(super) fn transcript_hash_sha384(&self) -> [u8; SHA384_OUTPUT_SIZE] {
        self.transcript.current_sha384()
    }

    /// Decide whether incoming TLS 1.3 ApplicationData should be decrypted
    /// with handshake traffic keys or application traffic keys.
    pub(super) fn tls13_reads_handshake_records(&self) -> bool {
        matches!(
            self.negotiation.state,
            TlsState::Tls13WaitEncryptedExtensions
                | TlsState::Tls13WaitCertificate
                | TlsState::Tls13WaitCertificateVerify
                | TlsState::Tls13WaitFinished
                | TlsState::Tls13ServerFinishedReceived
        )
    }

    /// Decrypt a TLS 1.3 record body (ciphertext || tag) and advance read sequence.
    pub(super) fn decrypt_tls13_record_payload(
        &mut self,
        payload: &PacketPayload,
    ) -> TlsResult<PacketPayload> {
        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let data = Self::contiguous_payload_bytes(payload).ok_or(TlsError::DecodeError)?;
        if data.len() < 16 {
            return Err(TlsError::DecodeError);
        }

        let (key, iv, seq, is_handshake) = if self.tls13_reads_handshake_records() {
            (
                &self.tls13.hs_read_key,
                &self.tls13.hs_read_iv,
                self.tls13.hs_read_seq,
                true,
            )
        } else {
            (
                &self.record.read_key,
                &self.record.read_iv,
                self.record.read_seq,
                false,
            )
        };
        if key.is_empty() || iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let ciphertext_len = data.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[ciphertext_len..]);
        let (nonce, aad) = Self::build_tls13_nonce_and_aad(iv.as_slice(), seq, data.len());
        let plaintext = Self::decrypt_aead(
            cipher,
            key.as_slice(),
            &nonce,
            &aad,
            &data[..ciphertext_len],
            &tag,
        )?;

        if is_handshake {
            self.tls13.hs_read_seq = self.tls13.hs_read_seq.saturating_add(1);
        } else {
            self.record.read_seq = self.record.read_seq.saturating_add(1);
        }
        Ok(plaintext)
    }

    /// Consume one full TLS record (header + body) and dispatch by content type.
    pub(super) fn consume_tls_record_payload(
        &mut self,
        record: PacketPayload,
        plaintext: &mut PacketPayload,
    ) -> TlsResult<()> {
        let record_span = PayloadSpanRef::from_payload(&record);
        let header = record_span
            .read_array::<5>(0)
            .ok_or(TlsError::DecodeError)?;
        let content_type = header[0];
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let _body_range = record_span
            .slice(5, record_len)
            .ok_or(TlsError::DecodeError)?;
        let body = crate::net::payload::retain_payload_window_owned(record, 5, record_len)
            .ok_or(TlsError::DecodeError)?;

        match ContentType::from_u8(content_type) {
            Some(ContentType::Handshake) => {
                self.process_handshake(body)?;
            }
            Some(ContentType::Alert) => {
                self.handle_alert_payload(&body)?;
            }
            Some(ContentType::ChangeCipherSpec) => {
                // TLS 1.2 read-side encryption becomes active after CCS.
                self.record.read_encryption_active = true;
            }
            Some(ContentType::ApplicationData) if self.negotiation.is_tls13 => {
                // TLS 1.3: encrypted inner content is further dispatched by inner type.
                let decrypted = self.decrypt_tls13_record_payload(&body)?;
                self.dispatch_tls13_inner_content(decrypted, plaintext)?;
            }
            Some(ContentType::ApplicationData) => {
                // TLS 1.2: decrypt and append plaintext application payload.
                let bytes = Self::contiguous_payload_bytes(&body).ok_or(TlsError::DecodeError)?;
                let decrypted = if self
                    .negotiation
                    .negotiated_cipher
                    .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256)
                    .is_chacha20_poly1305()
                {
                    self.decrypt_chacha20_poly1305(bytes, content_type)?
                } else {
                    self.decrypt_aes_gcm(bytes, content_type)?
                };
                append_payload(plaintext, decrypted);
            }
            _ => {}
        }

        Ok(())
    }

    pub fn process_incoming_payload(&mut self, payload: PacketPayload) -> TlsResult<PacketPayload> {
        append_payload(&mut self.record.recv_buffer, payload);
        let mut plaintext = PacketPayload::default();

        loop {
            let view = PacketPayloadView::new(&self.record.recv_buffer);
            if view.total_len() < 5 {
                break;
            }

            let header = view.read_array::<5>(0).ok_or(TlsError::DecodeError)?;
            let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let total_len = 5usize.saturating_add(record_len);
            if view.total_len() < total_len {
                break;
            }

            let recv_buffer = core::mem::take(&mut self.record.recv_buffer);
            let (record, remainder) =
                crate::net::payload::split_payload_prefix_owned(recv_buffer, total_len)
                    .ok_or(TlsError::DecodeError)?;
            self.record.recv_buffer = remainder;
            self.consume_tls_record_payload(record, &mut plaintext)?;
        }

        Ok(plaintext)
    }
    pub(super) fn handle_alert_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<()> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() >= 2 {
            let description = view.read_u8(1).ok_or(TlsError::DecodeError)?;
            if description == AlertDescription::CloseNotify as u8 {
                self.negotiation.state = TlsState::Closed;
            } else {
                self.negotiation.state = TlsState::Error;
                return Err(TlsError::Alert(description));
            }
        }
        Ok(())
    }

    /// TLS 1.3復号後の内部コンテントタイプを処理する
    pub(super) fn dispatch_tls13_inner_content(
        &mut self,
        decrypted: kernel_api::resource::net::PacketPayload,
        plaintext: &mut kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<()> {
        if let Some((inner_ct, inner_len)) = Self::tls13_split_content_type_payload(&decrypted) {
            match ContentType::from_u8(inner_ct) {
                Some(ContentType::ApplicationData) => {
                    let inner_payload =
                        crate::net::payload::retain_payload_window_owned(decrypted, 0, inner_len)
                            .ok_or(TlsError::DecodeError)?;
                    crate::net::payload::append_payload(plaintext, inner_payload);
                }
                Some(ContentType::Handshake) => {
                    let inner_data =
                        crate::net::payload::PayloadSpanRef::from_range(&decrypted, 0, inner_len)
                            .ok_or(TlsError::DecodeError)?;
                    // Post-handshake: NewSessionTicket, KeyUpdate
                    self.tls13_process_post_handshake(inner_data)?;
                }
                Some(ContentType::Alert) => {
                    let inner_payload =
                        crate::net::payload::retain_payload_window_owned(decrypted, 0, inner_len)
                            .ok_or(TlsError::DecodeError)?;
                    self.handle_alert_payload(&inner_payload)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl TlsConnection {
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

    pub(super) fn decrypt_aead(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        Self::decrypt_aead_payload(cipher, key, nonce, aad, ciphertext, tag)
    }

    /// TLS 1.3: レコード復号
    ///
    /// TLS 1.3のAEAD nonce = IV XOR seq_num
    /// AAD = TLS record header（5バイト: type || legacy_version || length）
    ///
    /// `is_handshake`: trueの場合ハンドシェイク鍵、falseの場合アプリケーション鍵を使用
    /// TLS 1.3: レコード暗号化
    ///
    /// inner_plaintext = content || content_type
    /// encrypted = AEAD-Encrypt(key, nonce, aad, inner_plaintext)
    /// record = header || encrypted || tag
    pub(super) fn tls13_encrypt_record(
        &mut self,
        inner_plaintext: &[u8],
        is_handshake: bool,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let (key, iv, seq) = if is_handshake {
            (
                &self.tls13.hs_write_key,
                &self.tls13.hs_write_iv,
                self.tls13.hs_write_seq,
            )
        } else {
            (
                &self.record.write_key,
                &self.record.write_iv,
                self.record.write_seq,
            )
        };

        if key.is_empty() || iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        // TLS 1.3 nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv.as_slice()[..12]);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // 暗号文 + タグの長さ
        let encrypted_len = inner_plaintext.len() + 16;

        // AAD: TLS record header
        let aad = Self::tls13_record_aad(encrypted_len);

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, key.as_slice(), &nonce, &aad, inner_plaintext)?;

        // TLS record
        let encrypted_len_bytes = (encrypted_len as u16).to_be_bytes();
        let record_header = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            encrypted_len_bytes[0],
            encrypted_len_bytes[1],
        ];

        // シーケンス番号をインクリメント
        if is_handshake {
            self.tls13.hs_write_seq += 1;
        } else {
            self.record.write_seq += 1;
        }

        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        builder.push_payload(ciphertext);
        builder.push_bytes(&auth_tag).ok_or(TlsError::DecodeError)?;
        Ok(builder.build())
    }

    /// TLS 1.3 アプリケーションデータ暗号化
    pub(crate) fn tls13_encrypt_application_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let payload_view = crate::net::payload::PacketPayloadView::new(payload);
        let mut inner =
            crate::net::payload::alloc_packet_with_headroom(payload_view.total_len() + 1, 0)
                .ok_or(TlsError::DecodeError)?;
        let mut copied = 0usize;
        payload_view.for_each_chunk(|chunk| {
            let take = chunk.len().min(payload_view.total_len() - copied);
            inner.data_mut()[copied..copied + take].copy_from_slice(&chunk[..take]);
            copied += take;
        });
        if copied != payload_view.total_len() {
            return Err(TlsError::DecodeError);
        }
        inner.data_mut()[payload_view.total_len()] = ContentType::ApplicationData as u8;
        self.tls13_encrypt_record(&inner.data()[..payload_view.total_len() + 1], false)
    }
    /// レコードを復号
    /// AES-GCM record decryption (TLS 1.2)
    pub(super) fn decrypt_aes_gcm(
        &mut self,
        data: &[u8],
        content_type: u8,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        // レコード構造:
        // - explicit_nonce (8 bytes, TLS 1.2)
        // - ciphertext (variable)
        // - auth_tag (16 bytes)

        if data.len() < 24 {
            // 最小: nonce(8) + tag(16)
            return Err(TlsError::DecodeError);
        }

        // Nonce: implicit_iv (4 bytes from key derivation) || explicit_nonce (8 bytes from record)
        let explicit_nonce = &data[0..8];
        let ciphertext_with_tag = &data[8..];

        if ciphertext_with_tag.len() < 16 {
            return Err(TlsError::DecryptError);
        }

        let ciphertext_len = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[0..ciphertext_len];
        let auth_tag = &ciphertext_with_tag[ciphertext_len..];

        // SECURITY: key 未設定時は安全側に倒して失敗させる。
        // Returning ciphertext as plaintext allows injection attacks!
        if self.record.read_key.is_empty() || self.record.read_iv.len() < 4 {
            return Err(TlsError::DecryptError);
        }

        // 12バイトのnonceを構築: implicit_iv(4) || explicit_nonce(8)
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.record.read_iv.as_slice()[0..4]);
        nonce[4..12].copy_from_slice(explicit_nonce);

        // AAD: seq_num(8) || type(1) || version(2) || length(2)
        let aad = Self::tls12_aad(self.record.read_seq, content_type, ciphertext_len);

        // 認証タグを配列に変換
        let mut tag = [0u8; 16];
        tag.copy_from_slice(auth_tag);

        // AES-GCM復号
        let plaintext = Self::decrypt_aead_payload(
            cipher,
            self.record.read_key.as_slice(),
            &nonce,
            &aad,
            ciphertext,
            &tag,
        )?;
        self.record.read_seq += 1;
        Ok(plaintext)
    }

    /// ChaCha20-Poly1305 record decryption (RFC 7905 for TLS 1.2, RFC 8446 for TLS 1.3)
    ///
    /// Record format for ChaCha20-Poly1305 in TLS 1.2 (RFC 7905):
    /// - No explicit nonce in the record (unlike AES-GCM)
    /// - ciphertext (variable length)
    /// - auth_tag (16 bytes)
    ///
    /// Nonce construction (RFC 7905 Section 2):
    /// - Write the sequence number as a 64-bit big-endian value, left-padded with zeros to 12 bytes
    /// - XOR with the IV from key derivation (12 bytes)
    pub(super) fn decrypt_chacha20_poly1305(
        &mut self,
        data: &[u8],
        content_type: u8,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        if data.len() < 16 {
            // Minimum: tag(16), no ciphertext is allowed (empty message)
            return Err(TlsError::DecodeError);
        }

        let ciphertext_len = data.len() - 16;
        let ciphertext = &data[0..ciphertext_len];
        let auth_tag = &data[ciphertext_len..];

        // Keys not set — return error (decryption requires valid keys)
        if self.record.read_key.is_empty()
            || self.record.read_key.len() < 32
            || self.record.read_iv.len() < 12
        {
            return Err(TlsError::CryptoError);
        }

        // Construct 12-byte nonce: IV XOR (zero-padded sequence number)
        // RFC 7905: nonce = iv XOR pad64(seq_num)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.record.read_iv.as_slice()[0..12]);
        let seq_bytes = self.record.read_seq.to_be_bytes(); // 8 bytes
        // XOR seq_num into the last 8 bytes of the nonce
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // AAD: seq_num(8) || type(1) || version(2) || length(2)
        let aad = Self::tls12_aad(self.record.read_seq, content_type, ciphertext_len);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(auth_tag);

        let plaintext = Self::decrypt_aead_payload(
            cipher,
            self.record.read_key.as_slice(),
            &nonce,
            &aad,
            ciphertext,
            &tag,
        )?;
        self.record.read_seq += 1;
        Ok(plaintext)
    }
}

// Building block: TLS encrypt/decrypt

impl TlsConnection {
    /// データを暗号化して送信
    ///
    /// Dispatches between TLS 1.3 record layer and TLS 1.2 cipher suites.
    pub fn encrypt(&mut self, data: &[u8]) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        // TLS 1.3: inner content type付きでAEAD暗号化
        if self.negotiation.is_tls13 {
            if self.negotiation.state != TlsState::Established
                && self.negotiation.state != TlsState::Handshaking
            {
                return Err(TlsError::NotConnected);
            }
            let mut inner_plaintext = TlsBytes::<16384>::new();
            inner_plaintext
                .append_slice(data)
                .ok_or(TlsError::DecodeError)?;
            inner_plaintext
                .push_byte(ContentType::ApplicationData as u8)
                .ok_or(TlsError::DecodeError)?;
            return self.tls13_encrypt_record(inner_plaintext.as_slice(), false);
        }

        // TLS 1.2
        if !self.record.write_encryption_active && self.negotiation.state != TlsState::Established {
            return Err(TlsError::NotConnected);
        }

        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_poly1305(data, ContentType::ApplicationData as u8)
        } else {
            self.encrypt_aes_gcm(data, ContentType::ApplicationData as u8)
        }
    }

    /// AES-GCM record encryption (TLS 1.2)
    ///
    /// Record structure:
    /// - content_type (1 byte) + version (2 bytes) + length (2 bytes)
    /// - explicit_nonce (8 bytes)
    /// - ciphertext (same length as plaintext)
    /// - auth_tag (16 bytes)
    pub(super) fn encrypt_aes_gcm(
        &mut self,
        data: &[u8],
        content_type: u8,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let explicit_nonce = self.record.write_seq.to_be_bytes();

        // Keys not set — return error (encryption requires valid keys)
        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        let (ciphertext, auth_tag) =
            if self.record.write_key.is_empty() || self.record.write_iv.len() < 4 {
                return Err(TlsError::CryptoError);
            } else {
                // 12-byte nonce: implicit_iv(4) || explicit_nonce(8)
                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(&self.record.write_iv.as_slice()[0..4]);
                nonce[4..12].copy_from_slice(&explicit_nonce);

                // AAD: seq_num(8) || type(1) || version(2) || length(2)
                let aad = Self::tls12_aad(self.record.write_seq, content_type, data.len());

                Self::encrypt_aead_payload(
                    cipher,
                    self.record.write_key.as_slice(),
                    &nonce,
                    &aad,
                    data,
                )?
            };

        // Record length: nonce(8) + ciphertext + tag(16)
        let record_len = 8 + ciphertext.total_len() + 16;

        let record_header = [
            content_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];

        self.record.write_seq += 1;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        builder
            .push_bytes(&explicit_nonce)
            .ok_or(TlsError::DecodeError)?;
        builder.push_payload(ciphertext);
        builder.push_bytes(&auth_tag).ok_or(TlsError::DecodeError)?;
        Ok(builder.build())
    }

    /// ChaCha20-Poly1305 record encryption (RFC 7905 for TLS 1.2)
    ///
    /// Record structure (no explicit nonce in ChaCha20-Poly1305):
    /// - content_type (1 byte) + version (2 bytes) + length (2 bytes)
    /// - ciphertext (same length as plaintext)
    /// - auth_tag (16 bytes)
    ///
    /// Nonce: IV XOR zero-padded sequence number (RFC 7905 Section 2)
    pub(super) fn encrypt_chacha20_poly1305(
        &mut self,
        data: &[u8],
        content_type: u8,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        // Keys not set — return error (encryption requires valid keys)
        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        let (ciphertext, auth_tag) = if self.record.write_key.is_empty()
            || self.record.write_key.len() < 32
            || self.record.write_iv.len() < 12
        {
            return Err(TlsError::CryptoError);
        } else {
            // Construct 12-byte nonce: IV XOR (zero-padded sequence number)
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&self.record.write_iv.as_slice()[0..12]);
            let seq_bytes = self.record.write_seq.to_be_bytes();
            for i in 0..8 {
                nonce[4 + i] ^= seq_bytes[i];
            }

            // AAD: seq_num(8) || type(1) || version(2) || length(2)
            let aad = Self::tls12_aad(self.record.write_seq, content_type, data.len());

            Self::encrypt_aead_payload(
                cipher,
                self.record.write_key.as_slice(),
                &nonce,
                &aad,
                data,
            )?
        };

        // Record length: ciphertext + tag(16) — no explicit nonce for ChaCha20-Poly1305
        let record_len = ciphertext.total_len() + 16;

        let record_header = [
            content_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];

        self.record.write_seq += 1;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        builder.push_payload(ciphertext);
        builder.push_bytes(&auth_tag).ok_or(TlsError::DecodeError)?;
        Ok(builder.build())
    }

    /// TLS 1.3: 復号されたレコードから内部コンテントタイプを除去し平文を返す
    ///
    /// TLS 1.3のレコード構造: plaintext || content_type || zeros(padding)
    /// 最後の非ゼロバイトがコンテントタイプ
    pub(crate) fn tls13_strip_content_type(decrypted: &[u8]) -> Option<&[u8]> {
        for i in (0..decrypted.len()).rev() {
            if decrypted[i] != 0 {
                // decrypted[i] は content_type
                return Some(&decrypted[..i]);
            }
        }
        None
    }

    /// TLS 1.3: 復号されたレコードから内部コンテントタイプと平文を分離する
    ///
    /// 戻り値: (content_type, plaintext)
    pub(crate) fn tls13_split_content_type(decrypted: &[u8]) -> Option<(u8, &[u8])> {
        for i in (0..decrypted.len()).rev() {
            if decrypted[i] != 0 {
                return Some((decrypted[i], &decrypted[..i]));
            }
        }
        None
    }

    pub(crate) fn tls13_split_content_type_payload(
        decrypted: &kernel_api::resource::net::PacketPayload,
    ) -> Option<(u8, usize)> {
        let span = crate::net::payload::PayloadSpanRef::from_payload(decrypted);
        for i in (0..span.total_len()).rev() {
            let byte = span.byte_at(i)?;
            if byte != 0 {
                return Some((byte, i));
            }
        }
        None
    }

    /// TLS 1.3: Post-handshake メッセージを処理
    ///
    /// RFC 8446 Section 4.6: Post-Handshake Messages
    /// - NewSessionTicket (type 4)
    /// - KeyUpdate (type 24)
    pub(crate) fn tls13_process_post_handshake(
        &mut self,
        data: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        let mut offset = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
                .slice(body_start, length)
                .ok_or(TlsError::DecodeError)?;

            match msg_type {
                4 => {
                    // NewSessionTicket (RFC 8446 Section 4.6.1)
                    let payload = payload.single_chunk().ok_or(TlsError::DecodeError)?;
                    self.tls13_process_new_session_ticket(payload)?;
                }
                24 => {
                    // KeyUpdate (RFC 8446 Section 4.6.3)
                    let payload = payload.single_chunk().ok_or(TlsError::DecodeError)?;
                    self.tls13_process_key_update(payload)?;
                }
                _ => {
                    // 未知のPost-Handshakeメッセージは無視
                }
            }

            offset = body_end;
        }
        Ok(())
    }

    /// TLS 1.3: NewSessionTicket を処理 (RFC 8446 Section 4.6.1)
    ///
    /// 構造:
    /// - ticket_lifetime (4 bytes)
    /// - ticket_age_add (4 bytes)
    /// - ticket_nonce_length (1 byte)
    /// - ticket_nonce (variable)
    /// - ticket_length (2 bytes)
    /// - ticket (variable)
    /// - extensions_length (2 bytes)
    /// - extensions (variable)
    /// TLS 1.3 New Session Ticketの拡張からmax_early_data_sizeを解析
    pub(super) fn parse_ticket_extensions(data: &[u8], off: usize) -> u32 {
        let mut max_early_data_size: u32 = 0;
        if data.len() < off + 2 {
            return max_early_data_size;
        }
        let ext_total_len = ((data[off] as usize) << 8) | data[off + 1] as usize;
        let mut eoff = off + 2;
        let ext_end = eoff + ext_total_len;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while eoff + 4 <= ext_end && eoff + 4 <= data.len() {
            let ext_type = ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
            let ext_len = ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
            eoff += 4;
            if eoff + ext_len > data.len() {
                break;
            }
            if ext_type == 42 && ext_len >= 4 {
                max_early_data_size = u32::from_be_bytes([
                    data[eoff],
                    data[eoff + 1],
                    data[eoff + 2],
                    data[eoff + 3],
                ]);
            }
            eoff += ext_len;
        }
        max_early_data_size
    }

    pub(crate) fn tls13_process_new_session_ticket(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 11 {
            return Err(TlsError::DecodeError);
        }

        let lifetime = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let age_add = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let nonce_len = data[8] as usize;
        let nonce_start = 9usize;
        let nonce_end = nonce_start.saturating_add(nonce_len);
        if nonce_end + 2 > data.len() {
            return Err(TlsError::DecodeError);
        }

        let ticket_len = u16::from_be_bytes([data[nonce_end], data[nonce_end + 1]]) as usize;
        let ticket_start = nonce_end + 2;
        let ticket_end = ticket_start.saturating_add(ticket_len);
        if ticket_end + 2 > data.len() {
            return Err(TlsError::DecodeError);
        }

        let max_early_data_size = Self::parse_ticket_extensions(data, ticket_end);

        let material_len = nonce_len
            .checked_add(ticket_len)
            .ok_or(TlsError::DecodeError)?;
        let mut material = crate::net::payload::alloc_packet_with_headroom(material_len, 0)
            .ok_or(TlsError::DecodeError)?;
        material.data_mut()[..nonce_len].copy_from_slice(&data[nonce_start..nonce_end]);
        material.data_mut()[nonce_len..material_len]
            .copy_from_slice(&data[ticket_start..ticket_end]);
        let nonce = PayloadRange::new(0, nonce_len);
        let ticket = PayloadRange::new(nonce_len, ticket_len);

        self.resumption.tls13_ticket_age_add = age_add;
        self.early_data.max_early_data_size = max_early_data_size;
        self.tls13.session_ticket = Some(SessionTicket {
            lifetime,
            age_add,
            payload: PacketPayload::single(material),
            nonce,
            ticket,
        });

        if let Some(psk) = self.derive_tls13_psk_from_rms(&data[nonce_start..nonce_end]) {
            self.resumption.tls13_psk = Some(psk);
        }

        Ok(())
    }

    /// Resumption Master SecretからPSKを導出
    pub(super) fn derive_tls13_psk_from_rms(&self, ticket_nonce: &[u8]) -> Option<TlsBytes<48>> {
        if self.resumption.resumption_master_secret.is_empty() {
            return None;
        }
        let use_384 = self
            .negotiation
            .negotiated_cipher
            .map_or(false, |c| c.uses_sha384());
        let hash_len = if use_384 { 48 } else { 32 };

        let psk = if use_384 {
            let mut rms = [0u8; 48];
            let copy_len = self.resumption.resumption_master_secret.len().min(48);
            rms[..copy_len]
                .copy_from_slice(&self.resumption.resumption_master_secret.as_slice()[..copy_len]);
            let mut derived = [0u8; 48];
            hkdf_expand_label_sha384(&rms, b"resumption", ticket_nonce, &mut derived[..hash_len]);
            TlsBytes::from_slice(&derived[..hash_len])?
        } else {
            let mut rms = [0u8; 32];
            let copy_len = self.resumption.resumption_master_secret.len().min(32);
            rms[..copy_len]
                .copy_from_slice(&self.resumption.resumption_master_secret.as_slice()[..copy_len]);
            let mut derived = [0u8; 32];
            hkdf_expand_label(&rms, b"resumption", ticket_nonce, &mut derived[..hash_len]);
            TlsBytes::from_slice(&derived[..hash_len])?
        };
        Some(psk)
    }

    /// TLS 1.3: KeyUpdate を処理 (RFC 8446 Section 4.6.3)
    ///
    /// 構造:
    /// - request_update (1 byte): 0=update_not_requested, 1=update_requested
    ///
    /// サーバーの読み取り鍵を更新し、要求された場合はクライアント側も更新する
    pub(super) fn tls13_process_key_update(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let request_update = data[0];

        let cipher = self
            .negotiation
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();
        let hash_len = if use_384 {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        };

        // サーバーの application_traffic_secret を更新
        // application_traffic_secret_N+1 =
        //     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
        let mut new_server_secret = [0u8; 48];
        if use_384 {
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

        // 新しいサーバー読み取り鍵を導出
        let mut new_read_iv = [0u8; 12];
        let mut new_read_key = [0u8; 32];
        if use_384 {
            tls13_derive_traffic_keys_sha384(
                &self.tls13.server_app_traffic_secret,
                &mut new_read_key[..key_len],
                &mut new_read_iv,
            );
        } else {
            let mut secret32 = [0u8; 32];
            secret32.copy_from_slice(&self.tls13.server_app_traffic_secret[..32]);
            tls13_derive_traffic_keys(&secret32, &mut new_read_key[..key_len], &mut new_read_iv);
        }
        Self::set_tls_bytes(&mut self.record.read_key, &new_read_key[..key_len])?;
        Self::set_tls_bytes(&mut self.record.read_iv, &new_read_iv)?;
        self.record.read_seq = 0;

        // update_requested (1) の場合、クライアント側鍵も更新して KeyUpdate を返信
        if request_update == 1 {
            let mut new_client_secret = [0u8; 48];
            if use_384 {
                let mut old_secret = [0u8; 48];
                old_secret.copy_from_slice(&self.tls13.client_app_traffic_secret);
                hkdf_expand_label_sha384(
                    &old_secret,
                    b"traffic upd",
                    b"",
                    &mut new_client_secret[..hash_len],
                );
            } else {
                let mut old_secret = [0u8; 32];
                old_secret.copy_from_slice(&self.tls13.client_app_traffic_secret[..32]);
                hkdf_expand_label(
                    &old_secret,
                    b"traffic upd",
                    b"",
                    &mut new_client_secret[..hash_len],
                );
            }
            self.tls13.client_app_traffic_secret = new_client_secret;

            let mut new_write_iv = [0u8; 12];
            let mut new_write_key = [0u8; 32];
            if use_384 {
                tls13_derive_traffic_keys_sha384(
                    &self.tls13.client_app_traffic_secret,
                    &mut new_write_key[..key_len],
                    &mut new_write_iv,
                );
            } else {
                let mut secret32 = [0u8; 32];
                secret32.copy_from_slice(&self.tls13.client_app_traffic_secret[..32]);
                tls13_derive_traffic_keys(
                    &secret32,
                    &mut new_write_key[..key_len],
                    &mut new_write_iv,
                );
            }
            Self::set_tls_bytes(&mut self.record.write_key, &new_write_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &new_write_iv)?;
            self.record.write_seq = 0;

            // KeyUpdate応答を送信キューに追加
            self.tls13.pending_key_update_response = true;
        }

        Ok(())
    }

    /// TLS 1.3: KeyUpdate応答メッセージを構築
    ///
    /// post-handshakeハンドシェイクメッセージとして暗号化して送信
    pub fn build_key_update_response_payload(
        &mut self,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        if !self.tls13.pending_key_update_response {
            return None;
        }
        self.tls13.pending_key_update_response = false;

        // KeyUpdate { update_not_requested(0) }
        let inner = [
            24, // msg_type = KeyUpdate
            0,
            0,
            1, // length = 1
            0, // update_not_requested
            ContentType::Handshake as u8,
        ];

        self.tls13_encrypt_record(&inner, false).ok()
    }

    /// TLS 1.3 モードかどうか
    pub fn is_tls13(&self) -> bool {
        self.negotiation.is_tls13
    }

    /// TLS 1.3: クライアントFinished送信が必要か
    pub fn needs_client_finished(&self) -> bool {
        self.negotiation.is_tls13 && self.negotiation.state == TlsState::Tls13ServerFinishedReceived
    }

    /// 接続を閉じる
    pub fn close_payload(&mut self) -> kernel_api::resource::net::PacketPayload {
        self.negotiation.state = TlsState::Closing;

        if self.negotiation.is_tls13 && !self.record.write_key.is_empty() {
            // TLS 1.3: close_notify を暗号化して送信
            let inner = [
                AlertLevel::Warning as u8,
                AlertDescription::CloseNotify as u8,
                ContentType::Alert as u8,
            ];
            if let Ok(record) = self.tls13_encrypt_record(&inner, false) {
                return record;
            }
        }

        // TLS 1.2 or fallback
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        if builder
            .push_bytes(&[
                ContentType::Alert as u8,
                0x03,
                0x03,
                0,
                2,
                AlertLevel::Warning as u8,
                AlertDescription::CloseNotify as u8,
            ])
            .is_none()
        {
            return kernel_api::resource::net::PacketPayload::default();
        }
        builder.build()
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn handshake_transcript_len(&self) -> usize {
        self.transcript_len()
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn has_local_ecdh_keypair(&self) -> bool {
        self.handshake_secrets.local_ecdh_keypair.is_some()
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn has_transcript_hash(&self) -> bool {
        self.transcript.is_initialized()
    }
}
