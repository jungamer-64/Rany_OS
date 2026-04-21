// ============================================================================
// kernel/src/net/security/tls/connection/handshake/tls13.rs - セキュリティ / TLS / 接続 / ハンドシェイク / TLS 1.3ハンドシェイク
// ============================================================================

use arrayvec::ArrayVec;

use super::super::{
    CertificateRequestContext, CipherSuite, ContentType, PacketPayload, PayloadRange,
    PayloadSpanRef, SessionCache, SessionCacheEntry, TlsBytes, TlsConnection, TlsError,
    TlsResult, TlsState, TlsVersion, TLS_CA_CERTS_CAPACITY, TLS_CERT_CHAIN_CAPACITY, ecdh,
};
use crate::net::security::tls::crypto::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, tls13_derive_secret, tls13_derive_secret_sha384,
    tls13_derive_traffic_keys, tls13_derive_traffic_keys_sha384, tls13_early_secret,
    tls13_early_secret_sha384, tls13_finished_key, tls13_finished_key_sha384,
    tls13_handshake_secret, tls13_handshake_secret_sha384, tls13_master_secret,
    tls13_master_secret_sha384, tls13_verify_data, tls13_verify_data_sha384,
};

impl TlsConnection {
    /// AES-GCM レコード暗号化 (TLS 1.2)
    pub(super) fn encrypt_aes_gcm_record(
        &mut self,
        content_type: u8,
        data: &[u8],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        let explicit_nonce = self.record.write_seq.to_be_bytes();

        if self.record.write_key.is_empty() || self.record.write_iv.len() < 4 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.record.write_iv.as_slice()[0..4]);
        nonce[4..12].copy_from_slice(&explicit_nonce);

        let aad = Self::tls12_aad(self.record.write_seq, content_type, data.len());

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, self.record.write_key.as_slice(), &nonce, &aad, data)?;

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

    /// ChaCha20-Poly1305 レコード暗号化 (TLS 1.2)
    pub(super) fn encrypt_chacha20_record(
        &mut self,
        content_type: u8,
        data: &[u8],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        if self.record.write_key.is_empty() || self.record.write_key.len() < 32 || self.record.write_iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.record.write_iv.as_slice()[0..12]);
        let seq_bytes = self.record.write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let aad = Self::tls12_aad(self.record.write_seq, content_type, data.len());

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, self.record.write_key.as_slice(), &nonce, &aad, data)?;

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

    // ========================================================================
    // TLS 1.3 Handshake Methods
    // ========================================================================

    /// TLS 1.3: ServerHello受信後にハンドシェイク鍵を導出
    ///
    /// RFC 8446 Section 7.1:
    /// 1. Early Secret = HKDF-Extract(0, PSK or 0)
    /// 2. Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), DHE)
    /// 3. client/server_handshake_traffic_secret
    /// 4. handshake traffic keys を導出
    pub(crate) fn tls13_derive_handshake_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();

        if use_384 {
            // SHA-384ベース鍵スケジュール
            let transcript_ch_sh = self.transcript_hash_sha384();

            let psk_ref = if self.resumption.tls13_using_psk {
                self.resumption.tls13_psk.as_ref().map(TlsBytes::as_slice)
            } else {
                None
            };
            let early_secret = tls13_early_secret_sha384(psk_ref);
            let handshake_secret =
                tls13_handshake_secret_sha384(&early_secret, self.handshake_secrets.pre_master_secret.as_slice());

            let chs =
                tls13_derive_secret_sha384(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs =
                tls13_derive_secret_sha384(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.tls13.client_hs_traffic_secret = chs;
            self.tls13.server_hs_traffic_secret = shs;

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(
                &shs,
                &mut self.tls13.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys_sha384(
                &chs,
                &mut self.tls13.hs_write_key.as_mut_storage()[..key_len],
                &mut client_iv,
            );
            self.tls13.hs_read_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            self.tls13.hs_write_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            Self::set_tls_bytes(&mut self.tls13.hs_read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.tls13.hs_write_iv, &client_iv)?;
            self.tls13.hs_read_seq = 0;
            self.tls13.hs_write_seq = 0;

            let ms = tls13_master_secret_sha384(&handshake_secret);
            self.handshake_secrets.master_secret[..48].copy_from_slice(&ms);
        } else {
            let transcript_ch_sh = self.transcript_hash_sha256();

            let psk_ref_256 = if self.resumption.tls13_using_psk {
                self.resumption.tls13_psk.as_ref().map(TlsBytes::as_slice)
            } else {
                None
            };
            let early_secret = tls13_early_secret(psk_ref_256);
            let handshake_secret =
                tls13_handshake_secret(&early_secret, self.handshake_secrets.pre_master_secret.as_slice());

            let chs = tls13_derive_secret(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs = tls13_derive_secret(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.tls13.client_hs_traffic_secret[..32].copy_from_slice(&chs);
            self.tls13.server_hs_traffic_secret[..32].copy_from_slice(&shs);

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(
                &shs,
                &mut self.tls13.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys(
                &chs,
                &mut self.tls13.hs_write_key.as_mut_storage()[..key_len],
                &mut client_iv,
            );
            self.tls13.hs_read_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            self.tls13.hs_write_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            Self::set_tls_bytes(&mut self.tls13.hs_read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.tls13.hs_write_iv, &client_iv)?;
            self.tls13.hs_read_seq = 0;
            self.tls13.hs_write_seq = 0;

            let master_secret_bytes = tls13_master_secret(&handshake_secret);
            self.handshake_secrets.master_secret[..32].copy_from_slice(&master_secret_bytes);
        }

        self.negotiation.state = TlsState::Tls13WaitEncryptedExtensions;
        Ok(())
    }

    /// TLS 1.3: 暗号化ハンドシェイク内の複数メッセージを処理
    pub(super) fn tls13_process_handshake_messages(&mut self, data: PacketPayload) -> TlsResult<()> {
        let messages = PayloadSpanRef::from_payload(&data);
        let mut offset = 0usize;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < messages.total_len() {
            if messages.total_len() - offset < 4 {
                return Err(TlsError::DecodeError);
            }

            let msg_type = messages.read_u8(offset).ok_or(TlsError::DecodeError)?;
            let length = messages
                .read_u24_be(offset + 1)
                .ok_or(TlsError::DecodeError)? as usize;
            let body_start = offset + 4;
            let body_end = body_start + length;
            if body_end > messages.total_len() {
                return Err(TlsError::DecodeError);
            }

            let payload = messages
                .slice(body_start, length)
                .ok_or(TlsError::DecodeError)?;
            let full_msg = messages
                .slice(offset, body_end - offset)
                .ok_or(TlsError::DecodeError)?;

            self.tls13_dispatch_handshake_msg(msg_type, payload)?;

            self.append_transcript_span(full_msg)?;

            if msg_type == 20 {
                self.transcript.snapshot_server_finished();
            }

            offset = body_end;
        }
        Ok(())
    }

    /// Dispatch a single TLS 1.3 handshake message to its handler.
    pub(super) fn tls13_dispatch_handshake_msg(
        &mut self,
        msg_type: u8,
        payload: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        let payload = payload
            .as_contiguous_slice()
            .ok_or(TlsError::DecodeError)?;
        match msg_type {
            8 => {
                // EncryptedExtensions
                self.tls13_process_encrypted_extensions(payload)?;
            }
            11 => {
                // Certificate (TLS 1.3 format)
                self.tls13_process_certificate(payload)?;
            }
            13 => {
                // CertificateRequest (RFC 8446 Section 4.3.2)
                self.tls13_process_certificate_request(payload)?;
            }
            15 => {
                // CertificateVerify
                self.tls13_process_certificate_verify(payload)?;
            }
            20 => {
                // Finished
                // トランスクリプトハッシュにFinished以前のメッセージを更新
                // (Finishedが含まれる前のハッシュでverify_dataを検証)
                self.tls13_process_server_finished(payload)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// TLS 1.3: EncryptedExtensionsを処理
    pub(super) fn tls13_process_encrypted_extensions(&mut self, data: &[u8]) -> TlsResult<()> {
        // EncryptedExtensions: extensions length(2) + extensions(N)
        if data.len() < 2 {
            return Err(TlsError::DecodeError);
        }

        let extensions_len = ((data[0] as usize) << 8) | data[1] as usize;
        if data.len() < 2 + extensions_len {
            return Err(TlsError::DecodeError);
        }

        // 拡張をパース（ALPN, early_data等）
        let mut eoff = 2usize;
        let ext_end = 2 + extensions_len;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while eoff + 4 <= ext_end && eoff + 4 <= data.len() {
            let ext_type = ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
            let ext_len = ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
            eoff += 4;
            if eoff + ext_len > data.len() {
                break;
            }
            match ext_type {
                42 => {
                    // early_data (type 42) — サーバーがEarly Dataを受理した
                    self.early_data.early_data_accepted = true;
                }
                _ => {
                    // 他の拡張は無視（ALPN等は将来対応）
                }
            }
            eoff += ext_len;
        }

        // PSK使用+Early Data送信済みだがacceptされていない場合、バッファは保持（再送用）
        self.negotiation.state = TlsState::Tls13WaitCertificate;
        Ok(())
    }

    /// Parse and skip certificate request extensions (we only need to detect signature_algorithms).
    pub(super) fn tls13_skip_cert_request_extensions(
        &self,
        data: &[u8],
        start: usize,
    ) -> TlsResult<()> {
        let mut off = start;
        if data.len() < off + 2 {
            return Err(TlsError::DecodeError);
        }
        let ext_total_len = ((data[off] as usize) << 8) | data[off + 1] as usize;
        off += 2;

        let ext_end = off + ext_total_len;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while off + 4 <= ext_end && off + 4 <= data.len() {
            let ext_type = ((data[off] as u16) << 8) | data[off + 1] as u16;
            let ext_len = ((data[off + 2] as usize) << 8) | data[off + 3] as usize;
            off += 4;
            if off + ext_len > data.len() {
                break;
            }
            if ext_type == 13 && ext_len >= 2 {
                // signature_algorithms — 将来のクライアント証明書署名用に保存可能
                // 現在は空Certificate応答のみのため、パースしてスキップ
            }
            off += ext_len;
        }
        Ok(())
    }

    pub(crate) fn tls13_process_certificate_request(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let context_len = data[0] as usize;
        let ext_start = 1usize.saturating_add(context_len);
        if ext_start > data.len() {
            return Err(TlsError::DecodeError);
        }

        self.tls13.client_auth_requested = true;
        self.tls13.certificate_request_context = if context_len == 0 {
            None
        } else {
            let mut packet = crate::net::payload::alloc_packet_with_headroom(context_len, 0)
                .ok_or(TlsError::DecodeError)?;
            packet
                .data_mut()
                .copy_from_slice(&data[1..1 + context_len]);
            Some(CertificateRequestContext::new(
                kernel_api::resource::net::PacketPayload::single(packet),
                PayloadRange::new(0, context_len),
            ))
        };
        self.tls13_skip_cert_request_extensions(data, ext_start)?;
        Ok(())
    }

    /// TLS 1.3 Certificateメッセージから証明書チェーンDERを抽出する。
    pub(super) fn tls13_extract_cert_chain<'a>(
        &self,
        data: &'a [u8],
    ) -> TlsResult<ArrayVec<&'a [u8], TLS_CERT_CHAIN_CAPACITY>> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let ctx_len = data[0] as usize;
        let mut offset = 1 + ctx_len;

        if data.len() < offset + 3 {
            return Err(TlsError::DecodeError);
        }

        let certs_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | data[offset + 2] as usize;
        offset += 3;

        if data.len() < offset + certs_len {
            return Err(TlsError::DecodeError);
        }

        let cert_list_end = offset + certs_len;
        let mut certs = ArrayVec::<&[u8], TLS_CERT_CHAIN_CAPACITY>::new();

        while offset < cert_list_end {
            if offset + 3 > cert_list_end {
                return Err(TlsError::DecodeError);
            }

            let cert_len = ((data[offset] as usize) << 16)
                | ((data[offset + 1] as usize) << 8)
                | data[offset + 2] as usize;
            offset += 3;

            if offset + cert_len > cert_list_end {
                return Err(TlsError::DecodeError);
            }

            certs
                .try_push(&data[offset..offset + cert_len])
                .map_err(|_| TlsError::CertificateError)?;
            offset += cert_len;

            // Skip extensions in CertificateEntry
            if offset + 2 > cert_list_end {
                return Err(TlsError::DecodeError);
            }
            let ext_len = ((data[offset] as usize) << 8) | data[offset + 1] as usize;
            offset += 2 + ext_len;

            if offset > cert_list_end {
                return Err(TlsError::DecodeError);
            }
        }

        Ok(certs)
    }

    /// TLS 1.3: Certificate を処理 (RFC 8446 Section 4.4.2)
    pub(super) fn tls13_process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        let certs = self.tls13_extract_cert_chain(data)?;

        if certs.is_empty() {
            if !self.config.should_skip_verify() {
                return Err(TlsError::CertificateError);
            }
            self.negotiation.state = TlsState::Tls13WaitCertificateVerify;
            return Ok(());
        }

        if !self.config.should_skip_verify() {
            // 証明書チェーンの検証 (issuerの一致、署名の妥当性、ホスト名の一致、およびルートCAへの信頼)
            let validated_spki = {
                let mut ca_ders = ArrayVec::<&[u8], TLS_CA_CERTS_CAPACITY>::new();
                for cert in &self.config.ca_certs {
                    if let Some(der) = cert.der_contiguous_slice() {
                        ca_ders
                            .try_push(der)
                            .map_err(|_| TlsError::CertificateError)?;
                    }
                }
                crate::net::security::x509::validate_certificate_chain(
                    &certs,
                    self.negotiation.server_name.as_ref().map(|name| name.as_str()),
                    &ca_ders,
                )
            };
            if let Some(spki) = validated_spki {
                self.extract_server_public_key_from_spki(spki)?;
            } else {
                return Err(TlsError::CertificateError);
            }
        } else {
            // 検証スキップ時は最初の証明書の鍵をそのまま使用
            self.set_server_public_key_from_cert(certs[0])?;
        }

        self.negotiation.state = TlsState::Tls13WaitCertificateVerify;
        Ok(())
    }

    /// TLS 1.3: CertificateVerify を処理 (RFC 8446 Section 4.4.3)
    ///
    /// CertificateVerify:
    /// - signature_algorithm (2 bytes)
    /// - signature length (2 bytes)
    /// - signature (variable)
    pub(super) fn tls13_process_certificate_verify(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 4 {
            return Err(TlsError::DecodeError);
        }

        let sig_algorithm = ((data[0] as u16) << 8) | data[1] as u16;
        let sig_len = ((data[2] as usize) << 8) | data[3] as usize;

        if data.len() < 4 + sig_len {
            return Err(TlsError::DecodeError);
        }

        let signature = &data[4..4 + sig_len];

        if self.config.should_skip_verify() {
            self.negotiation.state = TlsState::Tls13WaitFinished;
            return Ok(());
        }

        self.verify_tls13_certificate_verify(sig_algorithm, signature)?;

        self.negotiation.state = TlsState::Tls13WaitFinished;
        Ok(())
    }

    fn verify_tls13_certificate_verify(
        &self,
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        const LABEL: &[u8] = b"TLS 1.3, server CertificateVerify";
        let use_384 = self.negotiation.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        let mut content = [0u8; 64 + LABEL.len() + 1 + SHA384_OUTPUT_SIZE];
        content[..64].fill(0x20);
        let mut offset = 64;
        content[offset..offset + LABEL.len()].copy_from_slice(LABEL);
        offset += LABEL.len();
        content[offset] = 0x00;
        offset += 1;
        let hash_len = if use_384 {
            let hash = self.transcript_hash_sha384();
            content[offset..offset + SHA384_OUTPUT_SIZE].copy_from_slice(&hash);
            SHA384_OUTPUT_SIZE
        } else {
            let hash = self.transcript_hash_sha256();
            content[offset..offset + SHA256_OUTPUT_SIZE].copy_from_slice(&hash);
            SHA256_OUTPUT_SIZE
        };

        self.dispatch_tls13_signature_verification(
            sig_algorithm,
            &content[..offset + hash_len],
            signature,
        )
    }

    /// 署名アルゴリズムに基づくTLS 1.3署名検証ディスパッチ
    pub(super) fn dispatch_tls13_signature_verification(
        &self,
        sig_algorithm: u16,
        content: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        match sig_algorithm {
            // RFC 8446 Section 4.2.3: RSASSA-PKCS1-v1_5 (0x0*01) is NOT supported for CertificateVerify in TLS 1.3.
            // Only PSS or ECDSA are allowed for RSA/EC keys.
            0x0804 => self.verify_rsa_pss_signature(
                content,
                signature,
                crate::net::security::rsa::HashAlgorithm::Sha256,
            ),
            0x0805 => self.verify_rsa_pss_signature(
                content,
                signature,
                crate::net::security::rsa::HashAlgorithm::Sha384,
            ),
            0x0806 => self.verify_rsa_pss_signature(
                content,
                signature,
                crate::net::security::rsa::HashAlgorithm::Sha512,
            ),
            0x0403 => self.verify_ecdsa_p256_signature(content, signature),
            0x0503 => self.verify_ecdsa_p384_signature(content, signature),
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// RSA-PSS 署名検証ヘルパー (RFC 8446 required for TLS 1.3)
    pub(super) fn verify_rsa_pss_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        hash_alg: crate::net::security::rsa::HashAlgorithm,
    ) -> TlsResult<()> {
        let server_public_key = self
            .handshake_secrets
            .server_public_key
            .as_ref()
            .ok_or(TlsError::CertificateError)?;
        let (modulus, exponent) = server_public_key
            .rsa_components()
            .ok_or(TlsError::CertificateError)?;
        let pubkey = crate::net::security::rsa::RsaPublicKey { modulus, exponent };

        match hash_alg {
            crate::net::security::rsa::HashAlgorithm::Sha256 => {
                let digest = crate::crypto::sha256::compute(message);
                crate::net::security::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
                    .map_err(|_| TlsError::CryptoError)
            }
            crate::net::security::rsa::HashAlgorithm::Sha384 => {
                let digest = crate::crypto::sha384::compute(message);
                crate::net::security::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
                    .map_err(|_| TlsError::CryptoError)
            }
            crate::net::security::rsa::HashAlgorithm::Sha512 => {
                let digest = crate::crypto::sha512::compute(message);
                crate::net::security::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
                    .map_err(|_| TlsError::CryptoError)
            }
            // SECURITY: TLS 1.3 の PSS では SHA-1 をサポートしない。
            _ => Err(TlsError::CryptoError),
        }
    }

    /// ECDSA P-256 署名検証ヘルパー
    pub(super) fn verify_ecdsa_p256_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.handshake_secrets.server_public_key {
            Some(server_public_key) => server_public_key
                .ecdsa_p256_point()
                .ok_or(TlsError::CertificateError)?,
            _ => return Err(TlsError::CertificateError),
        };

        let digest = crate::crypto::sha256::compute(message);

        ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }
}

impl TlsConnection {
    /// ECDSA P-384 署名検証ヘルパー
    pub(super) fn verify_ecdsa_p384_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.handshake_secrets.server_public_key {
            Some(server_public_key) => server_public_key
                .ecdsa_p384_point()
                .ok_or(TlsError::CertificateError)?,
            _ => return Err(TlsError::CertificateError),
        };

        let digest = crate::crypto::sha384::compute(message);

        ecdh::p384::ecdsa_p384_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// TLS 1.3: サーバーFinishedを処理 (RFC 8446 Section 4.4.4)
    ///
    /// verify_data = HMAC(finished_key, Transcript-Hash(..before Finished))
    pub(super) fn tls13_process_server_finished(&mut self, data: &[u8]) -> TlsResult<()> {
        let hash_len = self.hash_len();
        if data.len() != hash_len {
            return Err(TlsError::DecodeError);
        }

        let use_384 = self.negotiation.negotiated_cipher.map_or(false, |c| c.uses_sha384());

        // Finished の verify_data を検証
        // トランスクリプトハッシュは Finished メッセージ自体を含まない状態で計算
        if use_384 {
            let transcript = self.transcript_hash_sha384();
            let mut shs = [0u8; 48];
            shs.copy_from_slice(&self.tls13.server_hs_traffic_secret[..48]);
            let finished_key = tls13_finished_key_sha384(&shs);
            let expected = tls13_verify_data_sha384(&finished_key, &transcript);
            let mut diff = 0u8;
            for i in 0..SHA384_OUTPUT_SIZE {
                diff |= data[i] ^ expected[i];
            }
            if diff != 0 {
                return Err(TlsError::HandshakeFailure);
            }
        } else {
            let transcript = self.transcript_hash_sha256();
            let mut shs = [0u8; 32];
            shs.copy_from_slice(&self.tls13.server_hs_traffic_secret[..32]);
            let finished_key = tls13_finished_key(&shs);
            let expected = tls13_verify_data(&finished_key, &transcript);
            let mut diff = 0u8;
            for i in 0..SHA256_OUTPUT_SIZE {
                diff |= data[i] ^ expected[i];
            }
            if diff != 0 {
                return Err(TlsError::HandshakeFailure);
            }
        }

        self.negotiation.state = TlsState::Tls13ServerFinishedReceived;
        Ok(())
    }

    /// EndOfEarlyDataレコードを構築する (RFC 8446 Section 4.5)
    pub(super) fn build_end_of_early_data_record(
        &mut self,
    ) -> TlsResult<Option<kernel_api::resource::net::PacketPayload>> {
        if !self.early_data.early_data_sent || !self.early_data.early_data_accepted {
            return Ok(None);
        }

        let eoed_msg: [u8; 4] = [5, 0, 0, 0];

        self.append_transcript_bytes(&eoed_msg)?;

        if self.early_data.early_write_key.is_empty() || self.early_data.early_write_iv.len() < 12 {
            return Ok(None);
        }

        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let inner = [
            eoed_msg[0],
            eoed_msg[1],
            eoed_msg[2],
            eoed_msg[3],
            ContentType::Handshake as u8,
        ];

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.early_data.early_write_iv.as_slice()[..12]);
        let seq_bytes = self.early_data.early_write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = inner.len() + 16;
        let aad = Self::tls13_record_aad(encrypted_len);

        let (ciphertext, auth_tag) = Self::encrypt_aead_payload(
            cipher,
            self.early_data.early_write_key.as_slice(),
            &nonce,
            &aad,
            &inner,
        )?;

        let encrypted_len_bytes = (encrypted_len as u16).to_be_bytes();
        let record_header = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            encrypted_len_bytes[0],
            encrypted_len_bytes[1],
        ];

        self.early_data.early_write_seq += 1;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        builder.push_payload(ciphertext);
        builder.push_bytes(&auth_tag).ok_or(TlsError::DecodeError)?;
        Ok(Some(builder.build()))
    }

    /// 空のCertificateメッセージレコードを構築する (RFC 8446 Section 4.4.2)
    pub(super) fn build_empty_certificate_record(
        &mut self,
    ) -> TlsResult<Option<kernel_api::resource::net::PacketPayload>> {
        if !self.tls13.client_auth_requested {
            return Ok(None);
        }

        let ctx = self.tls13.certificate_request_context
            .as_ref()
            .and_then(CertificateRequestContext::span)
            .and_then(|span| span.as_contiguous_slice())
            .unwrap_or(&[]);
        let ctx_len = ctx.len();
        let cert_body_len = 1 + ctx_len + 3;
        let mut cert_msg = TlsBytes::<512>::new();
        cert_msg.push_byte(11).ok_or(TlsError::DecodeError)?; // Certificate type
        cert_msg
            .append_be_u24(cert_body_len)
            .ok_or(TlsError::DecodeError)?;
        cert_msg
            .push_byte(ctx_len as u8)
            .ok_or(TlsError::DecodeError)?;
        cert_msg.append_slice(ctx).ok_or(TlsError::DecodeError)?;
        cert_msg
            .append_slice(&[0, 0, 0])
            .ok_or(TlsError::DecodeError)?; // empty certificate_list

        self.append_transcript_bytes(cert_msg.as_slice())?;

        let mut inner_cert = TlsBytes::<513>::new();
        inner_cert
            .append_slice(cert_msg.as_slice())
            .ok_or(TlsError::DecodeError)?;
        inner_cert
            .push_byte(ContentType::Handshake as u8)
            .ok_or(TlsError::DecodeError)?;
        let encrypted_cert = self.tls13_encrypt_record(inner_cert.as_slice(), true)?;
        Ok(Some(encrypted_cert))
    }

    /// TLS 1.3 クライアントFinished verify_data を計算する
    pub(super) fn compute_tls13_client_verify_data(&self) -> ([u8; 48], usize) {
        let use_384 = self.negotiation.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        if use_384 {
            let transcript = self.transcript_hash_sha384();
            let mut chs = [0u8; 48];
            chs.copy_from_slice(&self.tls13.client_hs_traffic_secret[..48]);
            let finished_key = tls13_finished_key_sha384(&chs);
            (
                tls13_verify_data_sha384(&finished_key, &transcript),
                SHA384_OUTPUT_SIZE,
            )
        } else {
            let transcript = self.transcript_hash_sha256();
            let mut chs = [0u8; 32];
            chs.copy_from_slice(&self.tls13.client_hs_traffic_secret[..32]);
            let finished_key = tls13_finished_key(&chs);
            let mut out = [0u8; 48];
            out[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(&tls13_verify_data(&finished_key, &transcript));
            (out, SHA256_OUTPUT_SIZE)
        }
    }

    /// TLS 1.3: クライアントFinishedメッセージを構築
    ///
    /// サーバーFinished受信後に呼び出す。
    /// アプリケーション鍵の導出も同時に行う。
    /// EndOfEarlyData + 空Certificateなど、Finished前のレコードを構築する
    pub(super) fn build_pre_finished_records_tls13(
        &mut self,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let mut records = kernel_api::resource::net::PacketPayload::default();
        if let Some(eoed_record) = self.build_end_of_early_data_record()? {
            crate::net::payload::append_payload(&mut records, eoed_record);
        }
        if let Some(cert_record) = self.build_empty_certificate_record()? {
            crate::net::payload::append_payload(&mut records, cert_record);
        }
        Ok(records)
    }

    pub fn build_client_finished_tls13_payload(
        &mut self,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        if !self.negotiation.is_tls13 || self.negotiation.state != TlsState::Tls13ServerFinishedReceived {
            return Err(TlsError::UnexpectedMessage);
        }

        let mut records = self.build_pre_finished_records_tls13()?;

        let (verify_data, verify_len) = self.compute_tls13_client_verify_data();
        let hash_len = self.hash_len();

        // Finished ハンドシェイクメッセージ
        let mut finished_msg = [0u8; 4 + SHA384_OUTPUT_SIZE];
        finished_msg[0] = 20; // Finished type
        finished_msg[3] = hash_len as u8;
        finished_msg[4..4 + verify_len].copy_from_slice(&verify_data[..verify_len]);
        let finished_msg = &finished_msg[..4 + verify_len];

        // トランスクリプトハッシュを更新（クライアントFinished含む）
        self.append_transcript_bytes(finished_msg)?;

        // TLS 1.3レコードとして暗号化
        let mut inner = [0u8; 5 + SHA384_OUTPUT_SIZE];
        inner[..4 + verify_len].copy_from_slice(finished_msg);
        inner[4 + verify_len] = ContentType::Handshake as u8;

        let encrypted = self.tls13_encrypt_record(&inner[..5 + verify_len], true)?;

        // アプリケーション鍵の導出
        self.tls13_derive_application_keys()?;

        crate::net::payload::append_payload(&mut records, encrypted);
        Ok(records)
    }

    /// TLS 1.3: アプリケーショントラフィック鍵を導出
    ///
    /// client/server_application_traffic_secret_0 を導出し、
    /// read_key/write_key/read_iv/write_iv に設定する。
    pub(super) fn tls13_derive_application_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();
        if use_384 {
            let transcript_sf = self.transcript
                .server_finished_sha384()
                .unwrap_or_else(|| self.transcript_hash_sha384());
            let mut master_secret = [0u8; 48];
            master_secret.copy_from_slice(&self.handshake_secrets.master_secret[..48]);

            let cas = tls13_derive_secret_sha384(&master_secret, b"c ap traffic", &transcript_sf);
            let sas = tls13_derive_secret_sha384(&master_secret, b"s ap traffic", &transcript_sf);
            self.tls13.client_app_traffic_secret = cas;
            self.tls13.server_app_traffic_secret = sas;

            let mut server_key = [0u8; 32];
            let mut server_iv = [0u8; 12];
            let mut client_key = [0u8; 32];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(&sas, &mut server_key[..key_len], &mut server_iv);
            tls13_derive_traffic_keys_sha384(&cas, &mut client_key[..key_len], &mut client_iv);

            Self::set_tls_bytes(&mut self.record.read_key, &server_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.record.write_key, &client_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &client_iv)?;
        } else {
            let transcript_sf = self.transcript
                .server_finished_sha256()
                .unwrap_or_else(|| self.transcript_hash_sha256());
            let mut master_secret = [0u8; 32];
            master_secret.copy_from_slice(&self.handshake_secrets.master_secret[..32]);

            let cas = tls13_derive_secret(&master_secret, b"c ap traffic", &transcript_sf);
            let sas = tls13_derive_secret(&master_secret, b"s ap traffic", &transcript_sf);
            self.tls13.client_app_traffic_secret[..32].copy_from_slice(&cas);
            self.tls13.server_app_traffic_secret[..32].copy_from_slice(&sas);

            let mut server_key = [0u8; 32];
            let mut server_iv = [0u8; 12];
            let mut client_key = [0u8; 32];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(&sas, &mut server_key[..key_len], &mut server_iv);
            tls13_derive_traffic_keys(&cas, &mut client_key[..key_len], &mut client_iv);

            Self::set_tls_bytes(&mut self.record.read_key, &server_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.record.write_key, &client_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &client_iv)?;
        }

        // resumption_master_secret を導出 (RFC 8446 Section 7.1)
        // RMS = Derive-Secret(master_secret, "res master", transcript_with_client_finished)
        // transcript には client Finished を含む全メッセージが含まれている
        if use_384 {
            let transcript_cf = self.transcript_hash_sha384();
            let mut ms48 = [0u8; 48];
            ms48.copy_from_slice(&self.handshake_secrets.master_secret[..48]);
            let rms = tls13_derive_secret_sha384(&ms48, b"res master", &transcript_cf);
            Self::set_tls_bytes(&mut self.resumption.resumption_master_secret, &rms)?;
        } else {
            let transcript_cf = self.transcript_hash_sha256();
            let mut ms32 = [0u8; 32];
            ms32.copy_from_slice(&self.handshake_secrets.master_secret[..32]);
            let rms = tls13_derive_secret(&ms32, b"res master", &transcript_cf);
            Self::set_tls_bytes(&mut self.resumption.resumption_master_secret, &rms)?;
        }

        self.record.read_seq = 0;
        self.record.write_seq = 0;
        self.negotiation.state = TlsState::Established;
        Ok(())
    }
}

impl TlsConnection {
    /// フルハンドシェイク完了後にセッションをキャッシュに保存する
    pub(super) fn cache_session_if_needed(&mut self) {
        if self.resumption.resuming_session || self.negotiation.session_id.0 == [0u8; 32] {
            return;
        }
        if self.resumption.session_cache.is_none() {
            self.resumption.session_cache = Some(SessionCache::new());
        }
        if let Some(ref mut cache) = self.resumption.session_cache {
            cache.insert(SessionCacheEntry {
                session_id: self.negotiation.session_id.0,
                master_secret: self.handshake_secrets.master_secret,
                cipher_suite: self.negotiation.negotiated_cipher
                    .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256),
                server_name: self.negotiation.server_name.take(),
                version: self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2),
            });
        }
    }

    /// Finishedを処理 (TLS 1.2)
    ///
    /// RFC 5246 Section 7.4.9:
    /// verify_data = PRF(master_secret, "server finished",
    ///                    Hash(handshake_messages))[0..11]
    ///
    /// サーバーのverify_dataを検証し、鍵ブロックを導出する。
    pub(crate) fn process_finished(&mut self, data: &[u8]) -> TlsResult<()> {
        // TLS 1.2 Finished verify_data は12バイト
        if data.len() < 12 {
            return Err(TlsError::DecodeError);
        }

        self.ensure_master_secret_derived();
        let expected_verify_data = self.compute_tls12_verify_data(b"server finished");

        // 定時間比較（タイミング攻撃対策）
        let mut diff = 0u8;
        for i in 0..12 {
            diff |= data[i] ^ expected_verify_data[i];
        }

        if diff != 0 {
            return Err(TlsError::HandshakeFailure);
        }

        // 鍵ブロック導出 (RFC 5246 Section 6.3)
        if self.record.write_key.is_empty() {
            self.derive_tls12_keys()?;
        }

        self.negotiation.state = TlsState::Established;
        self.cache_session_if_needed();

        Ok(())
    }
}
