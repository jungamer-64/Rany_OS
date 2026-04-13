use super::*;

mod signature_verify;
use arrayvec::ArrayVec;

impl TlsConnection {
    /// AES-GCM レコード暗号化 (TLS 1.2)
    pub(super) fn encrypt_aes_gcm_record(
        &mut self,
        content_type: u8,
        data: &[u8],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        let explicit_nonce = self.write_seq.to_be_bytes();

        if self.write_key.is_empty() || self.write_iv.len() < 4 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.write_iv.as_slice()[0..4]);
        nonce[4..12].copy_from_slice(&explicit_nonce);

        let aad = Self::tls12_aad(self.write_seq, content_type, data.len());

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, self.write_key.as_slice(), &nonce, &aad, data)?;

        let record_len = 8 + ciphertext.total_len() + 16;
        let record_header = [
            content_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];

        self.write_seq += 1;
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
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        if self.write_key.is_empty() || self.write_key.len() < 32 || self.write_iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.write_iv.as_slice()[0..12]);
        let seq_bytes = self.write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let aad = Self::tls12_aad(self.write_seq, content_type, data.len());

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, self.write_key.as_slice(), &nonce, &aad, data)?;

        let record_len = ciphertext.total_len() + 16;
        let record_header = [
            content_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];

        self.write_seq += 1;
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
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();

        if use_384 {
            // SHA-384ベース鍵スケジュール
            let transcript_ch_sh = self.transcript_hash_sha384();

            let psk_ref = if self.tls13_using_psk {
                self.tls13_psk.as_ref().map(TlsBytes::as_slice)
            } else {
                None
            };
            let early_secret = tls13_early_secret_sha384(psk_ref);
            let handshake_secret =
                tls13_handshake_secret_sha384(&early_secret, self.pre_master_secret.as_slice());

            let chs =
                tls13_derive_secret_sha384(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs =
                tls13_derive_secret_sha384(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.client_hs_traffic_secret = chs;
            self.server_hs_traffic_secret = shs;

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(
                &shs,
                &mut self.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys_sha384(
                &chs,
                &mut self.hs_write_key.as_mut_storage()[..key_len],
                &mut client_iv,
            );
            self.hs_read_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            self.hs_write_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            Self::set_tls_bytes(&mut self.hs_read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.hs_write_iv, &client_iv)?;
            self.hs_read_seq = 0;
            self.hs_write_seq = 0;

            let ms = tls13_master_secret_sha384(&handshake_secret);
            self.master_secret[..48].copy_from_slice(&ms);
        } else {
            let transcript_ch_sh = self.transcript_hash_sha256();

            let psk_ref_256 = if self.tls13_using_psk {
                self.tls13_psk.as_ref().map(TlsBytes::as_slice)
            } else {
                None
            };
            let early_secret = tls13_early_secret(psk_ref_256);
            let handshake_secret =
                tls13_handshake_secret(&early_secret, self.pre_master_secret.as_slice());

            let chs = tls13_derive_secret(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs = tls13_derive_secret(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.client_hs_traffic_secret[..32].copy_from_slice(&chs);
            self.server_hs_traffic_secret[..32].copy_from_slice(&shs);

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(
                &shs,
                &mut self.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys(
                &chs,
                &mut self.hs_write_key.as_mut_storage()[..key_len],
                &mut client_iv,
            );
            self.hs_read_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            self.hs_write_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            Self::set_tls_bytes(&mut self.hs_read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.hs_write_iv, &client_iv)?;
            self.hs_read_seq = 0;
            self.hs_write_seq = 0;

            let master_secret_bytes = tls13_master_secret(&handshake_secret);
            self.master_secret[..32].copy_from_slice(&master_secret_bytes);
        }

        self.state = TlsState::Tls13WaitEncryptedExtensions;
        Ok(())
    }

    /// TLS 1.3: 暗号化ハンドシェイクレコードを復号して処理
    ///
    /// TLS 1.3では ServerHello 以降のハンドシェイクメッセージは
    /// ApplicationData レコードとして暗号化されて送信される。
    /// 復号後、内部コンテントタイプ（最終の非ゼロバイト）に基づいて処理する。
    pub(crate) fn tls13_process_encrypted_handshake(
        &mut self,
        data: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let decrypted = self.tls13_decrypt_record(data, true)?;

        if decrypted.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let (inner_content_type, inner_data) =
            Self::tls13_split_content_type_payload(&decrypted).ok_or(TlsError::DecodeError)?;

        match ContentType::from_u8(inner_content_type) {
            Some(ContentType::Handshake) => {
                self.tls13_process_handshake_messages(
                    inner_data
                        .as_contiguous_slice()
                        .ok_or(TlsError::DecodeError)?,
                )?;
                Ok(kernel_api::resource::net::PacketPayload::default())
            }
            Some(ContentType::Alert) => {
                if inner_data.total_len() >= 2 {
                    let description = inner_data.byte_at(1).ok_or(TlsError::DecodeError)?;
                    if description == AlertDescription::CloseNotify as u8 {
                        self.state = TlsState::Closed;
                    } else {
                        self.state = TlsState::Error;
                        return Err(TlsError::Alert(description));
                    }
                }
                Ok(kernel_api::resource::net::PacketPayload::default())
            }
            Some(ContentType::ApplicationData) => {
                // ハンドシェイク完了後のアプリデータ
                inner_data.to_payload().ok_or(TlsError::DecodeError)
            }
            _ => Err(TlsError::UnexpectedMessage),
        }
    }

    /// TLS 1.3: 暗号化ハンドシェイク内の複数メッセージを処理
    pub(super) fn tls13_process_handshake_messages(&mut self, data: &[u8]) -> TlsResult<()> {
        let mut offset = 0usize;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while offset < data.len() {
            if data.len() - offset < 4 {
                return Err(TlsError::DecodeError);
            }

            let msg_type = data[offset];
            let length = ((data[offset + 1] as usize) << 16)
                | ((data[offset + 2] as usize) << 8)
                | data[offset + 3] as usize;
            let body_start = offset + 4;
            let body_end = body_start + length;
            if body_end > data.len() {
                return Err(TlsError::DecodeError);
            }

            let payload = &data[body_start..body_end];
            let full_msg = &data[offset..body_end];

            self.tls13_dispatch_handshake_msg(msg_type, payload)?;

            self.append_transcript_bytes(full_msg)?;

            if msg_type == 20 {
                self.transcript_state.snapshot_server_finished();
            }

            offset = body_end;
        }
        Ok(())
    }

    /// Dispatch a single TLS 1.3 handshake message to its handler.
    pub(super) fn tls13_dispatch_handshake_msg(
        &mut self,
        msg_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
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
                    self.early_data_accepted = true;
                }
                _ => {
                    // 他の拡張は無視（ALPN等は将来対応）
                }
            }
            eoff += ext_len;
        }

        // PSK使用+Early Data送信済みだがacceptされていない場合、バッファは保持（再送用）
        self.state = TlsState::Tls13WaitCertificate;
        Ok(())
    }

    /// TLS 1.3: CertificateRequest を処理 (RFC 8446 Section 4.3.2)
    ///
    /// 構造:
    /// - certificate_request_context length (1 byte)
    /// - certificate_request_context (variable)
    /// - extensions length (2 bytes)
    /// - extensions (variable) — signature_algorithms (type 13) は必須
    pub(super) fn tls13_process_certificate_request(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let ctx_len = data[0] as usize;
        let mut off = 1;

        if data.len() < off + ctx_len {
            return Err(TlsError::DecodeError);
        }
        self.certificate_request_context =
            Some(PayloadSpan::from_bytes(&data[off..off + ctx_len]).ok_or(TlsError::DecodeError)?);
        off += ctx_len;

        // 拡張をパース
        self.tls13_skip_cert_request_extensions(data, off)?;

        self.client_auth_requested = true;
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

    /// X.509 DERからサーバー公開鍵を抽出して設定する。
    pub(super) fn set_server_public_key_from_cert(&mut self, cert_der: &[u8]) -> TlsResult<()> {
        if let Some(cert) = crate::net::security::x509::parse_x509(cert_der) {
            match cert.subject_public_key_info {
                crate::net::security::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                    self.server_public_key = Some(ServerPublicKey::Rsa {
                        modulus: PayloadSpan::from_bytes(modulus).ok_or(TlsError::DecodeError)?,
                        exponent: PayloadSpan::from_bytes(exponent).ok_or(TlsError::DecodeError)?,
                    });
                }
                crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                    self.server_public_key = Some(ServerPublicKey::EcdsaP256 {
                        point: PayloadSpan::from_bytes(public_key).ok_or(TlsError::DecodeError)?,
                    });
                }
                crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
                    self.server_public_key = Some(ServerPublicKey::EcdsaP384 {
                        point: PayloadSpan::from_bytes(public_key).ok_or(TlsError::DecodeError)?,
                    });
                }
                _ => {
                    if !self.config.should_skip_verify() {
                        return Err(TlsError::CertificateError);
                    }
                }
            }
        } else if !self.config.should_skip_verify() {
            return Err(TlsError::CertificateError);
        }
        Ok(())
    }

    /// TLS 1.3: Certificate を処理 (RFC 8446 Section 4.4.2)
    pub(super) fn tls13_process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        let certs = self.tls13_extract_cert_chain(data)?;

        if certs.is_empty() {
            if !self.config.should_skip_verify() {
                return Err(TlsError::CertificateError);
            }
            self.state = TlsState::Tls13WaitCertificateVerify;
            return Ok(());
        }

        if !self.config.should_skip_verify() {
            // 証明書チェーンの検証 (issuerの一致、署名の妥当性、ホスト名の一致、およびルートCAへの信頼)
            let validated_spki = {
                let mut ca_ders = ArrayVec::<&[u8], TLS_CA_CERTS_CAPACITY>::new();
                for cert in &self.config.ca_certs {
                    if let Some(der) = cert.der.as_contiguous_slice() {
                        ca_ders
                            .try_push(der)
                            .map_err(|_| TlsError::CertificateError)?;
                    }
                }
                crate::net::security::x509::validate_certificate_chain(
                    &certs,
                    self.server_name.as_ref().map(|name| name.as_str()),
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

        self.state = TlsState::Tls13WaitCertificateVerify;
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
            self.state = TlsState::Tls13WaitFinished;
            return Ok(());
        }

        self.verify_tls13_certificate_verify(sig_algorithm, signature)?;

        self.state = TlsState::Tls13WaitFinished;
        Ok(())
    }

    fn verify_tls13_certificate_verify(
        &self,
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        const LABEL: &[u8] = b"TLS 1.3, server CertificateVerify";
        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
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
        let pubkey = match &self.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                let modulus = modulus
                    .as_contiguous_slice()
                    .ok_or(TlsError::CertificateError)?;
                let exponent = exponent
                    .as_contiguous_slice()
                    .ok_or(TlsError::CertificateError)?;
                crate::net::security::rsa::RsaPublicKey { modulus, exponent }
            }
            _ => return Err(TlsError::CertificateError),
        };

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
            // Security: SHA-1 is not supported for PSS in TLS 1.3.
            _ => Err(TlsError::CryptoError),
        }
    }

    /// ECDSA P-256 署名検証ヘルパー
    pub(super) fn verify_ecdsa_p256_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.server_public_key {
            Some(ServerPublicKey::EcdsaP256 { point }) => point
                .as_contiguous_slice()
                .ok_or(TlsError::CertificateError)?,
            _ => return Err(TlsError::CertificateError),
        };

        let digest = crate::crypto::sha256::compute(message);

        ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }
}
