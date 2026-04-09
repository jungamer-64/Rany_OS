use super::*;

mod signature_verify;
impl TlsConnection {
    /// AES-GCM レコード暗号化 (TLS 1.2)
    pub(super) fn encrypt_aes_gcm_record(
        &mut self,
        content_type: u8,
        data: &[u8],
    ) -> TlsResult<Vec<u8>> {
        let explicit_nonce = self.write_seq.to_be_bytes();

        if self.write_key.is_empty() || self.write_iv.len() < 4 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.write_iv[0..4]);
        nonce[4..12].copy_from_slice(&explicit_nonce);

        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.write_seq.to_be_bytes());
        aad.push(content_type);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        let (ciphertext, auth_tag) = aes_gcm_encrypt(&self.write_key, &nonce, &aad, data);

        let record_len = 8 + ciphertext.len() + 16;
        let mut record = vec![
            content_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];
        record.extend_from_slice(&explicit_nonce);
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&auth_tag);

        self.write_seq += 1;
        Ok(record)
    }

    /// ChaCha20-Poly1305 レコード暗号化 (TLS 1.2)
    pub(super) fn encrypt_chacha20_record(
        &mut self,
        content_type: u8,
        data: &[u8],
    ) -> TlsResult<Vec<u8>> {
        if self.write_key.is_empty() || self.write_key.len() < 32 || self.write_iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.write_iv[0..12]);
        let seq_bytes = self.write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.write_seq.to_be_bytes());
        aad.push(content_type);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.write_key[0..32]);

        let (ciphertext, auth_tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, data);

        let record_len = ciphertext.len() + 16;
        let mut record = vec![
            content_type,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&auth_tag);

        self.write_seq += 1;
        Ok(record)
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
                self.tls13_psk.as_deref()
            } else {
                None
            };
            let early_secret = tls13_early_secret_sha384(psk_ref);
            let handshake_secret =
                tls13_handshake_secret_sha384(&early_secret, &self.pre_master_secret);

            let chs =
                tls13_derive_secret_sha384(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs =
                tls13_derive_secret_sha384(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.client_hs_traffic_secret = chs;
            self.server_hs_traffic_secret = shs;

            let (server_key, server_iv) = tls13_derive_traffic_keys_sha384(&shs, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys_sha384(&chs, key_len);

            self.hs_read_key = server_key;
            self.hs_read_iv = server_iv;
            self.hs_write_key = client_key;
            self.hs_write_iv = client_iv;
            self.hs_read_seq = 0;
            self.hs_write_seq = 0;

            let ms = tls13_master_secret_sha384(&handshake_secret);
            self.master_secret[..48].copy_from_slice(&ms);

            let mut hasher = crate::crypto::sha384::Sha384::new();
            PacketPayloadView::new(&self.handshake_transcript)
                .for_each_chunk(|chunk| hasher.update(chunk));
            self.transcript_hash = Some(TranscriptHash::Sha384(hasher));
        } else {
            // SHA-256ベース鍵スケジュール
            use crate::crypto::sha256;

            let transcript_ch_sh = {
                let mut hasher = sha256::Sha256::new();
                PacketPayloadView::new(&self.handshake_transcript)
                    .for_each_chunk(|chunk| hasher.update(chunk));
                hasher.finalize()
            };

            let psk_ref_256 = if self.tls13_using_psk {
                self.tls13_psk.as_deref()
            } else {
                None
            };
            let early_secret = tls13_early_secret(psk_ref_256);
            let handshake_secret = tls13_handshake_secret(&early_secret, &self.pre_master_secret);

            let chs = tls13_derive_secret(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs = tls13_derive_secret(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.client_hs_traffic_secret[..32].copy_from_slice(&chs);
            self.server_hs_traffic_secret[..32].copy_from_slice(&shs);

            let (server_key, server_iv) = tls13_derive_traffic_keys(&shs, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys(&chs, key_len);

            self.hs_read_key = server_key;
            self.hs_read_iv = server_iv;
            self.hs_write_key = client_key;
            self.hs_write_iv = client_iv;
            self.hs_read_seq = 0;
            self.hs_write_seq = 0;

            let master_secret_bytes = tls13_master_secret(&handshake_secret);
            self.master_secret[..32].copy_from_slice(&master_secret_bytes);

            let mut new_hasher = sha256::Sha256::new();
            PacketPayloadView::new(&self.handshake_transcript)
                .for_each_chunk(|chunk| new_hasher.update(chunk));
            self.transcript_hash = Some(TranscriptHash::Sha256(new_hasher));
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
        data: &[u8],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        // ハンドシェイクトラフィック鍵で復号
        let decrypted = self.tls13_decrypt_record(data, true)?;

        if decrypted.is_empty() {
            return Err(TlsError::DecodeError);
        }

        // 内部コンテントタイプ = 最後の非ゼロバイト
        // TLS 1.3 record format: plaintext || content_type || zeros
        let mut inner_content_type = 0u8;
        let mut plaintext_len = decrypted.len();
        for i in (0..decrypted.len()).rev() {
            if decrypted[i] != 0 {
                inner_content_type = decrypted[i];
                plaintext_len = i;
                break;
            }
        }

        let inner_data = &decrypted[..plaintext_len];

        match ContentType::from_u8(inner_content_type) {
            Some(ContentType::Handshake) => {
                self.tls13_process_handshake_messages(inner_data)?;
                Ok(kernel_api::resource::net::PacketPayload::default())
            }
            Some(ContentType::Alert) => {
                if inner_data.len() >= 2 {
                    let description = inner_data[1];
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
                Ok(Self::packet_payload_from_slice(inner_data))
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

            // トランスクリプトハッシュを更新
            // (Finishedメッセージ自体もトランスクリプトに含める)
            if let Some(ref mut hasher) = self.transcript_hash {
                hasher.update(full_msg);
            }
            self.append_transcript_bytes(full_msg)?;

            // server Finished追加後のオフセットを記録
            // (アプリケーション鍵導出で「server Finishedまで」のトランスクリプトとして使用)
            if msg_type == 20 {
                self.server_finished_offset = self.transcript_len();
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
        self.certificate_request_context = Some(Self::span_from_bytes(&data[off..off + ctx_len])?);
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
    pub(super) fn tls13_extract_cert_chain<'a>(&self, data: &'a [u8]) -> TlsResult<Vec<&'a [u8]>> {
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
        let mut certs = Vec::new();

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

            certs.push(&data[offset..offset + cert_len]);
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
                        modulus: Self::span_from_bytes(modulus)?,
                        exponent: Self::span_from_bytes(exponent)?,
                    });
                }
                crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                    self.server_public_key = Some(ServerPublicKey::EcdsaP256 {
                        point: Self::span_from_bytes(public_key)?,
                    });
                }
                crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
                    self.server_public_key = Some(ServerPublicKey::EcdsaP384 {
                        point: Self::span_from_bytes(public_key)?,
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
            let ca_ders: Vec<&[u8]> = self
                .config
                .ca_certs
                .iter()
                .filter_map(|c| c.der.as_contiguous_slice())
                .collect();
            if let Some(spki) = crate::net::security::x509::validate_certificate_chain(
                &certs,
                self.config.server_name.as_deref(),
                &ca_ders,
            ) {
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

        let verify_content =
            self.build_tls13_cv_verify_content(b"TLS 1.3, server CertificateVerify");

        self.dispatch_tls13_signature_verification(sig_algorithm, &verify_content, signature)?;

        self.state = TlsState::Tls13WaitFinished;
        Ok(())
    }

    /// TLS 1.3 CertificateVerify用の検証対象コンテンツを構築
    ///
    /// RFC 8446 Section 4.4.3:
    /// content = 64 * 0x20 || label || 0x00 || transcript_hash
    pub(super) fn build_tls13_cv_verify_content(&self, label: &[u8]) -> Vec<u8> {
        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        let transcript_hash: Vec<u8> = if use_384 {
            self.transcript_hash_sha384().to_vec()
        } else {
            self.transcript_hash_sha256().to_vec()
        };

        let mut content = Vec::with_capacity(64 + label.len() + 1 + transcript_hash.len());
        content.extend_from_slice(&[0x20u8; 64]);
        content.extend_from_slice(label);
        content.push(0x00);
        content.extend_from_slice(&transcript_hash);
        content
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
