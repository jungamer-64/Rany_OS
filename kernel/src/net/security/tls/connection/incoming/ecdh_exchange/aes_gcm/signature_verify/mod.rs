use alloc::vec::Vec;

use super::*;

mod encrypt_decrypt;
impl TlsConnection {
    /// ECDSA P-384 署名検証ヘルパー
    pub(super) fn verify_ecdsa_p384_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.server_public_key {
            Some(ServerPublicKey::EcdsaP384 { point }) => point
                .as_contiguous_slice()
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

        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());

        // Finished の verify_data を検証
        // トランスクリプトハッシュは Finished メッセージ自体を含まない状態で計算
        if use_384 {
            let transcript = self.transcript_hash_sha384();
            let mut shs = [0u8; 48];
            shs.copy_from_slice(&self.server_hs_traffic_secret[..48]);
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
            shs.copy_from_slice(&self.server_hs_traffic_secret[..32]);
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

        self.state = TlsState::Tls13ServerFinishedReceived;
        Ok(())
    }

    /// EndOfEarlyDataレコードを構築する (RFC 8446 Section 4.5)
    pub(super) fn build_end_of_early_data_record(
        &mut self,
    ) -> TlsResult<Option<kernel_api::resource::net::PacketPayload>> {
        if !self.early_data_sent || !self.early_data_accepted {
            return Ok(None);
        }

        let eoed_msg: [u8; 4] = [5, 0, 0, 0];

        self.append_transcript_bytes(&eoed_msg)?;

        if self.early_write_key.is_empty() || self.early_write_iv.len() < 12 {
            return Ok(None);
        }

        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let inner = [
            eoed_msg[0],
            eoed_msg[1],
            eoed_msg[2],
            eoed_msg[3],
            ContentType::Handshake as u8,
        ];

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.early_write_iv.as_slice()[..12]);
        let seq_bytes = self.early_write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = inner.len() + 16;
        let aad = Self::tls13_record_aad(encrypted_len);

        let (ciphertext, auth_tag) = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&self.early_write_key.as_slice()[..32]);
            chacha20_poly1305_encrypt(&key_arr, &nonce, &aad, &inner)
        } else {
            aes_gcm_encrypt(self.early_write_key.as_slice(), &nonce, &aad, &inner)
        };

        let encrypted_len_bytes = (encrypted_len as u16).to_be_bytes();
        let record_header = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            encrypted_len_bytes[0],
            encrypted_len_bytes[1],
        ];

        self.early_write_seq += 1;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        builder
            .push_bytes(&ciphertext)
            .ok_or(TlsError::DecodeError)?;
        builder.push_bytes(&auth_tag).ok_or(TlsError::DecodeError)?;
        Ok(Some(builder.build()))
    }

    /// 空のCertificateメッセージレコードを構築する (RFC 8446 Section 4.4.2)
    pub(super) fn build_empty_certificate_record(
        &mut self,
    ) -> TlsResult<Option<kernel_api::resource::net::PacketPayload>> {
        if !self.client_auth_requested {
            return Ok(None);
        }

        let ctx = self
            .certificate_request_context
            .as_ref()
            .and_then(|span| span.as_contiguous_slice())
            .unwrap_or(&[]);
        let ctx_len = ctx.len();
        let cert_body_len = 1 + ctx_len + 3;
        let mut cert_msg = Vec::with_capacity(4 + cert_body_len);
        cert_msg.push(11); // Certificate type
        cert_msg.push(0);
        cert_msg.push(((cert_body_len >> 8) & 0xFF) as u8);
        cert_msg.push((cert_body_len & 0xFF) as u8);
        cert_msg.push(ctx_len as u8);
        cert_msg.extend_from_slice(ctx);
        cert_msg.extend_from_slice(&[0, 0, 0]); // empty certificate_list

        self.append_transcript_bytes(&cert_msg)?;

        let mut inner_cert = cert_msg;
        inner_cert.push(ContentType::Handshake as u8);
        let encrypted_cert = self.tls13_encrypt_record(&inner_cert, true)?;
        Ok(Some(encrypted_cert))
    }

    /// TLS 1.3 クライアントFinished verify_data を計算する
    pub(super) fn compute_tls13_client_verify_data(&self) -> ([u8; 48], usize) {
        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        if use_384 {
            let transcript = self.transcript_hash_sha384();
            let mut chs = [0u8; 48];
            chs.copy_from_slice(&self.client_hs_traffic_secret[..48]);
            let finished_key = tls13_finished_key_sha384(&chs);
            (
                tls13_verify_data_sha384(&finished_key, &transcript),
                SHA384_OUTPUT_SIZE,
            )
        } else {
            let transcript = self.transcript_hash_sha256();
            let mut chs = [0u8; 32];
            chs.copy_from_slice(&self.client_hs_traffic_secret[..32]);
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
        if !self.is_tls13 || self.state != TlsState::Tls13ServerFinishedReceived {
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
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();
        if use_384 {
            let transcript_sf = self
                .transcript_state
                .server_finished_sha384()
                .unwrap_or_else(|| self.transcript_hash_sha384());
            let mut master_secret = [0u8; 48];
            master_secret.copy_from_slice(&self.master_secret[..48]);

            let cas = tls13_derive_secret_sha384(&master_secret, b"c ap traffic", &transcript_sf);
            let sas = tls13_derive_secret_sha384(&master_secret, b"s ap traffic", &transcript_sf);
            self.client_app_traffic_secret = cas;
            self.server_app_traffic_secret = sas;

            let (server_key, server_iv) = tls13_derive_traffic_keys_sha384(&sas, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys_sha384(&cas, key_len);

            Self::set_tls_bytes(&mut self.read_key, &server_key)?;
            Self::set_tls_bytes(&mut self.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.write_key, &client_key)?;
            Self::set_tls_bytes(&mut self.write_iv, &client_iv)?;
        } else {
            let transcript_sf = self
                .transcript_state
                .server_finished_sha256()
                .unwrap_or_else(|| self.transcript_hash_sha256());
            let mut master_secret = [0u8; 32];
            master_secret.copy_from_slice(&self.master_secret[..32]);

            let cas = tls13_derive_secret(&master_secret, b"c ap traffic", &transcript_sf);
            let sas = tls13_derive_secret(&master_secret, b"s ap traffic", &transcript_sf);
            self.client_app_traffic_secret[..32].copy_from_slice(&cas);
            self.server_app_traffic_secret[..32].copy_from_slice(&sas);

            let (server_key, server_iv) = tls13_derive_traffic_keys(&sas, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys(&cas, key_len);

            Self::set_tls_bytes(&mut self.read_key, &server_key)?;
            Self::set_tls_bytes(&mut self.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.write_key, &client_key)?;
            Self::set_tls_bytes(&mut self.write_iv, &client_iv)?;
        }

        // resumption_master_secret を導出 (RFC 8446 Section 7.1)
        // RMS = Derive-Secret(master_secret, "res master", transcript_with_client_finished)
        // transcript には client Finished を含む全メッセージが含まれている
        if use_384 {
            let transcript_cf = self.transcript_hash_sha384();
            let mut ms48 = [0u8; 48];
            ms48.copy_from_slice(&self.master_secret[..48]);
            let rms = tls13_derive_secret_sha384(&ms48, b"res master", &transcript_cf);
            Self::set_tls_bytes(&mut self.resumption_master_secret, &rms)?;
        } else {
            let transcript_cf = self.transcript_hash_sha256();
            let mut ms32 = [0u8; 32];
            ms32.copy_from_slice(&self.master_secret[..32]);
            let rms = tls13_derive_secret(&ms32, b"res master", &transcript_cf);
            Self::set_tls_bytes(&mut self.resumption_master_secret, &rms)?;
        }

        self.read_seq = 0;
        self.write_seq = 0;
        self.state = TlsState::Established;
        Ok(())
    }

    // ========================================================================
    // TLS 1.3 Record Layer
    // ========================================================================

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
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_decrypt(&key_arr, nonce, aad, ciphertext, tag)
                .and_then(|plaintext| {
                    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                    builder.push_bytes(&plaintext)?;
                    Some(builder.build())
                })
                .ok_or(TlsError::DecryptError)
        } else {
            aes_gcm_decrypt(key, nonce, aad, ciphertext, tag)
                .and_then(|plaintext| {
                    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                    builder.push_bytes(&plaintext)?;
                    Some(builder.build())
                })
                .ok_or(TlsError::DecryptError)
        }
    }

    /// TLS 1.3: レコード復号
    ///
    /// TLS 1.3のAEAD nonce = IV XOR seq_num
    /// AAD = TLS record header（5バイト: type || legacy_version || length）
    ///
    /// `is_handshake`: trueの場合ハンドシェイク鍵、falseの場合アプリケーション鍵を使用
    pub(crate) fn tls13_decrypt_record(
        &mut self,
        data: &kernel_api::resource::net::PacketPayload,
        is_handshake: bool,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        // 鍵・IV・シーケンス番号を選択
        let (key, iv, seq) = if is_handshake {
            (&self.hs_read_key, &self.hs_read_iv, self.hs_read_seq)
        } else {
            (&self.read_key, &self.read_iv, self.read_seq)
        };

        if key.is_empty() || iv.len() < 12 {
            return Err(TlsError::DecryptError);
        }

        let data_view = crate::net::payload::PacketPayloadView::new(data);
        let data_bytes = data_view.read_vec(0, data_view.total_len());
        if data_bytes.len() != data_view.total_len() {
            return Err(TlsError::DecodeError);
        }
        let (nonce, aad) = Self::build_tls13_nonce_and_aad(iv.as_slice(), seq, data_bytes.len());

        if data_bytes.len() < 16 {
            return Err(TlsError::DecryptError);
        }

        let ciphertext_len = data_bytes.len() - 16;
        let ciphertext = &data_bytes[..ciphertext_len];
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data_bytes[ciphertext_len..]);

        let plaintext = Self::decrypt_aead(cipher, key.as_slice(), &nonce, &aad, ciphertext, &tag)?;

        // シーケンス番号をインクリメント
        if is_handshake {
            self.hs_read_seq += 1;
        } else {
            self.read_seq += 1;
        }

        Ok(plaintext)
    }

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
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let (key, iv, seq) = if is_handshake {
            (&self.hs_write_key, &self.hs_write_iv, self.hs_write_seq)
        } else {
            (&self.write_key, &self.write_iv, self.write_seq)
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

        let (ciphertext, auth_tag) = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key.as_slice()[..32]);
            chacha20_poly1305_encrypt(&key_arr, &nonce, &aad, inner_plaintext)
        } else {
            aes_gcm_encrypt(key.as_slice(), &nonce, &aad, inner_plaintext)
        };

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
            self.hs_write_seq += 1;
        } else {
            self.write_seq += 1;
        }

        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        builder
            .push_bytes(&ciphertext)
            .ok_or(TlsError::DecodeError)?;
        builder.push_bytes(&auth_tag).ok_or(TlsError::DecodeError)?;
        Ok(builder.build())
    }

    /// TLS 1.3 アプリケーションデータ暗号化
    pub(crate) fn tls13_encrypt_application_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let payload_view = crate::net::payload::PacketPayloadView::new(payload);
        let data = payload_view.read_vec(0, payload_view.total_len());
        if data.len() != payload_view.total_len() {
            return Err(TlsError::DecodeError);
        }
        // inner plaintext = data + content_type
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(&data);
        inner.push(ContentType::ApplicationData as u8);
        self.tls13_encrypt_record(&inner, false)
    }

    /// フルハンドシェイク完了後にセッションをキャッシュに保存する
    pub(super) fn cache_session_if_needed(&mut self) {
        if self.resuming_session || self.session_id.0 == [0u8; 32] {
            return;
        }
        if self.session_cache.is_none() {
            self.session_cache = Some(SessionCache::new(8));
        }
        if let Some(ref mut cache) = self.session_cache {
            cache.insert(SessionCacheEntry {
                session_id: self.session_id.0,
                master_secret: self.master_secret,
                cipher_suite: self
                    .negotiated_cipher
                    .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256),
                server_name: self.config.server_name.clone(),
                version: self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2),
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
        if self.write_key.is_empty() {
            self.derive_tls12_keys()?;
        }

        self.state = TlsState::Established;
        self.cache_session_if_needed();

        Ok(())
    }

    /// レコードを復号
    pub(crate) fn decrypt_record(
        &mut self,
        data: &kernel_api::resource::net::PacketPayload,
        content_type: u8,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let data_view = crate::net::payload::PacketPayloadView::new(data);
        let data_bytes = data_view.read_vec(0, data_view.total_len());
        if data_bytes.len() != data_view.total_len() {
            return Err(TlsError::DecodeError);
        }
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if cipher.is_cbc() {
            self.decrypt_cbc_record(&data_bytes, content_type)
        } else if cipher.is_chacha20_poly1305() {
            self.decrypt_chacha20_poly1305(&data_bytes, content_type)
        } else {
            self.decrypt_aes_gcm(&data_bytes, content_type)
        }
    }

    /// AES-GCM record decryption (TLS 1.2)
    pub(super) fn decrypt_aes_gcm(
        &mut self,
        data: &[u8],
        content_type: u8,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
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

        // Security: Fail securely if keys are not configured.
        // Returning ciphertext as plaintext allows injection attacks!
        if self.read_key.is_empty() || self.read_iv.len() < 4 {
            return Err(TlsError::DecryptError);
        }

        // 12バイトのnonceを構築: implicit_iv(4) || explicit_nonce(8)
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.read_iv.as_slice()[0..4]);
        nonce[4..12].copy_from_slice(explicit_nonce);

        // AAD: seq_num(8) || type(1) || version(2) || length(2)
        let aad = Self::tls12_aad(self.read_seq, content_type, ciphertext_len);

        // 認証タグを配列に変換
        let mut tag = [0u8; 16];
        tag.copy_from_slice(auth_tag);

        // AES-GCM復号
        match aes_gcm_decrypt(self.read_key.as_slice(), &nonce, &aad, ciphertext, &tag) {
            Some(plaintext) => {
                self.read_seq += 1;
                let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                builder
                    .push_bytes(&plaintext)
                    .ok_or(TlsError::DecodeError)?;
                Ok(builder.build())
            }
            None => Err(TlsError::DecryptError),
        }
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
        if data.len() < 16 {
            // Minimum: tag(16), no ciphertext is allowed (empty message)
            return Err(TlsError::DecodeError);
        }

        let ciphertext_len = data.len() - 16;
        let ciphertext = &data[0..ciphertext_len];
        let auth_tag = &data[ciphertext_len..];

        // Keys not set — return error (decryption requires valid keys)
        if self.read_key.is_empty() || self.read_key.len() < 32 || self.read_iv.len() < 12 {
            return Err(TlsError::CryptoError);
        }

        // Construct 12-byte nonce: IV XOR (zero-padded sequence number)
        // RFC 7905: nonce = iv XOR pad64(seq_num)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.read_iv.as_slice()[0..12]);
        let seq_bytes = self.read_seq.to_be_bytes(); // 8 bytes
        // XOR seq_num into the last 8 bytes of the nonce
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // AAD: seq_num(8) || type(1) || version(2) || length(2)
        let aad = Self::tls12_aad(self.read_seq, content_type, ciphertext_len);

        // Convert key and tag to fixed-size arrays
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.read_key.as_slice()[0..32]);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(auth_tag);

        match chacha20_poly1305_decrypt(&key, &nonce, &aad, ciphertext, &tag) {
            Some(plaintext) => {
                self.read_seq += 1;
                let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                builder
                    .push_bytes(&plaintext)
                    .ok_or(TlsError::DecodeError)?;
                Ok(builder.build())
            }
            None => Err(TlsError::DecryptError),
        }
    }
}
