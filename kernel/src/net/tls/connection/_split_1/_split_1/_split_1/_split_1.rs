use super::*;

mod _split_1;
pub use _split_1::*;
impl TlsConnection {

    /// ECDSA P-384 署名検証ヘルパー
    pub(super) fn verify_ecdsa_p384_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.server_public_key {
            Some(ServerPublicKey::EcdsaP384 { point }) => point.as_slice(),
            _ => return Err(TlsError::CertificateError),
        };

        let digest = crate::loader::sha384::compute(message);

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
            let transcript = crate::loader::sha384::compute(&self.handshake_messages);
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
            let transcript = {
                let mut hasher = crate::loader::sha256::Sha256::new();
                hasher.update(&self.handshake_messages);
                hasher.finalize()
            };
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
    pub(super) fn build_end_of_early_data_record(&mut self) -> TlsResult<Option<Vec<u8>>> {
        if !self.early_data_sent || !self.early_data_accepted {
            return Ok(None);
        }

        let eoed_msg: [u8; 4] = [5, 0, 0, 0];

        if let Some(ref mut hasher) = self.transcript_hash {
            hasher.update(&eoed_msg);
        }
        self.handshake_messages.extend_from_slice(&eoed_msg);

        if self.early_write_key.is_empty() || self.early_write_iv.len() < 12 {
            return Ok(None);
        }

        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let mut inner = Vec::with_capacity(5);
        inner.extend_from_slice(&eoed_msg);
        inner.push(ContentType::Handshake as u8);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.early_write_iv[..12]);
        let seq_bytes = self.early_write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = inner.len() + 16;
        let mut aad = Vec::with_capacity(5);
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(encrypted_len as u16).to_be_bytes());

        let (ciphertext, auth_tag) = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&self.early_write_key[..32]);
            chacha20_poly1305_encrypt(&key_arr, &nonce, &aad, &inner)
        } else {
            aes_gcm_encrypt(&self.early_write_key, &nonce, &aad, &inner)
        };

        let mut eoed_record = Vec::with_capacity(5 + encrypted_len);
        eoed_record.push(ContentType::ApplicationData as u8);
        eoed_record.extend_from_slice(&[0x03, 0x03]);
        eoed_record.extend_from_slice(&(encrypted_len as u16).to_be_bytes());
        eoed_record.extend_from_slice(&ciphertext);
        eoed_record.extend_from_slice(&auth_tag);

        self.early_write_seq += 1;
        Ok(Some(eoed_record))
    }

    /// 空のCertificateメッセージレコードを構築する (RFC 8446 Section 4.4.2)
    pub(super) fn build_empty_certificate_record(&mut self) -> TlsResult<Option<Vec<u8>>> {
        if !self.client_auth_requested {
            return Ok(None);
        }

        let ctx = &self.certificate_request_context;
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

        if let Some(ref mut hasher) = self.transcript_hash {
            hasher.update(&cert_msg);
        }
        self.handshake_messages.extend_from_slice(&cert_msg);

        let mut inner_cert = cert_msg;
        inner_cert.push(ContentType::Handshake as u8);
        let encrypted_cert = self.tls13_encrypt_record(&inner_cert, true)?;
        Ok(Some(encrypted_cert))
    }

    /// TLS 1.3 クライアントFinished verify_data を計算する
    pub(super) fn compute_tls13_client_verify_data(&self) -> Vec<u8> {
        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        if use_384 {
            let transcript = crate::loader::sha384::compute(&self.handshake_messages);
            let mut chs = [0u8; 48];
            chs.copy_from_slice(&self.client_hs_traffic_secret[..48]);
            let finished_key = tls13_finished_key_sha384(&chs);
            tls13_verify_data_sha384(&finished_key, &transcript).to_vec()
        } else {
            let transcript = {
                let mut hasher = crate::loader::sha256::Sha256::new();
                hasher.update(&self.handshake_messages);
                hasher.finalize()
            };
            let mut chs = [0u8; 32];
            chs.copy_from_slice(&self.client_hs_traffic_secret[..32]);
            let finished_key = tls13_finished_key(&chs);
            tls13_verify_data(&finished_key, &transcript).to_vec()
        }
    }

    /// TLS 1.3: クライアントFinishedメッセージを構築
    ///
    /// サーバーFinished受信後に呼び出す。
    /// アプリケーション鍵の導出も同時に行う。
    /// EndOfEarlyData + 空Certificateなど、Finished前のレコードを構築する
    pub(super) fn build_pre_finished_records_tls13(&mut self) -> TlsResult<Vec<u8>> {
        let mut records = Vec::new();
        if let Some(eoed_record) = self.build_end_of_early_data_record()? {
            records.extend_from_slice(&eoed_record);
        }
        if let Some(cert_record) = self.build_empty_certificate_record()? {
            records.extend_from_slice(&cert_record);
        }
        Ok(records)
    }

    pub fn build_client_finished_tls13(&mut self) -> TlsResult<Vec<u8>> {
        if !self.is_tls13 || self.state != TlsState::Tls13ServerFinishedReceived {
            return Err(TlsError::UnexpectedMessage);
        }

        let mut records = self.build_pre_finished_records_tls13()?;

        let verify_data_vec = self.compute_tls13_client_verify_data();
        let hash_len = self.hash_len();

        // Finished ハンドシェイクメッセージ
        let mut finished_msg = Vec::with_capacity(4 + hash_len);
        finished_msg.push(20); // Finished type
        finished_msg.push(0);
        finished_msg.push(0);
        finished_msg.push(hash_len as u8);
        finished_msg.extend_from_slice(&verify_data_vec);

        // トランスクリプトハッシュを更新（クライアントFinished含む）
        if let Some(ref mut hasher) = self.transcript_hash {
            hasher.update(&finished_msg);
        }
        self.handshake_messages.extend_from_slice(&finished_msg);

        // TLS 1.3レコードとして暗号化
        let mut inner = finished_msg;
        inner.push(ContentType::Handshake as u8);

        let encrypted = self.tls13_encrypt_record(&inner, true)?;

        // アプリケーション鍵の導出
        self.tls13_derive_application_keys()?;

        records.extend_from_slice(&encrypted);
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
        let hash_len = self.hash_len();

        // トランスクリプトハッシュ (ClientHello...server Finished)
        // server_finished_offset を使用して正確な境界を取得
        // (EndOfEarlyData, Certificate等がClientFinished前に追加されうるため、
        //  単純な client_finished_len 差し引きでは不正確)
        let sf_offset = if self.server_finished_offset > 0 {
            self.server_finished_offset
        } else {
            // フォールバック: 以前の挙動
            let client_finished_len = 4 + hash_len;
            self.handshake_messages.len().saturating_sub(client_finished_len)
        };
        let msgs_before_cf = &self.handshake_messages[..sf_offset];

        if use_384 {
            let transcript_sf = crate::loader::sha384::compute(msgs_before_cf);
            let mut master_secret = [0u8; 48];
            master_secret.copy_from_slice(&self.master_secret[..48]);

            let cas = tls13_derive_secret_sha384(&master_secret, b"c ap traffic", &transcript_sf);
            let sas = tls13_derive_secret_sha384(&master_secret, b"s ap traffic", &transcript_sf);
            self.client_app_traffic_secret = cas;
            self.server_app_traffic_secret = sas;

            let (server_key, server_iv) = tls13_derive_traffic_keys_sha384(&sas, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys_sha384(&cas, key_len);

            self.read_key = server_key;
            self.read_iv = server_iv;
            self.write_key = client_key;
            self.write_iv = client_iv;
        } else {
            let transcript_sf = {
                let mut hasher = crate::loader::sha256::Sha256::new();
                hasher.update(msgs_before_cf);
                hasher.finalize()
            };
            let mut master_secret = [0u8; 32];
            master_secret.copy_from_slice(&self.master_secret[..32]);

            let cas = tls13_derive_secret(&master_secret, b"c ap traffic", &transcript_sf);
            let sas = tls13_derive_secret(&master_secret, b"s ap traffic", &transcript_sf);
            self.client_app_traffic_secret[..32].copy_from_slice(&cas);
            self.server_app_traffic_secret[..32].copy_from_slice(&sas);

            let (server_key, server_iv) = tls13_derive_traffic_keys(&sas, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys(&cas, key_len);

            self.read_key = server_key;
            self.read_iv = server_iv;
            self.write_key = client_key;
            self.write_iv = client_iv;
        }

        // resumption_master_secret を導出 (RFC 8446 Section 7.1)
        // RMS = Derive-Secret(master_secret, "res master", transcript_with_client_finished)
        // handshake_messages には client Finished を含む全メッセージが含まれている
        if use_384 {
            let transcript_cf = crate::loader::sha384::compute(&self.handshake_messages);
            let mut ms48 = [0u8; 48];
            ms48.copy_from_slice(&self.master_secret[..48]);
            let rms = tls13_derive_secret_sha384(&ms48, b"res master", &transcript_cf);
            self.resumption_master_secret = rms.to_vec();
        } else {
            let transcript_cf = {
                let mut h = crate::loader::sha256::Sha256::new();
                h.update(&self.handshake_messages);
                h.finalize()
            };
            let mut ms32 = [0u8; 32];
            ms32.copy_from_slice(&self.master_secret[..32]);
            let rms = tls13_derive_secret(&ms32, b"res master", &transcript_cf);
            self.resumption_master_secret = rms.to_vec();
        }

        self.read_seq = 0;
        self.write_seq = 0;
        self.state = TlsState::Established;
        Ok(())
    }

    // ========================================================================
    // TLS 1.3 Record Layer
    // ========================================================================

    pub(super) fn build_tls13_nonce_and_aad(iv: &[u8], seq: u64, data_len: usize) -> ([u8; 12], Vec<u8>) {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv[..12]);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        let mut aad = Vec::with_capacity(5);
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data_len as u16).to_be_bytes());
        (nonce, aad)
    }

    pub(super) fn decrypt_aead(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> TlsResult<Vec<u8>> {
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_decrypt(&key_arr, nonce, aad, ciphertext, tag)
                .ok_or(TlsError::DecryptError)
        } else {
            aes_gcm_decrypt(key, nonce, aad, ciphertext, tag)
                .ok_or(TlsError::DecryptError)
        }
    }

    /// TLS 1.3: レコード復号
    ///
    /// TLS 1.3のAEAD nonce = IV XOR seq_num
    /// AAD = TLS record header（5バイト: type || legacy_version || length）
    ///
    /// `is_handshake`: trueの場合ハンドシェイク鍵、falseの場合アプリケーション鍵を使用
    pub(crate) fn tls13_decrypt_record(&mut self, data: &[u8], is_handshake: bool) -> TlsResult<Vec<u8>> {
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

        let (nonce, aad) = Self::build_tls13_nonce_and_aad(iv, seq, data.len());

        if data.len() < 16 {
            return Err(TlsError::DecryptError);
        }

        let ciphertext_len = data.len() - 16;
        let ciphertext = &data[..ciphertext_len];
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[ciphertext_len..]);

        let plaintext = Self::decrypt_aead(cipher, key, &nonce, &aad, ciphertext, &tag)?;

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
    ) -> TlsResult<Vec<u8>> {
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
        nonce.copy_from_slice(&iv[..12]);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // 暗号文 + タグの長さ
        let encrypted_len = inner_plaintext.len() + 16;

        // AAD: TLS record header
        let mut aad = Vec::with_capacity(5);
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(encrypted_len as u16).to_be_bytes());

        let (ciphertext, auth_tag) = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_encrypt(&key_arr, &nonce, &aad, inner_plaintext)
        } else {
            aes_gcm_encrypt(key, &nonce, &aad, inner_plaintext)
        };

        // TLS record
        let mut record = Vec::with_capacity(5 + encrypted_len);
        record.push(ContentType::ApplicationData as u8);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(encrypted_len as u16).to_be_bytes());
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&auth_tag);

        // シーケンス番号をインクリメント
        if is_handshake {
            self.hs_write_seq += 1;
        } else {
            self.write_seq += 1;
        }

        Ok(record)
    }

    /// TLS 1.3 アプリケーションデータ暗号化
    pub(crate) fn tls13_encrypt_application_data(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // inner plaintext = data + content_type
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
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
                cipher_suite: self.negotiated_cipher
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
    pub(crate) fn decrypt_record(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if cipher.is_cbc() {
            self.decrypt_cbc_record(data, ContentType::ApplicationData as u8)
        } else if cipher.is_chacha20_poly1305() {
            self.decrypt_chacha20_poly1305(data)
        } else {
            self.decrypt_aes_gcm(data)
        }
    }

    /// AES-GCM record decryption (TLS 1.2)
    pub(super) fn decrypt_aes_gcm(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
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

        // キーが設定されていない場合はプレースホルダー動作
        if self.read_key.is_empty() || self.read_iv.len() < 4 {
            self.read_seq += 1;
            return Ok(ciphertext.to_vec());
        }

        // 12バイトのnonceを構築: implicit_iv(4) || explicit_nonce(8)
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.read_iv[0..4]);
        nonce[4..12].copy_from_slice(explicit_nonce);

        // AAD: seq_num(8) || type(1) || version(2) || length(2)
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.read_seq.to_be_bytes());
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        aad.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());

        // 認証タグを配列に変換
        let mut tag = [0u8; 16];
        tag.copy_from_slice(auth_tag);

        // AES-GCM復号
        match aes_gcm_decrypt(&self.read_key, &nonce, &aad, ciphertext, &tag) {
            Some(plaintext) => {
                self.read_seq += 1;
                Ok(plaintext)
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
    pub(super) fn decrypt_chacha20_poly1305(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if data.len() < 16 {
            // Minimum: tag(16), no ciphertext is allowed (empty message)
            return Err(TlsError::DecodeError);
        }

        let ciphertext_len = data.len() - 16;
        let ciphertext = &data[0..ciphertext_len];
        let auth_tag = &data[ciphertext_len..];

        // Keys not set — placeholder passthrough
        if self.read_key.is_empty() || self.read_key.len() < 32 || self.read_iv.len() < 12 {
            self.read_seq += 1;
            return Ok(ciphertext.to_vec());
        }

        // Construct 12-byte nonce: IV XOR (zero-padded sequence number)
        // RFC 7905: nonce = iv XOR pad64(seq_num)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.read_iv[0..12]);
        let seq_bytes = self.read_seq.to_be_bytes(); // 8 bytes
        // XOR seq_num into the last 8 bytes of the nonce
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // AAD: seq_num(8) || type(1) || version(2) || length(2)
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.read_seq.to_be_bytes());
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        aad.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());

        // Convert key and tag to fixed-size arrays
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.read_key[0..32]);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(auth_tag);

        match chacha20_poly1305_decrypt(&key, &nonce, &aad, ciphertext, &tag) {
            Some(plaintext) => {
                self.read_seq += 1;
                Ok(plaintext)
            }
            None => Err(TlsError::DecryptError),
        }
    }
}
