use super::*;

mod aes_gcm;
impl TlsConnection {
    /// NamedGroup値をEcdhGroupに変換する
    pub(super) fn named_curve_to_ecdh_group(named_curve: u16) -> TlsResult<ecdh::EcdhGroup> {
        match named_curve {
            0x0017 => Ok(ecdh::EcdhGroup::Secp256r1),
            0x001D => Ok(ecdh::EcdhGroup::X25519),
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// ECDH鍵交換を実行する
    ///
    /// NamedGroup → 鍵ペア生成 → 共有秘密計算を一括で行う。
    pub(super) fn perform_ecdh_exchange(
        named_curve: u16,
        server_pubkey: &[u8],
    ) -> TlsResult<(ecdh::EcdhKeyPair, Vec<u8>)> {
        let group = Self::named_curve_to_ecdh_group(named_curve)?;
        let local_keypair =
            ecdh::EcdhKeyPair::generate(group).map_err(|_| TlsError::CryptoError)?;
        let shared_secret = local_keypair
            .shared_secret(server_pubkey)
            .map_err(|_| TlsError::CryptoError)?;
        Ok((local_keypair, shared_secret))
    }

    /// ServerKeyExchangeを処理
    ///
    /// ECDHEの場合、サーバー公開鍵を受け取り、クライアント側で
    /// 一時鍵ペアを生成してECDH共有秘密を計算する。
    pub(super) fn process_server_key_exchange(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 4 {
            return Err(TlsError::DecodeError);
        }

        let curve_type = data[0];
        if curve_type != 0x03 {
            return Err(TlsError::UnsupportedCipherSuite);
        }

        let named_curve = ((data[1] as u16) << 8) | (data[2] as u16);
        let pubkey_len = data[3] as usize;

        if data.len() < 4 + pubkey_len {
            return Err(TlsError::DecodeError);
        }

        let server_pubkey = &data[4..4 + pubkey_len];
        let ecdhe_params_end = 4 + pubkey_len;

        // 署名検証 (skip_verify でなければ)
        if !self.config.should_skip_verify() {
            self.verify_ske_signature(data, ecdhe_params_end)?;
        }

        // ECDH鍵交換: NamedGroup → 鍵ペア生成 → 共有秘密計算
        let (local_keypair, shared_secret) =
            Self::perform_ecdh_exchange(named_curve, server_pubkey)?;

        self.local_ecdh_keypair = Some(local_keypair);
        self.pre_master_secret = shared_secret;

        // Master secret導出（RFC 5246 Section 8.1）
        self.master_secret = derive_master_secret(
            &self.pre_master_secret,
            &self.client_random,
            &self.server_random,
        );

        Ok(())
    }

    /// ClientKeyExchangeメッセージ構築（TLS 1.2 ECDHE）
    ///
    /// クライアントの一時公開鍵をサーバーに送信する。
    /// `process_server_key_exchange()` の後に呼び出す。
    pub fn build_client_key_exchange_payload(&mut self) -> Option<kernel_api::resource::net::PacketPayload> {
        let keypair = self.local_ecdh_keypair.as_ref()?;
        let pubkey_bytes = keypair.public_key_bytes();

        // ECPoint format: length(1) + point(N)
        let mut body = Vec::with_capacity(1 + pubkey_bytes.len());
        body.push(pubkey_bytes.len() as u8);
        body.extend_from_slice(&pubkey_bytes);

        // Handshakeヘッダ: type(1) + length(3)
        let mut message = Vec::with_capacity(4 + body.len());
        message.push(16); // ClientKeyExchange type = 16
        message.push(0);
        message.push((body.len() >> 8) as u8);
        message.push(body.len() as u8);
        message.extend_from_slice(&body);

        // ハンドシェイクメッセージを記録（Finished verify用）
        self.append_transcript_bytes(&message)
            .expect("tls12 client key exchange transcript append");

        // TLSレコードヘッダ
        let mut record = Vec::with_capacity(5 + message.len());
        record.push(ContentType::Handshake as u8);
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        record.push((message.len() >> 8) as u8);
        record.push(message.len() as u8);
        record.extend_from_slice(&message);

        Some(Self::packet_payload_from_vec(record))
    }

    /// ServerHelloDoneを処理
    pub(super) fn process_server_hello_done(&mut self, _data: &[u8]) -> TlsResult<()> {
        self.state = TlsState::Handshaking;
        Ok(())
    }

    // ========================================================================
    // TLS 1.2 ChangeCipherSpec / Client Finished
    // ========================================================================

    /// ChangeCipherSpecレコードを構築 (TLS 1.2)
    ///
    /// RFC 5246 Section 7.1:
    /// ChangeCipherSpec = { type(20), major, minor, length(1), 1 }
    pub fn build_change_cipher_spec_payload(&mut self) -> kernel_api::resource::net::PacketPayload {
        self.write_encryption_active = true;
        Self::packet_payload_from_slice(&[
            ContentType::ChangeCipherSpec as u8,
            0x03,
            0x03, // TLS 1.2
            0x00,
            0x01, // length = 1
            0x01, // change_cipher_spec
        ])
    }

    /// Master secretが未導出の場合に導出する（TLS 1.2）
    pub(super) fn ensure_master_secret_derived(&mut self) {
        if !self.master_secret.iter().all(|&b| b == 0) {
            return;
        }
        if self.pre_master_secret.is_empty() {
            return;
        }
        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        self.master_secret = if version <= TlsVersion::TLS_1_1 {
            derive_master_secret_tls10(
                &self.pre_master_secret,
                &self.client_random,
                &self.server_random,
            )
        } else if cipher.uses_sha384() {
            derive_master_secret_sha384(
                &self.pre_master_secret,
                &self.client_random,
                &self.server_random,
            )
        } else {
            derive_master_secret(
                &self.pre_master_secret,
                &self.client_random,
                &self.server_random,
            )
        };
    }

    /// TLS 1.2のverify_dataを計算する共通ヘルパー
    pub(super) fn compute_tls12_verify_data(&self, label: &[u8]) -> [u8; 12] {
        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        let mut verify_data = [0u8; 12];
        if version <= TlsVersion::TLS_1_1 {
            let handshake_hash = if cipher.uses_sha384() {
                self.transcript_hash_sha384().to_vec()
            } else {
                self.transcript_hash_sha256().to_vec()
            };
            tls10_prf(
                &self.master_secret,
                label,
                &handshake_hash,
                &mut verify_data,
            );
        } else if cipher.uses_sha384() {
            let handshake_hash = self.transcript_hash_sha384();
            tls12_prf_sha384(
                &self.master_secret,
                label,
                &handshake_hash,
                &mut verify_data,
            );
        } else {
            let handshake_hash = self.transcript_hash_sha256();
            tls12_prf(
                &self.master_secret,
                label,
                &handshake_hash,
                &mut verify_data,
            );
        }
        verify_data
    }

    /// TLS 1.2 クライアントFinishedメッセージを構築
    ///
    /// RFC 5246 Section 7.4.9:
    /// verify_data = PRF(master_secret, "client finished",
    ///                    Hash(handshake_messages))[0..11]
    ///
    /// Finishedメッセージは暗号化して送信する。
    /// `build_change_cipher_spec_payload()` の後に呼び出し、鍵が有効な状態で使用する。

    /// Finishedメッセージを暗号スイートに応じて暗号化する (TLS 1.2)
    pub(super) fn encrypt_finished_tls12(&mut self, finished_msg: &[u8]) -> TlsResult<Vec<u8>> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        if cipher.is_cbc() {
            self.encrypt_cbc_handshake(finished_msg)
        } else if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_poly1305_handshake(finished_msg)
        } else {
            self.encrypt_aes_gcm_handshake(finished_msg)
        }
    }

    pub fn build_client_finished_tls12_payload(
        &mut self,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        if self.is_tls13 {
            return Err(TlsError::UnexpectedMessage);
        }

        self.ensure_master_secret_derived();
        let verify_data = self.compute_tls12_verify_data(b"client finished");

        // Finishedハンドシェイクメッセージ
        let mut finished_msg = Vec::with_capacity(4 + 12);
        finished_msg.push(HandshakeType::Finished as u8); // type = 20
        finished_msg.push(0);
        finished_msg.push(0);
        finished_msg.push(12); // length = 12
        finished_msg.extend_from_slice(&verify_data);

        // ハンドシェイクメッセージを記録
        self.append_transcript_bytes(&finished_msg)
            .expect("tls12 finished transcript append");

        // 鍵ブロック導出（まだ行っていない場合）
        if self.write_key.is_empty() {
            self.derive_tls12_keys()?;
        }

        // Finishedは暗号化して送信
        self.encrypt_finished_tls12(&finished_msg)
            .map(Self::packet_payload_from_vec)
    }

    /// TLS 1.2 鍵ブロック導出
    ///
    /// RFC 5246 Section 6.3 に基づき、master_secretからread/writeの
    /// 暗号鍵とIVを導出する。
    pub(super) fn derive_tls12_keys(&mut self) -> TlsResult<()> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let iv_len = cipher.iv_len();
        let mac_key_len = if cipher.is_cbc() {
            cipher.mac_key_len()
        } else {
            0
        };

        // CBC key block: mac_key(2) + enc_key(2) + iv(2)
        // AEAD key block: enc_key(2) + iv(2) (no MAC keys)
        let key_material_len = 2 * mac_key_len + 2 * key_len + 2 * iv_len;

        // バージョンに応じたPRFを使用
        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let use_sha384 = cipher.uses_sha384();

        let key_block = if version <= TlsVersion::TLS_1_1 {
            // TLS 1.0/1.1: デュアルハッシュPRF (P_MD5 XOR P_SHA-1)
            let mut kb = vec![0u8; key_material_len];
            let mut seed = Vec::with_capacity(64);
            seed.extend_from_slice(&self.server_random);
            seed.extend_from_slice(&self.client_random);
            tls10_prf(&self.master_secret, b"key expansion", &seed, &mut kb);
            kb
        } else if use_sha384 {
            // TLS 1.2 SHA-384
            derive_key_block_sha384(
                &self.master_secret,
                &self.server_random,
                &self.client_random,
                key_material_len,
            )
        } else {
            // TLS 1.2 SHA-256
            derive_key_block(
                &self.master_secret,
                &self.server_random,
                &self.client_random,
                key_material_len,
            )
        };

        if key_block.len() < key_material_len {
            return Err(TlsError::CryptoError);
        }

        let mut offset = 0;

        // CBC cipher suites have MAC keys first
        if cipher.is_cbc() {
            self.write_mac_key = key_block[offset..offset + mac_key_len].to_vec();
            offset += mac_key_len;
            self.read_mac_key = key_block[offset..offset + mac_key_len].to_vec();
            offset += mac_key_len;
        }

        self.write_key = key_block[offset..offset + key_len].to_vec();
        offset += key_len;
        self.read_key = key_block[offset..offset + key_len].to_vec();
        offset += key_len;

        if cipher.is_cbc() && iv_len == 16 {
            self.write_cbc_iv
                .copy_from_slice(&key_block[offset..offset + 16]);
            offset += 16;
            self.read_cbc_iv
                .copy_from_slice(&key_block[offset..offset + 16]);
        } else {
            self.write_iv = key_block[offset..offset + iv_len].to_vec();
            offset += iv_len;
            self.read_iv = key_block[offset..offset + iv_len].to_vec();
        }
        let _ = offset;

        self.read_seq = 0;
        self.write_seq = 0;

        Ok(())
    }

    /// AES-GCM ハンドシェイクメッセージ暗号化（TLS 1.2 Finished用）
    pub(super) fn encrypt_aes_gcm_handshake(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        let explicit_nonce = self.write_seq.to_be_bytes();

        if self.write_key.is_empty() || self.write_iv.len() < 4 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.write_iv[0..4]);
        nonce[4..12].copy_from_slice(&explicit_nonce);

        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.write_seq.to_be_bytes());
        aad.push(ContentType::Handshake as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        let (ciphertext, auth_tag) = aes_gcm_encrypt(&self.write_key, &nonce, &aad, data);

        let record_len = 8 + ciphertext.len() + 16;
        let mut record = vec![
            ContentType::Handshake as u8,
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

    /// ChaCha20-Poly1305 ハンドシェイクメッセージ暗号化（TLS 1.2 Finished用）
    pub(super) fn encrypt_chacha20_poly1305_handshake(
        &mut self,
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
        aad.push(ContentType::Handshake as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.write_key[0..32]);

        let (ciphertext, auth_tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, data);

        let record_len = ciphertext.len() + 16;
        let mut record = vec![
            ContentType::Handshake as u8,
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
    // CBC Record Encryption/Decryption (TLS 1.0/1.1/1.2)
    // ========================================================================

    /// CBC ハンドシェイクメッセージ暗号化（TLS 1.0/1.1/1.2 Finished用）
    pub(super) fn encrypt_cbc_handshake(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        self.encrypt_cbc_record(ContentType::Handshake as u8, data)
    }

    /// CBCレコード暗号化 (MAC-then-Encrypt)
    ///
    /// RFC 5246 Section 6.2.3.2:
    /// 1. MAC を計算: HMAC(mac_key, seq_num || type || version || length || fragment)
    /// 2. パディングを追加
    /// 3. CBC暗号化
    pub(super) fn encrypt_cbc_record(
        &mut self,
        content_type: u8,
        data: &[u8],
    ) -> TlsResult<Vec<u8>> {
        if self.write_key.is_empty() {
            return Err(TlsError::CryptoError);
        }

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        let use_sha1 = cipher.uses_sha1_mac();

        // Step 1: MAC計算
        let mac = compute_tls_mac(
            &self.write_mac_key,
            self.write_seq,
            content_type,
            version,
            data,
            use_sha1,
        );

        // Step 2: plaintext = data || MAC
        let mut plaintext = Vec::with_capacity(data.len() + mac.len());
        plaintext.extend_from_slice(data);
        plaintext.extend_from_slice(&mac);

        // Step 3: パディング追加
        let padded = tls_add_padding(&plaintext, 16);

        // Step 4: IV決定
        let iv = if version >= TlsVersion::TLS_1_1 {
            // TLS 1.1+: 明示的IV（ランダム生成）
            let mut explicit_iv = [0u8; 16];
            let base_rand = generate_random();
            explicit_iv.copy_from_slice(&base_rand[..16]);
            explicit_iv
        } else {
            // TLS 1.0: 暗黙IV（前レコードの最終暗号文ブロック or 初期IV）
            self.last_write_ciphertext_block
                .unwrap_or(self.write_cbc_iv)
        };

        // Step 5: CBC暗号化
        let ciphertext = aes_cbc_encrypt(&self.write_key, &iv, &padded);

        // TLS 1.0: 最終暗号文ブロックを記憶（次レコードのIVに使用）
        if version == TlsVersion::TLS_1_0 && ciphertext.len() >= 16 {
            let mut last_block = [0u8; 16];
            last_block.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
            self.last_write_ciphertext_block = Some(last_block);
        }

        // レコード構築
        let version_bytes = version.to_bytes();
        let payload = if version >= TlsVersion::TLS_1_1 {
            // TLS 1.1+: IV + ciphertext
            let mut p = Vec::with_capacity(16 + ciphertext.len());
            p.extend_from_slice(&iv);
            p.extend_from_slice(&ciphertext);
            p
        } else {
            // TLS 1.0: ciphertext のみ
            ciphertext
        };

        let mut record = Vec::with_capacity(5 + payload.len());
        record.push(content_type);
        record.push(version_bytes[0]);
        record.push(version_bytes[1]);
        record.push((payload.len() >> 8) as u8);
        record.push(payload.len() as u8);
        record.extend_from_slice(&payload);

        self.write_seq += 1;
        Ok(record)
    }

    /// CBC復号用: IVと暗号文を分離し、TLS 1.0の暗黙IVも処理
    pub(super) fn split_iv_and_ciphertext<'a>(
        &self,
        data: &'a [u8],
        version: TlsVersion,
    ) -> TlsResult<([u8; 16], &'a [u8])> {
        if version >= TlsVersion::TLS_1_1 {
            if data.len() < 16 {
                return Err(TlsError::DecodeError);
            }
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&data[..16]);
            Ok((iv, &data[16..]))
        } else {
            let iv = self.last_read_ciphertext_block.unwrap_or(self.read_cbc_iv);
            Ok((iv, data))
        }
    }

    /// パディング+MACを定時間で検証 (Lucky 13対策)
    pub(super) fn verify_cbc_padding_and_mac(
        &self,
        decrypted: &[u8],
        content_type: u8,
        version: TlsVersion,
        use_sha1: bool,
        mac_len: usize,
    ) -> TlsResult<usize> {
        let padding_result = tls_verify_padding(decrypted);
        let content_len = padding_result.unwrap_or(0);
        let padding_ok = padding_result.is_some() && content_len >= mac_len;

        // Security (Lucky13 mitigation): Always compute MAC over the same amount of data
        // regardless of whether padding was valid or not. If padding is invalid,
        // we use a dummy fragment (the entire decrypted data up to where the MAC would be
        // if padding length was 0) to ensure the HMAC function takes the same time.
        let safe_content_len = if padding_ok {
            content_len
        } else {
            decrypted.len()
        };

        // Prevent underflow if even the "safe" length is too short
        let safe_fragment_len = safe_content_len.saturating_sub(mac_len);
        let fragment = &decrypted[..safe_fragment_len];

        let received_mac = if padding_ok {
            &decrypted[content_len - mac_len..content_len]
        } else {
            // Dummy MAC for constant time comparison
            &decrypted[safe_content_len.saturating_sub(mac_len)..safe_content_len]
        };

        let expected_mac = compute_tls_mac(
            &self.read_mac_key,
            self.read_seq,
            content_type,
            version,
            fragment,
            use_sha1,
        );

        let len_match = received_mac.len() == expected_mac.len();
        let compare_len = mac_len.min(expected_mac.len()).min(received_mac.len());
        let mut diff = 0u8;
        for i in 0..compare_len {
            diff |= received_mac[i] ^ expected_mac[i];
        }
        diff |= (!len_match) as u8;
        diff |= (!padding_ok) as u8;

        if diff != 0 {
            return Err(TlsError::BadRecordMac);
        }

        Ok(safe_fragment_len)
    }

    /// CBCレコード復号 (Decrypt-then-Verify-MAC)
    ///
    /// RFC 5246 Section 6.2.3.2 (復号側):
    /// 1. CBC復号してパディング付き平文を得る
    /// 2. パディング検証
    /// 3. MACを分離して検証
    /// TLS 1.0のCBC暗号文最終ブロックを次のIVとして記憶する
    pub(super) fn store_last_ciphertext_block_if_tls10(
        &mut self,
        version: TlsVersion,
        ciphertext: &[u8],
    ) {
        if version == TlsVersion::TLS_1_0 && ciphertext.len() >= 16 {
            let mut last_block = [0u8; 16];
            last_block.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
            self.last_read_ciphertext_block = Some(last_block);
        }
    }

    pub(super) fn decrypt_cbc_record(
        &mut self,
        data: &[u8],
        content_type: u8,
    ) -> TlsResult<Vec<u8>> {
        if self.read_key.is_empty() {
            return Err(TlsError::CryptoError);
        }

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        let use_sha1 = cipher.uses_sha1_mac();
        let mac_len = cipher.mac_len();

        let (iv, ciphertext) = self.split_iv_and_ciphertext(data, version)?;

        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(TlsError::DecryptError);
        }

        self.store_last_ciphertext_block_if_tls10(version, ciphertext);

        let decrypted =
            aes_cbc_decrypt(&self.read_key, &iv, ciphertext).ok_or(TlsError::DecryptError)?;

        let fragment_len =
            self.verify_cbc_padding_and_mac(&decrypted, content_type, version, use_sha1, mac_len)?;

        self.read_seq += 1;
        Ok(decrypted[..fragment_len].to_vec())
    }

    // ========================================================================
    // RSA Key Transport (TLS_RSA_WITH_* cipher suites)
    // ========================================================================

    /// RSA鍵転送用 ClientKeyExchange構築
    ///
    /// TLS_RSA_WITH_* 暗号スイートの場合:
    /// 1. 48バイトのPre-Master Secretを生成: client_version(2) || random(46)
    /// 2. サーバーのRSA公開鍵で暗号化
    /// 3. EncryptedPreMasterSecret構造体として送信
    pub fn build_client_key_exchange_rsa_payload(
        &mut self,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        // サーバーのRSA公開鍵が必要
        let server_pk = self.server_public_key.as_ref()?;

        // RSA公開鍵を取得 (ServerPublicKeyからモジュラスと指数を取得)
        let (modulus, exponent) = match server_pk {
            ServerPublicKey::Rsa { modulus, exponent } => (
                modulus.as_contiguous_slice()?,
                exponent.as_contiguous_slice()?,
            ),
            _ => return None, // ECDSA鍵ではRSA鍵転送できない
        };

        // 48バイトのPMSを生成: version(2) || random(46)
        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let version_bytes = version.to_bytes();
        let mut pms = [0u8; 48];
        pms[0] = version_bytes[0];
        pms[1] = version_bytes[1];
        let random_bytes = generate_random();
        pms[2..34].copy_from_slice(&random_bytes);
        let random_bytes2 = generate_random();
        pms[34..48].copy_from_slice(&random_bytes2[..14]);

        // PMSを保存
        self.pre_master_secret = pms.to_vec();

        // RSA暗号化
        let rsa_key = crate::net::security::rsa::RsaPublicKey { modulus, exponent };
        let encrypted_pms = crate::net::security::rsa::rsa_pkcs1_encrypt(&rsa_key, &pms).ok()?;

        // EncryptedPreMasterSecret: length(2) || encrypted_pms
        let mut body = Vec::with_capacity(2 + encrypted_pms.len());
        body.push((encrypted_pms.len() >> 8) as u8);
        body.push(encrypted_pms.len() as u8);
        body.extend_from_slice(&encrypted_pms);

        // Handshakeヘッダ: type(1) + length(3)
        let mut message = Vec::with_capacity(4 + body.len());
        message.push(16); // ClientKeyExchange type = 16
        message.push(0);
        message.push((body.len() >> 8) as u8);
        message.push(body.len() as u8);
        message.extend_from_slice(&body);

        // ハンドシェイクメッセージを記録
        self.append_transcript_bytes(&message)
            .expect("rsa client key exchange transcript append");

        // TLSレコードヘッダ
        let version_rec = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let vb = version_rec.to_bytes();
        let mut record = Vec::with_capacity(5 + message.len());
        record.push(ContentType::Handshake as u8);
        record.push(vb[0]);
        record.push(vb[1]);
        record.push((message.len() >> 8) as u8);
        record.push(message.len() as u8);
        record.extend_from_slice(&message);

        Some(Self::packet_payload_from_vec(record))
    }

    // ========================================================================
    // Application Data Encryption/Decryption (TLS 1.0/1.1/1.2)
    // ========================================================================

    /// アプリケーションデータを暗号化して送信レコードを構築
    pub fn encrypt_application_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let data = Self::vec_from_payload(payload)?;
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if self.is_tls13 {
            return self.tls13_encrypt_application_payload(payload);
        }

        if cipher.is_cbc() {
            self.encrypt_cbc_record(ContentType::ApplicationData as u8, &data)
        } else if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_record(ContentType::ApplicationData as u8, &data)
        } else {
            self.encrypt_aes_gcm_record(ContentType::ApplicationData as u8, &data)
        }
        .map(Self::packet_payload_from_vec)
    }
}
