// ============================================================================
// kernel/src/net/security/tls/connection/handshake/tls12.rs - セキュリティ / TLS / 接続 / ハンドシェイク / TLS 1.2ハンドシェイク
// ============================================================================

use super::super::{
    CipherSuite, ContentType, HandshakeType, TlsBytes, TlsConnection, TlsError, TlsResult, TlsState,
    TlsVersion, ecdh,
};
use alloc::vec::Vec;
use crate::net::security::tls::crypto::{
    aes_cbc_encrypt_in_place, compute_tls_mac_into, derive_key_block, derive_key_block_sha384,
    derive_master_secret, derive_master_secret_sha384, derive_master_secret_tls10,
    generate_random, tls10_prf, tls12_prf, tls12_prf_sha384, tls_add_padding_in_place,
    tls_verify_padding,
};

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
    ) -> TlsResult<(ecdh::EcdhKeyPair, TlsBytes<64>)> {
        let group = Self::named_curve_to_ecdh_group(named_curve)?;
        let local_keypair =
            ecdh::EcdhKeyPair::generate(group).map_err(|_| TlsError::CryptoError)?;
        let shared_secret = local_keypair
            .shared_secret(server_pubkey)
            .map_err(|_| TlsError::CryptoError)?;
        let shared_secret =
            TlsBytes::from_slice(shared_secret.as_slice()).ok_or(TlsError::CryptoError)?;
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

        self.handshake_secrets.local_ecdh_keypair = Some(local_keypair);
        self.handshake_secrets.pre_master_secret = shared_secret;

        // Master secret導出（RFC 5246 Section 8.1）
        self.handshake_secrets.master_secret = derive_master_secret(
            self.handshake_secrets.pre_master_secret.as_slice(),
            &self.negotiation.client_random,
            &self.negotiation.server_random,
        );

        Ok(())
    }

    /// ClientKeyExchangeメッセージ構築（TLS 1.2 ECDHE）
    ///
    /// クライアントの一時公開鍵をサーバーに送信する。
    /// `process_server_key_exchange()` の後に呼び出す。
    pub fn build_client_key_exchange_payload(
        &mut self,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        let keypair = self.handshake_secrets.local_ecdh_keypair.as_ref()?;
        let pubkey_bytes = keypair.public_key_bytes();
        let point_len = pubkey_bytes.len();
        let body_len = 1 + point_len;
        let msg_len = 4 + body_len;

        let mut message = [0u8; 69];
        if msg_len > message.len() {
            return None;
        }
        message[0] = 16; // ClientKeyExchange
        message[2] = ((body_len >> 8) & 0xff) as u8;
        message[3] = (body_len & 0xff) as u8;
        message[4] = point_len as u8;
        message[5..5 + point_len].copy_from_slice(pubkey_bytes.as_slice());
        let message = &message[..msg_len];

        self.append_transcript_bytes(message)
            .expect("tls12 client key exchange transcript append");

        let record_header = [
            ContentType::Handshake as u8,
            0x03,
            0x03,
            (msg_len >> 8) as u8,
            msg_len as u8,
        ];

        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder.push_bytes(&record_header)?;
        builder.push_bytes(message)?;
        Some(builder.build())
    }

    /// ServerHelloDoneを処理
    pub(super) fn process_server_hello_done(&mut self, _data: &[u8]) -> TlsResult<()> {
        self.negotiation.state = TlsState::Handshaking;
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
        self.record.write_encryption_active = true;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        if builder
            .push_bytes(&[
                ContentType::ChangeCipherSpec as u8,
                0x03,
                0x03, // TLS 1.2
                0x00,
                0x01, // length = 1
                0x01, // change_cipher_spec
            ])
            .is_none()
        {
            return kernel_api::resource::net::PacketPayload::default();
        }
        builder.build()
    }

    /// Master secretが未導出の場合に導出する（TLS 1.2）
    pub(super) fn ensure_master_secret_derived(&mut self) {
        if !self.handshake_secrets.master_secret.iter().all(|&b| b == 0) {
            return;
        }
        if self.handshake_secrets.pre_master_secret.is_empty() {
            return;
        }
        let version = self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        self.handshake_secrets.master_secret = if version <= TlsVersion::TLS_1_1 {
            derive_master_secret_tls10(
                self.handshake_secrets.pre_master_secret.as_slice(),
                &self.negotiation.client_random,
                &self.negotiation.server_random,
            )
        } else if cipher.uses_sha384() {
            derive_master_secret_sha384(
                self.handshake_secrets.pre_master_secret.as_slice(),
                &self.negotiation.client_random,
                &self.negotiation.server_random,
            )
        } else {
            derive_master_secret(
                self.handshake_secrets.pre_master_secret.as_slice(),
                &self.negotiation.client_random,
                &self.negotiation.server_random,
            )
        };
    }

    /// TLS 1.2のverify_dataを計算する共通ヘルパー
    pub(super) fn compute_tls12_verify_data(&self, label: &[u8]) -> [u8; 12] {
        let version = self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        let mut verify_data = [0u8; 12];
        if version <= TlsVersion::TLS_1_1 {
            if cipher.uses_sha384() {
                let handshake_hash = self.transcript_hash_sha384();
                tls10_prf(
                    &self.handshake_secrets.master_secret,
                    label,
                    &handshake_hash,
                    &mut verify_data,
                );
            } else {
                let handshake_hash = self.transcript_hash_sha256();
                tls10_prf(
                    &self.handshake_secrets.master_secret,
                    label,
                    &handshake_hash,
                    &mut verify_data,
                );
            }
        } else if cipher.uses_sha384() {
            let handshake_hash = self.transcript_hash_sha384();
            tls12_prf_sha384(
                &self.handshake_secrets.master_secret,
                label,
                &handshake_hash,
                &mut verify_data,
            );
        } else {
            let handshake_hash = self.transcript_hash_sha256();
            tls12_prf(
                &self.handshake_secrets.master_secret,
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
    pub(super) fn encrypt_finished_tls12(
        &mut self,
        finished_msg: &[u8],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let cipher = self.negotiation.negotiated_cipher
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
        if self.negotiation.is_tls13 {
            return Err(TlsError::UnexpectedMessage);
        }

        self.ensure_master_secret_derived();
        let verify_data = self.compute_tls12_verify_data(b"client finished");

        // Finishedハンドシェイクメッセージ
        let mut finished_msg = [0u8; 16];
        finished_msg[0] = HandshakeType::Finished as u8; // type = 20
        finished_msg[3] = 12; // length = 12
        finished_msg[4..16].copy_from_slice(&verify_data);

        // ハンドシェイクメッセージを記録
        self.append_transcript_bytes(&finished_msg)
            .expect("tls12 finished transcript append");

        // 鍵ブロック導出（まだ行っていない場合）
        if self.record.write_key.is_empty() {
            self.derive_tls12_keys()?;
        }

        // Finishedは暗号化して送信
        self.encrypt_finished_tls12(&finished_msg)
    }

    /// TLS 1.2 鍵ブロック導出
    ///
    /// RFC 5246 Section 6.3 に基づき、master_secretからread/writeの
    /// 暗号鍵とIVを導出する。
    pub(super) fn derive_tls12_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.negotiated_cipher
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
        let version = self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let use_sha384 = cipher.uses_sha384();

        let mut key_block_storage = [0u8; 256];
        if key_material_len > key_block_storage.len() {
            return Err(TlsError::CryptoError);
        }
        let key_block = &mut key_block_storage[..key_material_len];

        if version <= TlsVersion::TLS_1_1 {
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(&self.negotiation.server_random);
            seed[32..].copy_from_slice(&self.negotiation.client_random);
            tls10_prf(&self.handshake_secrets.master_secret, b"key expansion", &seed, key_block);
        } else if use_sha384 {
            derive_key_block_sha384(
                &self.handshake_secrets.master_secret,
                &self.negotiation.server_random,
                &self.negotiation.client_random,
                key_block,
            );
        } else {
            derive_key_block(
                &self.handshake_secrets.master_secret,
                &self.negotiation.server_random,
                &self.negotiation.client_random,
                key_block,
            );
        }

        let mut offset = 0;

        // CBC cipher suites have MAC keys first
        if cipher.is_cbc() {
            Self::set_tls_bytes(
                &mut self.record.write_mac_key,
                &key_block[offset..offset + mac_key_len],
            )?;
            offset += mac_key_len;
            Self::set_tls_bytes(
                &mut self.record.read_mac_key,
                &key_block[offset..offset + mac_key_len],
            )?;
            offset += mac_key_len;
        }

        Self::set_tls_bytes(&mut self.record.write_key, &key_block[offset..offset + key_len])?;
        offset += key_len;
        Self::set_tls_bytes(&mut self.record.read_key, &key_block[offset..offset + key_len])?;
        offset += key_len;

        if cipher.is_cbc() && iv_len == 16 {
            self.record.write_cbc_iv
                .copy_from_slice(&key_block[offset..offset + 16]);
            offset += 16;
            self.record.read_cbc_iv
                .copy_from_slice(&key_block[offset..offset + 16]);
        } else {
            Self::set_tls_bytes(&mut self.record.write_iv, &key_block[offset..offset + iv_len])?;
            offset += iv_len;
            Self::set_tls_bytes(&mut self.record.read_iv, &key_block[offset..offset + iv_len])?;
        }
        let _ = offset;

        self.record.read_seq = 0;
        self.record.write_seq = 0;

        Ok(())
    }

    /// AES-GCM ハンドシェイクメッセージ暗号化（TLS 1.2 Finished用）
    pub(super) fn encrypt_aes_gcm_handshake(
        &mut self,
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

        let aad = Self::tls12_aad(self.record.write_seq, ContentType::Handshake as u8, data.len());

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, self.record.write_key.as_slice(), &nonce, &aad, data)?;

        let record_len = 8 + ciphertext.total_len() + 16;
        let record_header = [
            ContentType::Handshake as u8,
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

    /// ChaCha20-Poly1305 ハンドシェイクメッセージ暗号化（TLS 1.2 Finished用）
    pub(super) fn encrypt_chacha20_poly1305_handshake(
        &mut self,
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

        let aad = Self::tls12_aad(self.record.write_seq, ContentType::Handshake as u8, data.len());

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.record.write_key.as_slice()[0..32]);

        let (ciphertext, auth_tag) =
            Self::encrypt_aead_payload(cipher, self.record.write_key.as_slice(), &nonce, &aad, data)?;

        let record_len = ciphertext.total_len() + 16;
        let record_header = [
            ContentType::Handshake as u8,
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
    // CBC Record Encryption/Decryption (TLS 1.0/1.1/1.2)
    // ========================================================================

    /// CBC ハンドシェイクメッセージ暗号化（TLS 1.0/1.1/1.2 Finished用）
    pub(super) fn encrypt_cbc_handshake(
        &mut self,
        data: &[u8],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
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
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        if self.record.write_key.is_empty() {
            return Err(TlsError::CryptoError);
        }

        let version = self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        let use_sha1 = cipher.uses_sha1_mac();

        // Step 1: MAC計算
        let (mac, mac_len) = compute_tls_mac_into(
            self.record.write_mac_key.as_slice(),
            self.record.write_seq,
            content_type,
            version,
            data,
            use_sha1,
        );
        let mut packet =
            crate::net::payload::alloc_packet_with_headroom(data.len() + mac_len + 16, 0)
                .ok_or(TlsError::DecodeError)?;
        let packet_data = packet.data_mut();
        packet_data[..data.len()].copy_from_slice(data);
        packet_data[data.len()..data.len() + mac_len].copy_from_slice(&mac[..mac_len]);
        let padded_len = tls_add_padding_in_place(packet_data, data.len() + mac_len, 16)
            .ok_or(TlsError::CryptoError)?;
        packet.set_len(padded_len);

        // Step 4: IV決定
        let iv = if version >= TlsVersion::TLS_1_1 {
            // TLS 1.1+: 明示的IV（ランダム生成）
            let mut explicit_iv = [0u8; 16];
            let base_rand = generate_random();
            explicit_iv.copy_from_slice(&base_rand[..16]);
            explicit_iv
        } else {
            // TLS 1.0: 暗黙IV（前レコードの最終暗号文ブロック or 初期IV）
            self.record.last_write_ciphertext_block
                .unwrap_or(self.record.write_cbc_iv)
        };

        // Step 5: CBC暗号化
        aes_cbc_encrypt_in_place(
            self.record.write_key.as_slice(),
            &iv,
            &mut packet.data_mut()[..padded_len],
        )
        .ok_or(TlsError::CryptoError)?;

        // TLS 1.0: 最終暗号文ブロックを記憶（次レコードのIVに使用）
        if version == TlsVersion::TLS_1_0 && padded_len >= 16 {
            let mut last_block = [0u8; 16];
            last_block.copy_from_slice(&packet.data()[padded_len - 16..padded_len]);
            self.record.last_write_ciphertext_block = Some(last_block);
        }
        let version_bytes = version.to_bytes();
        let payload_len = if version >= TlsVersion::TLS_1_1 {
            16 + padded_len
        } else {
            padded_len
        };

        let record_header = [
            content_type,
            version_bytes[0],
            version_bytes[1],
            (payload_len >> 8) as u8,
            payload_len as u8,
        ];

        self.record.write_seq += 1;
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder
            .push_bytes(&record_header)
            .ok_or(TlsError::DecodeError)?;
        if version >= TlsVersion::TLS_1_1 {
            builder.push_bytes(&iv).ok_or(TlsError::DecodeError)?;
        }
        builder.push_payload(kernel_api::resource::net::PacketPayload::single(packet));
        Ok(builder.build())
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
            let iv = self.record.last_read_ciphertext_block.unwrap_or(self.record.read_cbc_iv);
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

        // SECURITY: Lucky13 対策として、常に同量の data で MAC を計算する。
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

        let (expected_mac, expected_mac_len) = compute_tls_mac_into(
            self.record.read_mac_key.as_slice(),
            self.record.read_seq,
            content_type,
            version,
            fragment,
            use_sha1,
        );

        let len_match = received_mac.len() == expected_mac_len;
        let compare_len = mac_len.min(expected_mac_len).min(received_mac.len());
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
            self.record.last_read_ciphertext_block = Some(last_block);
        }
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
        let server_pk = self.handshake_secrets.server_public_key.as_ref()?;

        // RSA公開鍵を取得 (ServerPublicKeyからモジュラスと指数を取得)
        let (modulus, exponent) = server_pk.rsa_components()?;

        // 48バイトのPMSを生成: version(2) || random(46)
        let version = self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let version_bytes = version.to_bytes();
        let mut pms = [0u8; 48];
        pms[0] = version_bytes[0];
        pms[1] = version_bytes[1];
        let random_bytes = generate_random();
        pms[2..34].copy_from_slice(&random_bytes);
        let random_bytes2 = generate_random();
        pms[34..48].copy_from_slice(&random_bytes2[..14]);

        // PMSを保存
        Self::set_tls_bytes(&mut self.handshake_secrets.pre_master_secret, &pms).ok()?;

        // RSA暗号化
        let rsa_key = crate::net::security::rsa::RsaPublicKey { modulus, exponent };
        let mut encrypted_pms = [0u8; crate::net::security::rsa::RSA_MAX_BYTES];
        let encrypted_pms_len =
            crate::net::security::rsa::rsa_pkcs1_encrypt_into(&rsa_key, &pms, &mut encrypted_pms)
                .ok()?;
        let encrypted_pms = &encrypted_pms[..encrypted_pms_len];

        // EncryptedPreMasterSecret: length(2) || encrypted_pms
        let mut body = TlsBytes::<1024>::new();
        body.append_be_u16(encrypted_pms.len() as u16)?;
        body.append_slice(encrypted_pms)?;

        // Handshakeヘッダ: type(1) + length(3)
        let mut message = TlsBytes::<1028>::new();
        message.push_byte(16)?; // ClientKeyExchange type = 16
        message.append_be_u24(body.len())?;
        message.append_slice(body.as_slice())?;

        // ハンドシェイクメッセージを記録
        self.append_transcript_bytes(message.as_slice())
            .expect("rsa client key exchange transcript append");

        // TLSレコードヘッダ
        let version_rec = self.negotiation.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let vb = version_rec.to_bytes();
        let record_header = [
            ContentType::Handshake as u8,
            vb[0],
            vb[1],
            (message.len() >> 8) as u8,
            message.len() as u8,
        ];

        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder.push_bytes(&record_header)?;
        builder.push_bytes(message.as_slice())?;
        Some(builder.build())
    }

    // ========================================================================
    // Application Data Encryption/Decryption (TLS 1.0/1.1/1.2)
    // ========================================================================

    /// アプリケーションデータを暗号化して送信レコードを構築
    pub fn encrypt_application_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let mut flattened = Vec::new();
        let data = if let Some(bytes) = Self::contiguous_payload_bytes(payload) {
            bytes
        } else {
            let view = crate::net::payload::PacketPayloadView::new(payload);
            flattened.reserve(view.total_len());
            view.for_each_chunk(|chunk| flattened.extend_from_slice(chunk));
            flattened.as_slice()
        };
        let cipher = self.negotiation.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if self.negotiation.is_tls13 {
            return self.tls13_encrypt_application_payload(payload);
        }

        if cipher.is_cbc() {
            self.encrypt_cbc_record(ContentType::ApplicationData as u8, &data)
        } else if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_record(ContentType::ApplicationData as u8, &data)
        } else {
            self.encrypt_aes_gcm_record(ContentType::ApplicationData as u8, &data)
        }
    }
}
