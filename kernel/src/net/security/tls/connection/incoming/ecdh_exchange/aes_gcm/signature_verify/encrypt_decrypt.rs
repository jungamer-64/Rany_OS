// Building block: TLS encrypt/decrypt

use super::*;

impl TlsConnection {
    /// データを暗号化して送信
    ///
    /// Dispatches between TLS 1.3 record layer and TLS 1.2 cipher suites.
    pub fn encrypt(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // TLS 1.3: inner content type付きでAEAD暗号化
        if self.is_tls13 {
            if self.state != TlsState::Established && self.state != TlsState::Handshaking {
                return Err(TlsError::NotConnected);
            }
            let mut inner_plaintext = Vec::with_capacity(data.len() + 1);
            inner_plaintext.extend_from_slice(data);
            inner_plaintext.push(ContentType::ApplicationData as u8);
            return self.tls13_encrypt_record(&inner_plaintext, false);
        }

        // TLS 1.2
        if !self.write_encryption_active && self.state != TlsState::Established {
            return Err(TlsError::NotConnected);
        }

        let cipher = self
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
    pub(super) fn encrypt_aes_gcm(&mut self, data: &[u8], content_type: u8) -> TlsResult<Vec<u8>> {
        let explicit_nonce = self.write_seq.to_be_bytes();

        // Keys not set — return error (encryption requires valid keys)
        let (ciphertext, auth_tag) = if self.write_key.is_empty() || self.write_iv.len() < 4 {
            return Err(TlsError::CryptoError);
        } else {
            // 12-byte nonce: implicit_iv(4) || explicit_nonce(8)
            let mut nonce = [0u8; 12];
            nonce[0..4].copy_from_slice(&self.write_iv[0..4]);
            nonce[4..12].copy_from_slice(&explicit_nonce);

            // AAD: seq_num(8) || type(1) || version(2) || length(2)
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.write_seq.to_be_bytes());
            aad.push(content_type);
            aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

            aes_gcm_encrypt(&self.write_key, &nonce, &aad, data)
        };

        // Record length: nonce(8) + ciphertext + tag(16)
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
    ) -> TlsResult<Vec<u8>> {
        // Keys not set — return error (encryption requires valid keys)
        let (ciphertext, auth_tag) =
            if self.write_key.is_empty() || self.write_key.len() < 32 || self.write_iv.len() < 12 {
                return Err(TlsError::CryptoError);
            } else {
                // Construct 12-byte nonce: IV XOR (zero-padded sequence number)
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&self.write_iv[0..12]);
                let seq_bytes = self.write_seq.to_be_bytes();
                for i in 0..8 {
                    nonce[4 + i] ^= seq_bytes[i];
                }

                // AAD: seq_num(8) || type(1) || version(2) || length(2)
                let mut aad = Vec::with_capacity(13);
                aad.extend_from_slice(&self.write_seq.to_be_bytes());
                aad.push(content_type);
                aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
                aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

                let mut key = [0u8; 32];
                key.copy_from_slice(&self.write_key[0..32]);

                chacha20_poly1305_encrypt(&key, &nonce, &aad, data)
            };

        // Record length: ciphertext + tag(16) — no explicit nonce for ChaCha20-Poly1305
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

    /// TLS 1.3: Post-handshake メッセージを処理
    ///
    /// RFC 8446 Section 4.6: Post-Handshake Messages
    /// - NewSessionTicket (type 4)
    /// - KeyUpdate (type 24)
    pub(crate) fn tls13_process_post_handshake(&mut self, data: &[u8]) -> TlsResult<()> {
        let mut offset = 0;
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

            match msg_type {
                4 => {
                    // NewSessionTicket (RFC 8446 Section 4.6.1)
                    self.tls13_process_new_session_ticket(payload)?;
                }
                24 => {
                    // KeyUpdate (RFC 8446 Section 4.6.3)
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

    /// Resumption Master SecretからPSKを導出
    pub(super) fn derive_tls13_psk_from_rms(&self, ticket_nonce: &[u8]) -> Option<Vec<u8>> {
        if self.resumption_master_secret.is_empty() {
            return None;
        }
        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        let hash_len = if use_384 { 48 } else { 32 };

        let psk = if use_384 {
            let mut rms = [0u8; 48];
            let copy_len = self.resumption_master_secret.len().min(48);
            rms[..copy_len].copy_from_slice(&self.resumption_master_secret[..copy_len]);
            hkdf_expand_label_sha384(&rms, b"resumption", ticket_nonce, hash_len).to_vec()
        } else {
            let mut rms = [0u8; 32];
            let copy_len = self.resumption_master_secret.len().min(32);
            rms[..copy_len].copy_from_slice(&self.resumption_master_secret[..copy_len]);
            hkdf_expand_label(&rms, b"resumption", ticket_nonce, hash_len).to_vec()
        };
        Some(psk)
    }

    pub(super) fn tls13_process_new_session_ticket(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 9 {
            return Err(TlsError::DecodeError);
        }

        let ticket_lifetime = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let ticket_age_add = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let nonce_len = data[8] as usize;

        let mut off = 9;
        if data.len() < off + nonce_len {
            return Err(TlsError::DecodeError);
        }
        let ticket_nonce = &data[off..off + nonce_len];
        off += nonce_len;

        if data.len() < off + 2 {
            return Err(TlsError::DecodeError);
        }
        let ticket_len = ((data[off] as usize) << 8) | data[off + 1] as usize;
        off += 2;

        if data.len() < off + ticket_len {
            return Err(TlsError::DecodeError);
        }
        let ticket = &data[off..off + ticket_len];
        off += ticket_len;

        self.max_early_data_size = Self::parse_ticket_extensions(data, off);

        self.session_ticket = Some(SessionTicket {
            lifetime: ticket_lifetime,
            age_add: ticket_age_add,
            nonce: ticket_nonce.to_vec(),
            ticket: ticket.to_vec(),
        });

        if let Some(psk) = self.derive_tls13_psk_from_rms(ticket_nonce) {
            self.tls13_psk = Some(psk);
            self.tls13_psk_identity = Some(ticket.to_vec());
            self.tls13_ticket_age_add = ticket_age_add;
            self.tls13_psk_cipher = self.negotiated_cipher;
        }

        Ok(())
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
            old_secret.copy_from_slice(&self.server_app_traffic_secret);
            let result = hkdf_expand_label_sha384(&old_secret, b"traffic upd", b"", hash_len);
            new_server_secret[..hash_len].copy_from_slice(&result[..hash_len]);
        } else {
            let mut old_secret = [0u8; 32];
            old_secret.copy_from_slice(&self.server_app_traffic_secret[..32]);
            let result = hkdf_expand_label(&old_secret, b"traffic upd", b"", hash_len);
            new_server_secret[..hash_len].copy_from_slice(&result[..hash_len]);
        }
        self.server_app_traffic_secret = new_server_secret;

        // 新しいサーバー読み取り鍵を導出
        let (new_read_key, new_read_iv) = if use_384 {
            tls13_derive_traffic_keys_sha384(&self.server_app_traffic_secret, key_len)
        } else {
            let mut secret32 = [0u8; 32];
            secret32.copy_from_slice(&self.server_app_traffic_secret[..32]);
            tls13_derive_traffic_keys(&secret32, key_len)
        };
        self.read_key = new_read_key;
        self.read_iv = new_read_iv;
        self.read_seq = 0;

        // update_requested (1) の場合、クライアント側鍵も更新して KeyUpdate を返信
        if request_update == 1 {
            let mut new_client_secret = [0u8; 48];
            if use_384 {
                let mut old_secret = [0u8; 48];
                old_secret.copy_from_slice(&self.client_app_traffic_secret);
                let result = hkdf_expand_label_sha384(&old_secret, b"traffic upd", b"", hash_len);
                new_client_secret[..hash_len].copy_from_slice(&result[..hash_len]);
            } else {
                let mut old_secret = [0u8; 32];
                old_secret.copy_from_slice(&self.client_app_traffic_secret[..32]);
                let result = hkdf_expand_label(&old_secret, b"traffic upd", b"", hash_len);
                new_client_secret[..hash_len].copy_from_slice(&result[..hash_len]);
            }
            self.client_app_traffic_secret = new_client_secret;

            let (new_write_key, new_write_iv) = if use_384 {
                tls13_derive_traffic_keys_sha384(&self.client_app_traffic_secret, key_len)
            } else {
                let mut secret32 = [0u8; 32];
                secret32.copy_from_slice(&self.client_app_traffic_secret[..32]);
                tls13_derive_traffic_keys(&secret32, key_len)
            };
            self.write_key = new_write_key;
            self.write_iv = new_write_iv;
            self.write_seq = 0;

            // KeyUpdate応答を送信キューに追加
            self.pending_key_update_response = true;
        }

        Ok(())
    }

    /// TLS 1.3: KeyUpdate応答メッセージを構築
    ///
    /// post-handshakeハンドシェイクメッセージとして暗号化して送信
    pub fn build_key_update_response_payload(
        &mut self,
    ) -> Option<kernel_api::resource::net::PacketPayload> {
        if !self.pending_key_update_response {
            return None;
        }
        self.pending_key_update_response = false;

        // KeyUpdate { update_not_requested(0) }
        let key_update_msg = vec![
            24, // msg_type = KeyUpdate
            0, 0, 1, // length = 1
            0, // update_not_requested
        ];

        // Handshake content type を付加して暗号化
        let mut inner = Vec::with_capacity(key_update_msg.len() + 1);
        inner.extend_from_slice(&key_update_msg);
        inner.push(ContentType::Handshake as u8);

        self.tls13_encrypt_record(&inner, false)
            .ok()
            .map(Self::packet_payload_from_vec)
    }

    /// TLS 1.3 モードかどうか
    pub fn is_tls13(&self) -> bool {
        self.is_tls13
    }

    /// TLS 1.3: クライアントFinished送信が必要か
    pub fn needs_client_finished(&self) -> bool {
        self.is_tls13 && self.state == TlsState::Tls13ServerFinishedReceived
    }

    /// 接続を閉じる
    pub fn close_payload(&mut self) -> kernel_api::resource::net::PacketPayload {
        self.state = TlsState::Closing;

        if self.is_tls13 && !self.write_key.is_empty() {
            // TLS 1.3: close_notify を暗号化して送信
            let mut inner = Vec::with_capacity(3);
            inner.push(AlertLevel::Warning as u8);
            inner.push(AlertDescription::CloseNotify as u8);
            inner.push(ContentType::Alert as u8);
            if let Ok(record) = self.tls13_encrypt_record(&inner, false) {
                return Self::packet_payload_from_vec(record);
            }
        }

        // TLS 1.2 or fallback
        Self::packet_payload_from_slice(&[
            ContentType::Alert as u8,
            0x03,
            0x03,
            0,
            2,
            AlertLevel::Warning as u8,
            AlertDescription::CloseNotify as u8,
        ])
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn handshake_messages_ref(&self) -> &[u8] {
        &self.handshake_messages
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn has_local_ecdh_keypair(&self) -> bool {
        self.local_ecdh_keypair.is_some()
    }

    #[cfg(any(test, feature = "qemu-test-export"))]
    pub fn has_transcript_hash(&self) -> bool {
        self.transcript_hash.is_some()
    }
}
