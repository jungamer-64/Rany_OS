use super::*;

mod ecdh_exchange;
impl TlsConnection {

    /// データを受信して処理
    pub fn process_incoming(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // Security: Limit receive buffer size to prevent DoS
        const MAX_RECV_BUFFER: usize = 65536;
        if self.recv_buffer.len() + data.len() > MAX_RECV_BUFFER {
            return Err(TlsError::DecodeError);
        }
        self.recv_buffer.extend_from_slice(data);

        let mut plaintext = Vec::new();

        while self.recv_buffer.len() >= 5 {
            let content_type = self.recv_buffer[0];
            let length = ((self.recv_buffer[3] as usize) << 8) | self.recv_buffer[4] as usize;

            // Security (RFC 5246 Section 6.2.1): Limit record length.
            // Max is 2^14 + 2048 = 18432. We use 20KB as a safe bound.
            if length > 20480 {
                return Err(TlsError::DecodeError);
            }

            if self.recv_buffer.len() < 5 + length {
                break; // もっとデータが必要
            }

            let record = self.recv_buffer.drain(..5 + length).collect::<Vec<_>>();
            let payload = &record[5..];

            self.process_single_record(content_type, payload, &mut plaintext)?;
        }

        Ok(plaintext)
    }

    /// 単一のTLSレコードを処理する
    pub(super) fn process_single_record(
        &mut self,
        content_type: u8,
        payload: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> TlsResult<()> {
        match ContentType::from_u8(content_type) {
            Some(ContentType::Handshake) => {
                self.process_handshake(payload)?;
            }
            Some(ContentType::ChangeCipherSpec) => {
                // TLS 1.2 略式ハンドシェイク: CCS受信で鍵導出
                if self.resuming_session && self.state == TlsState::WaitFinishedResumed {
                    self.derive_tls12_keys()?;
                }
                // TLS 1.3では無視
            }
            Some(ContentType::Alert) => {
                self.handle_alert(payload)?;
            }
            Some(ContentType::ApplicationData) => {
                self.process_app_data(payload, plaintext)?;
            }
            _ => {
                return Err(TlsError::UnexpectedMessage);
            }
        }
        Ok(())
    }

    /// TLSアラートを処理する
    pub(super) fn handle_alert(&mut self, payload: &[u8]) -> TlsResult<()> {
        if payload.len() >= 2 {
            let _level = payload[0];
            let description = payload[1];
            if description == AlertDescription::CloseNotify as u8 {
                self.state = TlsState::Closed;
            } else {
                self.state = TlsState::Error;
                return Err(TlsError::Alert(description));
            }
        }
        Ok(())
    }

    /// 確立済みセッションでレコードを復号する
    pub(super) fn decrypt_established_data(
        &mut self,
        payload: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> TlsResult<()> {
        if self.is_tls13 {
            let decrypted = self.tls13_decrypt_record(payload, false)?;
            self.dispatch_tls13_inner_content(&decrypted, plaintext)?;
        } else {
            let decrypted = self.decrypt_record(payload)?;
            plaintext.extend_from_slice(&decrypted);
        }
        Ok(())
    }

    /// ApplicationDataレコードを処理する
    pub(super) fn process_app_data(
        &mut self,
        payload: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> TlsResult<()> {
        if self.is_tls13 && self.state != TlsState::Established {
            // TLS 1.3: 暗号化ハンドシェイクメッセージ
            let app_data =
                self.tls13_process_encrypted_handshake(payload)?;
            if !app_data.is_empty() {
                plaintext.extend_from_slice(&app_data);
            }
        } else if self.state == TlsState::Established {
            self.decrypt_established_data(payload, plaintext)?;
        }
        Ok(())
    }

    /// TLS 1.3復号後の内部コンテントタイプを処理する
    pub(super) fn dispatch_tls13_inner_content(
        &mut self,
        decrypted: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> TlsResult<()> {
        if let Some((inner_ct, inner_data)) =
            Self::tls13_split_content_type(decrypted)
        {
            match ContentType::from_u8(inner_ct) {
                Some(ContentType::ApplicationData) => {
                    plaintext.extend_from_slice(inner_data);
                }
                Some(ContentType::Handshake) => {
                    // Post-handshake: NewSessionTicket, KeyUpdate
                    self.tls13_process_post_handshake(inner_data)?;
                }
                Some(ContentType::Alert) => {
                    self.handle_alert(inner_data)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// ハンドシェイクメッセージタイプに応じたディスパッチ
    pub(super) fn dispatch_handshake_message(&mut self, msg_type: u8, payload: &[u8]) -> TlsResult<()> {
        match msg_type {
            2 => self.process_server_hello(payload),   // ServerHello
            11 => self.process_certificate(payload),    // Certificate
            12 => self.process_server_key_exchange(payload), // ServerKeyExchange
            14 => self.process_server_hello_done(payload),   // ServerHelloDone
            20 => self.process_finished(payload),       // Finished
            _ => Ok(()),
        }
    }

    /// ハンドシェイクメッセージを記録し、トランスクリプトハッシュと鍵導出を更新する
    pub(super) fn record_and_update_handshake(&mut self, msg_data: &[u8], msg_type: u8) -> TlsResult<()> {
        self.handshake_messages.extend_from_slice(msg_data);
        if let Some(ref mut hasher) = self.transcript_hash {
            hasher.update(msg_data);
        }
        // TLS 1.3: ServerHello受信後にハンドシェイク鍵を導出
        if msg_type == 2 && self.is_tls13 {
            self.tls13_derive_handshake_keys()?;
        }
        Ok(())
    }

    /// ハンドシェイクメッセージを処理
    pub(crate) fn process_handshake(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let mut offset = 0usize;
        while offset < data.len() {
            if data.len() - offset < 4 {
                return Err(TlsError::DecodeError);
            }

            let msg_type = data[offset];
            let length = ((data[offset + 1] as usize) << 16)
                | ((data[offset + 2] as usize) << 8)
                | data[offset + 3] as usize;

            // Security: Limit handshake message length to prevent DoS.
            // Handshake messages (especially certificates) can be large, but 128KB should be plenty.
            if length > 131072 {
                return Err(TlsError::DecodeError);
            }

            let body_start = offset + 4;
            let body_end = body_start + length;
            if body_end > data.len() {
                return Err(TlsError::DecodeError);
            }

            let payload = &data[body_start..body_end];
            self.dispatch_handshake_message(msg_type, payload)?;
            self.record_and_update_handshake(&data[offset..body_end], msg_type)?;

            offset = body_end;
        }

        Ok(())
    }

    /// ServerHelloを処理
    pub(super) fn process_server_hello(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 34 {
            return Err(TlsError::DecodeError);
        }

        let _legacy_version = TlsVersion(((data[0] as u16) << 8) | data[1] as u16);
        self.server_random.copy_from_slice(&data[2..34]);

        let session_id_len = data[34] as usize;
        let mut server_session_id = [0u8; 32];
        if session_id_len == 32 && 35 + session_id_len <= data.len() {
            server_session_id.copy_from_slice(&data[35..35 + 32]);
        }
        let offset = 35 + session_id_len;

        if data.len() < offset + 2 {
            return Err(TlsError::DecodeError);
        }

        let cipher = CipherSuite(((data[offset] as u16) << 8) | data[offset + 1] as u16);
        self.negotiated_cipher = Some(cipher);

        let ext_offset = offset + 3;
        let (actual_version, server_key_share) =
            Self::parse_server_hello_extensions(data, ext_offset, _legacy_version, &mut self.tls13_using_psk, self.tls13_psk.is_some());

        self.negotiated_version = Some(actual_version);

        if actual_version == TlsVersion::TLS_1_3 {
            self.handle_tls13_hello(cipher, server_key_share)?;
        } else {
            self.handle_tls12_hello(session_id_len, &server_session_id)?;
        }

        Ok(())
    }

    /// Parse ServerHello extensions and return the negotiated version and optional key share.
    pub(super) fn parse_server_hello_extensions(
        data: &[u8],
        ext_offset: usize,
        default_version: TlsVersion,
        tls13_using_psk: &mut bool,
        has_psk: bool,
    ) -> (TlsVersion, Option<(u16, Vec<u8>)>) {
        let mut actual_version = default_version;
        let mut server_key_share: Option<(u16, Vec<u8>)> = None;

        if ext_offset + 2 > data.len() {
            return (actual_version, server_key_share);
        }

        let extensions_len =
            ((data[ext_offset] as usize) << 8) | data[ext_offset + 1] as usize;
        let mut eoff = ext_offset + 2;
        let extensions_end = eoff + extensions_len;

        while eoff + 4 <= extensions_end && eoff + 4 <= data.len() {
            let ext_type = ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
            let ext_len = ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
            eoff += 4;

            if eoff + ext_len > data.len() {
                break;
            }

            Self::apply_server_hello_extension(
                data, eoff, ext_type, ext_len,
                &mut actual_version, &mut server_key_share,
                tls13_using_psk, has_psk,
            );

            eoff += ext_len;
        }

        (actual_version, server_key_share)
    }

    /// Process a single ServerHello extension by type.
    pub(super) fn apply_server_hello_extension(
        data: &[u8],
        eoff: usize,
        ext_type: u16,
        ext_len: usize,
        actual_version: &mut TlsVersion,
        server_key_share: &mut Option<(u16, Vec<u8>)>,
        tls13_using_psk: &mut bool,
        has_psk: bool,
    ) {
        match ext_type {
            43 if ext_len >= 2 => {
                *actual_version =
                    TlsVersion(((data[eoff] as u16) << 8) | data[eoff + 1] as u16);
            }
            41 if ext_len >= 2 => {
                let selected_index =
                    ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
                if selected_index == 0 && has_psk {
                    *tls13_using_psk = true;
                }
            }
            51 if ext_len >= 4 => {
                let group =
                    ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
                let key_len =
                    ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
                if ext_len >= 4 + key_len {
                    *server_key_share =
                        Some((group, data[eoff + 4..eoff + 4 + key_len].to_vec()));
                }
            }
            _ => {}
        }
    }

    /// Handle TLS 1.3 ServerHello key exchange.
    pub(super) fn handle_tls13_hello(
        &mut self,
        cipher: CipherSuite,
        server_key_share: Option<(u16, Vec<u8>)>,
    ) -> TlsResult<()> {
        self.is_tls13 = true;

        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ];

        if self.server_random == HRR_RANDOM {
            return self.process_hello_retry_request(cipher, &server_key_share);
        }

        let (group_id, server_pubkey) = server_key_share
            .ok_or(TlsError::HandshakeFailure)?;

        let group = ecdh::EcdhGroup::from_named_group(group_id)
            .ok_or(TlsError::UnsupportedCipherSuite)?;

        let local_keypair = self
            .local_ecdh_keypair
            .as_ref()
            .ok_or(TlsError::HandshakeFailure)?;

        if local_keypair.group() != group {
            return Err(TlsError::HandshakeFailure);
        }

        let shared_secret = local_keypair
            .shared_secret(&server_pubkey)
            .map_err(|_| TlsError::CryptoError)?;

        self.pre_master_secret = shared_secret;
        self.state = TlsState::ServerHelloReceived;
        Ok(())
    }

    /// Handle TLS 1.2 ServerHello session resumption and state transition.
    pub(super) fn handle_tls12_hello(
        &mut self,
        session_id_len: usize,
        server_session_id: &[u8; 32],
    ) -> TlsResult<()> {
        if session_id_len == 32
            && self.session_id.0 != [0u8; 32]
            && *server_session_id == self.session_id.0
        {
            if let Some(ref cache) = self.session_cache {
                if let Some(entry) = cache.find(server_session_id) {
                    self.master_secret = entry.master_secret;
                    self.resuming_session = true;
                    self.state = TlsState::WaitFinishedResumed;
                    return Ok(());
                }
            }
        }
        if session_id_len == 32 {
            self.session_id = SessionId::new(*server_session_id);
        }
        self.state = TlsState::ServerHelloReceived;
        Ok(())
    }

    /// HelloRetryRequest を処理 (RFC 8446 Section 4.1.4)
    ///
    /// HRR受信時、サーバーが要求する鍵共有グループで新しいClientHelloを構築する。
    /// トランスクリプトはsynthetic message_hashに置き換える。
    pub(super) fn process_hello_retry_request(
        &mut self,
        cipher: CipherSuite,
        _server_key_share: &Option<(u16, Vec<u8>)>,
    ) -> TlsResult<()> {
        // RFC 8446 Section 4.4.1: synthetic message_hash に置き換え
        // MessageHash = Handshake(254, Hash(messages_so_far))
        let use_384 = cipher.uses_sha384();
        let current_hash: Vec<u8> = if use_384 {
            crate::loader::sha384::compute(&self.handshake_messages).to_vec()
        } else {
            let h = crate::loader::sha256::compute(&self.handshake_messages);
            h.to_vec()
        };
        let hash_len = current_hash.len();

        // synthetic message_hash 構築
        let mut synthetic = Vec::with_capacity(4 + hash_len);
        synthetic.push(254); // message_hash type
        synthetic.push(0);
        synthetic.push(0);
        synthetic.push(hash_len as u8); // hash length (32 or 48)
        synthetic.extend_from_slice(&current_hash);

        // ハンドシェイクメッセージをsynthetic message_hashに置き換え
        self.handshake_messages.clear();
        self.handshake_messages.extend_from_slice(&synthetic);

        // サーバーが要求するグループで新しい鍵ペアを生成
        // HRR の key_share 拡張はグループIDのみ含む（公開鍵なし）
        // ここではネゴシエートされた暗号スイートのグループに対応
        self.negotiated_cipher = Some(cipher);

        // 新しいClientHelloの再送信が必要であることを示す状態に遷移
        self.state = TlsState::HelloRetryReceived;

        Ok(())
    }

    /// HRR受信後に再送用の新しいClientHelloを構築
    ///
    /// `process_hello_retry_request()` で状態が `HelloRetryReceived` に
    /// 遷移した後に呼び出す。
    pub fn build_client_hello_retry(&mut self) -> Option<Vec<u8>> {
        if self.state != TlsState::HelloRetryReceived {
            return None;
        }

        // 新しいクライアントランダムは再利用可能（RFC 8446 Section 4.1.2）
        // 新しい鍵ペアを生成
        let group = if let Some(ref kp) = self.local_ecdh_keypair {
            kp.group()
        } else {
            ecdh::EcdhGroup::X25519
        };

        if let Ok(new_keypair) = ecdh::EcdhKeyPair::generate(group) {
            self.local_ecdh_keypair = Some(new_keypair);
        }

        // 通常のClientHelloと同じ構築
        self.state = TlsState::ClientHelloSent;
        Some(self.build_client_hello())
    }

    /// Certificateを処理
    ///
    /// 証明書チェーンを抽出し、検証を行う。
    /// 検証成功後、サーバー公開鍵を保存する。
    pub(super) fn extract_server_public_key_from_spki(
        &mut self,
        spki: crate::net::x509::SubjectPublicKeyInfo<'_>,
    ) -> TlsResult<()> {
        match spki {
            crate::net::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                self.server_public_key = Some(ServerPublicKey::Rsa {
                    modulus: modulus.to_vec(),
                    exponent: exponent.to_vec(),
                });
            }
            crate::net::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                self.server_public_key = Some(ServerPublicKey::EcdsaP256 {
                    point: public_key.to_vec(),
                });
            }
            crate::net::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
                self.server_public_key = Some(ServerPublicKey::EcdsaP384 {
                    point: public_key.to_vec(),
                });
            }
            _ => {
                if !self.config.skip_verify {
                    return Err(TlsError::CertificateError);
                }
            }
        }
        Ok(())
    }

    pub(super) fn extract_server_public_key(
        &mut self,
        cert: &crate::net::x509::X509Certificate,
    ) -> TlsResult<()> {
        self.extract_server_public_key_from_spki(cert.subject_public_key_info)
    }

    pub(super) fn process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 3 {
            return Err(TlsError::DecodeError);
        }

        let certs_len =
            ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

        // Security: Limit certificate chain length (e.g. 64KB)
        if data.len() < 3 + certs_len || certs_len == 0 || certs_len > 65536 {
            return Err(TlsError::CertificateError);
        }

        let cert_chain_data = &data[3..3 + certs_len];
        let mut certs = Vec::new();
        let mut offset = 0;

        // 全ての証明書を抽出
        while offset + 3 <= cert_chain_data.len() {
            let cert_len = ((cert_chain_data[offset] as usize) << 16)
                | ((cert_chain_data[offset + 1] as usize) << 8)
                | (cert_chain_data[offset + 2] as usize);
            offset += 3;

            if offset + cert_len > cert_chain_data.len() {
                return Err(TlsError::DecodeError);
            }

            certs.push(&cert_chain_data[offset..offset + cert_len]);
            offset += cert_len;
        }

        if certs.is_empty() {
            return Err(TlsError::CertificateError);
        }

        if !self.config.skip_verify {
            // 証明書チェーンの検証 (issuerの一致、署名の妥当性、ホスト名の一致)
            // NOTE: ルートCAの信頼性検証は将来的に実装予定
            if let Some(spki) = crate::net::x509::validate_certificate_chain(
                &certs,
                self.config.server_name.as_deref(),
            ) {
                self.extract_server_public_key_from_spki(spki)?;
            } else {
                return Err(TlsError::CertificateError);
            }
        } else {
            // 検証スキップ時は最初の証明書の鍵をそのまま使用
            if let Some(cert) = crate::net::x509::parse_x509(certs[0]) {
                self.extract_server_public_key(&cert)?;
            } else {
                return Err(TlsError::CertificateError);
            }
        }

        Ok(())
    }

    /// RSA署名でServerKeyExchangeを検証
    pub(super) fn verify_rsa_ske_signature(
        &self,
        signed_data: &[u8],
        signature: &[u8],
        alg_selector: u8,
    ) -> TlsResult<()> {
        let pubkey = match &self.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                crate::net::rsa::RsaPublicKey { modulus, exponent }
            }
            _ => return Err(TlsError::CertificateError),
        };

        let (hash_alg, digest) = match alg_selector {
            1 => {
                let d = crate::net::tls::crypto::legacy::sha1_compute(signed_data);
                (crate::net::rsa::HashAlgorithm::Sha1, d.to_vec())
            }
            2 => {
                let d = crate::loader::sha256::compute(signed_data);
                (crate::net::rsa::HashAlgorithm::Sha256, d.to_vec())
            }
            3 => {
                let d = crate::loader::sha384::compute(signed_data);
                (crate::net::rsa::HashAlgorithm::Sha384, d.to_vec())
            }
            _ => return Err(TlsError::CryptoError),
        };

        crate::net::rsa::rsa_pkcs1_verify(
            &pubkey,
            hash_alg,
            &digest,
            signature,
        )
        .map_err(|_| TlsError::CryptoError)
    }

    /// ECDSA P-256署名でServerKeyExchangeを検証
    pub(super) fn verify_ecdsa_ske_signature(
        &self,
        signed_data: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.server_public_key {
            Some(ServerPublicKey::EcdsaP256 { point }) => point.as_slice(),
            _ => return Err(TlsError::CertificateError),
        };
        let digest = crate::loader::sha256::compute(signed_data);
        ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// 署名アルゴリズムに応じたSKE署名検証ディスパッチ
    pub(super) fn verify_ske_sig_dispatch(
        &self,
        signed_data: &[u8],
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        match sig_algorithm {
            // RSA-PKCS1-SHA256 (0x0401)
            0x0401 => self.verify_rsa_ske_signature(signed_data, signature, 2), // 2 = SHA256
            // RSA-PKCS1-SHA384 (0x0501)
            0x0501 => self.verify_rsa_ske_signature(signed_data, signature, 3), // 3 = SHA384
            // ECDSA-SECP256R1-SHA256 (0x0403)
            0x0403 => self.verify_ecdsa_ske_signature(signed_data, signature),
            // RSA-PKCS1-SHA1 (0x0201)
            0x0201 => self.verify_rsa_ske_signature(signed_data, signature, 1), // 1 = SHA1
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// ServerKeyExchangeの署名を解析・検証
    pub(super) fn verify_ske_signature(&self, data: &[u8], ecdhe_params_end: usize) -> TlsResult<()> {
        let sig_offset = ecdhe_params_end;
        if data.len() < sig_offset + 4 {
            return Err(TlsError::DecodeError);
        }

        let sig_algorithm = ((data[sig_offset] as u16) << 8) | data[sig_offset + 1] as u16;
        let sig_len =
            ((data[sig_offset + 2] as usize) << 8) | data[sig_offset + 3] as usize;

        if data.len() < sig_offset + 4 + sig_len {
            return Err(TlsError::DecodeError);
        }

        let signature = &data[sig_offset + 4..sig_offset + 4 + sig_len];

        // 署名対象: client_random || server_random || ecdhe_params
        let ecdhe_params = &data[..ecdhe_params_end];
        let mut signed_data =
            Vec::with_capacity(32 + 32 + ecdhe_params.len());
        signed_data.extend_from_slice(&self.client_random);
        signed_data.extend_from_slice(&self.server_random);
        signed_data.extend_from_slice(ecdhe_params);

        self.verify_ske_sig_dispatch(&signed_data, sig_algorithm, signature)
    }
}
