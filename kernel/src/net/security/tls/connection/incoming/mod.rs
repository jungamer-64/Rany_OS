use arrayvec::ArrayVec;

use super::*;

mod ecdh_exchange;
impl TlsConnection {
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

    pub(super) fn handle_alert_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<()> {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        if view.total_len() >= 2 {
            let description = view.read_u8(1).ok_or(TlsError::DecodeError)?;
            if description == AlertDescription::CloseNotify as u8 {
                self.state = TlsState::Closed;
            } else {
                self.state = TlsState::Error;
                return Err(TlsError::Alert(description));
            }
        }
        Ok(())
    }

    /// TLS 1.3復号後の内部コンテントタイプを処理する
    pub(super) fn dispatch_tls13_inner_content(
        &mut self,
        decrypted: &kernel_api::resource::net::PacketPayload,
        plaintext: &mut kernel_api::resource::net::PacketPayload,
    ) -> TlsResult<()> {
        if let Some((inner_ct, inner_data)) = Self::tls13_split_content_type_payload(decrypted) {
            match ContentType::from_u8(inner_ct) {
                Some(ContentType::ApplicationData) => {
                    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                    builder
                        .push_span_ref(inner_data)
                        .ok_or(TlsError::DecodeError)?;
                    crate::net::payload::append_payload(plaintext, builder.build());
                }
                Some(ContentType::Handshake) => {
                    // Post-handshake: NewSessionTicket, KeyUpdate
                    self.tls13_process_post_handshake(
                        inner_data
                            .as_contiguous_slice()
                            .ok_or(TlsError::DecodeError)?,
                    )?;
                }
                Some(ContentType::Alert) => {
                    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                    builder
                        .push_span_ref(inner_data)
                        .ok_or(TlsError::DecodeError)?;
                    self.handle_alert_payload(&builder.build())?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// ハンドシェイクメッセージタイプに応じたディスパッチ
    pub(super) fn dispatch_handshake_message(
        &mut self,
        msg_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        match msg_type {
            2 => self.process_server_hello(payload), // ServerHello
            11 => self.process_certificate(payload), // Certificate
            12 => self.process_server_key_exchange(payload), // ServerKeyExchange
            14 => self.process_server_hello_done(payload), // ServerHelloDone
            20 => self.process_finished(payload),    // Finished
            _ => Ok(()),
        }
    }

    /// ハンドシェイクメッセージを記録し、トランスクリプトハッシュと鍵導出を更新する
    pub(super) fn record_and_update_handshake(
        &mut self,
        msg_data: &[u8],
        msg_type: u8,
    ) -> TlsResult<()> {
        // Security: Limit cumulative handshake messages to prevent memory DoS.
        // 128KB is the limit for a single message, so we allow 256KB total for the whole handshake.
        const MAX_HANDSHAKE_ACCUMULATOR: usize = 262144;
        if self.transcript_len() + msg_data.len() > MAX_HANDSHAKE_ACCUMULATOR {
            return Err(TlsError::DecodeError);
        }

        self.append_transcript_bytes(msg_data)?;
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
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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
        if data.len() < 35 {
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
        let (actual_version, server_key_share) = Self::parse_server_hello_extensions(
            data,
            ext_offset,
            _legacy_version,
            &mut self.tls13_using_psk,
            self.tls13_psk.is_some(),
        )?;

        self.negotiated_version = Some(actual_version);

        // Security: TLSダウングレード攻撃防止 (RFC 8446 Section 4.1.3)
        // TLS 1.3対応サーバーがTLS 1.2以下にネゴシエーションした場合、
        // ServerHello.randomの末尾8バイトにセンチネル値が含まれるか検証する。
        Self::check_downgrade_sentinel(&self.server_random, actual_version)?;

        if actual_version == TlsVersion::TLS_1_3 {
            self.handle_tls13_hello(cipher, server_key_share)?;
        } else {
            self.handle_tls12_hello(session_id_len, &server_session_id)?;
        }

        Ok(())
    }

    /// RFC 8446 Section 4.1.3: TLSダウングレードセンチネル検出
    ///
    /// TLS 1.3対応サーバーが低いバージョンにネゴシエーションした場合、
    /// server_randomの末尾8バイトに特定のセンチネル値を設定する。
    /// クライアントはこれを検出し、ダウングレード攻撃を防止する。
    fn check_downgrade_sentinel(
        server_random: &[u8; 32],
        negotiated_version: TlsVersion,
    ) -> TlsResult<()> {
        // "DOWNGRD\x01" - TLS 1.2へのダウングレード
        const DOWNGRD_12: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
        // "DOWNGRD\x00" - TLS 1.1以下へのダウングレード
        const DOWNGRD_11: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

        let sentinel = &server_random[24..32];

        if negotiated_version <= TlsVersion::TLS_1_2 && sentinel == &DOWNGRD_12 {
            log::warn!(
                "[TLS] Downgrade attack detected: server signaled TLS 1.2 downgrade sentinel"
            );
            return Err(TlsError::HandshakeFailure);
        }
        if negotiated_version <= TlsVersion(0x0302) && sentinel == &DOWNGRD_11 {
            log::warn!(
                "[TLS] Downgrade attack detected: server signaled TLS 1.1 downgrade sentinel"
            );
            return Err(TlsError::HandshakeFailure);
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
    ) -> TlsResult<(TlsVersion, Option<(u16, OwnedPayloadRange)>)> {
        let mut actual_version = default_version;
        let mut server_key_share: Option<(u16, OwnedPayloadRange)> = None;

        if ext_offset + 2 > data.len() {
            return Ok((actual_version, server_key_share));
        }

        let extensions_len = ((data[ext_offset] as usize) << 8) | data[ext_offset + 1] as usize;
        let mut eoff = ext_offset + 2;
        let extensions_end = eoff + extensions_len;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while eoff + 4 <= extensions_end && eoff + 4 <= data.len() {
            let ext_type = ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
            let ext_len = ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
            eoff += 4;

            if eoff + ext_len > data.len() {
                break;
            }

            Self::apply_server_hello_extension(
                data,
                eoff,
                ext_type,
                ext_len,
                &mut actual_version,
                &mut server_key_share,
                tls13_using_psk,
                has_psk,
            )?;

            eoff += ext_len;
        }

        Ok((actual_version, server_key_share))
    }

    fn payload_span_from_slice(data: &[u8]) -> TlsResult<OwnedPayloadRange> {
        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder.push_bytes(data).ok_or(TlsError::DecodeError)?;
        Ok(OwnedPayloadRange::from_payload(builder.build()))
    }

    pub(crate) fn apply_server_hello_extension(
        data: &[u8],
        offset: usize,
        ext_type: u16,
        ext_len: usize,
        actual_version: &mut TlsVersion,
        server_key_share: &mut Option<(u16, OwnedPayloadRange)>,
        tls13_using_psk: &mut bool,
        has_psk: bool,
    ) -> TlsResult<()> {
        let end = offset.saturating_add(ext_len);
        if end > data.len() {
            return Err(TlsError::DecodeError);
        }

        match ext_type {
            43 if ext_len == 2 => {
                *actual_version = TlsVersion(u16::from_be_bytes([data[offset], data[offset + 1]]));
            }
            51 if ext_len >= 2 => {
                let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
                if ext_len == 2 {
                    *server_key_share = Some((
                        group,
                        OwnedPayloadRange::from_payload(PacketPayload::default()),
                    ));
                } else {
                    if ext_len < 4 {
                        return Err(TlsError::DecodeError);
                    }
                    let key_len =
                        u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                    if 4 + key_len > ext_len {
                        return Err(TlsError::DecodeError);
                    }
                    let key_share =
                        Self::payload_span_from_slice(&data[offset + 4..offset + 4 + key_len])?;
                    *server_key_share = Some((group, key_share));
                }
            }
            41 if has_psk => {
                *tls13_using_psk = true;
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle TLS 1.3 ServerHello key exchange.
    pub(super) fn handle_tls13_hello(
        &mut self,
        cipher: CipherSuite,
        server_key_share: Option<(u16, OwnedPayloadRange)>,
    ) -> TlsResult<()> {
        self.is_tls13 = true;

        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];

        if self.server_random == HRR_RANDOM {
            return self.process_hello_retry_request(cipher, &server_key_share);
        }

        let (group_id, server_pubkey) = server_key_share.ok_or(TlsError::HandshakeFailure)?;

        let group =
            ecdh::EcdhGroup::from_named_group(group_id).ok_or(TlsError::UnsupportedCipherSuite)?;

        let local_keypair = self
            .local_ecdh_keypair
            .as_ref()
            .ok_or(TlsError::HandshakeFailure)?;

        if local_keypair.group() != group {
            return Err(TlsError::HandshakeFailure);
        }

        let server_pubkey = server_pubkey
            .as_contiguous_slice()
            .ok_or(TlsError::DecodeError)?;
        let shared_secret = local_keypair
            .shared_secret(&server_pubkey)
            .map_err(|_| TlsError::CryptoError)?;

        Self::set_tls_bytes(&mut self.pre_master_secret, shared_secret.as_slice())?;
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
        _server_key_share: &Option<(u16, OwnedPayloadRange)>,
    ) -> TlsResult<()> {
        // RFC 8446 Section 4.4.1: synthetic message_hash に置き換え
        // MessageHash = Handshake(254, Hash(messages_so_far))
        self.transcript_state
            .replace_with_message_hash(cipher.uses_sha384());

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
    pub fn build_client_hello_retry(&mut self) -> Option<kernel_api::resource::net::PacketPayload> {
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
        Some(self.build_client_hello_payload())
    }

    pub(super) fn extract_server_public_key(
        &mut self,
        cert: &crate::net::security::x509::X509Certificate,
    ) -> TlsResult<()> {
        self.extract_server_public_key_from_spki(cert.subject_public_key_info)
    }

    pub(crate) fn extract_server_public_key_from_spki(
        &mut self,
        spki: crate::net::security::x509::SubjectPublicKeyInfo<'_>,
    ) -> TlsResult<()> {
        self.server_public_key = Some(match spki {
            crate::net::security::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                ServerPublicKey::Rsa {
                    modulus: Self::payload_span_from_slice(modulus)?,
                    exponent: Self::payload_span_from_slice(exponent)?,
                }
            }
            crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                ServerPublicKey::EcdsaP256 {
                    point: Self::payload_span_from_slice(public_key)?,
                }
            }
            crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
                ServerPublicKey::EcdsaP384 {
                    point: Self::payload_span_from_slice(public_key)?,
                }
            }
            crate::net::security::x509::SubjectPublicKeyInfo::Unknown(_) => {
                return Err(TlsError::UnsupportedCipherSuite);
            }
        });
        Ok(())
    }

    pub(crate) fn set_server_public_key_from_cert(&mut self, cert_der: &[u8]) -> TlsResult<()> {
        let cert = crate::net::security::x509::parse_x509(cert_der)
            .ok_or(TlsError::CertificateError)?;
        self.extract_server_public_key(&cert)
    }

    pub(super) fn process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 3 {
            return Err(TlsError::DecodeError);
        }

        let certs_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

        // Security: Limit certificate chain length (e.g. 64KB)
        if data.len() < 3 + certs_len || certs_len == 0 || certs_len > 65536 {
            return Err(TlsError::CertificateError);
        }

        let cert_chain_data = &data[3..3 + certs_len];
        let mut certs = ArrayVec::<&[u8], TLS_CERT_CHAIN_CAPACITY>::new();
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

            certs
                .try_push(&cert_chain_data[offset..offset + cert_len])
                .map_err(|_| TlsError::CertificateError)?;
            offset += cert_len;
        }

        if certs.is_empty() {
            return Err(TlsError::CertificateError);
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
            log::warn!(
                "[TLS] Security: Certificate verification skipped. This connection is vulnerable to Man-in-the-Middle attacks!"
            );
            if let Some(cert) = crate::net::security::x509::parse_x509(certs[0]) {
                self.extract_server_public_key(&cert)?;
            } else {
                return Err(TlsError::CertificateError);
            }
        }

        Ok(())
    }

    /// RSA署名でServerKeyExchangeを検証
    pub(super) fn verify_rsa_ske_signature_parts(
        &self,
        ecdhe_params: &[u8],
        signature: &[u8],
        alg_selector: u8,
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

        match alg_selector {
            2 => {
                let mut hasher = crate::crypto::sha256::Sha256::new();
                hasher.update(&self.client_random);
                hasher.update(&self.server_random);
                hasher.update(ecdhe_params);
                let digest = hasher.finalize();
                crate::net::security::rsa::rsa_pkcs1_verify(
                    &pubkey,
                    crate::net::security::rsa::HashAlgorithm::Sha256,
                    &digest,
                    signature,
                )
                .map_err(|_| TlsError::CryptoError)
            }
            3 => {
                let mut hasher = crate::crypto::sha384::Sha384::new();
                hasher.update(&self.client_random);
                hasher.update(&self.server_random);
                hasher.update(ecdhe_params);
                let digest = hasher.finalize();
                crate::net::security::rsa::rsa_pkcs1_verify(
                    &pubkey,
                    crate::net::security::rsa::HashAlgorithm::Sha384,
                    &digest,
                    signature,
                )
                .map_err(|_| TlsError::CryptoError)
            }
            _ => Err(TlsError::CryptoError),
        }
    }

    /// ECDSA P-256署名でServerKeyExchangeを検証
    pub(super) fn verify_ecdsa_ske_signature_parts(
        &self,
        ecdhe_params: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.server_public_key {
            Some(ServerPublicKey::EcdsaP256 { point }) => point
                .as_contiguous_slice()
                .ok_or(TlsError::CertificateError)?,
            _ => return Err(TlsError::CertificateError),
        };
        let mut hasher = crate::crypto::sha256::Sha256::new();
        hasher.update(&self.client_random);
        hasher.update(&self.server_random);
        hasher.update(ecdhe_params);
        let digest = hasher.finalize();
        ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// 署名アルゴリズムに応じたSKE署名検証ディスパッチ
    pub(super) fn verify_ske_sig_dispatch(
        &self,
        ecdhe_params: &[u8],
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        match sig_algorithm {
            // RSA-PKCS1-SHA256 (0x0401)
            0x0401 => self.verify_rsa_ske_signature_parts(ecdhe_params, signature, 2), // 2 = SHA256
            // RSA-PKCS1-SHA384 (0x0501)
            0x0501 => self.verify_rsa_ske_signature_parts(ecdhe_params, signature, 3), // 3 = SHA384
            // ECDSA-SECP256R1-SHA256 (0x0403)
            0x0403 => self.verify_ecdsa_ske_signature_parts(ecdhe_params, signature),
            // Security: SHA-1 (0x0201) is deprecated and removed for security reasons.
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// ServerKeyExchangeの署名を解析・検証
    pub(super) fn verify_ske_signature(
        &self,
        data: &[u8],
        ecdhe_params_end: usize,
    ) -> TlsResult<()> {
        let sig_offset = ecdhe_params_end;
        if data.len() < sig_offset + 4 {
            return Err(TlsError::DecodeError);
        }

        let sig_algorithm = ((data[sig_offset] as u16) << 8) | data[sig_offset + 1] as u16;
        let sig_len = ((data[sig_offset + 2] as usize) << 8) | data[sig_offset + 3] as usize;

        if data.len() < sig_offset + 4 + sig_len {
            return Err(TlsError::DecodeError);
        }

        let signature = &data[sig_offset + 4..sig_offset + 4 + sig_len];

        // 署名対象: client_random || server_random || ecdhe_params
        let ecdhe_params = &data[..ecdhe_params_end];
        self.verify_ske_sig_dispatch(ecdhe_params, sig_algorithm, signature)
    }
}
