// ============================================================================
// kernel/src/net/security/tls/connection/handshake/server_hello.rs - セキュリティ / TLS / 接続 / ハンドシェイク / ServerHello処理
// ============================================================================

use super::super::{
    CipherSuite, OwnedPayloadRange, PacketPayload, SessionId, TlsConnection, TlsState, TlsVersion,
};
use crate::net::security::ecdh;
use crate::net::security::tls::error::{TlsError, TlsResult};

impl TlsConnection {
    pub(super) fn process_server_hello(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 35 {
            return Err(TlsError::DecodeError);
        }

        let _legacy_version = TlsVersion(((data[0] as u16) << 8) | data[1] as u16);
        self.negotiation.server_random.copy_from_slice(&data[2..34]);

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
        self.negotiation.negotiated_cipher = Some(cipher);

        let ext_offset = offset + 3;
        let (actual_version, server_key_share) = Self::parse_server_hello_extensions(
            data,
            ext_offset,
            _legacy_version,
            &mut self.resumption.tls13_using_psk,
            self.resumption.tls13_psk.is_some(),
        )?;

        self.negotiation.negotiated_version = Some(actual_version);

        // SECURITY: TLSダウングレード攻撃防止 (RFC 8446 Section 4.1.3)
        // TLS 1.3対応サーバーがTLS 1.2以下にネゴシエーションした場合、
        // ServerHello.randomの末尾8バイトにセンチネル値が含まれるか検証する。
        Self::check_downgrade_sentinel(&self.negotiation.server_random, actual_version)?;

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

    pub(super) fn payload_span_from_slice(data: &[u8]) -> TlsResult<OwnedPayloadRange> {
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
        self.negotiation.is_tls13 = true;

        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];

        if self.negotiation.server_random == HRR_RANDOM {
            return self.process_hello_retry_request(cipher, &server_key_share);
        }

        let (group_id, server_pubkey) = server_key_share.ok_or(TlsError::HandshakeFailure)?;

        let group =
            ecdh::EcdhGroup::from_named_group(group_id).ok_or(TlsError::UnsupportedCipherSuite)?;

        let local_keypair = self.handshake_secrets.local_ecdh_keypair
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

        Self::set_tls_bytes(&mut self.handshake_secrets.pre_master_secret, shared_secret.as_slice())?;
        self.negotiation.state = TlsState::ServerHelloReceived;
        Ok(())
    }

    /// Handle TLS 1.2 ServerHello session resumption and state transition.
    pub(super) fn handle_tls12_hello(
        &mut self,
        session_id_len: usize,
        server_session_id: &[u8; 32],
    ) -> TlsResult<()> {
        if session_id_len == 32
            && self.negotiation.session_id.0 != [0u8; 32]
            && *server_session_id == self.negotiation.session_id.0
        {
            if let Some(ref cache) = self.resumption.session_cache {
                if let Some(entry) = cache.find(server_session_id) {
                    self.handshake_secrets.master_secret = entry.master_secret;
                    self.resumption.resuming_session = true;
                    self.negotiation.state = TlsState::WaitFinishedResumed;
                    return Ok(());
                }
            }
        }
        if session_id_len == 32 {
            self.negotiation.session_id = SessionId::new(*server_session_id);
        }
        self.negotiation.state = TlsState::ServerHelloReceived;
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
        self.transcript
            .replace_with_message_hash(cipher.uses_sha384());

        // サーバーが要求するグループで新しい鍵ペアを生成
        // HRR の key_share 拡張はグループIDのみ含む（公開鍵なし）
        // ここではネゴシエートされた暗号スイートのグループに対応
        self.negotiation.negotiated_cipher = Some(cipher);

        // 新しいClientHelloの再送信が必要であることを示す状態に遷移
        self.negotiation.state = TlsState::HelloRetryReceived;

        Ok(())
    }

    /// HRR受信後に再送用の新しいClientHelloを構築
    ///
    /// `process_hello_retry_request()` で状態が `HelloRetryReceived` に
    /// 遷移した後に呼び出す。
    pub fn build_client_hello_retry(&mut self) -> Option<kernel_api::resource::net::PacketPayload> {
        if self.negotiation.state != TlsState::HelloRetryReceived {
            return None;
        }

        // 新しいクライアントランダムは再利用可能（RFC 8446 Section 4.1.2）
        // 新しい鍵ペアを生成
        let group = if let Some(ref kp) = self.handshake_secrets.local_ecdh_keypair {
            kp.group()
        } else {
            ecdh::EcdhGroup::X25519
        };

        if let Ok(new_keypair) = ecdh::EcdhKeyPair::generate(group) {
            self.handshake_secrets.local_ecdh_keypair = Some(new_keypair);
        }

        // 通常のClientHelloと同じ構築
        self.negotiation.state = TlsState::ClientHelloSent;
        Some(self.build_client_hello_payload())
    }
}
