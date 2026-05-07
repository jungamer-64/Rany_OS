// ============================================================================
// kernel/src/net/security/tls/connection/client_hello.rs - セキュリティ / TLS / 接続 / ClientHello処理
// ============================================================================

use super::{
    CipherSuite, ContentType, HandshakeType, PacketPayload, PacketPayloadBuilder,
    PacketPayloadView, SessionId, TLS_CLIENT_HELLO_SCRATCH_CAPACITY,
    TLS_EXTENSION_SCRATCH_CAPACITY, TlsBytes, TlsConnection, TlsState, TlsVersion, append_payload,
    ecdh,
};
use crate::net::security::tls::crypto::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, hmac_sha256, hmac_sha384, tls13_derive_secret,
    tls13_derive_secret_sha384, tls13_derive_traffic_keys, tls13_derive_traffic_keys_sha384,
    tls13_early_secret, tls13_early_secret_sha384,
};

impl TlsConnection {
    pub(super) fn hash_len(&self) -> usize {
        if self
            .negotiation
            .negotiated_cipher
            .map_or(false, |c| c.uses_sha384())
        {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        }
    }

    /// ClientHelloを構築
    /// TLS 1.3 用のECDH一時鍵を事前生成する
    fn prepare_tls13_ecdh_keypair(&mut self) {
        if self.config.max_version != TlsVersion::TLS_1_3
            || self.handshake_secrets.local_ecdh_keypair.is_some()
        {
            return;
        }
        if let Ok(keypair) = ecdh::EcdhKeyPair::generate(ecdh::EcdhGroup::X25519) {
            self.handshake_secrets.local_ecdh_keypair = Some(keypair);
        }
    }

    /// トランスクリプトハッシュを初期化する（HRR後の再送にも対応）
    fn init_transcript_hash(&mut self) {
        self.transcript.initialize();
    }

    /// セッションキャッシュからセッションIDを探してhelloに追加する
    fn append_session_id<const N: usize>(&mut self, hello: &mut TlsBytes<N>) -> Option<()> {
        let cached_session_id = if let Some(ref cache) = self.resumption.session_cache {
            if let Some(ref name) = self.negotiation.server_name {
                cache
                    .find_by_server_name(name.as_str())
                    .map(|entry| entry.session_id)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(sid) = cached_session_id {
            hello.push_byte(32)?;
            hello.append_slice(&sid)?;
            self.negotiation.session_id = SessionId::new(sid);
        } else {
            hello.push_byte(0)?;
        }
        Some(())
    }

    /// PSKバインダーを計算してmessageに上書きする (RFC 8446 Section 4.2.11.2)
    fn compute_psk_binders<const N: usize>(&self, message: &mut TlsBytes<N>) {
        let Some(psk) = self.resumption.tls13_psk.as_ref() else {
            return;
        };
        if self.tls13.session_ticket.is_none() {
            return;
        }
        let use_384 = self
            .resumption
            .tls13_psk_cipher
            .map_or(false, |c| c.uses_sha384());
        let hash_len = if use_384 { 48 } else { 32 };
        let binders_total = 2 + 1 + hash_len;

        if message.len() <= binders_total {
            return;
        }

        let truncated_len = message.len() - binders_total;

        if use_384 {
            let early_secret = tls13_early_secret_sha384(Some(psk.as_slice()));
            let empty_hash = crate::crypto::sha384::compute(&[]);
            let binder_key = tls13_derive_secret_sha384(&early_secret, b"res binder", &empty_hash);
            let transcript_hash =
                crate::crypto::sha384::compute(&message.as_slice()[..truncated_len]);
            let binder = hmac_sha384(&binder_key, &transcript_hash);
            let binder_start = message.len() - hash_len;
            let _ = message.write_slice(binder_start, &binder[..hash_len]);
        } else {
            let early_secret = tls13_early_secret(Some(psk.as_slice()));
            let empty_hash = {
                let h = crate::crypto::sha256::Sha256::new();
                h.finalize()
            };
            let binder_key = tls13_derive_secret(&early_secret, b"res binder", &empty_hash);
            let transcript_hash = {
                let mut h = crate::crypto::sha256::Sha256::new();
                h.update(&message.as_slice()[..truncated_len]);
                h.finalize()
            };
            let binder = hmac_sha256(&binder_key, &transcript_hash);
            let binder_start = message.len() - hash_len;
            let _ = message.write_slice(binder_start, &binder[..hash_len]);
        }
    }

    /// PSK使用時にEarly Data暗号化鍵を導出する (RFC 8446 Section 7.1)
    fn derive_early_data_keys_if_needed(&mut self) {
        if self.resumption.tls13_psk.is_none() || self.early_data.max_early_data_size == 0 {
            return;
        }
        let psk = self.resumption.tls13_psk.as_ref().unwrap();
        let use_384 = self
            .resumption
            .tls13_psk_cipher
            .map_or(false, |c| c.uses_sha384());
        let cipher = self
            .resumption
            .tls13_psk_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();

        if use_384 {
            let early_secret = tls13_early_secret_sha384(Some(psk.as_slice()));
            let ch_hash = self.transcript_hash_sha384();
            let cets = tls13_derive_secret_sha384(&early_secret, b"c e traffic", &ch_hash);
            let mut ew_iv = [0u8; 12];
            let ew_key = &mut self.early_data.early_write_key.as_mut_storage()[..key_len];
            tls13_derive_traffic_keys_sha384(&cets, ew_key, &mut ew_iv);
            self.early_data
                .early_write_key
                .set_filled_len(key_len)
                .expect("early write key length");
            Self::set_tls_bytes(&mut self.early_data.early_write_iv, &ew_iv)
                .expect("early write iv length");
        } else {
            let early_secret = tls13_early_secret(Some(psk.as_slice()));
            let ch_hash = self.transcript_hash_sha256();
            let cets = tls13_derive_secret(&early_secret, b"c e traffic", &ch_hash);
            let mut ew_iv = [0u8; 12];
            let ew_key = &mut self.early_data.early_write_key.as_mut_storage()[..key_len];
            tls13_derive_traffic_keys(&cets, ew_key, &mut ew_iv);
            self.early_data
                .early_write_key
                .set_filled_len(key_len)
                .expect("early write key length");
            Self::set_tls_bytes(&mut self.early_data.early_write_iv, &ew_iv)
                .expect("early write iv length");
        }
        self.early_data.early_write_seq = 0;
    }

    /// ClientHelloを構築
    pub fn build_client_hello_payload(&mut self) -> PacketPayload {
        self.prepare_tls13_ecdh_keypair();
        self.init_transcript_hash();

        let mut hello = TlsBytes::<TLS_CLIENT_HELLO_SCRATCH_CAPACITY>::new();

        // バージョン（TLS 1.2として送信、supported_versionsで実際のバージョンを指定）
        if hello.append_slice(&[0x03, 0x03]).is_none() {
            return PacketPayload::default();
        }

        // クライアントランダム
        if hello
            .append_slice(&self.negotiation.client_random)
            .is_none()
        {
            return PacketPayload::default();
        }

        // セッションID（キャッシュからの再開を試みる）
        if self.append_session_id(&mut hello).is_none() {
            return PacketPayload::default();
        }

        // 暗号スイート
        if hello
            .append_be_u16((self.config.cipher_suites.len() * 2) as u16)
            .is_none()
        {
            return PacketPayload::default();
        }
        for cipher in &self.config.cipher_suites {
            if hello.append_be_u16(cipher.0).is_none() {
                return PacketPayload::default();
            }
        }

        // 圧縮方式（null のみ）
        if hello.append_slice(&[0x01, 0x00]).is_none() {
            return PacketPayload::default();
        }

        // 拡張機能
        let mut extensions = TlsBytes::<TLS_EXTENSION_SCRATCH_CAPACITY>::new();
        if self.append_extensions(&mut extensions).is_none() {
            return PacketPayload::default();
        }
        if hello.append_be_u16(extensions.len() as u16).is_none()
            || hello.append_slice(extensions.as_slice()).is_none()
        {
            return PacketPayload::default();
        }

        // ハンドシェイクヘッダを追加
        let mut message = TlsBytes::<TLS_CLIENT_HELLO_SCRATCH_CAPACITY>::new();
        if message
            .push_byte(HandshakeType::ClientHello as u8)
            .is_none()
            || message.append_be_u24(hello.len()).is_none()
            || message.append_slice(hello.as_slice()).is_none()
        {
            return PacketPayload::default();
        }

        // PSKバインダー計算
        self.compute_psk_binders(&mut message);

        // ハンドシェイクメッセージを記録
        self.append_transcript_bytes(message.as_slice())
            .expect("client hello transcript append");

        // Early Data鍵導出
        self.derive_early_data_keys_if_needed();

        // レコードヘッダを追加
        let record_header = [
            ContentType::Handshake as u8,
            0x03,
            0x01, // TLS 1.0（互換性のため）
            (message.len() >> 8) as u8,
            message.len() as u8,
        ];

        self.negotiation.state = TlsState::ClientHelloSent;
        let mut builder = PacketPayloadBuilder::new();
        if builder.push_bytes(&record_header).is_none() {
            return PacketPayload::default();
        }
        if builder.push_bytes(message.as_slice()).is_none() {
            return PacketPayload::default();
        }
        builder.build()
    }

    /// 0-RTTアーリーデータを暗号化して送信 (RFC 8446 Section 4.2.10)
    ///
    /// ClientHello送信直後に呼び出す。Early Data鍵が導出済みの場合のみ動作。
    /// データはバッファリングされ、サーバーが拒否した場合は`get_rejected_early_data_payload()`で取得可能。
    ///
    /// # Returns
    /// 暗号化されたTLSレコード列。鍵未導出時やサイズ超過時は空。
    fn send_early_data_record_payload(&mut self, payload: &PacketPayload) -> PacketPayload {
        if self.early_data.early_write_key.is_empty() || self.early_data.early_write_iv.len() < 12 {
            return PacketPayload::default();
        }

        if payload.is_empty() {
            return PacketPayload::default();
        }

        let payload_view = PacketPayloadView::new(payload);

        let cipher = self
            .resumption
            .tls13_psk_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let mut inner_plaintext = match crate::net::payload::alloc_packet_with_headroom(
            payload_view.total_len() + 1,
            0,
        ) {
            Some(packet) => packet,
            None => return PacketPayload::default(),
        };
        let mut copied = 0usize;
        payload_view.for_each_chunk(|chunk| {
            let take = chunk.len().min(payload_view.total_len() - copied);
            inner_plaintext.data_mut()[copied..copied + take].copy_from_slice(&chunk[..take]);
            copied += take;
        });
        if copied != payload_view.total_len() {
            return PacketPayload::default();
        }
        inner_plaintext.data_mut()[payload_view.total_len()] = ContentType::ApplicationData as u8;

        // Nonce: IV XOR (zero-padded sequence number)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.early_data.early_write_iv.as_slice()[..12]);
        let seq_bytes = self.early_data.early_write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = payload_view.total_len() + 1 + 16;

        // AAD: TLS record header
        let aad = Self::tls13_record_aad(encrypted_len);

        let (ciphertext, auth_tag) = match Self::encrypt_aead_payload(
            cipher,
            self.early_data.early_write_key.as_slice(),
            &nonce,
            &aad,
            &inner_plaintext.data()[..payload_view.total_len() + 1],
        ) {
            Ok(parts) => parts,
            Err(_) => return PacketPayload::default(),
        };

        let encrypted_len_bytes = (encrypted_len as u16).to_be_bytes();
        let record_header = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            encrypted_len_bytes[0],
            encrypted_len_bytes[1],
        ];

        self.early_data.early_write_seq += 1;
        self.early_data.early_data_sent = true;
        let mut builder = PacketPayloadBuilder::new();
        if builder.push_bytes(&record_header).is_none() {
            return PacketPayload::default();
        }
        builder.push_payload(ciphertext);
        if builder.push_bytes(&auth_tag).is_none() {
            return PacketPayload::default();
        }
        builder.build()
    }

    pub fn send_early_data_payload(&mut self, payload: PacketPayload) -> PacketPayload {
        let total = self.early_data.early_data_buffer.total_len() + payload.total_len();
        if self.early_data.max_early_data_size > 0
            && total > self.early_data.max_early_data_size as usize
        {
            return PacketPayload::default();
        }
        let record = self.send_early_data_record_payload(&payload);
        append_payload(&mut self.early_data.early_data_buffer, payload);
        record
    }

    /// サーバーに拒否されたEarly Dataの平文を取得
    ///
    /// ハンドシェイク完了後、`early_data_accepted`がfalseの場合に呼び出し、
    /// バッファされたデータを通常のアプリケーションデータとして再送する。
    pub fn get_rejected_early_data_payload(&mut self) -> PacketPayload {
        if self.early_data.early_data_accepted || !self.early_data.early_data_sent {
            return PacketPayload::default();
        }
        core::mem::take(&mut self.early_data.early_data_buffer)
    }

    /// 拡張機能を構築
    /// Supported Versions拡張を構築 (RFC 8446 Section 4.2.1)
    fn append_supported_versions_ext<const N: usize>(&self, ext: &mut TlsBytes<N>) -> Option<()> {
        let len_offset = ext.len();
        ext.push_byte(0)?;
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            ext.append_slice(&[0x03, 0x04])?; // TLS 1.3
        }
        if self.config.min_version <= TlsVersion::TLS_1_2 {
            ext.append_slice(&[0x03, 0x03])?; // TLS 1.2
        }
        if self.config.min_version <= TlsVersion::TLS_1_1
            && self.config.max_version >= TlsVersion::TLS_1_1
        {
            ext.append_slice(&[0x03, 0x02])?; // TLS 1.1
        }
        if self.config.min_version <= TlsVersion::TLS_1_0 {
            ext.append_slice(&[0x03, 0x01])?; // TLS 1.0
        }
        let versions_len = ext.len().checked_sub(len_offset + 1)?;
        ext.write_slice(len_offset, &[versions_len as u8])?;
        Some(())
    }

    /// TLS 1.3固有の拡張を追加（PSK modes, Key Share, Early Data, Pre-Shared Key）
    fn append_tls13_extensions<const N: usize>(&self, extensions: &mut TlsBytes<N>) -> Option<()> {
        // PSK Key Exchange Modes (RFC 8446 Section 4.2.9)
        {
            extensions.append_slice(&[0, 45])?; // type = psk_key_exchange_modes
            extensions.append_be_u16(2)?;
            extensions.append_slice(&[1, 1])?;
        }

        // Key Share (RFC 8446 Section 4.2.8)
        if let Some(ref keypair) = self.handshake_secrets.local_ecdh_keypair {
            let pubkey_bytes = keypair.public_key_bytes();
            let group_id = keypair.group().to_named_group();
            let entry_len = 2 + 2 + pubkey_bytes.len();
            let mut ext = TlsBytes::<128>::new();
            ext.append_be_u16(entry_len as u16)?;
            ext.append_be_u16(group_id)?;
            ext.append_be_u16(pubkey_bytes.len() as u16)?;
            ext.append_slice(pubkey_bytes.as_slice())?;
            extensions.append_slice(&[0, 51])?; // type = key_share
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }

        // early_data (RFC 8446 Section 4.2.10)
        if self.resumption.tls13_psk.is_some() && self.early_data.max_early_data_size > 0 {
            extensions.append_slice(&[0, 42])?; // type = early_data
            extensions.append_be_u16(0)?; // length = 0
        }

        // pre_shared_key (RFC 8446 Section 4.2.11) - MUST be last extension
        if let Some(ref session_ticket) = self.tls13.session_ticket {
            let use_384 = self
                .resumption
                .tls13_psk_cipher
                .map_or(false, |c| c.uses_sha384());
            let hash_len = if use_384 { 48 } else { 32 };
            let obfuscated_age: u32 = self.resumption.tls13_ticket_age_add;
            let Some(identity_bytes) = session_ticket
                .ticket_span()
                .and_then(|span| span.single_chunk())
            else {
                return None;
            };
            let identity_len = identity_bytes.len();
            let identities_len = 2 + identity_len + 4;
            let binders_len = 1 + hash_len;
            let ext_data_len = 2 + identities_len + 2 + binders_len;

            extensions.append_slice(&[0, 41])?; // type = pre_shared_key
            extensions.append_be_u16(ext_data_len as u16)?;
            extensions.append_be_u16(identities_len as u16)?;
            extensions.append_be_u16(identity_len as u16)?;
            extensions.append_slice(identity_bytes)?;
            extensions.append_slice(&obfuscated_age.to_be_bytes())?;
            extensions.append_be_u16(binders_len as u16)?;
            extensions.push_byte(hash_len as u8)?;
            extensions.append_zeroes(hash_len)?; // binder placeholder
        }
        Some(())
    }

    /// 拡張機能を構築
    fn append_extensions<const N: usize>(&self, extensions: &mut TlsBytes<N>) -> Option<()> {
        // Server Name Indication
        if let Some(ref name) = self.negotiation.server_name {
            let name_bytes = name.as_bytes();
            let mut ext = TlsBytes::<512>::new();
            let list_len = name_bytes.len() + 3;
            ext.append_be_u16(list_len as u16)?;
            ext.push_byte(0)?; // hostname type
            ext.append_be_u16(name_bytes.len() as u16)?;
            ext.append_slice(name_bytes)?;
            extensions.append_slice(&[0, 0])?; // SNI type
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }

        // Supported Groups
        {
            let mut ext = TlsBytes::<128>::new();
            ext.append_be_u16((self.config.named_groups.len() * 2) as u16)?;
            for group in &self.config.named_groups {
                ext.append_be_u16(group.0)?;
            }
            extensions.append_slice(&[0, 10])?; // type
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }

        // Signature Algorithms
        {
            let mut ext = TlsBytes::<128>::new();
            ext.append_be_u16((self.config.signature_schemes.len() * 2) as u16)?;
            for scheme in &self.config.signature_schemes {
                ext.append_be_u16(scheme.0)?;
            }
            extensions.append_slice(&[0, 13])?; // type
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }

        // Supported Versions
        {
            let mut ext = TlsBytes::<32>::new();
            self.append_supported_versions_ext(&mut ext)?;
            extensions.append_slice(&[0, 43])?; // type = supported_versions
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }

        // TLS 1.3固有の拡張
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            self.append_tls13_extensions(extensions)?;
        }

        // ALPN
        if !self.config.alpn_protocols.is_empty() {
            let mut protos = TlsBytes::<512>::new();
            for proto in &self.config.alpn_protocols {
                protos.push_byte(proto.len() as u8)?;
                protos.append_slice(proto.as_bytes())?;
            }
            let mut ext = TlsBytes::<512>::new();
            ext.append_be_u16(protos.len() as u16)?;
            ext.append_slice(protos.as_slice())?;
            extensions.append_slice(&[0, 16])?; // type
            extensions.append_be_u16(ext.len() as u16)?;
            extensions.append_slice(ext.as_slice())?;
        }
        Some(())
    }
}
