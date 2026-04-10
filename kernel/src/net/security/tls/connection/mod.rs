// ============================================================================
// tls/connection.rs - TLS Connection State Machine
// ============================================================================

// Building block: TLS connection internals
#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

use super::crypto::*;
use super::error::{TlsError, TlsResult};
use super::types::*;
use crate::net::payload::{PacketPayloadBuilder, PacketPayloadView, PayloadSpan, append_payload};
use crate::net::security::ecdh;
use kernel_api::resource::net::PacketPayload;

/// TLS 1.3 トランスクリプトハッシュ（SHA-256 or SHA-384）
mod incoming;
enum TranscriptHash {
    Sha256(crate::crypto::sha256::Sha256),
    Sha384(crate::crypto::sha384::Sha384),
}

impl TranscriptHash {
    /// ハッシュデータを更新
    fn update(&mut self, data: &[u8]) {
        match self {
            TranscriptHash::Sha256(h) => h.update(data),
            TranscriptHash::Sha384(h) => h.update(data),
        }
    }
}

// ============================================================================
// TLS Connection
// ============================================================================

/// TLS接続
///
/// # NOTE
/// この構造体は多数のフィールドを持ち、スタック上で数KBを消費します。
/// スタックオーバーフローを避けるため、`Box<TlsConnection>` での
/// ヒープ確保を推奨します。
pub struct TlsConnection {
    /// 設定
    config: TlsConfig,
    /// 状態
    state: TlsState,
    /// ネゴシエートされたバージョン
    negotiated_version: Option<TlsVersion>,
    /// ネゴシエートされた暗号スイート
    negotiated_cipher: Option<CipherSuite>,
    /// セッションID
    session_id: SessionId,
    /// クライアントランダム
    client_random: [u8; 32],
    /// サーバーランダム
    server_random: [u8; 32],
    /// マスターシークレット
    master_secret: [u8; 48],
    /// 読み取りキー
    read_key: Vec<u8>,
    /// 書き込みキー
    write_key: Vec<u8>,
    /// 読み取りIV
    read_iv: Vec<u8>,
    /// 書き込みIV
    write_iv: Vec<u8>,
    /// シーケンス番号（読み取り）
    read_seq: u64,
    /// シーケンス番号（書き込み）
    write_seq: u64,
    /// 受信バッファ
    recv_buffer: PacketPayload,
    /// ハンドシェイクトランスクリプト（verify用）
    handshake_transcript: PacketPayload,
    /// Pre-master secret (from key exchange, used to derive master secret)
    pre_master_secret: Vec<u8>,
    /// ECDH一時鍵ペア（ClientKeyExchange送信用）
    local_ecdh_keypair: Option<ecdh::EcdhKeyPair>,
    /// サーバー証明書の公開鍵情報 (X.509から抽出)
    server_public_key: Option<ServerPublicKey>,
    // ========================================================================
    // TLS 1.3 specific fields
    // ========================================================================
    /// TLS 1.3 mode flag
    is_tls13: bool,
    /// TLS 1.3: ハンドシェイクトラフィック秘密（サーバー側）
    server_hs_traffic_secret: [u8; 48],
    /// TLS 1.3: ハンドシェイクトラフィック秘密（クライアント側）
    client_hs_traffic_secret: [u8; 48],
    /// TLS 1.3: アプリケーショントラフィック秘密（サーバー側）
    server_app_traffic_secret: [u8; 48],
    /// TLS 1.3: アプリケーショントラフィック秘密（クライアント側）
    client_app_traffic_secret: [u8; 48],
    /// TLS 1.3: ハンドシェイク読み取り鍵
    hs_read_key: Vec<u8>,
    /// TLS 1.3: ハンドシェイク読み取りIV
    hs_read_iv: Vec<u8>,
    /// TLS 1.3: ハンドシェイク書き込み鍵
    hs_write_key: Vec<u8>,
    /// TLS 1.3: ハンドシェイク書き込みIV
    hs_write_iv: Vec<u8>,
    /// TLS 1.3: ハンドシェイク読み取りシーケンス番号
    hs_read_seq: u64,
    /// TLS 1.3: ハンドシェイク書き込みシーケンス番号
    hs_write_seq: u64,
    /// TLS 1.3: ハンドシェイクメッセージのトランスクリプトハッシュ状態（SHA-256 or SHA-384）
    transcript_hash: Option<TranscriptHash>,
    /// TLS 1.3: 受信済みセッションチケット
    session_ticket: Option<SessionTicket>,
    /// TLS 1.3: KeyUpdate応答送信が必要か
    pending_key_update_response: bool,
    // ========================================================================
    // CBC mode fields (TLS 1.0/1.1/1.2 CBC cipher suites)
    // ========================================================================
    /// 読み取りMAC鍵 (HMAC-SHA1 or HMAC-SHA256)
    read_mac_key: Vec<u8>,
    /// 書き込みMAC鍵
    write_mac_key: Vec<u8>,
    /// CBC読み取りIV (TLS 1.0は前レコード最終ブロック / TLS 1.1+は明示的IV)
    read_cbc_iv: [u8; 16],
    /// CBC書き込みIV
    write_cbc_iv: [u8; 16],
    /// TLS 1.0用: 最後の読み取り暗号文ブロック（暗黙IV）
    last_read_ciphertext_block: Option<[u8; 16]>,
    /// TLS 1.0用: 最後の書き込み暗号文ブロック（暗黙IV）
    last_write_ciphertext_block: Option<[u8; 16]>,
    // ========================================================================
    // Session resumption (TLS 1.2)
    // ========================================================================
    /// セッションキャッシュ
    session_cache: Option<SessionCache>,
    /// 略式ハンドシェイク中か
    resuming_session: bool,
    // ========================================================================
    // TLS 1.3 PSK session resumption
    // ========================================================================
    /// TLS 1.3: resumption_master_secret (接続完了後に導出)
    resumption_master_secret: Vec<u8>,
    /// TLS 1.3: 導出済みPSK (チケットから導出)
    tls13_psk: Option<Vec<u8>>,
    /// TLS 1.3: PSK identity (セッションチケットそのもの)
    tls13_psk_identity: Option<PayloadSpan>,
    /// TLS 1.3: チケットage_add値
    tls13_ticket_age_add: u32,
    /// TLS 1.3: 現在の接続がPSKを使用中か
    tls13_using_psk: bool,
    /// TLS 1.3: PSK使用時の暗号スイート (再開接続で使用)
    tls13_psk_cipher: Option<CipherSuite>,
    // -- TLS 1.3 0-RTT Early Data --
    /// サーバーが許可する最大Early Dataサイズ (NewSessionTicketのtype42拡張)
    max_early_data_size: u32,
    /// Early Data送信バッファ（拒否時の再送用）
    early_data_buffer: PacketPayload,
    /// Early Data暗号化鍵
    early_write_key: Vec<u8>,
    /// Early Data暗号化IV
    early_write_iv: Vec<u8>,
    /// Early Dataシーケンス番号
    early_write_seq: u64,
    /// サーバーがEarly Dataを受理したか
    early_data_accepted: bool,
    /// Early Dataを送信したか
    early_data_sent: bool,
    // -- TLS 1.3 CertificateRequest --
    /// クライアント認証が要求されたか
    client_auth_requested: bool,
    /// CertificateRequestコンテキスト
    certificate_request_context: Option<PayloadSpan>,
    /// TLS 1.3: server Finishedまでのハンドシェイクメッセージ長
    /// (アプリケーション鍵導出時のトランスクリプト境界として使用)
    server_finished_offset: usize,
    /// TLS 1.2: 読み取り暗号化が有効か (ChangeCipherSpec受信後)
    read_encryption_active: bool,
    /// TLS 1.2: 書き込み暗号化が有効か (ChangeCipherSpec送信後)
    write_encryption_active: bool,
}

impl TlsConnection {
    fn packet_payload_from_slice(data: &[u8]) -> PacketPayload {
        let mut builder = PacketPayloadBuilder::new();
        if builder.push_bytes(data).is_none() {
            return PacketPayload::default();
        }
        builder.build()
    }

    fn packet_payload_from_parts(parts: &[&[u8]]) -> PacketPayload {
        let mut builder = PacketPayloadBuilder::new();
        for part in parts {
            if !part.is_empty() && builder.push_bytes(part).is_none() {
                return PacketPayload::default();
            }
        }
        builder.build()
    }

    pub(crate) fn vec_from_payload(payload: &PacketPayload) -> TlsResult<Vec<u8>> {
        let view = PacketPayloadView::new(payload);
        let len = view.total_len();
        let mut data = vec![0u8; len];
        if view.copy_all_into(&mut data) != len {
            return Err(TlsError::DecodeError);
        }
        Ok(data)
    }

    pub(crate) fn span_from_bytes(data: &[u8]) -> TlsResult<PayloadSpan> {
        PayloadSpan::from_bytes(data).ok_or(TlsError::DecodeError)
    }

    fn payload_hash_sha256(payload: &PacketPayload) -> [u8; SHA256_OUTPUT_SIZE] {
        let mut hasher = crate::crypto::sha256::Sha256::new();
        PacketPayloadView::new(payload).for_each_chunk(|chunk| hasher.update(chunk));
        hasher.finalize()
    }

    fn payload_hash_sha384(payload: &PacketPayload) -> [u8; SHA384_OUTPUT_SIZE] {
        let mut hasher = crate::crypto::sha384::Sha384::new();
        PacketPayloadView::new(payload).for_each_chunk(|chunk| hasher.update(chunk));
        hasher.finalize()
    }

    fn transcript_len(&self) -> usize {
        self.handshake_transcript.total_len()
    }

    fn append_transcript_bytes(&mut self, data: &[u8]) -> TlsResult<()> {
        let payload = Self::packet_payload_from_slice(data);
        if !data.is_empty() && payload.is_empty() {
            return Err(TlsError::DecodeError);
        }
        append_payload(&mut self.handshake_transcript, payload);
        Ok(())
    }

    fn replace_transcript_bytes(&mut self, data: &[u8]) -> TlsResult<()> {
        let payload = Self::packet_payload_from_slice(data);
        if !data.is_empty() && payload.is_empty() {
            return Err(TlsError::DecodeError);
        }
        self.handshake_transcript = payload;
        Ok(())
    }

    fn transcript_hash_sha256(&self) -> [u8; SHA256_OUTPUT_SIZE] {
        Self::payload_hash_sha256(&self.handshake_transcript)
    }

    fn transcript_hash_sha384(&self) -> [u8; SHA384_OUTPUT_SIZE] {
        Self::payload_hash_sha384(&self.handshake_transcript)
    }

    fn transcript_prefix_hash_sha256(&self, len: usize) -> TlsResult<[u8; SHA256_OUTPUT_SIZE]> {
        let prefix = crate::net::payload::payload_range(&self.handshake_transcript, 0, len)
            .ok_or(TlsError::DecodeError)?;
        Ok(Self::payload_hash_sha256(&prefix))
    }

    fn transcript_prefix_hash_sha384(&self, len: usize) -> TlsResult<[u8; SHA384_OUTPUT_SIZE]> {
        let prefix = crate::net::payload::payload_range(&self.handshake_transcript, 0, len)
            .ok_or(TlsError::DecodeError)?;
        Ok(Self::payload_hash_sha384(&prefix))
    }

    /// 新しいTLS接続を作成
    pub fn new(config: TlsConfig) -> Self {
        // RNGのセキュリティ状態をチェック
        if !has_secure_random() {
            log::warn!(
                "[TLS][SECURITY] Hardware RNG (RDRAND) unavailable — TLS session keys are generated with a WEAK fallback RNG. Connection security is severely degraded!"
            );
        }

        // クライアントランダムを生成
        let client_random = generate_random();

        Self {
            config,
            state: TlsState::Initial,
            negotiated_version: None,
            negotiated_cipher: None,
            session_id: SessionId::empty(),
            client_random,
            server_random: [0; 32],
            master_secret: [0; 48],
            read_key: Vec::new(),
            write_key: Vec::new(),
            read_iv: Vec::new(),
            write_iv: Vec::new(),
            read_seq: 0,
            write_seq: 0,
            recv_buffer: PacketPayload::default(),
            handshake_transcript: PacketPayload::default(),
            pre_master_secret: Vec::new(),
            local_ecdh_keypair: None,
            server_public_key: None,
            // TLS 1.3 fields
            is_tls13: false,
            server_hs_traffic_secret: [0; 48],
            client_hs_traffic_secret: [0; 48],
            server_app_traffic_secret: [0; 48],
            client_app_traffic_secret: [0; 48],
            hs_read_key: Vec::new(),
            hs_read_iv: Vec::new(),
            hs_write_key: Vec::new(),
            hs_write_iv: Vec::new(),
            hs_read_seq: 0,
            hs_write_seq: 0,
            transcript_hash: None,
            session_ticket: None,
            pending_key_update_response: false,
            // CBC mode fields
            read_mac_key: Vec::new(),
            write_mac_key: Vec::new(),
            read_cbc_iv: [0; 16],
            write_cbc_iv: [0; 16],
            last_read_ciphertext_block: None,
            last_write_ciphertext_block: None,
            // Session resumption
            session_cache: None,
            resuming_session: false,
            // TLS 1.3 PSK session resumption
            resumption_master_secret: Vec::new(),
            tls13_psk: None,
            tls13_psk_identity: None,
            tls13_ticket_age_add: 0,
            tls13_using_psk: false,
            tls13_psk_cipher: None,
            max_early_data_size: 0,
            early_data_buffer: PacketPayload::default(),
            early_write_key: Vec::new(),
            early_write_iv: Vec::new(),
            early_write_seq: 0,
            early_data_accepted: false,
            early_data_sent: false,
            client_auth_requested: false,
            certificate_request_context: None,
            server_finished_offset: 0,
            read_encryption_active: false,
            write_encryption_active: false,
        }
    }

    /// 状態を取得
    pub fn state(&self) -> TlsState {
        self.state
    }

    /// ネゴシエートされたバージョンを取得
    pub fn negotiated_version(&self) -> Option<TlsVersion> {
        self.negotiated_version
    }

    /// ネゴシエートされた暗号スイートのハッシュ長を返す（SHA-256: 32, SHA-384: 48）
    fn hash_len(&self) -> usize {
        if self.negotiated_cipher.map_or(false, |c| c.uses_sha384()) {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        }
    }

    /// ClientHelloを構築
    /// TLS 1.3 用のECDH一時鍵を事前生成する
    fn prepare_tls13_ecdh_keypair(&mut self) {
        if self.config.max_version != TlsVersion::TLS_1_3 || self.local_ecdh_keypair.is_some() {
            return;
        }
        if let Ok(keypair) = ecdh::EcdhKeyPair::generate(ecdh::EcdhGroup::X25519) {
            self.local_ecdh_keypair = Some(keypair);
        }
    }

    /// トランスクリプトハッシュを初期化する（HRR後の再送にも対応）
    fn init_transcript_hash(&mut self) {
        let mut hasher = crate::crypto::sha256::Sha256::new();
        PacketPayloadView::new(&self.handshake_transcript)
            .for_each_chunk(|chunk| hasher.update(chunk));
        self.transcript_hash = Some(TranscriptHash::Sha256(hasher));
    }

    /// セッションキャッシュからセッションIDを探してhelloに追加する
    fn append_session_id(&mut self, hello: &mut Vec<u8>) {
        let cached_session_id = if let Some(ref cache) = self.session_cache {
            if let Some(ref name) = self.config.server_name {
                cache.find_by_server_name(name).map(|e| e.session_id)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(sid) = cached_session_id {
            hello.push(32);
            hello.extend_from_slice(&sid);
            self.session_id = SessionId::new(sid);
        } else {
            hello.push(0);
        }
    }

    /// PSKバインダーを計算してmessageに上書きする (RFC 8446 Section 4.2.11.2)
    fn compute_psk_binders(&self, message: &mut Vec<u8>) {
        if self.tls13_psk.is_none() || self.tls13_psk_identity.is_none() {
            return;
        }
        let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
        let hash_len = if use_384 { 48 } else { 32 };
        let binders_total = 2 + 1 + hash_len;

        if message.len() <= binders_total {
            return;
        }

        let truncated_len = message.len() - binders_total;
        let psk = self.tls13_psk.as_ref().unwrap();

        if use_384 {
            let early_secret = tls13_early_secret_sha384(Some(psk));
            let empty_hash = crate::crypto::sha384::compute(&[]);
            let binder_key = tls13_derive_secret_sha384(&early_secret, b"res binder", &empty_hash);
            let transcript_hash = crate::crypto::sha384::compute(&message[..truncated_len]);
            let binder = hmac_sha384(&binder_key, &transcript_hash);
            let binder_start = message.len() - hash_len;
            message[binder_start..].copy_from_slice(&binder[..hash_len]);
        } else {
            let early_secret = tls13_early_secret(Some(psk));
            let empty_hash = {
                let h = crate::crypto::sha256::Sha256::new();
                h.finalize()
            };
            let binder_key = tls13_derive_secret(&early_secret, b"res binder", &empty_hash);
            let transcript_hash = {
                let mut h = crate::crypto::sha256::Sha256::new();
                h.update(&message[..truncated_len]);
                h.finalize()
            };
            let binder = hmac_sha256(&binder_key, &transcript_hash);
            let binder_start = message.len() - hash_len;
            message[binder_start..].copy_from_slice(&binder[..hash_len]);
        }
    }

    /// PSK使用時にEarly Data暗号化鍵を導出する (RFC 8446 Section 7.1)
    fn derive_early_data_keys_if_needed(&mut self) {
        if self.tls13_psk.is_none() || self.max_early_data_size == 0 {
            return;
        }
        let psk = self.tls13_psk.as_ref().unwrap();
        let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
        let cipher = self
            .tls13_psk_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();

        if use_384 {
            let early_secret = tls13_early_secret_sha384(Some(psk));
            let ch_hash = self.transcript_hash_sha384();
            let cets = tls13_derive_secret_sha384(&early_secret, b"c e traffic", &ch_hash);
            let (ew_key, ew_iv) = tls13_derive_traffic_keys_sha384(&cets, key_len);
            self.early_write_key = ew_key;
            self.early_write_iv = ew_iv;
        } else {
            let early_secret = tls13_early_secret(Some(psk));
            let ch_hash = self.transcript_hash_sha256();
            let cets = tls13_derive_secret(&early_secret, b"c e traffic", &ch_hash);
            let (ew_key, ew_iv) = tls13_derive_traffic_keys(&cets, key_len);
            self.early_write_key = ew_key;
            self.early_write_iv = ew_iv;
        }
        self.early_write_seq = 0;
    }

    /// ClientHelloを構築
    fn build_client_hello_payload(&mut self) -> PacketPayload {
        self.prepare_tls13_ecdh_keypair();
        self.init_transcript_hash();

        let mut hello = Vec::new();

        // バージョン（TLS 1.2として送信、supported_versionsで実際のバージョンを指定）
        hello.extend_from_slice(&[0x03, 0x03]);

        // クライアントランダム
        hello.extend_from_slice(&self.client_random);

        // セッションID（キャッシュからの再開を試みる）
        self.append_session_id(&mut hello);

        // 暗号スイート
        let cipher_bytes: Vec<u8> = self
            .config
            .cipher_suites
            .iter()
            .flat_map(|c| [(c.0 >> 8) as u8, c.0 as u8])
            .collect();
        hello.extend_from_slice(&[(cipher_bytes.len() >> 8) as u8, cipher_bytes.len() as u8]);
        hello.extend_from_slice(&cipher_bytes);

        // 圧縮方式（null のみ）
        hello.extend_from_slice(&[0x01, 0x00]);

        // 拡張機能
        let mut extensions = Vec::new();
        self.append_extensions(&mut extensions);
        hello.extend_from_slice(&[(extensions.len() >> 8) as u8, extensions.len() as u8]);
        hello.extend_from_slice(&extensions);

        // ハンドシェイクヘッダを追加
        let mut message = vec![HandshakeType::ClientHello as u8];
        message.extend_from_slice(&[0, (hello.len() >> 8) as u8, hello.len() as u8]);
        message.extend_from_slice(&hello);

        // PSKバインダー計算
        self.compute_psk_binders(&mut message);

        // ハンドシェイクメッセージを記録
        self.append_transcript_bytes(&message)
            .expect("client hello transcript append");

        // トランスクリプトハッシュにClientHelloを追加
        if let Some(ref mut hasher) = self.transcript_hash {
            hasher.update(&message);
        }

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

        self.state = TlsState::ClientHelloSent;
        Self::packet_payload_from_parts(&[&record_header, &message])
    }

    pub fn build_client_hello(&mut self) -> PacketPayload {
        self.build_client_hello_payload()
    }

    /// 0-RTTアーリーデータを暗号化して送信 (RFC 8446 Section 4.2.10)
    ///
    /// ClientHello送信直後に呼び出す。Early Data鍵が導出済みの場合のみ動作。
    /// データはバッファリングされ、サーバーが拒否した場合は`get_rejected_early_data_payload()`で取得可能。
    ///
    /// # Returns
    /// 暗号化されたTLSレコード列。鍵未導出時やサイズ超過時は空。
    fn send_early_data_record_payload(&mut self, data: &[u8]) -> PacketPayload {
        if self.early_write_key.is_empty() || self.early_write_iv.len() < 12 {
            return PacketPayload::default();
        }

        if data.is_empty() {
            return PacketPayload::default();
        }

        let cipher = self
            .tls13_psk_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        // TLS 1.3 inner plaintext: application_data || ContentType::ApplicationData(23)
        let mut inner_plaintext = Vec::with_capacity(data.len() + 1);
        inner_plaintext.extend_from_slice(data);
        inner_plaintext.push(ContentType::ApplicationData as u8);

        // Nonce: IV XOR (zero-padded sequence number)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.early_write_iv[..12]);
        let seq_bytes = self.early_write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = inner_plaintext.len() + 16;

        // AAD: TLS record header
        let mut aad = Vec::with_capacity(5);
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(encrypted_len as u16).to_be_bytes());

        let (ciphertext, auth_tag) = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&self.early_write_key[..32]);
            chacha20_poly1305_encrypt(&key_arr, &nonce, &aad, &inner_plaintext)
        } else {
            aes_gcm_encrypt(&self.early_write_key, &nonce, &aad, &inner_plaintext)
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
        self.early_data_sent = true;
        Self::packet_payload_from_parts(&[&record_header, &ciphertext, &auth_tag])
    }

    pub fn send_early_data_payload(&mut self, payload: &PacketPayload) -> PacketPayload {
        let total = self.early_data_buffer.total_len() + payload.total_len();
        if self.max_early_data_size > 0 && total > self.max_early_data_size as usize {
            return PacketPayload::default();
        }
        append_payload(&mut self.early_data_buffer, payload.clone());
        let Ok(data) = Self::vec_from_payload(payload) else {
            return PacketPayload::default();
        };
        self.send_early_data_record_payload(&data)
    }

    /// サーバーに拒否されたEarly Dataの平文を取得
    ///
    /// ハンドシェイク完了後、`early_data_accepted`がfalseの場合に呼び出し、
    /// バッファされたデータを通常のアプリケーションデータとして再送する。
    pub fn get_rejected_early_data_payload(&mut self) -> PacketPayload {
        if self.early_data_accepted || !self.early_data_sent {
            return PacketPayload::default();
        }
        core::mem::take(&mut self.early_data_buffer)
    }

    /// 拡張機能を構築
    /// Supported Versions拡張を構築 (RFC 8446 Section 4.2.1)
    fn append_supported_versions_ext(&self, ext: &mut Vec<u8>) {
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            ext.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        }
        if self.config.min_version <= TlsVersion::TLS_1_2 {
            ext.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        }
        if self.config.min_version <= TlsVersion::TLS_1_1
            && self.config.max_version >= TlsVersion::TLS_1_1
        {
            ext.extend_from_slice(&[0x03, 0x02]); // TLS 1.1
        }
        if self.config.min_version <= TlsVersion::TLS_1_0 {
            ext.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        }
        ext.insert(0, ext.len() as u8);
    }

    /// TLS 1.3固有の拡張を追加（PSK modes, Key Share, Early Data, Pre-Shared Key）
    fn append_tls13_extensions(&self, extensions: &mut Vec<u8>) {
        // PSK Key Exchange Modes (RFC 8446 Section 4.2.9)
        {
            let ext = vec![1, 1]; // 1 mode, psk_dhe_ke(1)
            extensions.extend_from_slice(&[0, 45]); // type = psk_key_exchange_modes
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // Key Share (RFC 8446 Section 4.2.8)
        if let Some(ref keypair) = self.local_ecdh_keypair {
            let pubkey_bytes = keypair.public_key_bytes();
            let group_id = keypair.group().to_named_group();
            let entry_len = 2 + 2 + pubkey_bytes.len();
            let mut ext = Vec::with_capacity(2 + entry_len);
            ext.push((entry_len >> 8) as u8);
            ext.push(entry_len as u8);
            ext.push((group_id >> 8) as u8);
            ext.push(group_id as u8);
            ext.push((pubkey_bytes.len() >> 8) as u8);
            ext.push(pubkey_bytes.len() as u8);
            ext.extend_from_slice(&pubkey_bytes);
            extensions.extend_from_slice(&[0, 51]); // type = key_share
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // early_data (RFC 8446 Section 4.2.10)
        if self.tls13_psk.is_some() && self.max_early_data_size > 0 {
            extensions.extend_from_slice(&[0, 42]); // type = early_data
            extensions.extend_from_slice(&[0, 0]); // length = 0
        }

        // pre_shared_key (RFC 8446 Section 4.2.11) - MUST be last extension
        if let Some(ref psk_identity) = self.tls13_psk_identity {
            let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
            let hash_len = if use_384 { 48 } else { 32 };
            let obfuscated_age: u32 = self.tls13_ticket_age_add;
            let Some(identity_bytes) = psk_identity.as_contiguous_slice() else {
                return;
            };
            let identity_len = identity_bytes.len();
            let identities_len = 2 + identity_len + 4;
            let binders_len = 1 + hash_len;
            let ext_data_len = 2 + identities_len + 2 + binders_len;

            extensions.extend_from_slice(&[0, 41]); // type = pre_shared_key
            extensions.extend_from_slice(&[(ext_data_len >> 8) as u8, ext_data_len as u8]);
            extensions.extend_from_slice(&[(identities_len >> 8) as u8, identities_len as u8]);
            extensions.extend_from_slice(&[(identity_len >> 8) as u8, identity_len as u8]);
            extensions.extend_from_slice(identity_bytes);
            extensions.extend_from_slice(&obfuscated_age.to_be_bytes());
            extensions.extend_from_slice(&[(binders_len >> 8) as u8, binders_len as u8]);
            extensions.push(hash_len as u8);
            extensions.extend_from_slice(&alloc::vec![0u8; hash_len]); // binder placeholder
        }
    }

    /// 拡張機能を構築
    fn append_extensions(&self, extensions: &mut Vec<u8>) {
        // Server Name Indication
        if let Some(ref name) = self.config.server_name {
            let name_bytes = name.as_bytes();
            let mut ext = Vec::new();
            let list_len = name_bytes.len() + 3;
            ext.extend_from_slice(&[(list_len >> 8) as u8, (list_len & 0xFF) as u8]);
            ext.push(0); // hostname type
            ext.extend_from_slice(&[
                (name_bytes.len() >> 8) as u8,
                (name_bytes.len() & 0xFF) as u8,
            ]);
            ext.extend_from_slice(name_bytes);
            extensions.extend_from_slice(&[0, 0]); // SNI type
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // Supported Groups
        {
            let groups: Vec<u8> = self
                .config
                .named_groups
                .iter()
                .flat_map(|g| [(g.0 >> 8) as u8, g.0 as u8])
                .collect();
            let mut ext = vec![(groups.len() >> 8) as u8, (groups.len() & 0xFF) as u8];
            ext.extend_from_slice(&groups);
            extensions.extend_from_slice(&[0, 10]); // type
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // Signature Algorithms
        {
            let schemes: Vec<u8> = self
                .config
                .signature_schemes
                .iter()
                .flat_map(|s| [(s.0 >> 8) as u8, s.0 as u8])
                .collect();
            let mut ext = vec![(schemes.len() >> 8) as u8, (schemes.len() & 0xFF) as u8];
            ext.extend_from_slice(&schemes);
            extensions.extend_from_slice(&[0, 13]); // type
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // Supported Versions
        {
            let start = extensions.len();
            extensions.extend_from_slice(&[0, 43]); // type = supported_versions
            extensions.extend_from_slice(&[0, 0]);
            let ext_start = extensions.len();
            self.append_supported_versions_ext(extensions);
            let ext_len = extensions.len() - ext_start;
            extensions[start + 2] = (ext_len >> 8) as u8;
            extensions[start + 3] = (ext_len & 0xFF) as u8;
        }

        // TLS 1.3固有の拡張
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            self.append_tls13_extensions(extensions);
        }

        // ALPN
        if !self.config.alpn_protocols.is_empty() {
            let mut protos = Vec::new();
            for proto in &self.config.alpn_protocols {
                protos.push(proto.len() as u8);
                protos.extend_from_slice(proto.as_bytes());
            }
            let mut ext = vec![(protos.len() >> 8) as u8, (protos.len() & 0xFF) as u8];
            ext.extend_from_slice(&protos);
            extensions.extend_from_slice(&[0, 16]); // type
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }
    }
}
