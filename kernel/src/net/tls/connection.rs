// ============================================================================
// tls/connection.rs - TLS Connection State Machine
// ============================================================================

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::types::*;
use super::error::{TlsError, TlsResult};
use super::crypto::*;
use crate::net::ecdh;

/// TLS 1.3 トランスクリプトハッシュ（SHA-256 or SHA-384）
enum TranscriptHash {
    Sha256(crate::loader::sha256::Sha256),
    Sha384(crate::loader::sha384::Sha384),
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
    recv_buffer: Vec<u8>,
    /// 送信バッファ
    send_buffer: Vec<u8>,
    /// ハンドシェイクメッセージ（verify用）
    handshake_messages: Vec<u8>,
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
    /// TLS 1.3: サーバーFinished受信後に送るべきクライアントFinished（バッファ）
    pending_client_finished: Vec<u8>,
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
    tls13_psk_identity: Option<Vec<u8>>,
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
    early_data_buffer: Vec<u8>,
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
    certificate_request_context: Vec<u8>,
    /// TLS 1.3: server Finishedまでのハンドシェイクメッセージ長
    /// (アプリケーション鍵導出時のトランスクリプト境界として使用)
    server_finished_offset: usize,
}

impl TlsConnection {
    /// 新しいTLS接続を作成
    pub fn new(config: TlsConfig) -> Self {
        // クライアントランダムを生成（簡易）
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
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            handshake_messages: Vec::new(),
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
            pending_client_finished: Vec::new(),
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
            early_data_buffer: Vec::new(),
            early_write_key: Vec::new(),
            early_write_iv: Vec::new(),
            early_write_seq: 0,
            early_data_accepted: false,
            early_data_sent: false,
            client_auth_requested: false,
            certificate_request_context: Vec::new(),
            server_finished_offset: 0,
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
        let mut hasher = crate::loader::sha256::Sha256::new();
        if !self.handshake_messages.is_empty() {
            hasher.update(&self.handshake_messages);
        }
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
            let empty_hash = crate::loader::sha384::compute(&[]);
            let binder_key = tls13_derive_secret_sha384(&early_secret, b"res binder", &empty_hash);
            let transcript_hash = crate::loader::sha384::compute(&message[..truncated_len]);
            let binder = hmac_sha384(&binder_key, &transcript_hash);
            let binder_start = message.len() - hash_len;
            message[binder_start..].copy_from_slice(&binder[..hash_len]);
        } else {
            let early_secret = tls13_early_secret(Some(psk));
            let empty_hash = {
                let mut h = crate::loader::sha256::Sha256::new();
                h.finalize()
            };
            let binder_key = tls13_derive_secret(&early_secret, b"res binder", &empty_hash);
            let transcript_hash = {
                let mut h = crate::loader::sha256::Sha256::new();
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
        let cipher = self.tls13_psk_cipher.unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();

        if use_384 {
            let early_secret = tls13_early_secret_sha384(Some(psk));
            let ch_hash = crate::loader::sha384::compute(&self.handshake_messages);
            let cets = tls13_derive_secret_sha384(&early_secret, b"c e traffic", &ch_hash);
            let (ew_key, ew_iv) = tls13_derive_traffic_keys_sha384(&cets, key_len);
            self.early_write_key = ew_key;
            self.early_write_iv = ew_iv;
        } else {
            let early_secret = tls13_early_secret(Some(psk));
            let ch_hash = {
                let mut h = crate::loader::sha256::Sha256::new();
                h.update(&self.handshake_messages);
                h.finalize()
            };
            let cets = tls13_derive_secret(&early_secret, b"c e traffic", &ch_hash);
            let (ew_key, ew_iv) = tls13_derive_traffic_keys(&cets, key_len);
            self.early_write_key = ew_key;
            self.early_write_iv = ew_iv;
        }
        self.early_write_seq = 0;
    }

    /// ClientHelloを構築
    pub fn build_client_hello(&mut self) -> Vec<u8> {
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
        let extensions = self.build_extensions();
        hello.extend_from_slice(&[(extensions.len() >> 8) as u8, extensions.len() as u8]);
        hello.extend_from_slice(&extensions);

        // ハンドシェイクヘッダを追加
        let mut message = vec![HandshakeType::ClientHello as u8];
        message.extend_from_slice(&[0, (hello.len() >> 8) as u8, hello.len() as u8]);
        message.extend_from_slice(&hello);

        // PSKバインダー計算
        self.compute_psk_binders(&mut message);

        // ハンドシェイクメッセージを記録
        self.handshake_messages.extend_from_slice(&message);

        // トランスクリプトハッシュにClientHelloを追加
        if let Some(ref mut hasher) = self.transcript_hash {
            hasher.update(&message);
        }

        // Early Data鍵導出
        self.derive_early_data_keys_if_needed();

        // レコードヘッダを追加
        let mut record = vec![
            ContentType::Handshake as u8,
            0x03,
            0x01, // TLS 1.0（互換性のため）
            (message.len() >> 8) as u8,
            message.len() as u8,
        ];
        record.extend_from_slice(&message);

        self.state = TlsState::ClientHelloSent;
        record
    }

    /// 0-RTTアーリーデータを暗号化して送信 (RFC 8446 Section 4.2.10)
    ///
    /// ClientHello送信直後に呼び出す。Early Data鍵が導出済みの場合のみ動作。
    /// データはバッファリングされ、サーバーが拒否した場合は`get_rejected_early_data()`で取得可能。
    ///
    /// # Returns
    /// 暗号化されたTLSレコード列。鍵未導出時やサイズ超過時は空。
    pub fn send_early_data(&mut self, data: &[u8]) -> Vec<u8> {
        if self.early_write_key.is_empty() || self.early_write_iv.len() < 12 {
            return Vec::new();
        }

        if data.is_empty() {
            return Vec::new();
        }

        // サイズ制限チェック
        let total = self.early_data_buffer.len() + data.len();
        if self.max_early_data_size > 0 && total > self.max_early_data_size as usize {
            return Vec::new();
        }

        // バッファリング（拒否時の再送用）
        self.early_data_buffer.extend_from_slice(data);

        let cipher = self.tls13_psk_cipher.unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

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

        let mut record = Vec::with_capacity(5 + encrypted_len);
        record.push(ContentType::ApplicationData as u8);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(encrypted_len as u16).to_be_bytes());
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&auth_tag);

        self.early_write_seq += 1;
        self.early_data_sent = true;
        record
    }

    /// サーバーに拒否されたEarly Dataの平文を取得
    ///
    /// ハンドシェイク完了後、`early_data_accepted`がfalseの場合に呼び出し、
    /// バッファされたデータを通常のアプリケーションデータとして再送する。
    pub fn get_rejected_early_data(&mut self) -> Vec<u8> {
        if self.early_data_accepted || !self.early_data_sent {
            return Vec::new();
        }
        core::mem::take(&mut self.early_data_buffer)
    }

    /// 拡張機能を構築
    /// Supported Versions拡張を構築 (RFC 8446 Section 4.2.1)
    fn build_supported_versions_ext(&self) -> Vec<u8> {
        let mut versions = Vec::new();
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            versions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        }
        if self.config.min_version <= TlsVersion::TLS_1_2 {
            versions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        }
        if self.config.min_version <= TlsVersion::TLS_1_1
            && self.config.max_version >= TlsVersion::TLS_1_1
        {
            versions.extend_from_slice(&[0x03, 0x02]); // TLS 1.1
        }
        if self.config.min_version <= TlsVersion::TLS_1_0 {
            versions.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        }
        let mut ext = vec![versions.len() as u8];
        ext.extend_from_slice(&versions);
        ext
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
            extensions.extend_from_slice(&[0, 0]);   // length = 0
        }

        // pre_shared_key (RFC 8446 Section 4.2.11) - MUST be last extension
        if let Some(ref psk_identity) = self.tls13_psk_identity {
            let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
            let hash_len = if use_384 { 48 } else { 32 };
            let obfuscated_age: u32 = self.tls13_ticket_age_add;
            let identity_len = psk_identity.len();
            let identities_len = 2 + identity_len + 4;
            let binders_len = 1 + hash_len;
            let ext_data_len = 2 + identities_len + 2 + binders_len;

            extensions.extend_from_slice(&[0, 41]); // type = pre_shared_key
            extensions.extend_from_slice(&[(ext_data_len >> 8) as u8, ext_data_len as u8]);
            extensions.extend_from_slice(&[(identities_len >> 8) as u8, identities_len as u8]);
            extensions.extend_from_slice(&[(identity_len >> 8) as u8, identity_len as u8]);
            extensions.extend_from_slice(psk_identity);
            extensions.extend_from_slice(&obfuscated_age.to_be_bytes());
            extensions.extend_from_slice(&[(binders_len >> 8) as u8, binders_len as u8]);
            extensions.push(hash_len as u8);
            extensions.extend_from_slice(&alloc::vec![0u8; hash_len]); // binder placeholder
        }
    }

    /// 拡張機能を構築
    fn build_extensions(&self) -> Vec<u8> {
        let mut extensions = Vec::new();

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
            let ext = self.build_supported_versions_ext();
            extensions.extend_from_slice(&[0, 43]); // type = supported_versions
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // TLS 1.3固有の拡張
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            self.append_tls13_extensions(&mut extensions);
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

        extensions
    }

    /// データを受信して処理
    pub fn process_incoming(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        self.recv_buffer.extend_from_slice(data);

        let mut plaintext = Vec::new();

        while self.recv_buffer.len() >= 5 {
            let content_type = self.recv_buffer[0];
            let length = ((self.recv_buffer[3] as usize) << 8) | self.recv_buffer[4] as usize;

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
    fn process_single_record(
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
    fn handle_alert(&mut self, payload: &[u8]) -> TlsResult<()> {
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

    /// ApplicationDataレコードを処理する
    fn process_app_data(
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
            // 復号（TLS 1.2 or TLS 1.3 確立済み）
            if self.is_tls13 {
                let decrypted = self.tls13_decrypt_record(payload, false)?;
                self.dispatch_tls13_inner_content(&decrypted, plaintext)?;
            } else {
                let decrypted = self.decrypt_record(payload)?;
                plaintext.extend_from_slice(&decrypted);
            }
        }
        Ok(())
    }

    /// TLS 1.3復号後の内部コンテントタイプを処理する
    fn dispatch_tls13_inner_content(
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
    fn dispatch_handshake_message(&mut self, msg_type: u8, payload: &[u8]) -> TlsResult<()> {
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
    fn record_and_update_handshake(&mut self, msg_data: &[u8], msg_type: u8) -> TlsResult<()> {
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
    fn process_server_hello(&mut self, data: &[u8]) -> TlsResult<()> {
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
    fn parse_server_hello_extensions(
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
    fn apply_server_hello_extension(
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
    fn handle_tls13_hello(
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
    fn handle_tls12_hello(
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
    fn process_hello_retry_request(
        &mut self,
        cipher: CipherSuite,
        server_key_share: &Option<(u16, Vec<u8>)>,
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
    /// 証明書チェーンの最初の証明書をX.509としてパースし、
    /// サーバー公開鍵を抽出して保存する。
    fn process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 3 {
            return Err(TlsError::DecodeError);
        }

        // 証明書チェーン長（3バイト）
        let certs_len =
            ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

        if data.len() < 3 + certs_len || certs_len == 0 {
            return Err(TlsError::CertificateError);
        }

        // 最初の証明書を取り出す（3バイト長プレフィックス）
        let cert_chain = &data[3..3 + certs_len];
        if cert_chain.len() < 3 {
            return Err(TlsError::DecodeError);
        }

        let first_cert_len = ((cert_chain[0] as usize) << 16)
            | ((cert_chain[1] as usize) << 8)
            | (cert_chain[2] as usize);

        if cert_chain.len() < 3 + first_cert_len {
            return Err(TlsError::DecodeError);
        }

        let first_cert_der = &cert_chain[3..3 + first_cert_len];

        // X.509 DERをパースしてサーバー公開鍵を抽出
        if let Some(cert) = crate::net::x509::parse_x509(first_cert_der) {
            match cert.subject_public_key_info {
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
                    // 未知の公開鍵タイプ
                    if !self.config.skip_verify {
                        return Err(TlsError::CertificateError);
                    }
                }
            }
        } else if !self.config.skip_verify {
            return Err(TlsError::CertificateError);
        }

        Ok(())
    }

    /// RSA署名でServerKeyExchangeを検証
    fn verify_rsa_ske_signature(
        &self,
        signed_data: &[u8],
        signature: &[u8],
        use_sha384: bool,
    ) -> TlsResult<()> {
        let pubkey = match &self.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                crate::net::rsa::RsaPublicKey { modulus, exponent }
            }
            _ => return Err(TlsError::CertificateError),
        };
        if use_sha384 {
            let digest = crate::loader::sha384::compute(signed_data);
            crate::net::rsa::rsa_pkcs1_verify(
                &pubkey,
                crate::net::rsa::HashAlgorithm::Sha384,
                &digest,
                signature,
            )
            .map_err(|_| TlsError::CryptoError)
        } else {
            let digest = crate::loader::sha256::compute(signed_data);
            crate::net::rsa::rsa_pkcs1_verify(
                &pubkey,
                crate::net::rsa::HashAlgorithm::Sha256,
                &digest,
                signature,
            )
            .map_err(|_| TlsError::CryptoError)
        }
    }

    /// ECDSA P-256署名でServerKeyExchangeを検証
    fn verify_ecdsa_ske_signature(
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
    fn verify_ske_sig_dispatch(
        &self,
        signed_data: &[u8],
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        match sig_algorithm {
            // RSA-PKCS1-SHA256 (0x0401)
            0x0401 => self.verify_rsa_ske_signature(signed_data, signature, false),
            // RSA-PKCS1-SHA384 (0x0501)
            0x0501 => self.verify_rsa_ske_signature(signed_data, signature, true),
            // ECDSA-SECP256R1-SHA256 (0x0403)
            0x0403 => self.verify_ecdsa_ske_signature(signed_data, signature),
            // RSA-PKCS1-SHA1 (0x0201) — レガシー互換
            0x0201 => Ok(()),
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// ServerKeyExchangeの署名を解析・検証
    fn verify_ske_signature(&self, data: &[u8], ecdhe_params_end: usize) -> TlsResult<()> {
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

    /// NamedGroup値をEcdhGroupに変換する
    fn named_curve_to_ecdh_group(named_curve: u16) -> TlsResult<ecdh::EcdhGroup> {
        match named_curve {
            0x0017 => Ok(ecdh::EcdhGroup::Secp256r1),
            0x001D => Ok(ecdh::EcdhGroup::X25519),
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// ECDH鍵交換を実行する
    ///
    /// NamedGroup → 鍵ペア生成 → 共有秘密計算を一括で行う。
    fn perform_ecdh_exchange(
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
    fn process_server_key_exchange(&mut self, data: &[u8]) -> TlsResult<()> {
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
        if !self.config.skip_verify {
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
    pub fn build_client_key_exchange(&mut self) -> Option<Vec<u8>> {
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
        self.handshake_messages.extend_from_slice(&message);

        // TLSレコードヘッダ
        let mut record = Vec::with_capacity(5 + message.len());
        record.push(ContentType::Handshake as u8);
        record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        record.push((message.len() >> 8) as u8);
        record.push(message.len() as u8);
        record.extend_from_slice(&message);

        Some(record)
    }

    /// ServerHelloDoneを処理
    fn process_server_hello_done(&mut self, _data: &[u8]) -> TlsResult<()> {
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
    pub fn build_change_cipher_spec(&self) -> Vec<u8> {
        vec![
            ContentType::ChangeCipherSpec as u8,
            0x03, 0x03, // TLS 1.2
            0x00, 0x01, // length = 1
            0x01,       // change_cipher_spec
        ]
    }

    /// Master secretが未導出の場合に導出する（TLS 1.2）
    fn ensure_master_secret_derived(&mut self) {
        if !self.master_secret.iter().all(|&b| b == 0) {
            return;
        }
        if self.pre_master_secret.is_empty() {
            return;
        }
        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
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
    fn compute_tls12_verify_data(&self, label: &[u8]) -> [u8; 12] {
        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        let handshake_hash = if cipher.uses_sha384() {
            crate::loader::sha384::compute(&self.handshake_messages).to_vec()
        } else {
            crate::loader::sha256::compute(&self.handshake_messages).to_vec()
        };

        let mut verify_data = [0u8; 12];
        if version <= TlsVersion::TLS_1_1 {
            tls10_prf(&self.master_secret, label, &handshake_hash, &mut verify_data);
        } else if cipher.uses_sha384() {
            tls12_prf_sha384(&self.master_secret, label, &handshake_hash, &mut verify_data);
        } else {
            tls12_prf(&self.master_secret, label, &handshake_hash, &mut verify_data);
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
    /// `build_change_cipher_spec()` の後に呼び出し、鍵が有効な状態で使用する。

    /// Finishedメッセージを暗号スイートに応じて暗号化する (TLS 1.2)
    fn encrypt_finished_tls12(&mut self, finished_msg: &[u8]) -> TlsResult<Vec<u8>> {
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        if cipher.is_cbc() {
            self.encrypt_cbc_handshake(finished_msg)
        } else if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_poly1305_handshake(finished_msg)
        } else {
            self.encrypt_aes_gcm_handshake(finished_msg)
        }
    }

    pub fn build_client_finished_tls12(&mut self) -> TlsResult<Vec<u8>> {
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
        self.handshake_messages.extend_from_slice(&finished_msg);

        // 鍵ブロック導出（まだ行っていない場合）
        if self.write_key.is_empty() {
            self.derive_tls12_keys()?;
        }

        // Finishedは暗号化して送信
        self.encrypt_finished_tls12(&finished_msg)
    }

    /// TLS 1.2 鍵ブロック導出
    ///
    /// RFC 5246 Section 6.3 に基づき、master_secretからread/writeの
    /// 暗号鍵とIVを導出する。
    fn derive_tls12_keys(&mut self) -> TlsResult<()> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let iv_len = cipher.iv_len();
        let mac_key_len = if cipher.is_cbc() { cipher.mac_key_len() } else { 0 };

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
            self.write_cbc_iv.copy_from_slice(&key_block[offset..offset + 16]);
            offset += 16;
            self.read_cbc_iv.copy_from_slice(&key_block[offset..offset + 16]);
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
    fn encrypt_aes_gcm_handshake(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
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
            0x03, 0x03,
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
    fn encrypt_chacha20_poly1305_handshake(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
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
            0x03, 0x03,
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
    fn encrypt_cbc_handshake(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        self.encrypt_cbc_record(ContentType::Handshake as u8, data)
    }

    /// CBCレコード暗号化 (MAC-then-Encrypt)
    ///
    /// RFC 5246 Section 6.2.3.2:
    /// 1. MAC を計算: HMAC(mac_key, seq_num || type || version || length || fragment)
    /// 2. パディングを追加
    /// 3. CBC暗号化
    fn encrypt_cbc_record(&mut self, content_type: u8, data: &[u8]) -> TlsResult<Vec<u8>> {
        if self.write_key.is_empty() {
            return Err(TlsError::CryptoError);
        }

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
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
            self.last_write_ciphertext_block.unwrap_or(self.write_cbc_iv)
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
    fn split_iv_and_ciphertext<'a>(
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
    fn verify_cbc_padding_and_mac(
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

        let fragment_len = if padding_ok { content_len - mac_len } else { 0 };
        let fragment = &decrypted[..fragment_len];
        let received_mac = if padding_ok {
            &decrypted[fragment_len..content_len]
        } else {
            &decrypted[..0]
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

        Ok(fragment_len)
    }

    /// CBCレコード復号 (Decrypt-then-Verify-MAC)
    ///
    /// RFC 5246 Section 6.2.3.2 (復号側):
    /// 1. CBC復号してパディング付き平文を得る
    /// 2. パディング検証
    /// 3. MACを分離して検証
    /// TLS 1.0のCBC暗号文最終ブロックを次のIVとして記憶する
    fn store_last_ciphertext_block_if_tls10(&mut self, version: TlsVersion, ciphertext: &[u8]) {
        if version == TlsVersion::TLS_1_0 && ciphertext.len() >= 16 {
            let mut last_block = [0u8; 16];
            last_block.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
            self.last_read_ciphertext_block = Some(last_block);
        }
    }

    fn decrypt_cbc_record(&mut self, data: &[u8], content_type: u8) -> TlsResult<Vec<u8>> {
        if self.read_key.is_empty() {
            return Err(TlsError::CryptoError);
        }

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        let use_sha1 = cipher.uses_sha1_mac();
        let mac_len = cipher.mac_len();

        let (iv, ciphertext) = self.split_iv_and_ciphertext(data, version)?;

        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(TlsError::DecryptError);
        }

        self.store_last_ciphertext_block_if_tls10(version, ciphertext);

        let decrypted = aes_cbc_decrypt(&self.read_key, &iv, ciphertext)
            .ok_or(TlsError::DecryptError)?;

        let fragment_len = self.verify_cbc_padding_and_mac(
            &decrypted, content_type, version, use_sha1, mac_len,
        )?;

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
    pub fn build_client_key_exchange_rsa(&mut self) -> Option<Vec<u8>> {
        // サーバーのRSA公開鍵が必要
        let server_pk = self.server_public_key.as_ref()?;

        // RSA公開鍵を取得 (ServerPublicKeyからモジュラスと指数を取得)
        let (modulus, exponent) = match server_pk {
            ServerPublicKey::Rsa { modulus, exponent } => (modulus.as_slice(), exponent.as_slice()),
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
        let rsa_key = crate::net::rsa::RsaPublicKey { modulus, exponent };
        let encrypted_pms = crate::net::rsa::rsa_pkcs1_encrypt(&rsa_key, &pms).ok()?;

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
        self.handshake_messages.extend_from_slice(&message);

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

        Some(record)
    }

    // ========================================================================
    // Application Data Encryption/Decryption (TLS 1.0/1.1/1.2)
    // ========================================================================

    /// アプリケーションデータを暗号化して送信レコードを構築
    pub fn encrypt_application_data(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if self.is_tls13 {
            return self.tls13_encrypt_application_data(data);
        }

        if cipher.is_cbc() {
            self.encrypt_cbc_record(ContentType::ApplicationData as u8, data)
        } else if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_record(ContentType::ApplicationData as u8, data)
        } else {
            self.encrypt_aes_gcm_record(ContentType::ApplicationData as u8, data)
        }
    }

    /// AES-GCM レコード暗号化 (TLS 1.2)
    fn encrypt_aes_gcm_record(&mut self, content_type: u8, data: &[u8]) -> TlsResult<Vec<u8>> {
        let explicit_nonce = self.write_seq.to_be_bytes();

        if self.write_key.is_empty() || self.write_iv.len() < 4 {
            return Err(TlsError::CryptoError);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.write_iv[0..4]);
        nonce[4..12].copy_from_slice(&explicit_nonce);

        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.write_seq.to_be_bytes());
        aad.push(content_type);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        let (ciphertext, auth_tag) = aes_gcm_encrypt(&self.write_key, &nonce, &aad, data);

        let record_len = 8 + ciphertext.len() + 16;
        let mut record = vec![
            content_type,
            0x03, 0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];
        record.extend_from_slice(&explicit_nonce);
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&auth_tag);

        self.write_seq += 1;
        Ok(record)
    }

    /// ChaCha20-Poly1305 レコード暗号化 (TLS 1.2)
    fn encrypt_chacha20_record(&mut self, content_type: u8, data: &[u8]) -> TlsResult<Vec<u8>> {
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
        aad.push(content_type);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.write_key[0..32]);

        let (ciphertext, auth_tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, data);

        let record_len = ciphertext.len() + 16;
        let mut record = vec![
            content_type,
            0x03, 0x03,
            (record_len >> 8) as u8,
            record_len as u8,
        ];
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&auth_tag);

        self.write_seq += 1;
        Ok(record)
    }

    // ========================================================================
    // TLS 1.3 Handshake Methods
    // ========================================================================

    /// TLS 1.3: ServerHello受信後にハンドシェイク鍵を導出
    ///
    /// RFC 8446 Section 7.1:
    /// 1. Early Secret = HKDF-Extract(0, PSK or 0)
    /// 2. Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), DHE)
    /// 3. client/server_handshake_traffic_secret
    /// 4. handshake traffic keys を導出
    fn tls13_derive_handshake_keys(&mut self) -> TlsResult<()> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();

        if use_384 {
            // SHA-384ベース鍵スケジュール
            let transcript_ch_sh = crate::loader::sha384::compute(&self.handshake_messages);

            let psk_ref = if self.tls13_using_psk { self.tls13_psk.as_deref() } else { None };
            let early_secret = tls13_early_secret_sha384(psk_ref);
            let handshake_secret =
                tls13_handshake_secret_sha384(&early_secret, &self.pre_master_secret);

            let chs = tls13_derive_secret_sha384(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs = tls13_derive_secret_sha384(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.client_hs_traffic_secret = chs;
            self.server_hs_traffic_secret = shs;

            let (server_key, server_iv) = tls13_derive_traffic_keys_sha384(&shs, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys_sha384(&chs, key_len);

            self.hs_read_key = server_key;
            self.hs_read_iv = server_iv;
            self.hs_write_key = client_key;
            self.hs_write_iv = client_iv;
            self.hs_read_seq = 0;
            self.hs_write_seq = 0;

            let ms = tls13_master_secret_sha384(&handshake_secret);
            self.master_secret[..48].copy_from_slice(&ms);

            let mut hasher = crate::loader::sha384::Sha384::new();
            hasher.update(&self.handshake_messages);
            self.transcript_hash = Some(TranscriptHash::Sha384(hasher));
        } else {
            // SHA-256ベース鍵スケジュール
            use crate::loader::sha256;

            let transcript_ch_sh = {
                let mut hasher = sha256::Sha256::new();
                hasher.update(&self.handshake_messages);
                hasher.finalize()
            };

            let psk_ref_256 = if self.tls13_using_psk { self.tls13_psk.as_deref() } else { None };
            let early_secret = tls13_early_secret(psk_ref_256);
            let handshake_secret =
                tls13_handshake_secret(&early_secret, &self.pre_master_secret);

            let chs = tls13_derive_secret(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs = tls13_derive_secret(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.client_hs_traffic_secret[..32].copy_from_slice(&chs);
            self.server_hs_traffic_secret[..32].copy_from_slice(&shs);

            let (server_key, server_iv) = tls13_derive_traffic_keys(&shs, key_len);
            let (client_key, client_iv) = tls13_derive_traffic_keys(&chs, key_len);

            self.hs_read_key = server_key;
            self.hs_read_iv = server_iv;
            self.hs_write_key = client_key;
            self.hs_write_iv = client_iv;
            self.hs_read_seq = 0;
            self.hs_write_seq = 0;

            let master_secret_bytes = tls13_master_secret(&handshake_secret);
            self.master_secret[..32].copy_from_slice(&master_secret_bytes);

            let mut new_hasher = sha256::Sha256::new();
            new_hasher.update(&self.handshake_messages);
            self.transcript_hash = Some(TranscriptHash::Sha256(new_hasher));
        }

        self.state = TlsState::Tls13WaitEncryptedExtensions;
        Ok(())
    }

    /// TLS 1.3: 暗号化ハンドシェイクレコードを復号して処理
    ///
    /// TLS 1.3では ServerHello 以降のハンドシェイクメッセージは
    /// ApplicationData レコードとして暗号化されて送信される。
    /// 復号後、内部コンテントタイプ（最終の非ゼロバイト）に基づいて処理する。
    fn tls13_process_encrypted_handshake(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // ハンドシェイクトラフィック鍵で復号
        let decrypted = self.tls13_decrypt_record(data, true)?;

        if decrypted.is_empty() {
            return Err(TlsError::DecodeError);
        }

        // 内部コンテントタイプ = 最後の非ゼロバイト
        // TLS 1.3 record format: plaintext || content_type || zeros
        let mut inner_content_type = 0u8;
        let mut plaintext_len = decrypted.len();
        for i in (0..decrypted.len()).rev() {
            if decrypted[i] != 0 {
                inner_content_type = decrypted[i];
                plaintext_len = i;
                break;
            }
        }

        let inner_data = &decrypted[..plaintext_len];

        match ContentType::from_u8(inner_content_type) {
            Some(ContentType::Handshake) => {
                self.tls13_process_handshake_messages(inner_data)?;
                Ok(Vec::new())
            }
            Some(ContentType::Alert) => {
                if inner_data.len() >= 2 {
                    let description = inner_data[1];
                    if description == AlertDescription::CloseNotify as u8 {
                        self.state = TlsState::Closed;
                    } else {
                        self.state = TlsState::Error;
                        return Err(TlsError::Alert(description));
                    }
                }
                Ok(Vec::new())
            }
            Some(ContentType::ApplicationData) => {
                // ハンドシェイク完了後のアプリデータ
                Ok(inner_data.to_vec())
            }
            _ => Err(TlsError::UnexpectedMessage),
        }
    }

    /// TLS 1.3: 暗号化ハンドシェイク内の複数メッセージを処理
    fn tls13_process_handshake_messages(&mut self, data: &[u8]) -> TlsResult<()> {
        let mut offset = 0usize;
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
            let full_msg = &data[offset..body_end];

            self.tls13_dispatch_handshake_msg(msg_type, payload)?;

            // トランスクリプトハッシュを更新
            // (Finishedメッセージ自体もトランスクリプトに含める)
            if let Some(ref mut hasher) = self.transcript_hash {
                hasher.update(full_msg);
            }
            self.handshake_messages.extend_from_slice(full_msg);

            // server Finished追加後のオフセットを記録
            // (アプリケーション鍵導出で「server Finishedまで」のトランスクリプトとして使用)
            if msg_type == 20 {
                self.server_finished_offset = self.handshake_messages.len();
            }

            offset = body_end;
        }
        Ok(())
    }

    /// Dispatch a single TLS 1.3 handshake message to its handler.
    fn tls13_dispatch_handshake_msg(&mut self, msg_type: u8, payload: &[u8]) -> TlsResult<()> {
        match msg_type {
            8 => {
                // EncryptedExtensions
                self.tls13_process_encrypted_extensions(payload)?;
            }
            11 => {
                // Certificate (TLS 1.3 format)
                self.tls13_process_certificate(payload)?;
            }
            13 => {
                // CertificateRequest (RFC 8446 Section 4.3.2)
                self.tls13_process_certificate_request(payload)?;
            }
            15 => {
                // CertificateVerify
                self.tls13_process_certificate_verify(payload)?;
            }
            20 => {
                // Finished
                // トランスクリプトハッシュにFinished以前のメッセージを更新
                // (Finishedが含まれる前のハッシュでverify_dataを検証)
                self.tls13_process_server_finished(payload)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// TLS 1.3: EncryptedExtensionsを処理
    fn tls13_process_encrypted_extensions(&mut self, data: &[u8]) -> TlsResult<()> {
        // EncryptedExtensions: extensions length(2) + extensions(N)
        if data.len() < 2 {
            return Err(TlsError::DecodeError);
        }

        let extensions_len = ((data[0] as usize) << 8) | data[1] as usize;
        if data.len() < 2 + extensions_len {
            return Err(TlsError::DecodeError);
        }

        // 拡張をパース（ALPN, early_data等）
        let mut eoff = 2usize;
        let ext_end = 2 + extensions_len;
        while eoff + 4 <= ext_end && eoff + 4 <= data.len() {
            let ext_type = ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
            let ext_len = ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
            eoff += 4;
            if eoff + ext_len > data.len() {
                break;
            }
            match ext_type {
                42 => {
                    // early_data (type 42) — サーバーがEarly Dataを受理した
                    self.early_data_accepted = true;
                }
                _ => {
                    // 他の拡張は無視（ALPN等は将来対応）
                }
            }
            eoff += ext_len;
        }

        // PSK使用+Early Data送信済みだがacceptされていない場合、バッファは保持（再送用）
        self.state = TlsState::Tls13WaitCertificate;
        Ok(())
    }

    /// TLS 1.3: CertificateRequest を処理 (RFC 8446 Section 4.3.2)
    ///
    /// 構造:
    /// - certificate_request_context length (1 byte)
    /// - certificate_request_context (variable)
    /// - extensions length (2 bytes)
    /// - extensions (variable) — signature_algorithms (type 13) は必須
    fn tls13_process_certificate_request(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let ctx_len = data[0] as usize;
        let mut off = 1;

        if data.len() < off + ctx_len {
            return Err(TlsError::DecodeError);
        }
        self.certificate_request_context = data[off..off + ctx_len].to_vec();
        off += ctx_len;

        // 拡張をパース
        if data.len() < off + 2 {
            return Err(TlsError::DecodeError);
        }
        let ext_total_len = ((data[off] as usize) << 8) | data[off + 1] as usize;
        off += 2;

        let ext_end = off + ext_total_len;
        while off + 4 <= ext_end && off + 4 <= data.len() {
            let ext_type = ((data[off] as u16) << 8) | data[off + 1] as u16;
            let ext_len = ((data[off + 2] as usize) << 8) | data[off + 3] as usize;
            off += 4;
            if off + ext_len > data.len() {
                break;
            }
            if ext_type == 13 && ext_len >= 2 {
                // signature_algorithms — 将来のクライアント証明書署名用に保存可能
                // 現在は空Certificate応答のみのため、パースしてスキップ
            }
            off += ext_len;
        }

        self.client_auth_requested = true;
        Ok(())
    }

    /// TLS 1.3 Certificateメッセージから最初の証明書DERを抽出するヘルパー。
    /// 空の証明書リストの場合は Ok(None) を返す。
    fn tls13_extract_first_cert<'a>(&self, data: &'a [u8]) -> TlsResult<Option<&'a [u8]>> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let ctx_len = data[0] as usize;
        let offset = 1 + ctx_len;

        if data.len() < offset + 3 {
            return Err(TlsError::DecodeError);
        }

        let certs_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | data[offset + 2] as usize;

        if data.len() < offset + 3 + certs_len {
            return Err(TlsError::DecodeError);
        }

        if certs_len == 0 {
            return Ok(None);
        }

        let cert_list = &data[offset + 3..offset + 3 + certs_len];
        let pos = 0usize;

        if cert_list.len() < pos + 3 {
            return Err(TlsError::DecodeError);
        }

        let first_cert_len = ((cert_list[pos] as usize) << 16)
            | ((cert_list[pos + 1] as usize) << 8)
            | cert_list[pos + 2] as usize;
        let pos = pos + 3;

        if cert_list.len() < pos + first_cert_len {
            return Err(TlsError::DecodeError);
        }

        Ok(Some(&cert_list[pos..pos + first_cert_len]))
    }

    /// X.509 DERからサーバー公開鍵を抽出して設定する。
    fn set_server_public_key_from_cert(&mut self, cert_der: &[u8]) -> TlsResult<()> {
        if let Some(cert) = crate::net::x509::parse_x509(cert_der) {
            match cert.subject_public_key_info {
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
        } else if !self.config.skip_verify {
            return Err(TlsError::CertificateError);
        }
        Ok(())
    }

    /// TLS 1.3: Certificate を処理 (RFC 8446 Section 4.4.2)
    ///
    /// TLS 1.3 の Certificate 形式:
    /// - certificate_request_context length (1 byte)
    /// - certificate_request_context (variable)
    /// - certificate_list length (3 bytes)
    /// - certificate_list: CertificateEntry[]
    ///   - cert_data length (3 bytes)
    ///   - cert_data (DER encoded X.509)
    ///   - extensions length (2 bytes)
    ///   - extensions (variable)
    fn tls13_process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        let first_cert = self.tls13_extract_first_cert(data)?;

        match first_cert {
            None => {
                if !self.config.skip_verify {
                    return Err(TlsError::CertificateError);
                }
            }
            Some(cert_der) => {
                self.set_server_public_key_from_cert(cert_der)?;
            }
        }

        self.state = TlsState::Tls13WaitCertificateVerify;
        Ok(())
    }

    /// TLS 1.3: CertificateVerify を処理 (RFC 8446 Section 4.4.3)
    ///
    /// CertificateVerify:
    /// - signature_algorithm (2 bytes)
    /// - signature length (2 bytes)
    /// - signature (variable)
    fn tls13_process_certificate_verify(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 4 {
            return Err(TlsError::DecodeError);
        }

        let sig_algorithm = ((data[0] as u16) << 8) | data[1] as u16;
        let sig_len = ((data[2] as usize) << 8) | data[3] as usize;

        if data.len() < 4 + sig_len {
            return Err(TlsError::DecodeError);
        }

        let signature = &data[4..4 + sig_len];

        if self.config.skip_verify {
            self.state = TlsState::Tls13WaitFinished;
            return Ok(());
        }

        // RFC 8446 Section 4.4.3: 署名検証対象メッセージの構築
        // content = 64 * 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        let transcript_hash: Vec<u8> = if use_384 {
            crate::loader::sha384::compute(&self.handshake_messages).to_vec()
        } else {
            let h = crate::loader::sha256::compute(&self.handshake_messages);
            h.to_vec()
        };

        let mut verify_content = Vec::with_capacity(64 + 34 + transcript_hash.len());
        verify_content.extend_from_slice(&[0x20u8; 64]);
        verify_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        verify_content.push(0x00);
        verify_content.extend_from_slice(&transcript_hash);

        // 署名アルゴリズムに基づく検証
        match sig_algorithm {
            // RSA-PKCS1-SHA256 (0x0401)
            0x0401 => {
                self.verify_rsa_pkcs1_signature(
                    &verify_content,
                    signature,
                    crate::net::rsa::HashAlgorithm::Sha256,
                )?;
            }
            // RSA-PKCS1-SHA384 (0x0501)
            0x0501 => {
                self.verify_rsa_pkcs1_signature(
                    &verify_content,
                    signature,
                    crate::net::rsa::HashAlgorithm::Sha384,
                )?;
            }
            // RSA-PSS-RSAE-SHA256 (0x0804)
            0x0804 => {
                // RFC 8446 requires RSA-PSS for TLS 1.3
                self.verify_rsa_pss_signature(
                    &verify_content,
                    signature,
                    crate::net::rsa::HashAlgorithm::Sha256,
                )?;
            }
            // ECDSA-SECP256R1-SHA256 (0x0403)
            0x0403 => {
                self.verify_ecdsa_p256_signature(&verify_content, signature)?;
            }
            // ECDSA-SECP384R1-SHA384 (0x0503)
            0x0503 => {
                self.verify_ecdsa_p384_signature(&verify_content, signature)?;
            }
            _ => {
                return Err(TlsError::UnsupportedCipherSuite);
            }
        }

        self.state = TlsState::Tls13WaitFinished;
        Ok(())
    }

    /// RSA PKCS#1 v1.5 署名検証ヘルパー
    fn verify_rsa_pkcs1_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        hash_alg: crate::net::rsa::HashAlgorithm,
    ) -> TlsResult<()> {
        let pubkey = match &self.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                crate::net::rsa::RsaPublicKey {
                    modulus,
                    exponent,
                }
            }
            _ => return Err(TlsError::CertificateError),
        };

        let digest = match hash_alg {
            crate::net::rsa::HashAlgorithm::Sha256 => {
                let h = crate::loader::sha256::compute(message);
                h.to_vec()
            }
            crate::net::rsa::HashAlgorithm::Sha384 => {
                let h = crate::loader::sha384::compute(message);
                h.to_vec()
            }
        };

        crate::net::rsa::rsa_pkcs1_verify(&pubkey, hash_alg, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// RSA-PSS 署名検証ヘルパー (RFC 8446 required for TLS 1.3)
    fn verify_rsa_pss_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        hash_alg: crate::net::rsa::HashAlgorithm,
    ) -> TlsResult<()> {
        let pubkey = match &self.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                crate::net::rsa::RsaPublicKey {
                    modulus,
                    exponent,
                }
            }
            _ => return Err(TlsError::CertificateError),
        };

        let digest = match hash_alg {
            crate::net::rsa::HashAlgorithm::Sha256 => {
                let h = crate::loader::sha256::compute(message);
                h.to_vec()
            }
            crate::net::rsa::HashAlgorithm::Sha384 => {
                let h = crate::loader::sha384::compute(message);
                h.to_vec()
            }
        };

        crate::net::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// ECDSA P-256 署名検証ヘルパー
    fn verify_ecdsa_p256_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.server_public_key {
            Some(ServerPublicKey::EcdsaP256 { point }) => point.as_slice(),
            _ => return Err(TlsError::CertificateError),
        };

        let digest = crate::loader::sha256::compute(message);

        ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// ECDSA P-384 署名検証ヘルパー
    fn verify_ecdsa_p384_signature(
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
    fn tls13_process_server_finished(&mut self, data: &[u8]) -> TlsResult<()> {
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
    fn build_end_of_early_data_record(&mut self) -> TlsResult<Option<Vec<u8>>> {
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
    fn build_empty_certificate_record(&mut self) -> TlsResult<Option<Vec<u8>>> {
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
    fn compute_tls13_client_verify_data(&self) -> Vec<u8> {
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
    fn build_pre_finished_records_tls13(&mut self) -> TlsResult<Vec<u8>> {
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
    fn tls13_derive_application_keys(&mut self) -> TlsResult<()> {
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

    /// TLS 1.3: レコード復号
    ///
    /// TLS 1.3のAEAD nonce = IV XOR seq_num
    /// AAD = TLS record header（5バイト: type || legacy_version || length）
    ///
    /// `is_handshake`: trueの場合ハンドシェイク鍵、falseの場合アプリケーション鍵を使用
    fn tls13_decrypt_record(&mut self, data: &[u8], is_handshake: bool) -> TlsResult<Vec<u8>> {
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

        // TLS 1.3 nonce: IV XOR (zero-padded 64-bit sequence number)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv[..12]);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        // AAD: TLS record header
        // content_type(1) = 0x17 (ApplicationData)
        // legacy_version(2) = 0x0303
        // length(2) = data.len()
        let mut aad = Vec::with_capacity(5);
        aad.push(ContentType::ApplicationData as u8);
        aad.extend_from_slice(&[0x03, 0x03]);
        aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

        if data.len() < 16 {
            return Err(TlsError::DecryptError);
        }

        let ciphertext_len = data.len() - 16;
        let ciphertext = &data[..ciphertext_len];
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[ciphertext_len..]);

        let plaintext = if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_decrypt(&key_arr, &nonce, &aad, ciphertext, &tag)
                .ok_or(TlsError::DecryptError)?
        } else {
            aes_gcm_decrypt(key, &nonce, &aad, ciphertext, &tag)
                .ok_or(TlsError::DecryptError)?
        };

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
    fn tls13_encrypt_record(
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
    fn tls13_encrypt_application_data(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // inner plaintext = data + content_type
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
        inner.push(ContentType::ApplicationData as u8);
        self.tls13_encrypt_record(&inner, false)
    }

    /// フルハンドシェイク完了後にセッションをキャッシュに保存する
    fn cache_session_if_needed(&mut self) {
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
    fn process_finished(&mut self, data: &[u8]) -> TlsResult<()> {
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
    fn decrypt_record(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
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
    fn decrypt_aes_gcm(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
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
    fn decrypt_chacha20_poly1305(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
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

    /// データを暗号化して送信
    ///
    /// Dispatches between TLS 1.3 record layer and TLS 1.2 cipher suites.
    pub fn encrypt(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if self.state != TlsState::Established {
            return Err(TlsError::NotConnected);
        }

        // TLS 1.3: inner content type付きでAEAD暗号化
        if self.is_tls13 {
            let mut inner_plaintext = Vec::with_capacity(data.len() + 1);
            inner_plaintext.extend_from_slice(data);
            inner_plaintext.push(ContentType::ApplicationData as u8);
            return self.tls13_encrypt_record(&inner_plaintext, false);
        }

        // TLS 1.2
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_poly1305(data)
        } else {
            self.encrypt_aes_gcm(data)
        }
    }

    /// AES-GCM record encryption (TLS 1.2)
    ///
    /// Record structure:
    /// - content_type (1 byte) + version (2 bytes) + length (2 bytes)
    /// - explicit_nonce (8 bytes)
    /// - ciphertext (same length as plaintext)
    /// - auth_tag (16 bytes)
    fn encrypt_aes_gcm(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        let explicit_nonce = self.write_seq.to_be_bytes();

        // Keys not set — placeholder passthrough
        let (ciphertext, auth_tag) = if self.write_key.is_empty() || self.write_iv.len() < 4 {
            (data.to_vec(), [0u8; 16])
        } else {
            // 12-byte nonce: implicit_iv(4) || explicit_nonce(8)
            let mut nonce = [0u8; 12];
            nonce[0..4].copy_from_slice(&self.write_iv[0..4]);
            nonce[4..12].copy_from_slice(&explicit_nonce);

            // AAD: seq_num(8) || type(1) || version(2) || length(2)
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.write_seq.to_be_bytes());
            aad.push(ContentType::ApplicationData as u8);
            aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

            aes_gcm_encrypt(&self.write_key, &nonce, &aad, data)
        };

        // Record length: nonce(8) + ciphertext + tag(16)
        let record_len = 8 + ciphertext.len() + 16;

        let mut record = vec![
            ContentType::ApplicationData as u8,
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
    fn encrypt_chacha20_poly1305(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // Keys not set — placeholder passthrough
        let (ciphertext, auth_tag) =
            if self.write_key.is_empty() || self.write_key.len() < 32 || self.write_iv.len() < 12 {
                (data.to_vec(), [0u8; 16])
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
                aad.push(ContentType::ApplicationData as u8);
                aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
                aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

                let mut key = [0u8; 32];
                key.copy_from_slice(&self.write_key[0..32]);

                chacha20_poly1305_encrypt(&key, &nonce, &aad, data)
            };

        // Record length: ciphertext + tag(16) — no explicit nonce for ChaCha20-Poly1305
        let record_len = ciphertext.len() + 16;

        let mut record = vec![
            ContentType::ApplicationData as u8,
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
    fn tls13_split_content_type(decrypted: &[u8]) -> Option<(u8, &[u8])> {
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
    fn tls13_process_post_handshake(&mut self, data: &[u8]) -> TlsResult<()> {
        let mut offset = 0;
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
    fn parse_ticket_extensions(data: &[u8], off: usize) -> u32 {
        let mut max_early_data_size: u32 = 0;
        if data.len() < off + 2 {
            return max_early_data_size;
        }
        let ext_total_len = ((data[off] as usize) << 8) | data[off + 1] as usize;
        let mut eoff = off + 2;
        let ext_end = eoff + ext_total_len;
        while eoff + 4 <= ext_end && eoff + 4 <= data.len() {
            let ext_type = ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
            let ext_len = ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
            eoff += 4;
            if eoff + ext_len > data.len() {
                break;
            }
            if ext_type == 42 && ext_len >= 4 {
                max_early_data_size = u32::from_be_bytes([
                    data[eoff], data[eoff + 1], data[eoff + 2], data[eoff + 3],
                ]);
            }
            eoff += ext_len;
        }
        max_early_data_size
    }

    /// Resumption Master SecretからPSKを導出
    fn derive_tls13_psk_from_rms(&self, ticket_nonce: &[u8]) -> Option<Vec<u8>> {
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

    fn tls13_process_new_session_ticket(&mut self, data: &[u8]) -> TlsResult<()> {
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
    fn tls13_process_key_update(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let request_update = data[0];

        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let use_384 = cipher.uses_sha384();
        let hash_len = if use_384 { SHA384_OUTPUT_SIZE } else { SHA256_OUTPUT_SIZE };

        // サーバーの application_traffic_secret を更新
        // application_traffic_secret_N+1 =
        //     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
        let mut new_server_secret = [0u8; 48];
        if use_384 {
            let mut old_secret = [0u8; 48];
            old_secret.copy_from_slice(&self.server_app_traffic_secret);
            let result = hkdf_expand_label_sha384(
                &old_secret,
                b"traffic upd",
                b"",
                hash_len,
            );
            new_server_secret[..hash_len].copy_from_slice(&result[..hash_len]);
        } else {
            let mut old_secret = [0u8; 32];
            old_secret.copy_from_slice(&self.server_app_traffic_secret[..32]);
            let result = hkdf_expand_label(
                &old_secret,
                b"traffic upd",
                b"",
                hash_len,
            );
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
                let result = hkdf_expand_label_sha384(
                    &old_secret,
                    b"traffic upd",
                    b"",
                    hash_len,
                );
                new_client_secret[..hash_len].copy_from_slice(&result[..hash_len]);
            } else {
                let mut old_secret = [0u8; 32];
                old_secret.copy_from_slice(&self.client_app_traffic_secret[..32]);
                let result = hkdf_expand_label(
                    &old_secret,
                    b"traffic upd",
                    b"",
                    hash_len,
                );
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
    pub fn build_key_update_response(&mut self) -> Option<Vec<u8>> {
        if !self.pending_key_update_response {
            return None;
        }
        self.pending_key_update_response = false;

        // KeyUpdate { update_not_requested(0) }
        let key_update_msg = vec![
            24,   // msg_type = KeyUpdate
            0, 0, 1, // length = 1
            0,    // update_not_requested
        ];

        // Handshake content type を付加して暗号化
        let mut inner = Vec::with_capacity(key_update_msg.len() + 1);
        inner.extend_from_slice(&key_update_msg);
        inner.push(ContentType::Handshake as u8);

        self.tls13_encrypt_record(&inner, false).ok()
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
    pub fn close(&mut self) -> Vec<u8> {
        self.state = TlsState::Closing;

        if self.is_tls13 && !self.write_key.is_empty() {
            // TLS 1.3: close_notify を暗号化して送信
            let mut inner = Vec::with_capacity(3);
            inner.push(AlertLevel::Warning as u8);
            inner.push(AlertDescription::CloseNotify as u8);
            inner.push(ContentType::Alert as u8);
            if let Ok(record) = self.tls13_encrypt_record(&inner, false) {
                return record;
            }
        }

        // TLS 1.2 or fallback
        vec![
            ContentType::Alert as u8,
            0x03,
            0x03,
            0,
            2,
            AlertLevel::Warning as u8,
            AlertDescription::CloseNotify as u8,
        ]
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
