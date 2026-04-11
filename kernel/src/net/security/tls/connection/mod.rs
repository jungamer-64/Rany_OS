// ============================================================================
// tls/connection.rs - TLS Connection State Machine
// ============================================================================

// Building block: TLS connection internals
#![allow(dead_code)]

use super::crypto::*;
use super::error::{TlsError, TlsResult};
use super::types::*;
use crate::net::payload::{PacketPayloadBuilder, PacketPayloadView, PayloadSpan, append_payload};
use crate::net::security::ecdh;
use kernel_api::resource::net::{PacketPayload, PacketRef};

/// TLS 1.3 トランスクリプトハッシュ（SHA-256 or SHA-384）
mod incoming;

#[derive(Clone)]
struct TranscriptState {
    sha256: crate::crypto::sha256::Sha256,
    sha384: crate::crypto::sha384::Sha384,
    len: usize,
    initialized: bool,
    server_finished_sha256: Option<[u8; SHA256_OUTPUT_SIZE]>,
    server_finished_sha384: Option<[u8; SHA384_OUTPUT_SIZE]>,
}

impl Default for TranscriptState {
    fn default() -> Self {
        Self {
            sha256: crate::crypto::sha256::Sha256::new(),
            sha384: crate::crypto::sha384::Sha384::new(),
            len: 0,
            initialized: false,
            server_finished_sha256: None,
            server_finished_sha384: None,
        }
    }
}

impl TranscriptState {
    fn initialize(&mut self) {
        self.sha256.reset();
        self.sha384.reset();
        self.len = 0;
        self.initialized = true;
        self.server_finished_sha256 = None;
        self.server_finished_sha384 = None;
    }

    fn set_bytes(&mut self, data: &[u8]) {
        self.initialize();
        self.update(data);
    }

    fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.sha384.update(data);
        self.len = self.len.saturating_add(data.len());
        self.initialized = true;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn current_sha256(&self) -> [u8; SHA256_OUTPUT_SIZE] {
        self.sha256.clone().finalize()
    }

    fn current_sha384(&self) -> [u8; SHA384_OUTPUT_SIZE] {
        self.sha384.clone().finalize()
    }

    fn replace_with_message_hash(&mut self, use_384: bool) {
        let digest_len = if use_384 {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        };
        let mut synthetic = [0u8; 4 + SHA384_OUTPUT_SIZE];
        synthetic[0] = HandshakeType::MessageHash as u8;
        synthetic[3] = digest_len as u8;
        if use_384 {
            synthetic[4..4 + SHA384_OUTPUT_SIZE].copy_from_slice(&self.current_sha384());
        } else {
            synthetic[4..4 + SHA256_OUTPUT_SIZE].copy_from_slice(&self.current_sha256());
        }
        self.set_bytes(&synthetic[..4 + digest_len]);
    }

    fn snapshot_server_finished(&mut self) {
        self.server_finished_sha256 = Some(self.current_sha256());
        self.server_finished_sha384 = Some(self.current_sha384());
    }

    fn server_finished_sha256(&self) -> Option<[u8; SHA256_OUTPUT_SIZE]> {
        self.server_finished_sha256
    }

    fn server_finished_sha384(&self) -> Option<[u8; SHA384_OUTPUT_SIZE]> {
        self.server_finished_sha384
    }
}

// ============================================================================
// TLS Connection
// ============================================================================

const TLS_CLIENT_HELLO_SCRATCH_CAPACITY: usize = 4096;
const TLS_EXTENSION_SCRATCH_CAPACITY: usize = 2048;

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
    read_key: TlsBytes<32>,
    /// 書き込みキー
    write_key: TlsBytes<32>,
    /// 読み取りIV
    read_iv: TlsBytes<16>,
    /// 書き込みIV
    write_iv: TlsBytes<16>,
    /// シーケンス番号（読み取り）
    read_seq: u64,
    /// シーケンス番号（書き込み）
    write_seq: u64,
    /// 受信バッファ
    recv_buffer: PacketPayload,
    /// Pre-master secret (from key exchange, used to derive master secret)
    pre_master_secret: TlsBytes<64>,
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
    hs_read_key: TlsBytes<32>,
    /// TLS 1.3: ハンドシェイク読み取りIV
    hs_read_iv: TlsBytes<16>,
    /// TLS 1.3: ハンドシェイク書き込み鍵
    hs_write_key: TlsBytes<32>,
    /// TLS 1.3: ハンドシェイク書き込みIV
    hs_write_iv: TlsBytes<16>,
    /// TLS 1.3: ハンドシェイク読み取りシーケンス番号
    hs_read_seq: u64,
    /// TLS 1.3: ハンドシェイク書き込みシーケンス番号
    hs_write_seq: u64,
    /// TLS ハンドシェイクトランスクリプト状態
    transcript_state: TranscriptState,
    /// TLS 1.3: 受信済みセッションチケット
    session_ticket: Option<SessionTicket>,
    /// TLS 1.3: KeyUpdate応答送信が必要か
    pending_key_update_response: bool,
    // ========================================================================
    // CBC mode fields (TLS 1.0/1.1/1.2 CBC cipher suites)
    // ========================================================================
    /// 読み取りMAC鍵 (HMAC-SHA1 or HMAC-SHA256)
    read_mac_key: TlsBytes<32>,
    /// 書き込みMAC鍵
    write_mac_key: TlsBytes<32>,
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
    resumption_master_secret: TlsBytes<48>,
    /// TLS 1.3: 導出済みPSK (チケットから導出)
    tls13_psk: Option<TlsBytes<48>>,
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
    early_write_key: TlsBytes<32>,
    /// Early Data暗号化IV
    early_write_iv: TlsBytes<16>,
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
    /// TLS 1.2: 読み取り暗号化が有効か (ChangeCipherSpec受信後)
    read_encryption_active: bool,
    /// TLS 1.2: 書き込み暗号化が有効か (ChangeCipherSpec送信後)
    write_encryption_active: bool,
}

impl TlsConnection {
    fn set_tls_bytes<const N: usize>(slot: &mut TlsBytes<N>, data: &[u8]) -> TlsResult<()> {
        slot.set(data).ok_or(TlsError::DecodeError)
    }

    pub(super) fn copy_payload_into_packet(payload: &PacketPayload) -> TlsResult<PacketRef> {
        let payload_view = PacketPayloadView::new(payload);
        let mut packet = crate::net::payload::alloc_packet_with_headroom(payload_view.total_len(), 0)
            .ok_or(TlsError::DecodeError)?;
        if payload_view.copy_all_into(&mut packet.data_mut()[..payload_view.total_len()])
            != payload_view.total_len()
        {
            return Err(TlsError::DecodeError);
        }
        Ok(packet)
    }

    fn tls12_aad(seq: u64, content_type: u8, len: usize) -> [u8; 13] {
        let seq_bytes = seq.to_be_bytes();
        let len_bytes = (len as u16).to_be_bytes();
        [
            seq_bytes[0],
            seq_bytes[1],
            seq_bytes[2],
            seq_bytes[3],
            seq_bytes[4],
            seq_bytes[5],
            seq_bytes[6],
            seq_bytes[7],
            content_type,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ]
    }

    fn tls13_record_aad(len: usize) -> [u8; 5] {
        let len_bytes = (len as u16).to_be_bytes();
        [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ]
    }

    fn encrypt_aead_payload(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> TlsResult<(kernel_api::resource::net::PacketPayload, [u8; 16])> {
        let mut packet = crate::net::payload::alloc_packet_with_headroom(plaintext.len(), 0)
            .ok_or(TlsError::DecodeError)?;
        if !plaintext.is_empty() {
            packet.data_mut()[..plaintext.len()].copy_from_slice(plaintext);
        }
        let mut tag = [0u8; 16];
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_encrypt_in_place(
                &key_arr,
                nonce,
                aad,
                &mut packet.data_mut()[..plaintext.len()],
                &mut tag,
            );
        } else {
            aes_gcm_encrypt_into(
                key,
                nonce,
                aad,
                plaintext,
                &mut packet.data_mut()[..plaintext.len()],
                &mut tag,
            )
            .map_err(|_| TlsError::CryptoError)?;
        }
        Ok((PacketPayload::single(packet), tag))
    }

    fn decrypt_aead_payload(
        cipher: CipherSuite,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> TlsResult<kernel_api::resource::net::PacketPayload> {
        let mut packet = crate::net::payload::alloc_packet_with_headroom(ciphertext.len(), 0)
            .ok_or(TlsError::DecodeError)?;
        if !ciphertext.is_empty() {
            packet.data_mut()[..ciphertext.len()].copy_from_slice(ciphertext);
        }
        if cipher.is_chacha20_poly1305() {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);
            chacha20_poly1305_decrypt_in_place(
                &key_arr,
                nonce,
                aad,
                &mut packet.data_mut()[..ciphertext.len()],
                tag,
            )
            .map_err(|_| TlsError::DecryptError)?;
        } else {
            aes_gcm_decrypt_into(
                key,
                nonce,
                aad,
                ciphertext,
                &mut packet.data_mut()[..ciphertext.len()],
                tag,
            )
            .map_err(|_| TlsError::DecryptError)?;
        }
        Ok(PacketPayload::single(packet))
    }

    fn transcript_len(&self) -> usize {
        self.transcript_state.len()
    }

    fn append_transcript_bytes(&mut self, data: &[u8]) -> TlsResult<()> {
        self.transcript_state.update(data);
        Ok(())
    }

    fn append_transcript_parts(&mut self, parts: &[&[u8]]) -> TlsResult<()> {
        for part in parts {
            if !part.is_empty() {
                self.transcript_state.update(part);
            }
        }
        Ok(())
    }

    fn replace_transcript_bytes(&mut self, data: &[u8]) -> TlsResult<()> {
        self.transcript_state.set_bytes(data);
        Ok(())
    }

    fn transcript_hash_sha256(&self) -> [u8; SHA256_OUTPUT_SIZE] {
        self.transcript_state.current_sha256()
    }

    fn transcript_hash_sha384(&self) -> [u8; SHA384_OUTPUT_SIZE] {
        self.transcript_state.current_sha384()
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
            read_key: TlsBytes::new(),
            write_key: TlsBytes::new(),
            read_iv: TlsBytes::new(),
            write_iv: TlsBytes::new(),
            read_seq: 0,
            write_seq: 0,
            recv_buffer: PacketPayload::default(),
            pre_master_secret: TlsBytes::new(),
            local_ecdh_keypair: None,
            server_public_key: None,
            // TLS 1.3 fields
            is_tls13: false,
            server_hs_traffic_secret: [0; 48],
            client_hs_traffic_secret: [0; 48],
            server_app_traffic_secret: [0; 48],
            client_app_traffic_secret: [0; 48],
            hs_read_key: TlsBytes::new(),
            hs_read_iv: TlsBytes::new(),
            hs_write_key: TlsBytes::new(),
            hs_write_iv: TlsBytes::new(),
            hs_read_seq: 0,
            hs_write_seq: 0,
            transcript_state: TranscriptState::default(),
            session_ticket: None,
            pending_key_update_response: false,
            // CBC mode fields
            read_mac_key: TlsBytes::new(),
            write_mac_key: TlsBytes::new(),
            read_cbc_iv: [0; 16],
            write_cbc_iv: [0; 16],
            last_read_ciphertext_block: None,
            last_write_ciphertext_block: None,
            // Session resumption
            session_cache: None,
            resuming_session: false,
            // TLS 1.3 PSK session resumption
            resumption_master_secret: TlsBytes::new(),
            tls13_psk: None,
            tls13_psk_identity: None,
            tls13_ticket_age_add: 0,
            tls13_using_psk: false,
            tls13_psk_cipher: None,
            max_early_data_size: 0,
            early_data_buffer: PacketPayload::default(),
            early_write_key: TlsBytes::new(),
            early_write_iv: TlsBytes::new(),
            early_write_seq: 0,
            early_data_accepted: false,
            early_data_sent: false,
            client_auth_requested: false,
            certificate_request_context: None,
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
        self.transcript_state.initialize();
    }

    /// セッションキャッシュからセッションIDを探してhelloに追加する
    fn append_session_id<const N: usize>(&mut self, hello: &mut TlsBytes<N>) -> Option<()> {
        let cached_session_id = if let Some(ref cache) = self.session_cache {
            if let Some(ref name) = self.config.server_name {
                cache.find_by_server_name(name.as_str())
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
            self.session_id = SessionId::new(sid);
        } else {
            hello.push_byte(0)?;
        }
        Some(())
    }

    /// PSKバインダーを計算してmessageに上書きする (RFC 8446 Section 4.2.11.2)
    fn compute_psk_binders<const N: usize>(&self, message: &mut TlsBytes<N>) {
        let Some(psk) = self.tls13_psk.as_ref() else {
            return;
        };
        if self.tls13_psk_identity.is_none() {
            return;
        }
        let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
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
            let early_secret = tls13_early_secret_sha384(Some(psk.as_slice()));
            let ch_hash = self.transcript_hash_sha384();
            let cets = tls13_derive_secret_sha384(&early_secret, b"c e traffic", &ch_hash);
            let mut ew_iv = [0u8; 12];
            let ew_key = &mut self.early_write_key.as_mut_storage()[..key_len];
            tls13_derive_traffic_keys_sha384(&cets, ew_key, &mut ew_iv);
            self.early_write_key
                .set_filled_len(key_len)
                .expect("early write key length");
            Self::set_tls_bytes(&mut self.early_write_iv, &ew_iv).expect("early write iv length");
        } else {
            let early_secret = tls13_early_secret(Some(psk.as_slice()));
            let ch_hash = self.transcript_hash_sha256();
            let cets = tls13_derive_secret(&early_secret, b"c e traffic", &ch_hash);
            let mut ew_iv = [0u8; 12];
            let ew_key = &mut self.early_write_key.as_mut_storage()[..key_len];
            tls13_derive_traffic_keys(&cets, ew_key, &mut ew_iv);
            self.early_write_key
                .set_filled_len(key_len)
                .expect("early write key length");
            Self::set_tls_bytes(&mut self.early_write_iv, &ew_iv).expect("early write iv length");
        }
        self.early_write_seq = 0;
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
        if hello.append_slice(&self.client_random).is_none() {
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
        if message.push_byte(HandshakeType::ClientHello as u8).is_none()
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

        self.state = TlsState::ClientHelloSent;
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
        if self.early_write_key.is_empty() || self.early_write_iv.len() < 12 {
            return PacketPayload::default();
        }

        if payload.is_empty() {
            return PacketPayload::default();
        }

        let payload_view = PacketPayloadView::new(payload);

        let cipher = self
            .tls13_psk_cipher
            .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);

        let mut inner_plaintext =
            match crate::net::payload::alloc_packet_with_headroom(payload_view.total_len() + 1, 0)
            {
                Some(packet) => packet,
                None => return PacketPayload::default(),
            };
        if payload_view.copy_all_into(&mut inner_plaintext.data_mut()[..payload_view.total_len()])
            != payload_view.total_len()
        {
            return PacketPayload::default();
        }
        inner_plaintext.data_mut()[payload_view.total_len()] = ContentType::ApplicationData as u8;

        // Nonce: IV XOR (zero-padded sequence number)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.early_write_iv.as_slice()[..12]);
        let seq_bytes = self.early_write_seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        let encrypted_len = payload_view.total_len() + 1 + 16;

        // AAD: TLS record header
        let aad = Self::tls13_record_aad(encrypted_len);

        let (ciphertext, auth_tag) = match Self::encrypt_aead_payload(
            cipher,
            self.early_write_key.as_slice(),
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

        self.early_write_seq += 1;
        self.early_data_sent = true;
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

    pub fn send_early_data_payload(&mut self, payload: &PacketPayload) -> PacketPayload {
        let total = self.early_data_buffer.total_len() + payload.total_len();
        if self.max_early_data_size > 0 && total > self.max_early_data_size as usize {
            return PacketPayload::default();
        }
        append_payload(&mut self.early_data_buffer, payload.clone());
        self.send_early_data_record_payload(payload)
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
    fn append_tls13_extensions<const N: usize>(
        &self,
        extensions: &mut TlsBytes<N>,
    ) -> Option<()> {
        // PSK Key Exchange Modes (RFC 8446 Section 4.2.9)
        {
            extensions.append_slice(&[0, 45])?; // type = psk_key_exchange_modes
            extensions.append_be_u16(2)?;
            extensions.append_slice(&[1, 1])?;
        }

        // Key Share (RFC 8446 Section 4.2.8)
        if let Some(ref keypair) = self.local_ecdh_keypair {
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
        if self.tls13_psk.is_some() && self.max_early_data_size > 0 {
            extensions.append_slice(&[0, 42])?; // type = early_data
            extensions.append_be_u16(0)?; // length = 0
        }

        // pre_shared_key (RFC 8446 Section 4.2.11) - MUST be last extension
        if let Some(ref psk_identity) = self.tls13_psk_identity {
            let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
            let hash_len = if use_384 { 48 } else { 32 };
            let obfuscated_age: u32 = self.tls13_ticket_age_add;
            let Some(identity_bytes) = psk_identity.as_contiguous_slice() else {
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
        if let Some(ref name) = self.config.server_name {
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
