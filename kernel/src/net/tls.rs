// ============================================================================
// src/net/tls.rs - TLS/SSL Protocol Support
// ============================================================================
//!
//! # TLS プロトコルサポート
//!
//! 安全な通信のためのTLS 1.2/1.3サポート。
//!
//! ## 機能
//! - TLS 1.2/1.3ハンドシェイク
//! - 暗号スイート（AES-GCM, ChaCha20-Poly1305）
//! - 証明書検証
//! - セッション再開

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// Type-Safe Identifiers
// ============================================================================

/// TLSバージョン
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsVersion(pub u16);

impl TlsVersion {
    pub const TLS_1_0: Self = Self(0x0301);
    pub const TLS_1_1: Self = Self(0x0302);
    pub const TLS_1_2: Self = Self(0x0303);
    pub const TLS_1_3: Self = Self(0x0304);

    pub fn major(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub fn minor(self) -> u8 {
        self.0 as u8
    }

    pub fn to_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// セッションID
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn empty() -> Self {
        Self([0; 32])
    }
}

// ============================================================================
// Cipher Suites
// ============================================================================

/// 暗号スイート
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    // TLS 1.2
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009C);
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009D);
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02F);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC030);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02B);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC02C);
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCA8);
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCA9);

    // TLS 1.3
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);

    /// Check if this is a ChaCha20-Poly1305 cipher suite
    pub fn is_chacha20_poly1305(&self) -> bool {
        matches!(self.0, 0xCCA8 | 0xCCA9 | 0x1303)
    }

    /// Check if this is an AES-GCM cipher suite
    pub fn is_aes_gcm(&self) -> bool {
        matches!(
            self.0,
            0x009C | 0x009D | 0xC02F | 0xC030 | 0xC02B | 0xC02C | 0x1301 | 0x1302
        )
    }

    /// Get the key length in bytes for this cipher suite
    pub fn key_len(&self) -> usize {
        match self.0 {
            // AES-128 suites (GCM)
            0x009C | 0xC02F | 0xC02B | 0x1301 => 16,
            // AES-256 suites (GCM)
            0x009D | 0xC030 | 0xC02C | 0x1302 => 32,
            // ChaCha20-Poly1305 suites (256-bit key)
            0xCCA8 | 0xCCA9 | 0x1303 => 32,
            // AES-128 CBC suites
            0x002F | 0x003C | 0xC013 | 0xC027 | 0xC009 => 16,
            // AES-256 CBC suites
            0x0035 | 0x003D | 0xC014 | 0xC00A => 32,
            // Default to 16
            _ => 16,
        }
    }

    /// Get the IV length in bytes for this cipher suite
    pub fn iv_len(&self) -> usize {
        match self.0 {
            // AES-GCM uses 4-byte implicit IV (TLS 1.2)
            0x009C | 0x009D | 0xC02F | 0xC030 | 0xC02B | 0xC02C => 4,
            // TLS 1.3 AES-GCM uses 12-byte IV
            0x1301 | 0x1302 => 12,
            // ChaCha20-Poly1305 uses 12-byte IV
            0xCCA8 | 0xCCA9 | 0x1303 => 12,
            // CBC uses 16-byte IV
            0x002F | 0x0035 | 0x003C | 0x003D |
            0xC013 | 0xC014 | 0xC027 | 0xC009 | 0xC00A => 16,
            // Default to 4
            _ => 4,
        }
    }

    /// デフォルトの暗号スイート一覧
    pub fn defaults() -> Vec<Self> {
        vec![
            // TLS 1.3 AEAD
            Self::TLS_AES_128_GCM_SHA256,
            Self::TLS_AES_256_GCM_SHA384,
            Self::TLS_CHACHA20_POLY1305_SHA256,
            // TLS 1.2 AEAD
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            // TLS 1.0/1.1/1.2 CBC
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            Self::TLS_RSA_WITH_AES_128_CBC_SHA256,
            Self::TLS_RSA_WITH_AES_256_CBC_SHA256,
            Self::TLS_RSA_WITH_AES_128_CBC_SHA,
            Self::TLS_RSA_WITH_AES_256_CBC_SHA,
        ]
    }
}

/// 署名アルゴリズム
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);
    pub const ED448: Self = Self(0x0808);
}

/// 名前付きグループ（楕円曲線）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    pub const SECP256R1: Self = Self(0x0017);
    pub const SECP384R1: Self = Self(0x0018);
    pub const SECP521R1: Self = Self(0x0019);
    pub const X25519: Self = Self(0x001D);
    pub const X448: Self = Self(0x001E);
    pub const FFDHE2048: Self = Self(0x0100);
    pub const FFDHE3072: Self = Self(0x0101);
}

// ============================================================================
// TLS Records
// ============================================================================

/// コンテントタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

impl ContentType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            24 => Some(Self::Heartbeat),
            _ => None,
        }
    }
}

/// ハンドシェイクタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

/// TLSレコードヘッダ
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct RecordHeader {
    pub content_type: u8,
    pub version: [u8; 2],
    pub length: [u8; 2],
}

impl RecordHeader {
    pub fn version(&self) -> TlsVersion {
        TlsVersion(((self.version[0] as u16) << 8) | self.version[1] as u16)
    }

    pub fn length(&self) -> u16 {
        ((self.length[0] as u16) << 8) | self.length[1] as u16
    }
}

// ============================================================================
// Alert
// ============================================================================

/// アラートレベル
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// アラート説明
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

// ============================================================================
// TLS Connection State
// ============================================================================

/// TLS接続状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsState {
    /// 初期状態
    Initial,
    /// ClientHello送信済み
    ClientHelloSent,
    /// ServerHello受信済み
    ServerHelloReceived,
    /// ハンドシェイク中
    Handshaking,
    /// TLS 1.3: ServerHello処理後、暗号化ハンドシェイク待ち
    Tls13WaitEncryptedExtensions,
    /// TLS 1.3: EncryptedExtensions受信後、Certificate待ち
    Tls13WaitCertificate,
    /// TLS 1.3: Certificate受信後、CertificateVerify待ち
    Tls13WaitCertificateVerify,
    /// TLS 1.3: CertificateVerify受信後、Finished待ち
    Tls13WaitFinished,
    /// TLS 1.3: サーバーFinished受信済み、クライアントFinished送信待ち
    Tls13ServerFinishedReceived,
    /// TLS 1.3: HelloRetryRequest 受信済み、再ClientHello送信待ち
    HelloRetryReceived,
    /// TLS 1.2: 略式ハンドシェイク中、サーバーChangeCipherSpec+Finished待ち
    WaitFinishedResumed,
    /// 接続確立
    Established,
    /// シャットダウン中
    Closing,
    /// 接続終了
    Closed,
    /// エラー
    Error,
}

// ============================================================================
// Extensions
// ============================================================================

/// TLS拡張タイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(0);
    pub const MAX_FRAGMENT_LENGTH: Self = Self(1);
    pub const STATUS_REQUEST: Self = Self(5);
    pub const SUPPORTED_GROUPS: Self = Self(10);
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    pub const USE_SRTP: Self = Self(14);
    pub const HEARTBEAT: Self = Self(15);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(16);
    pub const SIGNED_CERTIFICATE_TIMESTAMP: Self = Self(18);
    pub const CLIENT_CERTIFICATE_TYPE: Self = Self(19);
    pub const SERVER_CERTIFICATE_TYPE: Self = Self(20);
    pub const PADDING: Self = Self(21);
    pub const ENCRYPT_THEN_MAC: Self = Self(22);
    pub const EXTENDED_MASTER_SECRET: Self = Self(23);
    pub const SESSION_TICKET: Self = Self(35);
    pub const PRE_SHARED_KEY: Self = Self(41);
    pub const EARLY_DATA: Self = Self(42);
    pub const SUPPORTED_VERSIONS: Self = Self(43);
    pub const COOKIE: Self = Self(44);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(45);
    pub const CERTIFICATE_AUTHORITIES: Self = Self(47);
    pub const OID_FILTERS: Self = Self(48);
    pub const POST_HANDSHAKE_AUTH: Self = Self(49);
    pub const SIGNATURE_ALGORITHMS_CERT: Self = Self(50);
    pub const KEY_SHARE: Self = Self(51);
}

/// Server Name Indication
#[derive(Clone, Debug)]
pub struct ServerNameList {
    pub names: Vec<ServerName>,
}

/// サーバー名
#[derive(Clone, Debug)]
pub struct ServerName {
    pub name_type: u8, // 0 = hostname
    pub name: String,
}

// ============================================================================
// TLS Configuration
// ============================================================================

/// TLS設定
#[derive(Clone)]
pub struct TlsConfig {
    /// 最小バージョン
    pub min_version: TlsVersion,
    /// 最大バージョン
    pub max_version: TlsVersion,
    /// 暗号スイート
    pub cipher_suites: Vec<CipherSuite>,
    /// 署名アルゴリズム
    pub signature_schemes: Vec<SignatureScheme>,
    /// 名前付きグループ
    pub named_groups: Vec<NamedGroup>,
    /// ALPN
    pub alpn_protocols: Vec<String>,
    /// SNI
    pub server_name: Option<String>,
    /// セッション再開を許可
    pub enable_session_resumption: bool,
    /// クライアント証明書
    pub client_cert: Option<Certificate>,
    /// クライアント秘密鍵
    pub client_key: Option<PrivateKey>,
    /// CA証明書
    pub ca_certs: Vec<Certificate>,
    /// 証明書検証を無効化（デバッグ用）
    pub skip_verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::TLS_1_0,
            max_version: TlsVersion::TLS_1_3,
            cipher_suites: CipherSuite::defaults(),
            signature_schemes: vec![
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::ECDSA_SECP384R1_SHA384,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ],
            named_groups: vec![
                NamedGroup::X25519,
                NamedGroup::SECP256R1,
                NamedGroup::SECP384R1,
            ],
            alpn_protocols: Vec::new(),
            server_name: None,
            enable_session_resumption: true,
            client_cert: None,
            client_key: None,
            ca_certs: Vec::new(),
            skip_verify: false,
        }
    }
}

impl TlsConfig {
    /// 新しいTLS設定を作成
    pub fn new() -> Self {
        Self::default()
    }

    /// サーバー名を設定
    pub fn with_server_name(mut self, name: &str) -> Self {
        self.server_name = Some(String::from(name));
        self
    }

    /// ALPNプロトコルを設定
    pub fn with_alpn(mut self, protocols: &[&str]) -> Self {
        self.alpn_protocols = protocols.iter().map(|s| String::from(*s)).collect();
        self
    }
}

// ============================================================================
// Certificates
// ============================================================================

/// 証明書
#[derive(Clone, Debug)]
pub struct Certificate {
    /// DERエンコードされた証明書
    pub der: Vec<u8>,
}

impl Certificate {
    /// DERデータから作成
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }

    /// PEMから作成（簡易パース）
    pub fn from_pem(pem: &str) -> Option<Self> {
        let lines: Vec<&str> = pem.lines().collect();
        let mut in_cert = false;
        let mut base64_data = String::new();

        for line in lines {
            if line.contains("BEGIN CERTIFICATE") {
                in_cert = true;
            } else if line.contains("END CERTIFICATE") {
                break;
            } else if in_cert {
                base64_data.push_str(line.trim());
            }
        }

        // Base64デコード（簡易）
        base64_decode(&base64_data).map(|der| Self { der })
    }
}

/// 秘密鍵
#[derive(Clone)]
pub struct PrivateKey {
    /// DERエンコードされた秘密鍵
    pub der: Vec<u8>,
    /// 鍵タイプ
    pub key_type: KeyType,
}

/// 鍵タイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
}

/// 簡易Base64デコード
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }

        let value = TABLE.iter().position(|&x| x == c as u8)? as u32;
        buf = (buf << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(output)
}

// ============================================================================
// Server Public Key (extracted from X.509 certificate)
// ============================================================================

/// サーバー証明書から抽出した公開鍵情報
#[derive(Clone, Debug)]
pub enum ServerPublicKey {
    /// RSA公開鍵 (modulus, exponent をビッグエンディアンで保持)
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// ECDSA P-256公開鍵 (非圧縮ポイント 04 || x || y)
    EcdsaP256 { point: Vec<u8> },
    /// ECDSA P-384公開鍵 (非圧縮ポイント 04 || x || y)
    EcdsaP384 { point: Vec<u8> },
}

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

/// TLS 1.3 セッションチケット (RFC 8446 Section 4.6.1)
pub struct SessionTicket {
    /// チケット有効期間（秒）
    pub lifetime: u32,
    /// チケットエイジ加算値（難読化用）
    pub age_add: u32,
    /// チケットnonce
    pub nonce: Vec<u8>,
    /// チケットデータ
    pub ticket: Vec<u8>,
}

// ============================================================================
// Session Cache (TLS 1.2 Abbreviated Handshake)
// ============================================================================

/// セッションキャッシュエントリ
#[derive(Clone, Debug)]
pub struct SessionCacheEntry {
    /// セッションID
    pub session_id: [u8; 32],
    /// マスターシークレット
    pub master_secret: [u8; 48],
    /// ネゴシエートされた暗号スイート
    pub cipher_suite: CipherSuite,
    /// サーバー名
    pub server_name: Option<String>,
    /// TLSバージョン
    pub version: TlsVersion,
}

/// セッションキャッシュ
#[derive(Clone, Debug)]
pub struct SessionCache {
    entries: Vec<SessionCacheEntry>,
    max_entries: usize,
}

impl SessionCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    pub fn insert(&mut self, entry: SessionCacheEntry) {
        // 同じセッションIDがあれば上書き
        if let Some(pos) = self.entries.iter().position(|e| e.session_id == entry.session_id) {
            self.entries[pos] = entry;
        } else {
            if self.entries.len() >= self.max_entries {
                self.entries.remove(0); // LRU: 最古のエントリを削除
            }
            self.entries.push(entry);
        }
    }

    pub fn find(&self, session_id: &[u8]) -> Option<&SessionCacheEntry> {
        if session_id.len() != 32 {
            return None;
        }
        self.entries.iter().find(|e| e.session_id == session_id)
    }

    pub fn find_by_server_name(&self, name: &str) -> Option<&SessionCacheEntry> {
        self.entries.iter().rev().find(|e| {
            e.server_name.as_deref() == Some(name)
        })
    }
}

// ============================================================================
// TLS Connection
// ============================================================================

/// TLS接続
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
    local_ecdh_keypair: Option<super::ecdh::EcdhKeyPair>,
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
    pub fn build_client_hello(&mut self) -> Vec<u8> {
        // TLS 1.3: ClientHello送信前にECDH一時鍵を事前生成
        // KeyShare拡張にクライアントの公開鍵を含めるため
        if self.config.max_version == TlsVersion::TLS_1_3 && self.local_ecdh_keypair.is_none() {
            if let Ok(keypair) =
                super::ecdh::EcdhKeyPair::generate(super::ecdh::EcdhGroup::X25519)
            {
                self.local_ecdh_keypair = Some(keypair);
            }
        }

        // TLS 1.3: トランスクリプトハッシュの初期化
        self.transcript_hash = Some(TranscriptHash::Sha256(crate::loader::sha256::Sha256::new()));

        let mut hello = Vec::new();

        // バージョン（TLS 1.2として送信、supported_versionsで実際のバージョンを指定）
        hello.extend_from_slice(&[0x03, 0x03]);

        // クライアントランダム
        hello.extend_from_slice(&self.client_random);

        // セッションID（キャッシュからの再開を試みる）
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
            hello.push(32); // session_id length
            hello.extend_from_slice(&sid);
            self.session_id = SessionId::new(sid);
        } else {
            hello.push(0); // no session_id
        }

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

        // PSKバインダー計算 (RFC 8446 Section 4.2.11.2)
        // バインダーはClientHelloの一部であり、トランスクリプトハッシュに含まれる必要がある。
        // truncated_CH = message のうちバインダーリスト（binders_list_length + binder entries）を除外した部分
        if self.tls13_psk.is_some() && self.tls13_psk_identity.is_some() {
            let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
            let hash_len = if use_384 { 48 } else { 32 };
            let binders_total = 2 + 1 + hash_len; // binders_list_length(2) + binder_length(1) + binder(hash_len)

            if message.len() > binders_total {
                let truncated_len = message.len() - binders_total;
                let truncated_ch = &message[..truncated_len];

                let psk = self.tls13_psk.as_ref().unwrap();

                if use_384 {
                    // early_secret = HKDF-Extract(0, PSK)
                    let early_secret = tls13_early_secret_sha384(Some(psk));
                    // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
                    let empty_hash = crate::loader::sha384::compute(&[]);
                    let binder_key = tls13_derive_secret_sha384(&early_secret, b"res binder", &empty_hash);
                    // binder = HMAC(binder_key, Hash(truncated_CH))
                    let transcript_hash = crate::loader::sha384::compute(truncated_ch);
                    let binder = hmac_sha384(&binder_key, &transcript_hash);
                    // バインダーを上書き
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
                        h.update(truncated_ch);
                        h.finalize()
                    };
                    let binder = hmac_sha256(&binder_key, &transcript_hash);
                    let binder_start = message.len() - hash_len;
                    message[binder_start..].copy_from_slice(&binder[..hash_len]);
                }
            }
        }

        // ハンドシェイクメッセージを記録
        self.handshake_messages.extend_from_slice(&message);

        // Early Data鍵導出 (RFC 8446 Section 7.1)
        // PSK使用時かつmax_early_data_size > 0の場合、Early Data暗号化鍵を導出
        if self.tls13_psk.is_some() && self.max_early_data_size > 0 {
            let psk = self.tls13_psk.as_ref().unwrap();
            let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
            let cipher = self.tls13_psk_cipher.unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256);
            let key_len = cipher.key_len();

            if use_384 {
                let early_secret = tls13_early_secret_sha384(Some(psk));
                // client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)
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
    fn build_extensions(&self) -> Vec<u8> {
        let mut extensions = Vec::new();

        // Server Name Indication
        if let Some(ref name) = self.config.server_name {
            let name_bytes = name.as_bytes();
            let mut ext = Vec::new();
            let list_len = name_bytes.len() + 3;
            ext.extend_from_slice(&[(list_len >> 8) as u8, (list_len & 0xFF) as u8]); // list length
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

        // Supported Versions (RFC 8446 Section 4.2.1)
        // TLS 1.3 requires listing all supported versions
        {
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

            extensions.extend_from_slice(&[0, 43]); // type = supported_versions
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // PSK Key Exchange Modes (RFC 8446 Section 4.2.9)
        // Required for TLS 1.3 even without PSK
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            let mut ext = Vec::new();
            ext.push(1); // 1 mode
            ext.push(1); // psk_dhe_ke(1)

            extensions.extend_from_slice(&[0, 45]); // type = psk_key_exchange_modes
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
        }

        // Key Share (RFC 8446 Section 4.2.8)
        // Pre-generated ECDH public key for TLS 1.3 zero-RTT
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            if let Some(ref keypair) = self.local_ecdh_keypair {
                let pubkey_bytes = keypair.public_key_bytes();
                let group_id = keypair.group().to_named_group();

                // KeyShareEntry: NamedGroup(2) + key_exchange length(2) + key_exchange(N)
                let entry_len = 2 + 2 + pubkey_bytes.len();
                let mut ext = Vec::with_capacity(2 + entry_len);

                // client_shares length
                ext.push((entry_len >> 8) as u8);
                ext.push(entry_len as u8);

                // KeyShareEntry
                ext.push((group_id >> 8) as u8);
                ext.push(group_id as u8);
                ext.push((pubkey_bytes.len() >> 8) as u8);
                ext.push(pubkey_bytes.len() as u8);
                ext.extend_from_slice(&pubkey_bytes);

                extensions.extend_from_slice(&[0, 51]); // type = key_share
                extensions
                    .extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
                extensions.extend_from_slice(&ext);
            }
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

        // early_data (RFC 8446 Section 4.2.10) — type 42, empty body
        // PSK使用時かつサーバーがEarly Dataを許可している場合のみ
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            if self.tls13_psk.is_some() && self.max_early_data_size > 0 {
                extensions.extend_from_slice(&[0, 42]); // type = early_data
                extensions.extend_from_slice(&[0, 0]);   // length = 0 (empty body in ClientHello)
            }
        }

        // pre_shared_key (RFC 8446 Section 4.2.11) - MUST be last extension
        // PSKが利用可能な場合のみ。バインダーはbuild_client_hello()で後から計算・上書きする。
        if self.config.max_version >= TlsVersion::TLS_1_3 {
            if let Some(ref psk_identity) = self.tls13_psk_identity {
                let use_384 = self.tls13_psk_cipher.map_or(false, |c| c.uses_sha384());
                let hash_len = if use_384 { 48 } else { 32 };

                // obfuscated_ticket_age = 0 (チケットを受信して即座に再接続する想定)
                let obfuscated_age: u32 = self.tls13_ticket_age_add;

                // PskIdentity: identity_length(2) + identity + obfuscated_ticket_age(4)
                let identity_len = psk_identity.len();
                let identities_len = 2 + identity_len + 4; // per-identity: len(2) + data + age(4)

                // PskBinderEntry: binder_length(1) + binder(hash_len)
                let binders_len = 1 + hash_len;

                // extension data = identities_list_length(2) + identities + binders_list_length(2) + binders
                let ext_data_len = 2 + identities_len + 2 + binders_len;

                extensions.extend_from_slice(&[0, 41]); // type = pre_shared_key
                extensions.extend_from_slice(&[(ext_data_len >> 8) as u8, ext_data_len as u8]);

                // identities list
                extensions.extend_from_slice(&[(identities_len >> 8) as u8, identities_len as u8]);
                extensions.extend_from_slice(&[(identity_len >> 8) as u8, identity_len as u8]);
                extensions.extend_from_slice(psk_identity);
                extensions.extend_from_slice(&obfuscated_age.to_be_bytes());

                // binders list (placeholder zeros — overwritten by build_client_hello)
                extensions.extend_from_slice(&[(binders_len >> 8) as u8, binders_len as u8]);
                extensions.push(hash_len as u8);
                extensions.extend_from_slice(&alloc::vec![0u8; hash_len]); // binder placeholder
            }
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
                }
                Some(ContentType::ApplicationData) => {
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
                            // TLS 1.3: 内部コンテントタイプを判別
                            if let Some((inner_ct, inner_data)) =
                                Self::tls13_split_content_type(&decrypted)
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
                                        if inner_data.len() >= 2 {
                                            let description = inner_data[1];
                                            if description
                                                == AlertDescription::CloseNotify as u8
                                            {
                                                self.state = TlsState::Closed;
                                            } else {
                                                self.state = TlsState::Error;
                                                return Err(TlsError::Alert(description));
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            let decrypted = self.decrypt_record(payload)?;
                            plaintext.extend_from_slice(&decrypted);
                        }
                    }
                }
                _ => {
                    return Err(TlsError::UnexpectedMessage);
                }
            }
        }

        Ok(plaintext)
    }

    /// ハンドシェイクメッセージを処理
    fn process_handshake(&mut self, data: &[u8]) -> TlsResult<()> {
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

            match msg_type {
                2 => self.process_server_hello(payload)?, // ServerHello
                11 => self.process_certificate(payload)?, // Certificate
                12 => self.process_server_key_exchange(payload)?, // ServerKeyExchange
                14 => self.process_server_hello_done(payload)?, // ServerHelloDone
                20 => self.process_finished(payload)?,    // Finished
                _ => {}
            }

            // ハンドシェイクメッセージを記録
            self.handshake_messages
                .extend_from_slice(&data[offset..body_end]);

            // トランスクリプトハッシュを更新
            if let Some(ref mut hasher) = self.transcript_hash {
                hasher.update(&data[offset..body_end]);
            }

            // TLS 1.3: ServerHello受信後にハンドシェイク鍵を導出
            if msg_type == 2 && self.is_tls13 {
                self.tls13_derive_handshake_keys()?;
            }

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
        // セッションIDをキャプチャー
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

        // 圧縮方式をスキップ（1バイト）
        let ext_offset = offset + 3;

        // 拡張部分をパース
        let mut actual_version = _legacy_version;
        let mut server_key_share: Option<(u16, Vec<u8>)> = None;

        if ext_offset + 2 <= data.len() {
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

                match ext_type {
                    // supported_versions (43)
                    43 => {
                        if ext_len >= 2 {
                            actual_version =
                                TlsVersion(((data[eoff] as u16) << 8) | data[eoff + 1] as u16);
                        }
                    }
                    // pre_shared_key (41) — selected PSK index
                    41 => {
                        if ext_len >= 2 {
                            let selected_index =
                                ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
                            if selected_index == 0 && self.tls13_psk.is_some() {
                                self.tls13_using_psk = true;
                            }
                        }
                    }
                    // key_share (51)
                    51 => {
                        if ext_len >= 4 {
                            let group =
                                ((data[eoff] as u16) << 8) | data[eoff + 1] as u16;
                            let key_len =
                                ((data[eoff + 2] as usize) << 8) | data[eoff + 3] as usize;
                            if ext_len >= 4 + key_len {
                                server_key_share =
                                    Some((group, data[eoff + 4..eoff + 4 + key_len].to_vec()));
                            }
                        }
                    }
                    _ => {}
                }

                eoff += ext_len;
            }
        }

        self.negotiated_version = Some(actual_version);

        // TLS 1.3 検出
        if actual_version == TlsVersion::TLS_1_3 {
            self.is_tls13 = true;

            // HelloRetryRequest 検出 (RFC 8446 Section 4.1.3)
            // 特殊な server_random 値で識別
            const HRR_RANDOM: [u8; 32] = [
                0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
                0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
                0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
            ];

            if self.server_random == HRR_RANDOM {
                return self.process_hello_retry_request(cipher, &server_key_share);
            }

            // TLS 1.3: key_share からECDH共有秘密を計算
            let (group_id, server_pubkey) = server_key_share
                .ok_or(TlsError::HandshakeFailure)?;

            // グループの検証
            let group = super::ecdh::EcdhGroup::from_named_group(group_id)
                .ok_or(TlsError::UnsupportedCipherSuite)?;

            // ローカル鍵ペアの確認（build_client_helloで事前生成済み）
            let local_keypair = self
                .local_ecdh_keypair
                .as_ref()
                .ok_or(TlsError::HandshakeFailure)?;

            if local_keypair.group() != group {
                return Err(TlsError::HandshakeFailure);
            }

            // ECDH共有秘密を計算
            let shared_secret = local_keypair
                .shared_secret(&server_pubkey)
                .map_err(|_| TlsError::CryptoError)?;

            // TLS 1.3 鍵スケジュール
            // ClientHello...ServerHello のトランスクリプトハッシュを計算
            // (handshake_messages にはまだ ServerHello が追加されていない、
            //  process_handshake() で追加されるのでここで先に計算)
            let transcript_hash = {
                let mut hasher = crate::loader::sha256::Sha256::new();
                hasher.update(&self.handshake_messages);
                hasher
            };
            // トランスクリプトハッシュはprocess_handshake内のServerHello append後に計算される
            // ここではハンドシェイクの状態だけ保存して、鍵導出は後で行う
            self.pre_master_secret = shared_secret;
            self.transcript_hash = Some(TranscriptHash::Sha256(transcript_hash));
            self.state = TlsState::ServerHelloReceived;
        } else {
            // TLS 1.2: セッション再開チェック
            if session_id_len == 32
                && self.session_id.0 != [0u8; 32]
                && server_session_id == self.session_id.0
            {
                // サーバーが同一session_idを返却 → 略式ハンドシェイク
                if let Some(ref cache) = self.session_cache {
                    if let Some(entry) = cache.find(&server_session_id) {
                        // キャッシュからmaster_secretを復元
                        self.master_secret = entry.master_secret;
                        self.resuming_session = true;
                        self.state = TlsState::WaitFinishedResumed;
                        return Ok(());
                    }
                }
            }
            // フルハンドシェイク時もserver session_idを保存
            if session_id_len == 32 {
                self.session_id = SessionId::new(server_session_id);
            }
            self.state = TlsState::ServerHelloReceived;
        }

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
            super::ecdh::EcdhGroup::X25519
        };

        if let Ok(new_keypair) = super::ecdh::EcdhKeyPair::generate(group) {
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
        if let Some(cert) = super::x509::parse_x509(first_cert_der) {
            match cert.subject_public_key_info {
                super::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                    self.server_public_key = Some(ServerPublicKey::Rsa {
                        modulus: modulus.to_vec(),
                        exponent: exponent.to_vec(),
                    });
                }
                super::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                    self.server_public_key = Some(ServerPublicKey::EcdsaP256 {
                        point: public_key.to_vec(),
                    });
                }
                super::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
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

    /// ServerKeyExchangeを処理
    ///
    /// ECDHEの場合、サーバー公開鍵を受け取り、クライアント側で
    /// 一時鍵ペアを生成してECDH共有秘密を計算する。
    fn process_server_key_exchange(&mut self, data: &[u8]) -> TlsResult<()> {
        // ECDHEフォーマット（RFC 4492 Section 5.4）:
        // - curve_type (1 byte): 0x03 = named_curve
        // - named_curve (2 bytes)
        // - public_key_length (1 byte)
        // - public_key (variable)
        // - signature_algorithm (2 bytes) — TLS 1.2
        // - signature_length (2 bytes)
        // - signature (variable)

        if data.len() < 4 {
            return Err(TlsError::DecodeError);
        }

        let curve_type = data[0];
        if curve_type != 0x03 {
            // named_curveのみサポート
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

            match sig_algorithm {
                // RSA-PKCS1-SHA256 (0x0401)
                0x0401 => {
                    let digest = crate::loader::sha256::compute(&signed_data);
                    let pubkey = match &self.server_public_key {
                        Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                            super::rsa::RsaPublicKey { modulus, exponent }
                        }
                        _ => return Err(TlsError::CertificateError),
                    };
                    super::rsa::rsa_pkcs1_verify(
                        &pubkey,
                        super::rsa::HashAlgorithm::Sha256,
                        &digest,
                        signature,
                    )
                    .map_err(|_| TlsError::CryptoError)?;
                }
                // RSA-PKCS1-SHA384 (0x0501)
                0x0501 => {
                    let digest = crate::loader::sha384::compute(&signed_data);
                    let pubkey = match &self.server_public_key {
                        Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                            super::rsa::RsaPublicKey { modulus, exponent }
                        }
                        _ => return Err(TlsError::CertificateError),
                    };
                    super::rsa::rsa_pkcs1_verify(
                        &pubkey,
                        super::rsa::HashAlgorithm::Sha384,
                        &digest,
                        signature,
                    )
                    .map_err(|_| TlsError::CryptoError)?;
                }
                // ECDSA-SECP256R1-SHA256 (0x0403)
                0x0403 => {
                    let digest = crate::loader::sha256::compute(&signed_data);
                    let pubkey_bytes = match &self.server_public_key {
                        Some(ServerPublicKey::EcdsaP256 { point }) => point.as_slice(),
                        _ => return Err(TlsError::CertificateError),
                    };
                    super::ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
                        .map_err(|_| TlsError::CryptoError)?;
                }
                // RSA-PKCS1-SHA1 (0x0201) — レガシー互換
                0x0201 => {
                    // SHA-1は未実装、skip
                }
                _ => {
                    return Err(TlsError::UnsupportedCipherSuite);
                }
            }
        }

        // NamedGroup → EcdhGroup マッピング
        use super::ecdh::{EcdhGroup, EcdhKeyPair};
        let group = match named_curve {
            0x0017 => EcdhGroup::Secp256r1,
            0x001D => EcdhGroup::X25519,
            _ => return Err(TlsError::UnsupportedCipherSuite),
        };

        // クライアント一時鍵ペア生成 + ECDH共有秘密計算
        let local_keypair =
            EcdhKeyPair::generate(group).map_err(|_| TlsError::CryptoError)?;
        let shared_secret = local_keypair
            .shared_secret(server_pubkey)
            .map_err(|_| TlsError::CryptoError)?;

        // ClientKeyExchange送信用に鍵ペアを保存
        self.local_ecdh_keypair = Some(local_keypair);

        // pre_master_secret = ECDH共有秘密
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

    /// TLS 1.2 クライアントFinishedメッセージを構築
    ///
    /// RFC 5246 Section 7.4.9:
    /// verify_data = PRF(master_secret, "client finished",
    ///                    Hash(handshake_messages))[0..11]
    ///
    /// Finishedメッセージは暗号化して送信する。
    /// `build_change_cipher_spec()` の後に呼び出し、鍵が有効な状態で使用する。
    pub fn build_client_finished_tls12(&mut self) -> TlsResult<Vec<u8>> {
        if self.is_tls13 {
            return Err(TlsError::UnexpectedMessage);
        }

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        // Master secretが設定されていない場合は鍵導出
        if self.master_secret.iter().all(|&b| b == 0) {
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

        // ハンドシェイクメッセージのハッシュ（バージョンに応じたハッシュ関数）
        let handshake_hash = if cipher.uses_sha384() {
            crate::loader::sha384::compute(&self.handshake_messages).to_vec()
        } else {
            crate::loader::sha256::compute(&self.handshake_messages).to_vec()
        };

        // verify_data = PRF(master_secret, "client finished", Hash(...))[0..12]
        let mut verify_data = [0u8; 12];
        if version <= TlsVersion::TLS_1_1 {
            tls10_prf(
                &self.master_secret,
                b"client finished",
                &handshake_hash,
                &mut verify_data,
            );
        } else if cipher.uses_sha384() {
            tls12_prf_sha384(
                &self.master_secret,
                b"client finished",
                &handshake_hash,
                &mut verify_data,
            );
        } else {
            tls12_prf(
                &self.master_secret,
                b"client finished",
                &handshake_hash,
                &mut verify_data,
            );
        }

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
        let encrypted_record = if cipher.is_cbc() {
            self.encrypt_cbc_handshake(&finished_msg)?
        } else if cipher.is_chacha20_poly1305() {
            self.encrypt_chacha20_poly1305_handshake(&finished_msg)?
        } else {
            self.encrypt_aes_gcm_handshake(&finished_msg)?
        };

        Ok(encrypted_record)
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

    /// CBCレコード復号 (Decrypt-then-Verify-MAC)
    ///
    /// RFC 5246 Section 6.2.3.2 (復号側):
    /// 1. CBC復号してパディング付き平文を得る
    /// 2. パディング検証
    /// 3. MACを分離して検証
    fn decrypt_cbc_record(&mut self, data: &[u8], content_type: u8) -> TlsResult<Vec<u8>> {
        if self.read_key.is_empty() {
            return Err(TlsError::CryptoError);
        }

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        let use_sha1 = cipher.uses_sha1_mac();
        let mac_len = cipher.mac_len();

        // Step 1: IV と暗号文を分離
        let (iv, ciphertext) = if version >= TlsVersion::TLS_1_1 {
            // TLS 1.1+: 先頭16バイトが明示的IV
            if data.len() < 16 {
                return Err(TlsError::DecodeError);
            }
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&data[..16]);
            (iv, &data[16..])
        } else {
            // TLS 1.0: 暗黙IV
            let iv = self.last_read_ciphertext_block.unwrap_or(self.read_cbc_iv);
            (iv, data)
        };

        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(TlsError::DecryptError);
        }

        // TLS 1.0: 最終暗号文ブロック記憶
        if version == TlsVersion::TLS_1_0 && ciphertext.len() >= 16 {
            let mut last_block = [0u8; 16];
            last_block.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
            self.last_read_ciphertext_block = Some(last_block);
        }

        // Step 2: CBC復号
        let decrypted = aes_cbc_decrypt(&self.read_key, &iv, ciphertext)
            .ok_or(TlsError::DecryptError)?;

        // Step 3: パディング検証 (定時間)
        let content_len = tls_verify_padding(&decrypted)
            .ok_or(TlsError::BadRecordMac)?;

        // Step 4: MAC分離と検証
        if content_len < mac_len {
            return Err(TlsError::BadRecordMac);
        }

        let fragment_len = content_len - mac_len;
        let fragment = &decrypted[..fragment_len];
        let received_mac = &decrypted[fragment_len..content_len];

        // 期待されるMACを計算
        let expected_mac = compute_tls_mac(
            &self.read_mac_key,
            self.read_seq,
            content_type,
            version,
            fragment,
            use_sha1,
        );

        // 定時間比較
        let mut diff = 0u8;
        for i in 0..mac_len.min(expected_mac.len()).min(received_mac.len()) {
            diff |= received_mac[i] ^ expected_mac[i];
        }
        if diff != 0 || received_mac.len() != expected_mac.len() {
            return Err(TlsError::BadRecordMac);
        }

        self.read_seq += 1;
        Ok(fragment.to_vec())
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
        let rsa_key = super::rsa::RsaPublicKey { modulus, exponent };
        let encrypted_pms = super::rsa::rsa_pkcs1_encrypt(&rsa_key, &pms).ok()?;

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

            // トランスクリプトハッシュを更新
            // (Finishedメッセージ自体もトランスクリプトに含める)
            if let Some(ref mut hasher) = self.transcript_hash {
                hasher.update(full_msg);
            }
            self.handshake_messages.extend_from_slice(full_msg);

            offset = body_end;
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
            if !self.config.skip_verify {
                return Err(TlsError::CertificateError);
            }
            self.state = TlsState::Tls13WaitCertificateVerify;
            return Ok(());
        }

        // 証明書リストをパース
        let cert_list = &data[offset + 3..offset + 3 + certs_len];
        let mut pos = 0usize;

        // 最初の証明書（エンドエンティティ）を抽出
        if cert_list.len() < pos + 3 {
            return Err(TlsError::DecodeError);
        }

        let first_cert_len = ((cert_list[pos] as usize) << 16)
            | ((cert_list[pos + 1] as usize) << 8)
            | cert_list[pos + 2] as usize;
        pos += 3;

        if cert_list.len() < pos + first_cert_len {
            return Err(TlsError::DecodeError);
        }

        let first_cert_der = &cert_list[pos..pos + first_cert_len];
        pos += first_cert_len;

        // TLS 1.3 CertificateEntry: cert_data の後に extensions(2+) が続く
        if cert_list.len() >= pos + 2 {
            let ext_len =
                ((cert_list[pos] as usize) << 8) | cert_list[pos + 1] as usize;
            // extensions をスキップ
            let _ = ext_len;
        }

        // X.509 DERパースしてサーバー公開鍵を抽出
        if let Some(cert) = super::x509::parse_x509(first_cert_der) {
            match cert.subject_public_key_info {
                super::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                    self.server_public_key = Some(ServerPublicKey::Rsa {
                        modulus: modulus.to_vec(),
                        exponent: exponent.to_vec(),
                    });
                }
                super::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                    self.server_public_key = Some(ServerPublicKey::EcdsaP256 {
                        point: public_key.to_vec(),
                    });
                }
                super::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
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
                    super::rsa::HashAlgorithm::Sha256,
                )?;
            }
            // RSA-PKCS1-SHA384 (0x0501)
            0x0501 => {
                self.verify_rsa_pkcs1_signature(
                    &verify_content,
                    signature,
                    super::rsa::HashAlgorithm::Sha384,
                )?;
            }
            // RSA-PSS-RSAE-SHA256 (0x0804)
            0x0804 => {
                // RSA-PSSは現在PKCS#1 v1.5にフォールバック
                // 完全なPSS実装は将来追加
                self.verify_rsa_pkcs1_signature(
                    &verify_content,
                    signature,
                    super::rsa::HashAlgorithm::Sha256,
                ).or_else(|_| {
                    // PSS検証が必要な場合、skip_verifyでなければエラー
                    Err(TlsError::CryptoError)
                })?;
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
        hash_alg: super::rsa::HashAlgorithm,
    ) -> TlsResult<()> {
        let pubkey = match &self.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                super::rsa::RsaPublicKey {
                    modulus,
                    exponent,
                }
            }
            _ => return Err(TlsError::CertificateError),
        };

        let digest = match hash_alg {
            super::rsa::HashAlgorithm::Sha256 => {
                let h = crate::loader::sha256::compute(message);
                h.to_vec()
            }
            super::rsa::HashAlgorithm::Sha384 => {
                let h = crate::loader::sha384::compute(message);
                h.to_vec()
            }
        };

        super::rsa::rsa_pkcs1_verify(&pubkey, hash_alg, &digest, signature)
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

        super::ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
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

        super::ecdh::p384::ecdsa_p384_verify(pubkey_bytes, &digest, signature)
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

    /// TLS 1.3: クライアントFinishedメッセージを構築
    ///
    /// サーバーFinished受信後に呼び出す。
    /// アプリケーション鍵の導出も同時に行う。
    pub fn build_client_finished_tls13(&mut self) -> TlsResult<Vec<u8>> {
        if !self.is_tls13 || self.state != TlsState::Tls13ServerFinishedReceived {
            return Err(TlsError::UnexpectedMessage);
        }

        let mut records = Vec::new();

        // EndOfEarlyData (RFC 8446 Section 4.5)
        // Early Dataを送信し、サーバーが受理した場合のみ送信
        // EndOfEarlyData は early data 鍵で暗号化する
        if self.early_data_sent && self.early_data_accepted {
            // handshake type 5 (end_of_early_data), length 0
            let eoed_msg: [u8; 4] = [5, 0, 0, 0];

            // トランスクリプトハッシュに記録
            if let Some(ref mut hasher) = self.transcript_hash {
                hasher.update(&eoed_msg);
            }
            self.handshake_messages.extend_from_slice(&eoed_msg);

            // Early Data鍵で暗号化
            if !self.early_write_key.is_empty() && self.early_write_iv.len() >= 12 {
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
                records.extend_from_slice(&eoed_record);
            }
        }

        // 空Certificate送信 (RFC 8446 Section 4.4.2)
        // サーバーがCertificateRequestを送信した場合、
        // クライアント証明書がなくても空のCertificateメッセージを送る必要がある
        if self.client_auth_requested {
            let ctx = &self.certificate_request_context;
            let ctx_len = ctx.len();
            // Certificate body: context_length(1) + context + cert_list_length(3, value=0)
            let cert_body_len = 1 + ctx_len + 3;
            let mut cert_msg = Vec::with_capacity(4 + cert_body_len);
            cert_msg.push(11); // Certificate type
            cert_msg.push(0);
            cert_msg.push(((cert_body_len >> 8) & 0xFF) as u8);
            cert_msg.push((cert_body_len & 0xFF) as u8);
            cert_msg.push(ctx_len as u8);
            cert_msg.extend_from_slice(ctx);
            cert_msg.extend_from_slice(&[0, 0, 0]); // empty certificate_list (length = 0)

            // トランスクリプトハッシュに記録
            if let Some(ref mut hasher) = self.transcript_hash {
                hasher.update(&cert_msg);
            }
            self.handshake_messages.extend_from_slice(&cert_msg);

            // ハンドシェイク鍵で暗号化
            let mut inner_cert = cert_msg;
            inner_cert.push(ContentType::Handshake as u8);
            let encrypted_cert = self.tls13_encrypt_record(&inner_cert, true)?;
            records.extend_from_slice(&encrypted_cert);

            // CertificateVerifyはスキップ（クライアント秘密鍵未実装）
            // 空のcertificate_listの場合、CertificateVerifyは送信してはならない (RFC 8446 4.4.2)
        }

        let use_384 = self.negotiated_cipher.map_or(false, |c| c.uses_sha384());
        let hash_len = self.hash_len();

        // クライアントFinished verify_data を計算
        let verify_data_vec: Vec<u8> = if use_384 {
            let transcript = crate::loader::sha384::compute(&self.handshake_messages);
            let mut chs = [0u8; 48];
            chs.copy_from_slice(&self.client_hs_traffic_secret[..48]);
            let finished_key = tls13_finished_key_sha384(&chs);
            let vd = tls13_verify_data_sha384(&finished_key, &transcript);
            vd.to_vec()
        } else {
            let transcript = {
                let mut hasher = crate::loader::sha256::Sha256::new();
                hasher.update(&self.handshake_messages);
                hasher.finalize()
            };
            let mut chs = [0u8; 32];
            chs.copy_from_slice(&self.client_hs_traffic_secret[..32]);
            let finished_key = tls13_finished_key(&chs);
            let vd = tls13_verify_data(&finished_key, &transcript);
            vd.to_vec()
        };

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
        // inner: finished_msg + content_type(Handshake=22)
        let mut inner = finished_msg;
        inner.push(ContentType::Handshake as u8);

        let encrypted = self.tls13_encrypt_record(&inner, true)?;

        // アプリケーション鍵の導出
        self.tls13_derive_application_keys()?;

        // EndOfEarlyDataレコード + Finishedレコードを結合して返す
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
        // handshake_messages からクライアントFinished分を除外
        let client_finished_len = 4 + hash_len;
        let msgs_before_cf =
            &self.handshake_messages[..self.handshake_messages.len() - client_finished_len];

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

        let version = self.negotiated_version.unwrap_or(TlsVersion::TLS_1_2);
        let cipher = self.negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        // Master secretが未導出の場合は導出
        if self.master_secret.iter().all(|&b| b == 0) && !self.pre_master_secret.is_empty() {
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

        // Finished メッセージ自体を除いたハンドシェイクメッセージのハッシュ
        let handshake_hash = if cipher.uses_sha384() {
            crate::loader::sha384::compute(&self.handshake_messages).to_vec()
        } else {
            crate::loader::sha256::compute(&self.handshake_messages).to_vec()
        };

        // expected verify_data = PRF(master_secret, "server finished", Hash(...))
        let mut expected_verify_data = [0u8; 12];
        if version <= TlsVersion::TLS_1_1 {
            tls10_prf(
                &self.master_secret,
                b"server finished",
                &handshake_hash,
                &mut expected_verify_data,
            );
        } else if cipher.uses_sha384() {
            tls12_prf_sha384(
                &self.master_secret,
                b"server finished",
                &handshake_hash,
                &mut expected_verify_data,
            );
        } else {
            tls12_prf(
                &self.master_secret,
                b"server finished",
                &handshake_hash,
                &mut expected_verify_data,
            );
        }

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

        // フルハンドシェイク完了後、セッションをキャッシュに保存（略式ハンドシェイク時は不要）
        if !self.resuming_session && self.session_id.0 != [0u8; 32] {
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
    fn tls13_strip_content_type(decrypted: &[u8]) -> Option<&[u8]> {
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

        // 拡張をパース（max_early_data_size 等）
        let mut max_early_data_size: u32 = 0;
        if data.len() >= off + 2 {
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
                    // early_data (type 42): max_early_data_size
                    max_early_data_size = u32::from_be_bytes([
                        data[eoff], data[eoff + 1], data[eoff + 2], data[eoff + 3],
                    ]);
                }
                eoff += ext_len;
            }
        }
        self.max_early_data_size = max_early_data_size;

        // セッションチケットをストレージに保存
        self.session_ticket = Some(SessionTicket {
            lifetime: ticket_lifetime,
            age_add: ticket_age_add,
            nonce: ticket_nonce.to_vec(),
            ticket: ticket.to_vec(),
        });

        // PSK (Pre-Shared Key) の導出 (RFC 8446 Section 4.6.1)
        // PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, hash_len)
        if !self.resumption_master_secret.is_empty() {
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
}

// ============================================================================
// Errors
// ============================================================================

/// TLSエラー
#[derive(Clone, Copy, Debug)]
pub enum TlsError {
    /// 接続されていない
    NotConnected,
    /// 予期しないメッセージ
    UnexpectedMessage,
    /// デコードエラー
    DecodeError,
    /// 暗号化エラー
    CryptoError,
    /// 証明書エラー
    CertificateError,
    /// ハンドシェイク失敗
    HandshakeFailure,
    /// アラート
    Alert(u8),
    /// バージョン不一致
    VersionMismatch,
    /// 暗号スイート不一致
    CipherSuiteMismatch,
    /// サポートされていない暗号スイート
    UnsupportedCipherSuite,
    /// 復号エラー
    DecryptError,
    /// MACまたはパディング不正 (bad_record_mac alert)
    BadRecordMac,
}

pub type TlsResult<T> = Result<T, TlsError>;

// ============================================================================
// AES-GCM Implementation
// ============================================================================

/// AES-128 Sbox
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES Rcon (round constants)
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES-128キー展開
fn aes_key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys = [[0u8; 16]; 11];
    round_keys[0].copy_from_slice(key);

    for i in 1..11 {
        // 前のラウンドキーをコピーして借用問題を回避
        let prev = round_keys[i - 1];
        let mut temp = [prev[12], prev[13], prev[14], prev[15]];

        // RotWord
        temp.rotate_left(1);

        // SubWord
        for b in &mut temp {
            *b = AES_SBOX[*b as usize];
        }

        // XOR with Rcon
        temp[0] ^= RCON[i - 1];

        for j in 0..4 {
            for k in 0..4 {
                round_keys[i][j * 4 + k] = if j == 0 {
                    prev[k] ^ temp[k]
                } else {
                    prev[j * 4 + k] ^ round_keys[i][(j - 1) * 4 + k]
                };
            }
        }
    }

    round_keys
}

/// GF(2^8) 乗算
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    result
}

/// AES SubBytes
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// AES ShiftRows
fn aes_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    // Row 0: no shift
    // Row 1: shift left by 1
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    // Row 2: shift left by 2
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    // Row 3: shift left by 3
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

/// AES MixColumns
fn aes_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[i + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

/// AES AddRoundKey
fn aes_add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(round_key.iter()) {
        *s ^= *k;
    }
}

/// AES-128 ブロック暗号化
fn aes_encrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *block;

    // Initial round
    aes_add_round_key(&mut state, &round_keys[0]);

    // Main rounds
    for i in 1..10 {
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &round_keys[i]);
    }

    // Final round (no MixColumns)
    aes_sub_bytes(&mut state);
    aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &round_keys[10]);

    state
}

/// Expanded AES key schedule supporting AES-128/AES-256.
#[derive(Clone, Copy)]
struct AesRoundKeySchedule {
    /// Round keys (maximum needed by AES-256 = 15 keys)
    round_keys: [[u8; 16]; 15],
    /// Number of rounds (10 for AES-128, 14 for AES-256)
    rounds: usize,
}

/// Expand AES key schedule for AES-128 (16-byte key) or AES-256 (32-byte key).
fn aes_expand_key_schedule(key: &[u8]) -> Option<AesRoundKeySchedule> {
    let nk = match key.len() {
        16 => 4, // AES-128
        32 => 8, // AES-256
        _ => return None,
    };

    let nr = nk + 6; // 10 (AES-128) or 14 (AES-256)
    let total_words = 4 * (nr + 1); // 44 or 60

    let mut words = [[0u8; 4]; 60];
    for i in 0..nk {
        let base = i * 4;
        words[i].copy_from_slice(&key[base..base + 4]);
    }

    for i in nk..total_words {
        let mut temp = words[i - 1];

        if i % nk == 0 {
            temp.rotate_left(1); // RotWord
            for b in &mut temp {
                *b = AES_SBOX[*b as usize]; // SubWord
            }
            temp[0] ^= RCON[(i / nk) - 1];
        } else if nk > 6 && i % nk == 4 {
            // AES-256 additional SubWord step
            for b in &mut temp {
                *b = AES_SBOX[*b as usize];
            }
        }

        for j in 0..4 {
            words[i][j] = words[i - nk][j] ^ temp[j];
        }
    }

    let mut round_keys = [[0u8; 16]; 15];
    for round in 0..=nr {
        for word_idx in 0..4 {
            let word = words[round * 4 + word_idx];
            let start = word_idx * 4;
            round_keys[round][start..start + 4].copy_from_slice(&word);
        }
    }

    Some(AesRoundKeySchedule {
        round_keys,
        rounds: nr,
    })
}

/// Encrypt one AES block using a pre-expanded key schedule.
fn aes_encrypt_block_with_schedule(block: &[u8; 16], schedule: &AesRoundKeySchedule) -> [u8; 16] {
    let mut state = *block;

    aes_add_round_key(&mut state, &schedule.round_keys[0]);

    for i in 1..schedule.rounds {
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &schedule.round_keys[i]);
    }

    aes_sub_bytes(&mut state);
    aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &schedule.round_keys[schedule.rounds]);

    state
}

/// AES-CTR with pre-expanded schedule.
fn aes_ctr_with_schedule(schedule: &AesRoundKeySchedule, nonce: &[u8], data: &[u8]) -> Vec<u8> {
    if nonce.len() != 12 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(data.len());
    let mut counter_block = [0u8; 16];
    counter_block[0..12].copy_from_slice(nonce);

    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let counter = (chunk_idx as u32 + 1).to_be_bytes();
        counter_block[12..16].copy_from_slice(&counter);

        let keystream = aes_encrypt_block_with_schedule(&counter_block, schedule);

        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
    }

    result
}

/// AES-CTR モードでの暗号化/復号
fn aes_ctr(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let Some(schedule) = aes_expand_key_schedule(key) else {
        return Vec::new();
    };
    aes_ctr_with_schedule(&schedule, nonce, data)
}

/// GCM GHASH演算
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }

    // Process ciphertext
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }

    // Process length block
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());

    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    y = gf128_mul(&y, h);

    y
}

/// GF(2^128) 乗算 (GHASH用)
fn gf128_mul(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *h;

    for i in 0..128 {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);

        if (x[byte_idx] >> bit_idx) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }

        // V = V >> 1 in GF(2^128)
        let lsb = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;

        if lsb == 1 {
            v[0] ^= 0xe1; // R = 0xe1 << 120
        }
    }

    z
}

/// AES-GCM 暗号化
fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    if nonce.len() != 12 {
        return (Vec::new(), [0u8; 16]);
    }

    let Some(schedule) = aes_expand_key_schedule(key) else {
        return (Vec::new(), [0u8; 16]);
    };

    // Generate H = AES(K, 0^128)
    let h = aes_encrypt_block_with_schedule(&[0u8; 16], &schedule);

    // Encrypt plaintext with CTR mode
    let ciphertext = aes_ctr_with_schedule(&schedule, nonce, plaintext);

    // Calculate GHASH
    let s = ghash(&h, aad, &ciphertext);

    // Calculate tag: T = GHASH XOR AES(K, Y0)
    let mut y0 = [0u8; 16];
    y0[0..12].copy_from_slice(nonce);
    y0[15] = 1; // Counter = 1
    let encrypted_y0 = aes_encrypt_block_with_schedule(&y0, &schedule);

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ encrypted_y0[i];
    }

    (ciphertext, tag)
}

/// AES-GCM 復号
fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }

    let schedule = aes_expand_key_schedule(key)?;

    // Generate H
    let h = aes_encrypt_block_with_schedule(&[0u8; 16], &schedule);

    // Calculate expected tag
    let s = ghash(&h, aad, ciphertext);

    let mut y0 = [0u8; 16];
    y0[0..12].copy_from_slice(nonce);
    y0[15] = 1;
    let encrypted_y0 = aes_encrypt_block_with_schedule(&y0, &schedule);

    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = s[i] ^ encrypted_y0[i];
    }

    // Verify tag (constant-time comparison)
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }

    if diff != 0 {
        return None; // Authentication failed
    }

    // Decrypt
    let plaintext = aes_ctr_with_schedule(&schedule, nonce, ciphertext);
    Some(plaintext)
}

// ============================================================================
// HMAC-SHA256 (RFC 2104)
// ============================================================================

/// SHA-256 block size in bytes
const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-256 output size in bytes
const SHA256_OUTPUT_SIZE: usize = 32;

/// HMAC-SHA256 (RFC 2104)
///
/// Computes HMAC using SHA-256 as the underlying hash function.
/// Used as the foundation for TLS PRF and HKDF.
///
/// # Arguments
/// * `key` - HMAC key (any length; keys > 64 bytes are first hashed)
/// * `data` - Message to authenticate
///
/// # Returns
/// 32-byte MAC value
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_OUTPUT_SIZE] {
    use crate::loader::sha256;

    // Step 1: If key > block size, hash it to get a shorter key
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > SHA256_BLOCK_SIZE {
        hashed_key = sha256::compute(key);
        &hashed_key
    } else {
        key
    };

    // Step 2: Pad key to block size, XOR with ipad/opad
    let mut ipad = [0x36u8; SHA256_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA256_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    // Step 3: Inner hash = SHA-256(ipad || data)
    let mut inner_hasher = sha256::Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Step 4: Outer hash = SHA-256(opad || inner_hash)
    let mut outer_hasher = sha256::Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// SHA-384 block size in bytes (SHA-384 uses SHA-512 internals)
const SHA384_BLOCK_SIZE: usize = 128;

/// SHA-384 output size in bytes
const SHA384_OUTPUT_SIZE: usize = 48;

/// HMAC-SHA384 (RFC 2104)
///
/// Computes HMAC using SHA-384 as the underlying hash function.
/// Used for TLS 1.2 PRF when negotiating AES-256-GCM-SHA384 cipher suites.
///
/// # Arguments
/// * `key` - HMAC key (any length; keys > 128 bytes are first hashed)
/// * `data` - Message to authenticate
///
/// # Returns
/// 48-byte MAC value
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; SHA384_OUTPUT_SIZE] {
    use crate::loader::sha384;

    // Step 1: If key > block size, hash it to get a shorter key
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > SHA384_BLOCK_SIZE {
        hashed_key = sha384::compute(key);
        &hashed_key
    } else {
        key
    };

    // Step 2: Pad key to block size, XOR with ipad/opad
    let mut ipad = [0x36u8; SHA384_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA384_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    // Step 3: Inner hash = SHA-384(ipad || data)
    let mut inner_hasher = sha384::Sha384::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Step 4: Outer hash = SHA-384(opad || inner_hash)
    let mut outer_hasher = sha384::Sha384::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

// ============================================================================
// Random Generation (RDRAND Hardware RNG)
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering as AtomicOrdering};
#[cfg(feature = "qemu-test-export")]
use core::sync::atomic::AtomicU64;

/// Whether RDRAND availability has been checked
static RDRAND_CHECKED: AtomicBool = AtomicBool::new(false);
/// 0 = unknown, 1 = available, 2 = not available
static RDRAND_STATUS: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_RANDOM_OVERRIDE_ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_RANDOM_OVERRIDE_SEED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_RANDOM_OVERRIDE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_random_override_seed(seed: u64) {
    QEMU_TEST_RANDOM_OVERRIDE_SEED.store(seed, AtomicOrdering::Release);
    QEMU_TEST_RANDOM_OVERRIDE_COUNTER.store(0, AtomicOrdering::Release);
    QEMU_TEST_RANDOM_OVERRIDE_ENABLED.store(true, AtomicOrdering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_random_override() {
    QEMU_TEST_RANDOM_OVERRIDE_ENABLED.store(false, AtomicOrdering::Release);
    QEMU_TEST_RANDOM_OVERRIDE_COUNTER.store(0, AtomicOrdering::Release);
}

#[cfg(feature = "qemu-test-export")]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(feature = "qemu-test-export")]
fn generate_qemu_test_random() -> [u8; 32] {
    let seed = QEMU_TEST_RANDOM_OVERRIDE_SEED.load(AtomicOrdering::Acquire);
    let call_index = QEMU_TEST_RANDOM_OVERRIDE_COUNTER.fetch_add(1, AtomicOrdering::AcqRel);

    let mut result = [0u8; 32];
    for (chunk_index, chunk) in result.chunks_exact_mut(8).enumerate() {
        let input = seed
            .wrapping_add(call_index)
            .wrapping_add(chunk_index as u64);
        let mixed = splitmix64(input);
        chunk.copy_from_slice(&mixed.to_ne_bytes());
    }
    result
}


/// Check if the CPU supports RDRAND via CPUID
fn has_rdrand() -> bool {
    let status = RDRAND_STATUS.load(AtomicOrdering::Relaxed);
    if RDRAND_CHECKED.load(AtomicOrdering::Acquire) {
        return status == 1;
    }

    // CPUID leaf 1, ECX bit 30 = RDRAND support
    let available = {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid = core::arch::x86_64::__cpuid(1);
            ((cpuid.ecx >> 30) & 1) == 1
        }

        #[cfg(target_arch = "x86")]
        {
            let cpuid = core::arch::x86::__cpuid(1);
            ((cpuid.ecx >> 30) & 1) == 1
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            false
        }
    };

    RDRAND_STATUS.store(if available { 1 } else { 2 }, AtomicOrdering::Relaxed);
    RDRAND_CHECKED.store(true, AtomicOrdering::Release);
    available
}

/// Generate a 64-bit random value using RDRAND
///
/// Retries up to 10 times on transient failures.
fn rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let value: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) value,
                ok = out(reg_byte) success,
            );
        }
        if success != 0 {
            return Some(value);
        }
    }
    None
}

/// Generate 32 bytes of random data
///
/// Uses RDRAND hardware instruction when available (x86_64).
/// Falls back to a weak LCG for development/boot environments where
/// RDRAND is not yet available. The LCG fallback MUST NOT be used
/// for production cryptographic operations.
pub(crate) fn generate_random() -> [u8; 32] {
    #[cfg(feature = "qemu-test-export")]
    {
        if QEMU_TEST_RANDOM_OVERRIDE_ENABLED.load(AtomicOrdering::Acquire) {
            return generate_qemu_test_random();
        }
    }

    let mut result = [0u8; 32];

    if has_rdrand() {
        // Fill 32 bytes using 4 RDRAND calls (8 bytes each)
        for chunk in result.chunks_exact_mut(8) {
            if let Some(val) = rdrand64() {
                chunk.copy_from_slice(&val.to_ne_bytes());
            } else {
                // RDRAND failed after retries — fall through to LCG
                return generate_random_fallback();
            }
        }
        return result;
    }

    generate_random_fallback()
}

/// Fallback LCG-based random generation (development/boot only)
///
/// WARNING: This is NOT cryptographically secure. It exists only as a
/// fallback for environments where RDRAND is unavailable.
fn generate_random_fallback() -> [u8; 32] {
    static mut SEED: u64 = 0x1234567890abcdef;
    let mut result = [0u8; 32];

    unsafe {
        for byte in result.iter_mut() {
            SEED = SEED
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (SEED >> 56) as u8;
        }
    }

    result
}

// ============================================================================
// TLS 1.2 PRF (RFC 5246 Section 5)
// ============================================================================

/// P_SHA256 expansion function (RFC 5246 Section 5)
///
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                         HMAC_hash(secret, A(2) + seed) + ...
/// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
fn p_sha256(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha256(secret, seed); // A(1)
    let mut offset = 0;

    while offset < output.len() {
        // HMAC_hash(secret, A(i) + seed)
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let block = hmac_sha256(secret, &a_seed);

        let copy_len = (output.len() - offset).min(SHA256_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC_hash(secret, A(i))
        a = hmac_sha256(secret, &a);
    }
}

/// TLS 1.2 PRF using SHA-256 (RFC 5246 Section 5)
///
/// PRF(secret, label, seed) = P_SHA256(secret, label + seed)
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    p_sha256(secret, &combined_seed, output);
}

/// Derive TLS 1.2 master secret (RFC 5246 Section 8.1)
///
/// master_secret = PRF(pre_master_secret, "master secret",
///                      ClientHello.random + ServerHello.random)[0..47]
pub fn derive_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    tls12_prf(
        pre_master_secret,
        b"master secret",
        &seed,
        &mut master_secret,
    );
    master_secret
}

/// Derive TLS 1.2 key block (RFC 5246 Section 6.3)
///
/// key_block = PRF(SecurityParameters.master_secret, "key expansion",
///                  SecurityParameters.server_random +
///                  SecurityParameters.client_random)
pub fn derive_key_block(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let mut key_block = vec![0u8; key_material_len];
    tls12_prf(master_secret, b"key expansion", &seed, &mut key_block);
    key_block
}

/// Derive TLS 1.2 SHA-384 key block
pub fn derive_key_block_sha384(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let mut key_block = vec![0u8; key_material_len];
    tls12_prf_sha384(master_secret, b"key expansion", &seed, &mut key_block);
    key_block
}

/// Derive TLS 1.0/1.1 master secret (RFC 2246 Section 8.1)
///
/// デュアルハッシュPRFを使用する。
pub fn derive_master_secret_tls10(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    tls10_prf(
        pre_master_secret,
        b"master secret",
        &seed,
        &mut master_secret,
    );
    master_secret
}

/// Derive TLS 1.2 SHA-384 master secret
pub fn derive_master_secret_sha384(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);

    let mut master_secret = [0u8; 48];
    tls12_prf_sha384(
        pre_master_secret,
        b"master secret",
        &seed,
        &mut master_secret,
    );
    master_secret
}

// ============================================================================
// HKDF-SHA256 (RFC 5869)
// ============================================================================

/// HKDF-Extract (RFC 5869 Section 2.2)
///
/// PRK = HMAC-Hash(salt, IKM)
///
/// If salt is empty, a zero-filled key of HashLen bytes is used.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_OUTPUT_SIZE] {
    let effective_salt = if salt.is_empty() {
        &[0u8; SHA256_OUTPUT_SIZE] as &[u8]
    } else {
        salt
    };
    hmac_sha256(effective_salt, ikm)
}

/// HKDF-Expand (RFC 5869 Section 2.3)
///
/// OKM = T(1) || T(2) || ... || T(N)
/// T(0) = empty string
/// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
///
/// # Panics
/// Panics if length > 255 * HashLen (8160 bytes for SHA-256)
pub fn hkdf_expand(prk: &[u8; SHA256_OUTPUT_SIZE], info: &[u8], length: usize) -> Vec<u8> {
    assert!(
        length <= 255 * SHA256_OUTPUT_SIZE,
        "HKDF-Expand: requested length too large"
    );

    let n = (length + SHA256_OUTPUT_SIZE - 1) / SHA256_OUTPUT_SIZE;
    let mut okm = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new(); // T(0) = empty

    for i in 1..=n {
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        input.push(i as u8);

        let t_i = hmac_sha256(prk, &input);

        let copy_len = (length - okm.len()).min(SHA256_OUTPUT_SIZE);
        okm.extend_from_slice(&t_i[..copy_len]);

        t_prev = t_i.to_vec();
    }

    okm
}

/// HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1)
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// where HkdfLabel = struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// }
pub fn hkdf_expand_label(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    // Construct HkdfLabel
    let tls_label_prefix = b"tls13 ";
    let full_label_len = tls_label_prefix.len() + label.len();

    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());

    // uint16 length
    hkdf_label.push((length >> 8) as u8);
    hkdf_label.push(length as u8);

    // opaque label<7..255>
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(tls_label_prefix);
    hkdf_label.extend_from_slice(label);

    // opaque context<0..255>
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand(secret, &hkdf_label, length)
}

// ============================================================================
// TLS 1.3 Key Schedule (RFC 8446 Section 7.1)
// ============================================================================

/// Derive-Secret (RFC 8446 Section 7.1)
///
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
///
/// `transcript_hash` は Messages のSHA-256ハッシュ値。
pub fn tls13_derive_secret(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    label: &[u8],
    transcript_hash: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    let result = hkdf_expand_label(secret, label, transcript_hash, SHA256_OUTPUT_SIZE);
    let mut output = [0u8; SHA256_OUTPUT_SIZE];
    output.copy_from_slice(&result);
    output
}

/// TLS 1.3 鍵スケジュール: Early Secret を導出
///
/// Early Secret = HKDF-Extract(salt=0, IKM=PSK)
/// PSKなしの場合 IKM = ゼロ（32バイト）
pub fn tls13_early_secret(psk: Option<&[u8]>) -> [u8; SHA256_OUTPUT_SIZE] {
    let ikm = psk.unwrap_or(&[0u8; SHA256_OUTPUT_SIZE]);
    hkdf_extract(&[0u8; SHA256_OUTPUT_SIZE], ikm)
}

/// TLS 1.3 鍵スケジュール: Handshake Secret を導出
///
/// ```text
/// Derive-Secret(Early_Secret, "derived", "")
///       |
///       v
/// (EC)DHE -> HKDF-Extract = Handshake Secret
/// ```
pub fn tls13_handshake_secret(
    early_secret: &[u8; SHA256_OUTPUT_SIZE],
    shared_secret: &[u8],
) -> [u8; SHA256_OUTPUT_SIZE] {
    use crate::loader::sha256;
    let empty_hash = sha256::compute(&[]);
    let derived = tls13_derive_secret(early_secret, b"derived", &empty_hash);
    hkdf_extract(&derived, shared_secret)
}

/// TLS 1.3 鍵スケジュール: Master Secret を導出
///
/// ```text
/// Derive-Secret(Handshake_Secret, "derived", "")
///       |
///       v
///   0 -> HKDF-Extract = Master Secret
/// ```
pub fn tls13_master_secret(
    handshake_secret: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    use crate::loader::sha256;
    let empty_hash = sha256::compute(&[]);
    let derived = tls13_derive_secret(handshake_secret, b"derived", &empty_hash);
    hkdf_extract(&derived, &[0u8; SHA256_OUTPUT_SIZE])
}

/// TLS 1.3: トラフィック鍵のペアを導出
///
/// traffic_key = HKDF-Expand-Label(Secret, "key", "", key_length)
/// traffic_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length=12)
pub fn tls13_derive_traffic_keys(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    key_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    let key = hkdf_expand_label(secret, b"key", b"", key_len);
    let iv = hkdf_expand_label(secret, b"iv", b"", 12);
    (key, iv)
}

/// TLS 1.3: Finished鍵を導出
///
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
pub fn tls13_finished_key(
    base_key: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    let result = hkdf_expand_label(base_key, b"finished", b"", SHA256_OUTPUT_SIZE);
    let mut output = [0u8; SHA256_OUTPUT_SIZE];
    output.copy_from_slice(&result);
    output
}

/// TLS 1.3: Finished verify_data を計算
///
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
pub fn tls13_verify_data(
    finished_key: &[u8; SHA256_OUTPUT_SIZE],
    transcript_hash: &[u8; SHA256_OUTPUT_SIZE],
) -> [u8; SHA256_OUTPUT_SIZE] {
    hmac_sha256(finished_key, transcript_hash)
}

// ============================================================================
// HKDF-SHA384 (RFC 5869) — TLS_AES_256_GCM_SHA384 用
// ============================================================================

/// HKDF-Extract using SHA-384  (PRK = HMAC-SHA384(salt, IKM))
pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; SHA384_OUTPUT_SIZE] {
    let effective_salt = if salt.is_empty() {
        &[0u8; SHA384_OUTPUT_SIZE] as &[u8]
    } else {
        salt
    };
    hmac_sha384(effective_salt, ikm)
}

/// HKDF-Expand using SHA-384  (RFC 5869 Section 2.3)
pub fn hkdf_expand_sha384(prk: &[u8; SHA384_OUTPUT_SIZE], info: &[u8], length: usize) -> Vec<u8> {
    assert!(
        length <= 255 * SHA384_OUTPUT_SIZE,
        "HKDF-Expand-SHA384: requested length too large"
    );

    let n = (length + SHA384_OUTPUT_SIZE - 1) / SHA384_OUTPUT_SIZE;
    let mut okm = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        input.push(i as u8);

        let t_i = hmac_sha384(prk, &input);

        let copy_len = (length - okm.len()).min(SHA384_OUTPUT_SIZE);
        okm.extend_from_slice(&t_i[..copy_len]);

        t_prev = t_i.to_vec();
    }

    okm
}

/// HKDF-Expand-Label for TLS 1.3 using SHA-384 (RFC 8446 Section 7.1)
pub fn hkdf_expand_label_sha384(
    secret: &[u8; SHA384_OUTPUT_SIZE],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let tls_label_prefix = b"tls13 ";
    let full_label_len = tls_label_prefix.len() + label.len();

    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());

    // uint16 length
    hkdf_label.push((length >> 8) as u8);
    hkdf_label.push(length as u8);

    // opaque label<7..255>
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(tls_label_prefix);
    hkdf_label.extend_from_slice(label);

    // opaque context<0..255>
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand_sha384(secret, &hkdf_label, length)
}

/// Derive-Secret using SHA-384 for TLS 1.3
pub fn tls13_derive_secret_sha384(
    secret: &[u8; SHA384_OUTPUT_SIZE],
    label: &[u8],
    transcript_hash: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    let result = hkdf_expand_label_sha384(secret, label, transcript_hash, SHA384_OUTPUT_SIZE);
    let mut output = [0u8; SHA384_OUTPUT_SIZE];
    output.copy_from_slice(&result);
    output
}

/// TLS 1.3 Early Secret using SHA-384
pub fn tls13_early_secret_sha384(psk: Option<&[u8]>) -> [u8; SHA384_OUTPUT_SIZE] {
    let ikm = psk.unwrap_or(&[0u8; SHA384_OUTPUT_SIZE]);
    hkdf_extract_sha384(&[0u8; SHA384_OUTPUT_SIZE], ikm)
}

/// TLS 1.3 Handshake Secret using SHA-384
pub fn tls13_handshake_secret_sha384(
    early_secret: &[u8; SHA384_OUTPUT_SIZE],
    shared_secret: &[u8],
) -> [u8; SHA384_OUTPUT_SIZE] {
    use crate::loader::sha384;
    let empty_hash = sha384::compute(&[]);
    let derived = tls13_derive_secret_sha384(early_secret, b"derived", &empty_hash);
    hkdf_extract_sha384(&derived, shared_secret)
}

/// TLS 1.3 Master Secret using SHA-384
pub fn tls13_master_secret_sha384(
    handshake_secret: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    use crate::loader::sha384;
    let empty_hash = sha384::compute(&[]);
    let derived = tls13_derive_secret_sha384(handshake_secret, b"derived", &empty_hash);
    hkdf_extract_sha384(&derived, &[0u8; SHA384_OUTPUT_SIZE])
}

/// TLS 1.3 トラフィック鍵導出 using SHA-384
pub fn tls13_derive_traffic_keys_sha384(
    secret: &[u8; SHA384_OUTPUT_SIZE],
    key_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    let key = hkdf_expand_label_sha384(secret, b"key", b"", key_len);
    let iv = hkdf_expand_label_sha384(secret, b"iv", b"", 12);
    (key, iv)
}

/// TLS 1.3 Finished鍵導出 using SHA-384
pub fn tls13_finished_key_sha384(
    base_key: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    let result = hkdf_expand_label_sha384(base_key, b"finished", b"", SHA384_OUTPUT_SIZE);
    let mut output = [0u8; SHA384_OUTPUT_SIZE];
    output.copy_from_slice(&result);
    output
}

/// TLS 1.3 Finished verify_data using SHA-384
pub fn tls13_verify_data_sha384(
    finished_key: &[u8; SHA384_OUTPUT_SIZE],
    transcript_hash: &[u8; SHA384_OUTPUT_SIZE],
) -> [u8; SHA384_OUTPUT_SIZE] {
    hmac_sha384(finished_key, transcript_hash)
}

// ============================================================================
// P_SHA384 and TLS 1.2 PRF-SHA384
// ============================================================================

/// P_SHA384 expansion (RFC 5246 Section 5)
///
/// P_SHA384(secret, seed) = HMAC_SHA384(secret, A(1) + seed) +
///                           HMAC_SHA384(secret, A(2) + seed) + ...
/// A(0) = seed
/// A(i) = HMAC_SHA384(secret, A(i-1))
pub fn p_sha384(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha384(secret, seed); // A(1)
    let mut offset = 0;

    while offset < output.len() {
        // P_i = HMAC(secret, A(i) || seed)
        let mut input = Vec::with_capacity(SHA384_OUTPUT_SIZE + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);

        let p = hmac_sha384(secret, &input);
        let copy_len = (output.len() - offset).min(SHA384_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&p[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha384(secret, &a);
    }
}

/// TLS 1.2 PRF using SHA-384 (for AES-256-GCM-SHA384 cipher suites)
pub fn tls12_prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    p_sha384(secret, &combined_seed, output);
}

// ============================================================================
// ChaCha20-Poly1305 AEAD (RFC 8439)
// ============================================================================

/// ChaCha20 quarter round operation (RFC 8439 Section 2.1)
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function (RFC 8439 Section 2.3)
///
/// Generates 64 bytes of keystream from key, counter, and nonce.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initialize state:
    // "expand 32-byte k" constants + key(8 words) + counter(1 word) + nonce(3 words)
    let mut state = [0u32; 16];

    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (little-endian words)
    for i in 0..8 {
        let offset = i * 4;
        state[4 + i] = u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce (little-endian words)
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    // Save initial state for final addition
    let initial = state;

    // 20 rounds (10 iterations of double-round)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to little-endian bytes
    let mut result = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        result[i * 4] = bytes[0];
        result[i * 4 + 1] = bytes[1];
        result[i * 4 + 2] = bytes[2];
        result[i * 4 + 3] = bytes[3];
    }

    result
}

/// ChaCha20 encryption/decryption (RFC 8439 Section 2.4)
///
/// XOR data with ChaCha20 keystream. Works for both encryption and decryption
/// since ChaCha20 is a stream cipher.
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut block_counter = counter;

    for chunk in data.chunks(64) {
        let keystream = chacha20_block(key, block_counter, nonce);
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
        block_counter = block_counter.wrapping_add(1);
    }

    result
}

/// Poly1305 MAC computation (RFC 8439 Section 2.5)
///
/// Computes a 16-byte authentication tag using the Poly1305 algorithm.
/// The 32-byte key is split: r = key[0..16] (clamped), s = key[16..32].
pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    // Clamp r according to RFC 8439 Section 2.5.1.
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;

    // Represent r as 26-bit limbs.
    let t0 = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as u64;
    let t1 = u32::from_le_bytes([r[4], r[5], r[6], r[7]]) as u64;
    let t2 = u32::from_le_bytes([r[8], r[9], r[10], r[11]]) as u64;
    let t3 = u32::from_le_bytes([r[12], r[13], r[14], r[15]]) as u64;

    let r0 = t0 & 0x3ffffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    let r4 = (t3 >> 8) & 0x00fffff;

    let r1_5 = r1 * 5;
    let r2_5 = r2 * 5;
    let r3_5 = r3 * 5;
    let r4_5 = r4 * 5;

    // Accumulator h in 26-bit limbs.
    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    let mut offset = 0usize;
    while offset < message.len() {
        let block_len = (message.len() - offset).min(16);
        let mut block = [0u8; 17];
        block[..block_len].copy_from_slice(&message[offset..offset + block_len]);
        block[block_len] = 1;
        let m = poly1305_block_to_limbs(&block);

        h0 += m[0];
        h1 += m[1];
        h2 += m[2];
        h3 += m[3];
        h4 += m[4];

        let d0 = (h0 as u128 * r0 as u128)
            + (h1 as u128 * r4_5 as u128)
            + (h2 as u128 * r3_5 as u128)
            + (h3 as u128 * r2_5 as u128)
            + (h4 as u128 * r1_5 as u128);
        let d1 = (h0 as u128 * r1 as u128)
            + (h1 as u128 * r0 as u128)
            + (h2 as u128 * r4_5 as u128)
            + (h3 as u128 * r3_5 as u128)
            + (h4 as u128 * r2_5 as u128);
        let d2 = (h0 as u128 * r2 as u128)
            + (h1 as u128 * r1 as u128)
            + (h2 as u128 * r0 as u128)
            + (h3 as u128 * r4_5 as u128)
            + (h4 as u128 * r3_5 as u128);
        let d3 = (h0 as u128 * r3 as u128)
            + (h1 as u128 * r2 as u128)
            + (h2 as u128 * r1 as u128)
            + (h3 as u128 * r0 as u128)
            + (h4 as u128 * r4_5 as u128);
        let d4 = (h0 as u128 * r4 as u128)
            + (h1 as u128 * r3 as u128)
            + (h2 as u128 * r2 as u128)
            + (h3 as u128 * r1 as u128)
            + (h4 as u128 * r0 as u128);

        let mut c = (d0 >> 26) as u64;
        h0 = (d0 as u64) & 0x3ffffff;

        let d1 = d1 + c as u128;
        c = (d1 >> 26) as u64;
        h1 = (d1 as u64) & 0x3ffffff;

        let d2 = d2 + c as u128;
        c = (d2 >> 26) as u64;
        h2 = (d2 as u64) & 0x3ffffff;

        let d3 = d3 + c as u128;
        c = (d3 >> 26) as u64;
        h3 = (d3 as u64) & 0x3ffffff;

        let d4 = d4 + c as u128;
        c = (d4 >> 26) as u64;
        h4 = (d4 as u64) & 0x3ffffff;

        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        offset += block_len;
    }

    // Final carry propagation.
    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    // If h >= p (2^130 - 5), subtract p.
    const P0: u64 = 0x3fffffb;
    const P1: u64 = 0x3ffffff;
    const P2: u64 = 0x3ffffff;
    const P3: u64 = 0x3ffffff;
    const P4: u64 = 0x3ffffff;

    let ge_p = (h4 > P4)
        || (h4 == P4
            && ((h3 > P3)
                || (h3 == P3
                    && ((h2 > P2) || (h2 == P2 && ((h1 > P1) || (h1 == P1 && h0 >= P0)))))));

    if ge_p {
        let mut borrow = 0u64;

        let mut t0 = h0.wrapping_sub(P0 + borrow);
        borrow = if h0 < P0 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t0 = t0.wrapping_add(1 << 26);
        }

        let mut t1 = h1.wrapping_sub(P1 + borrow);
        borrow = if h1 < P1 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t1 = t1.wrapping_add(1 << 26);
        }

        let mut t2 = h2.wrapping_sub(P2 + borrow);
        borrow = if h2 < P2 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t2 = t2.wrapping_add(1 << 26);
        }

        let mut t3 = h3.wrapping_sub(P3 + borrow);
        borrow = if h3 < P3 + borrow { 1 } else { 0 };
        if borrow != 0 {
            t3 = t3.wrapping_add(1 << 26);
        }

        let t4 = h4.wrapping_sub(P4 + borrow);

        h0 = t0;
        h1 = t1;
        h2 = t2;
        h3 = t3;
        h4 = t4;
    }

    // Serialize h (130 bits) into 128 bits and add s (mod 2^128).
    let f0 = h0 | (h1 << 26);
    let f1 = (h1 >> 6) | (h2 << 20);
    let f2 = (h2 >> 12) | (h3 << 14);
    let f3 = (h3 >> 18) | (h4 << 8);

    let s0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]) as u64;
    let s1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]) as u64;
    let s2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]) as u64;
    let s3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]) as u64;

    let mut g0 = (f0 & 0xffff_ffff).wrapping_add(s0);
    let mut g1 = (f1 & 0xffff_ffff).wrapping_add(s1).wrapping_add(g0 >> 32);
    g0 &= 0xffff_ffff;
    let mut g2 = (f2 & 0xffff_ffff).wrapping_add(s2).wrapping_add(g1 >> 32);
    g1 &= 0xffff_ffff;
    let g3 = (f3 & 0xffff_ffff).wrapping_add(s3).wrapping_add(g2 >> 32);
    g2 &= 0xffff_ffff;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(g0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(g1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(g2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(g3 as u32).to_le_bytes());
    tag
}

/// Parse a Poly1305 block (16-byte chunk plus 0x01 pad byte) into 26-bit limbs.
fn poly1305_block_to_limbs(block: &[u8; 17]) -> [u64; 5] {
    let lo = u64::from_le_bytes([
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
    ]);
    let hi = u64::from_le_bytes([
        block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
    ]);
    let top = block[16] as u64;

    [
        lo & 0x3ffffff,
        (lo >> 26) & 0x3ffffff,
        ((lo >> 52) | (hi << 12)) & 0x3ffffff,
        (hi >> 14) & 0x3ffffff,
        ((hi >> 40) | (top << 24)) & 0x3ffffff,
    ]
}

/// Construct Poly1305 AEAD MAC input (RFC 8439 Section 2.8)
///
/// The MAC input for AEAD is:
///   AAD || pad16(AAD) || ciphertext || pad16(ciphertext) ||
///   le64(aad_len) || le64(ciphertext_len)
fn poly1305_aead_construct(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;

    let total = aad.len() + aad_pad + ciphertext.len() + ct_pad + 16;
    let mut mac_data = Vec::with_capacity(total);

    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len() + aad_pad, 0);

    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len() + ct_pad, 0);

    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    mac_data
}

/// ChaCha20-Poly1305 AEAD encryption (RFC 8439 Section 2.8)
///
/// # Returns
/// (ciphertext, 16-byte authentication tag)
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Generate Poly1305 one-time key from first ChaCha20 block (counter=0)
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Encrypt payload starting from counter=1
    let ciphertext = chacha20_encrypt(key, nonce, 1, plaintext);

    // Compute authentication tag
    let mac_input = poly1305_aead_construct(aad, &ciphertext);
    let tag = poly1305_mac(&poly_key, &mac_input);

    (ciphertext, tag)
}

/// ChaCha20-Poly1305 AEAD decryption (RFC 8439 Section 2.8)
///
/// # Returns
/// `Some(plaintext)` if authentication succeeds, `None` otherwise.
/// Uses constant-time tag comparison to prevent timing attacks.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    // Generate Poly1305 one-time key from first ChaCha20 block (counter=0)
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Compute expected authentication tag
    let mac_input = poly1305_aead_construct(aad, ciphertext);
    let expected_tag = poly1305_mac(&poly_key, &mac_input);

    // Constant-time tag comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }

    if diff != 0 {
        return None; // Authentication failed
    }

    // Decrypt payload starting from counter=1
    let plaintext = chacha20_encrypt(key, nonce, 1, ciphertext);
    Some(plaintext)
}

// ============================================================================
// MD5 Implementation (RFC 1321)
// TLS 1.0/1.1 PRF のデュアルハッシュ方式に必要
// ============================================================================

/// MD5 output size in bytes
const MD5_OUTPUT_SIZE: usize = 16;

/// MD5 block size in bytes
const MD5_BLOCK_SIZE: usize = 64;

/// MD5 initial hash values (RFC 1321 Section 3.3)
const MD5_INIT: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// MD5 per-round shift amounts (RFC 1321 Section 3.4)
const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 T[i] = floor(2^32 * abs(sin(i+1))) constants
const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// MD5ハッシュ計算 (ストリーミング対応)
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: MD5_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        // バッファに残りがあれば先に埋める
        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let copy_len = remaining.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            offset = copy_len;

            if self.buffer_len == 64 {
                let block = self.buffer;
                md5_compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        // 64バイトブロックを直接処理
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            md5_compress(&mut self.state, &block);
            offset += 64;
        }

        // 残りをバッファに保存
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        // MD5パディング: 1ビット + ゼロ + 64ビットリトルエンディアン長
        let bit_len = self.total_len * 8;
        let mut padding = [0u8; 72]; // 最大パディングサイズ
        padding[0] = 0x80;

        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        self.update(&padding[..pad_len]);

        // 長さをリトルエンディアンで追加
        let len_bytes = bit_len.to_le_bytes();
        self.update(&len_bytes);

        // 結果をリトルエンディアンで出力
        let mut result = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }
}

/// MD5圧縮関数 (RFC 1321 Section 3.4)
fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]) {
    // ブロックを16個のリトルエンディアンu32に変換
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | ((!b) & d), i),
            16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | (!d)), (7 * i) % 16),
        };

        let temp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(MD5_T[i])
                .wrapping_add(m[g])
                .rotate_left(MD5_S[i]),
        );
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// MD5ワンショット計算
pub fn md5_compute(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize()
}

// ============================================================================
// SHA-1 Implementation (FIPS 180-4)
// TLS 1.0/1.1 PRF および レガシー署名検証に必要
// ============================================================================

/// SHA-1 output size in bytes
const SHA1_OUTPUT_SIZE: usize = 20;

/// SHA-1 block size in bytes
const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-1 initial hash values (FIPS 180-4 Section 5.3.1)
const SHA1_INIT: [u32; 5] = [
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
];

/// SHA-1ハッシュ計算 (ストリーミング対応)
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: SHA1_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let copy_len = remaining.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            offset = copy_len;

            if self.buffer_len == 64 {
                let block = self.buffer;
                sha1_compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            sha1_compress(&mut self.state, &block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len * 8;
        let mut padding = [0u8; 72];
        padding[0] = 0x80;

        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        self.update(&padding[..pad_len]);

        // SHA-1はビッグエンディアンの長さ
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);

        let mut result = [0u8; 20];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}

/// SHA-1圧縮関数 (FIPS 180-4 Section 6.1.2)
fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];

    // メッセージスケジュール: W[0..15] はブロックから直接
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    // W[16..79] = (W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16]) <<< 1
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdcu32),
            _ => (b ^ c ^ d, 0xca62c1d6u32),
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// SHA-1ワンショット計算
pub fn sha1_compute(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

// ============================================================================
// HMAC-MD5 / HMAC-SHA1 (RFC 2104)
// TLS 1.0/1.1 PRF および CBC MAC に必要
// ============================================================================

/// HMAC-MD5 (RFC 2104)
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; MD5_OUTPUT_SIZE] {
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > MD5_BLOCK_SIZE {
        hashed_key = md5_compute(key);
        &hashed_key
    } else {
        key
    };

    let mut ipad = [0x36u8; MD5_BLOCK_SIZE];
    let mut opad = [0x5cu8; MD5_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    let mut inner = Md5::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Md5::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// HMAC-SHA1 (RFC 2104)
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_OUTPUT_SIZE] {
    let hashed_key;
    let key_bytes: &[u8] = if key.len() > SHA1_BLOCK_SIZE {
        hashed_key = sha1_compute(key);
        &hashed_key
    } else {
        key
    };

    let mut ipad = [0x36u8; SHA1_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA1_BLOCK_SIZE];

    for i in 0..key_bytes.len() {
        ipad[i] ^= key_bytes[i];
        opad[i] ^= key_bytes[i];
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ============================================================================
// AES-CBC Implementation (NIST SP 800-38A)
// TLS 1.0/1.1/1.2 CBC暗号スイートに必要
// ============================================================================

/// AES Inverse S-box (復号用)
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES InvSubBytes
fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

/// AES InvShiftRows
fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    // Row 0: no shift
    // Row 1: shift right by 1
    state[1] = temp[13];
    state[5] = temp[1];
    state[9] = temp[5];
    state[13] = temp[9];
    // Row 2: shift right by 2
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    // Row 3: shift right by 3
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];
}

/// AES InvMixColumns
fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i]     = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[i + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[i + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[i + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

/// AESブロック復号 (拡張鍵スケジュール使用)
fn aes_decrypt_block_with_schedule(block: &[u8; 16], schedule: &AesRoundKeySchedule) -> [u8; 16] {
    let mut state = *block;

    // 最終ラウンドキーを最初に適用
    aes_add_round_key(&mut state, &schedule.round_keys[schedule.rounds]);

    // 逆ラウンド (MixColumns含む)
    for i in (1..schedule.rounds).rev() {
        aes_inv_shift_rows(&mut state);
        aes_inv_sub_bytes(&mut state);
        aes_add_round_key(&mut state, &schedule.round_keys[i]);
        aes_inv_mix_columns(&mut state);
    }

    // 最初のラウンド (MixColumnsなし)
    aes_inv_shift_rows(&mut state);
    aes_inv_sub_bytes(&mut state);
    aes_add_round_key(&mut state, &schedule.round_keys[0]);

    state
}

/// AES-CBC暗号化
///
/// 入力はパディング済み（16バイトの倍数）であること。
/// C[i] = AES_Encrypt(P[i] XOR C[i-1]), C[-1] = IV
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let Some(schedule) = aes_expand_key_schedule(key) else {
        return Vec::new();
    };

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut prev_block = *iv;

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // XOR with previous ciphertext block
        for j in 0..16 {
            block[j] ^= prev_block[j];
        }

        let encrypted = aes_encrypt_block_with_schedule(&block, &schedule);
        ciphertext.extend_from_slice(&encrypted);
        prev_block = encrypted;
    }

    ciphertext
}

/// AES-CBC復号
///
/// P[i] = AES_Decrypt(C[i]) XOR C[i-1], C[-1] = IV
/// パディングは呼び出し側で検証・除去する。
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() % 16 != 0 || ciphertext.is_empty() {
        return None;
    }

    let schedule = aes_expand_key_schedule(key)?;

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = *iv;

    for chunk in ciphertext.chunks(16) {
        let mut ct_block = [0u8; 16];
        ct_block.copy_from_slice(chunk);

        let mut decrypted = aes_decrypt_block_with_schedule(&ct_block, &schedule);

        // XOR with previous ciphertext block
        for j in 0..16 {
            decrypted[j] ^= prev_block[j];
        }

        plaintext.extend_from_slice(&decrypted);
        prev_block = ct_block;
    }

    Some(plaintext)
}

/// TLSパディング追加 (RFC 5246 Section 6.2.3.2)
///
/// padding_length = block_size - ((data_len) % block_size) - 1 の場合もあるが、
/// TLSでは: padding = [pad_val; pad_val + 1] where pad_val = block_size - 1 - (data_len % block_size)
/// 各パディングバイトの値 = パディング長 - 1
fn tls_add_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let pad_byte = (pad_len - 1) as u8;
    let mut result = Vec::with_capacity(data.len() + pad_len);
    result.extend_from_slice(data);
    for _ in 0..pad_len {
        result.push(pad_byte);
    }
    result
}

/// TLSパディング検証 (定時間)
///
/// パディングの最後のバイトがパディング長を示す。
/// 全パディングバイトが同じ値であることを検証。
/// 戻り値: パディングを除いたデータ長、または None
fn tls_verify_padding(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }

    let pad_byte = data[data.len() - 1];
    let pad_len = pad_byte as usize + 1;

    if pad_len > data.len() || pad_len > 256 {
        return None;
    }

    // 定時間検証: 全パディングバイトが同じ値か
    let mut bad = 0u8;
    for i in 0..pad_len {
        bad |= data[data.len() - 1 - i] ^ pad_byte;
    }

    if bad != 0 {
        None
    } else {
        Some(data.len() - pad_len)
    }
}

// ============================================================================
// TLS 1.0/1.1 PRF (RFC 2246 Section 5, RFC 4346 Section 5)
// デュアルハッシュ方式: P_MD5 XOR P_SHA-1
// ============================================================================

/// P_MD5 expansion
fn p_md5(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_md5(secret, seed); // A(1)
    let mut offset = 0;

    while offset < output.len() {
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let block = hmac_md5(secret, &a_seed);
        let copy_len = (output.len() - offset).min(MD5_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;

        a = hmac_md5(secret, &a);
    }
}

/// P_SHA1 expansion
fn p_sha1(secret: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut a = hmac_sha1(secret, seed); // A(1)
    let mut offset = 0;

    while offset < output.len() {
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let block = hmac_sha1(secret, &a_seed);
        let copy_len = (output.len() - offset).min(SHA1_OUTPUT_SIZE);
        output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;

        a = hmac_sha1(secret, &a);
    }
}

/// TLS 1.0/1.1 PRF (RFC 2246 Section 5)
///
/// PRF(secret, label, seed) = P_MD5(S1, label+seed) XOR P_SHA-1(S2, label+seed)
/// S1 = secret[..L_S], S2 = secret[L_S..]
/// L_S = ceil(secret.len() / 2)
pub fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    // secret を前半・後半に分割 (奇数長は中央バイト共有)
    let half = (secret.len() + 1) / 2;
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    let mut md5_output = vec![0u8; output.len()];
    let mut sha1_output = vec![0u8; output.len()];

    p_md5(s1, &combined_seed, &mut md5_output);
    p_sha1(s2, &combined_seed, &mut sha1_output);

    // XOR して最終結果
    for i in 0..output.len() {
        output[i] = md5_output[i] ^ sha1_output[i];
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
fn tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished() -> Vec<u8> {
    // Handshake #1: ServerHelloDone (len=0)
    let server_hello_done = [14u8, 0, 0, 0];

    // Finished verify_data = PRF(master_secret, "server finished", Hash(handshake_messages))[0..12]
    // For TlsConnection::new(), master_secret starts as all-zero 48 bytes.
    let handshake_hash = crate::loader::sha256::compute(&server_hello_done);
    let master_secret = [0u8; 48];
    let mut verify_data = [0u8; 12];
    tls12_prf(&master_secret, b"server finished", &handshake_hash, &mut verify_data);

    // Handshake #2: Finished (len=12) + verify_data
    let mut data = Vec::with_capacity(server_hello_done.len() + 4 + verify_data.len());
    data.extend_from_slice(&server_hello_done);
    data.extend_from_slice(&[20u8, 0, 0, 12]);
    data.extend_from_slice(&verify_data);
    data
}

// ============================================================================
// TLS MAC computation (RFC 5246 Section 6.2.3.1)
// CBC暗号スイートのMAC-then-Encrypt用
// ============================================================================

/// TLS MAC計算
///
/// MAC = HMAC(mac_key, seq_num(8) || type(1) || version(2) || length(2) || fragment)
fn compute_tls_mac(
    mac_key: &[u8],
    seq_num: u64,
    content_type: u8,
    version: TlsVersion,
    fragment: &[u8],
    use_sha1: bool,
) -> Vec<u8> {
    let mut mac_input = Vec::with_capacity(13 + fragment.len());
    mac_input.extend_from_slice(&seq_num.to_be_bytes());
    mac_input.push(content_type);
    let ver_bytes = version.to_bytes();
    mac_input.push(ver_bytes[0]);
    mac_input.push(ver_bytes[1]);
    mac_input.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(fragment);

    if use_sha1 {
        hmac_sha1(mac_key, &mac_input).to_vec()
    } else {
        hmac_sha256(mac_key, &mac_input).to_vec()
    }
}

// ============================================================================
// CBC Cipher Suite Definitions
// ============================================================================

impl CipherSuite {
    // TLS 1.0/1.1/1.2 CBC 暗号スイート
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x002F);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0035);
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0x003C);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: Self = Self(0x003D);
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0xC013);
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0xC014);
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0xC027);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Self = Self(0xC009);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Self = Self(0xC00A);

    /// CBC暗号スイートかどうか
    pub fn is_cbc(&self) -> bool {
        matches!(
            self.0,
            0x002F | 0x0035 | 0x003C | 0x003D |
            0xC013 | 0xC014 | 0xC027 |
            0xC009 | 0xC00A
        )
    }

    /// RSA鍵転送を使用するか (TLS_RSA_WITH_*)
    pub fn is_rsa_key_transport(&self) -> bool {
        matches!(self.0, 0x002F | 0x0035 | 0x003C | 0x003D | 0x009C | 0x009D)
    }

    /// MAC鍵の長さ (バイト)
    pub fn mac_key_len(&self) -> usize {
        match self.0 {
            // SHA-1 MAC: 20 bytes
            0x002F | 0x0035 | 0xC013 | 0xC014 | 0xC009 | 0xC00A => 20,
            // SHA-256 MAC: 32 bytes
            0x003C | 0x003D | 0xC027 => 32,
            _ => 0,
        }
    }

    /// MACの出力長 (バイト)
    pub fn mac_len(&self) -> usize {
        self.mac_key_len()
    }

    /// SHA-1 MACを使用するか
    pub fn uses_sha1_mac(&self) -> bool {
        matches!(
            self.0,
            0x002F | 0x0035 | 0xC013 | 0xC014 | 0xC009 | 0xC00A
        )
    }

    /// CBC暗号スイートのIV長
    pub fn cbc_iv_len(&self) -> usize {
        if self.is_cbc() { 16 } else { 0 }
    }

    /// SHA-384ベースの暗号スイートかどうか
    pub fn uses_sha384(&self) -> bool {
        matches!(self.0, 0x009D | 0xC030 | 0xC02C | 0x1302)
    }

    /// TLS 1.0/1.1 で使用可能か
    pub fn is_legacy_compatible(&self) -> bool {
        self.is_cbc() || self.is_rsa_key_transport()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // HMAC-SHA256 Tests (RFC 4231)
    // ========================================================================

    /// RFC 4231 Test Case 1
    /// Key  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
    /// Data = "Hi There"
    #[test_case]
    fn test_hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    /// RFC 4231 Test Case 2
    /// Key  = "Jefe"
    /// Data = "what do ya want for nothing?"
    #[test_case]
    fn test_hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        let result = hmac_sha256(key, data);
        assert_eq!(result, expected);
    }

    /// RFC 4231 Test Case 3
    /// Key  = 0xaaaa... (20 bytes)
    /// Data = 0xdddd... (50 bytes)
    #[test_case]
    fn test_hmac_sha256_rfc4231_case3() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let expected: [u8; 32] = [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
            0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
            0xce, 0xd5, 0x65, 0xfe,
        ];
        let result = hmac_sha256(&key, &data);
        assert_eq!(result, expected);
    }

    /// HMAC-SHA256 with key longer than block size (64 bytes)
    /// RFC 4231 Test Case 6
    /// Key = 0xaaaa... (131 bytes)
    /// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    #[test_case]
    fn test_hmac_sha256_long_key() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    // ========================================================================
    // HKDF Tests (RFC 5869)
    // ========================================================================

    /// RFC 5869 Test Case 1 - HKDF-Extract
    /// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
    /// Salt = 0x000102030405060708090a0b0c (13 bytes)
    #[test_case]
    fn test_hkdf_rfc5869_case1_extract() {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk, expected_prk);
    }

    /// RFC 5869 Test Case 1 - HKDF-Expand
    /// PRK  = (from extract above)
    /// Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    /// L    = 42
    #[test_case]
    fn test_hkdf_rfc5869_case1_expand() {
        let prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(okm.as_slice(), &expected_okm);
    }

    /// HKDF-Extract with empty salt (uses zero-filled hash-length key)
    #[test_case]
    fn test_hkdf_extract_empty_salt() {
        let ikm = [0x0bu8; 22];
        let prk = hkdf_extract(&[], &ikm);
        // Should not panic and should produce a 32-byte output
        assert_eq!(prk.len(), 32);
        // Verify it's not all zeros (statistically impossible for valid HMAC)
        assert!(prk.iter().any(|&b| b != 0));
    }

    /// HKDF-Expand with zero-length output
    #[test_case]
    fn test_hkdf_expand_zero_length() {
        let prk = [0x42u8; 32];
        let okm = hkdf_expand(&prk, b"test", 0);
        assert!(okm.is_empty());
    }

    // ========================================================================
    // ChaCha20 Tests (RFC 8439)
    // ========================================================================

    /// RFC 8439 Section 2.3.2 - ChaCha20 Block Function Test Vector
    #[test_case]
    fn test_chacha20_rfc8439_block() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;

        let block = chacha20_block(&key, counter, &nonce);

        // RFC 8439 Section 2.3.2 expected output (first 16 bytes)
        let expected_start: [u8; 16] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4,
        ];
        assert_eq!(&block[0..16], &expected_start);

        // Last 16 bytes
        let expected_end: [u8; 16] = [
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50,
            0x3c, 0x4e,
        ];
        assert_eq!(&block[48..64], &expected_end);
    }

    /// RFC 8439 Section 2.4.2 - ChaCha20 Encryption Test Vector
    #[test_case]
    fn test_chacha20_rfc8439_encrypt() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let ciphertext = chacha20_encrypt(&key, &nonce, 1, plaintext);
        assert_eq!(ciphertext.as_slice(), &expected_ciphertext);

        // Verify decryption (ChaCha20 is symmetric)
        let decrypted = chacha20_encrypt(&key, &nonce, 1, &ciphertext);
        assert_eq!(decrypted.as_slice(), &plaintext[..]);
    }

    // ========================================================================
    // Poly1305 Tests (RFC 8439)
    // ========================================================================

    /// RFC 8439 Section 2.5.2 - Poly1305 MAC Test Vector
    #[test_case]
    fn test_poly1305_rfc8439() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";
        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        let tag = poly1305_mac(&key, message);
        assert_eq!(tag, expected_tag);
    }

    // ========================================================================
    // ChaCha20-Poly1305 AEAD Tests (RFC 8439)
    // ========================================================================

    /// RFC 8439 Section 2.8.2 - AEAD Encryption Test Vector
    #[test_case]
    fn test_chacha20_poly1305_rfc8439_encrypt() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
        assert_eq!(ciphertext.as_slice(), &expected_ciphertext);
        assert_eq!(tag, expected_tag);
    }

    /// RFC 8439 Section 2.8.2 - AEAD Decryption Test Vector
    #[test_case]
    fn test_chacha20_poly1305_rfc8439_decrypt() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let plaintext = chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag);
        assert!(plaintext.is_some());
        let pt = plaintext.unwrap();
        assert_eq!(
            &pt,
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        );
    }

    /// ChaCha20-Poly1305 authentication failure test
    #[test_case]
    fn test_chacha20_poly1305_auth_failure() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello, world!";

        let (ciphertext, mut tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

        // Corrupt the tag
        tag[0] ^= 0xFF;

        let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_none());
    }

    /// ChaCha20-Poly1305 roundtrip test
    #[test_case]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0xAAu8; 12];
        let aad = b"test aad";
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);

        // Verify ciphertext differs from plaintext
        assert_ne!(ciphertext.as_slice(), &plaintext[..]);

        let decrypted = chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap().as_slice(), &plaintext[..]);
    }

    /// ChaCha20-Poly1305 with empty plaintext
    #[test_case]
    fn test_chacha20_poly1305_empty_plaintext() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let aad = b"aad only";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, &[]);
        assert!(ciphertext.is_empty());

        // Tag should still be valid (authenticating AAD only)
        let result = chacha20_poly1305_decrypt(&key, &nonce, aad, &[], &tag);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    // ========================================================================
    // AES-GCM Tests
    // ========================================================================

    /// AES-128-GCM roundtrip encrypt/decrypt
    #[test_case]
    fn test_aes_gcm_roundtrip() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, AES-GCM encryption!";

        let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);

        // Verify ciphertext differs from plaintext
        assert_ne!(ciphertext.as_slice(), &plaintext[..]);
        assert_eq!(ciphertext.len(), plaintext.len());

        // Decrypt and verify
        let decrypted = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap().as_slice(), &plaintext[..]);
    }

    /// AES-256-GCM roundtrip encrypt/decrypt
    #[test_case]
    fn test_aes_gcm_256_roundtrip() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        let aad = b"aes-256-gcm aad";
        let plaintext = b"AES-256-GCM test payload";

        let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext.as_slice(), &plaintext[..]);

        let decrypted = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap().as_slice(), &plaintext[..]);
    }

    /// AES-128-GCM authentication failure
    #[test_case]
    fn test_aes_gcm_auth_failure() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"test aad";
        let plaintext = b"test data";

        let (ciphertext, mut tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);

        // Corrupt the tag
        tag[0] ^= 0xFF;

        let result = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_none());
    }

    /// AES-128-GCM with corrupted ciphertext
    #[test_case]
    fn test_aes_gcm_corrupted_ciphertext() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"test aad";
        let plaintext = b"test data for corruption";

        let (mut ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);

        // Corrupt a byte in the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_none());
    }

    /// AES-128-GCM with empty plaintext
    #[test_case]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"aad only, no payload";

        let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, &[]);
        assert!(ciphertext.is_empty());

        let result = aes_gcm_decrypt(&key, &nonce, aad, &[], &tag);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    // ========================================================================
    // AES-128 Core Tests
    // ========================================================================

    /// AES-128 key expansion sanity check
    #[test_case]
    fn test_aes_key_expansion() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let round_keys = aes_key_expansion(&key);

        // Round key 0 should be the original key
        assert_eq!(round_keys[0], key);

        // Round keys should all be different
        for i in 0..10 {
            assert_ne!(round_keys[i], round_keys[i + 1]);
        }
    }

    /// AES-128 encrypt/decrypt roundtrip via CTR mode
    #[test_case]
    fn test_aes_ctr_roundtrip() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [0x00; 12];
        let plaintext = b"AES-CTR mode test data that spans multiple blocks!!!!";

        let ciphertext = aes_ctr(&key, &nonce, plaintext);
        assert_ne!(ciphertext.as_slice(), &plaintext[..]);

        // CTR mode decryption is the same as encryption
        let decrypted = aes_ctr(&key, &nonce, &ciphertext);
        assert_eq!(decrypted.as_slice(), &plaintext[..]);
    }

    // ========================================================================
    // Hardware RNG Tests
    // ========================================================================

    /// Random output should not be all zeros
    #[test_case]
    fn test_generate_random_not_all_zeros() {
        let random = generate_random();
        assert!(random.iter().any(|&b| b != 0));
    }

    /// Two consecutive random calls should produce different results
    #[test_case]
    fn test_generate_random_different_calls() {
        let r1 = generate_random();
        let r2 = generate_random();
        // Statistically, two 32-byte random values should differ
        assert_ne!(r1, r2);
    }

    // ========================================================================
    // TLS Key Derivation Tests
    // ========================================================================

    /// Master secret derivation should produce 48 bytes
    #[test_case]
    fn test_derive_master_secret_length() {
        let pre_master = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms = derive_master_secret(&pre_master, &client_random, &server_random);
        assert_eq!(ms.len(), 48);
        // Should not be all zeros
        assert!(ms.iter().any(|&b| b != 0));
    }

    /// Key block derivation should produce requested length
    #[test_case]
    fn test_derive_key_block_length() {
        let master_secret = [0x55u8; 48];
        let server_random = [0xAAu8; 32];
        let client_random = [0xBBu8; 32];

        // AES-128-GCM: 2 * 16 (keys) + 2 * 4 (IVs) = 40 bytes
        let kb = derive_key_block(&master_secret, &server_random, &client_random, 40);
        assert_eq!(kb.len(), 40);
        assert!(kb.iter().any(|&b| b != 0));

        // AES-256-GCM: 2 * 32 (keys) + 2 * 4 (IVs) = 72 bytes
        let kb256 = derive_key_block(&master_secret, &server_random, &client_random, 72);
        assert_eq!(kb256.len(), 72);
    }

    /// Master secret should be deterministic for same inputs
    #[test_case]
    fn test_derive_master_secret_deterministic() {
        let pre_master = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms1 = derive_master_secret(&pre_master, &client_random, &server_random);
        let ms2 = derive_master_secret(&pre_master, &client_random, &server_random);
        assert_eq!(ms1, ms2);
    }

    /// Different pre-master secrets should produce different master secrets
    #[test_case]
    fn test_derive_master_secret_differs_with_input() {
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms1 = derive_master_secret(&[0x42u8; 48], &client_random, &server_random);
        let ms2 = derive_master_secret(&[0x43u8; 48], &client_random, &server_random);
        assert_ne!(ms1, ms2);
    }

    // ========================================================================
    // TLS 1.2 PRF Tests
    // ========================================================================

    /// PRF output should be deterministic
    #[test_case]
    fn test_tls12_prf_deterministic() {
        let secret = b"test secret";
        let label = b"test label";
        let seed = b"test seed";

        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        tls12_prf(secret, label, seed, &mut out1);
        tls12_prf(secret, label, seed, &mut out2);
        assert_eq!(out1, out2);
    }

    /// PRF with different labels should produce different output
    #[test_case]
    fn test_tls12_prf_different_labels() {
        let secret = b"test secret";
        let seed = b"test seed";

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        tls12_prf(secret, b"label A", seed, &mut out1);
        tls12_prf(secret, b"label B", seed, &mut out2);
        assert_ne!(out1, out2);
    }

    // ========================================================================
    // HKDF-Expand-Label Tests (TLS 1.3)
    // ========================================================================

    /// HKDF-Expand-Label should produce correct length output
    #[test_case]
    fn test_hkdf_expand_label_length() {
        let secret = [0x42u8; 32];
        let result = hkdf_expand_label(&secret, b"key", b"", 16);
        assert_eq!(result.len(), 16);

        let result32 = hkdf_expand_label(&secret, b"iv", b"", 12);
        assert_eq!(result32.len(), 12);
    }

    /// HKDF-Expand-Label with different labels should produce different output
    #[test_case]
    fn test_hkdf_expand_label_different_labels() {
        let secret = [0x42u8; 32];
        let result1 = hkdf_expand_label(&secret, b"key", b"", 32);
        let result2 = hkdf_expand_label(&secret, b"iv", b"", 32);
        assert_ne!(result1, result2);
    }

    // ========================================================================
    // TLS Connection Integration Tests
    // ========================================================================

    /// TLS connection state machine: initial state
    #[test_case]
    fn test_tls_connection_initial_state() {
        let config = TlsConfig::new();
        let conn = TlsConnection::new(config);
        assert_eq!(conn.state(), TlsState::Initial);
        assert!(conn.negotiated_version().is_none());
    }

    /// TLS connection: build ClientHello
    #[test_case]
    fn test_tls_connection_client_hello() {
        let config = TlsConfig::new().with_server_name("example.com");
        let mut conn = TlsConnection::new(config);

        let hello = conn.build_client_hello();

        // Should start with TLS record header
        assert_eq!(hello[0], ContentType::Handshake as u8);
        // Version should be TLS 1.0 for compatibility
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);

        // State should advance
        assert_eq!(conn.state(), TlsState::ClientHelloSent);
    }

    /// TLS connection: encrypt fails when not established
    #[test_case]
    fn test_tls_connection_encrypt_not_established() {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let result = conn.encrypt(b"hello");
        assert!(matches!(result, Err(TlsError::NotConnected)));
    }

    /// TLS handshake parser should handle multiple handshake messages in one record
    #[test_case]
    fn test_process_handshake_multiple_messages() {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);

        let data = tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished();
        let result = conn.process_handshake(&data);
        assert!(result.is_ok());
        assert_eq!(conn.state(), TlsState::Established);
        assert_eq!(conn.handshake_messages.as_slice(), data.as_slice());
    }

    /// Finished(len=0) is invalid for TLS 1.2 and must be rejected.
    #[test_case]
    fn test_process_handshake_finished_without_verify_data_rejected() {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);

        let data = [20u8, 0, 0, 0];
        let result = conn.process_handshake(&data);
        assert!(matches!(result, Err(TlsError::DecodeError)));
    }

    /// TLS handshake parser should reject truncated handshake headers
    #[test_case]
    fn test_process_handshake_truncated_header() {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);

        let data = [2u8, 0, 0];
        let result = conn.process_handshake(&data);
        assert!(matches!(result, Err(TlsError::DecodeError)));
    }

    /// CipherSuite helper methods
    #[test_case]
    fn test_cipher_suite_helpers() {
        // ChaCha20-Poly1305 suites
        assert!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
        assert!(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
        assert!(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305());
        assert!(!CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305());

        // AES-GCM suites
        assert!(CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm());
        assert!(CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm());
        assert!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.is_aes_gcm());
        assert!(!CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm());

        // Key lengths
        assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.key_len(), 16);
        assert_eq!(CipherSuite::TLS_AES_256_GCM_SHA384.key_len(), 32);
        assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len(), 32);

        // IV lengths
        assert_eq!(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.iv_len(), 4);
        assert_eq!(CipherSuite::TLS_AES_128_GCM_SHA256.iv_len(), 12);
        assert_eq!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len(), 12);
    }

    /// Base64 decode test
    #[test_case]
    fn test_base64_decode() {
        // "Hello" in Base64 = "SGVsbG8="
        let result = base64_decode("SGVsbG8=");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"Hello");

        // Empty string
        let empty = base64_decode("");
        assert!(empty.is_some());
        assert!(empty.unwrap().is_empty());
    }

    /// TLS version helpers
    #[test_case]
    fn test_tls_version() {
        assert_eq!(TlsVersion::TLS_1_2.major(), 3);
        assert_eq!(TlsVersion::TLS_1_2.minor(), 3);
        assert_eq!(TlsVersion::TLS_1_3.major(), 3);
        assert_eq!(TlsVersion::TLS_1_3.minor(), 4);
        assert_eq!(TlsVersion::TLS_1_0.minor(), 1);
    }

    /// Default cipher suite list should include modern suites
    #[test_case]
    fn test_cipher_suite_defaults() {
        let defaults = CipherSuite::defaults();
        assert!(!defaults.is_empty());
        // Should include TLS 1.3 suites
        assert!(defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256));
        assert!(defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384));
        assert!(defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
    }

    /// GF(2^128) multiplication sanity check
    #[test_case]
    fn test_gf128_mul_zero() {
        let zero = [0u8; 16];
        let h = [0x42u8; 16];
        let result = gf128_mul(&zero, &h);
        // 0 * anything = 0 in GF(2^128)
        assert_eq!(result, zero);
    }

    /// GF(2^8) multiplication sanity check
    #[test_case]
    fn test_gf_mul_basic() {
        // 0x02 * 0x87 = 0x15 in AES GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
        // 0x87 = 10000111, shift left: 100001110 = 0x10E, reduce: 0x10E XOR 0x11B = 0x15
        assert_eq!(gf_mul(0x02, 0x87), 0x15);
        // Identity: 0x01 * x = x
        assert_eq!(gf_mul(0x01, 0x53), 0x53);
        // Zero: 0x00 * x = 0
        assert_eq!(gf_mul(0x00, 0x53), 0x00);
    }

    // ========================================================================
    // TLS 1.3 Key Schedule Tests
    // ========================================================================

    /// TLS 1.3: Early Secret derivation (PSK=0)
    #[test_case]
    fn test_tls13_early_secret_no_psk() {
        let early_secret = tls13_early_secret(None);
        assert_eq!(early_secret.len(), 32);
        // Should produce a deterministic value for zero PSK
        let early_secret2 = tls13_early_secret(None);
        assert_eq!(early_secret, early_secret2);
        // Should not be all zeros
        assert!(early_secret.iter().any(|&b| b != 0));
    }

    /// TLS 1.3: Handshake Secret derivation
    #[test_case]
    fn test_tls13_handshake_secret() {
        let early_secret = tls13_early_secret(None);
        let shared_secret = [0x42u8; 32];
        let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);
        assert_eq!(hs_secret.len(), 32);
        assert!(hs_secret.iter().any(|&b| b != 0));

        // Different shared secrets → different handshake secrets
        let hs_secret2 = tls13_handshake_secret(&early_secret, &[0x43u8; 32]);
        assert_ne!(hs_secret, hs_secret2);
    }

    /// TLS 1.3: Master Secret derivation
    #[test_case]
    fn test_tls13_master_secret() {
        let early_secret = tls13_early_secret(None);
        let hs_secret = tls13_handshake_secret(&early_secret, &[0x42u8; 32]);
        let master_secret = tls13_master_secret(&hs_secret);
        assert_eq!(master_secret.len(), 32);
        assert!(master_secret.iter().any(|&b| b != 0));
    }

    /// TLS 1.3: Derive-Secret produces expected-length output
    #[test_case]
    fn test_tls13_derive_secret() {
        let secret = [0x55u8; 32];
        let transcript = [0xAAu8; 32];
        let result = tls13_derive_secret(&secret, b"c hs traffic", &transcript);
        assert_eq!(result.len(), 32);
        assert!(result.iter().any(|&b| b != 0));

        // Different labels → different secrets
        let result2 = tls13_derive_secret(&secret, b"s hs traffic", &transcript);
        assert_ne!(result, result2);
    }

    /// TLS 1.3: Traffic key derivation
    #[test_case]
    fn test_tls13_derive_traffic_keys() {
        let secret = [0x42u8; 32];

        // AES-128: 16-byte key
        let (key128, iv128) = tls13_derive_traffic_keys(&secret, 16);
        assert_eq!(key128.len(), 16);
        assert_eq!(iv128.len(), 12);

        // AES-256/ChaCha20: 32-byte key
        let (key256, iv256) = tls13_derive_traffic_keys(&secret, 32);
        assert_eq!(key256.len(), 32);
        assert_eq!(iv256.len(), 12);

        // Different key lengths → different keys
        assert_ne!(key128.as_slice(), &key256[..16]);
    }

    /// TLS 1.3: Finished key and verify_data
    #[test_case]
    fn test_tls13_finished_key_and_verify_data() {
        let base_key = [0x42u8; 32];
        let finished_key = tls13_finished_key(&base_key);
        assert_eq!(finished_key.len(), 32);
        assert!(finished_key.iter().any(|&b| b != 0));

        let transcript = [0xBBu8; 32];
        let verify_data = tls13_verify_data(&finished_key, &transcript);
        assert_eq!(verify_data.len(), 32);

        // Deterministic
        let verify_data2 = tls13_verify_data(&finished_key, &transcript);
        assert_eq!(verify_data, verify_data2);

        // Different transcripts → different verify_data
        let verify_data3 = tls13_verify_data(&finished_key, &[0xCCu8; 32]);
        assert_ne!(verify_data, verify_data3);
    }

    /// TLS 1.3: Full key schedule chain (Early → Handshake → Master)
    #[test_case]
    fn test_tls13_full_key_schedule() {
        let shared_secret = [0x01u8; 32];

        // Step 1: Early Secret
        let early_secret = tls13_early_secret(None);

        // Step 2: Handshake Secret
        let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);

        // Step 3: Derive handshake traffic secrets
        let transcript_ch_sh = [0x02u8; 32]; // Mock transcript hash
        let c_hs_traffic = tls13_derive_secret(&hs_secret, b"c hs traffic", &transcript_ch_sh);
        let s_hs_traffic = tls13_derive_secret(&hs_secret, b"s hs traffic", &transcript_ch_sh);
        assert_ne!(c_hs_traffic, s_hs_traffic);

        // Step 4: Derive traffic keys
        let (c_key, c_iv) = tls13_derive_traffic_keys(&c_hs_traffic, 16);
        let (s_key, s_iv) = tls13_derive_traffic_keys(&s_hs_traffic, 16);
        assert_ne!(c_key, s_key);
        assert_ne!(c_iv, s_iv);

        // Step 5: Master Secret
        let master = tls13_master_secret(&hs_secret);

        // Step 6: Application traffic secrets
        let transcript_sf = [0x03u8; 32]; // Mock transcript hash
        let c_app_traffic = tls13_derive_secret(&master, b"c ap traffic", &transcript_sf);
        let s_app_traffic = tls13_derive_secret(&master, b"s ap traffic", &transcript_sf);
        assert_ne!(c_app_traffic, s_app_traffic);
        assert_ne!(c_app_traffic, c_hs_traffic);
    }

    // ========================================================================
    // TLS 1.3 Connection Tests
    // ========================================================================

    /// TLS 1.3: ClientHello should include KeyShare extension
    #[test_case]
    fn test_tls13_client_hello_key_share() {
        let config = TlsConfig::new().with_server_name("example.com");
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();

        // Should have pre-generated ECDH key pair
        assert!(conn.local_ecdh_keypair.is_some());

        // Should have initialized transcript hash
        assert!(conn.transcript_hash.is_some());

        // Record should be valid TLS
        assert_eq!(hello[0], ContentType::Handshake as u8);

        // Search for KeyShare extension type (0x0033 = 51)
        // The hello bytes contain extensions including key_share
        let hello_payload = &hello[5..]; // Skip record header
        // Look for the key_share extension type bytes [0x00, 0x33]
        let mut found_key_share = false;
        for i in 0..hello_payload.len().saturating_sub(1) {
            if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x33 {
                found_key_share = true;
                break;
            }
        }
        assert!(found_key_share, "KeyShare extension not found in ClientHello");
    }

    /// TLS 1.3: Supported Versions extension should list both TLS 1.3 and 1.2
    #[test_case]
    fn test_tls13_client_hello_supported_versions() {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();

        let hello_payload = &hello[5..]; // Skip record header

        // Look for supported_versions extension [0x00, 0x2B]
        let mut found_sv = false;
        for i in 0..hello_payload.len().saturating_sub(1) {
            if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x2B {
                found_sv = true;
                // Verify it lists both TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
                if i + 8 < hello_payload.len() {
                    let ext_len =
                        ((hello_payload[i + 2] as usize) << 8) | hello_payload[i + 3] as usize;
                    // ext_data starts at i+4
                    let versions_len = hello_payload[i + 4] as usize;
                    // Should have at least 4 bytes (2 versions × 2 bytes)
                    assert!(
                        versions_len >= 4,
                        "Expected at least 2 versions in supported_versions"
                    );
                    assert_eq!(ext_len, versions_len + 1);
                }
                break;
            }
        }
        assert!(
            found_sv,
            "Supported Versions extension not found in ClientHello"
        );
    }

    /// TLS 1.3: PSK Key Exchange Modes extension present
    #[test_case]
    fn test_tls13_client_hello_psk_modes() {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();

        let hello_payload = &hello[5..];

        // Look for psk_key_exchange_modes extension [0x00, 0x2D]
        let mut found_psk = false;
        for i in 0..hello_payload.len().saturating_sub(1) {
            if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x2D {
                found_psk = true;
                break;
            }
        }
        assert!(
            found_psk,
            "PSK Key Exchange Modes extension not found in ClientHello"
        );
    }

    /// TLS 1.3: strip_content_type helper
    #[test_case]
    fn test_tls13_strip_content_type() {
        // Normal case: plaintext + content_type
        let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17]; // "Hello" + ApplicationData(23)
        let result = TlsConnection::tls13_strip_content_type(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);

        // With padding zeros
        let data2 = [0x48, 0x65, 0x17, 0x00, 0x00]; // "He" + type + zeros
        let result2 = TlsConnection::tls13_strip_content_type(&data2);
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), &[0x48, 0x65]);

        // Empty content (just content type)
        let data3 = [0x16]; // Handshake type only
        let result3 = TlsConnection::tls13_strip_content_type(&data3);
        assert!(result3.is_some());
        assert!(result3.unwrap().is_empty());

        // All zeros
        let data4 = [0x00, 0x00, 0x00];
        let result4 = TlsConnection::tls13_strip_content_type(&data4);
        assert!(result4.is_none());
    }

    /// TLS 1.3: is_tls13 flag starts false
    #[test_case]
    fn test_tls13_initial_state() {
        let config = TlsConfig::new();
        let conn = TlsConnection::new(config);
        assert!(!conn.is_tls13());
        assert!(!conn.needs_client_finished());
    }

    /// TLS 1.3: RFC 8446 Appendix A test vector for key schedule
    /// Tests HKDF-Expand-Label with known inputs/outputs
    #[test_case]
    fn test_tls13_hkdf_expand_label_rfc8446() {
        // RFC 8446 doesn't provide standalone HKDF-Expand-Label vectors,
        // but we can verify the label construction is correct by testing
        // idempotency and length properties.
        let secret = [0x33u8; 32];
        let result1 = hkdf_expand_label(&secret, b"key", b"", 16);
        let result2 = hkdf_expand_label(&secret, b"key", b"", 16);
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 16);

        // Different context → different output
        let result3 = hkdf_expand_label(&secret, b"key", &[0x42u8; 32], 16);
        assert_ne!(result1, result3);
    }

    /// TLS 1.3: Verify the key schedule produces consistent results
    /// matching the expected chain: Early → derive("derived") → Handshake → derive("derived") → Master
    #[test_case]
    fn test_tls13_key_schedule_chain_consistency() {
        use crate::loader::sha256;

        let shared = [0xABu8; 32];
        let empty_hash = sha256::compute(&[]);

        // Manual chain
        let early = tls13_early_secret(None);
        let derived1 = tls13_derive_secret(&early, b"derived", &empty_hash);
        let hs = hkdf_extract(&derived1, &shared);
        let derived2 = tls13_derive_secret(&hs, b"derived", &empty_hash);
        let master = hkdf_extract(&derived2, &[0u8; 32]);

        // Convenience function chain
        let hs2 = tls13_handshake_secret(&early, &shared);
        let master2 = tls13_master_secret(&hs2);

        assert_eq!(hs, hs2);
        assert_eq!(master, master2);
    }

    /// TLS 1.3: Finished verification round-trip
    #[test_case]
    fn test_tls13_finished_round_trip() {
        let base_key = [0x77u8; 32];
        let transcript_hash = [0x88u8; 32];

        let finished_key = tls13_finished_key(&base_key);
        let verify_data = tls13_verify_data(&finished_key, &transcript_hash);

        // Simulate server verification
        let expected = hmac_sha256(&finished_key, &transcript_hash);
        assert_eq!(verify_data, expected);
    }

    /// TLS 1.3: TlsVersion ordering
    #[test_case]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::TLS_1_0 < TlsVersion::TLS_1_1);
        assert!(TlsVersion::TLS_1_1 < TlsVersion::TLS_1_2);
        assert!(TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3);
        assert!(TlsVersion::TLS_1_3 >= TlsVersion::TLS_1_3);
    }

    // ========================================================================
    // MD5 Tests (RFC 1321 Appendix A.5)
    // ========================================================================

    #[test_case]
    fn test_md5_empty() {
        let result = md5_compute(b"");
        let expected = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
            0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
        ];
        assert_eq!(result, expected);
    }

    #[test_case]
    fn test_md5_a() {
        let result = md5_compute(b"a");
        let expected = [
            0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
            0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,
        ];
        assert_eq!(result, expected);
    }

    #[test_case]
    fn test_md5_abc() {
        let result = md5_compute(b"abc");
        let expected = [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
            0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
        ];
        assert_eq!(result, expected);
    }

    #[test_case]
    fn test_md5_message_digest() {
        let result = md5_compute(b"message digest");
        let expected = [
            0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
            0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
        ];
        assert_eq!(result, expected);
    }

    #[test_case]
    fn test_md5_alphabet() {
        let result = md5_compute(b"abcdefghijklmnopqrstuvwxyz");
        let expected = [
            0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
            0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b,
        ];
        assert_eq!(result, expected);
    }

    // ========================================================================
    // SHA-1 Tests (FIPS 180-4)
    // ========================================================================

    #[test_case]
    fn test_sha1_abc() {
        let result = sha1_compute(b"abc");
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(result, expected);
    }

    #[test_case]
    fn test_sha1_empty() {
        let result = sha1_compute(b"");
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
            0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
            0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(result, expected);
    }

    #[test_case]
    fn test_sha1_long() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let result = sha1_compute(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        );
        let expected = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e,
            0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
            0xe5, 0x46, 0x70, 0xf1,
        ];
        assert_eq!(result, expected);
    }

    // ========================================================================
    // HMAC-MD5 / HMAC-SHA1 Tests (RFC 2202)
    // ========================================================================

    #[test_case]
    fn test_hmac_md5_rfc2202_case1() {
        let key = [0x0bu8; 16];
        let data = b"Hi There";
        let expected = [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
            0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
        ];
        assert_eq!(hmac_md5(&key, data), expected);
    }

    #[test_case]
    fn test_hmac_md5_rfc2202_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
            0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
        ];
        assert_eq!(hmac_md5(key, data), expected);
    }

    #[test_case]
    fn test_hmac_sha1_rfc2202_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
            0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
            0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(hmac_sha1(&key, data), expected);
    }

    #[test_case]
    fn test_hmac_sha1_rfc2202_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
            0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
            0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(hmac_sha1(key, data), expected);
    }

    // ========================================================================
    // AES-CBC Tests
    // ========================================================================

    #[test_case]
    fn test_aes_cbc_roundtrip_128() {
        let key = [0x2bu8; 16];
        let iv = [0x00u8; 16];
        let plaintext = b"Hello, AES-CBC mode test!";
        let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext);
        let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
        assert!(decrypted.is_some());
        assert_eq!(&decrypted.unwrap()[..plaintext.len()], plaintext);
    }

    #[test_case]
    fn test_aes_cbc_roundtrip_256() {
        let key = [0x60u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = b"AES-256-CBC round-trip test data for verification!";
        let ciphertext = aes_cbc_encrypt(&key, &iv, plaintext);
        let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
        assert!(decrypted.is_some());
        assert_eq!(&decrypted.unwrap()[..plaintext.len()], plaintext);
    }

    #[test_case]
    fn test_aes_cbc_empty() {
        let key = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let ciphertext = aes_cbc_encrypt(&key, &iv, b"");
        // Empty plaintext still gets padded to one block
        assert_eq!(ciphertext.len(), 16);
        let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap().len(), 0);
    }

    // ========================================================================
    // TLS Padding Tests
    // ========================================================================

    #[test_case]
    fn test_tls_padding_add_verify() {
        let data = b"test data";
        let padded = tls_add_padding(data, 16);
        // padded length should be multiple of 16
        assert_eq!(padded.len() % 16, 0);
        // Verify padding is correct
        let valid_len = tls_verify_padding(&padded);
        assert!(valid_len.is_some());
        assert_eq!(valid_len.unwrap(), data.len());
    }

    #[test_case]
    fn test_tls_padding_exact_block() {
        // Data that's exactly one block minus 1 (needs 1 byte of padding content)
        let data = [0xAA; 15];
        let padded = tls_add_padding(&data, 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[15], 0x00); // pad_byte = 0 (length 1)
        let valid_len = tls_verify_padding(&padded);
        assert!(valid_len.is_some());
        assert_eq!(valid_len.unwrap(), 15);
    }

    #[test_case]
    fn test_tls_padding_full_block_pad() {
        // Data that falls exactly on block boundary → full block of padding
        let data = [0xBB; 16];
        let padded = tls_add_padding(&data, 16);
        assert_eq!(padded.len(), 32);
        let valid_len = tls_verify_padding(&padded);
        assert!(valid_len.is_some());
        assert_eq!(valid_len.unwrap(), 16);
    }

    // ========================================================================
    // TLS 1.0 PRF Tests
    // ========================================================================

    #[test_case]
    fn test_tls10_prf_deterministic() {
        let secret = [0x42u8; 48];
        let label = b"master secret";
        let seed = [0x01u8; 64];
        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];
        tls10_prf(&secret, label, &seed, &mut out1);
        tls10_prf(&secret, label, &seed, &mut out2);
        assert_eq!(out1, out2);
        // Should not be all zeros
        assert!(out1.iter().any(|&b| b != 0));
    }

    #[test_case]
    fn test_tls10_prf_different_labels() {
        let secret = [0x42u8; 48];
        let seed = [0x01u8; 64];
        let mut out1 = [0u8; 48];
        let mut out2 = [0u8; 48];
        tls10_prf(&secret, b"client finished", &seed, &mut out1);
        tls10_prf(&secret, b"server finished", &seed, &mut out2);
        assert_ne!(out1, out2);
    }

    // ========================================================================
    // TLS MAC Tests
    // ========================================================================

    #[test_case]
    fn test_tls_mac_sha1() {
        let key = [0x0Au8; 20];
        let mac = compute_tls_mac(
            &key, 0, ContentType::ApplicationData as u8,
            TlsVersion::TLS_1_0, b"hello", true,
        );
        assert_eq!(mac.len(), 20); // SHA-1 output
        // Should be deterministic
        let mac2 = compute_tls_mac(
            &key, 0, ContentType::ApplicationData as u8,
            TlsVersion::TLS_1_0, b"hello", true,
        );
        assert_eq!(mac, mac2);
    }

    #[test_case]
    fn test_tls_mac_sha256() {
        let key = [0x0Bu8; 32];
        let mac = compute_tls_mac(
            &key, 0, ContentType::ApplicationData as u8,
            TlsVersion::TLS_1_2, b"hello", false,
        );
        assert_eq!(mac.len(), 32); // SHA-256 output
    }

    #[test_case]
    fn test_tls_mac_seq_affects_output() {
        let key = [0x0Au8; 20];
        let mac1 = compute_tls_mac(
            &key, 0, ContentType::ApplicationData as u8,
            TlsVersion::TLS_1_0, b"hello", true,
        );
        let mac2 = compute_tls_mac(
            &key, 1, ContentType::ApplicationData as u8,
            TlsVersion::TLS_1_0, b"hello", true,
        );
        assert_ne!(mac1, mac2);
    }

    // ========================================================================
    // CBC Cipher Suite Helper Tests
    // ========================================================================

    #[test_case]
    fn test_cbc_cipher_suite_helpers() {
        let suite = CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA;
        assert!(suite.is_cbc());
        assert!(suite.is_rsa_key_transport());
        assert!(suite.uses_sha1_mac());
        assert_eq!(suite.mac_key_len(), 20);
        assert_eq!(suite.mac_len(), 20);
        assert_eq!(suite.cbc_iv_len(), 16);
        assert!(suite.is_legacy_compatible());
    }

    #[test_case]
    fn test_cbc_ecdhe_cipher_suite() {
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
        assert!(suite.is_cbc());
        assert!(!suite.is_rsa_key_transport());
        assert!(!suite.uses_sha1_mac());
        assert_eq!(suite.mac_key_len(), 32);
        assert_eq!(suite.mac_len(), 32);
    }

    #[test_case]
    fn test_aead_not_cbc() {
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        assert!(!suite.is_cbc());
        assert!(!suite.is_rsa_key_transport());
        assert!(!suite.is_legacy_compatible());
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn wave8_tls_hmac_sha256_rfc4231_case1_smoke() -> bool {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        hmac_sha256(&key, data) == expected
    }

    pub fn wave8_tls_hmac_sha256_rfc4231_case2_smoke() -> bool {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        hmac_sha256(key, data) == expected
    }

    pub fn wave8_tls_hmac_sha256_rfc4231_case3_smoke() -> bool {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let expected: [u8; 32] = [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
            0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
            0xce, 0xd5, 0x65, 0xfe,
        ];
        hmac_sha256(&key, &data) == expected
    }

    pub fn wave8_tls_hkdf_rfc5869_case1_extract_smoke() -> bool {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        hkdf_extract(&salt, &ikm) == expected_prk
    }

    pub fn wave8_tls_hkdf_rfc5869_case1_expand_smoke() -> bool {
        let prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        hkdf_expand(&prk, &info, 42).as_slice() == &expected_okm
    }

    pub fn wave8_tls_chacha20_rfc8439_block_smoke() -> bool {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let block = chacha20_block(&key, 1, &nonce);
        let expected_start: [u8; 16] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4,
        ];
        let expected_end: [u8; 16] = [
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50,
            0x3c, 0x4e,
        ];
        &block[0..16] == expected_start.as_slice() && &block[48..64] == expected_end.as_slice()
    }

    pub fn wave8_tls_chacha20_rfc8439_encrypt_smoke() -> bool {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let ciphertext = chacha20_encrypt(&key, &nonce, 1, plaintext);
        let decrypted = chacha20_encrypt(&key, &nonce, 1, &ciphertext);
        ciphertext.as_slice() == expected_ciphertext.as_slice() && decrypted.as_slice() == plaintext
    }

    pub fn wave8_tls_poly1305_rfc8439_smoke() -> bool {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";
        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        poly1305_mac(&key, message) == expected_tag
    }

    pub fn wave8_tls_chacha20_poly1305_rfc8439_encrypt_smoke() -> bool {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
        ciphertext.as_slice() == expected_ciphertext.as_slice() && tag == expected_tag
    }

    pub fn wave8_tls_chacha20_poly1305_rfc8439_decrypt_smoke() -> bool {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        let expected = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        match chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag) {
            Some(pt) => pt.as_slice() == expected,
            None => false,
        }
    }

    pub fn wave8_tls_aes_gcm_roundtrip_smoke() -> bool {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, AES-GCM encryption!";

        let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);
        if ciphertext.as_slice() == plaintext || ciphertext.len() != plaintext.len() {
            return false;
        }
        match aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag) {
            Some(pt) => pt.as_slice() == plaintext,
            None => false,
        }
    }

    pub fn wave8_tls_aes_gcm_auth_failure_smoke() -> bool {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"test aad";
        let plaintext = b"test data";

        let (ciphertext, mut tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);
        tag[0] ^= 0xFF;
        aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag).is_none()
    }

    pub fn wave8_tls_aes_ctr_roundtrip_smoke() -> bool {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [0x00; 12];
        let plaintext = b"AES-CTR mode test data that spans multiple blocks!!!!";

        let ciphertext = aes_ctr(&key, &nonce, plaintext);
        if ciphertext.as_slice() == plaintext {
            return false;
        }
        let decrypted = aes_ctr(&key, &nonce, &ciphertext);
        decrypted.as_slice() == plaintext
    }

    pub fn wave8_tls_gf128_mul_zero_smoke() -> bool {
        let zero = [0u8; 16];
        let h = [0x42u8; 16];
        gf128_mul(&zero, &h) == zero
    }

    pub fn wave8_tls_gf_mul_basic_smoke() -> bool {
        gf_mul(0x02, 0x87) == 0x15 && gf_mul(0x01, 0x53) == 0x53 && gf_mul(0x00, 0x53) == 0x00
    }

    pub fn wave8_tls_tls13_early_secret_no_psk_smoke() -> bool {
        let early_secret = tls13_early_secret(None);
        let early_secret2 = tls13_early_secret(None);
        early_secret.len() == 32
            && early_secret == early_secret2
            && early_secret.iter().any(|&b| b != 0)
    }

    pub fn wave8_tls_tls13_handshake_secret_smoke() -> bool {
        let early_secret = tls13_early_secret(None);
        let shared_secret = [0x42u8; 32];
        let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);
        let hs_secret2 = tls13_handshake_secret(&early_secret, &[0x43u8; 32]);
        hs_secret.len() == 32 && hs_secret.iter().any(|&b| b != 0) && hs_secret != hs_secret2
    }

    pub fn wave8_tls_tls13_master_secret_smoke() -> bool {
        let early_secret = tls13_early_secret(None);
        let hs_secret = tls13_handshake_secret(&early_secret, &[0x42u8; 32]);
        let master_secret = tls13_master_secret(&hs_secret);
        master_secret.len() == 32 && master_secret.iter().any(|&b| b != 0)
    }

    pub fn wave8_tls_tls13_derive_secret_smoke() -> bool {
        let secret = [0x55u8; 32];
        let transcript = [0xAAu8; 32];
        let result = tls13_derive_secret(&secret, b"c hs traffic", &transcript);
        let result2 = tls13_derive_secret(&secret, b"s hs traffic", &transcript);
        result.len() == 32 && result.iter().any(|&b| b != 0) && result != result2
    }

    pub fn wave8_tls_tls13_derive_traffic_keys_smoke() -> bool {
        let secret = [0x42u8; 32];
        let (key128, iv128) = tls13_derive_traffic_keys(&secret, 16);
        let (key256, iv256) = tls13_derive_traffic_keys(&secret, 32);

        key128.len() == 16
            && iv128.len() == 12
            && key256.len() == 32
            && iv256.len() == 12
            && key128.as_slice() != &key256[..16]
    }

    pub fn wave8_tls_tls13_finished_key_and_verify_data_smoke() -> bool {
        let base_key = [0x42u8; 32];
        let finished_key = tls13_finished_key(&base_key);
        let transcript = [0xBBu8; 32];
        let verify_data = tls13_verify_data(&finished_key, &transcript);
        let verify_data2 = tls13_verify_data(&finished_key, &transcript);
        let verify_data3 = tls13_verify_data(&finished_key, &[0xCCu8; 32]);

        finished_key.len() == 32
            && finished_key.iter().any(|&b| b != 0)
            && verify_data.len() == 32
            && verify_data == verify_data2
            && verify_data != verify_data3
    }

    pub fn wave8_tls_tls13_full_key_schedule_smoke() -> bool {
        let shared_secret = [0x01u8; 32];

        let early_secret = tls13_early_secret(None);
        let hs_secret = tls13_handshake_secret(&early_secret, &shared_secret);

        let transcript_ch_sh = [0x02u8; 32];
        let c_hs_traffic = tls13_derive_secret(&hs_secret, b"c hs traffic", &transcript_ch_sh);
        let s_hs_traffic = tls13_derive_secret(&hs_secret, b"s hs traffic", &transcript_ch_sh);

        let (c_key, c_iv) = tls13_derive_traffic_keys(&c_hs_traffic, 16);
        let (s_key, s_iv) = tls13_derive_traffic_keys(&s_hs_traffic, 16);

        let master = tls13_master_secret(&hs_secret);

        let transcript_sf = [0x03u8; 32];
        let c_app_traffic = tls13_derive_secret(&master, b"c ap traffic", &transcript_sf);
        let s_app_traffic = tls13_derive_secret(&master, b"s ap traffic", &transcript_sf);

        c_hs_traffic != s_hs_traffic
            && c_key != s_key
            && c_iv != s_iv
            && c_app_traffic != s_app_traffic
            && c_app_traffic != c_hs_traffic
    }

    pub fn wave8_tls_tls13_hkdf_expand_label_rfc8446_smoke() -> bool {
        let secret = [0x33u8; 32];
        let result1 = hkdf_expand_label(&secret, b"key", b"", 16);
        let result2 = hkdf_expand_label(&secret, b"key", b"", 16);
        let result3 = hkdf_expand_label(&secret, b"key", &[0x42u8; 32], 16);

        result1 == result2 && result1.len() == 16 && result1 != result3
    }

    pub fn wave8_tls_tls13_key_schedule_chain_consistency_smoke() -> bool {
        use crate::loader::sha256;

        let shared = [0xABu8; 32];
        let empty_hash = sha256::compute(&[]);

        let early = tls13_early_secret(None);
        let derived1 = tls13_derive_secret(&early, b"derived", &empty_hash);
        let hs = hkdf_extract(&derived1, &shared);
        let derived2 = tls13_derive_secret(&hs, b"derived", &empty_hash);
        let master = hkdf_extract(&derived2, &[0u8; 32]);

        let hs2 = tls13_handshake_secret(&early, &shared);
        let master2 = tls13_master_secret(&hs2);

        hs == hs2 && master == master2
    }

    pub fn wave8_tls_tls13_finished_round_trip_smoke() -> bool {
        let base_key = [0x77u8; 32];
        let transcript_hash = [0x88u8; 32];

        let finished_key = tls13_finished_key(&base_key);
        let verify_data = tls13_verify_data(&finished_key, &transcript_hash);
        let expected = hmac_sha256(&finished_key, &transcript_hash);

        verify_data == expected
    }

    pub fn wave8_tls_tls13_initial_state_smoke() -> bool {
        let config = TlsConfig::new();
        let conn = TlsConnection::new(config);
        !conn.is_tls13() && !conn.needs_client_finished()
    }

    pub fn wave8_tls_tls13_client_hello_key_share_smoke() -> bool {
        let config = TlsConfig::new().with_server_name("example.com");
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();

        if conn.local_ecdh_keypair.is_none() || conn.transcript_hash.is_none() {
            return false;
        }
        if hello.first().copied() != Some(ContentType::Handshake as u8) {
            return false;
        }

        let Some(hello_payload) = hello.get(5..) else {
            return false;
        };

        for i in 0..hello_payload.len().saturating_sub(1) {
            if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x33 {
                return true;
            }
        }

        false
    }

    pub fn wave8_tls_tls13_client_hello_supported_versions_smoke() -> bool {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();
        let Some(hello_payload) = hello.get(5..) else {
            return false;
        };

        for i in 0..hello_payload.len().saturating_sub(1) {
            if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x2B {
                if i + 8 >= hello_payload.len() {
                    return false;
                }
                let ext_len = ((hello_payload[i + 2] as usize) << 8) | hello_payload[i + 3] as usize;
                let versions_len = hello_payload[i + 4] as usize;
                return versions_len >= 4 && ext_len == versions_len + 1;
            }
        }

        false
    }

    pub fn wave8_tls_tls13_client_hello_psk_modes_smoke() -> bool {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();
        let Some(hello_payload) = hello.get(5..) else {
            return false;
        };

        for i in 0..hello_payload.len().saturating_sub(1) {
            if hello_payload[i] == 0x00 && hello_payload[i + 1] == 0x2D {
                return true;
            }
        }

        false
    }

    pub fn wave8_tls_tls13_strip_content_type_smoke() -> bool {
        let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x17];
        let data2 = [0x48, 0x65, 0x17, 0x00, 0x00];
        let data3 = [0x16];
        let data4 = [0x00, 0x00, 0x00];

        let case1 = matches!(TlsConnection::tls13_strip_content_type(&data), Some(v) if v == &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        let case2 = matches!(TlsConnection::tls13_strip_content_type(&data2), Some(v) if v == &[0x48, 0x65]);
        let case3 = matches!(TlsConnection::tls13_strip_content_type(&data3), Some(v) if v.is_empty());
        let case4 = TlsConnection::tls13_strip_content_type(&data4).is_none();

        case1 && case2 && case3 && case4
    }

    pub fn wave8_tls_hmac_sha256_long_key_smoke() -> bool {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        hmac_sha256(&key, data) == expected
    }

    pub fn wave8_tls_hkdf_extract_empty_salt_smoke() -> bool {
        let ikm = [0x0bu8; 22];
        let prk = hkdf_extract(&[], &ikm);
        prk.len() == 32 && prk.iter().any(|&b| b != 0)
    }

    pub fn wave8_tls_hkdf_expand_zero_length_smoke() -> bool {
        let prk = [0x42u8; 32];
        hkdf_expand(&prk, b"test", 0).is_empty()
    }

    pub fn wave8_tls_chacha20_poly1305_auth_failure_smoke() -> bool {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello, world!";

        let (ciphertext, mut tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
        tag[0] ^= 0xFF;

        chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag).is_none()
    }

    pub fn wave8_tls_chacha20_poly1305_roundtrip_smoke() -> bool {
        let key = [0x55u8; 32];
        let nonce = [0xAAu8; 12];
        let aad = b"test aad";
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
        if ciphertext.as_slice() == plaintext {
            return false;
        }

        match chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag) {
            Some(decrypted) => decrypted.as_slice() == plaintext,
            None => false,
        }
    }

    pub fn wave8_tls_chacha20_poly1305_empty_plaintext_smoke() -> bool {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let aad = b"aad only";

        let (ciphertext, tag) = chacha20_poly1305_encrypt(&key, &nonce, aad, &[]);
        if !ciphertext.is_empty() {
            return false;
        }

        match chacha20_poly1305_decrypt(&key, &nonce, aad, &[], &tag) {
            Some(result) => result.is_empty(),
            None => false,
        }
    }

    pub fn wave8_tls_aes_gcm_256_roundtrip_smoke() -> bool {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        let aad = b"aes-256-gcm aad";
        let plaintext = b"AES-256-GCM test payload";

        let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);
        if ciphertext.len() != plaintext.len() || ciphertext.as_slice() == plaintext {
            return false;
        }

        match aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag) {
            Some(decrypted) => decrypted.as_slice() == plaintext,
            None => false,
        }
    }

    pub fn wave8_tls_aes_gcm_corrupted_ciphertext_smoke() -> bool {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"test aad";
        let plaintext = b"test data for corruption";

        let (mut ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, plaintext);
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        aes_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag).is_none()
    }

    pub fn wave8_tls_aes_gcm_empty_plaintext_smoke() -> bool {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"aad only, no payload";

        let (ciphertext, tag) = aes_gcm_encrypt(&key, &nonce, aad, &[]);
        if !ciphertext.is_empty() {
            return false;
        }

        match aes_gcm_decrypt(&key, &nonce, aad, &[], &tag) {
            Some(decrypted) => decrypted.is_empty(),
            None => false,
        }
    }

    pub fn wave8_tls_aes_key_expansion_smoke() -> bool {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let round_keys = aes_key_expansion(&key);
        if round_keys[0] != key {
            return false;
        }
        for i in 0..10 {
            if round_keys[i] == round_keys[i + 1] {
                return false;
            }
        }
        true
    }

    pub fn wave8_tls_derive_master_secret_length_smoke() -> bool {
        let pre_master = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms = derive_master_secret(&pre_master, &client_random, &server_random);
        ms.len() == 48 && ms.iter().any(|&b| b != 0)
    }

    pub fn wave8_tls_derive_key_block_length_smoke() -> bool {
        let master_secret = [0x55u8; 48];
        let server_random = [0xAAu8; 32];
        let client_random = [0xBBu8; 32];

        let kb = derive_key_block(&master_secret, &server_random, &client_random, 40);
        let kb256 = derive_key_block(&master_secret, &server_random, &client_random, 72);

        kb.len() == 40 && kb.iter().any(|&b| b != 0) && kb256.len() == 72
    }

    pub fn wave8_tls_derive_master_secret_deterministic_smoke() -> bool {
        let pre_master = [0x42u8; 48];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms1 = derive_master_secret(&pre_master, &client_random, &server_random);
        let ms2 = derive_master_secret(&pre_master, &client_random, &server_random);
        ms1 == ms2
    }

    pub fn wave8_tls_derive_master_secret_differs_with_input_smoke() -> bool {
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let ms1 = derive_master_secret(&[0x42u8; 48], &client_random, &server_random);
        let ms2 = derive_master_secret(&[0x43u8; 48], &client_random, &server_random);
        ms1 != ms2
    }

    pub fn wave8_tls_tls12_prf_deterministic_smoke() -> bool {
        let secret = b"test secret";
        let label = b"test label";
        let seed = b"test seed";

        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        tls12_prf(secret, label, seed, &mut out1);
        tls12_prf(secret, label, seed, &mut out2);
        out1 == out2
    }

    pub fn wave8_tls_tls12_prf_different_labels_smoke() -> bool {
        let secret = b"test secret";
        let seed = b"test seed";

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        tls12_prf(secret, b"label A", seed, &mut out1);
        tls12_prf(secret, b"label B", seed, &mut out2);
        out1 != out2
    }

    pub fn wave8_tls_hkdf_expand_label_length_smoke() -> bool {
        let secret = [0x42u8; 32];
        let result = hkdf_expand_label(&secret, b"key", b"", 16);
        let result32 = hkdf_expand_label(&secret, b"iv", b"", 12);
        result.len() == 16 && result32.len() == 12
    }

    pub fn wave8_tls_hkdf_expand_label_different_labels_smoke() -> bool {
        let secret = [0x42u8; 32];
        let result1 = hkdf_expand_label(&secret, b"key", b"", 32);
        let result2 = hkdf_expand_label(&secret, b"iv", b"", 32);
        result1 != result2
    }

    pub fn wave8_tls_cipher_suite_helpers_smoke() -> bool {
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
            && CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
            && CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.is_chacha20_poly1305()
            && !CipherSuite::TLS_AES_128_GCM_SHA256.is_chacha20_poly1305()
            && CipherSuite::TLS_AES_128_GCM_SHA256.is_aes_gcm()
            && CipherSuite::TLS_AES_256_GCM_SHA384.is_aes_gcm()
            && CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.is_aes_gcm()
            && !CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_aes_gcm()
            && CipherSuite::TLS_AES_128_GCM_SHA256.key_len() == 16
            && CipherSuite::TLS_AES_256_GCM_SHA384.key_len() == 32
            && CipherSuite::TLS_CHACHA20_POLY1305_SHA256.key_len() == 32
            && CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.iv_len() == 4
            && CipherSuite::TLS_AES_128_GCM_SHA256.iv_len() == 12
            && CipherSuite::TLS_CHACHA20_POLY1305_SHA256.iv_len() == 12
    }

    pub fn wave8_tls_base64_decode_smoke() -> bool {
        let result = base64_decode("SGVsbG8=");
        let empty = base64_decode("");
        matches!(result, Some(ref v) if v.as_slice() == b"Hello")
            && matches!(empty, Some(ref v) if v.is_empty())
    }

    pub fn wave8_tls_tls_version_smoke() -> bool {
        TlsVersion::TLS_1_2.major() == 3
            && TlsVersion::TLS_1_2.minor() == 3
            && TlsVersion::TLS_1_3.major() == 3
            && TlsVersion::TLS_1_3.minor() == 4
            && TlsVersion::TLS_1_0.minor() == 1
    }

    pub fn wave8_tls_cipher_suite_defaults_smoke() -> bool {
        let defaults = CipherSuite::defaults();
        !defaults.is_empty()
            && defaults.contains(&CipherSuite::TLS_AES_128_GCM_SHA256)
            && defaults.contains(&CipherSuite::TLS_AES_256_GCM_SHA384)
            && defaults.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
    }

    pub fn wave8_tls_tls_version_ordering_smoke() -> bool {
        TlsVersion::TLS_1_0 < TlsVersion::TLS_1_1
            && TlsVersion::TLS_1_1 < TlsVersion::TLS_1_2
            && TlsVersion::TLS_1_2 < TlsVersion::TLS_1_3
            && TlsVersion::TLS_1_3 >= TlsVersion::TLS_1_3
    }

    pub fn wave8_tls_generate_random_not_all_zeros_smoke() -> bool {
        qemu_test_set_random_override_seed(0x0123_4567_89AB_CDEF);
        let random = generate_random();
        let ok = random.iter().any(|&b| b != 0);
        qemu_test_clear_random_override();
        ok
    }

    pub fn wave8_tls_generate_random_different_calls_smoke() -> bool {
        qemu_test_set_random_override_seed(0x89AB_CDEF_0123_4567);
        let first = generate_random();
        let second = generate_random();
        qemu_test_clear_random_override();
        first != second
    }

    // ========================================================================
    // Wave8 Phase E: SHA-384 + HMAC-SHA384 テスト
    // ========================================================================

    pub fn wave8_tls_sha384_empty_smoke() -> bool {
        use crate::loader::sha384;
        // SHA-384("") — FIPS 180-4 既知テストベクトル
        let hash = sha384::compute(b"");
        let expected: [u8; 48] = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
            0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
            0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
            0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
            0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
            0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
        ];
        hash == expected
    }

    pub fn wave8_tls_sha384_abc_smoke() -> bool {
        use crate::loader::sha384;
        // SHA-384("abc") — FIPS 180-4 既知テストベクトル
        let hash = sha384::compute(b"abc");
        let expected: [u8; 48] = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
            0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
            0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
            0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        hash == expected
    }

    pub fn wave8_tls_hmac_sha384_rfc4231_case1_smoke() -> bool {
        // RFC 4231 Test Case 1: HMAC-SHA384
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 48] = [
            0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
            0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
            0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
            0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
            0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
            0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
        ];
        hmac_sha384(&key, data) == expected
    }

    pub fn wave8_tls_hmac_sha384_rfc4231_case2_smoke() -> bool {
        // RFC 4231 Test Case 2: HMAC-SHA384
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 48] = [
            0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31,
            0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a, 0x6b, 0x1b,
            0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
            0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e,
            0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7,
            0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49,
        ];
        hmac_sha384(key, data) == expected
    }

    // ========================================================================
    // Wave8 Phase B: P-256 ECDH テスト
    // ========================================================================

    /// P-256 ベースポイントが曲線上にあることを検証 (FIPS 186-4)
    pub fn wave8_tls_p256_point_on_curve_smoke() -> bool {
        use crate::net::ecdh::p256::P256Point;
        let g = P256Point::generator();
        g.is_on_curve()
    }

    /// P-256 [k]G の既知結果照合 (RFC 5903 Section 8.1)
    ///
    /// k = 1 → [1]G = G を検証する。
    pub fn wave8_tls_p256_scalar_mul_base_smoke() -> bool {
        use crate::net::ecdh::p256::{P256Point, scalar_base_mul};
        let g = P256Point::generator();
        let (gx, gy) = match g.to_affine() {
            Some(v) => v,
            None => return false,
        };

        let mut scalar_one = [0u8; 32];
        scalar_one[31] = 1;

        let result = scalar_base_mul(&scalar_one);
        let (rx, ry) = match result.to_affine() {
            Some(v) => v,
            None => return false,
        };

        rx == gx && ry == gy
    }

    /// P-256 ECDH 鍵交換対称性テスト
    pub fn wave8_ecdh_p256_key_exchange_symmetry_smoke() -> bool {
        crate::net::ecdh::qemu_tests::ecdh_p256_key_exchange_symmetry_smoke()
    }

    /// P-256 公開鍵長テスト (65バイト)
    pub fn wave8_ecdh_p256_public_key_length_smoke() -> bool {
        crate::net::ecdh::qemu_tests::ecdh_p256_public_key_length_smoke()
    }

    /// P-256 不正なピア鍵拒否テスト
    pub fn wave8_ecdh_p256_reject_invalid_peer_key_smoke() -> bool {
        crate::net::ecdh::qemu_tests::ecdh_p256_reject_invalid_peer_key_smoke()
    }

    /// P-256 NamedGroupマッピングテスト
    pub fn wave8_ecdh_group_from_named_group_p256_smoke() -> bool {
        crate::net::ecdh::qemu_tests::ecdh_group_from_named_group_p256_smoke()
    }

    pub fn wave8_tls_tls_connection_initial_state_smoke() -> bool {
        let config = TlsConfig::new();
        let conn = TlsConnection::new(config);
        conn.state() == TlsState::Initial && conn.negotiated_version().is_none()
    }

    pub fn wave8_tls_tls_connection_client_hello_smoke() -> bool {
        let config = TlsConfig::new().with_server_name("example.com");
        let mut conn = TlsConnection::new(config);
        let hello = conn.build_client_hello();
        hello.len() >= 3
            && hello[0] == ContentType::Handshake as u8
            && hello[1] == 0x03
            && hello[2] == 0x01
            && conn.state() == TlsState::ClientHelloSent
    }

    pub fn wave8_tls_tls_connection_encrypt_not_established_smoke() -> bool {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        matches!(conn.encrypt(b"hello"), Err(TlsError::NotConnected))
    }

    pub fn wave8_tls_process_handshake_multiple_messages_smoke() -> bool {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let data = tls12_multi_handshake_fixture_server_hello_done_plus_valid_finished();
        conn.process_handshake(&data).is_ok()
            && conn.state() == TlsState::Established
            && conn.handshake_messages.as_slice() == data.as_slice()
    }

    pub fn wave8_tls_process_handshake_truncated_header_smoke() -> bool {
        let config = TlsConfig::new();
        let mut conn = TlsConnection::new(config);
        let data = [2u8, 0, 0];
        matches!(conn.process_handshake(&data), Err(TlsError::DecodeError))
    }

    // ====================================================================
    // Phase C: X.509 DERパース + RSA署名検証 デリゲート
    // ====================================================================

    /// DERパーサー基本テスト: タグ・長さ読み取り
    pub fn wave8_tls_der_parse_tag_length_smoke() -> bool {
        crate::net::x509::qemu_tests::x509_der_parse_tag_length_smoke()
    }

    /// DERパーサーINTEGER読み取りテスト
    pub fn wave8_tls_der_parse_integer_smoke() -> bool {
        crate::net::x509::qemu_tests::x509_der_parse_integer_smoke()
    }

    /// DERパーサーSEQUENCEトラバーサルテスト
    pub fn wave8_tls_der_parse_sequence_smoke() -> bool {
        crate::net::x509::qemu_tests::x509_der_parse_sequence_smoke()
    }

    /// X.509証明書パース基本テスト
    pub fn wave8_tls_x509_parse_self_signed_smoke() -> bool {
        crate::net::x509::qemu_tests::x509_parse_self_signed_smoke()
    }

    /// RSA公開鍵抽出テスト
    pub fn wave8_tls_x509_extract_rsa_pubkey_smoke() -> bool {
        crate::net::x509::qemu_tests::x509_extract_rsa_pubkey_smoke()
    }

    /// 署名アルゴリズムOIDマッピングテスト
    pub fn wave8_tls_x509_signature_algorithm_oid_smoke() -> bool {
        crate::net::x509::qemu_tests::x509_signature_algorithm_oid_smoke()
    }

    /// 小さな値のモジュラ冪乗テスト
    pub fn wave8_tls_rsa_modexp_small_smoke() -> bool {
        crate::net::rsa::qemu_tests::rsa_modexp_small_smoke()
    }

    /// 256ビット決定論的モジュラ冪乗テスト
    pub fn wave8_tls_rsa_modexp_medium_smoke() -> bool {
        crate::net::rsa::qemu_tests::rsa_modexp_medium_smoke()
    }

    /// PKCS#1 v1.5 署名検証テスト
    pub fn wave8_tls_rsa_pkcs1_verify_smoke() -> bool {
        crate::net::rsa::qemu_tests::rsa_pkcs1_verify_smoke()
    }

    /// PKCS#1 v1.5 不正署名拒否テスト
    pub fn wave8_tls_rsa_pkcs1_verify_bad_sig_smoke() -> bool {
        crate::net::rsa::qemu_tests::rsa_pkcs1_verify_bad_sig_smoke()
    }

    /// BigUint 乗算・除算ラウンドトリップテスト
    pub fn wave8_tls_rsa_biguint_mul_div_smoke() -> bool {
        crate::net::rsa::qemu_tests::rsa_biguint_mul_div_smoke()
    }

}
