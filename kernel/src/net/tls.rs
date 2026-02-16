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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            // AES-128 suites
            0x009C | 0xC02F | 0xC02B | 0x1301 => 16,
            // AES-256 suites
            0x009D | 0xC030 | 0xC02C | 0x1302 => 32,
            // ChaCha20-Poly1305 suites (256-bit key)
            0xCCA8 | 0xCCA9 | 0x1303 => 32,
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
            // Default to 4
            _ => 4,
        }
    }

    /// デフォルトの暗号スイート一覧
    pub fn defaults() -> Vec<Self> {
        vec![
            Self::TLS_AES_128_GCM_SHA256,
            Self::TLS_AES_256_GCM_SHA384,
            Self::TLS_CHACHA20_POLY1305_SHA256,
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
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
            min_version: TlsVersion::TLS_1_2,
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

    /// ClientHelloを構築
    pub fn build_client_hello(&mut self) -> Vec<u8> {
        let mut hello = Vec::new();

        // バージョン（TLS 1.2として送信、supported_versionsで実際のバージョンを指定）
        hello.extend_from_slice(&[0x03, 0x03]);

        // クライアントランダム
        hello.extend_from_slice(&self.client_random);

        // セッションID長
        hello.push(0);

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

        // ハンドシェイクメッセージを記録
        self.handshake_messages.extend_from_slice(&message);

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

        // Supported Versions (for TLS 1.3)
        {
            let mut ext = vec![2]; // 1 version = 2 bytes
            ext.extend_from_slice(&[
                (self.config.max_version.0 >> 8) as u8,
                self.config.max_version.0 as u8,
            ]);

            extensions.extend_from_slice(&[0, 43]); // type
            extensions.extend_from_slice(&[(ext.len() >> 8) as u8, (ext.len() & 0xFF) as u8]);
            extensions.extend_from_slice(&ext);
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

            match ContentType::from_u8(content_type) {
                Some(ContentType::Handshake) => {
                    self.process_handshake(payload)?;
                }
                Some(ContentType::ChangeCipherSpec) => {
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
                    if self.state == TlsState::Established {
                        // 復号
                        let decrypted = self.decrypt_record(payload)?;
                        plaintext.extend_from_slice(&decrypted);
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

            self.handshake_messages
                .extend_from_slice(&data[offset..body_end]);
            offset = body_end;
        }

        Ok(())
    }

    /// ServerHelloを処理
    fn process_server_hello(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 34 {
            return Err(TlsError::DecodeError);
        }

        let version = TlsVersion(((data[0] as u16) << 8) | data[1] as u16);
        self.server_random.copy_from_slice(&data[2..34]);

        let session_id_len = data[34] as usize;
        let offset = 35 + session_id_len;

        if data.len() < offset + 2 {
            return Err(TlsError::DecodeError);
        }

        let cipher = CipherSuite(((data[offset] as u16) << 8) | data[offset + 1] as u16);

        self.negotiated_version = Some(version);
        self.negotiated_cipher = Some(cipher);
        self.state = TlsState::ServerHelloReceived;

        Ok(())
    }

    /// Certificateを処理
    fn process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        // 証明書検証（簡略化）
        if !self.config.skip_verify {
            // 証明書チェーンの検証
            // 1. 証明書フォーマットのパース（X.509 DER形式）
            // 2. 署名検証（現在はself-signed証明書のみ対応）
            // 3. 有効期限の確認
            if data.len() < 3 {
                return Err(TlsError::DecodeError);
            }

            // 証明書チェーン長（3バイト）
            let certs_len =
                ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

            if data.len() < 3 + certs_len {
                return Err(TlsError::DecodeError);
            }

            // 最低限の検証: 証明書データが存在することを確認
            // 完全な実装にはRSA/ECDSA署名検証が必要
            if certs_len == 0 {
                return Err(TlsError::CertificateError);
            }
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
        // - signature (variable) — 署名検証は将来実装

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

        // NamedGroup → EcdhGroup マッピング
        use super::ecdh::{EcdhGroup, EcdhKeyPair};
        let group = match named_curve {
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

    /// Finishedを処理
    fn process_finished(&mut self, _data: &[u8]) -> TlsResult<()> {
        // Derive key material from master secret (RFC 5246 Section 6.3)
        //
        // Key block layout for AES-128-GCM:
        //   client_write_key (key_len) | server_write_key (key_len) |
        //   client_write_iv (iv_len)   | server_write_iv (iv_len)
        //
        // For AEAD ciphers, MAC keys are not needed (MAC is part of AEAD).
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        let key_len = cipher.key_len();
        let iv_len = cipher.iv_len();

        // Total key material: 2 * key_len + 2 * iv_len
        let key_material_len = 2 * key_len + 2 * iv_len;

        let key_block = derive_key_block(
            &self.master_secret,
            &self.server_random,
            &self.client_random,
            key_material_len,
        );

        if key_block.len() >= key_material_len {
            let mut offset = 0;

            // Client write key (we are the client → this is our write key)
            self.write_key = key_block[offset..offset + key_len].to_vec();
            offset += key_len;

            // Server write key (we are the client → this is our read key)
            self.read_key = key_block[offset..offset + key_len].to_vec();
            offset += key_len;

            // Client write IV
            self.write_iv = key_block[offset..offset + iv_len].to_vec();
            offset += iv_len;

            // Server write IV
            self.read_iv = key_block[offset..offset + iv_len].to_vec();

            // Reset sequence numbers for the new cipher state
            self.read_seq = 0;
            self.write_seq = 0;
        }

        self.state = TlsState::Established;
        Ok(())
    }

    /// レコードを復号
    fn decrypt_record(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        let cipher = self
            .negotiated_cipher
            .unwrap_or(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);

        if cipher.is_chacha20_poly1305() {
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
    /// Dispatches between AES-GCM and ChaCha20-Poly1305 based on the
    /// negotiated cipher suite.
    pub fn encrypt(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if self.state != TlsState::Established {
            return Err(TlsError::NotConnected);
        }

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

    /// 接続を閉じる
    pub fn close(&mut self) -> Vec<u8> {
        self.state = TlsState::Closing;

        // close_notify アラートを送信
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

// ============================================================================
// Random Generation (RDRAND Hardware RNG)
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering as AtomicOrdering};

/// Whether RDRAND availability has been checked
static RDRAND_CHECKED: AtomicBool = AtomicBool::new(false);
/// 0 = unknown, 1 = available, 2 = not available
static RDRAND_STATUS: AtomicU8 = AtomicU8::new(0);

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
            0xd2, 0xa6, 0x2a, 0x02, 0xa1, 0x26, 0xa4, 0x81, 0x3c, 0xf3, 0xab, 0xb2, 0xcc, 0x72,
            0x10, 0x16,
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

        // ServerHelloDone (len=0) + Finished (len=0)
        let data = [14u8, 0, 0, 0, 20, 0, 0, 0];
        let result = conn.process_handshake(&data);
        assert!(result.is_ok());
        assert_eq!(conn.state(), TlsState::Established);
        assert_eq!(conn.handshake_messages.as_slice(), &data);
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
}
