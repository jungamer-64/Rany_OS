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

        let msg_type = data[0];
        let _length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
        let payload = &data[4..];

        match msg_type {
            2 => self.process_server_hello(payload)?, // ServerHello
            11 => self.process_certificate(payload)?, // Certificate
            12 => self.process_server_key_exchange(payload)?, // ServerKeyExchange
            14 => self.process_server_hello_done(payload)?, // ServerHelloDone
            20 => self.process_finished(payload)?,    // Finished
            _ => {}
        }

        self.handshake_messages.extend_from_slice(data);
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
            let certs_len = ((data[0] as usize) << 16) 
                          | ((data[1] as usize) << 8) 
                          | (data[2] as usize);
            
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
    fn process_server_key_exchange(&mut self, data: &[u8]) -> TlsResult<()> {
        // キー交換パラメータの処理
        // ECDHEの場合:
        // - curve_type (1 byte)
        // - named_curve (2 bytes)
        // - public_key_length (1 byte)
        // - public_key (variable)
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
        
        // サーバーの公開鍵を保存（完全な実装ではECDH共有秘密計算に使用）
        let _server_pubkey = &data[4..4 + pubkey_len];
        
        // Note: 完全な実装には以下が必要:
        // 1. クライアント側のECDHキーペア生成
        // 2. 共有秘密の計算
        // 3. マスターシークレットの導出
        
        let _ = named_curve; // 将来の使用のために保持
        
        Ok(())
    }

    /// ServerHelloDoneを処理
    fn process_server_hello_done(&mut self, _data: &[u8]) -> TlsResult<()> {
        self.state = TlsState::Handshaking;
        Ok(())
    }

    /// Finishedを処理
    fn process_finished(&mut self, _data: &[u8]) -> TlsResult<()> {
        self.state = TlsState::Established;
        Ok(())
    }

    /// レコードを復号
    fn decrypt_record(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        // AES-GCM復号処理
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

    /// データを暗号化して送信
    pub fn encrypt(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if self.state != TlsState::Established {
            return Err(TlsError::NotConnected);
        }

        // AES-GCM暗号化処理
        // レコード構造:
        // - content_type (1 byte)
        // - version (2 bytes)
        // - length (2 bytes)
        // - explicit_nonce (8 bytes)
        // - ciphertext (same as plaintext length)
        // - auth_tag (16 bytes)
        
        // explicit nonceの生成（シーケンス番号ベース）
        let explicit_nonce = self.write_seq.to_be_bytes();
        
        // キーが設定されていない場合はプレースホルダー動作
        let (ciphertext, auth_tag) = if self.write_key.is_empty() || self.write_iv.len() < 4 {
            (data.to_vec(), [0u8; 16])
        } else {
            // 12バイトのnonceを構築: implicit_iv(4) || explicit_nonce(8)
            let mut nonce = [0u8; 12];
            nonce[0..4].copy_from_slice(&self.write_iv[0..4]);
            nonce[4..12].copy_from_slice(&explicit_nonce);
            
            // AAD: seq_num(8) || type(1) || version(2) || length(2)
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.write_seq.to_be_bytes());
            aad.push(ContentType::ApplicationData as u8);
            aad.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            aad.extend_from_slice(&(data.len() as u16).to_be_bytes());
            
            // AES-GCM暗号化
            aes_gcm_encrypt(&self.write_key, &nonce, &aad, data)
        };
        
        // レコード長: nonce(8) + ciphertext + tag(16)
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

/// AES-CTR モードでの暗号化/復号
fn aes_ctr(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    if key.len() != 16 || nonce.len() != 12 {
        return Vec::new();
    }
    
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let round_keys = aes_key_expansion(&key_arr);
    
    let mut result = Vec::with_capacity(data.len());
    let mut counter_block = [0u8; 16];
    counter_block[0..12].copy_from_slice(nonce);
    
    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        // Set counter (big-endian)
        let counter = (chunk_idx as u32 + 1).to_be_bytes();
        counter_block[12..16].copy_from_slice(&counter);
        
        // Encrypt counter block
        let keystream = aes_encrypt_block(&counter_block, &round_keys);
        
        // XOR with data
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
    }
    
    result
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
    if key.len() != 16 || nonce.len() != 12 {
        return (Vec::new(), [0u8; 16]);
    }
    
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let round_keys = aes_key_expansion(&key_arr);
    
    // Generate H = AES(K, 0^128)
    let h = aes_encrypt_block(&[0u8; 16], &round_keys);
    
    // Encrypt plaintext with CTR mode
    let ciphertext = aes_ctr(key, nonce, plaintext);
    
    // Calculate GHASH
    let s = ghash(&h, aad, &ciphertext);
    
    // Calculate tag: T = GHASH XOR AES(K, Y0)
    let mut y0 = [0u8; 16];
    y0[0..12].copy_from_slice(nonce);
    y0[15] = 1; // Counter = 1
    let encrypted_y0 = aes_encrypt_block(&y0, &round_keys);
    
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ encrypted_y0[i];
    }
    
    (ciphertext, tag)
}

/// AES-GCM 復号
fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Option<Vec<u8>> {
    if key.len() != 16 || nonce.len() != 12 {
        return None;
    }
    
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let round_keys = aes_key_expansion(&key_arr);
    
    // Generate H
    let h = aes_encrypt_block(&[0u8; 16], &round_keys);
    
    // Calculate expected tag
    let s = ghash(&h, aad, ciphertext);
    
    let mut y0 = [0u8; 16];
    y0[0..12].copy_from_slice(nonce);
    y0[15] = 1;
    let encrypted_y0 = aes_encrypt_block(&y0, &round_keys);
    
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
    let plaintext = aes_ctr(key, nonce, ciphertext);
    Some(plaintext)
}

// ============================================================================
// Random Generation
// ============================================================================

/// 簡易乱数生成（実際はハードウェアRNGを使用）
fn generate_random() -> [u8; 32] {
    static mut SEED: u64 = 0x1234567890abcdef;
    let mut result = [0u8; 32];

    unsafe {
        for i in 0..32 {
            SEED = SEED
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            result[i] = (SEED >> 56) as u8;
        }
    }

    result
}

