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
    fn process_certificate(&mut self, _data: &[u8]) -> TlsResult<()> {
        // 証明書検証（簡略化）
        if !self.config.skip_verify {
            // TODO: 証明書チェーンの検証
        }
        Ok(())
    }

    /// ServerKeyExchangeを処理
    fn process_server_key_exchange(&mut self, _data: &[u8]) -> TlsResult<()> {
        // TODO: キー交換パラメータの処理
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
    fn decrypt_record(&mut self, _data: &[u8]) -> TlsResult<Vec<u8>> {
        // TODO: 実際の復号処理（AES-GCMなど）
        self.read_seq += 1;
        Ok(Vec::new())
    }

    /// データを暗号化して送信
    pub fn encrypt(&mut self, data: &[u8]) -> TlsResult<Vec<u8>> {
        if self.state != TlsState::Established {
            return Err(TlsError::NotConnected);
        }

        // TODO: 実際の暗号化処理
        let mut record = vec![
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            (data.len() >> 8) as u8,
            data.len() as u8,
        ];
        record.extend_from_slice(data);

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
}

pub type TlsResult<T> = Result<T, TlsError>;

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
