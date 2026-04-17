// ============================================================================
// tls/types.rs - TLS Type Definitions
// ============================================================================

use crate::net::payload::{OwnedPayloadRange, PacketPayloadBuilder};
use arrayvec::{ArrayString, ArrayVec};
use kernel_api::resource::net::PacketPayload;

pub const TLS_CIPHER_SUITES_CAPACITY: usize = 16;
pub const TLS_SIGNATURE_SCHEMES_CAPACITY: usize = 16;
pub const TLS_NAMED_GROUPS_CAPACITY: usize = 8;
pub const TLS_ALPN_PROTOCOLS_CAPACITY: usize = 8;
pub const TLS_SERVER_NAME_CAPACITY: usize = 253;
pub const TLS_CA_CERTS_CAPACITY: usize = 192;
pub const TLS_CERT_CHAIN_CAPACITY: usize = 16;
pub const TLS_SESSION_CACHE_CAPACITY: usize = 8;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsBytes<const N: usize> {
    len: usize,
    bytes: [u8; N],
}

impl<const N: usize> Default for TlsBytes<N> {
    fn default() -> Self {
        Self {
            len: 0,
            bytes: [0; N],
        }
    }
}

impl<const N: usize> TlsBytes<N> {
    pub const fn new() -> Self {
        Self {
            len: 0,
            bytes: [0; N],
        }
    }

    pub fn from_slice(data: &[u8]) -> Option<Self> {
        let mut output = Self::new();
        output.set(data)?;
        Some(output)
    }

    pub fn set(&mut self, data: &[u8]) -> Option<()> {
        if data.len() > N {
            return None;
        }
        self.bytes.fill(0);
        self.bytes[..data.len()].copy_from_slice(data);
        self.len = data.len();
        Some(())
    }

    pub fn clear(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    pub fn as_mut_storage(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub fn push_byte(&mut self, byte: u8) -> Option<()> {
        if self.len >= N {
            return None;
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Some(())
    }

    pub fn append_slice(&mut self, data: &[u8]) -> Option<()> {
        let new_len = self.len.checked_add(data.len())?;
        if new_len > N {
            return None;
        }
        self.bytes[self.len..new_len].copy_from_slice(data);
        self.len = new_len;
        Some(())
    }

    pub fn append_be_u16(&mut self, value: u16) -> Option<()> {
        self.append_slice(&value.to_be_bytes())
    }

    pub fn append_be_u24(&mut self, value: usize) -> Option<()> {
        if value > 0x00FF_FFFF {
            return None;
        }
        self.append_slice(&[
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ])
    }

    pub fn append_zeroes(&mut self, count: usize) -> Option<()> {
        let new_len = self.len.checked_add(count)?;
        if new_len > N {
            return None;
        }
        self.bytes[self.len..new_len].fill(0);
        self.len = new_len;
        Some(())
    }

    pub fn write_slice(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        let end = offset.checked_add(data.len())?;
        if end > self.len {
            return None;
        }
        self.bytes[offset..end].copy_from_slice(data);
        Some(())
    }

    pub fn set_filled_len(&mut self, len: usize) -> Option<()> {
        if len > N {
            return None;
        }
        self.len = len;
        Some(())
    }

    pub fn copy_into_array<const M: usize>(&self) -> Option<[u8; M]> {
        if self.len != M {
            return None;
        }
        let mut out = [0u8; M];
        out.copy_from_slice(self.as_slice());
        Some(out)
    }
}

impl<const N: usize> AsRef<[u8]> for TlsBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> core::ops::Deref for TlsBytes<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

// ============================================================================
// Cipher Suites
// ============================================================================

/// 暗号スイート
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    // TLS 1.2 AEAD
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
            0x002F | 0x0035 | 0x003C | 0x003D | 0xC013 | 0xC014 | 0xC027 | 0xC009 | 0xC00A => 16,
            // Default to 4
            _ => 4,
        }
    }

    /// デフォルトの暗号スイート一覧
    ///
    /// Security: 前方秘匿性(Forward Secrecy)を持たないRSA鍵転送スイートと
    /// SHA-1ベースのCBCスイートはデフォルトから除外済み。
    pub fn defaults() -> ArrayVec<Self, TLS_CIPHER_SUITES_CAPACITY> {
        let mut defaults = ArrayVec::new();
        defaults.push(Self::TLS_AES_128_GCM_SHA256);
        defaults.push(Self::TLS_AES_256_GCM_SHA384);
        defaults.push(Self::TLS_CHACHA20_POLY1305_SHA256);
        defaults.push(Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        defaults.push(Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        defaults.push(Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        defaults.push(Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        defaults
    }

    /// CBC暗号スイートかどうか
    pub fn is_cbc(&self) -> bool {
        matches!(
            self.0,
            0x002F | 0x0035 | 0x003C | 0x003D | 0xC013 | 0xC014 | 0xC027 | 0xC009 | 0xC00A
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
        matches!(self.0, 0x002F | 0x0035 | 0xC013 | 0xC014 | 0xC009 | 0xC00A)
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
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
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
    pub names: ArrayVec<ServerName, TLS_ALPN_PROTOCOLS_CAPACITY>,
}

/// サーバー名
#[derive(Clone, Debug)]
pub struct ServerName {
    pub name_type: u8, // 0 = hostname
    pub name: ArrayString<TLS_SERVER_NAME_CAPACITY>,
}

// ============================================================================
// TLS Configuration
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsConfigError {
    NameTooLong,
    TooManyAlpnProtocols,
    AlpnProtocolTooLong,
    TooManyCaCerts,
}

/// TLS設定
#[derive(Debug)]
pub struct TlsConfig {
    /// 最小バージョン
    pub min_version: TlsVersion,
    /// 最大バージョン
    pub max_version: TlsVersion,
    /// 暗号スイート
    pub cipher_suites: ArrayVec<CipherSuite, TLS_CIPHER_SUITES_CAPACITY>,
    /// 署名アルゴリズム
    pub signature_schemes: ArrayVec<SignatureScheme, TLS_SIGNATURE_SCHEMES_CAPACITY>,
    /// 名前付きグループ
    pub named_groups: ArrayVec<NamedGroup, TLS_NAMED_GROUPS_CAPACITY>,
    /// ALPN
    pub alpn_protocols: ArrayVec<ArrayString<255>, TLS_ALPN_PROTOCOLS_CAPACITY>,
    /// SNI
    pub server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
    /// セッション再開を許可
    pub enable_session_resumption: bool,
    /// クライアント証明書
    pub client_cert: Option<Certificate>,
    /// クライアント秘密鍵
    pub client_key: Option<PrivateKey>,
    /// CA証明書
    pub ca_certs: ArrayVec<Certificate, TLS_CA_CERTS_CAPACITY>,
    /// 証明書検証を無効化（デバッグ/テスト用）
    ///
    /// # WARNING
    /// このフラグを有効にすると、サーバー証明書の真正性が検証されません。
    /// 本番環境では絶対に使用しないでください。
    /// テスト/QEMUビルドでのみ利用可能です。
    #[cfg(any(test, feature = "qemu-test-export"))]
    pub skip_verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        let mut ca_certs = ArrayVec::new();
        for &(_label, der) in security::root_certs::ROOT_CERTS {
            if let Some(cert) = Certificate::from_der_bytes(der) {
                if ca_certs.try_push(cert).is_err() {
                    break;
                }
            }
        }

        let mut signature_schemes = ArrayVec::new();
        signature_schemes.push(SignatureScheme::ECDSA_SECP256R1_SHA256);
        signature_schemes.push(SignatureScheme::ECDSA_SECP384R1_SHA384);
        signature_schemes.push(SignatureScheme::RSA_PSS_RSAE_SHA256);
        signature_schemes.push(SignatureScheme::RSA_PKCS1_SHA256);

        let mut named_groups = ArrayVec::new();
        named_groups.push(NamedGroup::X25519);
        named_groups.push(NamedGroup::SECP256R1);
        named_groups.push(NamedGroup::SECP384R1);

        Self {
            // Security: Use TLS 1.2 as minimum version.
            // TLS 1.0 and 1.1 are deprecated (RFC 8996).
            min_version: TlsVersion::TLS_1_2,
            max_version: TlsVersion::TLS_1_3,
            cipher_suites: CipherSuite::defaults(),
            signature_schemes,
            named_groups,
            alpn_protocols: ArrayVec::new(),
            server_name: None,
            enable_session_resumption: true,
            client_cert: None,
            client_key: None,
            ca_certs,
            #[cfg(any(test, feature = "qemu-test-export"))]
            skip_verify: false,
        }
    }
}

impl TlsConfig {
    /// 新しいTLS設定を作成
    pub fn new() -> Self {
        Self::default()
    }

    /// 証明書検証をスキップするかどうかを返す
    ///
    /// テスト/QEMU環境でのみskip_verifyフィールドを参照可能。
    /// プロダクションビルドでは常にfalseを返す（検証を必ず実行）。
    pub fn should_skip_verify(&self) -> bool {
        #[cfg(any(test, feature = "qemu-test-export"))]
        {
            self.skip_verify
        }
        #[cfg(not(any(test, feature = "qemu-test-export")))]
        {
            false
        }
    }

    /// サーバー名を設定
    pub fn with_server_name(mut self, name: &str) -> Result<Self, TlsConfigError> {
        let mut server_name = ArrayString::new();
        server_name
            .try_push_str(name)
            .map_err(|_| TlsConfigError::NameTooLong)?;
        self.server_name = Some(server_name);
        Ok(self)
    }

    /// ALPNプロトコルを設定
    pub fn with_alpn(mut self, protocols: &[&str]) -> Result<Self, TlsConfigError> {
        let mut alpn_protocols = ArrayVec::new();
        for protocol in protocols {
            let mut entry = ArrayString::new();
            entry
                .try_push_str(protocol)
                .map_err(|_| TlsConfigError::AlpnProtocolTooLong)?;
            alpn_protocols
                .try_push(entry)
                .map_err(|_| TlsConfigError::TooManyAlpnProtocols)?;
        }
        self.alpn_protocols = alpn_protocols;
        Ok(self)
    }
}

// ============================================================================
// Certificates
// ============================================================================

/// 証明書
#[derive(Debug)]
pub struct Certificate {
    /// DERエンコードされた証明書
    pub der: OwnedPayloadRange,
}

impl Certificate {
    pub fn from_der_payload(der: PacketPayload) -> Self {
        Self {
            der: OwnedPayloadRange::from_payload(der),
        }
    }

    /// DERデータから作成
    pub fn from_der_bytes(der: &[u8]) -> Option<Self> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_bytes(der)?;
        Some(Self::from_der_payload(builder.build()))
    }

    /// PEMから作成（簡易パース）
    pub fn from_pem(pem: &str) -> Option<Self> {
        let mut in_cert = false;
        let mut builder = PacketPayloadBuilder::new();
        let mut chunk = [0u8; 3];
        let mut chunk_len = 0usize;
        let mut buf = 0u32;
        let mut bits = 0u32;

        for line in pem.lines() {
            if line.contains("BEGIN CERTIFICATE") {
                in_cert = true;
            } else if line.contains("END CERTIFICATE") {
                break;
            } else if in_cert {
                for c in line.trim().chars() {
                    if c == '=' {
                        break;
                    }
                    let value = base64_value(c)?;
                    buf = (buf << 6) | value as u32;
                    bits += 6;

                    if bits >= 8 {
                        bits -= 8;
                        chunk[chunk_len] = (buf >> bits) as u8;
                        chunk_len += 1;
                        buf &= (1 << bits) - 1;
                        if chunk_len == chunk.len() {
                            builder.push_bytes(&chunk)?;
                            chunk_len = 0;
                        }
                    }
                }
            }
        }

        if chunk_len > 0 {
            builder.push_bytes(&chunk[..chunk_len])?;
        }
        Some(Self {
            der: OwnedPayloadRange::from_payload(builder.build()),
        })
    }
}

/// 秘密鍵
#[derive(Debug)]
pub struct PrivateKey {
    /// DERエンコードされた秘密鍵
    pub der: OwnedPayloadRange,
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
pub(crate) fn base64_decode_payload(input: &str) -> Option<OwnedPayloadRange> {
    let mut builder = PacketPayloadBuilder::new();
    let mut chunk = [0u8; 3];
    let mut chunk_len = 0usize;
    let mut buf = 0u32;
    let mut bits = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }

        let value = base64_value(c)? as u32;
        buf = (buf << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            chunk[chunk_len] = (buf >> bits) as u8;
            chunk_len += 1;
            buf &= (1 << bits) - 1;
            if chunk_len == chunk.len() {
                builder.push_bytes(&chunk)?;
                chunk_len = 0;
            }
        }
    }

    if chunk_len > 0 {
        builder.push_bytes(&chunk[..chunk_len])?;
    }

    Some(OwnedPayloadRange::from_payload(builder.build()))
}

fn base64_value(c: char) -> Option<u8> {
    match c {
        'A'..='Z' => Some((c as u8) - b'A'),
        'a'..='z' => Some((c as u8) - b'a' + 26),
        '0'..='9' => Some((c as u8) - b'0' + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    }
}

// ============================================================================
// Server Public Key (extracted from X.509 certificate)
// ============================================================================

/// サーバー証明書から抽出した公開鍵情報
#[derive(Debug)]
pub enum ServerPublicKey {
    /// RSA公開鍵 (modulus, exponent をビッグエンディアンで保持)
    Rsa {
        modulus: OwnedPayloadRange,
        exponent: OwnedPayloadRange,
    },
    /// ECDSA P-256公開鍵 (非圧縮ポイント 04 || x || y)
    EcdsaP256 { point: OwnedPayloadRange },
    /// ECDSA P-384公開鍵 (非圧縮ポイント 04 || x || y)
    EcdsaP384 { point: OwnedPayloadRange },
}

/// TLS 1.3 セッションチケット (RFC 8446 Section 4.6.1)
#[derive(Debug)]
pub struct SessionTicket {
    /// チケット有効期間（秒）
    pub lifetime: u32,
    /// チケットエイジ加算値（難読化用）
    pub age_add: u32,
    /// チケットnonce
    pub nonce: OwnedPayloadRange,
    /// チケットデータ
    pub ticket: OwnedPayloadRange,
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
    pub server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
    /// TLSバージョン
    pub version: TlsVersion,
}

/// セッションキャッシュ
#[derive(Clone, Debug)]
pub struct SessionCache {
    entries: ArrayVec<SessionCacheEntry, TLS_SESSION_CACHE_CAPACITY>,
}

impl SessionCache {
    pub fn new() -> Self {
        Self {
            entries: ArrayVec::new(),
        }
    }

    pub fn insert(&mut self, entry: SessionCacheEntry) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.session_id == entry.session_id)
        {
            self.entries.remove(pos);
        } else if self.entries.len() == TLS_SESSION_CACHE_CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn find(&self, session_id: &[u8]) -> Option<&SessionCacheEntry> {
        if session_id.len() != 32 {
            return None;
        }
        self.entries.iter().find(|e| e.session_id == session_id)
    }

    pub fn find_by_server_name(&self, name: &str) -> Option<&SessionCacheEntry> {
        self.entries.iter().rev().find(|entry| {
            entry
                .server_name
                .as_ref()
                .map(|server_name| server_name.as_str())
                == Some(name)
        })
    }
}
