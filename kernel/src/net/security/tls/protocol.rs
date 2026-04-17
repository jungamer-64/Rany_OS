// ============================================================================
// tls/protocol.rs - TLS protocol primitives
// ============================================================================

use arrayvec::ArrayVec;

use super::config::TLS_CIPHER_SUITES_CAPACITY;

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

/// 暗号スイート
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0x009C);
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0x009D);
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02F);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC030);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02B);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC02C);
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCA8);
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Self = Self(0xCCA9);

    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);

    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x002F);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Self = Self(0x0035);
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0x003C);
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: Self = Self(0x003D);
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Self = Self(0xC013);
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Self = Self(0xC014);
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Self = Self(0xC027);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Self = Self(0xC009);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Self = Self(0xC00A);

    pub fn is_chacha20_poly1305(&self) -> bool {
        matches!(self.0, 0xCCA8 | 0xCCA9 | 0x1303)
    }

    pub fn is_aes_gcm(&self) -> bool {
        matches!(
            self.0,
            0x009C | 0x009D | 0xC02F | 0xC030 | 0xC02B | 0xC02C | 0x1301 | 0x1302
        )
    }

    pub fn key_len(&self) -> usize {
        match self.0 {
            0x009C | 0xC02F | 0xC02B | 0x1301 => 16,
            0x009D | 0xC030 | 0xC02C | 0x1302 => 32,
            0xCCA8 | 0xCCA9 | 0x1303 => 32,
            0x002F | 0x003C | 0xC013 | 0xC027 | 0xC009 => 16,
            0x0035 | 0x003D | 0xC014 | 0xC00A => 32,
            _ => 16,
        }
    }

    pub fn iv_len(&self) -> usize {
        match self.0 {
            0x009C | 0x009D | 0xC02F | 0xC030 | 0xC02B | 0xC02C => 4,
            0x1301 | 0x1302 | 0xCCA8 | 0xCCA9 | 0x1303 => 12,
            0x002F | 0x0035 | 0x003C | 0x003D | 0xC013 | 0xC014 | 0xC027 | 0xC009 | 0xC00A => 16,
            _ => 4,
        }
    }

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

    pub fn is_cbc(&self) -> bool {
        matches!(
            self.0,
            0x002F | 0x0035 | 0x003C | 0x003D | 0xC013 | 0xC014 | 0xC027 | 0xC009 | 0xC00A
        )
    }

    pub fn is_rsa_key_transport(&self) -> bool {
        matches!(self.0, 0x002F | 0x0035 | 0x003C | 0x003D | 0x009C | 0x009D)
    }

    pub fn mac_key_len(&self) -> usize {
        match self.0 {
            0x002F | 0x0035 | 0xC013 | 0xC014 | 0xC009 | 0xC00A => 20,
            0x003C | 0x003D | 0xC027 => 32,
            _ => 0,
        }
    }

    pub fn mac_len(&self) -> usize {
        self.mac_key_len()
    }

    pub fn uses_sha1_mac(&self) -> bool {
        matches!(self.0, 0x002F | 0x0035 | 0xC013 | 0xC014 | 0xC009 | 0xC00A)
    }

    pub fn cbc_iv_len(&self) -> usize {
        if self.is_cbc() { 16 } else { 0 }
    }

    pub fn uses_sha384(&self) -> bool {
        matches!(self.0, 0x009D | 0xC030 | 0xC02C | 0x1302)
    }

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

/// コンテントタイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentType {
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
pub(crate) enum HandshakeType {
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
pub(crate) struct RecordHeader {
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

/// アラートレベル
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// アラート説明
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AlertDescription {
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

/// TLS拡張タイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExtensionType(pub u16);

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
