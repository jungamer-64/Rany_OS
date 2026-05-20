// ============================================================================
// kernel/src/net/security/tls/protocol.rs - TLS 1.3 protocol primitives
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsVersion;

impl TlsVersion {
    pub const TLS_1_3: Self = Self;
    pub const WIRE: u16 = 0x0304;

    pub const fn major(self) -> u8 {
        0x03
    }

    pub const fn minor(self) -> u8 {
        0x04
    }

    pub const fn to_bytes(self) -> [u8; 2] {
        Self::WIRE.to_be_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
}

impl CipherSuite {
    pub const TLS_AES_128_GCM_SHA256: Self = Self::TlsAes128GcmSha256;
    pub const TLS_AES_256_GCM_SHA384: Self = Self::TlsAes256GcmSha384;
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self::TlsChacha20Poly1305Sha256;

    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(Self::TlsAes128GcmSha256),
            0x1302 => Some(Self::TlsAes256GcmSha384),
            0x1303 => Some(Self::TlsChacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub const fn wire(self) -> u16 {
        match self {
            Self::TlsAes128GcmSha256 => 0x1301,
            Self::TlsAes256GcmSha384 => 0x1302,
            Self::TlsChacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub const fn is_chacha20_poly1305(self) -> bool {
        matches!(self, Self::TlsChacha20Poly1305Sha256)
    }

    pub const fn is_aes_gcm(self) -> bool {
        matches!(self, Self::TlsAes128GcmSha256 | Self::TlsAes256GcmSha384)
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::TlsAes128GcmSha256 => 16,
            Self::TlsAes256GcmSha384 | Self::TlsChacha20Poly1305Sha256 => 32,
        }
    }

    pub const fn iv_len(self) -> usize {
        12
    }

    pub const fn uses_sha384(self) -> bool {
        matches!(self, Self::TlsAes256GcmSha384)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureScheme {
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,
}

impl SignatureScheme {
    pub const ECDSA_SECP256R1_SHA256: Self = Self::EcdsaSecp256r1Sha256;
    pub const ECDSA_SECP384R1_SHA384: Self = Self::EcdsaSecp384r1Sha384;
    pub const RSA_PSS_RSAE_SHA256: Self = Self::RsaPssRsaeSha256;
    pub const RSA_PSS_RSAE_SHA384: Self = Self::RsaPssRsaeSha384;
    pub const RSA_PSS_RSAE_SHA512: Self = Self::RsaPssRsaeSha512;

    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x0403 => Some(Self::EcdsaSecp256r1Sha256),
            0x0503 => Some(Self::EcdsaSecp384r1Sha384),
            0x0804 => Some(Self::RsaPssRsaeSha256),
            0x0805 => Some(Self::RsaPssRsaeSha384),
            0x0806 => Some(Self::RsaPssRsaeSha512),
            _ => None,
        }
    }

    pub const fn wire(self) -> u16 {
        match self {
            Self::EcdsaSecp256r1Sha256 => 0x0403,
            Self::EcdsaSecp384r1Sha384 => 0x0503,
            Self::RsaPssRsaeSha256 => 0x0804,
            Self::RsaPssRsaeSha384 => 0x0805,
            Self::RsaPssRsaeSha512 => 0x0806,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedGroup {
    Secp256r1,
    Secp384r1,
    X25519,
}

impl NamedGroup {
    pub const SECP256R1: Self = Self::Secp256r1;
    pub const SECP384R1: Self = Self::Secp384r1;
    pub const X25519: Self = Self::X25519;

    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(Self::Secp256r1),
            0x0018 => Some(Self::Secp384r1),
            0x001D => Some(Self::X25519),
            _ => None,
        }
    }

    pub const fn wire(self) -> u16 {
        match self {
            Self::Secp256r1 => 0x0017,
            Self::Secp384r1 => 0x0018,
            Self::X25519 => 0x001D,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentType {
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            8 => Some(Self::EncryptedExtensions),
            11 => Some(Self::Certificate),
            13 => Some(Self::CertificateRequest),
            15 => Some(Self::CertificateVerify),
            20 => Some(Self::Finished),
            24 => Some(Self::KeyUpdate),
            254 => Some(Self::MessageHash),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AlertDescription {
    CloseNotify = 0,
}
