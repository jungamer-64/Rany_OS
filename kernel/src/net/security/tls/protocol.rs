// ============================================================================
// kernel/src/net/security/tls/protocol.rs - TLS 1.3 protocol primitives
// ============================================================================

use arrayvec::ArrayVec;

use super::config::TLS_CIPHER_SUITES_CAPACITY;

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
pub struct CipherSuite(pub u16);

impl CipherSuite {
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);

    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(Self::TLS_AES_128_GCM_SHA256),
            0x1302 => Some(Self::TLS_AES_256_GCM_SHA384),
            0x1303 => Some(Self::TLS_CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    pub const fn is_chacha20_poly1305(self) -> bool {
        matches!(self.0, 0x1303)
    }

    pub const fn is_aes_gcm(self) -> bool {
        matches!(self.0, 0x1301 | 0x1302)
    }

    pub const fn key_len(self) -> usize {
        match self.0 {
            0x1301 => 16,
            0x1302 | 0x1303 => 32,
            _ => 16,
        }
    }

    pub const fn iv_len(self) -> usize {
        12
    }

    pub fn defaults() -> ArrayVec<Self, TLS_CIPHER_SUITES_CAPACITY> {
        let mut defaults = ArrayVec::new();
        defaults.push(Self::TLS_AES_128_GCM_SHA256);
        defaults.push(Self::TLS_AES_256_GCM_SHA384);
        defaults.push(Self::TLS_CHACHA20_POLY1305_SHA256);
        defaults
    }

    pub const fn uses_sha384(self) -> bool {
        matches!(self.0, 0x1302)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    pub const SECP256R1: Self = Self(0x0017);
    pub const SECP384R1: Self = Self(0x0018);
    pub const X25519: Self = Self(0x001D);
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
