// ============================================================================
// kernel/src/net/security/tls/credentials.rs - TLS credential and key material types
// ============================================================================

use crate::net::security::x509::CertificateSpan;
use alloc::string::String;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use kernel_api::resource::net::PacketPayload;

/// Immutable encoded material keeps configured bytes or received packets alive
/// through every parsed borrow. Certificate policy establishes validity/trust.
#[derive(Debug)]
pub struct Certificate {
    material: CertificateStorage,
}

#[derive(Debug)]
enum CertificateStorage {
    Bytes(Vec<u8>),
    Packet(PacketPayload),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateDataError {
    Empty,
    InvalidEncoding,
    MetadataAllocation,
}

impl Certificate {
    pub fn from_der_payload(der: PacketPayload) -> Self {
        Self {
            material: CertificateStorage::Packet(der),
        }
    }

    /// Retains configured bytes in CPU-owned storage.
    /// DER validity and trust are established by the certificate policy.
    ///
    /// # Errors
    /// Rejects empty material or metadata allocation failure before publishing
    /// a certificate; the caller retains its input on both outcomes.
    pub fn from_der_bytes(der: &[u8]) -> Result<Self, CertificateDataError> {
        if der.is_empty() {
            return Err(CertificateDataError::Empty);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(der.len())
            .map_err(|_| CertificateDataError::MetadataAllocation)?;
        bytes.extend_from_slice(der);
        Ok(Self {
            material: CertificateStorage::Bytes(bytes),
        })
    }

    /// # Errors
    /// Rejects empty decoded material, invalid base64 digits, or metadata
    /// allocation failure. Rejection leaves the caller's PEM storage intact.
    pub fn from_pem(pem: &str) -> Result<Self, CertificateDataError> {
        let mut in_cert = false;
        let mut encoded = String::new();
        encoded
            .try_reserve(pem.len())
            .map_err(|_| CertificateDataError::MetadataAllocation)?;
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
                    encoded.push(c);
                }
            }
        }
        Ok(Self {
            material: CertificateStorage::Bytes(base64_decode_bytes(&encoded)?),
        })
    }

    pub(crate) fn der_span(&self) -> CertificateSpan<'_> {
        match &self.material {
            CertificateStorage::Bytes(bytes) => CertificateSpan::from_bytes(bytes),
            CertificateStorage::Packet(payload) => CertificateSpan::from_payload(payload),
        }
    }
}

pub(crate) fn base64_decode_bytes(input: &str) -> Result<Vec<u8>, CertificateDataError> {
    let mut decoded = Vec::new();
    decoded
        .try_reserve(input.len())
        .map_err(|_| CertificateDataError::MetadataAllocation)?;
    let mut chunk = [0u8; 3];
    let mut chunk_len = 0usize;
    let mut buf = 0u32;
    let mut bits = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }

        let value = base64_value(c).ok_or(CertificateDataError::InvalidEncoding)? as u32;
        buf = (buf << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            chunk[chunk_len] = (buf >> bits) as u8;
            chunk_len += 1;
            buf &= (1 << bits) - 1;
            if chunk_len == chunk.len() {
                decoded.extend_from_slice(&chunk);
                chunk_len = 0;
            }
        }
    }

    if chunk_len > 0 {
        decoded.extend_from_slice(&chunk[..chunk_len]);
    }

    if decoded.is_empty() {
        return Err(CertificateDataError::Empty);
    }
    Ok(decoded)
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

/// サーバー証明書から抽出した公開鍵情報
#[derive(Debug)]
pub(crate) enum ServerPublicKey {
    Rsa {
        modulus: ArrayVec<u8, 1024>,
        exponent: ArrayVec<u8, 8>,
    },
    EcdsaP256 {
        point: ArrayVec<u8, 65>,
    },
    EcdsaP384 {
        point: ArrayVec<u8, 97>,
    },
}

impl ServerPublicKey {
    pub(crate) fn rsa(modulus: &[u8], exponent: &[u8]) -> Option<Self> {
        let modulus = ArrayVec::try_from(modulus).ok()?;
        let exponent = ArrayVec::try_from(exponent).ok()?;
        Some(Self::Rsa { modulus, exponent })
    }

    pub(crate) fn ecdsa_p256(point: &[u8]) -> Option<Self> {
        Some(Self::EcdsaP256 {
            point: ArrayVec::try_from(point).ok()?,
        })
    }

    pub(crate) fn ecdsa_p384(point: &[u8]) -> Option<Self> {
        Some(Self::EcdsaP384 {
            point: ArrayVec::try_from(point).ok()?,
        })
    }

    pub(crate) fn rsa_components(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::Rsa { modulus, exponent } => Some((modulus.as_slice(), exponent.as_slice())),
            _ => None,
        }
    }

    pub(crate) fn ecdsa_p256_point(&self) -> Option<&[u8]> {
        match self {
            Self::EcdsaP256 { point } => Some(point.as_slice()),
            _ => None,
        }
    }

    pub(crate) fn ecdsa_p384_point(&self) -> Option<&[u8]> {
        match self {
            Self::EcdsaP384 { point } => Some(point.as_slice()),
            _ => None,
        }
    }
}
