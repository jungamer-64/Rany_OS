// ============================================================================
// kernel/src/net/security/tls/credentials.rs - TLS credential and key material types
// ============================================================================

use crate::net::security::x509::CertificateSpan;
use arrayvec::ArrayVec;

/// A process-lifetime encoded trust anchor. Received certificates borrow
/// their encoding from the retained handshake payload.
#[derive(Debug)]
pub struct Certificate(&'static [u8]);

impl Certificate {
    pub fn from_static_der(der: &'static [u8]) -> Option<Self> {
        (!der.is_empty()).then_some(Self(der))
    }

    pub(crate) fn der_span(&self) -> CertificateSpan<'_> {
        CertificateSpan::from_bytes(self.0)
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
