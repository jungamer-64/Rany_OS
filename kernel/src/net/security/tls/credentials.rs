// ============================================================================
// kernel/src/net/security/tls/credentials.rs - TLS credential and key material types
// ============================================================================

use crate::net::payload::PayloadSpanRef;
use alloc::string::String;
use alloc::vec::Vec;
use arrayvec::ArrayVec;
use kernel_api::resource::net::PacketPayload;

/// 証明書
#[derive(Debug)]
pub struct Certificate {
    pub der: PacketPayload,
}

impl Certificate {
    pub fn from_der_payload(der: PacketPayload) -> Self {
        Self { der }
    }

    pub fn from_der_bytes(der: &[u8]) -> Option<Self> {
        Some(Self::from_der_payload(store_tls_bytes(der)?))
    }

    pub fn from_pem(pem: &str) -> Option<Self> {
        let mut in_cert = false;
        let mut encoded = String::new();

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

        Some(Self::from_der_payload(base64_decode_payload(&encoded)?))
    }

    pub(crate) fn der_span(&self) -> PayloadSpanRef<'_> {
        PayloadSpanRef::from_payload(&self.der)
    }
}

pub(crate) fn base64_decode_payload(input: &str) -> Option<PacketPayload> {
    let mut decoded = Vec::new();
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
                decoded.extend_from_slice(&chunk);
                chunk_len = 0;
            }
        }
    }

    if chunk_len > 0 {
        decoded.extend_from_slice(&chunk[..chunk_len]);
    }

    store_tls_bytes(&decoded)
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

fn store_tls_key_material(parts: &[&[u8]]) -> Option<PacketPayload> {
    let total_len = parts
        .iter()
        .try_fold(0usize, |acc, part| acc.checked_add(part.len()))?;
    if total_len == 0 {
        return Some(PacketPayload::default());
    }
    let mut packet = crate::net::payload::alloc_packet_with_headroom(total_len, 0)?;
    let mut offset = 0usize;
    for part in parts {
        let end = offset.checked_add(part.len())?;
        packet.data_mut()[offset..end].copy_from_slice(part);
        offset = end;
    }
    Some(PacketPayload::single(packet))
}

fn store_tls_bytes(data: &[u8]) -> Option<PacketPayload> {
    store_tls_key_material(&[data])
}
