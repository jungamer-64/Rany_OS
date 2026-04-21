// ============================================================================
// kernel/src/net/security/tls/credentials.rs - TLS credential and key material types
// ============================================================================

use crate::net::payload::{PayloadRange, PayloadSpanRef};
use alloc::vec::Vec;
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
        let mut decoded = Vec::new();
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
                            decoded.extend_from_slice(&chunk);
                            chunk_len = 0;
                        }
                    }
                }
            }
        }

        if chunk_len > 0 {
            decoded.extend_from_slice(&chunk[..chunk_len]);
        }
        Some(Self::from_der_payload(store_tls_bytes(&decoded)?))
    }

    pub(crate) fn der_span(&self) -> PayloadSpanRef<'_> {
        PayloadSpanRef::from_payload(&self.der)
    }

    pub(crate) fn der_contiguous_slice(&self) -> Option<&[u8]> {
        self.der_span().as_contiguous_slice()
    }
}

/// 秘密鍵
#[derive(Debug)]
pub struct PrivateKey {
    pub der: PacketPayload,
    pub(crate) key_type: KeyType,
}

/// 鍵タイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
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
        material: PacketPayload,
        modulus: PayloadRange,
        exponent: PayloadRange,
    },
    EcdsaP256 {
        material: PacketPayload,
        point: PayloadRange,
    },
    EcdsaP384 {
        material: PacketPayload,
        point: PayloadRange,
    },
}

impl ServerPublicKey {
    pub(crate) fn rsa(modulus: &[u8], exponent: &[u8]) -> Option<Self> {
        let material = store_tls_key_material(&[modulus, exponent])?;
        let modulus_range = PayloadRange::new(0, modulus.len());
        let exponent_range = PayloadRange::new(modulus.len(), exponent.len());
        Some(Self::Rsa {
            material,
            modulus: modulus_range,
            exponent: exponent_range,
        })
    }

    pub(crate) fn ecdsa_p256(point: &[u8]) -> Option<Self> {
        let material = store_tls_key_material(&[point])?;
        Some(Self::EcdsaP256 {
            material,
            point: PayloadRange::new(0, point.len()),
        })
    }

    pub(crate) fn ecdsa_p384(point: &[u8]) -> Option<Self> {
        let material = store_tls_key_material(&[point])?;
        Some(Self::EcdsaP384 {
            material,
            point: PayloadRange::new(0, point.len()),
        })
    }

    pub(crate) fn rsa_components(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::Rsa {
                material,
                modulus,
                exponent,
            } => Some((
                modulus.span(material)?.as_contiguous_slice()?,
                exponent.span(material)?.as_contiguous_slice()?,
            )),
            _ => None,
        }
    }

    pub(crate) fn ecdsa_p256_point(&self) -> Option<&[u8]> {
        match self {
            Self::EcdsaP256 { material, point } => point.span(material)?.as_contiguous_slice(),
            _ => None,
        }
    }

    pub(crate) fn ecdsa_p384_point(&self) -> Option<&[u8]> {
        match self {
            Self::EcdsaP384 { material, point } => point.span(material)?.as_contiguous_slice(),
            _ => None,
        }
    }
}

fn store_tls_key_material(parts: &[&[u8]]) -> Option<PacketPayload> {
    let total_len = parts
        .iter()
        .try_fold(0usize, |acc, part| acc.checked_add(part.len()))?;
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
