// ============================================================================
// kernel/src/net/security/tls/credentials.rs - TLS credential and key material types
// ============================================================================

use crate::net::payload::{OwnedPayloadRange, PacketPayloadBuilder};
use kernel_api::resource::net::PacketPayload;

/// 証明書
#[derive(Debug)]
pub struct Certificate {
    pub der: OwnedPayloadRange,
}

impl Certificate {
    pub fn from_der_payload(der: PacketPayload) -> Self {
        Self {
            der: OwnedPayloadRange::from_payload(der),
        }
    }

    pub fn from_der_bytes(der: &[u8]) -> Option<Self> {
        let mut builder = PacketPayloadBuilder::new();
        builder.push_bytes(der)?;
        Some(Self::from_der_payload(builder.build()))
    }

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
    pub der: OwnedPayloadRange,
    pub(crate) key_type: KeyType,
}

/// 鍵タイプ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
}

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

/// サーバー証明書から抽出した公開鍵情報
#[derive(Debug)]
pub(crate) enum ServerPublicKey {
    Rsa {
        modulus: OwnedPayloadRange,
        exponent: OwnedPayloadRange,
    },
    EcdsaP256 { point: OwnedPayloadRange },
    EcdsaP384 { point: OwnedPayloadRange },
}
