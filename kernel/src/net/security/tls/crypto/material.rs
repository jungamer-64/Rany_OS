// ============================================================================
// kernel/src/net/security/tls/crypto/material.rs - typed TLS key material
// ============================================================================

use core::{convert::TryInto, marker::PhantomData};

use crate::net::security::tls::{CipherSuite, TlsError, TlsResult};

pub(crate) struct Sha256Hash;
pub(crate) struct Sha384Hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TranscriptHash<Hash, const N: usize> {
    bytes: [u8; N],
    _hash: PhantomData<Hash>,
}

impl<Hash, const N: usize> TranscriptHash<Hash, N> {
    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _hash: PhantomData,
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HandshakeSecret<Hash, const N: usize> {
    bytes: [u8; N],
    _hash: PhantomData<Hash>,
}

impl<Hash, const N: usize> HandshakeSecret<Hash, N> {
    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _hash: PhantomData,
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MasterSecret<Hash, const N: usize> {
    bytes: [u8; N],
    _hash: PhantomData<Hash>,
}

impl<Hash, const N: usize> MasterSecret<Hash, N> {
    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _hash: PhantomData,
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrafficSecret<Hash, const N: usize> {
    bytes: [u8; N],
    _hash: PhantomData<Hash>,
}

impl<Hash, const N: usize> TrafficSecret<Hash, N> {
    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _hash: PhantomData,
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FinishedKey<Hash, const N: usize> {
    bytes: [u8; N],
    _hash: PhantomData<Hash>,
}

impl<Hash, const N: usize> FinishedKey<Hash, N> {
    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _hash: PhantomData,
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AeadNonce([u8; 12]);

impl AeadNonce {
    pub(crate) fn from_iv_and_sequence(iv: &[u8], seq: u64) -> TlsResult<Self> {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv.get(..12).ok_or(TlsError::CryptoError)?);
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        Ok(Self(nonce))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AeadTag([u8; 16]);

impl AeadTag {
    pub(crate) const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) const fn len(self) -> usize {
        self.0.len()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Aes128GcmKey<'a>(&'a [u8; 16]);

impl<'a> Aes128GcmKey<'a> {
    pub(crate) fn from_slice(key: &'a [u8]) -> TlsResult<Self> {
        Ok(Self(key.try_into().map_err(|_| TlsError::CryptoError)?))
    }

    pub(crate) const fn as_bytes(self) -> &'a [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Aes256GcmKey<'a>(&'a [u8; 32]);

impl<'a> Aes256GcmKey<'a> {
    pub(crate) fn from_slice(key: &'a [u8]) -> TlsResult<Self> {
        Ok(Self(key.try_into().map_err(|_| TlsError::CryptoError)?))
    }

    pub(crate) const fn as_bytes(self) -> &'a [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ChaCha20Poly1305Key<'a>(&'a [u8; 32]);

impl<'a> ChaCha20Poly1305Key<'a> {
    pub(crate) fn from_slice(key: &'a [u8]) -> TlsResult<Self> {
        Ok(Self(key.try_into().map_err(|_| TlsError::CryptoError)?))
    }

    pub(crate) const fn as_bytes(self) -> &'a [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TlsAeadKey<'a> {
    Aes128Gcm(Aes128GcmKey<'a>),
    Aes256Gcm(Aes256GcmKey<'a>),
    ChaCha20Poly1305(ChaCha20Poly1305Key<'a>),
}

impl<'a> TlsAeadKey<'a> {
    pub(crate) fn from_cipher_suite(cipher: CipherSuite, key: &'a [u8]) -> TlsResult<Self> {
        match cipher {
            CipherSuite::TLS_AES_128_GCM_SHA256 => {
                Ok(Self::Aes128Gcm(Aes128GcmKey::from_slice(key)?))
            }
            CipherSuite::TLS_AES_256_GCM_SHA384 => {
                Ok(Self::Aes256Gcm(Aes256GcmKey::from_slice(key)?))
            }
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Ok(Self::ChaCha20Poly1305(
                ChaCha20Poly1305Key::from_slice(key)?,
            )),
        }
    }
}
