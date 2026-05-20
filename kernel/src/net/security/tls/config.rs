// ============================================================================
// kernel/src/net/security/tls/config.rs - TLS configuration types
// ============================================================================

use arrayvec::{ArrayString, ArrayVec};

use super::credentials::Certificate;
use super::error::TlsError;
use super::protocol::{CipherSuite, NamedGroup, SignatureScheme};

pub(crate) const TLS_CIPHER_SUITES_CAPACITY: usize = 16;
pub(crate) const TLS_SIGNATURE_SCHEMES_CAPACITY: usize = 16;
pub(crate) const TLS_NAMED_GROUPS_CAPACITY: usize = 8;
pub(crate) const TLS_ALPN_PROTOCOLS_CAPACITY: usize = 8;
pub(crate) const TLS_SERVER_NAME_CAPACITY: usize = 253;
pub(crate) const TLS_CA_CERTS_CAPACITY: usize = 192;
pub(crate) const TLS_CERT_CHAIN_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsClientConfigError {
    NameTooLong,
    TooManyCipherSuites,
    EmptyCipherSuites,
    TooManySignatureSchemes,
    EmptySignatureSchemes,
    TooManyNamedGroups,
    EmptyNamedGroups,
    TooManyAlpnProtocols,
    AlpnProtocolTooLong,
    TooManyTrustAnchors,
}

#[derive(Debug)]
pub struct TlsServerName(ArrayString<TLS_SERVER_NAME_CAPACITY>);

impl TlsServerName {
    pub fn parse(name: &str) -> Result<Self, TlsClientConfigError> {
        let mut server_name = ArrayString::new();
        server_name
            .try_push_str(name)
            .map_err(|_| TlsClientConfigError::NameTooLong)?;
        Ok(Self(server_name))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Debug)]
pub struct AlpnProtocol(ArrayString<255>);

impl AlpnProtocol {
    pub fn parse(protocol: &str) -> Result<Self, TlsClientConfigError> {
        let mut entry = ArrayString::new();
        entry
            .try_push_str(protocol)
            .map_err(|_| TlsClientConfigError::AlpnProtocolTooLong)?;
        Ok(Self(entry))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Debug)]
pub struct AlpnProtocols(ArrayVec<AlpnProtocol, TLS_ALPN_PROTOCOLS_CAPACITY>);

impl AlpnProtocols {
    pub(crate) fn empty() -> Self {
        Self(ArrayVec::new())
    }

    pub fn from_protocols(protocols: &[&str]) -> Result<Self, TlsClientConfigError> {
        let mut entries = ArrayVec::new();
        for protocol in protocols {
            entries
                .try_push(AlpnProtocol::parse(protocol)?)
                .map_err(|_| TlsClientConfigError::TooManyAlpnProtocols)?;
        }
        Ok(Self(entries))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn iter(&self) -> core::slice::Iter<'_, AlpnProtocol> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a AlpnProtocols {
    type Item = &'a AlpnProtocol;
    type IntoIter = core::slice::Iter<'a, AlpnProtocol>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub struct OfferedCipherSuites(ArrayVec<CipherSuite, TLS_CIPHER_SUITES_CAPACITY>);

impl OfferedCipherSuites {
    pub fn from_slice(suites: &[CipherSuite]) -> Result<Self, TlsClientConfigError> {
        if suites.is_empty() {
            return Err(TlsClientConfigError::EmptyCipherSuites);
        }
        let mut offered = ArrayVec::new();
        for suite in suites {
            offered
                .try_push(*suite)
                .map_err(|_| TlsClientConfigError::TooManyCipherSuites)?;
        }
        Ok(Self(offered))
    }

    pub(crate) fn defaults() -> Self {
        Self::from_slice(&[
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        ])
        .expect("default TLS cipher suites fit the fixed capacity")
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn iter(&self) -> core::slice::Iter<'_, CipherSuite> {
        self.0.iter()
    }

    pub(crate) fn contains(&self, cipher: CipherSuite) -> bool {
        self.0.contains(&cipher)
    }

    pub(crate) fn negotiate_wire(&self, wire: u16) -> Result<NegotiatedCipherSuite, TlsError> {
        let cipher = CipherSuite::from_wire(wire).ok_or(TlsError::UnsupportedCipherSuite)?;
        if !self.contains(cipher) {
            return Err(TlsError::UnsolicitedCipherSuite);
        }
        Ok(NegotiatedCipherSuite(cipher))
    }
}

impl<'a> IntoIterator for &'a OfferedCipherSuites {
    type Item = &'a CipherSuite;
    type IntoIter = core::slice::Iter<'a, CipherSuite>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NegotiatedCipherSuite(CipherSuite);

impl NegotiatedCipherSuite {
    pub(crate) const fn cipher(self) -> CipherSuite {
        self.0
    }

    pub(crate) const fn key_len(self) -> usize {
        self.0.key_len()
    }

    pub(crate) const fn uses_sha384(self) -> bool {
        self.0.uses_sha384()
    }

    pub(crate) const fn is_chacha20_poly1305(self) -> bool {
        self.0.is_chacha20_poly1305()
    }
}

#[derive(Debug)]
pub struct OfferedSignatureSchemes(ArrayVec<SignatureScheme, TLS_SIGNATURE_SCHEMES_CAPACITY>);

impl OfferedSignatureSchemes {
    pub fn from_slice(schemes: &[SignatureScheme]) -> Result<Self, TlsClientConfigError> {
        if schemes.is_empty() {
            return Err(TlsClientConfigError::EmptySignatureSchemes);
        }
        let mut offered = ArrayVec::new();
        for scheme in schemes {
            offered
                .try_push(*scheme)
                .map_err(|_| TlsClientConfigError::TooManySignatureSchemes)?;
        }
        Ok(Self(offered))
    }

    pub(crate) fn defaults() -> Self {
        Self::from_slice(&[
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
        ])
        .expect("default TLS signature schemes fit the fixed capacity")
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn iter(&self) -> core::slice::Iter<'_, SignatureScheme> {
        self.0.iter()
    }

    pub(crate) fn contains(&self, scheme: SignatureScheme) -> bool {
        self.0.contains(&scheme)
    }
}

impl<'a> IntoIterator for &'a OfferedSignatureSchemes {
    type Item = &'a SignatureScheme;
    type IntoIter = core::slice::Iter<'a, SignatureScheme>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub struct OfferedNamedGroups(ArrayVec<NamedGroup, TLS_NAMED_GROUPS_CAPACITY>);

impl OfferedNamedGroups {
    pub fn from_slice(groups: &[NamedGroup]) -> Result<Self, TlsClientConfigError> {
        if groups.is_empty() {
            return Err(TlsClientConfigError::EmptyNamedGroups);
        }
        let mut offered = ArrayVec::new();
        for group in groups {
            offered
                .try_push(*group)
                .map_err(|_| TlsClientConfigError::TooManyNamedGroups)?;
        }
        Ok(Self(offered))
    }

    pub(crate) fn defaults() -> Self {
        Self::from_slice(&[
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
        ])
        .expect("default TLS named groups fit the fixed capacity")
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn iter(&self) -> core::slice::Iter<'_, NamedGroup> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a OfferedNamedGroups {
    type Item = &'a NamedGroup;
    type IntoIter = core::slice::Iter<'a, NamedGroup>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub struct TlsTrustAnchors(ArrayVec<Certificate, TLS_CA_CERTS_CAPACITY>);

impl TlsTrustAnchors {
    pub(crate) fn empty() -> Self {
        Self(ArrayVec::new())
    }

    pub(crate) fn push(&mut self, cert: Certificate) -> Result<(), TlsClientConfigError> {
        self.0
            .try_push(cert)
            .map_err(|_| TlsClientConfigError::TooManyTrustAnchors)
    }

    pub(crate) fn iter(&self) -> core::slice::Iter<'_, Certificate> {
        self.0.iter()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// TLS 1.3 client configuration.
#[derive(Debug)]
pub struct TlsClientConfig {
    pub(crate) cipher_suites: OfferedCipherSuites,
    pub(crate) signature_schemes: OfferedSignatureSchemes,
    pub(crate) named_groups: OfferedNamedGroups,
    pub(crate) alpn_protocols: AlpnProtocols,
    pub(crate) server_name: Option<TlsServerName>,
    pub(crate) trust_anchors: TlsTrustAnchors,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            cipher_suites: OfferedCipherSuites::defaults(),
            signature_schemes: OfferedSignatureSchemes::defaults(),
            named_groups: OfferedNamedGroups::defaults(),
            alpn_protocols: AlpnProtocols::empty(),
            server_name: None,
            trust_anchors: TlsTrustAnchors::empty(),
        }
    }
}

impl TlsClientConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_server_name(mut self, name: &str) -> Result<Self, TlsClientConfigError> {
        self.server_name = Some(TlsServerName::parse(name)?);
        Ok(self)
    }

    pub fn with_alpn(mut self, protocols: &[&str]) -> Result<Self, TlsClientConfigError> {
        self.alpn_protocols = AlpnProtocols::from_protocols(protocols)?;
        Ok(self)
    }

    pub fn with_cipher_suites(
        mut self,
        suites: &[CipherSuite],
    ) -> Result<Self, TlsClientConfigError> {
        self.cipher_suites = OfferedCipherSuites::from_slice(suites)?;
        Ok(self)
    }

    pub fn with_signature_schemes(
        mut self,
        schemes: &[SignatureScheme],
    ) -> Result<Self, TlsClientConfigError> {
        self.signature_schemes = OfferedSignatureSchemes::from_slice(schemes)?;
        Ok(self)
    }

    pub fn with_named_groups(
        mut self,
        groups: &[NamedGroup],
    ) -> Result<Self, TlsClientConfigError> {
        self.named_groups = OfferedNamedGroups::from_slice(groups)?;
        Ok(self)
    }

    pub fn with_trust_anchor(mut self, cert: Certificate) -> Result<Self, TlsClientConfigError> {
        self.trust_anchors.push(cert)?;
        Ok(self)
    }
}
