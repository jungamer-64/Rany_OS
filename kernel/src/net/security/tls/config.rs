// ============================================================================
// kernel/src/net/security/tls/config.rs - TLS configuration types
// ============================================================================

use arrayvec::{ArrayString, ArrayVec};

use super::credentials::Certificate;
use super::protocol::{CipherSuite, NamedGroup, SignatureScheme};

pub(crate) const TLS_CIPHER_SUITES_CAPACITY: usize = 16;
pub(crate) const TLS_SIGNATURE_SCHEMES_CAPACITY: usize = 16;
pub(crate) const TLS_NAMED_GROUPS_CAPACITY: usize = 8;
pub(crate) const TLS_ALPN_PROTOCOLS_CAPACITY: usize = 8;
pub(crate) const TLS_SERVER_NAME_CAPACITY: usize = 253;
pub(crate) const TLS_CA_CERTS_CAPACITY: usize = 192;
pub(crate) const TLS_CERT_CHAIN_CAPACITY: usize = 16;

/// Server Name Indication
#[derive(Clone, Debug)]
pub(crate) struct ServerNameList {
    pub names: ArrayVec<ServerName, TLS_ALPN_PROTOCOLS_CAPACITY>,
}

/// サーバー名
#[derive(Clone, Debug)]
pub(crate) struct ServerName {
    pub name_type: u8,
    pub name: ArrayString<TLS_SERVER_NAME_CAPACITY>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsConfigError {
    NameTooLong,
    TooManyAlpnProtocols,
    AlpnProtocolTooLong,
}

/// TLS設定
#[derive(Debug)]
pub struct TlsConfig {
    pub cipher_suites: ArrayVec<CipherSuite, TLS_CIPHER_SUITES_CAPACITY>,
    pub signature_schemes: ArrayVec<SignatureScheme, TLS_SIGNATURE_SCHEMES_CAPACITY>,
    pub named_groups: ArrayVec<NamedGroup, TLS_NAMED_GROUPS_CAPACITY>,
    pub alpn_protocols: ArrayVec<ArrayString<255>, TLS_ALPN_PROTOCOLS_CAPACITY>,
    pub server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
    pub ca_certs: ArrayVec<Certificate, TLS_CA_CERTS_CAPACITY>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        let mut signature_schemes = ArrayVec::new();
        signature_schemes.push(SignatureScheme::ECDSA_SECP256R1_SHA256);
        signature_schemes.push(SignatureScheme::ECDSA_SECP384R1_SHA384);
        signature_schemes.push(SignatureScheme::RSA_PSS_RSAE_SHA256);

        let mut named_groups = ArrayVec::new();
        named_groups.push(NamedGroup::X25519);
        named_groups.push(NamedGroup::SECP256R1);
        named_groups.push(NamedGroup::SECP384R1);

        Self {
            cipher_suites: CipherSuite::defaults(),
            signature_schemes,
            named_groups,
            alpn_protocols: ArrayVec::new(),
            server_name: None,
            ca_certs: ArrayVec::new(),
        }
    }
}

impl TlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_server_name(mut self, name: &str) -> Result<Self, TlsConfigError> {
        let mut server_name = ArrayString::new();
        server_name
            .try_push_str(name)
            .map_err(|_| TlsConfigError::NameTooLong)?;
        self.server_name = Some(server_name);
        Ok(self)
    }

    pub fn with_alpn(mut self, protocols: &[&str]) -> Result<Self, TlsConfigError> {
        let mut alpn_protocols = ArrayVec::new();
        for protocol in protocols {
            let mut entry = ArrayString::new();
            entry
                .try_push_str(protocol)
                .map_err(|_| TlsConfigError::AlpnProtocolTooLong)?;
            alpn_protocols
                .try_push(entry)
                .map_err(|_| TlsConfigError::TooManyAlpnProtocols)?;
        }
        self.alpn_protocols = alpn_protocols;
        Ok(self)
    }
}
