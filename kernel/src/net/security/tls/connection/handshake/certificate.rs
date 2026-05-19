// ============================================================================
// kernel/src/net/security/tls/connection/handshake/certificate.rs
// ============================================================================

use super::super::{ExperimentalTlsConnection, ServerPublicKey};
use crate::net::security::tls::error::{TlsError, TlsResult};

impl ExperimentalTlsConnection {
    pub(crate) fn extract_server_public_key_from_spki(
        &mut self,
        spki: crate::net::security::x509::SubjectPublicKeyInfo,
    ) -> TlsResult<()> {
        self.handshake_secrets.server_public_key = Some(match spki {
            crate::net::security::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                ServerPublicKey::rsa(modulus.as_slice(), exponent.as_slice())
                    .ok_or(TlsError::DecodeError)?
            }
            crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                ServerPublicKey::ecdsa_p256(public_key.as_slice()).ok_or(TlsError::DecodeError)?
            }
            crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
                ServerPublicKey::ecdsa_p384(public_key.as_slice()).ok_or(TlsError::DecodeError)?
            }
            crate::net::security::x509::SubjectPublicKeyInfo::Unknown => {
                return Err(TlsError::UnsupportedCipherSuite);
            }
        });
        Ok(())
    }
}
