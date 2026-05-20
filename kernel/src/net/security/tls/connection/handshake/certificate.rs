// ============================================================================
// kernel/src/net/security/tls/connection/handshake/certificate.rs
// ============================================================================

use super::super::{TlsConnectionCore, ServerPublicKey};
use crate::net::security::tls::error::{TlsError, TlsResult};
use crate::net::security::x509::{VerifiedServerCertificate, VerifiedServerPublicKey};

impl TlsConnectionCore {
    pub(crate) fn install_verified_server_certificate(
        &mut self,
        certificate: VerifiedServerCertificate,
    ) -> TlsResult<()> {
        self.handshake_secrets.server_public_key = Some(match certificate.public_key {
            VerifiedServerPublicKey::Rsa { modulus, exponent } => {
                ServerPublicKey::rsa(modulus.as_slice(), exponent.as_slice())
                    .ok_or(TlsError::DecodeError)?
            }
            VerifiedServerPublicKey::EcdsaP256 { public_key } => {
                ServerPublicKey::ecdsa_p256(public_key.as_slice()).ok_or(TlsError::DecodeError)?
            }
            VerifiedServerPublicKey::EcdsaP384 { public_key } => {
                ServerPublicKey::ecdsa_p384(public_key.as_slice()).ok_or(TlsError::DecodeError)?
            }
        });
        Ok(())
    }
}
