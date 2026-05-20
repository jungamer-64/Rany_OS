// ============================================================================
// kernel/src/net/security/tls/connection/handshake/tls13.rs
// ============================================================================

use arrayvec::ArrayVec;

use super::super::state::TlsConnectionPhase;
use super::super::{
    ContentType, PacketPayload, PayloadSpanRef, TLS_CA_CERTS_CAPACITY, TLS_CERT_CHAIN_CAPACITY,
    TlsConnectionCore, TlsError, TlsResult, ecdh,
};
use crate::net::security::tls::crypto::{
    SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE, tls13_derive_secret, tls13_derive_secret_sha384,
    tls13_derive_traffic_keys, tls13_derive_traffic_keys_sha384, tls13_early_secret,
    tls13_early_secret_sha384, tls13_finished_key, tls13_finished_key_sha384,
    tls13_handshake_secret, tls13_handshake_secret_sha384, tls13_master_secret,
    tls13_master_secret_sha384, tls13_verify_data, tls13_verify_data_sha384,
};
use crate::net::security::tls::protocol::SignatureScheme;

impl TlsConnectionCore {
    pub(crate) fn tls13_derive_handshake_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.negotiated.cipher()?;
        let key_len = cipher.key_len();

        if cipher.uses_sha384() {
            let transcript_ch_sh = self.transcript_hash_sha384();
            let early_secret = tls13_early_secret_sha384(None);
            let handshake_secret = tls13_handshake_secret_sha384(
                &early_secret,
                self.handshake_secrets.pre_master_secret.as_slice(),
            );
            let chs =
                tls13_derive_secret_sha384(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs =
                tls13_derive_secret_sha384(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.tls13.client_hs_traffic_secret = chs;
            self.tls13.server_hs_traffic_secret = shs;

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(
                &shs,
                &mut self.tls13.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys_sha384(
                &chs,
                &mut self.tls13.hs_write_key.as_mut_storage()[..key_len],
                &mut client_iv,
            );
            self.tls13
                .hs_read_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            self.tls13
                .hs_write_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            Self::set_tls_bytes(&mut self.tls13.hs_read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.tls13.hs_write_iv, &client_iv)?;
            self.tls13.hs_read_seq.reset();
            self.tls13.hs_write_seq.reset();
            let ms = tls13_master_secret_sha384(&handshake_secret);
            self.handshake_secrets.master_secret.copy_from_slice(&ms);
        } else {
            let transcript_ch_sh = self.transcript_hash_sha256();
            let early_secret = tls13_early_secret(None);
            let handshake_secret = tls13_handshake_secret(
                &early_secret,
                self.handshake_secrets.pre_master_secret.as_slice(),
            );
            let chs = tls13_derive_secret(&handshake_secret, b"c hs traffic", &transcript_ch_sh);
            let shs = tls13_derive_secret(&handshake_secret, b"s hs traffic", &transcript_ch_sh);
            self.tls13.client_hs_traffic_secret[..32].copy_from_slice(&chs);
            self.tls13.server_hs_traffic_secret[..32].copy_from_slice(&shs);

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(
                &shs,
                &mut self.tls13.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys(
                &chs,
                &mut self.tls13.hs_write_key.as_mut_storage()[..key_len],
                &mut client_iv,
            );
            self.tls13
                .hs_read_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            self.tls13
                .hs_write_key
                .set_filled_len(key_len)
                .ok_or(TlsError::DecodeError)?;
            Self::set_tls_bytes(&mut self.tls13.hs_read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.tls13.hs_write_iv, &client_iv)?;
            self.tls13.hs_read_seq.reset();
            self.tls13.hs_write_seq.reset();
            let ms = tls13_master_secret(&handshake_secret);
            self.handshake_secrets.master_secret[..32].copy_from_slice(&ms);
        }

        self.negotiation.phase = TlsConnectionPhase::encrypted_extensions_pending();
        Ok(())
    }

    pub(super) fn tls13_process_encrypted_extensions(
        &mut self,
        data: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        if data.total_len() < 2 {
            return Err(TlsError::DecodeError);
        }
        let extensions_len = data.read_u16_be(0).ok_or(TlsError::DecodeError)? as usize;
        let mut offset = 2usize;
        let end = offset
            .checked_add(extensions_len)
            .ok_or(TlsError::DecodeError)?;
        if end > data.total_len() {
            return Err(TlsError::DecodeError);
        }
        while offset < end {
            if offset + 4 > end {
                return Err(TlsError::DecodeError);
            }
            let ext_len = data.read_u16_be(offset + 2).ok_or(TlsError::DecodeError)? as usize;
            offset = offset
                .checked_add(4)
                .and_then(|value| value.checked_add(ext_len))
                .ok_or(TlsError::DecodeError)?;
            if offset > end {
                return Err(TlsError::DecodeError);
            }
        }
        self.negotiation.phase = TlsConnectionPhase::certificate_pending();
        Ok(())
    }

    pub(crate) fn tls13_process_certificate_request(
        &mut self,
        _data: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        Err(TlsError::CertificateError)
    }

    pub(super) fn tls13_extract_cert_chain<'a>(
        &self,
        data: PayloadSpanRef<'a>,
    ) -> TlsResult<ArrayVec<PayloadSpanRef<'a>, TLS_CERT_CHAIN_CAPACITY>> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }
        let ctx_len = data.read_u8(0).ok_or(TlsError::DecodeError)? as usize;
        let mut offset = 1usize.checked_add(ctx_len).ok_or(TlsError::DecodeError)?;
        if offset + 3 > data.total_len() {
            return Err(TlsError::DecodeError);
        }
        let certs_len = data.read_u24_be(offset).ok_or(TlsError::DecodeError)? as usize;
        offset += 3;
        let cert_list_end = offset.checked_add(certs_len).ok_or(TlsError::DecodeError)?;
        if cert_list_end > data.total_len() {
            return Err(TlsError::DecodeError);
        }

        let mut certs = ArrayVec::<PayloadSpanRef<'a>, TLS_CERT_CHAIN_CAPACITY>::new();
        while offset < cert_list_end {
            if offset + 3 > cert_list_end {
                return Err(TlsError::DecodeError);
            }
            let cert_len = data.read_u24_be(offset).ok_or(TlsError::DecodeError)? as usize;
            offset += 3;
            let cert_end = offset.checked_add(cert_len).ok_or(TlsError::DecodeError)?;
            if cert_end + 2 > cert_list_end {
                return Err(TlsError::DecodeError);
            }
            certs
                .try_push(
                    data.subspan(offset, cert_len)
                        .ok_or(TlsError::DecodeError)?,
                )
                .map_err(|_| TlsError::CertificateError)?;
            offset = cert_end;
            let ext_len = data.read_u16_be(offset).ok_or(TlsError::DecodeError)? as usize;
            offset = offset
                .checked_add(2)
                .and_then(|value| value.checked_add(ext_len))
                .ok_or(TlsError::DecodeError)?;
            if offset > cert_list_end {
                return Err(TlsError::DecodeError);
            }
        }

        Ok(certs)
    }

    pub(super) fn tls13_process_certificate(&mut self, data: PayloadSpanRef<'_>) -> TlsResult<()> {
        let certs = self.tls13_extract_cert_chain(data)?;
        if certs.is_empty() {
            return Err(TlsError::CertificateError);
        }

        let mut ca_certs = ArrayVec::<PayloadSpanRef<'_>, TLS_CA_CERTS_CAPACITY>::new();
        for cert in self.config.trust_anchors.iter() {
            ca_certs
                .try_push(cert.der_span())
                .map_err(|_| TlsError::CertificateError)?;
        }

        let verification_context = crate::net::security::x509::TlsServerVerificationContext {
            now_unix: crate::drivers::time::unix_timestamp(),
            server_name: self
                .negotiation
                .server_name
                .as_ref()
                .map(|name| name.as_str()),
            trusted_roots: &ca_certs,
        };
        let verified_certificate =
            crate::net::security::x509::CertificatePolicy::Tls13ServerAuth(verification_context)
                .verify_chain(&certs)
                .ok_or(TlsError::CertificateError)?;
        drop(ca_certs);
        self.install_verified_server_certificate(verified_certificate)?;
        self.negotiation.phase = TlsConnectionPhase::certificate_verify_pending();
        Ok(())
    }

    pub(super) fn tls13_process_certificate_verify(
        &mut self,
        data: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        if data.total_len() < 4 {
            return Err(TlsError::DecodeError);
        }
        let sig_algorithm = data.read_u16_be(0).ok_or(TlsError::DecodeError)?;
        let sig_len = data.read_u16_be(2).ok_or(TlsError::DecodeError)? as usize;
        if 4 + sig_len > data.total_len() {
            return Err(TlsError::DecodeError);
        }
        let signature = data
            .subspan(4, sig_len)
            .ok_or(TlsError::DecodeError)?
            .read_fixed_bytes::<1024>(sig_len)
            .ok_or(TlsError::DecodeError)?;

        self.verify_tls13_certificate_verify(sig_algorithm, signature.as_slice())?;
        self.negotiation.phase = TlsConnectionPhase::server_finished_pending();
        Ok(())
    }

    fn verify_tls13_certificate_verify(
        &self,
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        const LABEL: &[u8] = b"TLS 1.3, server CertificateVerify";
        let use_384 = self.negotiation.negotiated.cipher()?.uses_sha384();
        let mut content = [0u8; 64 + LABEL.len() + 1 + SHA384_OUTPUT_SIZE];
        content[..64].fill(0x20);
        let mut offset = 64;
        content[offset..offset + LABEL.len()].copy_from_slice(LABEL);
        offset += LABEL.len();
        content[offset] = 0;
        offset += 1;
        let hash_len = if use_384 {
            let hash = self.transcript_hash_sha384();
            content[offset..offset + SHA384_OUTPUT_SIZE].copy_from_slice(&hash);
            SHA384_OUTPUT_SIZE
        } else {
            let hash = self.transcript_hash_sha256();
            content[offset..offset + SHA256_OUTPUT_SIZE].copy_from_slice(&hash);
            SHA256_OUTPUT_SIZE
        };
        self.dispatch_tls13_signature_verification(
            sig_algorithm,
            &content[..offset + hash_len],
            signature,
        )
    }

    pub(super) fn dispatch_tls13_signature_verification(
        &self,
        sig_algorithm: u16,
        content: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let selected_scheme =
            SignatureScheme::from_wire(sig_algorithm).ok_or(TlsError::UnsupportedCipherSuite)?;
        if !self.config.signature_schemes.contains(selected_scheme) {
            return Err(TlsError::UnsolicitedSignatureScheme);
        }

        match sig_algorithm {
            0x0804 => self.verify_rsa_pss_signature(
                content,
                signature,
                crate::net::security::rsa::HashAlgorithm::Sha256,
            ),
            0x0805 => self.verify_rsa_pss_signature(
                content,
                signature,
                crate::net::security::rsa::HashAlgorithm::Sha384,
            ),
            0x0806 => self.verify_rsa_pss_signature(
                content,
                signature,
                crate::net::security::rsa::HashAlgorithm::Sha512,
            ),
            0x0403 => self.verify_ecdsa_p256_signature(content, signature),
            0x0503 => self.verify_ecdsa_p384_signature(content, signature),
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    pub(super) fn verify_rsa_pss_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        hash_alg: crate::net::security::rsa::HashAlgorithm,
    ) -> TlsResult<()> {
        let server_public_key = self
            .handshake_secrets
            .server_public_key
            .as_ref()
            .ok_or(TlsError::CertificateError)?;
        let (modulus, exponent) = server_public_key
            .rsa_components()
            .ok_or(TlsError::CertificateError)?;
        let pubkey = crate::net::security::rsa::RsaPublicKey { modulus, exponent };

        match hash_alg {
            crate::net::security::rsa::HashAlgorithm::Sha256 => {
                let digest = crate::crypto::sha256::compute(message);
                crate::net::security::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
                    .map_err(|_| TlsError::CryptoError)
            }
            crate::net::security::rsa::HashAlgorithm::Sha384 => {
                let digest = crate::crypto::sha384::compute(message);
                crate::net::security::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
                    .map_err(|_| TlsError::CryptoError)
            }
            crate::net::security::rsa::HashAlgorithm::Sha512 => {
                let digest = crate::crypto::sha512::compute(message);
                crate::net::security::rsa::rsa_pss_verify(&pubkey, hash_alg, &digest, signature)
                    .map_err(|_| TlsError::CryptoError)
            }
        }
    }

    pub(super) fn verify_ecdsa_p256_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let public_key = self
            .handshake_secrets
            .server_public_key
            .as_ref()
            .and_then(|key| key.ecdsa_p256_point())
            .ok_or(TlsError::CertificateError)?;
        let digest = crate::crypto::sha256::compute(message);
        ecdh::p256::ecdsa_p256_verify(public_key, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    pub(super) fn verify_ecdsa_p384_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let public_key = self
            .handshake_secrets
            .server_public_key
            .as_ref()
            .and_then(|key| key.ecdsa_p384_point())
            .ok_or(TlsError::CertificateError)?;
        let digest = crate::crypto::sha384::compute(message);
        ecdh::p384::ecdsa_p384_verify(public_key, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    pub(super) fn tls13_process_server_finished(
        &mut self,
        data: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        let hash_len = self.hash_len();
        if data.total_len() != hash_len {
            return Err(TlsError::DecodeError);
        }
        let received = data
            .read_fixed_bytes::<SHA384_OUTPUT_SIZE>(hash_len)
            .ok_or(TlsError::DecodeError)?;

        if self.negotiation.negotiated.cipher()?.uses_sha384() {
            let transcript = self.transcript_hash_sha384();
            let mut shs = [0u8; 48];
            shs.copy_from_slice(&self.tls13.server_hs_traffic_secret);
            let finished_key = tls13_finished_key_sha384(&shs);
            let expected = tls13_verify_data_sha384(&finished_key, &transcript);
            if !constant_time_eq(received.as_slice(), &expected[..hash_len]) {
                return Err(TlsError::HandshakeFailure);
            }
        } else {
            let transcript = self.transcript_hash_sha256();
            let mut shs = [0u8; 32];
            shs.copy_from_slice(&self.tls13.server_hs_traffic_secret[..32]);
            let finished_key = tls13_finished_key(&shs);
            let expected = tls13_verify_data(&finished_key, &transcript);
            if !constant_time_eq(received.as_slice(), &expected[..hash_len]) {
                return Err(TlsError::HandshakeFailure);
            }
        }

        self.negotiation.phase = TlsConnectionPhase::server_finished_received();
        Ok(())
    }

    pub(super) fn compute_tls13_client_verify_data(&self) -> TlsResult<([u8; 48], usize)> {
        if self.negotiation.negotiated.cipher()?.uses_sha384() {
            let transcript = self.transcript_hash_sha384();
            let mut chs = [0u8; 48];
            chs.copy_from_slice(&self.tls13.client_hs_traffic_secret);
            let finished_key = tls13_finished_key_sha384(&chs);
            Ok((
                tls13_verify_data_sha384(&finished_key, &transcript),
                SHA384_OUTPUT_SIZE,
            ))
        } else {
            let transcript = self.transcript_hash_sha256();
            let mut chs = [0u8; 32];
            chs.copy_from_slice(&self.tls13.client_hs_traffic_secret[..32]);
            let finished_key = tls13_finished_key(&chs);
            let mut out = [0u8; 48];
            out[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(&tls13_verify_data(&finished_key, &transcript));
            Ok((out, SHA256_OUTPUT_SIZE))
        }
    }

    pub fn build_client_finished_tls13_payload(&mut self) -> TlsResult<PacketPayload> {
        if !self.negotiation.phase.is_server_finished_received() {
            return Err(TlsError::UnexpectedMessage);
        }

        let (verify_data, verify_len) = self.compute_tls13_client_verify_data()?;
        let mut finished_msg = [0u8; 4 + SHA384_OUTPUT_SIZE];
        finished_msg[0] = 20;
        finished_msg[3] = verify_len as u8;
        finished_msg[4..4 + verify_len].copy_from_slice(&verify_data[..verify_len]);
        let finished_msg = &finished_msg[..4 + verify_len];
        self.append_transcript_bytes(finished_msg)?;

        let mut inner = [0u8; 5 + SHA384_OUTPUT_SIZE];
        inner[..4 + verify_len].copy_from_slice(finished_msg);
        inner[4 + verify_len] = ContentType::Handshake as u8;
        let encrypted = self.tls13_encrypt_record(&inner[..5 + verify_len], true)?;
        self.tls13_derive_application_keys()?;
        Ok(encrypted)
    }

    pub(super) fn tls13_derive_application_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.negotiated.cipher()?;
        let key_len = cipher.key_len();
        if cipher.uses_sha384() {
            let transcript = self.transcript_hash_sha384();
            let mut master_secret = [0u8; 48];
            master_secret.copy_from_slice(&self.handshake_secrets.master_secret);
            let cas = tls13_derive_secret_sha384(&master_secret, b"c ap traffic", &transcript);
            let sas = tls13_derive_secret_sha384(&master_secret, b"s ap traffic", &transcript);
            self.tls13.client_app_traffic_secret = cas;
            self.tls13.server_app_traffic_secret = sas;
            let mut server_key = [0u8; 32];
            let mut server_iv = [0u8; 12];
            let mut client_key = [0u8; 32];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(&sas, &mut server_key[..key_len], &mut server_iv);
            tls13_derive_traffic_keys_sha384(&cas, &mut client_key[..key_len], &mut client_iv);
            Self::set_tls_bytes(&mut self.record.read_key, &server_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.record.write_key, &client_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &client_iv)?;
        } else {
            let transcript = self.transcript_hash_sha256();
            let mut master_secret = [0u8; 32];
            master_secret.copy_from_slice(&self.handshake_secrets.master_secret[..32]);
            let cas = tls13_derive_secret(&master_secret, b"c ap traffic", &transcript);
            let sas = tls13_derive_secret(&master_secret, b"s ap traffic", &transcript);
            self.tls13.client_app_traffic_secret[..32].copy_from_slice(&cas);
            self.tls13.server_app_traffic_secret[..32].copy_from_slice(&sas);
            let mut server_key = [0u8; 32];
            let mut server_iv = [0u8; 12];
            let mut client_key = [0u8; 32];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(&sas, &mut server_key[..key_len], &mut server_iv);
            tls13_derive_traffic_keys(&cas, &mut client_key[..key_len], &mut client_iv);
            Self::set_tls_bytes(&mut self.record.read_key, &server_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.record.write_key, &client_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &client_iv)?;
        }

        self.record.read_seq.reset();
        self.record.write_seq.reset();
        self.negotiation.phase = TlsConnectionPhase::established();
        Ok(())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn certificate_verify_rejects_unoffered_signature_scheme() {
        let config = crate::net::security::tls::TlsClientConfig::new()
            .with_signature_schemes(&[
                crate::net::security::tls::protocol::SignatureScheme::ECDSA_SECP256R1_SHA256,
            ])
            .expect("test signature scheme set is non-empty");
        let conn =
            TlsConnectionCore::new(config).expect("test TLS connection entropy is available");

        let result = conn.dispatch_tls13_signature_verification(
            crate::net::security::tls::protocol::SignatureScheme::RSA_PSS_RSAE_SHA256.wire(),
            b"content",
            b"signature",
        );

        assert!(matches!(result, Err(TlsError::UnsolicitedSignatureScheme)));
    }
}
