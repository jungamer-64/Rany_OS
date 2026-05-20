// ============================================================================
// kernel/src/net/security/tls/connection/handshake/tls13.rs
// ============================================================================

use arrayvec::ArrayVec;

use super::super::state::{TlsHandshakeProgress, TlsRecordEpoch};
use super::super::{
    ContentType, PacketPayload, PayloadSpanRef, TLS_CA_CERTS_CAPACITY, TLS_CERT_CHAIN_CAPACITY,
    TlsConnectionCore, TlsError, TlsResult, ecdh,
};
use crate::net::security::tls::crypto::hkdf::{
    tls13_derive_secret, tls13_derive_secret_sha384, tls13_derive_traffic_keys,
    tls13_derive_traffic_keys_sha384, tls13_early_secret, tls13_early_secret_sha384,
    tls13_finished_key, tls13_finished_key_sha384, tls13_handshake_secret,
    tls13_handshake_secret_sha384, tls13_master_secret, tls13_master_secret_sha384,
    tls13_verify_data, tls13_verify_data_sha384,
};
use crate::net::security::tls::crypto::material::{
    FinishedKey, HandshakeSecret, MasterSecret, Sha256Hash, Sha384Hash, TrafficSecret,
    TranscriptHash,
};
use crate::net::security::tls::crypto::{SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE};
use crate::net::security::tls::protocol::SignatureScheme;

impl TlsConnectionCore {
    pub(crate) fn tls13_derive_handshake_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.selected()?.cipher();
        let key_len = cipher.key_len();

        if cipher.uses_sha384() {
            let transcript_ch_sh = TranscriptHash::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                self.transcript_hash_sha384(),
            );
            let early_secret = tls13_early_secret_sha384(None);
            let handshake_secret = HandshakeSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                tls13_handshake_secret_sha384(
                    &early_secret,
                    self.handshake_secrets.pre_master_secret()?.as_slice(),
                ),
            );
            let chs =
                TrafficSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(tls13_derive_secret_sha384(
                    handshake_secret.as_bytes(),
                    b"c hs traffic",
                    transcript_ch_sh.as_bytes(),
                ));
            let shs =
                TrafficSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(tls13_derive_secret_sha384(
                    handshake_secret.as_bytes(),
                    b"s hs traffic",
                    transcript_ch_sh.as_bytes(),
                ));
            self.tls13
                .client_hs_traffic_secret
                .copy_from_slice(chs.as_bytes());
            self.tls13
                .server_hs_traffic_secret
                .copy_from_slice(shs.as_bytes());

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(
                shs.as_bytes(),
                &mut self.tls13.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys_sha384(
                chs.as_bytes(),
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
            let ms = MasterSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                tls13_master_secret_sha384(handshake_secret.as_bytes()),
            );
            self.handshake_secrets
                .master_secret
                .copy_from_slice(ms.as_bytes());
        } else {
            let transcript_ch_sh = TranscriptHash::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(
                self.transcript_hash_sha256(),
            );
            let early_secret = tls13_early_secret(None);
            let handshake_secret =
                HandshakeSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(tls13_handshake_secret(
                    &early_secret,
                    self.handshake_secrets.pre_master_secret()?.as_slice(),
                ));
            let chs = TrafficSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(tls13_derive_secret(
                handshake_secret.as_bytes(),
                b"c hs traffic",
                transcript_ch_sh.as_bytes(),
            ));
            let shs = TrafficSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(tls13_derive_secret(
                handshake_secret.as_bytes(),
                b"s hs traffic",
                transcript_ch_sh.as_bytes(),
            ));
            self.tls13.client_hs_traffic_secret[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(chs.as_bytes());
            self.tls13.server_hs_traffic_secret[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(shs.as_bytes());

            let mut server_iv = [0u8; 12];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(
                shs.as_bytes(),
                &mut self.tls13.hs_read_key.as_mut_storage()[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys(
                chs.as_bytes(),
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
            let ms = MasterSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(tls13_master_secret(
                handshake_secret.as_bytes(),
            ));
            self.handshake_secrets.master_secret[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(ms.as_bytes());
        }

        self.negotiation.progress =
            TlsHandshakeProgress::EncryptedExtensionsPending(self.negotiation.selected()?);
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
        self.negotiation.progress =
            TlsHandshakeProgress::CertificatePending(self.negotiation.selected()?);
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
            server_name: self.config.server_name.as_str(),
            trusted_roots: &ca_certs,
        };
        let verified_certificate =
            crate::net::security::x509::CertificatePolicy::Tls13ServerAuth(verification_context)
                .verify_chain(&certs)
                .ok_or(TlsError::CertificateError)?;
        drop(ca_certs);
        self.install_verified_server_certificate(verified_certificate)?;
        self.negotiation.progress =
            TlsHandshakeProgress::CertificateVerifyPending(self.negotiation.selected()?);
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
        self.negotiation.progress =
            TlsHandshakeProgress::ServerFinishedPending(self.negotiation.selected()?);
        Ok(())
    }

    fn verify_tls13_certificate_verify(
        &self,
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        const LABEL: &[u8] = b"TLS 1.3, server CertificateVerify";
        let use_384 = self.negotiation.selected()?.cipher().uses_sha384();
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
            SignatureScheme::parse_wire(sig_algorithm).ok_or(TlsError::UnsupportedCipherSuite)?;
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
        let server_public_key = self.handshake_secrets.server_public_key()?;
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
            .server_public_key()?
            .ecdsa_p256_point()
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
            .server_public_key()?
            .ecdsa_p384_point()
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

        if self.negotiation.selected()?.cipher().uses_sha384() {
            let transcript = TranscriptHash::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                self.transcript_hash_sha384(),
            );
            let mut shs = [0u8; 48];
            shs.copy_from_slice(&self.tls13.server_hs_traffic_secret);
            let shs = TrafficSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(shs);
            let finished_key = FinishedKey::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                tls13_finished_key_sha384(shs.as_bytes()),
            );
            let expected = tls13_verify_data_sha384(finished_key.as_bytes(), transcript.as_bytes());
            if !constant_time_eq(received.as_slice(), &expected[..hash_len]) {
                return Err(TlsError::HandshakeFailure);
            }
        } else {
            let transcript = TranscriptHash::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(
                self.transcript_hash_sha256(),
            );
            let mut shs = [0u8; 32];
            shs.copy_from_slice(&self.tls13.server_hs_traffic_secret[..32]);
            let shs = TrafficSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(shs);
            let finished_key = FinishedKey::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(
                tls13_finished_key(shs.as_bytes()),
            );
            let expected = tls13_verify_data(finished_key.as_bytes(), transcript.as_bytes());
            if !constant_time_eq(received.as_slice(), &expected[..hash_len]) {
                return Err(TlsError::HandshakeFailure);
            }
        }

        self.negotiation.progress =
            TlsHandshakeProgress::ServerFinishedReceived(self.negotiation.selected()?);
        Ok(())
    }

    pub(super) fn compute_tls13_client_verify_data(&self) -> TlsResult<([u8; 48], usize)> {
        if self.negotiation.selected()?.cipher().uses_sha384() {
            let transcript = TranscriptHash::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                self.transcript_hash_sha384(),
            );
            let mut chs = [0u8; 48];
            chs.copy_from_slice(&self.tls13.client_hs_traffic_secret);
            let chs = TrafficSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(chs);
            let finished_key = FinishedKey::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                tls13_finished_key_sha384(chs.as_bytes()),
            );
            Ok((
                tls13_verify_data_sha384(finished_key.as_bytes(), transcript.as_bytes()),
                SHA384_OUTPUT_SIZE,
            ))
        } else {
            let transcript = TranscriptHash::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(
                self.transcript_hash_sha256(),
            );
            let mut chs = [0u8; 32];
            chs.copy_from_slice(&self.tls13.client_hs_traffic_secret[..32]);
            let chs = TrafficSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(chs);
            let finished_key = FinishedKey::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(
                tls13_finished_key(chs.as_bytes()),
            );
            let mut out = [0u8; 48];
            out[..SHA256_OUTPUT_SIZE].copy_from_slice(&tls13_verify_data(
                finished_key.as_bytes(),
                transcript.as_bytes(),
            ));
            Ok((out, SHA256_OUTPUT_SIZE))
        }
    }

    pub fn build_client_finished_tls13_payload(&mut self) -> TlsResult<PacketPayload> {
        if !self.negotiation.progress.is_server_finished_received() {
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
        let encrypted =
            self.tls13_encrypt_record(&inner[..5 + verify_len], TlsRecordEpoch::Handshake)?;
        self.tls13_derive_application_keys()?;
        Ok(encrypted)
    }

    pub(super) fn tls13_derive_application_keys(&mut self) -> TlsResult<()> {
        let cipher = self.negotiation.selected()?.cipher();
        let key_len = cipher.key_len();
        if cipher.uses_sha384() {
            let transcript = TranscriptHash::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(
                self.transcript_hash_sha384(),
            );
            let mut master_secret = [0u8; 48];
            master_secret.copy_from_slice(&self.handshake_secrets.master_secret);
            let master_secret = MasterSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(master_secret);
            let cas =
                TrafficSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(tls13_derive_secret_sha384(
                    master_secret.as_bytes(),
                    b"c ap traffic",
                    transcript.as_bytes(),
                ));
            let sas =
                TrafficSecret::<Sha384Hash, SHA384_OUTPUT_SIZE>::new(tls13_derive_secret_sha384(
                    master_secret.as_bytes(),
                    b"s ap traffic",
                    transcript.as_bytes(),
                ));
            self.tls13
                .client_app_traffic_secret
                .copy_from_slice(cas.as_bytes());
            self.tls13
                .server_app_traffic_secret
                .copy_from_slice(sas.as_bytes());
            let mut server_key = [0u8; 32];
            let mut server_iv = [0u8; 12];
            let mut client_key = [0u8; 32];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys_sha384(
                sas.as_bytes(),
                &mut server_key[..key_len],
                &mut server_iv,
            );
            tls13_derive_traffic_keys_sha384(
                cas.as_bytes(),
                &mut client_key[..key_len],
                &mut client_iv,
            );
            Self::set_tls_bytes(&mut self.record.read_key, &server_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.record.write_key, &client_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &client_iv)?;
        } else {
            let transcript = TranscriptHash::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(
                self.transcript_hash_sha256(),
            );
            let mut master_secret = [0u8; 32];
            master_secret.copy_from_slice(&self.handshake_secrets.master_secret[..32]);
            let master_secret = MasterSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(master_secret);
            let cas = TrafficSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(tls13_derive_secret(
                master_secret.as_bytes(),
                b"c ap traffic",
                transcript.as_bytes(),
            ));
            let sas = TrafficSecret::<Sha256Hash, SHA256_OUTPUT_SIZE>::new(tls13_derive_secret(
                master_secret.as_bytes(),
                b"s ap traffic",
                transcript.as_bytes(),
            ));
            self.tls13.client_app_traffic_secret[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(cas.as_bytes());
            self.tls13.server_app_traffic_secret[..SHA256_OUTPUT_SIZE]
                .copy_from_slice(sas.as_bytes());
            let mut server_key = [0u8; 32];
            let mut server_iv = [0u8; 12];
            let mut client_key = [0u8; 32];
            let mut client_iv = [0u8; 12];
            tls13_derive_traffic_keys(sas.as_bytes(), &mut server_key[..key_len], &mut server_iv);
            tls13_derive_traffic_keys(cas.as_bytes(), &mut client_key[..key_len], &mut client_iv);
            Self::set_tls_bytes(&mut self.record.read_key, &server_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.read_iv, &server_iv)?;
            Self::set_tls_bytes(&mut self.record.write_key, &client_key[..key_len])?;
            Self::set_tls_bytes(&mut self.record.write_iv, &client_iv)?;
        }

        self.record.read_seq.reset();
        self.record.write_seq.reset();
        self.negotiation.progress = TlsHandshakeProgress::Established(self.negotiation.selected()?);
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
        let config = crate::net::security::tls::TlsClientConfig::for_server_name(
            "example.com",
            crate::net::security::tls::TlsTrustAnchors::empty(),
        )
        .expect("test server name fits")
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
