use arrayvec::ArrayVec;

use super::*;

impl TlsConnection {
    pub(super) fn extract_server_public_key(
        &mut self,
        cert: &crate::net::security::x509::X509Certificate,
    ) -> TlsResult<()> {
        self.extract_server_public_key_from_spki(cert.subject_public_key_info)
    }

    pub(crate) fn extract_server_public_key_from_spki(
        &mut self,
        spki: crate::net::security::x509::SubjectPublicKeyInfo<'_>,
    ) -> TlsResult<()> {
        self.handshake_secrets.server_public_key = Some(match spki {
            crate::net::security::x509::SubjectPublicKeyInfo::Rsa { modulus, exponent } => {
                ServerPublicKey::Rsa {
                    modulus: Self::payload_span_from_slice(modulus)?,
                    exponent: Self::payload_span_from_slice(exponent)?,
                }
            }
            crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP256 { public_key } => {
                ServerPublicKey::EcdsaP256 {
                    point: Self::payload_span_from_slice(public_key)?,
                }
            }
            crate::net::security::x509::SubjectPublicKeyInfo::EcdsaP384 { public_key } => {
                ServerPublicKey::EcdsaP384 {
                    point: Self::payload_span_from_slice(public_key)?,
                }
            }
            crate::net::security::x509::SubjectPublicKeyInfo::Unknown(_) => {
                return Err(TlsError::UnsupportedCipherSuite);
            }
        });
        Ok(())
    }

    pub(crate) fn set_server_public_key_from_cert(&mut self, cert_der: &[u8]) -> TlsResult<()> {
        let cert = crate::net::security::x509::parse_x509(cert_der)
            .ok_or(TlsError::CertificateError)?;
        self.extract_server_public_key(&cert)
    }

    pub(super) fn process_certificate(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.len() < 3 {
            return Err(TlsError::DecodeError);
        }

        let certs_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

        // Security: Limit certificate chain length (e.g. 64KB)
        if data.len() < 3 + certs_len || certs_len == 0 || certs_len > 65536 {
            return Err(TlsError::CertificateError);
        }

        let cert_chain_data = &data[3..3 + certs_len];
        let mut certs = ArrayVec::<&[u8], TLS_CERT_CHAIN_CAPACITY>::new();
        let mut offset = 0;

        // 全ての証明書を抽出
        while offset + 3 <= cert_chain_data.len() {
            let cert_len = ((cert_chain_data[offset] as usize) << 16)
                | ((cert_chain_data[offset + 1] as usize) << 8)
                | (cert_chain_data[offset + 2] as usize);
            offset += 3;

            if offset + cert_len > cert_chain_data.len() {
                return Err(TlsError::DecodeError);
            }

            certs
                .try_push(&cert_chain_data[offset..offset + cert_len])
                .map_err(|_| TlsError::CertificateError)?;
            offset += cert_len;
        }

        if certs.is_empty() {
            return Err(TlsError::CertificateError);
        }

        if !self.config.should_skip_verify() {
            // 証明書チェーンの検証 (issuerの一致、署名の妥当性、ホスト名の一致、およびルートCAへの信頼)
            let validated_spki = {
                let mut ca_ders = ArrayVec::<&[u8], TLS_CA_CERTS_CAPACITY>::new();
                for cert in &self.config.ca_certs {
                    if let Some(der) = cert.der.as_contiguous_slice() {
                        ca_ders
                            .try_push(der)
                            .map_err(|_| TlsError::CertificateError)?;
                    }
                }
                crate::net::security::x509::validate_certificate_chain(
                    &certs,
                    self.negotiation.server_name.as_ref().map(|name| name.as_str()),
                    &ca_ders,
                )
            };
            if let Some(spki) = validated_spki {
                self.extract_server_public_key_from_spki(spki)?;
            } else {
                return Err(TlsError::CertificateError);
            }
        } else {
            // 検証スキップ時は最初の証明書の鍵をそのまま使用
            log::warn!(
                "[TLS] Security: Certificate verification skipped. This connection is vulnerable to Man-in-the-Middle attacks!"
            );
            if let Some(cert) = crate::net::security::x509::parse_x509(certs[0]) {
                self.extract_server_public_key(&cert)?;
            } else {
                return Err(TlsError::CertificateError);
            }
        }

        Ok(())
    }

    /// RSA署名でServerKeyExchangeを検証
    pub(super) fn verify_rsa_ske_signature_parts(
        &self,
        ecdhe_params: &[u8],
        signature: &[u8],
        alg_selector: u8,
    ) -> TlsResult<()> {
        let pubkey = match &self.handshake_secrets.server_public_key {
            Some(ServerPublicKey::Rsa { modulus, exponent }) => {
                let modulus = modulus
                    .as_contiguous_slice()
                    .ok_or(TlsError::CertificateError)?;
                let exponent = exponent
                    .as_contiguous_slice()
                    .ok_or(TlsError::CertificateError)?;
                crate::net::security::rsa::RsaPublicKey { modulus, exponent }
            }
            _ => return Err(TlsError::CertificateError),
        };

        match alg_selector {
            2 => {
                let mut hasher = crate::crypto::sha256::Sha256::new();
                hasher.update(&self.negotiation.client_random);
                hasher.update(&self.negotiation.server_random);
                hasher.update(ecdhe_params);
                let digest = hasher.finalize();
                crate::net::security::rsa::rsa_pkcs1_verify(
                    &pubkey,
                    crate::net::security::rsa::HashAlgorithm::Sha256,
                    &digest,
                    signature,
                )
                .map_err(|_| TlsError::CryptoError)
            }
            3 => {
                let mut hasher = crate::crypto::sha384::Sha384::new();
                hasher.update(&self.negotiation.client_random);
                hasher.update(&self.negotiation.server_random);
                hasher.update(ecdhe_params);
                let digest = hasher.finalize();
                crate::net::security::rsa::rsa_pkcs1_verify(
                    &pubkey,
                    crate::net::security::rsa::HashAlgorithm::Sha384,
                    &digest,
                    signature,
                )
                .map_err(|_| TlsError::CryptoError)
            }
            _ => Err(TlsError::CryptoError),
        }
    }

    /// ECDSA P-256署名でServerKeyExchangeを検証
    pub(super) fn verify_ecdsa_ske_signature_parts(
        &self,
        ecdhe_params: &[u8],
        signature: &[u8],
    ) -> TlsResult<()> {
        let pubkey_bytes = match &self.handshake_secrets.server_public_key {
            Some(ServerPublicKey::EcdsaP256 { point }) => point
                .as_contiguous_slice()
                .ok_or(TlsError::CertificateError)?,
            _ => return Err(TlsError::CertificateError),
        };
        let mut hasher = crate::crypto::sha256::Sha256::new();
        hasher.update(&self.negotiation.client_random);
        hasher.update(&self.negotiation.server_random);
        hasher.update(ecdhe_params);
        let digest = hasher.finalize();
        ecdh::p256::ecdsa_p256_verify(pubkey_bytes, &digest, signature)
            .map_err(|_| TlsError::CryptoError)
    }

    /// 署名アルゴリズムに応じたSKE署名検証ディスパッチ
    pub(super) fn verify_ske_sig_dispatch(
        &self,
        ecdhe_params: &[u8],
        sig_algorithm: u16,
        signature: &[u8],
    ) -> TlsResult<()> {
        match sig_algorithm {
            // RSA-PKCS1-SHA256 (0x0401)
            0x0401 => self.verify_rsa_ske_signature_parts(ecdhe_params, signature, 2), // 2 = SHA256
            // RSA-PKCS1-SHA384 (0x0501)
            0x0501 => self.verify_rsa_ske_signature_parts(ecdhe_params, signature, 3), // 3 = SHA384
            // ECDSA-SECP256R1-SHA256 (0x0403)
            0x0403 => self.verify_ecdsa_ske_signature_parts(ecdhe_params, signature),
            // Security: SHA-1 (0x0201) is deprecated and removed for security reasons.
            _ => Err(TlsError::UnsupportedCipherSuite),
        }
    }

    /// ServerKeyExchangeの署名を解析・検証
    pub(super) fn verify_ske_signature(
        &self,
        data: &[u8],
        ecdhe_params_end: usize,
    ) -> TlsResult<()> {
        let sig_offset = ecdhe_params_end;
        if data.len() < sig_offset + 4 {
            return Err(TlsError::DecodeError);
        }

        let sig_algorithm = ((data[sig_offset] as u16) << 8) | data[sig_offset + 1] as u16;
        let sig_len = ((data[sig_offset + 2] as usize) << 8) | data[sig_offset + 3] as usize;

        if data.len() < sig_offset + 4 + sig_len {
            return Err(TlsError::DecodeError);
        }

        let signature = &data[sig_offset + 4..sig_offset + 4 + sig_len];

        // 署名対象: client_random || server_random || ecdhe_params
        let ecdhe_params = &data[..ecdhe_params_end];
        self.verify_ske_sig_dispatch(ecdhe_params, sig_algorithm, signature)
    }
}
