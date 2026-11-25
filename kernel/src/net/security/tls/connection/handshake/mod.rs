// ============================================================================
// kernel/src/net/security/tls/connection/handshake/mod.rs - Handshake frame dispatch
// ============================================================================

use super::state::TlsHandshakeProgress;
use super::{HandshakeType, TlsConnectionCore};
use crate::net::payload::PayloadSpanRef;
use crate::net::security::tls::error::{TlsError, TlsResult};

mod certificate;
mod server_hello;
mod tls13;

enum Tls13ServerHandshakeMessage<'a> {
    ServerHello(PayloadSpanRef<'a>),
    EncryptedExtensions(PayloadSpanRef<'a>),
    Certificate(PayloadSpanRef<'a>),
    CertificateRequest(PayloadSpanRef<'a>),
    CertificateVerify(PayloadSpanRef<'a>),
    Finished(PayloadSpanRef<'a>),
}

impl<'a> Tls13ServerHandshakeMessage<'a> {
    fn from_frame(msg_type: u8, payload: PayloadSpanRef<'a>) -> TlsResult<Self> {
        match HandshakeType::parse_wire(msg_type) {
            Some(HandshakeType::ServerHello) => Ok(Self::ServerHello(payload)),
            Some(HandshakeType::EncryptedExtensions) => Ok(Self::EncryptedExtensions(payload)),
            Some(HandshakeType::Certificate) => Ok(Self::Certificate(payload)),
            Some(HandshakeType::CertificateRequest) => Ok(Self::CertificateRequest(payload)),
            Some(HandshakeType::CertificateVerify) => Ok(Self::CertificateVerify(payload)),
            Some(HandshakeType::Finished) => Ok(Self::Finished(payload)),
            _ => Err(TlsError::UnexpectedMessage),
        }
    }
}

impl TlsConnectionCore {
    pub(super) fn dispatch_handshake_message(
        &mut self,
        msg_type: u8,
        payload: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        match (
            self.negotiation.progress,
            Tls13ServerHandshakeMessage::from_frame(msg_type, payload)?,
        ) {
            (
                TlsHandshakeProgress::ClientHelloSent,
                Tls13ServerHandshakeMessage::ServerHello(payload),
            ) => self.process_server_hello(payload),
            (
                TlsHandshakeProgress::EncryptedExtensionsPending(_),
                Tls13ServerHandshakeMessage::EncryptedExtensions(payload),
            ) => self.tls13_process_encrypted_extensions(payload),
            (
                TlsHandshakeProgress::CertificatePending(_),
                Tls13ServerHandshakeMessage::Certificate(payload),
            ) => self.tls13_process_certificate(payload),
            (
                TlsHandshakeProgress::CertificatePending(_),
                Tls13ServerHandshakeMessage::CertificateRequest(payload),
            ) => self.tls13_process_certificate_request(payload),
            (
                TlsHandshakeProgress::CertificateVerifyPending(_),
                Tls13ServerHandshakeMessage::CertificateVerify(payload),
            ) => self.tls13_process_certificate_verify(payload),
            (
                TlsHandshakeProgress::ServerFinishedPending(_),
                Tls13ServerHandshakeMessage::Finished(payload),
            ) => self.tls13_process_server_finished(payload),
            _ => Err(TlsError::UnexpectedMessage),
        }
    }

    pub(super) fn record_and_update_handshake(
        &mut self,
        msg_data: PayloadSpanRef<'_>,
        msg_type: u8,
    ) -> TlsResult<()> {
        const MAX_HANDSHAKE_ACCUMULATOR: usize = 262_144;
        if self.transcript_len() + msg_data.total_len() > MAX_HANDSHAKE_ACCUMULATOR {
            return Err(TlsError::DecodeError);
        }

        self.append_transcript_span(msg_data)?;
        if msg_type == 2 {
            self.tls13_derive_handshake_keys()?;
        }
        Ok(())
    }

}
