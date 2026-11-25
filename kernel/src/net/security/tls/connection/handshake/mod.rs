// ============================================================================
// kernel/src/net/security/tls/connection/handshake/mod.rs - Handshake frame dispatch
// ============================================================================

use super::state::TlsHandshakeProgress;
use super::{HandshakeType, PacketPayload, PacketPayloadView, TlsConnectionCore};
use crate::net::payload::PayloadSpanRef;
use crate::net::security::tls::error::{TlsError, TlsResult};
use kernel_api::resource::net::{PacketByteCount, PacketPayloadFront};

mod certificate;
mod server_hello;
mod tls13;

const MAX_HANDSHAKE_BODY: usize = 131_072;
const HANDSHAKE_HEADER_LEN: usize = 4;

#[derive(Default)]
pub(super) struct HandshakeIngress(Option<PacketPayload>);

impl HandshakeIngress {
    pub(super) const fn is_pending(&self) -> bool {
        self.0.is_some()
    }

    fn push(&mut self, fragment: PacketPayload) -> TlsResult<()> {
        self.0 = Some(match self.0.take() {
            Some(buffered) => buffered
                .try_append(fragment)
                .map_err(|_| TlsError::DecodeError)?,
            None => fragment,
        });
        Ok(())
    }

    fn pop_message(&mut self) -> TlsResult<Option<PacketPayload>> {
        let Some(buffered) = &self.0 else {
            return Ok(None);
        };
        let view = PacketPayloadView::new(buffered);
        let Some([_, hi, mid, lo]) = view.read_array::<4>(0) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([0, hi, mid, lo]) as usize;
        if len > MAX_HANDSHAKE_BODY {
            return Err(TlsError::DecodeError);
        }
        let total = HANDSHAKE_HEADER_LEN + len;
        if view.total_len() < total {
            return Ok(None);
        }
        let count = PacketByteCount::new(total).ok_or(TlsError::DecodeError)?;
        match self
            .0
            .take()
            .ok_or(TlsError::DecodeError)?
            .try_take_front(count)
        {
            Ok(PacketPayloadFront::Whole(message)) => Ok(Some(message)),
            Ok(PacketPayloadFront::Prefix { front, remainder }) => {
                self.0 = Some(remainder);
                Ok(Some(front))
            }
            Err(_) => Err(TlsError::DecodeError),
        }
    }
}

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

    pub(super) fn receive_handshake_fragment(&mut self, fragment: PacketPayload) -> TlsResult<()> {
        self.handshake_ingress.push(fragment)?;
        // LOOP_PROOF: mode=condition; reason=Each iteration removes a complete handshake message from the finite receive buffer.;
        while let Some(message) = self.handshake_ingress.pop_message()? {
            let frame = PayloadSpanRef::from_payload(&message);
            let kind = frame.read_u8(0).ok_or(TlsError::DecodeError)?;
            let body = frame
                .subspan(
                    HANDSHAKE_HEADER_LEN,
                    frame.total_len() - HANDSHAKE_HEADER_LEN,
                )
                .ok_or(TlsError::DecodeError)?;
            if self.negotiation.progress.has_application_keys() {
                match HandshakeType::parse_wire(kind) {
                    Some(HandshakeType::NewSessionTicket) => {}
                    Some(HandshakeType::KeyUpdate)
                        if !self.handshake_ingress.is_pending() && body.total_len() == 1 =>
                    {
                        self.tls13_process_key_update(body)?
                    }
                    _ => return Err(TlsError::UnexpectedMessage),
                }
            } else {
                self.dispatch_handshake_message(kind, body)?;
                self.record_and_update_handshake(frame, kind)?;
                // A message that changes the protection epoch must end its record.
                if matches!(
                    HandshakeType::parse_wire(kind),
                    Some(HandshakeType::ServerHello | HandshakeType::Finished)
                ) && self.handshake_ingress.is_pending()
                {
                    return Err(TlsError::UnexpectedMessage);
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;
    use crate::net::l4::test_support::packet_fixture_with_data;

    fn fragment(bytes: &[u8]) -> PacketPayload {
        PacketPayload::try_single(packet_fixture_with_data(bytes)).expect("fixture payload")
    }

    #[test]
    fn reconstructs_header_and_body_split_across_records() {
        let mut ingress = HandshakeIngress::default();
        ingress.push(fragment(&[11, 0, 0])).expect("partial header");
        assert!(ingress.pop_message().expect("partial header").is_none());
        ingress.push(fragment(&[2, 1])).expect("partial body");
        assert!(ingress.pop_message().expect("partial body").is_none());
        ingress
            .push(fragment(&[2, 20, 0, 0, 0]))
            .expect("two messages");
        let body = ingress
            .pop_message()
            .expect("valid frame")
            .expect("complete frame");
        assert!(PayloadSpanRef::from_payload(&body).eq_bytes(&[11, 0, 0, 2, 1, 2]));
        let next = ingress
            .pop_message()
            .expect("valid frame")
            .expect("complete frame");
        assert!(PayloadSpanRef::from_payload(&next).eq_bytes(&[20, 0, 0, 0]));
        assert!(!ingress.is_pending());
    }
}
