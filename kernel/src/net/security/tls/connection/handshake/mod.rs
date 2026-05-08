// ============================================================================
// kernel/src/net/security/tls/connection/handshake/mod.rs - Handshake frame dispatch
// ============================================================================

use super::super::TlsConnection;
use crate::net::payload::PayloadSpanRef;
use crate::net::security::tls::error::{TlsError, TlsResult};
use kernel_api::resource::net::PacketPayload;

mod certificate;
mod server_hello;
mod tls13;

impl TlsConnection {
    pub(super) fn dispatch_handshake_message(
        &mut self,
        msg_type: u8,
        payload: PayloadSpanRef<'_>,
    ) -> TlsResult<()> {
        let payload = payload.single_chunk().ok_or(TlsError::DecodeError)?;
        match msg_type {
            2 => self.process_server_hello(payload),
            11 => self.process_certificate(payload),
            12 => self.process_server_key_exchange(payload),
            14 => self.process_server_hello_done(payload),
            20 => self.process_finished(payload),
            _ => Ok(()),
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
        if msg_type == 2 && self.negotiation.is_tls13 {
            self.tls13_derive_handshake_keys()?;
        }
        Ok(())
    }

    pub(crate) fn process_handshake(&mut self, data: PacketPayload) -> TlsResult<()> {
        let handshake = PayloadSpanRef::from_payload(&data);
        if handshake.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let mut offset = 0usize;
        while offset < handshake.total_len() {
            if handshake.total_len() - offset < 4 {
                return Err(TlsError::DecodeError);
            }

            let msg_type = handshake.read_u8(offset).ok_or(TlsError::DecodeError)?;
            let length = handshake
                .read_u24_be(offset + 1)
                .ok_or(TlsError::DecodeError)? as usize;

            if length > 131_072 {
                return Err(TlsError::DecodeError);
            }

            let body_start = offset + 4;
            let body_end = body_start + length;
            if body_end > handshake.total_len() {
                return Err(TlsError::DecodeError);
            }

            let payload = handshake
                .slice(body_start, length)
                .ok_or(TlsError::DecodeError)?;
            let full_msg = handshake
                .slice(offset, body_end - offset)
                .ok_or(TlsError::DecodeError)?;
            self.dispatch_handshake_message(msg_type, payload)?;
            self.record_and_update_handshake(full_msg, msg_type)?;
            offset = body_end;
        }

        Ok(())
    }
}
