// ============================================================================
// tls/connection/handshake/mod.rs - Handshake frame dispatch
// ============================================================================

use super::*;

mod certificate;
mod server_hello;
mod tls12;
mod tls13;

impl TlsConnection {
    pub(super) fn dispatch_handshake_message(
        &mut self,
        msg_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
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
        msg_data: &[u8],
        msg_type: u8,
    ) -> TlsResult<()> {
        const MAX_HANDSHAKE_ACCUMULATOR: usize = 262_144;
        if self.transcript_len() + msg_data.len() > MAX_HANDSHAKE_ACCUMULATOR {
            return Err(TlsError::DecodeError);
        }

        self.append_transcript_bytes(msg_data)?;
        if msg_type == 2 && self.negotiation.is_tls13 {
            self.tls13_derive_handshake_keys()?;
        }
        Ok(())
    }

    pub(crate) fn process_handshake(&mut self, data: &[u8]) -> TlsResult<()> {
        if data.is_empty() {
            return Err(TlsError::DecodeError);
        }

        let mut offset = 0usize;
        while offset < data.len() {
            if data.len() - offset < 4 {
                return Err(TlsError::DecodeError);
            }

            let msg_type = data[offset];
            let length = ((data[offset + 1] as usize) << 16)
                | ((data[offset + 2] as usize) << 8)
                | data[offset + 3] as usize;

            if length > 131_072 {
                return Err(TlsError::DecodeError);
            }

            let body_start = offset + 4;
            let body_end = body_start + length;
            if body_end > data.len() {
                return Err(TlsError::DecodeError);
            }

            let payload = &data[body_start..body_end];
            self.dispatch_handshake_message(msg_type, payload)?;
            self.record_and_update_handshake(&data[offset..body_end], msg_type)?;
            offset = body_end;
        }

        Ok(())
    }
}
