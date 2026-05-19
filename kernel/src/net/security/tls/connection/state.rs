// ============================================================================
// kernel/src/net/security/tls/connection/state.rs - Grouped TLS connection state
// ============================================================================

use super::super::{
    CipherSuite, ServerPublicKey, TLS_SERVER_NAME_CAPACITY, TlsBytes, TlsState, TlsVersion,
};
use crate::net::payload::{append_payload, move_payload_window_owned};
use crate::net::security::ecdh;
use arrayvec::ArrayString;
use kernel_api::resource::net::PacketPayload;

pub(super) struct NegotiationState {
    pub(super) server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
    pub(super) state: TlsState,
    pub(super) negotiated_version: Option<TlsVersion>,
    pub(super) negotiated_cipher: Option<CipherSuite>,
    pub(super) client_random: [u8; 32],
    pub(super) server_random: [u8; 32],
}

impl NegotiationState {
    pub(super) fn new(
        server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
        client_random: [u8; 32],
    ) -> Self {
        Self {
            server_name,
            state: TlsState::Initial,
            negotiated_version: None,
            negotiated_cipher: None,
            client_random,
            server_random: [0; 32],
        }
    }
}

pub(super) struct RecordProtectionState {
    pub(super) read_key: TlsBytes<32>,
    pub(super) write_key: TlsBytes<32>,
    pub(super) read_iv: TlsBytes<16>,
    pub(super) write_iv: TlsBytes<16>,
    pub(super) read_seq: u64,
    pub(super) write_seq: u64,
    pub(super) ingress: TlsRecordIngressQueue,
}

impl Default for RecordProtectionState {
    fn default() -> Self {
        Self {
            read_key: TlsBytes::new(),
            write_key: TlsBytes::new(),
            read_iv: TlsBytes::new(),
            write_iv: TlsBytes::new(),
            read_seq: 0,
            write_seq: 0,
            ingress: TlsRecordIngressQueue::default(),
        }
    }
}

pub(super) struct TlsRecordIngressQueue {
    payload: PacketPayload,
    cursor: usize,
}

impl Default for TlsRecordIngressQueue {
    fn default() -> Self {
        Self {
            payload: PacketPayload::default(),
            cursor: 0,
        }
    }
}

impl TlsRecordIngressQueue {
    pub(super) fn push(&mut self, payload: PacketPayload) {
        append_payload(&mut self.payload, payload);
    }

    pub(super) fn payload(&self) -> &PacketPayload {
        &self.payload
    }

    pub(super) fn payload_mut(&mut self) -> &mut PacketPayload {
        &mut self.payload
    }

    pub(super) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(super) fn advance(&mut self, len: usize) -> Option<()> {
        let next = self.cursor.checked_add(len)?;
        (next <= self.payload.total_len()).then(|| {
            self.cursor = next;
        })
    }

    pub(super) fn compact_consumed(&mut self) -> Option<()> {
        if self.cursor == 0 {
            return Some(());
        }

        let remaining_len = self.payload.total_len().checked_sub(self.cursor)?;
        let remaining = move_payload_window_owned(
            core::mem::take(&mut self.payload),
            self.cursor,
            remaining_len,
        )?;
        self.payload = remaining;
        self.cursor = 0;
        Some(())
    }

    pub(super) fn clear(&mut self) {
        self.payload = PacketPayload::default();
        self.cursor = 0;
    }
}

pub(super) struct HandshakeSecrets {
    pub(super) master_secret: [u8; 48],
    pub(super) pre_master_secret: TlsBytes<64>,
    pub(super) local_ecdh_keypair: Option<ecdh::EcdhKeyPair>,
    pub(super) server_public_key: Option<ServerPublicKey>,
}

impl Default for HandshakeSecrets {
    fn default() -> Self {
        Self {
            master_secret: [0; 48],
            pre_master_secret: TlsBytes::new(),
            local_ecdh_keypair: None,
            server_public_key: None,
        }
    }
}

pub(super) struct Tls13State {
    pub(super) server_hs_traffic_secret: [u8; 48],
    pub(super) client_hs_traffic_secret: [u8; 48],
    pub(super) server_app_traffic_secret: [u8; 48],
    pub(super) client_app_traffic_secret: [u8; 48],
    pub(super) hs_read_key: TlsBytes<32>,
    pub(super) hs_read_iv: TlsBytes<16>,
    pub(super) hs_write_key: TlsBytes<32>,
    pub(super) hs_write_iv: TlsBytes<16>,
    pub(super) hs_read_seq: u64,
    pub(super) hs_write_seq: u64,
    pub(super) pending_key_update_response: bool,
}

impl Default for Tls13State {
    fn default() -> Self {
        Self {
            server_hs_traffic_secret: [0; 48],
            client_hs_traffic_secret: [0; 48],
            server_app_traffic_secret: [0; 48],
            client_app_traffic_secret: [0; 48],
            hs_read_key: TlsBytes::new(),
            hs_read_iv: TlsBytes::new(),
            hs_write_key: TlsBytes::new(),
            hs_write_iv: TlsBytes::new(),
            hs_read_seq: 0,
            hs_write_seq: 0,
            pending_key_update_response: false,
        }
    }
}
