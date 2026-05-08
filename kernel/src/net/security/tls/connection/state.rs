// ============================================================================
// kernel/src/net/security/tls/connection/state.rs - Grouped TLS connection state
// ============================================================================

use super::super::{
    CipherSuite, ServerPublicKey, TLS_SERVER_NAME_CAPACITY, TlsBytes, TlsState, TlsVersion,
};
use crate::net::security::ecdh;
use arrayvec::ArrayString;

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
    pub(super) recv_buffer: kernel_api::resource::net::PacketPayload,
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
            recv_buffer: kernel_api::resource::net::PacketPayload::default(),
        }
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
