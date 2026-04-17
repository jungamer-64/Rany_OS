// ============================================================================
// tls/connection/state.rs - Grouped TLS connection state
// ============================================================================

use arrayvec::ArrayString;
use kernel_api::resource::net::PacketPayload;

use super::super::{
    CipherSuite, ServerPublicKey, SessionCache, SessionId, SessionTicket, TLS_SERVER_NAME_CAPACITY,
    TlsBytes, TlsState, TlsVersion,
};
use crate::net::payload::OwnedPayloadRange;
use crate::net::security::ecdh;

pub(super) struct NegotiationState {
    pub(super) server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
    pub(super) state: TlsState,
    pub(super) negotiated_version: Option<TlsVersion>,
    pub(super) negotiated_cipher: Option<CipherSuite>,
    pub(super) session_id: SessionId,
    pub(super) client_random: [u8; 32],
    pub(super) server_random: [u8; 32],
    pub(super) is_tls13: bool,
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
            session_id: SessionId::empty(),
            client_random,
            server_random: [0; 32],
            is_tls13: false,
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
    pub(super) recv_buffer: PacketPayload,
    pub(super) read_mac_key: TlsBytes<32>,
    pub(super) write_mac_key: TlsBytes<32>,
    pub(super) read_cbc_iv: [u8; 16],
    pub(super) write_cbc_iv: [u8; 16],
    pub(super) last_read_ciphertext_block: Option<[u8; 16]>,
    pub(super) last_write_ciphertext_block: Option<[u8; 16]>,
    pub(super) read_encryption_active: bool,
    pub(super) write_encryption_active: bool,
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
            recv_buffer: PacketPayload::default(),
            read_mac_key: TlsBytes::new(),
            write_mac_key: TlsBytes::new(),
            read_cbc_iv: [0; 16],
            write_cbc_iv: [0; 16],
            last_read_ciphertext_block: None,
            last_write_ciphertext_block: None,
            read_encryption_active: false,
            write_encryption_active: false,
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
    pub(super) session_ticket: Option<SessionTicket>,
    pub(super) pending_key_update_response: bool,
    pub(super) client_auth_requested: bool,
    pub(super) certificate_request_context: Option<OwnedPayloadRange>,
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
            session_ticket: None,
            pending_key_update_response: false,
            client_auth_requested: false,
            certificate_request_context: None,
        }
    }
}

pub(super) struct ResumptionState {
    pub(super) session_cache: Option<SessionCache>,
    pub(super) resuming_session: bool,
    pub(super) resumption_master_secret: TlsBytes<48>,
    pub(super) tls13_psk: Option<TlsBytes<48>>,
    pub(super) tls13_psk_identity: Option<OwnedPayloadRange>,
    pub(super) tls13_ticket_age_add: u32,
    pub(super) tls13_using_psk: bool,
    pub(super) tls13_psk_cipher: Option<CipherSuite>,
}

impl Default for ResumptionState {
    fn default() -> Self {
        Self {
            session_cache: None,
            resuming_session: false,
            resumption_master_secret: TlsBytes::new(),
            tls13_psk: None,
            tls13_psk_identity: None,
            tls13_ticket_age_add: 0,
            tls13_using_psk: false,
            tls13_psk_cipher: None,
        }
    }
}

pub(super) struct EarlyDataState {
    pub(super) max_early_data_size: u32,
    pub(super) early_data_buffer: PacketPayload,
    pub(super) early_write_key: TlsBytes<32>,
    pub(super) early_write_iv: TlsBytes<16>,
    pub(super) early_write_seq: u64,
    pub(super) early_data_accepted: bool,
    pub(super) early_data_sent: bool,
}

impl Default for EarlyDataState {
    fn default() -> Self {
        Self {
            max_early_data_size: 0,
            early_data_buffer: PacketPayload::default(),
            early_write_key: TlsBytes::new(),
            early_write_iv: TlsBytes::new(),
            early_write_seq: 0,
            early_data_accepted: false,
            early_data_sent: false,
        }
    }
}
