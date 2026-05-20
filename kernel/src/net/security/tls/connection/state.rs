// ============================================================================
// kernel/src/net/security/tls/connection/state.rs - Grouped TLS connection state
// ============================================================================

use super::super::{
    NegotiatedCipherSuite, ServerPublicKey, TlsBytes, TlsError, TlsResult, TlsServerName,
};
use crate::net::payload::{append_payload, move_payload_window_owned};
use crate::net::security::ecdh;
use kernel_api::resource::net::PacketPayload;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InitialPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClientHelloSentPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ServerHelloReceivedPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HelloRetryPendingPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EncryptedExtensionsPendingPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CertificatePendingPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CertificateVerifyPendingPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ServerFinishedPendingPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ServerFinishedReceivedPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EstablishedPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClosingPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClosedPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FailedPhase;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TlsConnectionPhase {
    Initial(InitialPhase),
    ClientHelloSent(ClientHelloSentPhase),
    ServerHelloReceived(ServerHelloReceivedPhase),
    HelloRetryPending(HelloRetryPendingPhase),
    EncryptedExtensionsPending(EncryptedExtensionsPendingPhase),
    CertificatePending(CertificatePendingPhase),
    CertificateVerifyPending(CertificateVerifyPendingPhase),
    ServerFinishedPending(ServerFinishedPendingPhase),
    ServerFinishedReceived(ServerFinishedReceivedPhase),
    Established(EstablishedPhase),
    Closing(ClosingPhase),
    Closed(ClosedPhase),
    Failed(FailedPhase),
}

impl TlsConnectionPhase {
    pub(super) const fn initial() -> Self {
        Self::Initial(InitialPhase)
    }

    pub(super) const fn client_hello_sent() -> Self {
        Self::ClientHelloSent(ClientHelloSentPhase)
    }

    pub(super) const fn server_hello_received() -> Self {
        Self::ServerHelloReceived(ServerHelloReceivedPhase)
    }

    pub(super) const fn hello_retry_pending() -> Self {
        Self::HelloRetryPending(HelloRetryPendingPhase)
    }

    pub(super) const fn encrypted_extensions_pending() -> Self {
        Self::EncryptedExtensionsPending(EncryptedExtensionsPendingPhase)
    }

    pub(super) const fn certificate_pending() -> Self {
        Self::CertificatePending(CertificatePendingPhase)
    }

    pub(super) const fn certificate_verify_pending() -> Self {
        Self::CertificateVerifyPending(CertificateVerifyPendingPhase)
    }

    pub(super) const fn server_finished_pending() -> Self {
        Self::ServerFinishedPending(ServerFinishedPendingPhase)
    }

    pub(super) const fn server_finished_received() -> Self {
        Self::ServerFinishedReceived(ServerFinishedReceivedPhase)
    }

    pub(super) const fn established() -> Self {
        Self::Established(EstablishedPhase)
    }

    pub(super) const fn closing() -> Self {
        Self::Closing(ClosingPhase)
    }

    pub(super) const fn closed() -> Self {
        Self::Closed(ClosedPhase)
    }

    pub(super) const fn failed() -> Self {
        Self::Failed(FailedPhase)
    }

    pub(super) const fn reads_handshake_records(self) -> bool {
        matches!(
            self,
            Self::EncryptedExtensionsPending(_)
                | Self::CertificatePending(_)
                | Self::CertificateVerifyPending(_)
                | Self::ServerFinishedPending(_)
                | Self::ServerFinishedReceived(_)
        )
    }

    pub(super) const fn is_established(self) -> bool {
        matches!(self, Self::Established(_))
    }

    pub(super) const fn is_server_finished_received(self) -> bool {
        matches!(self, Self::ServerFinishedReceived(_))
    }

    pub(super) const fn is_hello_retry_pending(self) -> bool {
        matches!(self, Self::HelloRetryPending(_))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NegotiatedTlsParameters {
    Pending,
    Tls13 { cipher: NegotiatedCipherSuite },
}

impl NegotiatedTlsParameters {
    pub(super) const fn pending() -> Self {
        Self::Pending
    }

    pub(super) const fn tls13(cipher: NegotiatedCipherSuite) -> Self {
        Self::Tls13 { cipher }
    }

    pub(super) fn cipher(self) -> TlsResult<NegotiatedCipherSuite> {
        match self {
            Self::Pending => Err(TlsError::HandshakeFailure),
            Self::Tls13 { cipher } => Ok(cipher),
        }
    }
}

pub(super) struct NegotiationState {
    pub(super) server_name: Option<TlsServerName>,
    pub(super) phase: TlsConnectionPhase,
    pub(super) negotiated: NegotiatedTlsParameters,
    pub(super) client_random: [u8; 32],
    pub(super) server_random: [u8; 32],
}

impl NegotiationState {
    pub(super) fn new(server_name: Option<TlsServerName>, client_random: [u8; 32]) -> Self {
        Self {
            server_name,
            phase: TlsConnectionPhase::initial(),
            negotiated: NegotiatedTlsParameters::pending(),
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
    pub(super) read_seq: TlsSeqNo,
    pub(super) write_seq: TlsSeqNo,
    pub(super) ingress: TlsRecordIngressQueue,
}

impl Default for RecordProtectionState {
    fn default() -> Self {
        Self {
            read_key: TlsBytes::new(),
            write_key: TlsBytes::new(),
            read_iv: TlsBytes::new(),
            write_iv: TlsBytes::new(),
            read_seq: TlsSeqNo::new(),
            write_seq: TlsSeqNo::new(),
            ingress: TlsRecordIngressQueue::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct TlsSeqNo(u64);

impl TlsSeqNo {
    pub(super) const fn new() -> Self {
        Self(0)
    }

    pub(super) fn current(self) -> TlsResult<u64> {
        if self.0 == u64::MAX {
            Err(TlsError::SequenceExhausted)
        } else {
            Ok(self.0)
        }
    }

    pub(super) fn advance(&mut self) -> TlsResult<()> {
        let current = self.current()?;
        self.0 = current.checked_add(1).ok_or(TlsError::SequenceExhausted)?;
        Ok(())
    }

    pub(super) fn reset(&mut self) {
        self.0 = 0;
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
    pub(super) hs_read_seq: TlsSeqNo,
    pub(super) hs_write_seq: TlsSeqNo,
    pub(super) key_update_response: KeyUpdateResponseState,
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
            hs_read_seq: TlsSeqNo::new(),
            hs_write_seq: TlsSeqNo::new(),
            key_update_response: KeyUpdateResponseState::idle(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyUpdateResponseState {
    Idle,
    Required,
}

impl KeyUpdateResponseState {
    pub(super) const fn idle() -> Self {
        Self::Idle
    }

    pub(super) fn require(&mut self) {
        *self = Self::Required;
    }

    pub(super) fn take_required(&mut self) -> bool {
        match *self {
            Self::Idle => false,
            Self::Required => {
                *self = Self::Idle;
                true
            }
        }
    }
}
