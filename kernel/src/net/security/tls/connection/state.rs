// ============================================================================
// kernel/src/net/security/tls/connection/state.rs - Typed TLS 1.3 state
// ============================================================================

use super::super::{NegotiatedCipherSuite, ServerPublicKey, TlsBytes, TlsError, TlsResult};
use super::record::TlsRecordPacket;
use crate::net::payload::append_payload;
use crate::net::security::ecdh;
use kernel_api::resource::net::{PacketPayload, PacketPayloadFront, PacketWindowError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TlsClientRandom([u8; 32]);

impl TlsClientRandom {
    pub(super) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TlsServerRandom([u8; 32]);

impl TlsServerRandom {
    pub(super) const HELLO_RETRY_REQUEST: Self = Self([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ]);

    pub(super) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) const fn is_hello_retry_request(self) -> bool {
        matches!(self, Self::HELLO_RETRY_REQUEST)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SelectedTls13Parameters {
    cipher: NegotiatedCipherSuite,
}

impl SelectedTls13Parameters {
    pub(super) const fn new(cipher: NegotiatedCipherSuite) -> Self {
        Self { cipher }
    }

    pub(super) const fn cipher(self) -> NegotiatedCipherSuite {
        self.cipher
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TlsHandshakeProgress {
    Initial,
    ClientHelloSent,
    ServerHelloReceived(SelectedTls13Parameters),
    HelloRetryPending(SelectedTls13Parameters),
    EncryptedExtensionsPending(SelectedTls13Parameters),
    CertificatePending(SelectedTls13Parameters),
    CertificateVerifyPending(SelectedTls13Parameters),
    ServerFinishedPending(SelectedTls13Parameters),
    ServerFinishedReceived(SelectedTls13Parameters),
    Established(SelectedTls13Parameters),
    Closing(SelectedTls13Parameters),
    Closed,
    Failed,
}

impl TlsHandshakeProgress {
    pub(super) const fn selected(self) -> TlsResult<SelectedTls13Parameters> {
        match self {
            Self::ServerHelloReceived(selected)
            | Self::HelloRetryPending(selected)
            | Self::EncryptedExtensionsPending(selected)
            | Self::CertificatePending(selected)
            | Self::CertificateVerifyPending(selected)
            | Self::ServerFinishedPending(selected)
            | Self::ServerFinishedReceived(selected)
            | Self::Established(selected)
            | Self::Closing(selected) => Ok(selected),
            Self::Initial | Self::ClientHelloSent | Self::Closed | Self::Failed => {
                Err(TlsError::HandshakeFailure)
            }
        }
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

pub(super) struct NegotiationState {
    pub(super) progress: TlsHandshakeProgress,
    pub(super) client_random: TlsClientRandom,
    pub(super) server_random: TlsServerRandom,
}

impl NegotiationState {
    pub(super) fn new(client_random: [u8; 32]) -> Self {
        Self {
            progress: TlsHandshakeProgress::Initial,
            client_random: TlsClientRandom::new(client_random),
            server_random: TlsServerRandom::new([0; 32]),
        }
    }

    pub(super) const fn selected(&self) -> TlsResult<SelectedTls13Parameters> {
        self.progress.selected()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TlsRecordEpoch {
    Handshake,
    Application,
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
}

impl Default for TlsRecordIngressQueue {
    fn default() -> Self {
        Self {
            payload: PacketPayload::default(),
        }
    }
}

impl TlsRecordIngressQueue {
    pub(super) fn push(&mut self, payload: PacketPayload) {
        append_payload(&mut self.payload, payload);
    }

    pub(super) fn pop_ready_record(&mut self) -> TlsResult<Option<TlsRecordPacket>> {
        let Some(len) = TlsRecordPacket::ready_len(&self.payload)? else {
            return Ok(None);
        };
        let queued = core::mem::take(&mut self.payload);
        let record = match queued.take_front(len) {
            Ok(PacketPayloadFront::Whole(record)) => record,
            Ok(PacketPayloadFront::Prefix { front, remainder }) => {
                self.payload = remainder;
                front
            }
            Err(PacketWindowError::BackendSplitUnsupported) => {
                self.payload = PacketPayload::default();
                return Err(TlsError::DecodeError);
            }
            Err(PacketWindowError::Empty | PacketWindowError::OutOfBounds) => {
                self.payload = PacketPayload::default();
                return Err(TlsError::DecodeError);
            }
        };
        TlsRecordPacket::parse(record).map(Some)
    }
}

pub(super) struct HandshakeSecrets {
    pub(super) master_secret: [u8; 48],
    pre_master_secret: PreMasterSecretState,
    pub(super) local_ecdh_keypair: ecdh::EcdhKeyPair,
    server_public_key: VerifiedSigningKeyState,
}

impl HandshakeSecrets {
    pub(super) fn new(local_ecdh_keypair: ecdh::EcdhKeyPair) -> Self {
        Self {
            master_secret: [0; 48],
            pre_master_secret: PreMasterSecretState::Missing,
            local_ecdh_keypair,
            server_public_key: VerifiedSigningKeyState::Missing,
        }
    }

    pub(super) fn set_pre_master_secret(&mut self, shared_secret: &[u8]) -> TlsResult<()> {
        let mut bytes = TlsBytes::new();
        bytes.set(shared_secret).ok_or(TlsError::DecodeError)?;
        self.pre_master_secret = PreMasterSecretState::Ready(bytes);
        Ok(())
    }

    pub(super) fn pre_master_secret(&self) -> TlsResult<&TlsBytes<64>> {
        match &self.pre_master_secret {
            PreMasterSecretState::Ready(secret) => Ok(secret),
            PreMasterSecretState::Missing => Err(TlsError::HandshakeFailure),
        }
    }

    pub(super) fn install_server_public_key(&mut self, public_key: ServerPublicKey) {
        self.server_public_key = VerifiedSigningKeyState::Verified(public_key);
    }

    pub(super) fn server_public_key(&self) -> TlsResult<&ServerPublicKey> {
        match &self.server_public_key {
            VerifiedSigningKeyState::Verified(public_key) => Ok(public_key),
            VerifiedSigningKeyState::Missing => Err(TlsError::CertificateError),
        }
    }
}

enum PreMasterSecretState {
    Missing,
    Ready(TlsBytes<64>),
}

enum VerifiedSigningKeyState {
    Missing,
    Verified(ServerPublicKey),
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
            key_update_response: KeyUpdateResponseState::Idle,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyUpdateResponseState {
    Idle,
    Required,
}

impl KeyUpdateResponseState {
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
