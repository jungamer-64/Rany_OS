// ============================================================================
// kernel/src/net/security/tls/connection/mod.rs - TLS Connection public boundary
// ============================================================================

pub(crate) use super::error::{TlsError, TlsResult};
pub(crate) use super::{
    AlertDescription, ContentType, HandshakeType, KeyUpdateRequest, ServerPublicKey,
    TLS_CA_CERTS_CAPACITY, TLS_CERT_CHAIN_CAPACITY, TlsBytes, TlsClientConfig,
};
pub(crate) use crate::net::payload::{
    GeneratedPacketWriter, MutablePayloadBounds, OwnedPayloadBounds, PacketPayloadView,
    PayloadRange, PayloadSpanMut, PayloadSpanRef,
};
pub(crate) use crate::net::security::ecdh;
pub(crate) use kernel_api::resource::net::PacketPayload;

mod client_hello;
mod handshake;
mod record;
mod state;
mod transcript;

use super::crypto::generate_random;
use state::{HandshakeSecrets, NegotiationState, RecordProtectionState, Tls13State};
use transcript::TranscriptState;

const TLS_CLIENT_HELLO_SCRATCH_CAPACITY: usize = 4096;
const TLS_EXTENSION_SCRATCH_CAPACITY: usize = 2048;

/// TLS接続
///
/// # 使用上の注意
/// この構造体は多数のフィールドを持ち、スタック上で数KBを消費します。
/// スタックオーバーフローを避けるため、`Box<TlsConnectionCore>` での
/// ヒープ確保を推奨します。
pub struct TlsHandshake {
    core: TlsConnectionCore,
}

pub enum TlsHandshakeStep {
    NeedMoreInput(TlsHandshake),
    SendClientHello {
        handshake: TlsHandshake,
        payload: PacketPayload,
    },
    Established {
        session: TlsEstablishedSession,
        payload: PacketPayload,
    },
}

pub struct TlsEstablishedSession {
    core: TlsConnectionCore,
}

pub struct TlsInboundPlaintext {
    pub application_data: Option<PacketPayload>,
    pub key_update: KeyUpdateAction,
}

pub enum KeyUpdateAction {
    None,
    Send(PacketPayload),
}

pub(crate) struct TlsConnectionCore {
    config: TlsClientConfig,
    negotiation: NegotiationState,
    record: RecordProtectionState,
    handshake_secrets: HandshakeSecrets,
    tls13: Tls13State,
    transcript: TranscriptState,
}

impl TlsHandshake {
    pub fn start(config: TlsClientConfig) -> TlsResult<(Self, PacketPayload)> {
        let mut core = TlsConnectionCore::new(config)?;
        let payload = core.build_client_hello_payload()?;
        Ok((Self { core }, payload))
    }

    pub fn process_incoming_payload(self, payload: PacketPayload) -> TlsResult<TlsHandshakeStep> {
        let mut core = self.core;
        let _ignored_application_data = core.process_incoming_payload(payload)?;

        if core.negotiation.progress.is_server_finished_received() {
            let payload = core.build_client_finished_tls13_payload()?;
            return Ok(TlsHandshakeStep::Established {
                session: TlsEstablishedSession { core },
                payload,
            });
        }

        if core.negotiation.progress.is_hello_retry_pending() {
            let payload = core.build_client_hello_retry()?;
            return Ok(TlsHandshakeStep::SendClientHello {
                handshake: Self { core },
                payload,
            });
        }

        Ok(TlsHandshakeStep::NeedMoreInput(Self { core }))
    }
}

impl TlsEstablishedSession {
    pub fn process_incoming_payload(
        &mut self,
        payload: PacketPayload,
    ) -> TlsResult<TlsInboundPlaintext> {
        let application_data = self.core.process_incoming_payload(payload)?;
        let key_update = match self.core.take_key_update_response_payload()? {
            Some(payload) => KeyUpdateAction::Send(payload),
            None => KeyUpdateAction::None,
        };
        Ok(TlsInboundPlaintext {
            application_data,
            key_update,
        })
    }

    pub fn encrypt_payload(&mut self, payload: PacketPayload) -> TlsResult<PacketPayload> {
        self.core.tls13_encrypt_application_payload(payload)
    }

    pub fn send_close_notify(&mut self) -> TlsResult<PacketPayload> {
        self.core.send_close_notify()
    }
}

impl TlsConnectionCore {
    pub(crate) fn new(config: TlsClientConfig) -> TlsResult<Self> {
        let client_random = generate_random().map_err(|_| TlsError::SecureRandomUnavailable)?;
        let local_ecdh_keypair = ecdh::EcdhKeyPair::generate(ecdh::EcdhGroup::X25519)
            .map_err(|_| TlsError::SecureRandomUnavailable)?;

        Ok(Self {
            config,
            negotiation: NegotiationState::new(client_random),
            record: RecordProtectionState::default(),
            handshake_secrets: HandshakeSecrets::new(local_ecdh_keypair),
            tls13: Tls13State::default(),
            transcript: TranscriptState::default(),
        })
    }
}
