// ============================================================================
// kernel/src/net/security/tls/connection/mod.rs - TLS Connection public boundary
// ============================================================================

pub(crate) use super::error::{TlsError, TlsResult};
pub(crate) use super::{
    AlertDescription, AlertLevel, CipherSuite, ContentType, HandshakeType, ServerPublicKey,
    SessionCache, SessionCacheEntry, SessionId, SessionTicket, TLS_CA_CERTS_CAPACITY,
    TLS_CERT_CHAIN_CAPACITY, TlsBytes, TlsConfig, TlsState, TlsVersion,
};
pub(crate) use crate::net::payload::{
    PacketPayloadBuilder, PacketPayloadView, PayloadRange, PayloadSpanRef, append_payload,
};
pub(crate) use crate::net::security::ecdh;
pub(crate) use kernel_api::resource::net::PacketPayload;

mod client_hello;
mod handshake;
mod record;
mod state;
mod transcript;

use state::{
    CertificateRequestContext, EarlyDataState, HandshakeSecrets, NegotiationState,
    RecordProtectionState, ResumptionState, Tls13State,
};
use super::crypto::{generate_random, has_secure_random};
use transcript::TranscriptState;

const TLS_CLIENT_HELLO_SCRATCH_CAPACITY: usize = 4096;
const TLS_EXTENSION_SCRATCH_CAPACITY: usize = 2048;

/// TLS接続
///
/// # 使用上の注意
/// この構造体は多数のフィールドを持ち、スタック上で数KBを消費します。
/// スタックオーバーフローを避けるため、`Box<TlsConnection>` での
/// ヒープ確保を推奨します。
pub struct TlsConnection {
    config: TlsConfig,
    negotiation: NegotiationState,
    record: RecordProtectionState,
    handshake_secrets: HandshakeSecrets,
    tls13: Tls13State,
    resumption: ResumptionState,
    early_data: EarlyDataState,
    transcript: TranscriptState,
}

impl TlsConnection {
    pub fn new(mut config: TlsConfig) -> Self {
        if !has_secure_random() {
            log::warn!(
                "[TLS][SECURITY] Hardware RNG (RDRAND) unavailable — TLS session keys are generated with a WEAK fallback RNG. Connection security is severely degraded!"
            );
        }

        let client_random = generate_random();
        let server_name = config.server_name.take();

        Self {
            config,
            negotiation: NegotiationState::new(server_name, client_random),
            record: RecordProtectionState::default(),
            handshake_secrets: HandshakeSecrets::default(),
            tls13: Tls13State::default(),
            resumption: ResumptionState::default(),
            early_data: EarlyDataState::default(),
            transcript: TranscriptState::default(),
        }
    }

    pub fn state(&self) -> TlsState {
        self.negotiation.state
    }

    pub fn negotiated_version(&self) -> Option<TlsVersion> {
        self.negotiation.negotiated_version
    }
}
