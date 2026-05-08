// ============================================================================
// kernel/src/net/security/tls/state.rs - TLS connection state machine labels
// ============================================================================

/// TLS接続状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    Handshaking,
    Tls13WaitEncryptedExtensions,
    Tls13WaitCertificate,
    Tls13WaitCertificateVerify,
    Tls13WaitFinished,
    Tls13ServerFinishedReceived,
    HelloRetryReceived,
    Established,
    Closing,
    Closed,
    Error,
}
