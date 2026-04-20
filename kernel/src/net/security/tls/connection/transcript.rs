// ============================================================================
// kernel/src/net/security/tls/connection/transcript.rs - TLS transcript hash state
// ============================================================================

use crate::net::security::tls::HandshakeType;
use crate::net::security::tls::crypto::{SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE};

#[derive(Clone)]
pub(super) struct TranscriptState {
    sha256: crate::crypto::sha256::Sha256,
    sha384: crate::crypto::sha384::Sha384,
    len: usize,
    initialized: bool,
    server_finished_sha256: Option<[u8; SHA256_OUTPUT_SIZE]>,
    server_finished_sha384: Option<[u8; SHA384_OUTPUT_SIZE]>,
}

impl Default for TranscriptState {
    fn default() -> Self {
        Self {
            sha256: crate::crypto::sha256::Sha256::new(),
            sha384: crate::crypto::sha384::Sha384::new(),
            len: 0,
            initialized: false,
            server_finished_sha256: None,
            server_finished_sha384: None,
        }
    }
}

impl TranscriptState {
    pub(super) fn initialize(&mut self) {
        self.sha256.reset();
        self.sha384.reset();
        self.len = 0;
        self.initialized = true;
        self.server_finished_sha256 = None;
        self.server_finished_sha384 = None;
    }

    pub(super) fn set_bytes(&mut self, data: &[u8]) {
        self.initialize();
        self.update(data);
    }

    pub(super) fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.sha384.update(data);
        self.len = self.len.saturating_add(data.len());
        self.initialized = true;
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub(super) fn current_sha256(&self) -> [u8; SHA256_OUTPUT_SIZE] {
        self.sha256.snapshot()
    }

    pub(super) fn current_sha384(&self) -> [u8; SHA384_OUTPUT_SIZE] {
        self.sha384.snapshot()
    }

    pub(super) fn replace_with_message_hash(&mut self, use_384: bool) {
        let digest_len = if use_384 {
            SHA384_OUTPUT_SIZE
        } else {
            SHA256_OUTPUT_SIZE
        };
        let mut synthetic = [0u8; 4 + SHA384_OUTPUT_SIZE];
        synthetic[0] = HandshakeType::MessageHash as u8;
        synthetic[3] = digest_len as u8;
        if use_384 {
            synthetic[4..4 + SHA384_OUTPUT_SIZE].copy_from_slice(&self.current_sha384());
        } else {
            synthetic[4..4 + SHA256_OUTPUT_SIZE].copy_from_slice(&self.current_sha256());
        }
        self.set_bytes(&synthetic[..4 + digest_len]);
    }

    pub(super) fn snapshot_server_finished(&mut self) {
        self.server_finished_sha256 = Some(self.current_sha256());
        self.server_finished_sha384 = Some(self.current_sha384());
    }

    pub(super) fn server_finished_sha256(&self) -> Option<[u8; SHA256_OUTPUT_SIZE]> {
        self.server_finished_sha256
    }

    pub(super) fn server_finished_sha384(&self) -> Option<[u8; SHA384_OUTPUT_SIZE]> {
        self.server_finished_sha384
    }
}
