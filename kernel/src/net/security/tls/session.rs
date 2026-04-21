// ============================================================================
// kernel/src/net/security/tls/session.rs - TLS session identifiers and caches
// ============================================================================

use arrayvec::{ArrayString, ArrayVec};

use super::config::{TLS_SERVER_NAME_CAPACITY, TLS_SESSION_CACHE_CAPACITY};
use super::protocol::{CipherSuite, TlsVersion};
use crate::net::payload::{PayloadRange, PayloadSpanRef};
use kernel_api::resource::net::PacketPayload;

/// セッションID
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn empty() -> Self {
        Self([0; 32])
    }
}

/// TLS 1.3 セッションチケット (RFC 8446 Section 4.6.1)
#[derive(Debug)]
pub struct SessionTicket {
    pub lifetime: u32,
    pub age_add: u32,
    pub payload: PacketPayload,
    pub nonce: PayloadRange,
    pub ticket: PayloadRange,
}

impl SessionTicket {
    pub fn nonce_span(&self) -> Option<PayloadSpanRef<'_>> {
        self.nonce.span(&self.payload)
    }

    pub fn ticket_span(&self) -> Option<PayloadSpanRef<'_>> {
        self.ticket.span(&self.payload)
    }
}

/// セッションキャッシュエントリ
#[derive(Clone, Debug)]
pub(crate) struct SessionCacheEntry {
    pub session_id: [u8; 32],
    pub master_secret: [u8; 48],
    pub cipher_suite: CipherSuite,
    pub server_name: Option<ArrayString<TLS_SERVER_NAME_CAPACITY>>,
    pub version: TlsVersion,
}

/// セッションキャッシュ
#[derive(Clone, Debug)]
pub struct SessionCache {
    entries: ArrayVec<SessionCacheEntry, TLS_SESSION_CACHE_CAPACITY>,
}

impl SessionCache {
    pub fn new() -> Self {
        Self {
            entries: ArrayVec::new(),
        }
    }

    pub(crate) fn insert(&mut self, entry: SessionCacheEntry) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|existing| existing.session_id == entry.session_id)
        {
            self.entries.remove(pos);
        } else if self.entries.len() == TLS_SESSION_CACHE_CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub(crate) fn find(&self, session_id: &[u8]) -> Option<&SessionCacheEntry> {
        if session_id.len() != 32 {
            return None;
        }
        self.entries.iter().find(|entry| entry.session_id == session_id)
    }

    pub(crate) fn find_by_server_name(&self, name: &str) -> Option<&SessionCacheEntry> {
        self.entries.iter().rev().find(|entry| {
            entry
                .server_name
                .as_ref()
                .map(|server_name| server_name.as_str())
                == Some(name)
        })
    }
}
