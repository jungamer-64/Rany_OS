// ============================================================================
// kernel/src/net/obs/mod.rs - Observability（オブザーバビリティ）
// ============================================================================
//! # Observability（オブザーバビリティ）
//!
//! ネットワークサブシステムの監視・診断機能を提供する。
//!
//! - [`counters`] — runtime-local atomic counters（rx/tx パケット数・バイト数、ドロップ、エラー）
//! - [`trace`] — 構造化トレースイベントのリングバッファ記録
//! - [`snapshot`] — カウンタ・トレース・インターフェース情報の統合スナップショット

pub mod counters;
pub mod snapshot;
pub mod trace;

use crate::net::runtime::NetRuntimeHandle;
use counters::NetCounters;
pub use snapshot::{NetSnapshot, snapshot_in};
pub use trace::NetTraceEvent;
use trace::NetTraceLog;

pub struct NetObservability {
    counters: NetCounters,
    trace: NetTraceLog,
}

impl NetObservability {
    pub const fn new() -> Self {
        Self {
            counters: NetCounters::new(),
            trace: NetTraceLog::new(),
        }
    }

    pub const fn counters(&self) -> &NetCounters {
        &self.counters
    }

    pub const fn trace(&self) -> &NetTraceLog {
        &self.trace
    }
}

pub fn observability_in(runtime: NetRuntimeHandle) -> &'static NetObservability {
    &runtime.context().observability
}
