//! # Observability（オブザーバビリティ）
//!
//! ネットワークサブシステムの監視・診断機能を提供する。
//!
//! - [`counters`] — グローバルなアトミックカウンタ（rx/tx パケット数・バイト数、ドロップ、エラー）
//! - [`trace`] — 構造化トレースイベントのリングバッファ記録
//! - [`snapshot`] — カウンタ・トレース・インターフェース情報の統合スナップショット

pub mod counters;
pub mod trace;
pub mod snapshot;

pub use trace::NetTraceEvent;
pub use snapshot::{NetSnapshot, snapshot};
