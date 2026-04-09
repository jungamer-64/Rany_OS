// ============================================================================
// kernel/src/net/services/http/mod.rs
// ============================================================================
//!
//! # HTTP/HTTPS クライアント実装
//!
//! ExoRust カーネル用の非同期・ゼロコピー指向 HTTP/1.1 クライアントです。
//! `TcpConnection` と `TlsConnection` を統合し、セキュアなHTTPSリクエストを
//! フルスクラッチでサポートします。

pub mod client;
pub mod parser;
pub mod server;
pub mod types;
