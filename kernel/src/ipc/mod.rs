// ============================================================================
// IPC (Inter-Process Communication) Module
// 設計書 3.2/8.2: ドメイン間通信とプロキシパターン
// ============================================================================
pub mod proxy;
pub mod rref;
pub use proxy::{BasicProxy, DomainProxy, ProxyError, ProxyResult};
pub use rref::{DomainId, RRef, reclaim_domain_resources};
