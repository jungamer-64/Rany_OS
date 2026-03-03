// ============================================================================
// IPC (Inter-Process Communication) Module
// 設計書 3.2/8.2: ドメイン間通信とプロキシパターン
// ============================================================================
pub mod proxy;
pub mod rref;

#[allow(unused_imports)]
pub use proxy::{
    BasicProxy,
    DomainProxy,
    ProxyError,
    ProxyResult,
    // パニック捕捉
    begin_proxy_call,
    did_proxy_panic,
    record_proxy_panic,
};
pub use rref::{DomainId, RRef, reclaim_domain_resources};
