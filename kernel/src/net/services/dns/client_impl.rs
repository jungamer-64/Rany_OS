// ============================================================================
// kernel/src/net/services/dns/client_impl.rs - サービス / DNS / クライアント実装
// ============================================================================

use super::*;

impl DnsClient {
    /// 指定runtimeに属するDNSクライアントを作成
    pub fn new(runtime: crate::net::runtime::NetRuntimeHandle, tick_rate: u64) -> Self {
        Self {
            runtime,
            ipv4_servers: PoisonLock::new(Vec::new()),
            ipv6_servers: PoisonLock::new(Vec::new()),
            ipv4_cache: PoisonLock::new(DnsCache::new(tick_rate)),
            ipv6_cache: PoisonLock::new(DnsCache::new(tick_rate)),
            search_domains: PoisonLock::new(Vec::new()),
            stats: DnsStats::new(),
            pending_ids: PoisonLock::new(BTreeMap::new()),
        }
    }
}
