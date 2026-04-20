// ============================================================================
// kernel/src/net/services/dns/client_impl.rs - サービス / DNS / クライアント実装
// ============================================================================

use super::*;

impl DnsClient {
    /// 新しいDNSクライアントを作成
    pub fn new(tick_rate: u64) -> Self {
        Self {
            ipv4_servers: PoisonLock::new(Vec::new()),
            ipv6_servers: PoisonLock::new(Vec::new()),
            cache: PoisonLock::new(DnsCache::new(tick_rate)),
            stats: DnsStats::new(),
            pending_ids: PoisonLock::new(BTreeMap::new()),
        }
    }
}
