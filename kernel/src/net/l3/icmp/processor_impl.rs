// ============================================================================
// kernel/src/net/l3/icmp/processor_impl.rs - L3 / ICMP / プロセッサ実装
// ============================================================================

use super::*;

impl IcmpProcessor {
    /// Create a new ICMP processor
    pub fn new(_local_ip: Ipv4Address) -> Self {
        IcmpProcessor {
            _local_ip,
            stats: IcmpStats::default(),
            per_ip_rate_limits: alloc::collections::BTreeMap::new(),
            global_last_time: 0,
            global_tokens: 100,  // Egress (sending) tokens
            ingress_tokens: 200, // Ingress (receiving) tokens
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }
}
