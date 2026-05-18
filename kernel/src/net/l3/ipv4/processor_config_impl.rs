// ============================================================================
// kernel/src/net/l3/ipv4/processor_config_impl.rs - L3 / IPv4 / 設定処理
// ============================================================================

use super::*;

impl Ipv4Processor {
    /// Create a new IPv4 processor
    pub fn new(config: Ipv4Config) -> Self {
        // Use cryptographically secure random for initial ID and secret
        let random_bytes = match crate::net::security::tls::crypto::generate_random() {
            Ok(bytes) => bytes,
            Err(error) => panic!("[IPv4] secure ID entropy unavailable: {error:?}"),
        };
        let id_init = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);
        let secret = u32::from_le_bytes([
            random_bytes[2],
            random_bytes[3],
            random_bytes[4],
            random_bytes[5],
        ]);

        Ipv4Processor {
            config,
            stats: Ipv4Stats::default(),
            next_id: id_init,
            id_secret: secret,
            reassembler: FragmentReassembler::new(FragmentReassembler::DEFAULT_MAX_BUFFERS),
            pmtu_cache: PmtuCache::new(PmtuCache::DEFAULT_MAX_ENTRIES),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &Ipv4Config {
        &self.config
    }

    /// Set configuration
    pub fn set_config(&mut self, config: Ipv4Config) {
        self.config = config;
    }

    /// Get statistics
    pub fn stats(&self) -> &Ipv4Stats {
        &self.stats
    }

    /// Get fragment reassembler statistics
    pub fn fragment_stats(&self) -> &FragmentStats {
        self.reassembler.stats()
    }

    /// Get PMTU cache statistics
    pub fn pmtu_stats(&self) -> &PmtuStats {
        self.pmtu_cache.stats()
    }

    /// Get Path MTU for a destination
    pub fn get_pmtu(&mut self, dst: Ipv4Address, current_time: u64) -> u16 {
        self.pmtu_cache.get(dst, current_time)
    }

    /// Update Path MTU (called when receiving ICMP Fragmentation Needed)
    pub fn update_pmtu(&mut self, dst: Ipv4Address, mtu: u16, current_time: u64) {
        self.pmtu_cache.update(dst, mtu, current_time);
    }
}
