// ============================================================================
// kernel/src/net/l3/icmp/processor_rate_limit_impl.rs - L3 / ICMP / レート制限処理
// ============================================================================

use super::*;

impl IcmpProcessor {
    /// Update token buckets
    fn update_tokens(&mut self, current_time: u64) {
        let elapsed_global = current_time.saturating_sub(self.global_last_time);
        if elapsed_global >= 10 {
            let new_global_tokens = (elapsed_global / 10) as u32;
            // Egress: 100 pkts/sec, max 100
            self.global_tokens = (self.global_tokens + new_global_tokens).min(100);
            // Ingress: 200 pkts/sec, max 400
            self.ingress_tokens = (self.ingress_tokens + (new_global_tokens * 2)).min(400);
            self.global_last_time = current_time;
        }
    }

    /// Check rate limit for a given IP (Token Bucket) - Egress (Sending)
    /// Returns true if allowed, false if dropped.
    pub fn check_rate_limit(&mut self, ip: Ipv4Address, current_time: u64) -> bool {
        self.update_tokens(current_time);

        if self.global_tokens == 0 {
            return false;
        }

        // Per-IP rate limit: Add 1 token per 100ms, max 20 tokens per IP.
        const MAX_RATE_LIMIT_ENTRIES: usize = 1024;

        // If entry doesn't exist and map is full, we need to evict.
        // We check this before taking the entry to avoid borrow checker issues.
        if !self.per_ip_rate_limits.contains_key(&ip)
            && self.per_ip_rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES
        {
            if let Some(&first_key) = self.per_ip_rate_limits.keys().next() {
                self.per_ip_rate_limits.remove(&first_key);
            }
        }

        let (last_time, tokens) = self
            .per_ip_rate_limits
            .entry(ip)
            .or_insert((current_time, 10));
        let elapsed = current_time.saturating_sub(*last_time);
        if elapsed >= 100 {
            let new_tokens = (elapsed / 100) as u32;
            *tokens = (*tokens + new_tokens).min(20);
            *last_time = current_time;
        }

        if *tokens == 0 {
            return false;
        }

        *tokens -= 1;
        self.global_tokens -= 1;
        true
    }

    /// Check rate limit for an incoming packet
    pub fn check_ingress_rate_limit(&mut self, current_time: u64) -> bool {
        self.update_tokens(current_time);

        if self.ingress_tokens == 0 {
            return false;
        }

        self.ingress_tokens -= 1;
        true
    }
}
