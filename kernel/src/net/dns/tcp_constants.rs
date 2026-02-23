use super::*;


/// DNS over TCP constants
pub mod tcp {
    /// Maximum DNS message size for TCP (RFC 7766)
    /// While UDP is limited to 512 bytes (or 4096 with EDNS),
    /// TCP can carry messages up to 65535 bytes.
    pub const MAX_TCP_MESSAGE_SIZE: usize = 65535;
    
    /// Minimum buffer size for TCP DNS (length prefix + minimal message)
    pub const MIN_TCP_BUFFER_SIZE: usize = 14; // 2 + 12 (header only)
    
    /// Recommended buffer size for TCP DNS queries
    pub const RECOMMENDED_QUERY_BUFFER: usize = 512;
    
    /// Recommended buffer size for TCP DNS responses
    pub const RECOMMENDED_RESPONSE_BUFFER: usize = 4096;
    
    /// TCP connection timeout for DNS (RFC 7766 recommends 30 seconds)
    pub const TCP_TIMEOUT_MS: u64 = 30_000;
    
    /// Idle timeout for persistent TCP connections
    pub const TCP_IDLE_TIMEOUT_MS: u64 = 30_000;
}

/// グローバルDNSクライアント
pub(crate) static DNS_CLIENT: PoisonLock<Option<DnsClient>> = PoisonLock::new(None);

/// DNSクライアントを初期化
pub fn init(tick_rate: u64) {
    let client = DnsClient::new(tick_rate);
    match DNS_CLIENT.lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DNS Global lock poisoned (init) - initialization skipped"),
    }
}

/// DNSサーバーを設定
pub fn set_servers(servers: Vec<Ipv4Address>) {
    match DNS_CLIENT.lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.set_servers(servers);
            }
        }
        Err(_) => log::error!("[NET] DNS Global lock poisoned (set_servers) - operation skipped"),
    }
}

/// キャッシュからIPアドレスを解決
pub fn resolve_cached(name: &str, current_tick: u64) -> Option<Ipv4Address> {
    match DNS_CLIENT.lock() {
        Ok(g) => g.as_ref().and_then(|c| c.resolve_cached(name, current_tick)),
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (resolve_cached) - treating as cache miss");
            None
        }
    }
}

/// Build a DNS query for TCP transport (global API)
/// 
/// Returns the total length including the 2-byte length prefix.
pub fn build_tcp_query(
    buffer: &mut [u8],
    name: &str,
    qtype: DnsQueryType,
) -> Result<usize, &'static str> {
    match DNS_CLIENT.lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.build_tcp_query(buffer, name, qtype)
            } else {
                Err("DNS client not initialized")
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (build_tcp_query)");
            Err("DNS client lock poisoned")
        }
    }
}

/// Parse a DNS response received over TCP (global API)
pub fn parse_tcp_response(
    data: &[u8],
    current_tick: u64,
) -> Result<Vec<DnsRecord>, DnsResponseCode> {
    match DNS_CLIENT.lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.parse_tcp_response(data, current_tick)
            } else {
                Err(DnsResponseCode::ServerFailure)
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (parse_tcp_response)");
            Err(DnsResponseCode::ServerFailure)
        }
    }
}

/// Check if a UDP response requires TCP fallback (global API)
pub fn needs_tcp_fallback(data: &[u8]) -> bool {
    match DNS_CLIENT.lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.needs_tcp_fallback(data)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// 期限切れDNSキャッシュエントリを定期的にクリーンアップ
///
/// ネットワークスタックの`periodic()`から呼び出される。
pub fn cleanup_cache(current_tick: u64) {
    match DNS_CLIENT.lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.cleanup_cache(current_tick);
            }
        }
        Err(_) => {}
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
#[path = "tests.rs"]
pub(crate) mod tests;
