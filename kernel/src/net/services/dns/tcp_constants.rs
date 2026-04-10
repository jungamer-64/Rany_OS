// Building block: DNS over TCP constants

use super::*;
use alloc::sync::Arc;

/// DNSクライアントを初期化
pub fn init(tick_rate: u64) {
    let client = Arc::new(DnsClient::new(tick_rate));
    match super::shared_client_lock().lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DNS Global lock poisoned (init) - initialization skipped"),
    }
}

/// IPv4 DNSサーバーを設定
pub fn set_ipv4_servers(servers: Vec<Ipv4Address>) {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.set_ipv4_servers(servers);
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (set_ipv4_servers) - operation skipped")
        }
    }
}

/// IPv6 DNSサーバーを設定
pub fn set_ipv6_servers(servers: Vec<Ipv6Address>) {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.set_ipv6_servers(servers);
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (set_ipv6_servers) - operation skipped")
        }
    }
}

/// IPv6 DNSサーバーを追加
pub fn add_ipv6_server(server: Ipv6Address) {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.add_ipv6_server(server);
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (add_ipv6_server) - operation skipped")
        }
    }
}

/// IPv4 DNSサーバーを追加
pub fn add_ipv4_server(server: Ipv4Address) {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.add_ipv4_server(server);
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (add_ipv4_server) - operation skipped")
        }
    }
}

/// キャッシュからIPアドレスを解決
pub fn resolve_cached(name: &str, current_tick: u64) -> Option<Ipv4Address> {
    match super::shared_client_lock().lock() {
        Ok(g) => g
            .as_ref()
            .and_then(|c| c.resolve_cached(name, current_tick)),
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (resolve_cached) - treating as cache miss");
            None
        }
    }
}

/// 非同期でIPv4アドレスを解決 (Global API)
pub async fn resolve_ipv4(name: &str) -> Option<Ipv4Address> {
    // 1. クライアントの Arc を取得 (ロック時間は最小)
    let client = match super::shared_client_lock().lock() {
        Ok(g) => g.as_ref().cloned(),
        Err(_) => None,
    }?;

    // 2. 非同期解決を実行
    client.resolve_ipv4(name).await
}

/// 非同期でIPv6アドレスを解決 (Global API)
pub async fn resolve_ipv6(name: &str) -> Option<Ipv6Address> {
    let client = match super::shared_client_lock().lock() {
        Ok(g) => g.as_ref().cloned(),
        Err(_) => None,
    }?;

    client.resolve_ipv6(name).await
}

/// 非同期でTXTレコードを解決 (Global API)
pub async fn resolve_txt(name: &str) -> Option<Vec<DnsTxtView>> {
    let client = match super::shared_client_lock().lock() {
        Ok(g) => g.as_ref().cloned(),
        Err(_) => None,
    }?;

    client.resolve_txt(name).await
}

/// 非同期でSRVレコードを解決 (Global API)
pub async fn resolve_srv(name: &str) -> Option<Vec<DnsSrvRecord>> {
    let client = match super::shared_client_lock().lock() {
        Ok(g) => g.as_ref().cloned(),
        Err(_) => None,
    }?;

    client.resolve_srv(name).await
}

/// 非同期でIPv4逆引き（PTR）を解決 (Global API)
pub async fn resolve_ptr_ipv4(ip: Ipv4Address) -> Option<DnsNameView> {
    let client = match super::shared_client_lock().lock() {
        Ok(g) => g.as_ref().cloned(),
        Err(_) => None,
    }?;

    client.resolve_ptr_ipv4(ip).await
}

/// Build a DNS query for TCP transport (global API)
pub fn build_tcp_query_payload(
    name: &str,
    qtype: DnsQueryType,
) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.build_tcp_query_payload(name, qtype)
            } else {
                Err("DNS client not initialized")
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (build_tcp_query_payload)");
            Err("DNS lock poisoned")
        }
    }
}

/// Parse a DNS response received over TCP (global API)
pub fn parse_tcp_response_payload(
    payload: &kernel_api::resource::net::PacketPayload,
    current_tick: u64,
    expected_name: &str,
    expected_type: DnsQueryType,
) -> Result<DnsResponseView, DnsResponseCode> {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.parse_tcp_response_payload(
                    payload,
                    current_tick,
                    expected_name,
                    expected_type,
                )
            } else {
                Err(DnsResponseCode::ServerFailure)
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (parse_tcp_response_payload)");
            Err(DnsResponseCode::ServerFailure)
        }
    }
}

/// Check if a UDP response requires TCP fallback (global API)
pub fn needs_tcp_fallback(data: &[u8]) -> bool {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.needs_tcp_fallback(data)
            } else {
                false
            }
        }
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (needs_tcp_fallback)");
            false
        }
    }
}

/// 期限切れDNSキャッシュエントリを定期的にクリーンアップ
///
/// ネットワークスタックの`periodic()`から呼び出される。
pub fn cleanup_cache(current_tick: u64) {
    match super::shared_client_lock().lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.cleanup_cache(current_tick);
            }
        }
        Err(_) => log::error!("[NET] DNS Global lock poisoned (cleanup_cache) - operation skipped"),
    }
}
