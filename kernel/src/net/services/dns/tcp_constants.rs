// ============================================================================
// kernel/src/net/services/dns/tcp_constants.rs - DNS over TCP constants
// ============================================================================

use super::*;
use alloc::boxed::Box;

/// DNSクライアントを初期化
pub fn init_in(runtime: crate::net::runtime::NetRuntimeHandle, tick_rate: u64) {
    let client = Box::leak(Box::new(DnsClient::new(runtime, tick_rate)));
    match super::shared_client_lock_in(runtime).lock() {
        Ok(mut g) => *g = Some(client),
        Err(_) => log::error!("[NET] DNS Global lock poisoned (init) - initialization skipped"),
    }
}

/// IPv4 DNSサーバーを設定
pub fn set_ipv4_servers_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    servers: &[Ipv4Address],
) {
    match super::shared_client_lock_in(runtime).lock() {
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
pub fn set_ipv6_servers_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    servers: &[Ipv6Address],
) {
    match super::shared_client_lock_in(runtime).lock() {
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
pub fn add_ipv6_server_in(runtime: crate::net::runtime::NetRuntimeHandle, server: Ipv6Address) {
    match super::shared_client_lock_in(runtime).lock() {
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
pub fn add_ipv4_server_in(runtime: crate::net::runtime::NetRuntimeHandle, server: Ipv4Address) {
    match super::shared_client_lock_in(runtime).lock() {
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
pub fn resolve_cached_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
    current_tick: u64,
) -> Option<Ipv4Address> {
    match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => g
            .as_ref()
            .and_then(|c| c.resolve_cached(name, current_tick)),
        Err(_) => {
            log::error!("[NET] DNS Global lock poisoned (resolve_cached) - treating as cache miss");
            None
        }
    }
}

/// 非同期でIPv4アドレスを解決
pub async fn resolve_ipv4_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
) -> Option<Ipv4Address> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    // 2. 非同期解決を実行
    client.resolve_ipv4(name).await
}

/// 非同期でIPv6アドレスを解決
pub async fn resolve_ipv6_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
) -> Option<Ipv6Address> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    client.resolve_ipv6(name).await
}

/// 非同期でTXTレコードを解決
pub async fn resolve_txt_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
) -> Option<Vec<alloc::string::String>> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    client.resolve_txt(name).await
}

/// 非同期でSRVレコードを解決
pub async fn resolve_srv_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
) -> Option<Vec<DnsSrvRecord>> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    client.resolve_srv(name).await
}

/// 非同期でMXレコードを解決
pub async fn resolve_mx_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
) -> Option<Vec<DnsMxRecord>> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    client.resolve_mx(name).await
}

/// 非同期でIPv4逆引き（PTR）を解決
pub async fn resolve_ptr_ipv4_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    ip: Ipv4Address,
) -> Option<alloc::string::String> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    client.resolve_ptr_ipv4(ip).await
}

/// 非同期でIPv6逆引き（PTR）を解決
pub async fn resolve_ptr_ipv6_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    ip: Ipv6Address,
) -> Option<alloc::string::String> {
    let client = match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => *g,
        Err(_) => None,
    }?;

    client.resolve_ptr_ipv6(ip).await
}

/// Build a DNS query for TCP transport in the specified runtime.
pub fn build_tcp_query_payload_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    name: &str,
    qtype: DnsQueryType,
) -> Result<kernel_api::resource::net::PacketPayload, &'static str> {
    match super::shared_client_lock_in(runtime).lock() {
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

/// Parse a DNS response received over TCP in the specified runtime.
pub fn parse_tcp_response_payload_in(
    runtime: crate::net::runtime::NetRuntimeHandle,
    payload: kernel_api::resource::net::PacketPayload,
    current_tick: u64,
    expected_name: &str,
    expected_type: DnsQueryType,
) -> Result<DnsResponseView, DnsResponseCode> {
    match super::shared_client_lock_in(runtime).lock() {
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

/// Check if a UDP response requires TCP fallback in the specified runtime.
pub fn needs_tcp_fallback_in(runtime: crate::net::runtime::NetRuntimeHandle, data: &[u8]) -> bool {
    match super::shared_client_lock_in(runtime).lock() {
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
pub fn cleanup_cache_in(runtime: crate::net::runtime::NetRuntimeHandle, current_tick: u64) {
    match super::shared_client_lock_in(runtime).lock() {
        Ok(g) => {
            if let Some(client) = g.as_ref() {
                client.cleanup_cache(current_tick);
            }
        }
        Err(_) => log::error!("[NET] DNS Global lock poisoned (cleanup_cache) - operation skipped"),
    }
}
