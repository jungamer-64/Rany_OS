// ============================================================================
// kernel/src/net/api/shell.rs - 後方互換性ファサード
// ============================================================================
//! # Shell API 後方互換モジュール
//!
//! 以前のモノリシックな `shell.rs` は責任ごとに下記サブモジュールへ分割された:
//!
//! - [`super::config`]       — ネットワーク設定・統計の取得
//! - [`super::connections`]  — TCP/UDP接続情報・ARP操作
//! - [`super::icmp`]         — ICMP Echo (ping) 操作
//! - [`super::dhcp`]         — DHCP v4/v6 操作
//! - [`super::diagnostics`]  — 診断・DNS・スナップショット
//!
//! このファイルは既存コード (`crate::net::api::shell::*`) との後方互換のため
//! 全シンボルを再エクスポートする。新規コードは各サブモジュールを直接参照すること。

// ── 再エクスポート: config ──────────────────────────────
#[allow(deprecated)]
pub use super::config::{
    NetworkConfigSnapshot, NetworkStatsSnapshot,
    get_network_config, get_network_stats,
    get_network_config_async, get_network_stats_async,
    GetConfigFuture, GetStatsFuture,
};

// ── 再エクスポート: connections ─────────────────────────
#[allow(deprecated)]
pub use super::connections::{
    TcpConnectionInfo, UdpEndpointInfo, ArpCacheEntry,
    get_tcp_connections, get_udp_endpoints, get_arp_cache, arp_cache_insert,
    get_arp_cache_async, arp_cache_insert_async,
    get_udp_endpoints_async,
    get_tcp_connections_async,
};

// ── 再エクスポート: icmp ────────────────────────────────
#[allow(deprecated)]
pub use super::icmp::{send_icmp_echo, send_icmp_echo_async, ping_async, ping_async_with_timeout};

// ── 再エクスポート: dhcp ────────────────────────────────
#[allow(deprecated)]
pub use super::dhcp::{
    DhcpRuntimeState, DhcpOfferInfo,
    dhcp_discover, dhcp_request, dhcp_release,
    dhcp_last_declined, dhcp_last_released,
    init_dhcp_runtime, dhcp_state, dhcp_renew,
    dhcp_state_async, dhcp_renew_async, dhcp_release_async,
    dhcp_discover_async, dhcp_last_declined_async, dhcp_last_released_async,
};

// ── 再エクスポート: diagnostics ─────────────────────────
pub use super::diagnostics::{dns_resolve, network_snapshot, network_recent_events};

pub fn init_network_shell() {
    // no-op: runtime state is sourced from the actual network stack/DHCP clients.
}
