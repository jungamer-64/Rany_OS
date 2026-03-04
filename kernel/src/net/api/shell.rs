// ============================================================================
// kernel/src/net/api/shell.rs - シェル向けネットワークAPI ファサード
// ============================================================================
//! シェルコマンドおよびテストから使用される統一API。
//!
//! 各サブモジュール (`config`, `icmp`, `dhcp`, `diagnostics`) の公開関数を
//! 単一の名前空間に集約し、`crate::net::api::shell::*` でアクセスできるようにする。

// ---- config ----------------------------------------------------------------
pub use super::config::{
    get_network_config_async,
    get_network_stats_async,
};

// ---- icmp ------------------------------------------------------------------
pub use super::icmp::{
    send_icmp_echo_async,
    ping_async,
    ping_async_with_timeout,
};

// ---- dhcp ------------------------------------------------------------------
pub use super::dhcp::{
    dhcp_v4_state_name,
    dhcp_v6_state_name,
    lease_remaining_secs,
    init_dhcp_runtime,
    dhcp_state,
    dhcp_state_async,
    dhcp_renew_async,
    dhcp_release_async,
    dhcp_discover_async,
    dhcp_last_declined_async,
    dhcp_last_released_async,
};

// ---- diagnostics -----------------------------------------------------------
pub use super::diagnostics::{
    network_snapshot,
    network_recent_events,
};
