// ============================================================================
// kernel/src/net/services/dhcp/v6/mod.rs - サービス / DHCP / v6 モジュール
// ============================================================================

mod client;
mod types;

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::client::tests;

pub use self::types::{
    DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT, DhcpV6AppliedConfig, DhcpV6Client, DhcpV6Lease,
    DhcpV6MessageType, DhcpV6ReplyOutcome, DhcpV6State,
};
