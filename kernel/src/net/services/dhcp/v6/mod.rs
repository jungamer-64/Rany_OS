// ============================================================================
// kernel/src/net/services/dhcp/v6/mod.rs - サービス / DHCP / v6 モジュール
// ============================================================================

mod client;
mod response;
mod types;

pub(crate) use self::client::DhcpV6Client;
#[cfg(feature = "qemu-test-export")]
pub(crate) use self::client::tests;
pub(crate) use self::types::DHCPV6_CLIENT_PORT;
pub use self::types::DhcpV6State;
