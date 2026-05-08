// ============================================================================
// kernel/src/net/services/dhcp/v4/mod.rs - サービス / DHCP / v4 モジュール
// ============================================================================

mod client;
mod state_machine;
mod types;

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;

use self::types::ParsedOptions;

pub use self::types::{
    DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_MAX_MESSAGE_SIZE, DHCP_SERVER_PORT, DhcpAckResult,
    DhcpClient, DhcpHeader, DhcpLease, DhcpMessageType, DhcpOperation, DhcpOption,
    DhcpResponseResult, DhcpState, DhcpV4AppliedConfig,
};
