// ============================================================================
// kernel/src/net/services/dhcp/mod.rs - サービス / DHCP モジュール
// ============================================================================
//! DHCP (Dynamic Host Configuration Protocol) クライアント実装
//!
//! DHCPを使用してIPアドレス、サブネットマスク、ゲートウェイ、
//! DNSサーバーなどのネットワーク設定を自動取得する。
mod runtime;
mod v4;
mod v6;

pub(crate) use self::runtime::{
    DhcpRuntimeState, clear_primary_interface_in, ensure_interface_runtime_in, has_bound_lease_in,
    interface_v4_client_in, lease_for_interface_in, mark_primary_interface_in,
    primary_v4_client_in, primary_v6_client_in, release_interface_in, restart_interface_runtime_in,
    unregister_interface_runtime_in, update_runtime_mac,
};
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::v4::tests as qemu_v4_tests;
pub use self::v4::{
    DHCP_CLIENT_PORT, DHCP_MAGIC_COOKIE, DHCP_MAX_MESSAGE_SIZE, DHCP_SERVER_PORT, DhcpAckResult,
    DhcpClient, DhcpHeader, DhcpLease, DhcpMessageType, DhcpOperation, DhcpOption,
    DhcpResponseResult, DhcpState, DhcpV4AppliedConfig,
};
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::v6::tests as qemu_v6_tests;
pub use self::v6::{
    DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT, DhcpV6AppliedConfig, DhcpV6Client, DhcpV6Lease,
    DhcpV6MessageType, DhcpV6ReplyOutcome, DhcpV6State,
};
