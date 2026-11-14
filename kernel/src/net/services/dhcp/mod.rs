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
    DhcpRuntimeState, ensure_interface_runtime_in, interface_v4_client_in, primary_v4_client_in,
    primary_v6_client_in, release_interface_in, restart_interface_runtime_in,
    unregister_interface_runtime_in,
};
#[cfg(feature = "qemu-test-export")]
pub(crate) use self::v4::tests as qemu_v4_tests;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::v4::{
    DHCP_MAGIC_COOKIE, DHCP_MAX_MESSAGE_SIZE, DhcpClient, DhcpHeader, DhcpMessageType,
    DhcpOperation, DhcpOption,
};
pub use self::v4::{DhcpAckResult, DhcpLease, DhcpState, DhcpV4AppliedConfig};
#[cfg(feature = "qemu-test-export")]
pub(crate) use self::v6::tests as qemu_v6_tests;
pub use self::v6::{DhcpV6AppliedConfig, DhcpV6State};
