//! DHCP (Dynamic Host Configuration Protocol) クライアント実装
//!
//! DHCPを使用してIPアドレス、サブネットマスク、ゲートウェイ、
//! DNSサーバーなどのネットワーク設定を自動取得する。
use crate::net::runtime::manager::NetIfId;
use alloc::sync::Arc;

mod runtime;
mod v4;
mod v6;

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::v4::tests as qemu_v4_tests;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) use self::v6::tests as qemu_v6_tests;
pub(crate) use self::runtime::{
    DhcpRuntimeState, clear_primary_interface, ensure_interface_runtime, has_bound_lease,
    interface_v4_client_in, lease_for_interface, mark_primary_interface, primary_v4_client_in,
    primary_v6_client_in, release_interface, restart_interface_runtime,
    unregister_interface_runtime, update_runtime_mac,
};
pub use self::v4::*;
pub use self::v6::*;

pub(crate) fn interface_v4_client(if_id: NetIfId) -> Option<Arc<DhcpClient>> {
    self::runtime::interface_v4_client(if_id)
}

pub(crate) fn primary_interface_if_id() -> Option<NetIfId> {
    self::runtime::primary_interface_if_id()
}
