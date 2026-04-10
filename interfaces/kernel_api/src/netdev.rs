// ============================================================================
// kernel_api/src/netdev.rs - Network device discovery and runtime traits
// ============================================================================

extern crate alloc;

use crate::resource::net::{PacketPayload, PacketRef};
use crate::service::kernel;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const ZERO: Self = Self([0; 6]);

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }

    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum NetPortKind {
    #[default]
    Unknown = 0,
    Virtio = 1,
    Mlx5 = 2,
    Other = 255,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetLogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDriverEvent {
    Interrupt,
    QueueWake { queue_index: u16 },
    Poll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetRxMeta {
    pub queue_index: u16,
    pub header_len: u16,
    pub payload_len: u16,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum NetTxCompletionPolicy {
    #[default]
    QueueAcceptance = 0,
    DeviceCompletion = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetTxMeta {
    pub queue_index: Option<u16>,
    pub flags: u32,
    pub vlan_tag: Option<u16>,
    pub completion_id: Option<u64>,
    pub completion_policy: NetTxCompletionPolicy,
}

impl Default for NetTxMeta {
    fn default() -> Self {
        Self {
            queue_index: None,
            flags: 0,
            vlan_tag: None,
            completion_id: None,
            completion_policy: NetTxCompletionPolicy::QueueAcceptance,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetPortStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub initialized: bool,
}

pub const NETDEV_FLAG_ADMIN_UP: u32 = 1 << 0;
pub const NETDEV_FLAG_BOUND_PORT: u32 = 1 << 1;
pub const NETDEV_FLAG_HEALTHY: u32 = 1 << 2;
pub const NETDEV_FLAG_PRIMARY: u32 = 1 << 3;
pub const NETDEV_FLAG_LINK_UP: u32 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceInfo {
    pub port_id: u64,
    pub if_id: Option<u16>,
    pub kind: NetPortKind,
    pub driver_name: &'static str,
    pub queue_pairs: u16,
    pub mtu: u32,
    pub mac: MacAddress,
    pub flags: u32,
}

impl Default for NetDeviceInfo {
    fn default() -> Self {
        Self {
            port_id: 0,
            if_id: None,
            kind: NetPortKind::Unknown,
            driver_name: "unknown",
            queue_pairs: 1,
            mtu: 1500,
            mac: MacAddress::ZERO,
            flags: 0,
        }
    }
}

pub trait NetPortRuntime: Send + Sync {
    fn alloc_packet(&self) -> Option<PacketRef>;
    fn submit_rx(&self, packet: PacketRef, meta: NetRxMeta) -> Result<(), &'static str>;
    fn schedule_event(&self, event: NetDriverEvent) -> Result<(), &'static str>;
    fn update_link(&self, up: bool) -> Result<(), &'static str>;
    fn log(&self, level: NetLogLevel, message: &str);
}

pub trait NetDevicePort: Send + Sync {
    fn info(&self) -> NetDeviceInfo;

    fn start(&self, runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str>;

    fn bind(&self, _if_id: u16) -> Result<(), &'static str> {
        Ok(())
    }

    fn submit_tx(&self, payload: PacketPayload, meta: NetTxMeta) -> Result<(), &'static str>;

    fn set_interrupts_enabled(&self, _enabled: bool) -> Result<(), &'static str> {
        Ok(())
    }

    fn poll(&self, _if_id: u16) -> Result<(), &'static str> {
        Ok(())
    }

    fn handle_event(&self, if_id: u16, event: NetDriverEvent) -> Result<(), &'static str>;

    fn stats(&self) -> NetPortStats;

    fn stop(&self);
}

pub trait NetDeviceServices: Send + Sync {
    fn devices(&self) -> Vec<NetDeviceInfo>;

    fn primary_device(&self) -> Option<NetDeviceInfo> {
        let devices = self.devices();
        devices
            .iter()
            .copied()
            .find(|device| device.flags & NETDEV_FLAG_PRIMARY != 0)
            .or_else(|| {
                devices
                    .into_iter()
                    .find(|device| device.flags & NETDEV_FLAG_BOUND_PORT != 0)
            })
    }
}

#[inline]
pub fn try_instance() -> Option<&'static dyn NetDeviceServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().netdev()
}

#[inline]
pub fn instance() -> &'static dyn NetDeviceServices {
    try_instance().expect("NetDeviceServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct FakeServices {
        devices: Vec<NetDeviceInfo>,
    }

    impl NetDeviceServices for FakeServices {
        fn devices(&self) -> Vec<NetDeviceInfo> {
            self.devices.clone()
        }
    }

    struct FakePort {
        info: NetDeviceInfo,
        stats: NetPortStats,
    }

    impl NetDevicePort for FakePort {
        fn info(&self) -> NetDeviceInfo {
            self.info
        }

        fn start(&self, _runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str> {
            Ok(())
        }

        fn submit_tx(&self, _payload: PacketPayload, _meta: NetTxMeta) -> Result<(), &'static str> {
            Ok(())
        }

        fn handle_event(&self, _if_id: u16, _event: NetDriverEvent) -> Result<(), &'static str> {
            Ok(())
        }

        fn stats(&self) -> NetPortStats {
            self.stats
        }

        fn stop(&self) {}
    }

    #[test]
    fn mac_address_helpers_roundtrip() {
        let mac = MacAddress::from_octets(1, 2, 3, 4, 5, 6);
        assert_eq!(mac.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }

    #[test]
    fn primary_device_prefers_primary_flag_over_bound_port() {
        let bound = NetDeviceInfo {
            port_id: 1,
            flags: NETDEV_FLAG_BOUND_PORT,
            ..NetDeviceInfo::default()
        };
        let primary = NetDeviceInfo {
            port_id: 2,
            flags: NETDEV_FLAG_PRIMARY,
            ..NetDeviceInfo::default()
        };
        let services = FakeServices {
            devices: vec![bound, primary],
        };

        assert_eq!(services.primary_device(), Some(primary));
    }

    #[test]
    fn net_device_port_trait_object_reports_info_and_stats() {
        let port: Arc<dyn NetDevicePort> = Arc::new(FakePort {
            info: NetDeviceInfo {
                port_id: 99,
                kind: NetPortKind::Virtio,
                driver_name: "fake-port",
                queue_pairs: 2,
                flags: NETDEV_FLAG_HEALTHY,
                ..NetDeviceInfo::default()
            },
            stats: NetPortStats {
                tx_packets: 3,
                rx_packets: 4,
                initialized: true,
                ..NetPortStats::default()
            },
        });

        assert_eq!(port.info().port_id, 99);
        assert_eq!(port.stats().rx_packets, 4);
        assert!(port.stats().initialized);
    }
}
