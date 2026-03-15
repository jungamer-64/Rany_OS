use super::{VirtioNetDevice, VirtioNetError};
use crate::io::virtio::transport::VirtioMmioTransport;
use crate::io::virtio::transport::VirtioTransport;
use crate::net::runtime::context::default_runtime_context;
use crate::net::runtime::device::NetDeviceKey;
use crate::sync::{PoisonLock, PoisonRwLock};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kernel_api::resource::net::PacketRef;
use kernel_api::service::netdev::{
    MacAddress, NETDEV_FLAG_HEALTHY, NETDEV_FLAG_LINK_UP, NetDeviceInfo, NetDevicePort,
    NetDriverEvent, NetPortKind, NetPortRuntime, NetPortStats, NetTxMeta,
};

pub(crate) struct VirtioNetRegistryState {
    devices: PoisonRwLock<BTreeMap<u8, Arc<PoisonLock<VirtioNetDevice>>>>,
    transports: PoisonRwLock<BTreeMap<u8, Arc<dyn VirtioTransport>>>,
    runtimes: PoisonRwLock<BTreeMap<u8, Arc<dyn NetPortRuntime>>>,
}

impl VirtioNetRegistryState {
    pub const fn new() -> Self {
        Self {
            devices: PoisonRwLock::new(BTreeMap::new()),
            transports: PoisonRwLock::new(BTreeMap::new()),
            runtimes: PoisonRwLock::new(BTreeMap::new()),
        }
    }
}

fn registry_state() -> &'static VirtioNetRegistryState {
    &default_runtime_context().virtio_net
}

pub(crate) fn virtio_net_runtime(index: u8) -> Option<Arc<dyn NetPortRuntime>> {
    registry_state()
        .runtimes
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()
}

fn install_virtio_net_runtime(index: u8, runtime: Arc<dyn NetPortRuntime>) {
    registry_state()
        .runtimes
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, runtime);
}

fn install_virtio_net_device(index: u8, device: VirtioNetDevice) {
    let transport = device.transport.clone();
    registry_state()
        .devices
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, Arc::new(PoisonLock::new(device)));
    registry_state()
        .transports
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, transport);
}

#[cfg(test)]
fn test_device_for_index(index: u8) -> crate::io::iommu::types::DeviceId {
    let device = crate::io::iommu::types::DeviceId::new(0, 0, index, 0);
    crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device);
    device
}

#[derive(Debug, Clone, Copy)]
pub struct VirtioNetDriverAdapter {
    index: u8,
}

impl VirtioNetDriverAdapter {
    pub const fn new(index: u8) -> Self {
        Self { index }
    }
}

fn submit_zero_copy_tx(index: u8, packet: PacketRef, meta: NetTxMeta) -> Result<(), &'static str> {
    with_virtio_net_device_at_index(index, |device| {
        device
            .enqueue_send_zero_copy(packet, meta)
            .map_err(|err| match err {
                crate::drivers::virtio::net::VirtioNetError::QueueFull => "TX queue full",
                _ => "enqueue_send_zero_copy failed",
            })
    })
    .unwrap_or(Err("VirtIO-Net device not initialized"))
}

fn process_device_events(index: u8) -> Result<(), &'static str> {
    crate::net::runtime::bridge::enter_deferred_rx_mode();
    let result = with_virtio_net_device_at_index(index, |device| {
        device.process_interrupt_deferred();
        device.refill_rx_queues();
    });
    crate::net::runtime::bridge::drain_deferred_rx_packets();
    crate::net::runtime::bridge::flush_batch();

    if result.is_some() {
        Ok(())
    } else {
        Err("VirtIO-Net device removed")
    }
}

impl NetDevicePort for VirtioNetDriverAdapter {
    fn info(&self) -> NetDeviceInfo {
        with_virtio_net_device_at_index(self.index, |device| {
            let mac = device.mac_address();
            NetDeviceInfo {
                port_id: NetDeviceKey::Virtio(self.index).port_id(),
                if_id: device.net_if_id().map(|if_id| if_id.0),
                kind: NetPortKind::Virtio,
                driver_name: "virtio-net",
                queue_pairs: device.core.get_pair_count() as u16,
                mtu: crate::net::runtime::stack::MTU as u32,
                mac: MacAddress::from_octets(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
                flags: NETDEV_FLAG_HEALTHY | NETDEV_FLAG_LINK_UP,
            }
        })
        .unwrap_or(NetDeviceInfo {
            port_id: NetDeviceKey::Virtio(self.index).port_id(),
            if_id: None,
            kind: NetPortKind::Virtio,
            driver_name: "virtio-net",
            queue_pairs: 1,
            mtu: crate::net::runtime::stack::MTU as u32,
            mac: MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01),
            flags: 0,
        })
    }

    fn start(&self, runtime: Arc<dyn NetPortRuntime>) -> Result<(), &'static str> {
        install_virtio_net_runtime(self.index, runtime);
        Ok(())
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        if bind_virtio_net_interface(self.index, crate::net::runtime::manager::NetIfId(if_id)) {
            Ok(())
        } else {
            Err("VirtIO-Net device not initialized for binding")
        }
    }

    fn submit_tx(&self, packet: PacketRef, meta: NetTxMeta) -> Result<(), &'static str> {
        submit_zero_copy_tx(self.index, packet, meta)
    }

    fn poll(&self, _if_id: u16) -> Result<(), &'static str> {
        process_device_events(self.index)
    }

    fn handle_event(&self, _if_id: u16, event: NetDriverEvent) -> Result<(), &'static str> {
        match event {
            NetDriverEvent::Interrupt | NetDriverEvent::QueueWake { .. } | NetDriverEvent::Poll => {
                process_device_events(self.index)
            }
        }
    }

    fn stats(&self) -> NetPortStats {
        with_virtio_net_device_at_index(self.index, |device| NetPortStats {
            tx_packets: device
                .tx_packets
                .load(core::sync::atomic::Ordering::Relaxed) as u64,
            rx_packets: device
                .rx_packets
                .load(core::sync::atomic::Ordering::Relaxed) as u64,
            tx_errors: 0,
            rx_errors: 0,
            initialized: true,
        })
        .unwrap_or_default()
    }

    fn stop(&self) {
        registry_state()
            .runtimes
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.index);
    }
}

pub fn virtio_net_driver_adapter(index: u8) -> Arc<dyn NetDevicePort> {
    Arc::new(VirtioNetDriverAdapter::new(index))
}

pub(crate) fn with_virtio_net_device_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    let device = registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()?;
    let guard = device.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(&guard))
}

fn with_virtio_net_device_at_index_mut<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&mut VirtioNetDevice) -> R,
{
    let device = registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()?;
    let mut guard = device.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(&mut guard))
}

pub(crate) fn has_virtio_net_device(index: u8) -> bool {
    registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&index)
}

fn collect_registered_virtio_net_indices() -> Vec<usize> {
    registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .map(|index| *index as usize)
        .collect()
}

#[cfg(test)]
/// VirtIO ネットワークデバイス（MMIO）を index 指定で初期化
pub fn init_virtio_net_at_index(index: u8, base_addr: usize) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new_with_index_and_device(
        index,
        Box::new(transport),
        test_device_for_index(index),
    );
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

#[cfg(test)]
/// VirtIO ネットワークデバイス（MMIO）を初期化
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    init_virtio_net_at_index(0, base_addr)
}

/// VirtIO ネットワークデバイス（MMIO）を index + IOMMUデバイスID指定で初期化
pub fn init_virtio_net_for_device_at_index(
    index: u8,
    base_addr: usize,
    device: crate::io::iommu::types::DeviceId,
) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new_with_index_and_device(index, Box::new(transport), device);
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// VirtIO ネットワークデバイス（MMIO）を初期化（IOMMUデバイスID付き）
pub fn init_virtio_net_for_device(
    base_addr: usize,
    device: crate::io::iommu::types::DeviceId,
) -> Result<(), VirtioNetError> {
    init_virtio_net_for_device_at_index(0, base_addr, device)
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
pub fn init_virtio_net_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: crate::io::iommu::types::DeviceId,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new_with_index_and_device(index, transport, iommu_device_id);
    device.init()?;
    install_virtio_net_device(index, device);
    Ok(())
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI).
pub fn init_virtio_net_with_transport(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: crate::io::iommu::types::DeviceId,
) -> Result<(), VirtioNetError> {
    init_virtio_net_with_transport_at_index(0, transport, iommu_device_id)
}

/// VirtIO ネットワークデバイスに index 指定でアクセス
pub fn with_virtio_net_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    with_virtio_net_device_at_index(index, f)
}

/// Bind a VirtIO-Net device index to a logical network interface id.
pub fn bind_virtio_net_interface(index: u8, if_id: crate::net::runtime::manager::NetIfId) -> bool {
    with_virtio_net_device_at_index_mut(index, |device| {
        device.set_net_if_id(if_id);
    })
    .is_some()
}

/// 登録済み VirtIO-Net デバイスを列挙して処理する。
pub fn for_each_virtio_net<F>(mut f: F)
where
    F: FnMut(u8, &VirtioNetDevice),
{
    let indices = collect_registered_virtio_net_indices();
    for index in indices {
        let index = index as u8;
        let _ = with_virtio_net_device_at_index(index, |device| {
            f(index, device);
        });
    }
}

/// VirtIO ネットワークデバイスにアクセス
pub fn with_virtio_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    with_virtio_net_device_at_index(0, f)
}

#[cfg(test)]
pub(crate) fn clear_virtio_net_devices_for_tests() {
    registry_state()
        .devices
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    registry_state()
        .transports
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    registry_state()
        .runtimes
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::virtio::{TransportType, VIRTQUEUE_MAX_SIZE, VirtioDeviceType, VirtioTransport};

    #[derive(Debug)]
    struct NoopTransport;

    impl VirtioTransport for NoopTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Network
        }

        fn get_status(&self) -> u8 {
            0
        }

        fn set_status(&self, _status: u8) {}

        fn get_device_features_low(&self) -> u32 {
            0
        }

        fn get_device_features_high(&self) -> u32 {
            0
        }

        fn set_driver_features_low(&self, _features: u32) {}

        fn set_driver_features_high(&self, _features: u32) {}

        fn get_num_queues(&self) -> u16 {
            2
        }

        fn select_queue(&self, _queue_index: u16) {}

        fn get_queue_max_size(&self) -> u16 {
            VIRTQUEUE_MAX_SIZE
        }

        fn set_queue_size(&self, _size: u16) {}

        fn is_queue_ready(&self) -> bool {
            false
        }

        fn enable_queue(&self) {}

        fn disable_queue(&self) {}

        fn set_queue_desc_addr(&self, _addr: u64) {}

        fn set_queue_avail_addr(&self, _addr: u64) {}

        fn set_queue_used_addr(&self, _addr: u64) {}

        fn notify_queue(&self, _queue_index: u16) {}

        fn get_notify_addr(&self, _queue_index: u16) -> Option<u64> {
            None
        }

        fn get_interrupt_status(&self) -> u32 {
            0
        }

        fn ack_interrupt(&self, _status: u32) {}

        fn read_config_u8(&self, _offset: usize) -> u8 {
            0
        }

        fn read_config_u16(&self, _offset: usize) -> u16 {
            0
        }

        fn read_config_u32(&self, _offset: usize) -> u32 {
            0
        }

        fn write_config_u8(&self, _offset: usize, _value: u8) {}

        fn write_config_u16(&self, _offset: usize, _value: u16) {}

        fn write_config_u32(&self, _offset: usize, _value: u32) {}

        fn transport_type(&self) -> TransportType {
            TransportType::Mmio
        }
    }

    #[test]
    fn registry_tracks_zero_and_nonzero_indices_uniformly() {
        clear_virtio_net_devices_for_tests();

        install_virtio_net_device(0, VirtioNetDevice::new_at_index(0, Box::new(NoopTransport)));
        install_virtio_net_device(3, VirtioNetDevice::new_at_index(3, Box::new(NoopTransport)));

        let indices = collect_registered_virtio_net_indices();

        assert_eq!(indices, alloc::vec![0, 3]);
        assert!(has_virtio_net_device(0));
        assert!(has_virtio_net_device(3));
        assert!(with_virtio_net_at_index(0, |_| ()).is_some());
        assert!(with_virtio_net_at_index(3, |_| ()).is_some());
    }
}
