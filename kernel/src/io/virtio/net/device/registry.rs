use super::{VirtioNetDevice, VirtioNetError};
use crate::io::virtio::transport::VirtioMmioTransport;
use crate::io::virtio::transport::VirtioTransport;
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

// ============================================================================
// Global Device Instance
// ============================================================================

/// Primary (legacy) VirtIO-Net device slot kept for compatibility (`index=0`).
pub(crate) static VIRTIO_NET_DEVICE: PoisonLock<Option<VirtioNetDevice>> = PoisonLock::new(None);
/// Additional VirtIO-Net devices (`index != 0`).
pub(crate) static VIRTIO_NET_DEVICES: PoisonRwLock<BTreeMap<u8, Arc<PoisonLock<VirtioNetDevice>>>> =
    PoisonRwLock::new(BTreeMap::new());
/// ISR-safe access to transport layer for interrupt acknowledgement.
pub(crate) static VIRTIO_NET_TRANSPORTS: PoisonRwLock<BTreeMap<u8, Arc<dyn VirtioTransport>>> =
    PoisonRwLock::new(BTreeMap::new());
pub(crate) static VIRTIO_NET_RUNTIMES: PoisonRwLock<BTreeMap<u8, Arc<dyn NetPortRuntime>>> =
    PoisonRwLock::new(BTreeMap::new());

pub(crate) fn virtio_net_runtime(index: u8) -> Option<Arc<dyn NetPortRuntime>> {
    VIRTIO_NET_RUNTIMES
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()
}

fn install_virtio_net_runtime(index: u8, runtime: Arc<dyn NetPortRuntime>) {
    VIRTIO_NET_RUNTIMES
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, runtime);
}

fn install_virtio_net_device(index: u8, device: VirtioNetDevice) {
    let transport = device.transport.clone();
    if index == 0 {
        *VIRTIO_NET_DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = Some(device);
    } else {
        VIRTIO_NET_DEVICES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, Arc::new(PoisonLock::new(device)));
    }
    VIRTIO_NET_TRANSPORTS
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
        VIRTIO_NET_RUNTIMES
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
    if index == 0 {
        return VIRTIO_NET_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(f);
    }

    let device = VIRTIO_NET_DEVICES
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
    if index == 0 {
        let mut guard = VIRTIO_NET_DEVICE.lock().unwrap_or_else(|e| e.into_inner());
        return guard.as_mut().map(f);
    }

    let device = VIRTIO_NET_DEVICES
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()?;
    let mut guard = device.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(&mut guard))
}

pub(crate) fn has_virtio_net_device(index: u8) -> bool {
    if index == 0 {
        return VIRTIO_NET_DEVICE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
    }
    VIRTIO_NET_DEVICES
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&index)
}

fn collect_registered_virtio_net_indices() -> Vec<usize> {
    let mut indices = Vec::new();
    if VIRTIO_NET_DEVICE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
    {
        indices.push(0);
    }
    indices.extend(
        VIRTIO_NET_DEVICES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .map(|index| *index as usize),
    );
    indices
}

#[cfg(test)]
/// VirtIO ネットワークデバイス（MMIO）を index 指定で初期化
pub fn init_virtio_net_at_index(index: u8, base_addr: usize) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device =
        VirtioNetDevice::new_with_index_and_device(index, Box::new(transport), test_device_for_index(index));
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

    let mut device =
        VirtioNetDevice::new_with_index_and_device(index, Box::new(transport), device);
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
    *VIRTIO_NET_DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    VIRTIO_NET_DEVICES
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}
