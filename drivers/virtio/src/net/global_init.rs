use super::managed::{NetCompletionHandler, VirtioNetDevice};
use super::{NetRuntime, VirtioNetError};
use crate::transport::{VirtioMmioTransport, VirtioTransport};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use exorust_sync::PoisonRwLock;
use kernel_api::netdev::{
    MacAddress, NetDeviceInfo, NetDevicePort, NetDriverEvent, NetPortId, NetPortRuntimeHandle,
    NetPortStats, NetTxMeta, TxSubmission,
};

const VIRTIO_PORT_ID_BASE: u64 = 0x0001_0000;

pub struct VirtioNetRegistryState {
    devices: PoisonRwLock<BTreeMap<u8, Arc<VirtioNetDevice>>>,
    runtimes: PoisonRwLock<BTreeMap<u8, NetPortRuntimeHandle>>,
}

impl VirtioNetRegistryState {
    pub const fn new() -> Self {
        Self {
            devices: PoisonRwLock::new(BTreeMap::new()),
            runtimes: PoisonRwLock::new(BTreeMap::new()),
        }
    }
}

pub(crate) static VIRTIO_NET_REGISTRY: VirtioNetRegistryState = VirtioNetRegistryState::new();

fn registry_state() -> &'static VirtioNetRegistryState {
    &VIRTIO_NET_REGISTRY
}

fn virtio_port_id(index: u8) -> NetPortId {
    NetPortId::new(VIRTIO_PORT_ID_BASE | index as u64)
}

pub(crate) fn virtio_net_runtime(index: u8) -> Option<NetPortRuntimeHandle> {
    registry_state()
        .runtimes
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .copied()
}

fn install_virtio_net_runtime(index: u8, runtime: NetPortRuntimeHandle) {
    registry_state()
        .runtimes
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, runtime);
}

fn install_virtio_net_device(index: u8, device: Arc<VirtioNetDevice>) {
    registry_state()
        .devices
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, device);
}

pub fn with_virtio_net_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    let devices = registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner());
    devices.get(&index).map(|device| f(device.as_ref()))
}

pub fn for_each_virtio_net<F>(mut f: F)
where
    F: FnMut(u8, &VirtioNetDevice),
{
    let devices = registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner());
    for (index, device) in devices.iter() {
        f(*index, device.as_ref());
    }
}

pub fn bind_virtio_net_interface(index: u8, if_id: u16) -> bool {
    with_virtio_net_at_index(index, |device| device.set_net_if_id(if_id)).is_some()
}

pub fn set_virtio_net_completion_handler(index: u8, handler: Option<NetCompletionHandler>) -> bool {
    with_virtio_net_at_index(index, |device| device.set_completion_handler(handler)).is_some()
}

fn process_device_events(index: u8) -> Result<(), &'static str> {
    with_virtio_net_at_index(index, |device| {
        device.process_interrupt_deferred();
        device.refill_rx_queues();
    })
    .ok_or("VirtIO-Net device removed")
}

fn set_device_interrupts_enabled(index: u8, enabled: bool) -> Result<(), &'static str> {
    with_virtio_net_at_index(index, |device| device.set_interrupts_enabled_all(enabled))
        .ok_or("VirtIO-Net device not initialized")
}

#[derive(Debug, Clone, Copy)]
pub struct VirtioNetDriverAdapter {
    index: u8,
}

impl VirtioNetDriverAdapter {
    pub const fn new(index: u8) -> Self {
        Self { index }
    }

    fn default_info(&self) -> NetDeviceInfo {
        NetDeviceInfo {
            port_id: virtio_port_id(self.index),
            if_id: None,
            driver_name: "virtio-net",
            queue_pairs: 1,
            mtu: 1500,
            mac: MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01),
            flags: 0,
        }
    }
}

impl NetDevicePort for VirtioNetDriverAdapter {
    fn info(&self) -> NetDeviceInfo {
        with_virtio_net_at_index(self.index, |device| {
            device.info_snapshot(virtio_port_id(self.index))
        })
        .unwrap_or_else(|| self.default_info())
    }

    fn start(&self, runtime: NetPortRuntimeHandle) -> Result<(), &'static str> {
        install_virtio_net_runtime(self.index, runtime);
        Ok(())
    }

    fn bind(&self, if_id: u16) -> Result<(), &'static str> {
        if bind_virtio_net_interface(self.index, if_id) {
            Ok(())
        } else {
            Err("VirtIO-Net device not initialized for binding")
        }
    }

    fn submit_tx_chain(
        &self,
        submission: TxSubmission<'_>,
        meta: NetTxMeta,
    ) -> Result<(), &'static str> {
        with_virtio_net_at_index(self.index, |device| {
            device
                .enqueue_send_submission(submission, meta)
                .map_err(|err| match err {
                    VirtioNetError::QueueFull => "TX queue full",
                    _ => "enqueue_send_submission failed",
                })
        })
        .unwrap_or(Err("VirtIO-Net device not initialized"))
    }

    fn set_interrupts_enabled(&self, enabled: bool) -> Result<(), &'static str> {
        set_device_interrupts_enabled(self.index, enabled)
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
        with_virtio_net_at_index(self.index, |device| device.net_port_stats()).unwrap_or_default()
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

pub unsafe fn init_virtio_net_for_device_at_index(
    index: u8,
    base_addr: usize,
    runtime: Arc<dyn NetRuntime>,
) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };
    let mut device = VirtioNetDevice::new(index, Box::new(transport), runtime);
    device.init()?;
    install_virtio_net_device(index, Arc::new(device));
    Ok(())
}

pub unsafe fn init_virtio_net_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    runtime: Arc<dyn NetRuntime>,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new(index, transport, runtime);
    device.init()?;
    install_virtio_net_device(index, Arc::new(device));
    Ok(())
}

pub fn handle_virtio_net_interrupt_for_index(index: u8) {
    if let Some(device) = get_virtio_net_device_at_index(index) {
        device.ack_interrupt();
        device.handle_interrupt();
    }
}

#[cfg(test)]
pub(crate) fn clear_virtio_net_devices_for_tests() {
    registry_state()
        .devices
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
    use crate::defs::VirtioDeviceType;
    use crate::transport::TransportType;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use kernel_api::dma::{CpuOwned, DmaSlice, InternalDmaReclaimer};

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
            crate::VIRTQUEUE_MAX_SIZE
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

    fn release_test_dma_buffer(ptr: *mut u8, size: usize, _host_addr: u64) {
        let raw = core::ptr::slice_from_raw_parts_mut(ptr, size);
        unsafe {
            drop(Box::<[u8]>::from_raw(raw));
        }
    }

    #[derive(Debug)]
    struct NoopRuntime;

    impl NetRuntime for NoopRuntime {
        fn alloc_dma(
            &self,
            size: usize,
            _purpose: super::super::NetDmaPurpose,
        ) -> Result<DmaSlice<CpuOwned>, VirtioNetError> {
            let mut backing = vec![0u8; size].into_boxed_slice();
            let ptr = backing.as_mut_ptr();
            let len = backing.len();
            let raw = Box::into_raw(backing) as *mut u8;
            let addr = ptr as usize as u64;
            Ok(unsafe {
                DmaSlice::from_internal_parts_unchecked(
                    addr,
                    addr,
                    raw,
                    len,
                    InternalDmaReclaimer::KernelBuffer {
                        releaser: Some(release_test_dma_buffer),
                    },
                )
            })
        }

        fn alloc_packet(&self) -> Option<PacketRef> {
            None
        }
        fn map_packet(
            &self,
            _packet: &PacketRef,
            _direction: super::super::NetDmaDirection,
        ) -> Result<super::super::NetDmaMappingToken, VirtioNetError> {
            Err(VirtioNetError::DeviceError)
        }
        fn release_dma_mapping(&self, _mapping: super::super::NetDmaMappingToken) {}
        fn receive_packet(
            &self,
            _queue_index: u16,
            _packet: PacketRef,
            _header_len: usize,
            _payload_len: usize,
        ) {
        }
        fn transmit_complete(&self, _queue_index: u16, _lease_id: kernel_api::netdev::TxLeaseId) {}
        fn schedule_wake(&self, _queue_index: u16) {}
        fn log(&self, _level: log::Level, _msg: core::fmt::Arguments) {}
    }

    #[test]
    fn registry_tracks_multiple_device_indices() {
        clear_virtio_net_devices_for_tests();

        let runtime: Arc<dyn NetRuntime> = Arc::new(NoopRuntime);
        install_virtio_net_device(
            0,
            Arc::new(VirtioNetDevice::new(
                0,
                Box::new(NoopTransport),
                runtime.clone(),
            )),
        );
        install_virtio_net_device(
            3,
            Arc::new(VirtioNetDevice::new(3, Box::new(NoopTransport), runtime)),
        );

        let mut seen = Vec::new();
        for_each_virtio_net(|index, _| seen.push(index));
        seen.sort_unstable();

        assert_eq!(seen, vec![0, 3]);
        assert!(with_virtio_net_at_index(0, |_| ()).is_some());
        assert!(with_virtio_net_at_index(3, |_| ()).is_some());
    }

    #[test]
    fn driver_adapter_reports_missing_device_as_uninitialized() {
        clear_virtio_net_devices_for_tests();

        let info = virtio_net_driver_adapter(9).info();
        assert_eq!(info.port_id, NetPortId::new(VIRTIO_PORT_ID_BASE | 9));
        assert_eq!(info.flags, 0);
    }
}
