use super::managed::VirtioNetDevice;
use super::{NetRuntime, VirtioNetError};
use crate::transport::VirtioTransport;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use exorust_sync::PoisonRwLock;

struct VirtioNetRegistryState {
    devices: PoisonRwLock<BTreeMap<u8, Arc<VirtioNetDevice>>>,
}

impl VirtioNetRegistryState {
    pub const fn new() -> Self {
        Self {
            devices: PoisonRwLock::new(BTreeMap::new()),
        }
    }
}

static VIRTIO_NET_REGISTRY: VirtioNetRegistryState = VirtioNetRegistryState::new();

fn registry_state() -> &'static VirtioNetRegistryState {
    &VIRTIO_NET_REGISTRY
}

fn install_virtio_net_device(index: u8, device: Arc<VirtioNetDevice>) {
    registry_state()
        .devices
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(index, device);
}

pub(crate) fn with_virtio_net_at_index<F, R>(index: u8, f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    let device = registry_state()
        .devices
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&index)
        .cloned()?;
    Some(f(device.as_ref()))
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub(crate) unsafe fn init_virtio_net_with_transport_at_index(
    index: u8,
    transport: Box<dyn VirtioTransport>,
    runtime: Arc<dyn NetRuntime>,
    queue_msix_table: Option<u16>,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new(transport, runtime, queue_msix_table);
    device.init()?;
    install_virtio_net_device(index, Arc::new(device));
    Ok(())
}

pub(crate) fn handle_virtio_net_interrupt_for_index(index: u8) {
    let _ = with_virtio_net_at_index(index, |device| {
        device.ack_interrupt();
        device.handle_interrupt();
    });
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

        fn lease_rx_buffer(&self) -> Option<crate::net::RxDmaLease> {
            None
        }
        fn receive_packet(
            &self,
            _queue_index: u16,
            _buffer: crate::net::RxDmaLease,
            _header_len: usize,
            _payload_len: usize,
            _flags: u32,
        ) {
        }
        fn transmit_complete(&self, _queue_index: u16, _lease_id: kernel_api::netdev::TxLeaseId) {}
        fn schedule_interrupt(&self) {}
        fn update_link(&self, _up: bool) {}
        fn log(&self, _level: log::Level, _msg: core::fmt::Arguments) {}
    }

    #[test]
    fn registry_tracks_multiple_device_indices() {
        registry_state()
            .devices
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .clear();

        let runtime0: Arc<dyn NetRuntime> = Arc::new(NoopRuntime);
        install_virtio_net_device(
            0,
            Arc::new(VirtioNetDevice::new(
                Box::new(NoopTransport),
                runtime0,
                None,
            )),
        );
        let runtime3: Arc<dyn NetRuntime> = Arc::new(NoopRuntime);
        install_virtio_net_device(
            3,
            Arc::new(VirtioNetDevice::new(
                Box::new(NoopTransport),
                runtime3,
                None,
            )),
        );

        let seen = registry_state()
            .devices
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .keys()
            .copied()
            .collect::<Vec<_>>();

        assert_eq!(seen, vec![0, 3]);
        assert!(with_virtio_net_at_index(0, |_| ()).is_some());
        assert!(with_virtio_net_at_index(3, |_| ()).is_some());
    }
}
