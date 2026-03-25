use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use exorust_sync::PoisonLock;
use kernel_api::abi::driver::PackedPciLocation;

use super::*;
use crate::{
    TransportType, VIRTQUEUE_MAX_SIZE, VirtioDeviceStatus, VirtioDeviceType, VirtioTransport,
};

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

/// Noop transport for unit-testing balloon without real hardware
struct NoopTransport {
    /// Simulated config space (at least 8 bytes for num_pages + actual)
    config: PoisonLock<[u8; 16]>,
}

impl core::fmt::Debug for NoopTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoopTransport").finish()
    }
}

fn test_device() -> PackedPciLocation {
    PackedPciLocation::new(0, 0, 0x30, 0)
}

impl NoopTransport {
    fn new() -> Self {
        Self {
            config: PoisonLock::new([0u8; 16]),
        }
    }

    /// Create a transport with a pre-set target num_pages value
    fn with_target(num_pages: u32) -> Self {
        let mut config = [0u8; 16];
        config[0..4].copy_from_slice(&num_pages.to_le_bytes());
        Self {
            config: PoisonLock::new(config),
        }
    }
}

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Balloon
    }

    fn get_status(&self) -> u8 {
        // Return FeaturesOk to allow init to succeed
        VirtioDeviceStatus::Acknowledge as u8
            | VirtioDeviceStatus::Driver as u8
            | VirtioDeviceStatus::FeaturesOk as u8
    }

    fn set_status(&self, _status: u8) {}

    fn get_device_features_low(&self) -> u32 {
        (features::VIRTIO_BALLOON_F_MUST_TELL_HOST | features::VIRTIO_BALLOON_F_DEFLATE_ON_OOM)
            as u32
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

    fn read_config_u8(&self, offset: usize) -> u8 {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if offset < config.len() {
            config[offset]
        } else {
            0
        }
    }

    fn read_config_u16(&self, offset: usize) -> u16 {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if offset + 1 < config.len() {
            u16::from_le_bytes([config[offset], config[offset + 1]])
        } else {
            0
        }
    }

    fn read_config_u32(&self, offset: usize) -> u32 {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if offset + 3 < config.len() {
            u32::from_le_bytes([
                config[offset],
                config[offset + 1],
                config[offset + 2],
                config[offset + 3],
            ])
        } else {
            0
        }
    }

    fn write_config_u8(&self, offset: usize, value: u8) {
        let mut config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if offset < config.len() {
            config[offset] = value;
        }
    }

    fn write_config_u16(&self, offset: usize, value: u16) {
        let mut config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if offset + 1 < config.len() {
            let bytes = value.to_le_bytes();
            config[offset] = bytes[0];
            config[offset + 1] = bytes[1];
        }
    }

    fn write_config_u32(&self, offset: usize, value: u32) {
        let mut config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if offset + 3 < config.len() {
            let bytes = value.to_le_bytes();
            config[offset] = bytes[0];
            config[offset + 1] = bytes[1];
            config[offset + 2] = bytes[2];
            config[offset + 3] = bytes[3];
        }
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Mmio
    }
}

/// Helper: create a VirtioBalloonDevice with manually wired queues
/// (bypasses hardware init, directly injects VirtQueues)
fn make_test_device(transport: NoopTransport) -> (VirtioBalloonDevice, TestQueues) {
    let queue_size: u16 = 8;

    // Inflate queue memory
    let mut inflate_descs = vec![VringDesc::default(); queue_size as usize];
    let inflate_desc_ptr = inflate_descs.as_mut_ptr();
    let mut inflate_avail = vec![0u16; 2 + queue_size as usize];
    let inflate_avail_ptr = inflate_avail.as_mut_ptr() as *mut VringAvail;
    let inflate_used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut inflate_used_mem = vec![0u8; inflate_used_bytes];
    let inflate_used_ptr = inflate_used_mem.as_mut_ptr() as *mut VringUsed;

    let inflate_vq = unsafe {
        VirtQueue::new(
            0,
            queue_size,
            inflate_desc_ptr,
            inflate_avail_ptr,
            inflate_used_ptr,
            None,
            0,
        )
    }
    .expect("inflate_vq");

    // Deflate queue memory
    let mut deflate_descs = vec![VringDesc::default(); queue_size as usize];
    let deflate_desc_ptr = deflate_descs.as_mut_ptr();
    let mut deflate_avail = vec![0u16; 2 + queue_size as usize];
    let deflate_avail_ptr = deflate_avail.as_mut_ptr() as *mut VringAvail;
    let deflate_used_bytes = core::mem::size_of::<VringUsed>()
        + (queue_size as usize) * core::mem::size_of::<VringUsedElem>();
    let mut deflate_used_mem = vec![0u8; deflate_used_bytes];
    let deflate_used_ptr = deflate_used_mem.as_mut_ptr() as *mut VringUsed;

    let deflate_vq = unsafe {
        VirtQueue::new(
            1,
            queue_size,
            deflate_desc_ptr,
            deflate_avail_ptr,
            deflate_used_ptr,
            None,
            0,
        )
    }
    .expect("deflate_vq");

    let mut dev = VirtioBalloonDevice::new(Box::new(transport), test_device());
    dev.inflate_queue = Some(Arc::new(PoisonLock::new(inflate_vq)));
    dev.deflate_queue = Some(Arc::new(PoisonLock::new(deflate_vq)));
    dev.ready.store(true, Ordering::Release);

    let queues = TestQueues {
        inflate_descs,
        inflate_avail,
        inflate_used_mem,
        inflate_desc_ptr,
        deflate_descs,
        deflate_avail,
        deflate_used_mem,
        deflate_desc_ptr,
    };

    (dev, queues)
}

/// Holds Vec ownership so queue memory stays alive for the test
#[allow(dead_code)]
struct TestQueues {
    inflate_descs: Vec<VringDesc>,
    inflate_avail: Vec<u16>,
    inflate_used_mem: Vec<u8>,
    inflate_desc_ptr: *mut VringDesc,
    deflate_descs: Vec<VringDesc>,
    deflate_avail: Vec<u16>,
    deflate_used_mem: Vec<u8>,
    deflate_desc_ptr: *mut VringDesc,
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_device_creation() {
    let transport = NoopTransport::new();
    let dev = VirtioBalloonDevice::new(Box::new(transport), test_device());
    assert!(!dev.is_ready());
    assert_eq!(dev.features(), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_read_target() {
    let transport = NoopTransport::with_target(1024);
    let dev = VirtioBalloonDevice::new(Box::new(transport), test_device());
    assert_eq!(dev.read_target(), 1024);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_write_actual() {
    let transport = NoopTransport::new();
    let dev = VirtioBalloonDevice::new(Box::new(transport), test_device());
    dev.write_actual(512);
    // Read back from config space offset 4
    let actual = dev.transport.read_config_u32(config_offsets::ACTUAL);
    assert_eq!(actual, 512);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_inflate_not_ready() {
    let transport = NoopTransport::new();
    let dev = VirtioBalloonDevice::new(Box::new(transport), test_device());
    // Device is not ready, inflate should fail with NotReady
    let pfns = [0x1000u32, 0x2000, 0x3000];
    assert_eq!(dev.inflate_pages(&pfns), Err(BalloonError::NotReady));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_inflate_empty_pfns() {
    let transport = NoopTransport::new();
    let (dev, _queues) = make_test_device(transport);
    // Empty PFN array should succeed without submitting
    assert_eq!(dev.inflate_pages(&[]), Ok(()));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
#[ignore = "requires installed kernel DMA services"]
fn test_balloon_inflate_submits_descriptor() {
    let transport = NoopTransport::new();
    let (dev, queues) = make_test_device(transport);

    let pfns = [0x100u32, 0x200, 0x300];
    let result = dev.inflate_pages(&pfns);
    assert_eq!(result, Ok(()));

    // Verify descriptor was written
    let desc = unsafe { *queues.inflate_desc_ptr.add(0) };
    assert_eq!(desc.len, (3 * core::mem::size_of::<u32>()) as u32);
    // Should be readable (no WRITE flag)
    assert_eq!(desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);

    // Verify inflight buffer is tracked
    let inflight = dev
        .inflight_buffers
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert!(inflight.contains_key(&0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
#[ignore = "requires installed kernel DMA services"]
fn test_balloon_deflate_submits_descriptor() {
    let transport = NoopTransport::new();
    let (dev, queues) = make_test_device(transport);

    let pfns = [0x400u32, 0x500];
    let result = dev.deflate_pages(&pfns);
    assert_eq!(result, Ok(()));

    // Verify descriptor was written on deflate queue
    let desc = unsafe { *queues.deflate_desc_ptr.add(0) };
    assert_eq!(desc.len, (2 * core::mem::size_of::<u32>()) as u32);
    assert_eq!(desc.flags & vring_flags::VRING_DESC_F_WRITE, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_feature_bits() {
    assert_eq!(features::VIRTIO_BALLOON_F_MUST_TELL_HOST, 1 << 0);
    assert_eq!(features::VIRTIO_BALLOON_F_STATS_VQ, 1 << 1);
    assert_eq!(features::VIRTIO_BALLOON_F_DEFLATE_ON_OOM, 1 << 2);
    assert_eq!(features::VIRTIO_BALLOON_F_FREE_PAGE_HINT, 1 << 3);
    assert_eq!(features::VIRTIO_BALLOON_F_PAGE_REPORTING, 1 << 5);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_error_variants() {
    assert_ne!(BalloonError::NotReady, BalloonError::IoError);
    assert_ne!(BalloonError::QueueFull, BalloonError::AllocFailed);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_handle_interrupt_no_panic() {
    let transport = NoopTransport::new();
    let (dev, _queues) = make_test_device(transport);
    // Should not panic even with no completions
    dev.handle_interrupt();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_balloon_align_up() {
    assert_eq!(align_up(0, 4), 0);
    assert_eq!(align_up(1, 4), 4);
    assert_eq!(align_up(4, 4), 4);
    assert_eq!(align_up(5, 4), 8);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
}
