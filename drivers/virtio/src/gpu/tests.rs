use kernel_api::abi::driver::PackedPciLocation;

use super::*;
use crate::{TransportType, VIRTQUEUE_MAX_SIZE, VirtioTransport};

#[derive(Debug)]
struct NoopTransport;

fn test_device() -> PackedPciLocation {
    PackedPciLocation::new(0, 0, 0x41, 0)
}

impl VirtioTransport for NoopTransport {
    fn device_type(&self) -> crate::VirtioDeviceType {
        crate::VirtioDeviceType::Gpu
    }

    fn get_status(&self) -> u8 {
        crate::defs::status::VIRTIO_STATUS_ACKNOWLEDGE
            | crate::defs::status::VIRTIO_STATUS_DRIVER
            | crate::defs::status::VIRTIO_STATUS_FEATURES_OK
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_gpu_device_creation() {
    let gpu = VirtioGpu::new(Box::new(NoopTransport), test_device());
    assert!(!gpu.is_initialized());
    assert!(!gpu.has_3d_support());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_gpu_alloc_resource_id() {
    let gpu = VirtioGpu::new(Box::new(NoopTransport), test_device());
    assert_eq!(gpu.alloc_resource_id(), 1);
    assert_eq!(gpu.alloc_resource_id(), 2);
    assert_eq!(gpu.alloc_resource_id(), 3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_gpu_ctrl_hdr_new() {
    let hdr = GpuCtrlHdr::new(GpuCmd::GetDisplayInfo);
    assert_eq!(hdr.cmd_type, GpuCmd::GetDisplayInfo as u32);
    assert_eq!(hdr.flags, 0);
    assert_eq!(hdr.fence_id, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_gpu_ctrl_hdr_with_fence() {
    let hdr = GpuCtrlHdr::new(GpuCmd::ResourceFlush).with_fence(42);
    assert_eq!(hdr.flags, 1);
    assert_eq!(hdr.fence_id, 42);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_rect_new() {
    let r = Rect::new(10, 20, 640, 480);
    assert_eq!(r.x, 10);
    assert_eq!(r.y, 20);
    assert_eq!(r.width, 640);
    assert_eq!(r.height, 480);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_gpu_error_variants() {
    assert_ne!(GpuError::DeviceNotFound, GpuError::InitFailed);
    assert_ne!(GpuError::OutOfMemory, GpuError::DeviceError);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_align_up() {
    assert_eq!(align_up(0, 4), 0);
    assert_eq!(align_up(1, 4), 4);
    assert_eq!(align_up(4, 4), 4);
    assert_eq!(align_up(5, 4), 8);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_pixel_format_values() {
    assert_eq!(PixelFormat::B8G8R8A8Unorm as u32, 1);
    assert_eq!(PixelFormat::R8G8B8A8Unorm as u32, 67);
}
