// ============================================================================
// drivers/virtio/src/lib.rs - VirtIO Driver
// ============================================================================
//!
//! # VirtIO Driver
//!
//! VirtIO device support (block, network, etc.)
//!
//! ## Architecture
//! - Common VirtQueue definitions
//! - Transport abstraction (PCI/MMIO)
//! - Device-specific drivers
//!
//! Note: Some implementations remain in kernel due to deep dependencies.
//! This crate provides type definitions and core abstractions.

#![no_std]
#![allow(dead_code)]
#![allow(clippy::collapsible_if)] // Clear conditional logic
#![allow(clippy::type_complexity)] // Complex VirtQueue types

extern crate alloc;

pub mod core;
pub mod defs;
pub mod transport;

// Re-export core types
pub use crate::core::*;

// Re-export transport types
pub use transport::{
    TransportError, TransportResult, TransportType, VirtioDeviceInit, VirtioMmioTransport,
    VirtioPciTransport, VirtioTransport,
};

// Re-export commonly used types from defs
pub use defs::{
    VIRTIO_MMIO_MAGIC,
    // Queue constants
    VIRTQUEUE_DEFAULT_SIZE,
    VIRTQUEUE_MAX_SIZE,
    // Status
    VirtioDeviceStatus,
    // Transport types
    // VirtioTransport is defined in `defs` and re-exported below to avoid duplicate definitions.
    VirtioDeviceType,
    VirtioPciCap,
    // PCI
    VirtioPciCapType,
    // Fixed-size rings
    VringAvail256,
    VringAvailHeader,
    // Descriptor types
    VringDesc,
    VringUsed256,
    VringUsedElem,
    VringUsedHeader,
    avail_flags,
    // Features
    common_features,
    // MMIO
    mmio_regs,
    status,
    used_flags,
    vring_flags,
};

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    struct MockTransport {
        status: u8,
        device_features: u64,
        driver_features: u64,
        queue_sizes: [u16; 8],
        selected_queue: u16,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                status: 0,
                device_features: 0xFFFFFFFF,
                driver_features: 0,
                queue_sizes: [256; 8],
                selected_queue: 0,
            }
        }
    }

    impl VirtioTransport for MockTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Network
        }

        fn get_status(&self) -> u8 {
            self.status
        }

        fn set_status(&mut self, status: u8) {
            self.status = status;
        }

        fn get_device_features_low(&self) -> u32 {
            self.device_features as u32
        }

        fn get_device_features_high(&self) -> u32 {
            (self.device_features >> 32) as u32
        }

        fn set_driver_features_low(&mut self, features: u32) {
            self.driver_features =
                (self.driver_features & 0xFFFFFFFF00000000) | features as u64;
        }

        fn set_driver_features_high(&mut self, features: u32) {
            self.driver_features =
                (self.driver_features & 0x00000000FFFFFFFF) | ((features as u64) << 32);
        }

        fn get_num_queues(&self) -> u16 {
            8
        }

        fn select_queue(&mut self, queue_index: u16) {
            self.selected_queue = queue_index;
        }

        fn get_queue_max_size(&self) -> u16 {
            self.queue_sizes[self.selected_queue as usize]
        }

        fn set_queue_size(&mut self, size: u16) {
            self.queue_sizes[self.selected_queue as usize] = size;
        }

        fn is_queue_ready(&self) -> bool {
            false
        }

        fn enable_queue(&mut self) {}
        fn disable_queue(&mut self) {}
        fn set_queue_desc_addr(&mut self, _addr: u64) {}
        fn set_queue_avail_addr(&mut self, _addr: u64) {}
        fn set_queue_used_addr(&mut self, _addr: u64) {}
        fn notify_queue(&mut self, _queue_index: u16) {}
        fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> {
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
        fn write_config_u8(&mut self, _offset: usize, _value: u8) {}
        fn write_config_u16(&mut self, _offset: usize, _value: u16) {}
        fn write_config_u32(&mut self, _offset: usize, _value: u32) {}
        fn transport_type(&self) -> TransportType {
            TransportType::Mmio
        }
    }

    pub fn transport_init_sequence_smoke() -> bool {
        let mut transport = MockTransport::new();
        let mut init = VirtioDeviceInit::new(&mut transport);

        match init.initialize(0xFFFF) {
            Ok(negotiated) => negotiated == 0xFFFF,
            Err(_) => false,
        }
    }
}
