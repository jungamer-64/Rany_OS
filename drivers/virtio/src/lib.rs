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

#[cfg(test)]
mod qemu_tests {
    use super::*;
    use spin::Mutex;

    #[derive(Debug)]
    struct MockTransport {
        state: Mutex<MockTransportState>,
    }

    #[derive(Debug)]
    struct MockTransportState {
        status: u8,
        device_features: u64,
        driver_features: u64,
        queue_sizes: [u16; 8],
        selected_queue: u16,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                state: Mutex::new(MockTransportState {
                    status: 0,
                    device_features: 0xFFFF_FFFF,
                    driver_features: 0,
                    queue_sizes: [256; 8],
                    selected_queue: 0,
                }),
            }
        }
    }

    impl VirtioTransport for MockTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Network
        }

        fn get_status(&self) -> u8 {
            self.state.lock().status
        }

        fn set_status(&self, status: u8) {
            self.state.lock().status = status;
        }

        fn get_device_features_low(&self) -> u32 {
            self.state.lock().device_features as u32
        }

        fn get_device_features_high(&self) -> u32 {
            (self.state.lock().device_features >> 32) as u32
        }

        fn set_driver_features_low(&self, features: u32) {
            let mut s = self.state.lock();
            s.driver_features = (s.driver_features & 0xFFFF_FFFF_0000_0000) | features as u64;
        }

        fn set_driver_features_high(&self, features: u32) {
            let mut s = self.state.lock();
            s.driver_features = (s.driver_features & 0x0000_0000_FFFF_FFFF) | ((features as u64) << 32);
        }

        fn get_num_queues(&self) -> u16 {
            8
        }

        fn select_queue(&self, queue_index: u16) {
            self.state.lock().selected_queue = queue_index;
        }

        fn get_queue_max_size(&self) -> u16 {
            let s = self.state.lock();
            s.queue_sizes[s.selected_queue as usize]
        }

        fn set_queue_size(&self, size: u16) {
            let mut s = self.state.lock();
            let idx = s.selected_queue as usize;
            s.queue_sizes[idx] = size;
        }

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

    pub fn transport_init_sequence_smoke() -> bool {
        let mut transport = MockTransport::new();
        let init = VirtioDeviceInit::new(&mut transport);

        match init.initialize(0xFFFF) {
            Ok(negotiated) => negotiated == 0xFFFF,
            Err(_) => false,
        }
    }
}


#[cfg(test)]
mod qemu_smoke_tests {
    use super::qemu_tests;

    #[test]
    fn transport_init_sequence_smoke() {
        assert!(qemu_tests::transport_init_sequence_smoke());
    }
}
