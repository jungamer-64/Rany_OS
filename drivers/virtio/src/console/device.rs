// ============================================================================
// drivers/virtio/src/console/device.rs - Shared VirtIO Console Device Logic
// ============================================================================

use crate::console::features;
use crate::defs::status;
use crate::transport::TransportError;
use crate::transport::VirtioTransport;

use crate::console::*;

/// Shared VirtIO Console Device logic.
#[derive(Debug, Default)]
pub struct VirtioConsoleDevice {
    pub config: VirtioConsoleConfig,
    pub features: u64,
}

impl VirtioConsoleDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the console device.
    pub fn init(&mut self, transport: &dyn VirtioTransport) -> Result<(), TransportError> {
        // 1. Reset
        transport.reset();

        // 2. Acknowledge
        transport.add_status(status::VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Driver
        transport.add_status(status::VIRTIO_STATUS_DRIVER);

        // 4. Negotiate features
        self.negotiate_features(transport);

        // 5. Features OK
        transport.add_status(status::VIRTIO_STATUS_FEATURES_OK);
        if (transport.get_status() & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            transport.add_status(status::VIRTIO_STATUS_FAILED);
            return Err(TransportError::DeviceError);
        }

        // 6. Read config
        self.read_config(transport);

        Ok(())
    }

    pub fn negotiate_features(&mut self, transport: &dyn VirtioTransport) -> u64 {
        let device_features = transport.get_device_features();

        let accepted_features = device_features
            & (crate::core::VIRTIO_F_VERSION_1
                | crate::defs::VIRTIO_F_INDIRECT_DESC
                | features::VIRTIO_CONSOLE_F_SIZE
                | features::VIRTIO_CONSOLE_F_MULTIPORT
                | features::VIRTIO_CONSOLE_F_EMERG_WRITE);

        transport.set_driver_features(accepted_features);
        self.features = accepted_features;
        accepted_features
    }

    pub fn read_config(&mut self, transport: &dyn VirtioTransport) {
        self.config.cols = transport.read_config_u16(0);
        self.config.rows = transport.read_config_u16(2);
        self.config.max_nr_ports = transport.read_config_u32(4);
    }

    pub fn emergency_write(&self, transport: &dyn VirtioTransport, c: u8) {
        transport.write_config_u8(8, c);
    }
}
