// ============================================================================
// drivers/virtio/src/balloon/device.rs - Shared VirtIO Balloon Device Logic
// ============================================================================

use crate::transport::VirtioTransport;
use crate::transport::TransportError;
use crate::defs::status;

/// Shared VirtIO Balloon Device logic.
#[derive(Debug, Default)]
pub struct VirtioBalloonDevice {
    pub num_pages: u32,
    pub actual_pages: u32,
    pub features: u64,
}

impl VirtioBalloonDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the balloon device.
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

        let accepted_features = device_features & (
            crate::core::VIRTIO_F_VERSION_1 |
            crate::defs::VIRTIO_F_INDIRECT_DESC
        );

        transport.set_driver_features(accepted_features);
        self.features = accepted_features;
        accepted_features
    }

    pub fn read_config(&mut self, transport: &dyn VirtioTransport) {
        self.num_pages = transport.read_config_u32(0);
        self.actual_pages = transport.read_config_u32(4);
    }

    pub fn read_target(&self, transport: &dyn VirtioTransport) -> u32 {
        transport.read_config_u32(0)
    }

    pub fn write_actual(&self, transport: &dyn VirtioTransport, pages: u32) {
        transport.write_config_u32(4, pages);
    }
}
