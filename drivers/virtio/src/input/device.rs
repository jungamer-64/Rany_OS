// ============================================================================
// drivers/virtio/src/input/device.rs - Shared VirtIO Input Device Logic
// ============================================================================

use crate::defs::status;
use crate::transport::TransportError;
use crate::transport::VirtioTransport;

/// Shared VirtIO Input Device logic.
#[derive(Debug, Default)]
pub struct VirtioInputDevice {
    pub select: u8,
    pub subsel: u8,
    pub size: u8,
    pub features: u64,
}

impl VirtioInputDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the input device.
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

        Ok(())
    }

    pub fn negotiate_features(&mut self, transport: &dyn VirtioTransport) -> u64 {
        let device_features = transport.get_device_features();

        let accepted_features = device_features
            & (crate::core::VIRTIO_F_VERSION_1 | crate::defs::VIRTIO_F_INDIRECT_DESC);

        transport.set_driver_features(accepted_features);
        self.features = accepted_features;
        accepted_features
    }

    pub fn select_config(&mut self, transport: &dyn VirtioTransport, select: u8, subsel: u8) {
        transport.write_config_u8(0, select); // SELECT
        transport.write_config_u8(1, subsel); // SUBSEL
        self.select = select;
        self.subsel = subsel;
        self.size = transport.read_config_u8(2); // SIZE
    }

    pub fn query_config(
        &self,
        transport: &dyn VirtioTransport,
        select: u8,
        subsel: u8,
    ) -> alloc::vec::Vec<u8> {
        transport.write_config_u8(0, select);
        transport.write_config_u8(1, subsel);
        let size = transport.read_config_u8(2);
        let mut data = alloc::vec::Vec::with_capacity(size as usize);
        for i in 0..size {
            data.push(transport.read_config_u8(8 + i as usize));
        }
        data
    }

    pub fn device_name(&self, transport: &dyn VirtioTransport) -> alloc::vec::Vec<u8> {
        self.query_config(
            transport,
            crate::input::config_select::VIRTIO_INPUT_CFG_ID_NAME,
            0,
        )
    }
}
