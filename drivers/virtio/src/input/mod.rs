//! Owned input queues retain event storage through completion and observed stop.
#![deny(unsafe_code)]

/// Config select values for querying input device configuration.
pub mod config_select {
    pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
    pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
    pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
    pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
    pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
    pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
    pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioInputEvent {
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}

mod device;
pub use device::*;
mod queue;
#[cfg(test)]
mod tests;
