//! A console service owns its receive/transmit queues through observed reset.
#![deny(unsafe_code)]

pub mod features {
    pub const VIRTIO_CONSOLE_F_SIZE: u64 = 1 << 0;
    pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;
    pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 1 << 2;
}

mod device;
pub use device::*;
mod queue;
#[cfg(test)]
mod tests;
