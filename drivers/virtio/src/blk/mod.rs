//! Block commands execute on an owned split queue. The host retains payload
//! DMA; the device core owns protocol metadata and one terminal notification.

mod protocol;
mod queue;
pub use protocol::*;
pub use queue::*;
