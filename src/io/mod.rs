// ============================================================================
// I/O Subsystem Module
// ============================================================================
pub mod virtio;

pub use virtio::{async_receive_packet, VirtioSharedState};
