// ============================================================================
// drivers/virtio/src/net/mod.rs - Shared VirtIO Net types
// ============================================================================

use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::resource::net::PacketRef;

pub mod features;

/// Runtime DMA allocation purpose for virtio-net queue and bounce memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDmaPurpose {
    QueueMemory,
    TxBounce,
    RxBounce,
    TxHeaders,
}

/// Kernel-owned allocation hooks used by the portable virtio-net core.
pub trait NetRuntime {
    fn alloc_dma(
        &self,
        size: usize,
        purpose: NetDmaPurpose,
    ) -> Result<DmaSlice<CpuOwned>, VirtioNetError>;

    fn alloc_packet(&self) -> Option<PacketRef>;
}

/// Shared device configuration snapshot.
#[derive(Debug, Clone)]
pub struct VirtioNetConfig {
    pub mac: [u8; 6],
    pub max_queues: u16,
    pub mtu: u16,
}

impl Default for VirtioNetConfig {
    fn default() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            max_queues: 1,
            mtu: 1500,
        }
    }
}

/// Shared VirtIO network header layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const F_NEEDS_CSUM: u8 = 1;
    pub const GSO_TCPV4: u8 = 1;

    pub fn new_tx() -> Self {
        Self::default()
    }

    pub fn with_checksum_offload(mut self, start: u16, offset: u16) -> Self {
        self.flags |= Self::F_NEEDS_CSUM;
        self.csum_start = start;
        self.csum_offset = offset;
        self
    }

    pub fn with_gso_tcpv4(mut self, hdr_len: u16, gso_size: u16) -> Self {
        self.gso_type = Self::GSO_TCPV4;
        self.hdr_len = hdr_len;
        self.gso_size = gso_size;
        self
    }
}

/// Shared statistics snapshot for virtio-net adapters.
#[derive(Debug, Clone, Default)]
pub struct VirtioNetStats {
    pub tx_packets: u32,
    pub rx_packets: u32,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
}

/// Shared error surface for virtio-net adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    NotInitialized,
    QueueFull,
    BufferTooSmall,
    DeviceError,
    Timeout,
}

impl core::fmt::Display for VirtioNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "Device not initialized"),
            Self::QueueFull => write!(f, "Queue is full"),
            Self::BufferTooSmall => write!(f, "Buffer too small"),
            Self::DeviceError => write!(f, "Device error"),
            Self::Timeout => write!(f, "Operation timed out"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VirtioNetHeader;

    #[test]
    fn virtio_net_header_smoke() {
        let header = VirtioNetHeader::new_tx();
        assert_eq!(header.flags, 0);
        assert_eq!(VirtioNetHeader::SIZE, 12);
    }
}
