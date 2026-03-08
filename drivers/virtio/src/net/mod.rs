// ============================================================================
// drivers/virtio/src/net/mod.rs - Shared VirtIO Net types
// ============================================================================

use core::ptr::NonNull;
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::resource::net::PacketRef;

pub mod features;
pub mod device;

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
    
    /// Schedule a waker for a queue event.
    fn schedule_wake(&self, queue_index: u16);
}

/// Shared VirtIO network queue implementation.
#[derive(Debug)]
pub struct NetVirtQueue {
    pub vq: crate::core::virtqueue::VirtQueue,
    /// Physical address of the TX headers (if this is a TX queue)
    pub tx_header_phys: Option<u64>,
    /// Virtual address of the TX headers (if this is a TX queue)
    pub tx_headers: Option<NonNull<VirtioNetHeader>>,
}

unsafe impl Send for NetVirtQueue {}
unsafe impl Sync for NetVirtQueue {}

impl NetVirtQueue {
    /// Create a new network queue.
    pub unsafe fn new(
        vq: crate::core::virtqueue::VirtQueue,
        tx_header_phys: Option<u64>,
        tx_headers: Option<*mut VirtioNetHeader>,
    ) -> Self {
        Self {
            vq,
            tx_header_phys,
            tx_headers: tx_headers.map(|p| unsafe { NonNull::new_unchecked(p) }),
        }
    }

    /// Add a TX buffer to the queue.
    pub unsafe fn add_tx_buffer(
        &self,
        header: &VirtioNetHeader,
        data_phys: u64,
        data_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let desc_idx = self.vq.alloc_desc().ok_or(VirtioNetError::QueueFull)?;
        let data_desc_idx = match self.vq.alloc_desc() {
            Some(idx) => idx,
            None => {
                self.vq.free_desc(desc_idx);
                return Err(VirtioNetError::QueueFull);
            }
        };

        let header_ptr = self.tx_headers.ok_or(VirtioNetError::DeviceError)?;
        let header_dma_base = self.tx_header_phys.ok_or(VirtioNetError::DeviceError)?;

        unsafe {
            // Write header
            let header_slot = &mut *header_ptr.as_ptr().add(desc_idx as usize);
            *header_slot = *header;

            // Header descriptor
            let d0 = self.vq.get_desc_mut(desc_idx);
            d0.addr = header_dma_base + (desc_idx as u64 * VirtioNetHeader::SIZE as u64);
            d0.len = VirtioNetHeader::SIZE as u32;
            d0.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
            d0.next = data_desc_idx;

            // Data descriptor
            let d1 = self.vq.get_desc_mut(data_desc_idx);
            d1.addr = data_phys;
            d1.len = data_len as u32;
            d1.flags = 0;
            d1.next = 0;

            self.vq.submit_avail(desc_idx);
        }

        Ok(desc_idx)
    }

    /// Add an RX buffer to the queue.
    pub unsafe fn add_rx_buffer(
        &self,
        phys_addr: u64,
        len: usize,
    ) -> Result<u16, VirtioNetError> {
        let desc_idx = self.vq.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            let d0 = self.vq.get_desc_mut(desc_idx);
            d0.addr = phys_addr;
            d0.len = len as u32;
            d0.flags = crate::defs::vring_flags::VRING_DESC_F_WRITE;
            d0.next = 0;

            self.vq.submit_avail(desc_idx);
        }

        Ok(desc_idx)
    }
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

/// Helper for network queue memory layout.
pub struct QueueMemoryLayout {
    pub desc_size: usize,
    pub avail_size: usize,
    pub used_size: usize,
    pub used_offset: usize,
    pub header_offset: usize,
    pub total_size: usize,
}

impl QueueMemoryLayout {
    pub fn calculate(queue_index: u16, queue_size: u16) -> Self {
        let (desc_size, avail_size, used_offset, vring_total_size) =
            crate::core::virtqueue::VirtQueue::calculate_layout(queue_size);

        let header_align = core::mem::align_of::<VirtioNetHeader>();
        let header_offset = (vring_total_size + header_align - 1) & !(header_align - 1);
        let header_table_size = VirtioNetHeader::SIZE * queue_size as usize;

        let total_size = if (queue_index % 2) == 1 {
            header_offset + header_table_size
        } else {
            vring_total_size
        };

        Self {
            desc_size,
            avail_size,
            used_size: (vring_total_size - used_offset),
            used_offset,
            header_offset,
            total_size,
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

impl From<crate::transport::TransportError> for VirtioNetError {
    fn from(err: crate::transport::TransportError) -> Self {
        match err {
            crate::transport::TransportError::Timeout => Self::Timeout,
            _ => Self::DeviceError,
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
