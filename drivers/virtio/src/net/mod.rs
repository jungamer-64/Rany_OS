// ============================================================================
// drivers/virtio/src/net/mod.rs - Shared VirtIO Net types
// ============================================================================

use core::ptr::NonNull;
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::netdev::{NetTxSegment, TxLeaseId};
use kernel_api::resource::net::PacketRef;

pub mod device;
pub mod driver;
pub mod features;
mod global_init;
pub mod inflight;
pub mod managed;

pub use global_init::*;
pub use inflight::InflightTracker;
pub use managed::{ManagedNetVirtQueue, NetCompletionHandler, NetCompletionKind, VirtioNetDevice};

/// In-flight RX packet state.
#[derive(Debug)]
pub struct RxInflight {
    pub packet: PacketRef,
    pub dma_mapping: Option<NetDmaMappingToken>,
}

/// In-flight TX packet state.
#[derive(Debug)]
pub struct TxInflight {
    pub lease_id: TxLeaseId,
}

/// Opaque DMA mapping token returned by the runtime.
///
/// The driver core only uses the hardware-visible device address and passes the
/// token back to the runtime for teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDmaMappingToken {
    device_addr: u64,
    release_key: Option<u64>,
    mapped_len: u64,
}

impl NetDmaMappingToken {
    pub fn direct(device_addr: u64) -> Self {
        Self {
            device_addr,
            release_key: None,
            mapped_len: 0,
        }
    }

    pub fn mapped(device_addr: u64, release_key: u64, mapped_len: u64) -> Self {
        Self {
            device_addr,
            release_key: Some(release_key),
            mapped_len,
        }
    }

    pub fn device_address(&self) -> u64 {
        self.device_addr
    }

    pub fn release_key(&self) -> Option<u64> {
        self.release_key
    }

    pub fn mapped_len(&self) -> u64 {
        self.mapped_len
    }

    pub fn requires_unmap(&self) -> bool {
        self.release_key.is_some()
    }
}

/// Runtime DMA allocation purpose for virtio-net queue and bounce memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDmaPurpose {
    QueueMemory,
    TxBounce,
    RxBounce,
    TxHeaders,
}

/// DMA direction for IOMMU mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

/// Kernel-owned allocation hooks used by the portable virtio-net core.
pub trait NetRuntime: Send + Sync {
    fn alloc_dma(
        &self,
        size: usize,
        purpose: NetDmaPurpose,
    ) -> Result<DmaSlice<CpuOwned>, VirtioNetError>;

    fn alloc_packet(&self) -> Option<PacketRef>;

    /// Map a packet for DMA access by the device (IOMMU support).
    fn map_packet(
        &self,
        packet: &PacketRef,
        direction: NetDmaDirection,
    ) -> Result<NetDmaMappingToken, VirtioNetError>;

    /// Release a DMA mapping previously returned by `map_packet()`.
    fn release_dma_mapping(&self, mapping: NetDmaMappingToken);

    /// Called when a packet has been received.
    fn receive_packet(
        &self,
        queue_index: u16,
        packet: PacketRef,
        header_len: usize,
        payload_len: usize,
    );

    /// Called when a packet transmission is complete.
    fn transmit_complete(&self, queue_index: u16, lease_id: TxLeaseId);

    /// Schedule a waker for a queue event.
    fn schedule_wake(&self, queue_index: u16);

    /// Log a message from the driver core.
    fn log(&self, level: log::Level, msg: core::fmt::Arguments);
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

    /// Add a TX buffer chain backed by caller-retained packet segments.
    pub unsafe fn add_tx_buffer_chain(
        &self,
        header: &VirtioNetHeader,
        segments: &[NetTxSegment],
    ) -> Result<u16, VirtioNetError> {
        if segments.is_empty() {
            return Err(VirtioNetError::DeviceError);
        }

        let desc_idx = self.vq.alloc_desc().ok_or(VirtioNetError::QueueFull)?;
        let mut data_descs = alloc::vec::Vec::with_capacity(segments.len());
        for _ in segments {
            let Some(desc) = self.vq.alloc_desc() else {
                self.vq.free_desc(desc_idx);
                for allocated in data_descs {
                    self.vq.free_desc(allocated);
                }
                return Err(VirtioNetError::QueueFull);
            };
            data_descs.push(desc);
        }

        let header_ptr = self.tx_headers.ok_or(VirtioNetError::DeviceError)?;
        let header_dma_base = self.tx_header_phys.ok_or(VirtioNetError::DeviceError)?;

        let header_slot = unsafe { &mut *header_ptr.as_ptr().add(desc_idx as usize) };
        *header_slot = *header;

        let header_desc = self.vq.get_desc_mut(desc_idx);
        header_desc.addr = header_dma_base + (desc_idx as u64 * VirtioNetHeader::SIZE as u64);
        header_desc.len = VirtioNetHeader::SIZE as u32;
        header_desc.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
        header_desc.next = data_descs[0];

        for (index, segment) in segments.iter().enumerate() {
            let desc = self.vq.get_desc_mut(data_descs[index]);
            desc.addr = segment.device_addr;
            desc.len = segment.len as u32;
            if index + 1 < data_descs.len() {
                desc.flags = crate::defs::vring_flags::VRING_DESC_F_NEXT;
                desc.next = data_descs[index + 1];
            } else {
                desc.flags = 0;
                desc.next = 0;
            }
        }

        unsafe {
            self.vq.submit_avail(desc_idx);
        }
        Ok(desc_idx)
    }

    /// Add an RX buffer to the queue.
    pub unsafe fn add_rx_buffer(&self, phys_addr: u64, len: usize) -> Result<u16, VirtioNetError> {
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

    /// Get the number of available descriptors.
    pub fn available_descriptors(&self) -> u16 {
        self.vq.free_count()
    }

    /// Poll for completed buffers.
    pub fn poll_complete(&self) -> Option<(u16, u32)> {
        self.vq.poll_complete()
    }

    /// Reclaim a descriptor chain.
    pub fn free_desc_chain(&self, head: u16) {
        self.vq.free_desc_chain(head);
    }

    /// Notify the device.
    pub fn notify(&self, transport: &dyn crate::transport::VirtioTransport) {
        self.vq.notify(transport);
    }

    pub fn set_interrupts_enabled(&self, enabled: bool) {
        self.vq.set_interrupts_enabled(enabled);
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
    pub const F_DATA_VALID: u8 = 2;
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
