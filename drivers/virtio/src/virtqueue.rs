// ============================================================================
// drivers/virtio/src/virtqueue.rs - Public VirtQueue alias
// ============================================================================

use kernel_api::dma::{CpuOwned, DmaSlice};

pub use crate::defs::{
    VIRTIO_F_INDIRECT_DESC, VIRTQUEUE_MAX_SIZE, VRING_AVAIL_ALIGN, VRING_DESC_ALIGN,
    VRING_USED_ALIGN, VringAvailHeader as VringAvail, VringDesc, VringUsedElem,
    VringUsedHeader as VringUsed, avail_flags, vring_flags,
};

pub type VirtQueue = crate::core::OwnedVirtQueue<DmaSlice<CpuOwned>>;
