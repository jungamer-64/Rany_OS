//! A memory service owns balloon pages, PFN commands and queue RAM until
//! acknowledged deflation or reset. Physical PFNs are distinct from IOVAs.
#![deny(unsafe_code)]

pub mod features {
    pub const VIRTIO_BALLOON_F_MUST_TELL_HOST: u64 = 1 << 0;
    pub const VIRTIO_BALLOON_F_STATS_VQ: u64 = 1 << 1;
    pub const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 1 << 2;
    pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u64 = 1 << 3;
    pub const VIRTIO_BALLOON_F_PAGE_REPORTING: u64 = 1 << 5;
}
mod device;
mod queue;
pub use device::*;
#[cfg(test)]
mod tests;
