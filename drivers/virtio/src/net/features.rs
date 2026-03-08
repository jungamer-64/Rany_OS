// ============================================================================
// drivers/virtio/src/net/features.rs - VirtIO Network Feature Bits
// ============================================================================

//! # VirtIO Network Feature Bits
//!
//! Based on VirtIO Specification v1.2, Section 5.1.3.

/// Device handles packets with partial checksum.
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
/// Guest handles packets with partial checksum.
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
/// Control channel is available.
pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
/// Device has given MAC address.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Device reports link status.
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
/// Device supports MTU configuration.
pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;

// GSO / Offloading Features
pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
pub const VIRTIO_NET_F_GUEST_ECN: u64 = 1 << 9;
pub const VIRTIO_NET_F_GUEST_UFO: u64 = 1 << 10;
pub const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
pub const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
pub const VIRTIO_NET_F_HOST_ECN: u64 = 1 << 13;
pub const VIRTIO_NET_F_HOST_UFO: u64 = 1 << 14;
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
